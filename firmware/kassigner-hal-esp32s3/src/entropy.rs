// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The ESP32-S3 hardware random number generator.
//!
//! Implements [`kassigner_hal::entropy::Entropy`] over the WDEV RNG: the
//! raw, tested source. The flow does not draw it directly: `unit::bring_up`
//! wraps it in `kassigner_hal::drbg::Drbg`, and the unit holds that: the
//! health tests here catch a dead or stuck source, not a biased one, and
//! without the DRBG these words would go straight to ephemeral scalars and
//! GCM nonces.
//!
//! # Address and clock
//!
//! `WDEV_RND_REG` is read at the S3's address, not the ESP32's, and the
//! generator needs `SYSTEM_WIFI_CLK_RNG_EN`: either mistake gives all
//! zeros, and thirty-two zero words hash to a respectable-looking digest.
//! `WDEV_RND` and `APB_CTRL_WIFI_CLK_EN` appear nowhere else in the tree.
//!
//! # The generator needs an analogue source
//!
//! The TRM says true randomness needs the high-speed ADC or the SAR ADC;
//! `RC_FAST_CLK` alone adds metastability but is not enough. Espressif's
//! `bootloader_random_esp32s3.c` is milder, calling the fast clock enough
//! and the SAR ADC "some insurance". Either way [`Rng::start`] puts the ADC
//! there.
//!
//! **Powered is not sampling.** The ADC feeds the generator only while its
//! digital controller converts, continuously and on a timer, an internal
//! voltage with nothing on it. [`Rng::start`] does what Espressif's
//! `bootloader_random_enable` does for this chip, register for register,
//! each write naming its line (ESP-IDF v5.5.1); [`Rng::adc_sampling`] reads
//! the result back.
//!
//! **ADC1 has one owner at a time, and it is this generator**, through the
//! digital controller (`SENS_SAR1_DIG_FORCE`). The Waveshare's battery pin,
//! GPIO5, is on ADC1 too, and its gauge takes ADC1 by clearing that bit, so
//! the Waveshare runs without a cell and its signing firmware never reads
//! the battery (Home shows it empty). Its hardware test reads the battery
//! before starting the generator, and again after the generator's checks.
//!
//! Two steps differ from Espressif's routine, which runs inside the
//! bootloader while this runs after it. The controller is first released
//! from reset: the bootloader's `bootloader_random_disable` leaves it held
//! there, and esp-hal releases no peripheral it runs no driver for. And its
//! peripheral clock stays on, as ESP-IDF's application driver leaves it,
//! where the bootloader turns it off again ("Reset ADC clock").
//!
//! With the SAR ADC feeding it, the generator gets two bits per 20 MHz
//! cycle, so a fresh word needs reads no faster than 500 kHz: 2 µs, timed
//! by SYSTIMER, not by a spin-loop count.
//!
//! # Health is checked, and failure means no bytes
//!
//! `fill` returns bytes or an error, never bytes it does not trust, and on
//! failure zeroes the caller's buffer. The tests are
//! [`kassigner_hal::entropy::health`]: three answer "is it stuck" and would
//! pass a free-running counter; two catch a counter, which is what a wrong
//! address gives if it lands on a timer instead of on nothing.
//!
//! # The draw does not outlive the call
//!
//! Every draw is wiped: the window once its bytes are handed over, each
//! word's four bytes as they are copied, a window that failed its tests
//! before it is dropped, and the unused words of a short request's last
//! window.
//!
//! These are `Copy` values, so a copy may remain in a spill slot or a
//! register: the wipes shorten the exposure rather than end it, and the
//! caller must still treat what it received as a secret. Not observable
//! from outside, so not tested; each wipe sits at the value's last use, not
//! at the function's end.

use kassigner_hal::entropy::{health, Entropy, Error};
use kassigner_hal::timer::Timer;

use crate::systimer::SysTimer;

/// `WDEV_RND_REG`, the generator's output, at the S3's address (the ESP32's
/// `0x6003_5144` reads zero here).
const WDEV_RND: u32 = 0x6003_507C;

/// `SYSTEM_WIFI_CLK_EN_REG`. Shared, so every write is read-modify-write.
const APB_CTRL_WIFI_CLK_EN: u32 = 0x6002_6014;
/// The generator's own clock enable: **without it, it produces nothing**.
const SYSTEM_WIFI_CLK_RNG_EN: u32 = 1 << 15;

/// `RTC_CNTL_CLK_CONF_REG`.
const RTC_CNTL_CLK_CONF: u32 = 0x6000_8074;
/// Enables `RC_FAST_CLK`, which feeds clock jitter into the generator.
const DIG_CLK8M_EN: u32 = 1 << 10;

/// `SYSTEM_PERIP_CLK_EN0_REG`.
const SYSTEM_PERIP_CLK_EN0: u32 = 0x600C_0018;
/// The SAR ADC peripheral clock.
const SARADC_CLK_EN: u32 = 1 << 28;

/// On-chip sensor registers.
const SENS_BASE: u32 = 0x6000_8800;
/// `SENS_SAR_POWER_XPD_SAR_REG`.
const SENS_SAR_POWER_XPD_SAR: u32 = SENS_BASE + 0x003C;
/// `SENS_SAR_PERI_CLK_GATE_CONF_REG`.
const SENS_SAR_PERI_CLK_GATE: u32 = SENS_BASE + 0x0104;
/// `SENS_SARADC_CLK_EN`, bit 30 of that register (Espressif's
/// `sens_struct.h`): the converter's own clock. Distinct from
/// [`SARADC_CLK_EN`], bit 28 of `SYSTEM_PERIP_CLK_EN0`, which clocks the
/// *digital* controller. Bits 0 to 5 here are reserved.
const SENS_SARADC_CLK_EN: u32 = 1 << 30;
/// `SENS_FORCE_XPD_SAR`, bits 30:29.
const FORCE_XPD_SAR_MASK: u32 = 0x3 << 29;
/// Force the SAR ADC powered up: **3, not the 2 the manual gives.**
///
/// TRM v1.8 reads "2: Enable force power up, 3: Enable force power down";
/// Espressif's driver does the opposite, `sar_ctrl_ll_set_power_mode`
/// writing 3 for `SAR_CTRL_LL_POWER_ON` and 2 for off in esp-idf v5.1 to
/// v5.3, and the manual's revision history shows this field's description
/// has changed before. Written as 2, the converter is forced down, and
/// nothing fails visibly: the health tests pass on clock jitter alone.
const FORCE_XPD_SAR_ON: u32 = 0x3 << 29;

// ── The SAR ADC's digital controller, for sampling ──────────────────────────
//
// Addresses and fields from ESP-IDF v5.5.1, `soc/esp32s3/register/soc/`
// `apb_saradc_reg.h`, `sens_reg.h` and `system_reg.h`.

/// `SYSTEM_PERIP_RST_EN0_REG`.
const SYSTEM_PERIP_RST_EN0: u32 = 0x600C_0020;
/// `SYSTEM_APB_SARADC_RST`, bit 28: the digital controller held in reset.
const APB_SARADC_RST: u32 = 1 << 28;

/// The digital controller's registers.
const APB_SARADC_BASE: u32 = 0x6004_0000;
/// `APB_SARADC_CTRL_REG`.
const SARADC_CTRL: u32 = APB_SARADC_BASE;
/// `APB_SARADC_CTRL2_REG`.
const SARADC_CTRL2: u32 = APB_SARADC_BASE + 0x04;
/// `APB_SARADC_SAR1_PATT_TAB1_REG`.
const SARADC_SAR1_PATT_TAB1: u32 = APB_SARADC_BASE + 0x18;
/// `APB_SARADC_SAR2_PATT_TAB1_REG`.
const SARADC_SAR2_PATT_TAB1: u32 = APB_SARADC_BASE + 0x28;
/// `APB_SARADC_APB_ADC_ARB_CTRL_REG`.
const SARADC_ARB_CTRL: u32 = APB_SARADC_BASE + 0x38;
/// `APB_SARADC_FILTER_CTRL0_REG`.
const SARADC_FILTER_CTRL0: u32 = APB_SARADC_BASE + 0x3C;
/// `APB_SARADC_APB_ADC_CLKM_CONF_REG`.
const SARADC_CLKM_CONF: u32 = APB_SARADC_BASE + 0x70;

/// `APB_SARADC_START_FORCE`, `CTRL` bit 0.
const START_FORCE: u32 = 1;
/// `APB_SARADC_WORK_MODE`, `CTRL` bits 4:3.
const WORK_MODE: (u32, u32) = (3, 0x3);
/// `APB_SARADC_SAR_CLK_GATED`, `CTRL` bit 6.
const SAR_CLK_GATED: u32 = 1 << 6;
/// `APB_SARADC_SAR_CLK_DIV`, `CTRL` bits 14:7.
const SAR_CLK_DIV: (u32, u32) = (7, 0xFF);
/// `APB_SARADC_SAR1_PATT_LEN`, `CTRL` bits 18:15.
const SAR1_PATT_LEN: (u32, u32) = (15, 0xF);
/// `APB_SARADC_SAR2_PATT_LEN`, `CTRL` bits 22:19.
const SAR2_PATT_LEN: (u32, u32) = (19, 0xF);
/// `APB_SARADC_MEAS_NUM_LIMIT`, `CTRL2` bit 0.
const MEAS_NUM_LIMIT: u32 = 1;
/// `APB_SARADC_TIMER_SEL`, `CTRL2` bit 11.
const TIMER_SEL: u32 = 1 << 11;
/// `APB_SARADC_TIMER_TARGET`, `CTRL2` bits 23:12.
const TIMER_TARGET: (u32, u32) = (12, 0xFFF);
/// `APB_SARADC_TIMER_EN`, `CTRL2` bit 24.
const TIMER_EN: u32 = 1 << 24;
/// `APB_SARADC_ADC_ARB_GRANT_FORCE`, `ARB_CTRL` bit 5.
const ARB_GRANT_FORCE: u32 = 1 << 5;
/// `APB_SARADC_ADC_ARB_FIX_PRIORITY`, `ARB_CTRL` bit 12.
const ARB_FIX_PRIORITY: u32 = 1 << 12;
/// `APB_SARADC_FILTER_CHANNEL1`, `FILTER_CTRL0` bits 18:14.
const FILTER_CHANNEL1: (u32, u32) = (14, 0x1F);
/// `APB_SARADC_FILTER_CHANNEL0`, `FILTER_CTRL0` bits 23:19.
const FILTER_CHANNEL0: (u32, u32) = (19, 0x1F);
/// `APB_SARADC_CLKM_DIV_NUM`, `CLKM_CONF` bits 7:0.
const CLKM_DIV_NUM: (u32, u32) = (0, 0xFF);
/// `APB_SARADC_CLK_EN`, `CLKM_CONF` bit 20.
const CLKM_CLK_EN: u32 = 1 << 20;
/// `APB_SARADC_CLK_SEL`, `CLKM_CONF` bits 22:21.
const CLKM_CLK_SEL: (u32, u32) = (21, 0x3);

/// `SENS_SAR_MEAS1_MUX_REG`.
const SENS_SAR_MEAS1_MUX: u32 = SENS_BASE + 0x0010;
/// `SENS_SAR1_DIG_FORCE`, bit 31: ADC1 under the digital controller.
const SAR1_DIG_FORCE: u32 = 1 << 31;
/// `SENS_SAR_MEAS2_MUX_REG`.
const SENS_SAR_MEAS2_MUX: u32 = SENS_BASE + 0x0034;
/// `SENS_SAR2_RTC_FORCE`, bit 31: ADC2 held by the RTC controller.
const SAR2_RTC_FORCE: u32 = 1 << 31;

/// The pattern table entry both ADCs are given: channel `0xa`, which the
/// controller reads as "measure the internal voltage", with nothing on it.
const PATT_INTERNAL_VOLTAGE: u32 = 0x00af_ffff;

/// Register 7 of the SAR ADC's internal I2C block (`regi2c_saradc.h`).
const I2C_SAR_REG7: u8 = 0x7;
/// The five bits of register 7 that [`Rng::start`] writes, ENCAL_REF b4,
/// ENT_RTC b3, ENT_TSENS b2 and DTEST_RTC `[1:0]`, and what they read once
/// written: ENCAL_REF and ENT_TSENS on, the rest off.
const SAR_REG7_FIELDS: u8 = 0x1F;
const SAR_REG7_SET: u8 = (1 << 4) | (1 << 2);

/// Set `field` (shift, mask) of `word` to `value`.
const fn with_field(word: u32, (shift, mask): (u32, u32), value: u32) -> u32 {
    (word & !(mask << shift)) | ((value & mask) << shift)
}

/// Read-modify-write one register through `f`.
///
/// # Safety
///
/// `addr` must be one of the documented registers above.
unsafe fn modify(addr: u32, f: impl FnOnce(u32) -> u32) {
    // SAFETY: the caller's; a volatile read and write of one aligned
    // register word, never a bare store over bits this module does not own.
    unsafe {
        let v = core::ptr::read_volatile(addr as *const u32);
        core::ptr::write_volatile(addr as *mut u32, f(v));
    }
}

/// The internal I2C block that holds the SAR ADC's analogue settings:
/// `I2C_SAR_ADC`, host 1 (`regi2c_saradc.h`).
#[cfg(target_arch = "xtensa")]
const I2C_SAR_ADC: u8 = 0x69;
#[cfg(target_arch = "xtensa")]
const I2C_SAR_ADC_HOSTID: u8 = 1;

#[cfg(target_arch = "xtensa")]
unsafe extern "C" {
    /// `esp_rom_regi2c_write_mask`, in the S3's mask ROM.
    fn rom_i2c_writeReg_Mask(block: u8, host_id: u8, reg: u8, msb: u8, lsb: u8, data: u8);
    /// `esp_rom_regi2c_read`, beside it in the mask ROM.
    fn rom_i2c_readReg(block: u8, host_id: u8, reg: u8) -> u8;
}

/// One field of an internal-I2C analogue register, through the ROM's own
/// routine, as esp-hal and ESP-IDF both do on this chip.
#[cfg(target_arch = "xtensa")]
fn regi2c_write_mask(reg: u8, msb: u8, lsb: u8, value: u8) {
    // SAFETY: a ROM routine with a fixed address in `esp32s3.rom.ld`, given
    // the SAR ADC's block, host and register from `regi2c_saradc.h`.
    unsafe { rom_i2c_writeReg_Mask(I2C_SAR_ADC, I2C_SAR_ADC_HOSTID, reg, msb, lsb, value) };
}

/// One whole internal-I2C analogue register, through the ROM's routine.
#[cfg(target_arch = "xtensa")]
fn regi2c_read(reg: u8) -> u8 {
    // SAFETY: a ROM routine with a fixed address in `esp32s3.rom.ld`, given
    // the block, host and register the writes use; a read changes nothing.
    unsafe { rom_i2c_readReg(I2C_SAR_ADC, I2C_SAR_ADC_HOSTID, reg) }
}

/// On the host there is no analogue block to write.
#[cfg(not(target_arch = "xtensa"))]
fn regi2c_write_mask(_reg: u8, _msb: u8, _lsb: u8, _value: u8) {}

/// On the host there is no analogue block to read.
#[cfg(not(target_arch = "xtensa"))]
fn regi2c_read(_reg: u8) -> u8 {
    0
}

/// Microseconds between reads: the TRM's 500 kHz ceiling for a generator fed
/// by the SAR ADC. Faster, a word is partly the previous one.
pub const READ_SPACING_US: u32 = 2;

/// Words drawn and tested as one window: 1024 bits, the window the health
/// tests were calibrated against on real devices.
pub const WINDOW_WORDS: usize = 32;

/// The hardware generator.
pub struct Rng {
    timer: SysTimer,
    started: bool,
}

impl Rng {
    /// A handle not yet started: nothing is enabled until [`Rng::start`]
    /// runs, and [`Entropy::fill`] refuses until then.
    pub const fn new() -> Self {
        Self {
            timer: SysTimer,
            started: false,
        }
    }

    /// Enable the generator and its noise source. Call once before any
    /// draw; idempotent.
    ///
    /// All three are required: the generator's clock, the `RC_FAST_CLK`
    /// jitter feed, and the SAR ADC clocked, powered and sampling, the
    /// analogue noise source the TRM says to always enable.
    pub fn start(&mut self) {
        // SAFETY: read-modify-write of five documented registers, never a
        // bare store: `APB_CTRL_WIFI_CLK_EN` also holds the radio clocks,
        // which a whole-word store would change.
        unsafe {
            let wifi = core::ptr::read_volatile(APB_CTRL_WIFI_CLK_EN as *const u32);
            core::ptr::write_volatile(
                APB_CTRL_WIFI_CLK_EN as *mut u32,
                wifi | SYSTEM_WIFI_CLK_RNG_EN,
            );

            let clk = core::ptr::read_volatile(RTC_CNTL_CLK_CONF as *const u32);
            core::ptr::write_volatile(RTC_CNTL_CLK_CONF as *mut u32, clk | DIG_CLK8M_EN);

            let perip = core::ptr::read_volatile(SYSTEM_PERIP_CLK_EN0 as *const u32);
            core::ptr::write_volatile(SYSTEM_PERIP_CLK_EN0 as *mut u32, perip | SARADC_CLK_EN);

            // The converter's clock, bit 30: see `SENS_SARADC_CLK_EN`.
            let gate = core::ptr::read_volatile(SENS_SAR_PERI_CLK_GATE as *const u32);
            core::ptr::write_volatile(
                SENS_SAR_PERI_CLK_GATE as *mut u32,
                gate | SENS_SARADC_CLK_EN,
            );

            let pwr = core::ptr::read_volatile(SENS_SAR_POWER_XPD_SAR as *const u32);
            core::ptr::write_volatile(
                SENS_SAR_POWER_XPD_SAR as *mut u32,
                (pwr & !FORCE_XPD_SAR_MASK) | FORCE_XPD_SAR_ON,
            );
        }
        self.start_sampling();

        // The RC oscillator needs a moment to settle, timed by SYSTIMER as
        // the read spacing is.
        self.timer.delay_us(500);
        self.started = true;
    }

    /// Make the SAR ADC convert continuously, so its noise reaches the
    /// generator: `bootloader_random_enable` for this chip, in its order.
    fn start_sampling(&self) {
        // SAFETY: read-modify-writes of the documented registers above.
        unsafe {
            // Out of the reset the bootloader left it in (module doc).
            modify(SYSTEM_PERIP_RST_EN0, |v| v & !APB_SARADC_RST);

            // "Enable clock and select clock source for ADC digital
            // controller": APB clock, controller clock on.
            modify(SARADC_CLKM_CONF, |v| with_field(v, CLKM_CLK_SEL, 2));
            modify(SARADC_CTRL, |v| v | SAR_CLK_GATED);
            modify(SARADC_CLKM_CONF, |v| v | CLKM_CLK_EN);
            // "Read frequency has to be at least 35 times lower than the
            // sampling frequency": divider 3, SAR clock divider 3, timer 70.
            modify(SARADC_CLKM_CONF, |v| with_field(v, CLKM_DIV_NUM, 3));
            modify(SARADC_CTRL, |v| with_field(v, SAR_CLK_DIV, 3));
            modify(SARADC_CTRL2, |v| with_field(v, TIMER_TARGET, 70));
            modify(SARADC_CTRL, |v| v & !START_FORCE);
            // (`SENS_FORCE_XPD_SAR` = 3 is set in `start` already.)
            modify(SARADC_CTRL2, |v| v & !MEAS_NUM_LIMIT);
            modify(SARADC_CTRL, |v| with_field(v, WORK_MODE, 1));
            // "Test internal voltage if the channel info is 0xa", one
            // pattern entry per ADC.
            modify(SARADC_CTRL, |v| with_field(v, SAR2_PATT_LEN, 0));
            modify(SARADC_SAR2_PATT_TAB1, |_| PATT_INTERNAL_VOLTAGE);
            modify(SARADC_CTRL, |v| with_field(v, SAR1_PATT_LEN, 0));
            modify(SARADC_SAR1_PATT_TAB1, |_| PATT_INTERNAL_VOLTAGE);
            // "Enable adc1 digital controller", and the ADC2 arbiter.
            modify(SENS_SAR_MEAS1_MUX, |v| v | SAR1_DIG_FORCE);
            modify(SENS_SAR_MEAS2_MUX, |v| v & !SAR2_RTC_FORCE);
            modify(SARADC_ARB_CTRL, |v| {
                v & !(ARB_GRANT_FORCE | ARB_FIX_PRIORITY)
            });
            // "Disable ADC filter".
            modify(SARADC_FILTER_CTRL0, |v| {
                with_field(with_field(v, FILTER_CHANNEL0, 0xD), FILTER_CHANNEL1, 0xD)
            });
            // "Start ADC sample".
            modify(SARADC_CTRL2, |v| v | TIMER_SEL);
            modify(SARADC_CTRL2, |v| v | TIMER_EN);
        }
        // "Choose the appropriate internal voltage to measure":
        // ENCAL_REF bit 4, ENT_TSENS bit 2, ENT_RTC bit 3, DTEST_RTC bits 1:0.
        regi2c_write_mask(I2C_SAR_REG7, 4, 4, 1);
        regi2c_write_mask(I2C_SAR_REG7, 2, 2, 1);
        regi2c_write_mask(I2C_SAR_REG7, 3, 3, 0);
        regi2c_write_mask(I2C_SAR_REG7, 1, 0, 0);
    }

    /// Whether the SAR ADC is converting for the generator, read back from
    /// the registers [`Rng::start`] wrote: out of reset, its clock on, the
    /// converter forced up, ADC1 under the digital controller, the sampling
    /// timer running, and analogue register 7 choosing the voltage it
    /// measures. That last one is written through the ROM's analogue bus,
    /// where a write that did not land says nothing.
    ///
    /// The health tests pass on the fast clock alone, so they cannot tell a
    /// converter left idle; this can. The units fail their self-test on it
    /// at start, and every draw checks it again ([`Rng::draw_window`]).
    pub fn adc_sampling(&self) -> bool {
        // SAFETY: volatile reads of documented registers, no side effects.
        unsafe {
            let rst = core::ptr::read_volatile(SYSTEM_PERIP_RST_EN0 as *const u32);
            let clkm = core::ptr::read_volatile(SARADC_CLKM_CONF as *const u32);
            let xpd = core::ptr::read_volatile(SENS_SAR_POWER_XPD_SAR as *const u32);
            let mux1 = core::ptr::read_volatile(SENS_SAR_MEAS1_MUX as *const u32);
            let ctrl2 = core::ptr::read_volatile(SARADC_CTRL2 as *const u32);
            self.started
                && rst & APB_SARADC_RST == 0
                && clkm & CLKM_CLK_EN != 0
                && xpd & FORCE_XPD_SAR_MASK == FORCE_XPD_SAR_ON
                && mux1 & SAR1_DIG_FORCE != 0
                && ctrl2 & (TIMER_EN | TIMER_SEL) == (TIMER_EN | TIMER_SEL)
                && regi2c_read(I2C_SAR_REG7) & SAR_REG7_FIELDS == SAR_REG7_SET
        }
    }

    /// Whether [`Rng::start`] has run.
    pub const fn is_started(&self) -> bool {
        self.started
    }

    /// One raw word.
    fn read(&self) -> u32 {
        // SAFETY: a volatile read of `WDEV_RND_REG` at the S3's address, with
        // no side effect on any other peripheral.
        unsafe { core::ptr::read_volatile(WDEV_RND as *const u32) }
    }

    /// Draw a window and test it: the words, or `None` if they failed or the
    /// converter is not sampling ([`Rng::adc_sampling`]). Public for a
    /// self-test, which wants the window rather than bytes.
    pub fn draw_window(&mut self) -> Option<[u32; WINDOW_WORDS]> {
        if !self.started {
            return None;
        }
        // The converter still sampling, at every draw, not only at bring-up:
        // the health tests pass on the fast clock alone, so a converter
        // turned off since would go unnoticed while the generator above
        // reseeds from this. A window refused here is `Unhealthy` to `fill`,
        // which poisons that generator.
        if !self.adc_sampling() {
            return None;
        }
        let mut words = [0u32; WINDOW_WORDS];
        for w in words.iter_mut() {
            *w = self.read();
            // The TRM's ceiling.
            self.timer.delay_us(READ_SPACING_US);
        }
        if health::all(&words) {
            Some(words)
        } else {
            // A failed window is still a draw from the generator: not
            // something to leave on the stack.
            wipe(&mut words);
            None
        }
    }
}

impl Rng {
    /// One window drawn, tested and thrown away: the start-up check, so a
    /// dead or stuck source shows at boot rather than when a seed or a
    /// signature first needs it.
    ///
    /// The window is wiped whether it passed or not: generator output is not
    /// left on a stack frame for the next call to overwrite at leisure.
    pub fn health_check(&mut self) -> bool {
        match self.draw_window() {
            Some(mut words) => {
                wipe(&mut words);
                true
            }
            // `draw_window` wipes a window that failed.
            None => false,
        }
    }
}

/// Overwrite with zeros, volatile so the optimiser cannot drop a store it
/// sees is never read: `zeroize`'s job written out, as this crate does not
/// depend on `zeroize`.
fn wipe(words: &mut [u32]) {
    for w in words.iter_mut() {
        // SAFETY: a word of a slice held exclusively by the caller.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
}

/// See [`wipe`].
fn wipe_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

impl Entropy for Rng {
    /// Fill `out` from tested windows.
    ///
    /// # Errors
    ///
    /// `Unavailable` if [`Rng::start`] has not run, `Unhealthy` if a window
    /// failed its tests. On either, `out` is zeroed, so a caller that ignores
    /// the result finds nothing that looks like randomness.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if !self.started {
            out.fill(0);
            return Err(Error::Unavailable);
        }

        let mut written = 0usize;
        while written < out.len() {
            let Some(mut words) = self.draw_window() else {
                out.fill(0);
                return Err(Error::Unhealthy);
            };
            for w in words.iter() {
                if written >= out.len() {
                    break;
                }
                let mut bytes = w.to_le_bytes();
                let take = (out.len() - written).min(4);
                out[written..written + take].copy_from_slice(&bytes[..take]);
                written += take;
                wipe_bytes(&mut bytes);
            }
            // The window, once handed over: the caller's bytes are in `out`,
            // and the draw they came from, a signing nonce's perhaps, would
            // otherwise stay on the stack after the call. The last window of
            // a short request also holds words never used.
            wipe(&mut words);
        }
        Ok(())
    }
}
