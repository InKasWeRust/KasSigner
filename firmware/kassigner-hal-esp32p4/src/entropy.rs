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

//! Hardware entropy source: the SAR ADC folded into `LP_SYS.rng_data`.
//!
//! This module turns the source on and reads it raw; the generator draws it
//! only through `crate::drbg`'s health tests. Outside the bring-up tests,
//! nothing should call [`read`].
//!
//! Assessed under SP 800-90B (`ea_non_iid` on the `p4_entropy` capture, at
//! [`settle::RNG_READ_GAP_US`]): 7.269 bits per byte with an earlier
//! start-up, 7.31 with ESP-IDF's, below.
//!
//! ## The situation on rev1.3 silicon
//!
//! `LP_SYS.rng_data` is the random-number register. On chip revisions >= 3.0
//! a dedicated TRNG block feeds it; this silicon has none:
//!
//! ```c
//! // bootloader_random_esp32p4.c
//! #if HAL_CONFIG(CHIP_SUPPORT_MIN_REV) >= 300
//!     trng_ll_enable();
//! #endif
//! ```
//!
//! The ONLY entropy source here is the SAR ADC, run continuously in digital
//! mode with its noise folded into `rng_data`. The bootloader enables it and
//! disables it again before the app (the log shows both), so after boot
//! NOTHING feeds `rng_data`. esp-hal turns the source on in
//! `soc/<chip>/trng.rs` for every other target but has no
//! `soc/esp32p4/trng.rs`, so its `Rng` here reads a starved register.
//!
//! **Never generate a key from `rng_data` without calling `enable()` first,
//! and never trust it without the `p4_entropy` example's restart test
//! passing.**
//!
//! ## The sequence
//!
//! ESP-IDF's `bootloader_random_enable()` for esp32p4, register by register
//! through `adc_ll.h` and `regi2c_ctrl_ll.h`:
//!
//! ```text
//!  1  reset the ADC          hp_rst_en2.rst_en_adc          pulse
//!  2  ADC bus clocks         soc_clk_ctrl2.adc_apb_clk_en
//!                            peri_clk_ctrl23.adc_clk_en
//!  3  digital clock = XTAL   peri_clk_ctrl22.adc_clk_src_sel = 0
//!  4  divider 0/0/0          peri_clk_ctrl23 div_num/a/b
//!  5  power the analog I2C   PMU.rf_pwc: clear perif_i2c_rstb, 1 us,
//!                            set xpd_perif_i2c, set perif_i2c_rstb
//!  6  analog I2C master clk  LP_PERI.clk_en.ck_en_lp_i2cmst
//!  7  ADC regi2c init        REGI2C SAR reg 0x9: DTEST [3:0] = 0, ENT b4 = 1
//!  8  calibration = 2166     REGI2C SAR1 initial code hi [3:0] / lo [7:0]
//!  9  pattern table          4 entries: ADC1, channel 10, 12 dB
//! 10  pattern length 1       ctrl.sar1_patt_len = 0
//! 11  controller = digital   LP_ADC.meas1_mux.sar1_dig_force = 1
//!                            LP_ADC.meas1_ctrl2 start_force = 1, en_pad_force = 1
//! 12  power on               ctrl.sar_clk_gated = 1
//! 13  clock div 15           ctrl.sar_clk_div = 15
//! 14  trigger interval 100   ctrl2.timer_target = 100
//! 15  trigger enable         ctrl2.timer_sel = 1, timer_en = 1
//! ```
//!
//! Steps 7 and 8 go through the analog register interface, `soc::regi2c`,
//! this crate's own port, as esp-hal keeps its own private.
//!
//! Every address and bit comes from the esp32p4 PAC or ESP-IDF headers;
//! steps 5, 7 and 8 match ESP-IDF master `d35ea023` and v5.4. ESP-IDF's
//! newest `bootloader_random_enable` also starts revision 3.0's RNG block,
//! which this chip lacks.

use crate::drbg::Entropy;
use crate::soc::{clocks, regi2c, settle};
use esp32p4::{ADC, LP_ADC, LP_PERI, LP_SYS, PMU};
use esp_hal::delay::Delay;

// Register access is through the `esp32p4` PAC, every bit a named field:
// `ADC.ctrl` sar_clk_gated b5 / sar_clk_div [13:6] / sar1_patt_len [17:14],
// `ADC.ctrl2` timer_sel b11 / timer_target [23:12] / timer_en b24,
// `LP_ADC.meas1_mux` sar1_dig_force b31, `LP_ADC.meas1_ctrl2`
// meas1_start_force b18 / sar1_en_pad_force b31, `PMU.rf_pwc`
// perif_i2c_rstb b26 / xpd_perif_i2c b27, `LP_PERI.clk_en` ck_en_lp_i2cmst
// b27, `LP_SYS.rng_data.rnd_data`. All accesses are read-modify-write.
macro_rules! block {
    ($p:ident) => {
        // SAFETY: fixed MMIO blocks, always mapped. esp-hal does not
        // touch the SAR ADC on P4; the PMU/LP_PERI bits here are disjoint
        // from anything esp-hal sets, and nothing runs concurrently.
        unsafe { &*$p::PTR }
    };
}

use regi2c::block::SAR_I2C as I2C_SAR_ADC;

/// SAR ADC calibration registers, from `regi2c_saradc.h`.
const SAR1_INITIAL_CODE_LOW: u8 = 0x0; // bits [7:0]
const SAR1_INITIAL_CODE_HIGH: u8 = 0x1; // bits [3:0]
/// `I2C_SAR_ADC_DTEST_VDD_GRP1` `[3:0]` and `I2C_SAR_ADC_ENT_VDD_GRP1` b4,
/// from `regi2c_saradc.h`: one register.
const SAR_VDD_GRP1: u8 = 0x9;
/// The two fields of [`SAR_VDD_GRP1`] step 7 writes, DTEST `[3:0]` and ENT
/// b4, and what they read once it took: DTEST 0, ENT 1.
const SAR_INIT_FIELDS: u8 = 0x1F;
const SAR_INIT_ON: u8 = 0x10;
/// `I2C_SAR_ADC_INIT_CODE_VAL` from bootloader_random_esp32p4.c.
const CALIBRATION: u32 = 2166;

/// `adc_digi_pattern_config_t { unit: ADC_UNIT_1, atten: 12dB (3), channel: 10 }`
/// packed as `(atten & 3) | ((channel & 0xF) << 2)`.
const PATTERN: u32 = 3 | (10 << 2);

/// Why `enable()` could not be confirmed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The analog master rejected or timed out on a calibration write.
    RegI2c(regi2c::Error),
    /// The ADC trigger is not running after enable.
    NotRunning,
    /// Calibration read back a different value than was written.
    CalibrationMismatch(u16),
    /// Step 7's register read back other than written, the generator's
    /// enable bit clear or its test field set: the whole register.
    SarInitMismatch(u8),
}

/// Bring the SAR ADC entropy source up and CONFIRM it took. Idempotent.
///
/// `Err` if a REGI2C write or the read-back fails, the trigger is not
/// running, the calibration reads back wrong, or step 7's register does
/// not read back enabled, so an enable that did nothing is never taken for
/// one that worked.
pub fn enable(delay: &Delay) -> Result<(), Error> {
    // 1-4, in `soc::clocks` with the other HP_SYS_CLKRST bits.
    clocks::enable_adc(delay);

    // 5. PERIF_I2C power group, as `regi2c_ctrl_ll_i2c_sar_periph_enable`:
    //    into reset, powered, out of reset.
    let pmu = block!(PMU);
    pmu.rf_pwc().modify(|_, w| w.perif_i2c_rstb().clear_bit());
    settle::us(delay, settle::REGI2C_RESET_US);
    pmu.rf_pwc().modify(|_, w| w.xpd_perif_i2c().set_bit());
    pmu.rf_pwc().modify(|_, w| w.perif_i2c_rstb().set_bit());

    // 6. analog I2C master clock
    block!(LP_PERI)
        .clk_en()
        .modify(|_, w| w.ck_en_lp_i2cmst().set_bit());

    // 7. `adc_ll_regi2c_init`: the SAR's test mux off, its ENT bit on.
    regi2c_sar_init(true).map_err(Error::RegI2c)?;

    // 8. calibration through REGI2C
    regi2c_calibrate(CALIBRATION).map_err(Error::RegI2c)?;

    // 9. pattern table: all four slots ADC1 / ch10 / 12 dB.
    //    Slot i occupies bits [23-6i : 18-6i] of sar1_patt_tab1.
    let adc = block!(ADC);
    adc.sar1_patt_tab1().modify(|r, w| {
        let mut tab = r.sar1_patt_tab1().bits();
        for i in 0..4u32 {
            let offset = i * 6;
            tab &= !(0xFC0000 >> offset);
            tab |= (PATTERN & 0x3F) << (18 - offset);
        }
        // SAFETY: six-bit entries shifted into place, the field's layout;
        // any 24-bit value is a valid table.
        unsafe { w.sar1_patt_tab1().bits(tab) }
    });

    // 10. pattern length 1 (register holds len - 1)
    adc.ctrl()
        // SAFETY: zero is a length of one; the field holds length - 1.
        .modify(|_, w| unsafe { w.sar1_patt_len().bits(0) });

    // 11. digital controller
    let lp = block!(LP_ADC);
    lp.meas1_mux().modify(|_, w| w.sar1_dig_force().set_bit());
    lp.meas1_ctrl2().modify(|_, w| {
        w.meas1_start_force()
            .set_bit()
            .sar1_en_pad_force()
            .set_bit()
    });

    // 12-13. power on, clock divider 15
    // SAFETY: a clock divider of 15, within the eight-bit field.
    adc.ctrl().modify(|_, w| unsafe {
        w.sar_clk_gated().set_bit().sar_clk_div().bits(15) // gated = 1 means ON, counter-intuitively
    });

    // 14-15. free-running trigger every 100 cycles
    // SAFETY: a timer target of 100 cycles, within the twelve-bit field.
    adc.ctrl2().modify(|_, w| unsafe {
        w.timer_target()
            .bits(100)
            .timer_sel()
            .set_bit()
            .timer_en()
            .set_bit()
    });

    settle::us(delay, settle::ADC_WARMUP_US); // let a few conversions land

    let (running, cal, _, _) = verify().map_err(Error::RegI2c)?;
    if !running {
        return Err(Error::NotRunning);
    }
    if cal != EXPECTED_CALIBRATION {
        return Err(Error::CalibrationMismatch(cal));
    }
    // Step 7's register, read back as step 8's are: its writes go through
    // the same analog master and can fail as silently, and its enable bit
    // is the one that turns the source on.
    let sar = regi2c::read(I2C_SAR_ADC, SAR_VDD_GRP1).map_err(Error::RegI2c)?;
    if sar & SAR_INIT_FIELDS != SAR_INIT_ON {
        return Err(Error::SarInitMismatch(sar));
    }
    Ok(())
}

/// Mirror of `bootloader_random_disable()`.
pub fn disable() -> Result<(), regi2c::Error> {
    block!(ADC).ctrl2().modify(|_, w| w.timer_en().clear_bit());
    let r = regi2c_calibrate(0).and(regi2c_sar_init(false));
    block!(LP_PERI)
        .clk_en()
        .modify(|_, w| w.ck_en_lp_i2cmst().clear_bit());
    block!(LP_ADC)
        .meas1_mux()
        .modify(|_, w| w.sar1_dig_force().clear_bit()); // back to ULP control
    r
}

/// `adc_ll_set_calibration_param` for ADC1: the code's high four bits and
/// low eight, each into its own register, the high register's other bits
/// kept.
fn regi2c_calibrate(code: u32) -> Result<(), regi2c::Error> {
    let msb = ((code >> 8) & 0x0f) as u8;
    let lsb = (code & 0xff) as u8;
    regi2c::write_mask(I2C_SAR_ADC, SAR1_INITIAL_CODE_HIGH, 3, 0, msb)?;
    regi2c::write_mask(I2C_SAR_ADC, SAR1_INITIAL_CODE_LOW, 7, 0, lsb)
}

/// `adc_ll_regi2c_init` with `on`, `adc_ll_regi2c_adc_deinit` without: the
/// SAR's DTEST field to 0 and its ENT bit to `on`.
fn regi2c_sar_init(on: bool) -> Result<(), regi2c::Error> {
    regi2c::write_mask(I2C_SAR_ADC, SAR_VDD_GRP1, 3, 0, 0)?;
    regi2c::write_mask(I2C_SAR_ADC, SAR_VDD_GRP1, 4, 4, u8::from(on))
}

/// Address of `LP_SYS.rng_data`, as the `p4_entropy` example prints it.
pub fn rng_data_addr() -> u32 {
    block!(LP_SYS).rng_data().as_ptr() as u32
}

/// Read one raw, unpaced 32-bit word, meaningful only after `enable()`. For
/// [`sanity`] and the `p4_entropy` example, which want the register as is;
/// all else draws through [`HwSource`] and the DRBG.
pub fn read() -> u32 {
    block!(LP_SYS).rng_data().read().rnd_data().bits()
}

/// The noise source, as a [`crate::drbg::Entropy`], its reads paced by
/// [`settle::RNG_READ_GAP_US`] as in the SP 800-90B capture. The health
/// tests are [`crate::drbg::Guarded`]'s; this checks only that the
/// converter still runs.
pub struct HwSource {
    delay: Delay,
}

impl HwSource {
    /// Wrap the enabled source. Call [`enable`] first and check its result.
    pub fn new(delay: Delay) -> Self {
        Self { delay }
    }
}

impl Entropy for HwSource {
    type Error = Error;
    /// One word, the converter checked still running first.
    ///
    /// # Errors
    ///
    /// `NotRunning` when it is not ([`sampling`]): the health tests cannot
    /// tell a starved `rng_data` from a fed one, so a converter stopped after
    /// [`enable`] would otherwise go on reseeding the generator unseen.
    /// [`crate::drbg::Guarded`] poisons on it, and the generator with it.
    fn sample(&mut self) -> Result<u32, Self::Error> {
        settle::us(&self.delay, settle::RNG_READ_GAP_US);
        if !sampling() {
            return Err(Error::NotRunning);
        }
        Ok(read())
    }
}

/// Whether the converter is feeding `rng_data`: powered with its clock on,
/// ADC1 under the digital controller and its trigger running, as [`enable`]
/// left it. Three register reads, no side effects; [`verify`] calls it at
/// bring-up, [`HwSource`] before every sample.
pub fn sampling() -> bool {
    let ctrl = block!(ADC).ctrl().read();
    let ctrl2 = block!(ADC).ctrl2().read();
    let mux = block!(LP_ADC).meas1_mux().read();
    ctrl.sar_clk_gated().bit_is_set()
        && ctrl2.timer_en().bit_is_set()
        && ctrl2.timer_sel().bit_is_set()
        && mux.sar1_dig_force().bit_is_set()
}

/// Whether `enable()` took: the REGI2C calibration writes go through the
/// analog master, not plain MMIO, and can fail silently, leaving `rng_data`
/// fed by whatever fed it before.
///
/// Returns `(running, calibration, ADC ctrl, ADC ctrl2)`, `running` as
/// [`sampling`] reads it, or the REGI2C error if the analog master is
/// stuck, so a stuck master is never read as a calibration value.
pub fn verify() -> Result<(bool, u16, u32, u32), regi2c::Error> {
    let adc = block!(ADC);
    let running = sampling();
    let (ctrl, ctrl2) = (adc.ctrl().read().bits(), adc.ctrl2().read().bits());
    let hi = regi2c::read(I2C_SAR_ADC, SAR1_INITIAL_CODE_HIGH)? as u16;
    let lo = regi2c::read(I2C_SAR_ADC, SAR1_INITIAL_CODE_LOW)? as u16;
    Ok((running, ((hi & 0x0f) << 8) | lo, ctrl, ctrl2))
}

/// The calibration value `enable()` should have written.
pub const EXPECTED_CALIBRATION: u16 = CALIBRATION as u16;

/// Crude check on `n` successive reads, for a stuck or obviously periodic
/// register, nothing more.
///
/// **It cannot tell a real entropy source from a starved one**: on this
/// board, reads before and after `enable()` both gave 256/256 distinct and
/// ~50% ones. The RESTART test in the `p4_entropy` example discriminates: a
/// deterministic source starts from the same state after every reset.
///
/// Returns `(distinct, bit_ones, total_bits)`, `distinct` counting the reads
/// unlike the one before, the first included.
pub fn sanity(n: u32, delay: &Delay) -> (u32, u32, u32) {
    let mut prev = read();
    let mut distinct = 1u32;
    let mut ones = prev.count_ones();
    for _ in 1..n {
        settle::us(delay, settle::RNG_READ_GAP_US);
        let v = read();
        if v != prev {
            distinct += 1;
        }
        ones += v.count_ones();
        prev = v;
    }
    (distinct, ones, n * 32)
}
