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

//! The battery.
//!
//! This board has no PMU: the cell is read off a divider into the SAR ADC,
//! through registers only.
//!
//! # It takes ADC1 from the entropy source
//!
//! [`crate::entropy`] keeps the SAR ADC on and gives ADC1 to the digital
//! controller as the generator's analogue noise source (the TRM says
//! `RC_FAST_CLK` alone is not enough). A conversion here clears
//! `SENS_SAR1_DIG_FORCE` to put ADC1 under the RTC controller, which takes it
//! from the generator until the generator is started again. So the signing
//! firmware never reads this battery, and the Waveshare runs without a cell:
//! this module is the hardware test's. Powering the ADC down to save current
//! would stop the entropy source too.
//!
//! # A reading below the floor is not a full battery
//!
//! A raw value under [`IMPLAUSIBLE_BELOW`] is [`Reading::Implausible`], not
//! 4200 mV and 100%: "I cannot read this" is not "it is full".
//!
//! # Whether a cell is fitted is not known
//!
//! The charger's status pin drives the red LED and no GPIO. With no cell the
//! divider sees the charger's float, about 4.2 V (4266 mV measured), the same
//! as a full cell: `present` is `None`, and a reading at the top of the range
//! means "full, or no battery".
//!
//! # A conversion that never finishes is not a reading
//!
//! Any of the four conversions timing out makes the whole reading
//! `Error::Io`: counted as 0, a timeout would read as a believable level a
//! quarter lower.
//!
//! # The charge state is unknown
//!
//! A divider gives a voltage, not the direction of the current: a full cell
//! just off USB, or a cell charging at a low voltage, would be guessed wrong.
//! This reports [`ChargeState::Unknown`].

const SENS_BASE: u32 = 0x6000_8800;
const SENS_SAR_READER1_CTRL: u32 = SENS_BASE; // + 0x0000
const SENS_SAR_MEAS1_CTRL2: u32 = SENS_BASE + 0x000C;
const SENS_SAR_MEAS1_MUX: u32 = SENS_BASE + 0x0010;
const SENS_SAR_ATTEN1: u32 = SENS_BASE + 0x0014;
const SENS_SAR_POWER_XPD_SAR: u32 = SENS_BASE + 0x003C;
const SENS_SAR_PERI_CLK_GATE: u32 = SENS_BASE + 0x0104;

/// `RTC_IO_TOUCH_PAD5_REG`, the RTC pad register for GPIO5, where the
/// battery divider lands (ADC1 channel 4). Analog input goes through the RTC
/// domain, not the digital IO MUX, so the pad is handed over first.
const RTC_IO_TOUCH_PAD5: u32 = 0x6000_8400 + 0x98;

/// `MUX_SEL`, bit 19: 0 routes the pad to the digital GPIO module, 1 to the
/// analog RTC module.
const PAD_MUX_SEL: u32 = 1 << 19;
/// `FUN_SEL`, bits 18:17. Zero selects the RTC function.
const PAD_FUN_SEL_MASK: u32 = 0x3 << 17;
/// `RUE`, bit 27: the pad's pull-up.
const PAD_RUE: u32 = 1 << 27;
/// `RDE`, bit 28: the pad's pull-down. **Defaults to 1.**
const PAD_RDE: u32 = 1 << 28;

/// `SENS_SAR_SLAVE_ADDR1_REG`, which carries an undocumented status field.
const SENS_SAR_SLAVE_ADDR1: u32 = SENS_BASE + 0x0040;

/// `meas_status`, bits 29:22 of that register: reserved in the manual, named
/// in Espressif's `sens_struct.h`. A converter reporting busy ignores a
/// start, so their one-shot waits for zero first.
const MEAS_STATUS_MASK: u32 = 0xFF << 22;

// System peripheral clock
const SYSTEM_PERIP_CLK_EN0: u32 = 0x600C_0018;

/// `SENS_FORCE_XPD_SAR`, bits 30:29 of `SENS_SAR_POWER_XPD_SAR_REG` (TRM
/// register 39.18).
const FORCE_XPD_SAR_MASK: u32 = 0x3 << 29;

/// Force the converter powered up: **3, not the 2 the manual gives.**
///
/// TRM v1.8 reads "2: Enable force power up, 3: Enable force power down", but
/// esp-idf v5.1 to v5.3 write 3 for on and 2 for off
/// (`sar_ctrl_ll_set_power_mode`), and the manual's revision history shows
/// this field's description has been changed before. This follows esp-idf.
const FORCE_XPD_SAR_ON: u32 = 0x3 << 29;

/// `SENS_SARADC_CLK_EN`, bit 30 of `SENS_SAR_PERI_CLK_GATE_CONF_REG`: the
/// converter's clock. Without it a conversion starts and `DONE` never
/// arrives. Bit position from Espressif's `sens_struct.h`.
const SARADC_CLK_EN: u32 = 1 << 30;

/// `RTC_CNTL_RTC_CLK_CONF_REG`. TRM register 10.25.
const RTC_CNTL_CLK_CONF: u32 = 0x6000_8074;
/// `RTC_CNTL_CK8M_FORCE_PU`, bit 26: keep the RC oscillator powered.
const CK8M_FORCE_PU: u32 = 1 << 26;

/// Divider from `RTC_FAST_CLK` to the converter's own clock.
///
/// The TRM requires at least 2 and `RTCADC_SARCLK` under 5 MHz, above which
/// sampling precision falls off. 15 keeps well under it, at a cost of
/// microseconds per reading.
const SAR_CLK_DIV: u32 = 15;

#[inline(always)]
unsafe fn reg_write(addr: u32, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

#[inline(always)]
unsafe fn reg_read(addr: u32) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

pub use kassigner_hal::battery::{BatteryStatus, ChargeState, Error, Reading};

pub fn init_battery_adc() {
    // SAFETY: read-modify-writes of SYSTEM_PERIP_CLK_EN0, the SENS registers
    // for ADC1, the GPIO5 pad and RTC_CNTL_CLK_CONF, at their fixed
    // addresses; each touches only the bits it names. Called from the
    // hardware test only: ADC1 is shared with the random generator
    // (`crate::entropy`).
    unsafe {
        // Enable SARADC peripheral clock (bit 28 of PERIP_CLK_EN0)
        let clk = reg_read(SYSTEM_PERIP_CLK_EN0);
        reg_write(SYSTEM_PERIP_CLK_EN0, clk | (1u32 << 28));

        // The converter's clock (`SARADC_CLK_EN`).
        let gate = reg_read(SENS_SAR_PERI_CLK_GATE);
        reg_write(SENS_SAR_PERI_CLK_GATE, gate | SARADC_CLK_EN);

        // Hand GPIO5 to the analog domain. Clearing `FUN_IE` in the IO MUX
        // only stops digital input; without `MUX_SEL` the ADC samples an
        // unconnected input and reads near the rail. The pulls go too: `RDE`
        // **defaults to set**, and a pull on a divider moves the reading.
        // Espressif's one-shot driver does the same (`rtc_gpio_init`,
        // `rtc_gpio_pulldown_dis`, `rtc_gpio_pullup_dis`).
        let iomux5 = (0x6000_9004u32 + 5 * 4) as *mut u32;
        let v = core::ptr::read_volatile(iomux5);
        core::ptr::write_volatile(iomux5, v & !(1u32 << 9)); // clear FUN_IE

        let pad = reg_read(RTC_IO_TOUCH_PAD5);
        reg_write(
            RTC_IO_TOUCH_PAD5,
            (pad & !(PAD_FUN_SEL_MASK | PAD_RUE | PAD_RDE)) | PAD_MUX_SEL,
        );

        // ADC1 under the RTC controller: SENS_SAR_MEAS1_MUX bit 31,
        // SAR1_DIG_FORCE, cleared. This takes ADC1 from the random generator
        // (`crate::entropy`).
        let mux = reg_read(SENS_SAR_MEAS1_MUX);
        reg_write(SENS_SAR_MEAS1_MUX, mux & !(1u32 << 31));

        // Attenuation for channel 4: bits 9:8 = 3 (12 dB).
        let atten = reg_read(SENS_SAR_ATTEN1);
        reg_write(SENS_SAR_ATTEN1, (atten & !(0x3u32 << 8)) | (0x3u32 << 8));

        // Force the converter on: bits 30:29 = 3 (`FORCE_XPD_SAR_ON` says why
        // not 2). Bits 1:0, the ESP32's field, are reserved on this chip.
        let pwr = reg_read(SENS_SAR_POWER_XPD_SAR);
        reg_write(
            SENS_SAR_POWER_XPD_SAR,
            (pwr & !FORCE_XPD_SAR_MASK) | FORCE_XPD_SAR_ON,
        );

        // The converter is clocked from RTC_FAST_CLK: keep the RC oscillator
        // behind it powered, read-modify-write, since this register also
        // holds the digital core's 8 MHz enable the entropy source needs.
        // Then `SAR_CLK_DIV` into SAR1_CLK_DIV, bits 7:0 of
        // SENS_SAR_READER1_CTRL.
        let clk_conf = reg_read(RTC_CNTL_CLK_CONF);
        reg_write(RTC_CNTL_CLK_CONF, clk_conf | CK8M_FORCE_PU);

        let reader = reg_read(SENS_SAR_READER1_CTRL);
        reg_write(SENS_SAR_READER1_CTRL, (reader & !0xFF) | SAR_CLK_DIV);
    }
}

/// One conversion on channel 4; `None` when it never reports done.
fn adc1_oneshot_ch4() -> Option<u16> {
    // SAFETY: writes and polls ADC1's one-shot registers in SENS at their
    // fixed addresses, for channel 4 only; no other peripheral's bits change.
    unsafe {
        // SENS_SAR_MEAS1_CTRL2:
        //   bit 31: SAR1_EN_PAD_FORCE = 1 (software controls pad enable)
        //   bits 30:19: SAR1_EN_PAD = channel bitmask (ch4 → bit4 at position 23)
        //   bit 18: MEAS1_START_FORCE = 1 (software trigger)
        //   bit 17: MEAS1_START_SAR = trigger bit (write 1 to start)
        //   bit 16: MEAS1_DONE_SAR (read-only, set when done)
        //   bits 15:0: MEAS1_DATA_SAR (read-only, result)

        let en_pad = 1u32 << (19 + 4); // channel 4 in SAR1_EN_PAD field (bit 23)
        let force_bits = (1u32 << 31) | (1u32 << 18); // EN_PAD_FORCE + START_FORCE

        // Clear start, set up pad selection
        reg_write(SENS_SAR_MEAS1_CTRL2, force_bits | en_pad);

        // Small delay for setup
        for _ in 0..10u32 {
            reg_read(SENS_SAR_MEAS1_CTRL2);
        }

        // Wait for idle (`MEAS_STATUS_MASK`): a start while busy is ignored.
        for _ in 0..10_000u32 {
            if reg_read(SENS_SAR_SLAVE_ADDR1) & MEAS_STATUS_MASK == 0 {
                break;
            }
        }

        // Trigger: a rising edge on MEAS1_START_SAR (bit 17).
        reg_write(SENS_SAR_MEAS1_CTRL2, force_bits | en_pad | (1u32 << 17));

        // Wait for MEAS1_DONE_SAR (bit 16) with timeout
        for _ in 0..100_000u32 {
            let ctrl2 = reg_read(SENS_SAR_MEAS1_CTRL2);
            if ctrl2 & (1u32 << 16) != 0 {
                // The 12-bit result, bits 11:0.
                return Some((ctrl2 & 0xFFF) as u16);
            }
        }

        // Timeout. Drop START: left set, the next attempt makes no rising
        // edge, and every later one fails too.
        reg_write(SENS_SAR_MEAS1_CTRL2, force_bits | en_pad);
        None
    }
}

/// Four conversions averaged: one on this divider is noisy enough to move the
/// percentage between reads. `None` when any of them times out.
fn average_of_four() -> Option<u16> {
    let mut sum = 0u32;
    for _ in 0..4 {
        sum += u32::from(adc1_oneshot_ch4()?);
    }
    Some((sum / 4) as u16)
}

/// Full scale in millivolts: Waveshare's figure. Their wiki converts the same
/// 200K over 100K divider on a sibling board as
/// `3.3 / (1 << 12) * 3 * AD_Value`. (2500 is the ESP32's figure at 11 dB, a
/// level this chip lacks; the manual's nominal `Vref / k`, 1100 mV over about
/// 25%, gives 4400.)
///
/// Uncalibrated, so a few percent out: fine for a flat-battery warning, not
/// for a number. Measured on the unit it reads **high**, 4.25 to 4.39 V from
/// a charging cell that cannot exceed 4.2 V, moving about 3% between runs.
/// Espressif's eFuse calibration does not fit how this module sets the
/// converter up.
pub const FULL_SCALE_MV: u32 = 3300;

/// Steps in the converter's range, Waveshare's `1 << 12`. The manual divides
/// by 4095; the 0.02% difference is inside the uncalibrated error.
pub const FULL_SCALE_STEPS: u32 = 4096;

/// The divider: the converter sees two thirds of the cell, so the cell is the
/// reading times three over two.
///
/// **Not the one third the schematic's annotation gives.** Measured: with a
/// cell the converter reads 2.60 V, a 3.90 V cell at two thirds (7.80 V at
/// one third); with none, 4.40 V at two thirds, an unloaded charger output.
/// So R19 is the 100K in series and R20 the 200K to ground.
pub const DIVIDER_NUM: u32 = 3;
/// See [`DIVIDER_NUM`].
pub const DIVIDER_DEN: u32 = 2;

fn raw_to_voltage_mv(raw: u16) -> u16 {
    let vadc_mv = (raw as u32 * FULL_SCALE_MV) / FULL_SCALE_STEPS;
    (vadc_mv * DIVIDER_NUM / DIVIDER_DEN) as u16
}

fn voltage_to_percent(mv: u16) -> u8 {
    if mv >= 4150 {
        return 100;
    }
    if mv >= 4050 {
        return 90;
    }
    if mv >= 3950 {
        return 80;
    }
    if mv >= 3850 {
        return 70;
    }
    if mv >= 3780 {
        return 60;
    }
    if mv >= 3720 {
        return 50;
    }
    if mv >= 3680 {
        return 40;
    }
    if mv >= 3620 {
        return 30;
    }
    if mv >= 3560 {
        return 20;
    }
    if mv >= 3490 {
        return 10;
    }
    if mv >= 3300 {
        return 5;
    }
    0
}

/// The raw value below which no real cell can be present.
pub const IMPLAUSIBLE_BELOW: u16 = 50;

/// Read the cell: four conversions averaged.
///
/// # Errors
///
/// `Io` when any of the four conversions times out.
pub fn read() -> Result<Reading, Error> {
    let raw = average_of_four().ok_or(Error::Io)?;

    if raw < IMPLAUSIBLE_BELOW {
        return Ok(Reading::Implausible { raw });
    }

    let voltage_mv = raw_to_voltage_mv(raw);
    Ok(Reading::Battery(BatteryStatus {
        // Not known: with no cell fitted the divider sees the charger's float,
        // about 4.2 V, which reads as a full cell.
        present: None,
        voltage_mv,
        percentage: voltage_to_percent(voltage_mv),
        state: ChargeState::Unknown,
    }))
}

/// The averaged converter output, before any scaling, for checking
/// [`FULL_SCALE_MV`] against a multimeter. `None` when a conversion times
/// out.
pub fn read_raw() -> Option<u16> {
    average_of_four()
}

/// The converter's control and power registers, for when a read fails:
/// whether the ADC is powered, on the right channel, and whether the
/// conversion started.
pub fn control_state() -> (u32, u32) {
    // SAFETY: two volatile reads of documented registers, no side effects.
    unsafe {
        (
            reg_read(SENS_SAR_MEAS1_CTRL2),
            reg_read(SENS_SAR_POWER_XPD_SAR),
        )
    }
}

/// Whether the converter is forced on.
pub fn is_powered() -> bool {
    let (_, pwr) = control_state();
    pwr & FORCE_XPD_SAR_MASK == FORCE_XPD_SAR_ON
}

/// The raw value a voltage would produce: the inverse of the conversion.
pub const fn voltage_to_raw(mv: u16) -> u16 {
    ((mv as u32 * DIVIDER_DEN * FULL_SCALE_STEPS) / (FULL_SCALE_MV * DIVIDER_NUM)) as u16
}

/// The battery, as a [`kassigner_hal::battery::Battery`].
///
/// Nothing to own: the converter is registers. [`init_battery_adc`] must have
/// run once first.
#[derive(Clone, Copy, Debug)]
pub struct WaveshareBattery;

impl kassigner_hal::battery::Battery for WaveshareBattery {
    /// This module's `read`: `Io` when a conversion times out.
    fn read(&mut self) -> Result<Reading, Error> {
        read()
    }
}
