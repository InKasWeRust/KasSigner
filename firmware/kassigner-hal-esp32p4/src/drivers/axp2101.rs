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

//! AXP2101 PMU, I2C 0x34: battery, rails, charging and the power button.
//!
//! From the X-Powers AXP2101 datasheet, Rev 0.2 (register map in section 8)
//! and V1.0, which also documents 0x26, 0x28 and 0x56-0x5B; everything else
//! here is the same in both. Espressif has no driver for it: the part is
//! Waveshare's addition to this board.
//!
//! There is no chip-ID register (some drivers read 0x03 expecting 0x4A,
//! but 0x03 is not in the map): presence is the bus ACK and plausible
//! status.
//!
//! Read-only by default: a write can brown out the board or misconfigure
//! charging, and these rails power the SoC. The few writes are `unsafe`.

use crate::board::i2c::{self, Bus};

/// I2C address. Fixed by the part.
pub const ADDR: u8 = 0x34;

/// Register addresses, datasheet section 8.1.
#[allow(missing_docs)] // register table
pub mod reg {
    pub const STATUS1: u8 = 0x00;
    pub const STATUS2: u8 = 0x01;
    pub const COMMON_CONFIG: u8 = 0x10;
    pub const BATFET_CTRL: u8 = 0x12;
    pub const DIE_TEMP_CTRL: u8 = 0x13;
    pub const MIN_SYS_VOLTAGE: u8 = 0x14;
    pub const VIN_VOLTAGE_LIMIT: u8 = 0x15;
    pub const VIN_CURRENT_LIMIT: u8 = 0x16;
    pub const CHG_GAUGE_WDT_CTRL: u8 = 0x18;
    pub const PWRON_STATUS: u8 = 0x20;
    pub const PWROFF_STATUS: u8 = 0x21;
    pub const PWROFF_EN: u8 = 0x22;
    pub const ADC_CHANNEL_CTRL: u8 = 0x30;
    /// ADC data block 0x34-0x3D. vbat_h/l first.
    pub const ADC_VBAT_H: u8 = 0x34;
    pub const ADC_VBAT_L: u8 = 0x35;
    pub const ADC_TS_H: u8 = 0x36;
    pub const ADC_TS_L: u8 = 0x37;
    pub const ADC_VBUS_H: u8 = 0x38;
    pub const ADC_VBUS_L: u8 = 0x39;
    pub const ADC_VSYS_H: u8 = 0x3A;
    pub const ADC_VSYS_L: u8 = 0x3B;
    pub const ADC_TDIE_H: u8 = 0x3C;
    pub const ADC_TDIE_L: u8 = 0x3D;
    pub const IRQ_EN0: u8 = 0x40;
    pub const IRQ_EN1: u8 = 0x41;
    pub const IRQ_EN2: u8 = 0x42;
    pub const IRQ_STATUS0: u8 = 0x48;
    /// IRQ Status 1 — carries the POWERON button events.
    pub const IRQ_STATUS1: u8 = 0x49;
    pub const IRQ_STATUS2: u8 = 0x4A;
    pub const ICC_CHARGER: u8 = 0x62;
    pub const CV_CHARGER_VOLTAGE: u8 = 0x64;
    pub const CHGLED_CTRL: u8 = 0x69;

    // ---- sleep, power-on, charge temperature, JEITA, rails, gauge -------
    /// Sleep and wakeup control.
    pub const SLEEP_WAKEUP_CTRL: u8 = 0x26;
    /// Fast power-on start sequence 0.
    pub const FAST_PWRON0: u8 = 0x28;
    /// VLTF for charging, also JEITA's T1: N * 32 mV, default 0x29 (about
    /// 0 degC).
    pub const VLTF_CHG: u8 = 0x54;
    /// VHTF for charging.
    pub const VHTF_CHG: u8 = 0x55;
    /// VLTF work threshold. N * 32 mV, default about -10 degC.
    pub const VLTF_WORK: u8 = 0x56;
    /// VHTF work threshold. N * 2 mV, default about 60 degC.
    pub const VHTF_WORK: u8 = 0x57;
    /// JEITA standard enable, bit 0.
    pub const JEITA_ENABLE: u8 = 0x58;
    /// JEITA CV configuration — current and voltage derating.
    pub const JEITA_CV: u8 = 0x59;
    /// JEITA cool threshold T2. N * 16 mV, default 0x37 (about 10 degC).
    pub const JEITA_COOL: u8 = 0x5A;
    /// JEITA warm threshold T3. N * 8 mV, default 0x1E (about 45 degC).
    pub const JEITA_WARM: u8 = 0x5B;
    pub const DCDC_ONOFF: u8 = 0x80;
    pub const LDO_ONOFF0: u8 = 0x90;
    pub const LDO_ONOFF1: u8 = 0x91;
    pub const BATTERY_PERCENT: u8 = 0xA4;
}

/// REG 00 — PMU status1.
#[allow(missing_docs)] // bit table
pub mod status1 {
    pub const VBUS_GOOD: u8 = 1 << 5;
    pub const BATFET_OPEN: u8 = 1 << 4;
    pub const BATTERY_PRESENT: u8 = 1 << 3;
    pub const BATTERY_ACTIVE: u8 = 1 << 2;
    pub const THERMAL_REGULATION: u8 = 1 << 1;
    pub const CURRENT_LIMIT: u8 = 1 << 0;
}

/// REG 01 — PMU status2.
#[allow(missing_docs)] // bit table
pub mod status2 {
    pub const SYSTEM_ON: u8 = 1 << 4;
    pub const VINDPM: u8 = 1 << 3;
}

/// REG 10 — PMU common configuration, from datasheet V1.4 (6.13.2.7). Bits
/// 0 and 1 act when written as 1 and clear themselves; bit 4, undocumented
/// and 1 by default, is kept as read.
pub mod common {
    /// Write 1: soft power-off, every rail off.
    pub const PWROFF: u8 = 1 << 0;
    /// Write 1: restart, every rail off and back on.
    pub const RESTART: u8 = 1 << 1;
    /// PWROK pulled low from outside restarts the PMU, as `RESTART` does.
    /// 0 by default.
    pub const PWROK_RESTART: u8 = 1 << 3;
    /// Rails discharged inside the PMU as they switch off. 1 by default.
    pub const OFF_DISCHARGE: u8 = 1 << 5;
}

/// REG 49 — IRQ Status 1, RW1C (write 1 to clear): the power button, which
/// the AXP2101 debounces and classifies in hardware.
#[allow(missing_docs)] // bit table
pub mod irq1 {
    pub const VBUS_INSERT: u8 = 1 << 7;
    pub const VBUS_REMOVE: u8 = 1 << 6;
    pub const BATTERY_INSERT: u8 = 1 << 5;
    pub const BATTERY_REMOVE: u8 = 1 << 4;
    pub const PWRON_SHORT_PRESS: u8 = 1 << 3;
    pub const PWRON_LONG_PRESS: u8 = 1 << 2;
    pub const PWRON_NEGATIVE_EDGE: u8 = 1 << 1;
    pub const PWRON_POSITIVE_EDGE: u8 = 1 << 0;
}

/// REG 30 — ADC channel enable.
#[allow(missing_docs)] // register table
pub mod adc_ch {
    pub const VBAT: u8 = 1 << 0;
    pub const TS: u8 = 1 << 1;
    pub const VBUS: u8 = 1 << 2;
    pub const VSYS: u8 = 1 << 3;
    pub const TDIE: u8 = 1 << 4;
}

/// Battery current direction, status2 bits `[6:5]`.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BatteryDirection {
    /// No battery current.
    Standby,
    /// Current into the battery.
    Charging,
    /// Current out of the battery.
    Discharging,
    /// Value the datasheet does not define.
    Reserved,
}

/// Charging state, status2 bits `[2:0]`.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ChargeState {
    /// Trickle charge (deeply discharged battery).
    TrickleCharge,
    /// Pre-charge.
    PreCharge,
    /// Constant-current phase.
    ConstantCurrent,
    /// Constant-voltage phase.
    ConstantVoltage,
    /// Charge complete.
    Done,
    /// Charger idle.
    NotCharging,
    /// Value the datasheet does not define.
    Reserved,
}

/// What the power button did since the last poll.
#[derive(Copy, Clone, Debug)]
pub struct ButtonEvent {
    /// PWRON short press seen since last clear.
    pub short_press: bool,
    /// PWRON long press seen since last clear.
    pub long_press: bool,
    /// PWRON went down (negative edge).
    pub pressed: bool,
    /// PWRON came up (positive edge).
    pub released: bool,
    /// Raw IRQ status 1 byte.
    pub raw: u8,
}

impl ButtonEvent {
    /// True if any button event is set.
    pub fn any(&self) -> bool {
        self.raw & 0x0f != 0
    }
}

#[derive(Copy, Clone, Debug)]
/// A snapshot of the PMU: rails, charger, battery direction, voltages.
pub struct State {
    /// VBUS present and within range.
    pub vbus_good: bool,
    /// Battery detected.
    pub battery_present: bool,
    /// Battery in active (not standby) mode.
    pub battery_active: bool,
    /// Battery FET open (battery disconnected from system).
    pub batfet_open: bool,
    /// Charger in thermal regulation.
    pub thermal_regulation: bool,
    /// Input current limit active.
    pub current_limit: bool,
    /// System rail on.
    pub system_on: bool,
    /// Input voltage regulation (VINDPM) active.
    pub vindpm: bool,
    /// Which way battery current flows.
    pub direction: BatteryDirection,
    /// Charger state machine.
    pub charge: ChargeState,
    /// Battery charge, percent. Only meaningful once the fuel gauge has run.
    pub percent: u8,
    /// Raw REG 00.
    pub status1_raw: u8,
    /// Raw REG 01.
    pub status2_raw: u8,
}

/// AXP2101 PMU driver. Stateless: every call takes the bus.
pub struct Axp2101;

impl Axp2101 {
    /// Whether the PMU answers: an ACK, and status2 reporting the system
    /// on, as it must while it powers the SoC asking.
    pub fn present(bus: &mut Bus<'_>) -> bool {
        match i2c::read8(bus, ADDR, reg::STATUS2) {
            Some(s) => s & status2::SYSTEM_ON != 0,
            None => false,
        }
    }

    /// Read one register.
    pub fn read(bus: &mut Bus<'_>, r: u8) -> Option<u8> {
        i2c::read8(bus, ADDR, r)
    }

    /// Read the full state. All reads; nothing is modified.
    pub fn state(bus: &mut Bus<'_>) -> Option<State> {
        let s1 = i2c::read8(bus, ADDR, reg::STATUS1)?;
        let s2 = i2c::read8(bus, ADDR, reg::STATUS2)?;
        let percent = i2c::read8(bus, ADDR, reg::BATTERY_PERCENT)?;

        Some(State {
            vbus_good: s1 & status1::VBUS_GOOD != 0,
            battery_present: s1 & status1::BATTERY_PRESENT != 0,
            battery_active: s1 & status1::BATTERY_ACTIVE != 0,
            batfet_open: s1 & status1::BATFET_OPEN != 0,
            thermal_regulation: s1 & status1::THERMAL_REGULATION != 0,
            current_limit: s1 & status1::CURRENT_LIMIT != 0,
            system_on: s2 & status2::SYSTEM_ON != 0,
            vindpm: s2 & status2::VINDPM != 0,
            direction: match (s2 >> 5) & 0x03 {
                0 => BatteryDirection::Standby,
                1 => BatteryDirection::Charging,
                2 => BatteryDirection::Discharging,
                _ => BatteryDirection::Reserved,
            },
            charge: match s2 & 0x07 {
                0 => ChargeState::TrickleCharge,
                1 => ChargeState::PreCharge,
                2 => ChargeState::ConstantCurrent,
                3 => ChargeState::ConstantVoltage,
                4 => ChargeState::Done,
                5 => ChargeState::NotCharging,
                _ => ChargeState::Reserved,
            },
            percent,
            status1_raw: s1,
            status2_raw: s2,
        })
    }

    /// Which ADC channels the PMU currently samples.
    pub fn adc_channels(bus: &mut Bus<'_>) -> Option<u8> {
        i2c::read8(bus, ADDR, reg::ADC_CHANNEL_CTRL)
    }

    /// Read a 14-bit ADC value: bits `[13:8]` in the high register's
    /// `[5:0]` (its top two are `ch_dbg_en`), `[7:0]` in the low one. One
    /// burst: two `read8` calls can straddle the PMU's update of the pair.
    fn adc14(bus: &mut Bus<'_>, hi: u8) -> Option<u16> {
        let mut b = [0u8; 2];
        if !i2c::read8_n(bus, ADDR, hi, &mut b) {
            return None;
        }
        Some((((b[0] as u16) & 0x3f) << 8) | b[1] as u16)
    }

    /// Battery voltage in millivolts. `None` while the VBAT channel is off,
    /// when it reads a stale or zero value that looks real.
    pub fn battery_mv(bus: &mut Bus<'_>) -> Option<u16> {
        let ch = Self::adc_channels(bus)?;
        if ch & adc_ch::VBAT == 0 {
            return None;
        }
        Self::adc14(bus, reg::ADC_VBAT_H)
    }

    /// VBUS voltage in millivolts. `None` until the ADC channel is enabled.
    pub fn vbus_mv(bus: &mut Bus<'_>) -> Option<u16> {
        let ch = Self::adc_channels(bus)?;
        if ch & adc_ch::VBUS == 0 {
            return None;
        }
        Self::adc14(bus, reg::ADC_VBUS_H)
    }

    /// System rail voltage in millivolts. `None` until the ADC channel is enabled.
    pub fn vsys_mv(bus: &mut Bus<'_>) -> Option<u16> {
        let ch = Self::adc_channels(bus)?;
        if ch & adc_ch::VSYS == 0 {
            return None;
        }
        Self::adc14(bus, reg::ADC_VSYS_H)
    }

    /// Which DCDC rails are on. REG 80 bits `[4:0]` = DCDC5..DCDC1.
    pub fn dcdc_enabled(bus: &mut Bus<'_>) -> Option<u8> {
        i2c::read8(bus, ADDR, reg::DCDC_ONOFF).map(|v| v & 0x1f)
    }

    /// Which LDOs are on. REG 90, plus DLDO2 from REG 91 bit 0.
    pub fn ldo_enabled(bus: &mut Bus<'_>) -> Option<(u8, u8)> {
        let a = i2c::read8(bus, ADDR, reg::LDO_ONOFF0)?;
        let b = i2c::read8(bus, ADDR, reg::LDO_ONOFF1)?;
        Some((a, b & 0x01))
    }

    /// Whether JEITA charge control is on (REG 58 bit 0), and the raw JEITA
    /// CV configuration (REG 59). JEITA derates charging at temperature
    /// extremes; without it a lithium cell can be charged at 0 degC or
    /// 50 degC.
    pub fn jeita(bus: &mut Bus<'_>) -> Option<(bool, u8)> {
        let en = i2c::read8(bus, ADDR, reg::JEITA_ENABLE)?;
        let cv = i2c::read8(bus, ADDR, reg::JEITA_CV)?;
        Some((en & 0x01 != 0, cv))
    }

    /// The four charge-temperature thresholds, raw: scaling differs per
    /// register (`reg`), and degrees need the board's TS-pin resistors.
    pub fn temp_thresholds(bus: &mut Bus<'_>) -> Option<(u8, u8, u8, u8)> {
        Some((
            i2c::read8(bus, ADDR, reg::VLTF_CHG)?,
            i2c::read8(bus, ADDR, reg::VHTF_CHG)?,
            i2c::read8(bus, ADDR, reg::JEITA_COOL)?,
            i2c::read8(bus, ADDR, reg::JEITA_WARM)?,
        ))
    }

    /// Read the three IRQ status registers; `IRQ_STATUS1` has the power
    /// button's events.
    pub fn irq_status(bus: &mut Bus<'_>) -> Option<(u8, u8, u8)> {
        Some((
            i2c::read8(bus, ADDR, reg::IRQ_STATUS0)?,
            i2c::read8(bus, ADDR, reg::IRQ_STATUS1)?,
            i2c::read8(bus, ADDR, reg::IRQ_STATUS2)?,
        ))
    }

    /// Clear IRQ bits (RW1C: a 1 clears). Events latch, so without this the
    /// same press is reported forever.
    ///
    /// # Safety
    ///
    /// Writes to the PMU only to acknowledge interrupts: no rail and no
    /// charge setting.
    pub unsafe fn clear_irq(bus: &mut Bus<'_>, s0: u8, s1: u8, s2: u8) -> bool {
        i2c::write8(bus, ADDR, reg::IRQ_STATUS0, s0)
            && i2c::write8(bus, ADDR, reg::IRQ_STATUS1, s1)
            && i2c::write8(bus, ADDR, reg::IRQ_STATUS2, s2)
    }

    /// Poll the power button: its events, with every pending IRQ bit
    /// cleared.
    ///
    /// # Safety
    ///
    /// Clears IRQ bits, as `clear_irq`.
    pub unsafe fn poll_button(bus: &mut Bus<'_>) -> Option<ButtonEvent> {
        let (s0, s1, s2) = Self::irq_status(bus)?;
        let ev = ButtonEvent {
            short_press: s1 & irq1::PWRON_SHORT_PRESS != 0,
            long_press: s1 & irq1::PWRON_LONG_PRESS != 0,
            pressed: s1 & irq1::PWRON_NEGATIVE_EDGE != 0,
            released: s1 & irq1::PWRON_POSITIVE_EDGE != 0,
            raw: s1,
        };
        if s0 != 0 || s1 != 0 || s2 != 0 {
            // SAFETY: this function's contract: acknowledging IRQs only.
            unsafe { Self::clear_irq(bus, s0, s1, s2) };
        }
        Some(ev)
    }

    /// Enable ADC channels so voltage readings mean something.
    ///
    /// # Safety
    ///
    /// A write to the chip powering the SoC, though only to measurement
    /// channels: no rail (REG 80, REG 90) is touched.
    pub unsafe fn enable_adc(bus: &mut Bus<'_>, channels: u8) -> bool {
        let cur = match i2c::read8(bus, ADDR, reg::ADC_CHANNEL_CTRL) {
            Some(v) => v,
            None => return false,
        };
        i2c::write8(bus, ADDR, reg::ADC_CHANNEL_CTRL, cur | (channels & 0x1f))
    }

    /// Set (`on`) or clear configuration bits in REG 10, keeping the others;
    /// REG 10 before and after. [`common::PWROFF`] and [`common::RESTART`]
    /// are always written as 0, so nothing switches off when this runs.
    ///
    /// # Safety
    ///
    /// A write to the chip powering the SoC. No rail switches now, but the
    /// bits change what the PMU does later: with [`common::PWROK_RESTART`],
    /// PWROK pulled low cycles every rail.
    pub unsafe fn set_common(bus: &mut Bus<'_>, bits: u8, on: bool) -> Option<(u8, u8)> {
        let before = i2c::read8(bus, ADDR, reg::COMMON_CONFIG)?;
        let set = if on { before | bits } else { before & !bits };
        let want = set & !(common::PWROFF | common::RESTART);
        if want != before && !i2c::write8(bus, ADDR, reg::COMMON_CONFIG, want) {
            return None;
        }
        Some((before, i2c::read8(bus, ADDR, reg::COMMON_CONFIG)?))
    }
}
