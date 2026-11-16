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

//! The M5 battery, as the AXP2101 reports it, not through the SoC's ADC.
//!
//! - `0x00` bit 3: a cell is present.
//! - `0x01` bits 6:5: current direction, 1 charging and 2 discharging.
//! - `0x34` bits 5:0 and `0x35`: cell voltage, fourteen bits, in millivolts,
//!   once [`super::pmu::AXP_SEQUENCE`] has enabled the converter.
//!
//! The percentage and the current's direction are
//! [`kassigner_hal::battery::axp2101`]'s, as the P4's are.
//! [`BatteryStatus::present`] is the PMU's own bit: when it is clear the
//! voltage is whatever the converter reads with no cell, and a caller should
//! show no battery rather than a percentage.
//!
//! VBAT is no entropy source: 32 samples 20 ms apart on battery read one
//! value.

use embedded_hal::i2c::I2c;
use kassigner_hal::battery::axp2101::{percent_for, state_of};
use kassigner_hal::battery::{Battery, Error, Reading};

use super::pmu::{self, AXP2101};

/// `PMU_STATUS1`: bit 3 is battery present.
const REG_STATUS1: u8 = 0x00;
/// `PMU_STATUS2`: bits 6:5 are the current direction.
const REG_STATUS2: u8 = 0x01;
/// Cell voltage, high six bits.
const REG_VBAT_H: u8 = 0x34;
/// Cell voltage, low eight bits.
const REG_VBAT_L: u8 = 0x35;

pub use kassigner_hal::battery::{BatteryStatus, ChargeState};

/// The cell voltage from its two registers.
pub const fn voltage_of(high: u8, low: u8) -> u16 {
    ((high as u16 & 0x3F) << 8) | low as u16
}

/// Read the battery.
///
/// # Errors
///
/// The bus error from the first read that failed.
pub fn read<I: I2c>(i2c: &mut I) -> Result<BatteryStatus, I::Error> {
    let status1 = pmu::read_reg(i2c, AXP2101, REG_STATUS1)?;
    let status2 = pmu::read_reg(i2c, AXP2101, REG_STATUS2)?;
    let high = pmu::read_reg(i2c, AXP2101, REG_VBAT_H)?;
    let low = pmu::read_reg(i2c, AXP2101, REG_VBAT_L)?;
    let voltage_mv = voltage_of(high, low);
    Ok(BatteryStatus {
        present: Some(status1 & 0x08 != 0),
        voltage_mv,
        percentage: percent_for(voltage_mv),
        state: state_of(status2),
    })
}

/// The battery, as a [`Battery`], over the bus the PMU is on.
pub struct M5Battery<I> {
    i2c: I,
}

impl<I: I2c> M5Battery<I> {
    /// Take the bus.
    pub fn new(i2c: I) -> Self {
        Self { i2c }
    }

    /// Give the bus back.
    pub fn release(self) -> I {
        self.i2c
    }
}

impl<I: I2c> Battery for M5Battery<I> {
    /// A PMU reading is always believable as a number; whether a cell is
    /// fitted is [`BatteryStatus::present`].
    fn read(&mut self) -> Result<Reading, Error> {
        read(&mut self.i2c)
            .map(Reading::Battery)
            .map_err(|_| Error::Io)
    }
}
