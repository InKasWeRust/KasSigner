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

//! The cell, and what a board can say about it.
//!
//! The M5 and the P4 ask their AXP2101: whether a cell is fitted, its
//! voltage, and which way current flows. The Waveshare has no PMU and reads
//! only a voltage, through a divider on the SAR ADC.
//!
//! A board that cannot measure the current's direction reports
//! [`ChargeState::Unknown`], not a guess from the voltage, and one that
//! cannot tell whether a cell is fitted says `present: None`. On the
//! Waveshare a missing cell reads as a full one: the divider then sees the
//! charger's own float, about 4.2 V.
//!
//! [`Reading::Implausible`], a value below any real cell, is a converter
//! that is not working or has nothing connected: neither a low battery nor
//! a full one.

/// Which way current is flowing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargeState {
    /// Charging from USB.
    Charging,
    /// Running on the cell.
    Discharging,
    /// Standby, a code the board does not name, or a board that cannot tell.
    Unknown,
}

/// A measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatteryStatus {
    /// Whether a cell is fitted, or `None` for a board that cannot tell.
    pub present: Option<bool>,
    /// Cell voltage.
    pub voltage_mv: u16,
    /// Estimated charge, 0 to 100.
    pub percentage: u8,
    /// Current direction.
    pub state: ChargeState,
}

/// What a read produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reading {
    /// A believable measurement.
    Battery(BatteryStatus),
    /// A value below any real cell, with the raw converter output behind it.
    Implausible { raw: u16 },
}

/// Why a read failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The board's measurement path failed. On a PMU, a bus transfer.
    Io,
}

/// A board's battery.
pub trait Battery {
    /// Measure the cell.
    ///
    /// # Errors
    ///
    /// `Io` if the board could not measure.
    fn read(&mut self) -> Result<Reading, Error>;
}

/// The AXP2101's reading, which the M5 and the P4 both take: one curve, so
/// both units show the same percentage for the same voltage, and the
/// current's direction as the PMU's status register gives it. The
/// Waveshare has no PMU and keeps its own curve.
pub mod axp2101 {
    use super::ChargeState;

    /// Millivolts read as empty.
    pub const EMPTY_MV: u16 = 3200;
    /// Millivolts read as full.
    pub const FULL_MV: u16 = 4100;

    /// The percentage for a voltage: linear from [`EMPTY_MV`] at 0% to
    /// [`FULL_MV`] at 100%.
    pub const fn percent_for(mv: u16) -> u8 {
        if mv <= EMPTY_MV {
            0
        } else if mv >= FULL_MV {
            100
        } else {
            ((mv - EMPTY_MV) as u32 * 100 / (FULL_MV - EMPTY_MV) as u32) as u8
        }
    }

    /// The current's direction from `PMU_STATUS2`'s bits 6:5: 1 charging,
    /// 2 discharging, anything else unknown.
    pub const fn state_of(status2: u8) -> ChargeState {
        match (status2 >> 5) & 0x03 {
            1 => ChargeState::Charging,
            2 => ChargeState::Discharging,
            _ => ChargeState::Unknown,
        }
    }
}
