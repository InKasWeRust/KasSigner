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

//! The cell, through the AXP2101, as the [`kassigner_hal::battery`] contract
//! has it, read as the M5 reads the same part: a status bit for a fitted
//! cell, two for the current's direction, and the converter's voltage, with
//! the percentage [`kassigner_hal::battery::axp2101`] gives both units. The
//! fuel gauge is not used: it means something only once it has learnt the
//! cell, and both units should say the same for the same voltage.
//!
//! The converter measures the cell once [`enable`] turns its channel on
//! (one write, no rail touched); until then [`read`] refuses.

use kassigner_hal::battery::axp2101::{percent_for, state_of};
use kassigner_hal::battery::{BatteryStatus, Error, Reading};

use crate::board::i2c::Bus;
use crate::cam::SharedBus;
use crate::drivers::axp2101::{adc_ch, reg, status1, Axp2101};

/// Turn on the converter's cell channel, on the unit's shared bus; whether
/// the PMU took it.
pub fn enable(bus: &SharedBus) -> bool {
    bus.try_borrow_mut()
        .is_ok_and(|mut bus| enable_on(&mut bus))
}

/// [`enable`] on a bus held whole, as the hardware test holds it.
pub fn enable_on(bus: &mut Bus<'_>) -> bool {
    // SAFETY: sets the cell's bit in the channel-enable register alone,
    // keeping the others; no rail or charge setting, as `enable_adc` asks.
    unsafe { Axp2101::enable_adc(bus, adc_ch::VBAT) }
}

/// Read the cell, on the unit's shared bus.
///
/// # Errors
///
/// `Io` when the bus is busy, a read fails, or the cell channel is off.
pub fn read(bus: &SharedBus) -> Result<Reading, Error> {
    read_on(&mut *bus.try_borrow_mut().map_err(|_| Error::Io)?)
}

/// [`read`] on a bus held whole, as the hardware test holds it.
///
/// # Errors
///
/// As [`read`].
pub fn read_on(bus: &mut Bus<'_>) -> Result<Reading, Error> {
    let s1 = Axp2101::read(bus, reg::STATUS1).ok_or(Error::Io)?;
    let s2 = Axp2101::read(bus, reg::STATUS2).ok_or(Error::Io)?;
    let voltage_mv = Axp2101::battery_mv(bus).ok_or(Error::Io)?;
    Ok(Reading::Battery(BatteryStatus {
        present: Some(s1 & status1::BATTERY_PRESENT != 0),
        voltage_mv,
        percentage: percent_for(voltage_mv),
        state: state_of(s2),
    }))
}
