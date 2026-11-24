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

//! OV5647 driver over the shared I2C bus.

use super::ov5647::{self, reg, ADDR};
use crate::board::i2c::{self, Bus};
use esp_hal::delay::Delay;

/// OV5647 sensor driver over SCCB. Stateless: every call takes the bus.
pub struct Ov5647;

/// Why sensor configuration failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// This many writes of the reset and the mode table were not ACKed.
    ModeTableIncomplete(u32),
    /// This many writes switching the stream on or off were not ACKed.
    StreamSwitch(u32),
}

/// Write `table`, counting the writes the sensor did not ACK.
fn write_all(bus: &mut Bus<'_>, table: &[(u16, u8)]) -> u32 {
    let mut failures = 0u32;
    for (r, v) in table {
        if !i2c::write16(bus, ADDR, *r, *v) {
            failures += 1;
        }
    }
    failures
}

/// `Ok` when nothing failed, else `error` with the count.
fn counted(failures: u32, error: fn(u32) -> Error) -> Result<(), Error> {
    if failures == 0 {
        Ok(())
    } else {
        Err(error(failures))
    }
}

impl Ov5647 {
    /// Read the chip ID from 0x300A/0x300B. Expect 0x5647.
    pub fn chip_id(bus: &mut Bus<'_>) -> Option<u16> {
        let hi = i2c::read16(bus, ADDR, reg::CHIP_ID_HI)?;
        let lo = i2c::read16(bus, ADDR, reg::CHIP_ID_LO)?;
        Some(((hi as u16) << 8) | lo as u16)
    }

    /// Whether the sensor at the OV5647 address reads back its chip ID.
    pub fn present(bus: &mut Bus<'_>) -> bool {
        Self::chip_id(bus) == Some(ov5647::CHIP_ID)
    }

    /// Reset, then load the 480x480 RAW8 mode and the boot defaults, before
    /// the D-PHY leaves reset.
    ///
    /// # Errors
    /// `ModeTableIncomplete(n)` if `n` of those writes, the reset's
    /// included, were not ACKed; the sensor's mode is then undefined until
    /// a reset. Linux's driver holds the software reset to its ACK too: it
    /// writes it in its mode tables and stops at the first write refused.
    pub fn configure(bus: &mut Bus<'_>, delay: &Delay) -> Result<(), Error> {
        // Sleep and software reset, then the clock lane once it is back.
        let mut failures = write_all(bus, &ov5647::RESET_REGS[..2]);
        delay.delay_millis(10);
        failures += write_all(bus, &ov5647::RESET_REGS[2..]);
        failures += write_all(bus, ov5647::MODE_480X480_RAW8);
        failures += write_all(bus, ov5647::BOOT_DEFAULTS);
        delay.delay_millis(10);
        counted(failures, Error::ModeTableIncomplete)
    }

    /// Start streaming, once the D-PHY is up.
    ///
    /// # Errors
    /// `StreamSwitch(n)` if `n` of its writes were not ACKed: the sensor
    /// may not be streaming.
    pub fn stream_on(bus: &mut Bus<'_>) -> Result<(), Error> {
        counted(write_all(bus, ov5647::STREAM_ON), Error::StreamSwitch)
    }

    /// Stop streaming and enter software standby.
    ///
    /// # Errors
    /// `StreamSwitch(n)` if `n` of its writes were not ACKed: the sensor
    /// may still be streaming.
    pub fn stream_off(bus: &mut Bus<'_>) -> Result<(), Error> {
        counted(write_all(bus, ov5647::STREAM_OFF), Error::StreamSwitch)
    }

    /// Current exposure in lines and gain out of 1023; gain at 1023 means
    /// the loop has saturated on a dark scene.
    pub fn exposure(bus: &mut Bus<'_>) -> Option<(u32, u32)> {
        let e2 = i2c::read16(bus, ADDR, reg::EXPOSURE_HI)? as u32;
        let e1 = i2c::read16(bus, ADDR, reg::EXPOSURE_HI + 1)? as u32;
        let e0 = i2c::read16(bus, ADDR, reg::EXPOSURE_HI + 2)? as u32;
        let g1 = i2c::read16(bus, ADDR, reg::GAIN_HI)? as u32;
        let g0 = i2c::read16(bus, ADDR, reg::GAIN_HI + 1)? as u32;
        Some((
            (((e2 & 0x0F) << 12) | (e1 << 4) | (e0 >> 4)),
            (g1 << 8) | g0,
        ))
    }
}
