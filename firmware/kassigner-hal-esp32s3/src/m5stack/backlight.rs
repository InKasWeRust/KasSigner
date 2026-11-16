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

//! The M5 backlight: the AXP2101's DLDO1 rail. No PWM: brightness is the
//! rail voltage, 500 mV plus 100 mV a code.
//!
//! Levels 0 to 255 map onto codes `0x11` to `0x1C`, 2.2 V to 3.3 V, the
//! range measured as visible on the unit, so the lowest level is still lit.
//! `Level::Off` clears DLDO1's enable bit, as M5GFX's
//! `Light_M5StackCoreS3::setBrightness` does for zero (bit 7 of `0x90`); the
//! next level sets the voltage before the bit, so the panel comes back at
//! that level rather than flashing at the last.
//!
//! Off here is a rail switch, an I2C transfer that can fail, so `set` can
//! return `Io`; on the Waveshare board it is duty zero.

use embedded_hal::i2c::I2c;
use kassigner_hal::display::{Backlight as Level, Error};

use super::pmu;

/// The dimmest code that still lights the panel: 2.2 V.
pub const CODE_MIN: u8 = 0x11;
/// Full brightness: 3.3 V.
pub const CODE_MAX: u8 = 0x1C;

/// The DLDO1 code for a level: [`CODE_MIN`] plus `level * 11 / 255`, so
/// levels 0 to 23 give the minimum and only 255 the maximum.
pub const fn code_for(level: u8) -> u8 {
    let range = CODE_MAX - CODE_MIN;
    if level <= 1 {
        return CODE_MIN;
    }
    let step = (level as u16 * range as u16 / 255) as u8;
    if step < range {
        CODE_MIN + step
    } else {
        CODE_MAX
    }
}

/// The backlight.
///
/// Owns a handle to the shared I2C bus. The rail must already have been set
/// up by [`pmu::init_axp2101`], which leaves it on at full brightness.
pub struct M5Backlight<I> {
    i2c: I,
}

impl<I: I2c> M5Backlight<I> {
    /// Take a bus handle.
    pub fn new(i2c: I) -> Self {
        Self { i2c }
    }

    /// Give the bus handle back.
    pub fn release(self) -> I {
        self.i2c
    }
}

impl<I: I2c> crate::panel::Backlight for M5Backlight<I> {
    fn set(&mut self, level: Level) -> Result<(), Error> {
        match level {
            Level::Off => {
                pmu::set_rails(&mut self.i2c, pmu::BACKLIGHT, false).map_err(|_| Error::Io)
            }
            Level::Level(n) => {
                // The voltage first, so a panel coming back from `Off`
                // lights at this level.
                pmu::write_reg(&mut self.i2c, pmu::AXP2101, pmu::REG_DLDO1_V, code_for(n))
                    .map_err(|_| Error::Io)?;
                // Then the rail, which writes nothing when it is already on.
                pmu::set_rails(&mut self.i2c, pmu::BACKLIGHT, true).map_err(|_| Error::Io)
            }
        }
    }
}
