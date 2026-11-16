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

//! The Waveshare backlight.
//!
//! LEDC low-speed timer 1, channel 1, on GPIO1. Startup configures the
//! channel's frequency and resolution; this only moves the duty.
//!
//! # Off is duty zero, and genuinely dark
//!
//! Not so on the M5, whose AXP2101 rail's lowest step, 2.2 V, is still lit,
//! so [`Level::Off`] there disables the rail. That is why
//! `kassigner_hal::display::Backlight` is an enum, not a `u8`; here `Off` is
//! `0` and every level is itself.
//!
//! # Registers, from the technical reference manual
//!
//! `LEDC_LSCH1_DUTY_REG` holds the duty in Q4 fixed point, so a duty of `n`
//! is written `n << 4`. `LEDC_LSCH1_CONF1_REG` bit 31, `DUTY_START`, begins
//! the duty transfer; `LEDC_LSCH1_CONF0_REG` bit 4, `PARA_UP`, latches the
//! new parameters at the next cycle boundary rather than mid-pulse. All
//! three writes are needed, in that order: without `DUTY_START` and
//! `PARA_UP` a duty sits in the shadow register and never reaches the
//! output.

use kassigner_hal::display::{Backlight as Level, Error};

/// LEDC peripheral base.
const LEDC_BASE: u32 = 0x6001_9000;
/// `LEDC_LSCH1_CONF0_REG`.
const LSCH1_CONF0: u32 = LEDC_BASE + 0x14;
/// `LEDC_LSCH1_DUTY_REG`.
const LSCH1_DUTY: u32 = LEDC_BASE + 0x1C;
/// `LEDC_LSCH1_CONF1_REG`.
const LSCH1_CONF1: u32 = LEDC_BASE + 0x20;

/// `DUTY_START`, bit 31 of `CONF1`.
const DUTY_START: u32 = 1 << 31;
/// `PARA_UP`, bit 4 of `CONF0`.
const PARA_UP: u32 = 1 << 4;
/// The duty register is Q4: four fractional bits.
const DUTY_SHIFT: u32 = 4;

/// The backlight: a unit struct, as the channel is registers and there is
/// nothing to own. The LEDC channel must already be configured at startup.
#[derive(Clone, Copy, Debug)]
pub struct WaveshareBacklight;

/// The duty value for a level, apart so a host test can check it: a wrong
/// shift would silently give a sixteenth of the brightness.
pub const fn duty_for(level: Level) -> u32 {
    match level {
        Level::Off => 0,
        Level::Level(n) => (n as u32) << DUTY_SHIFT,
    }
}

impl crate::panel::Backlight for WaveshareBacklight {
    fn set(&mut self, level: Level) -> Result<(), Error> {
        let duty = duty_for(level);
        // SAFETY: volatile accesses to LEDC channel 1 registers at the
        // manual's addresses. `CONF0` is read-modify-write, as it also holds
        // the timer selection and output enable startup set. `DUTY` and
        // `CONF1` are written whole: every field in them is this operation's.
        unsafe {
            core::ptr::write_volatile(LSCH1_DUTY as *mut u32, duty);
            core::ptr::write_volatile(LSCH1_CONF1 as *mut u32, DUTY_START);
            let conf0 = core::ptr::read_volatile(LSCH1_CONF0 as *const u32);
            core::ptr::write_volatile(LSCH1_CONF0 as *mut u32, conf0 | PARA_UP);
        }
        Ok(())
    }
}
