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

//! How the M5 panel is built: what it needs, as constants, so whoever owns
//! the SPI bus (the unit's bring-up, a test binary) cannot build it
//! otherwise. The adapter is [`crate::panel::Panel`], shared with the
//! Waveshare unit.
//!
//! # No reset pin
//!
//! GPIO14 is `I2S_DATI`, the microphone's data line; the panel's reset,
//! `LCD_RST`, is expander line `P1.1`, pulsed in
//! [`super::pmu::AW_SEQUENCE`]. So the panel is built with
//! `mipidsi::NoResetPin`, and `mipidsi` sends a software reset instead.
//!
//! # Colours are inverted and in BGR order
//!
//! Both are panel facts; M5Stack's own driver sets inversion on as well.
//!
//! # Turned 180 degrees
//!
//! The ILI9342C is 320x240 landscape natively, so the turn moves the origin,
//! not the size. Touch makes the same turn: [`super::touch::rotate`].
//!
//! # Only the ILI9342C is supported
//!
//! Recent CoreS3 units ship an ILI9342E. M5Stack's M5GFX tells the two apart
//! by the touch controller's firmware ID, register `0xA6` at `0x38` with
//! vendor `0x11` in `0xA8`: `0x10` is the C, `0x12` the E, which gets extra
//! panel commands after the normal initialisation. Nothing has been tried on
//! an E.

use kassigner_hal::display::Size;
use mipidsi::options::{ColorInversion, ColorOrder, Orientation, Rotation};

/// The panel's native size.
pub const NATIVE: Size = Size::new(320, 240);

/// The size a caller draws against. The same: the turn is 180 degrees.
pub const SIZE: Size = Size::new(320, 240);

/// The panel's mounting.
pub const ROTATION: Rotation = Rotation::Deg180;

/// Colour order. BGR.
pub const COLOR_ORDER: ColorOrder = ColorOrder::Bgr;

/// Colour inversion. On.
pub const INVERSION: ColorInversion = ColorInversion::Inverted;

/// The orientation to pass to the builder, so `init` writes it to `MADCTL`.
pub fn orientation() -> Orientation {
    Orientation::default().rotate(ROTATION)
}

/// Bytes of SPI scratch the interface batches pixels through.
pub const SPI_BUFFER_BYTES: usize = 512;

/// SPI clock, in MHz, in mode 0.
pub const SPI_MHZ: u32 = 40;
