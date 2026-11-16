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

//! How the Waveshare panel is built.
//!
//! The adapter presenting a `mipidsi` display as
//! [`kassigner_hal::display::Display`] is [`crate::panel`], shared by both
//! units. Here is the configuration this unit needs, as constants, since a
//! mistake in it gives a picture subtly wrong rather than absent.
//!
//! # The panel is mounted turned
//!
//! An ST7789T3 is 240x320 portrait natively. The board mounts it rotated, so
//! the driver is built at its native size with a 90 degree rotation, giving
//! 320x240 landscape: [`SIZE`], what every caller draws against.
//!
//! # Colours are inverted and in RGB order
//!
//! Both are panel facts. Without inversion the picture is a negative; the
//! wrong order swaps red and blue, easy to miss on a mostly monochrome
//! interface.
//!
//! # No reset pin
//!
//! The schematic draws `LCD_RST` from GPIO0, but the board does not fit the
//! link (R16), and GPIO0 is the BOOT button, which the firmware leaves
//! alone. The panel is built without a reset pin, and `mipidsi` sends a
//! software reset instead, after `unit::blank` has sent its own.
//!
//! # Why the constructor is not here
//!
//! Building the driver needs an `esp-hal` SPI device and two output pins,
//! and this module builds off the Xtensa target too. The device-only
//! `unit::bring_up` builds the display from these constants and hands it to
//! `crate::panel::Panel::new`.

use kassigner_hal::display::Size;
use mipidsi::options::{ColorInversion, ColorOrder, Orientation, Rotation};

/// The panel's native size, before rotation: what `mipidsi`'s
/// `display_size` takes, as the driver applies the rotation itself.
pub const NATIVE: Size = Size::new(240, 320);

/// The size a caller draws against, after rotation.
pub const SIZE: Size = Size::new(320, 240);

/// The rotation that turns the native portrait panel into landscape.
pub const ROTATION: Rotation = Rotation::Deg90;

/// Colour order. RGB, not BGR.
pub const COLOR_ORDER: ColorOrder = ColorOrder::Rgb;

/// Colour inversion. This panel needs it on.
pub const INVERSION: ColorInversion = ColorInversion::Inverted;

/// The orientation to pass to the builder.
pub fn orientation() -> Orientation {
    Orientation::default().rotate(ROTATION)
}

/// Bytes of SPI scratch: `mipidsi`'s SPI interface batches pixel writes
/// through a caller-provided buffer.
pub const SPI_BUFFER_BYTES: usize = 512;
