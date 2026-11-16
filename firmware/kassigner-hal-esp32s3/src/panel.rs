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

//! [`kassigner_hal::display::Display`] over a `mipidsi` panel.
//!
//! Both units drive their panel through `mipidsi`, generic over the
//! interface it writes to, so one module serves both. What differs is the
//! backlight, behind [`Backlight`].
//!
//! # The bounds check is the point
//!
//! `mipidsi::Display::set_pixels` says: *no bounds checking is performed on
//! these values. Using out of range values will result in undefined
//! behavior.* So every write first goes through
//! [`kassigner_hal::display::Display::check`]: a rectangle that leaves the
//! panel, or a buffer that does not match one, never reaches the driver.
//!
//! What is checked is the bounds, not the absence of `unsafe` in the path:
//! there is none in this file and plenty in the SPI driver a unit hands to
//! [`Panel::new`].

use embedded_graphics_core::pixelcolor::{raw::RawU16, Rgb565};
use embedded_hal::digital::OutputPin;
use kassigner_hal::display::{Backlight as Level, Display, Error, Rect, Size};
use mipidsi::interface::{Interface, InterfacePixelFormat};
use mipidsi::models::Model;

/// A board's backlight.
///
/// The Waveshare drives an LEDC channel, where duty zero is dark. The M5
/// sets an AXP2101 rail voltage whose lowest step is still lit, so
/// [`Level::Off`] there disables the rail; hence `Level` is an enum.
pub trait Backlight {
    /// Set the level.
    ///
    /// # Errors
    ///
    /// `Error::Io` if the board's mechanism failed: on the M5 a PMU register
    /// write over I2C.
    fn set(&mut self, level: Level) -> Result<(), Error>;
}

/// A `mipidsi` panel behind [`Display`]. The trait bounds repeat
/// `mipidsi::Display`'s own, which a field of that type needs.
pub struct Panel<DI, M, RST, BL>
where
    DI: Interface,
    M: Model,
    M::ColorFormat: InterfacePixelFormat<DI::Word>,
    RST: OutputPin,
{
    display: mipidsi::Display<DI, M, RST>,
    backlight: BL,
    size: Size,
}

impl<DI, M, RST, BL> Panel<DI, M, RST, BL>
where
    DI: Interface,
    M: Model<ColorFormat = Rgb565>,
    Rgb565: InterfacePixelFormat<DI::Word>,
    RST: OutputPin,
    BL: Backlight,
{
    /// Wrap a built panel. `size` is its dimensions in the orientation it was
    /// built with, fixed for the handle's life: rotation is set at
    /// construction, not per draw.
    pub fn new(display: mipidsi::Display<DI, M, RST>, backlight: BL, size: Size) -> Self {
        Self {
            display,
            backlight,
            size,
        }
    }

    /// The underlying driver, for what the trait does not expose. Anything
    /// reached through it is board-specific, and unchecked for bounds.
    pub fn inner(&mut self) -> &mut mipidsi::Display<DI, M, RST> {
        &mut self.display
    }

    /// A rectangle as `mipidsi`'s inclusive corners: width `w` at `x` ends at
    /// `x + w - 1`. `None` where that would underflow: zero width at column
    /// 0, or zero height at row 0. Any other empty rectangle ends before it
    /// starts, and no pixels are sent.
    fn corners(rect: Rect) -> Option<(u16, u16, u16, u16)> {
        let ex = rect.x.checked_add(rect.width)?.checked_sub(1)?;
        let ey = rect.y.checked_add(rect.height)?.checked_sub(1)?;
        Some((rect.x, rect.y, ex, ey))
    }
}

impl<DI, M, RST, BL> Display for Panel<DI, M, RST, BL>
where
    DI: Interface,
    M: Model<ColorFormat = Rgb565>,
    Rgb565: InterfacePixelFormat<DI::Word>,
    RST: OutputPin,
    BL: Backlight,
{
    fn size(&self) -> Size {
        self.size
    }

    fn blit(&mut self, rect: Rect, pixels: &[u16]) -> Result<(), Error> {
        // `set_pixels` does no bounds checking: this is the check.
        self.check(rect, Some(pixels))?;

        let Some((sx, sy, ex, ey)) = Self::corners(rect) else {
            // Zero width at column 0 or zero height at row 0: nothing to draw.
            return Ok(());
        };

        self.display
            .set_pixels(
                sx,
                sy,
                ex,
                ey,
                pixels.iter().map(|c| Rgb565::from(RawU16::new(*c))),
            )
            .map_err(|_| Error::Io)
    }

    fn fill(&mut self, rect: Rect, color: u16) -> Result<(), Error> {
        self.check(rect, None)?;

        let Some((sx, sy, ex, ey)) = Self::corners(rect) else {
            return Ok(());
        };

        let c = Rgb565::from(RawU16::new(color));
        self.display
            .set_pixels(sx, sy, ex, ey, core::iter::repeat_n(c, rect.pixels()))
            .map_err(|_| Error::Io)
    }

    fn set_backlight(&mut self, level: Level) -> Result<(), Error> {
        self.backlight.set(level)
    }
}
