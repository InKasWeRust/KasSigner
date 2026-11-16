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

//! The panel: pixels into a rectangle, and a backlight. Screens are
//! drawings, the same on every board, and stay out of this trait so they
//! stay portable.
//!
//! Pixels are `u16` RGB565, what every panel here takes over SPI and the
//! buffers hold; a colour type would only be converted back at the boundary.
//!
//! [`Backlight`] is an enum so that off is not a dim level. The Waveshare
//! and the P4 drive an LEDC channel, where duty zero is dark. The M5 sets
//! the AXP2101's DLDO1 rail voltage, codes `0x11` to `0x1C` (2.2 V to
//! 3.3 V), where the lowest is still lit; off there clears the rail's enable
//! bit. On a unit that shows seed words and amounts, an idle timeout that
//! dims on one board and darkens on another is a privacy difference, so an
//! implementor handles [`Backlight::Off`] explicitly.

/// Panel dimensions, in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub width: u16,
    pub height: u16,
}

impl Size {
    pub const fn new(width: u16, height: u16) -> Self {
        Self { width, height }
    }

    /// Pixels in the whole panel.
    pub const fn pixels(&self) -> usize {
        self.width as usize * self.height as usize
    }
}

/// A rectangle, in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl Rect {
    pub const fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Pixels the rectangle covers.
    pub const fn pixels(&self) -> usize {
        self.width as usize * self.height as usize
    }

    /// Whether this rectangle fits inside a panel of `size`. An edge past
    /// `u16` is out of bounds, not wrapped.
    pub const fn fits(&self, size: Size) -> bool {
        match (
            self.x.checked_add(self.width),
            self.y.checked_add(self.height),
        ) {
            (Some(right), Some(bottom)) => right <= size.width && bottom <= size.height,
            _ => false,
        }
    }
}

/// How bright the backlight is; `Off` is not a low level (module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backlight {
    /// Dark: the panel unlit, not at its dimmest visible setting.
    Off,
    /// On, from 1 (the board's dimmest lit setting) to 255. Perceptual, not
    /// physical: each board maps it to a PWM duty or a rail voltage.
    Level(u8),
}

impl Backlight {
    /// A level, zero meaning off, for a `u8` from a settings screen. Named,
    /// not `From`, so the zero-means-off rule shows at the call site.
    pub const fn from_u8(v: u8) -> Self {
        if v == 0 {
            Backlight::Off
        } else {
            Backlight::Level(v)
        }
    }

    /// Whether the panel is lit.
    pub const fn is_lit(&self) -> bool {
        matches!(self, Backlight::Level(_))
    }
}

/// Why a draw failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The rectangle is not entirely on the panel.
    OutOfBounds { rect: Rect, size: Size },
    /// The pixel buffer does not match the rectangle: a caller bug, caught
    /// before a transfer could slice past the buffer's end.
    WrongLength { expected: usize, got: usize },
    /// The panel or its bus failed.
    Io,
}

/// A panel that takes RGB565 pixels.
pub trait Display {
    /// Panel dimensions, fixed for the handle's life (any rotation is set
    /// when the panel is built).
    fn size(&self) -> Size;

    /// Write pixels into a rectangle, row by row from the top left;
    /// `pixels.len()` must equal `rect.pixels()`.
    ///
    /// # Errors
    ///
    /// `OutOfBounds` if the rectangle leaves the panel, `WrongLength` if the
    /// buffer does not match it (both checked before anything is sent), `Io`
    /// on a bus failure.
    fn blit(&mut self, rect: Rect, pixels: &[u16]) -> Result<(), Error>;

    /// Fill a rectangle with one colour, which a panel can usually do without
    /// a buffer; clearing is the commonest draw on a unit with no framebuffer.
    ///
    /// # Errors
    ///
    /// As [`Display::blit`], without `WrongLength`.
    fn fill(&mut self, rect: Rect, color: u16) -> Result<(), Error>;

    /// Set the backlight.
    ///
    /// # Errors
    ///
    /// `Io` if the board's brightness control failed, such as a PMU bus
    /// write.
    fn set_backlight(&mut self, level: Backlight) -> Result<(), Error>;

    /// Clear the whole panel.
    fn clear(&mut self, color: u16) -> Result<(), Error> {
        let size = self.size();
        self.fill(Rect::new(0, 0, size.width, size.height), color)
    }

    /// Check a rectangle and a buffer before any byte goes to the panel.
    ///
    /// # Errors
    ///
    /// `OutOfBounds` or `WrongLength`.
    fn check(&self, rect: Rect, pixels: Option<&[u16]>) -> Result<(), Error> {
        let size = self.size();
        if !rect.fits(size) {
            return Err(Error::OutOfBounds { rect, size });
        }
        if let Some(p) = pixels {
            let expected = rect.pixels();
            if p.len() != expected {
                return Err(Error::WrongLength {
                    expected,
                    got: p.len(),
                });
            }
        }
        Ok(())
    }
}
