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

//! The ST7796 behind `kassigner-hal`'s `Display`: a 480 by 320 panel,
//! landscape as the board is held, with `blit` and `fill` over the driver's
//! clipped window writes on SPI2 at [`crate::board::LCD_SPI_HZ`], 80 MHz,
//! and a backlight level, which [`crate::backlight`] sets through the LED
//! PWM controller on GPIO28.

use kassigner_hal::display::{Backlight, Display, Error, Rect, Size};

use crate::board::{LCD_H, LCD_W};
use crate::drivers::st7796;

/// The panel, landscape as the board is held.
pub const SIZE: Size = Size::new(LCD_W, LCD_H);

/// The display driver as the flow sees it.
pub struct Panel {
    lcd: st7796::Display<'static>,
}

impl Panel {
    /// Over an initialised driver.
    pub fn new(lcd: st7796::Display<'static>) -> Self {
        Self { lcd }
    }

    /// The driver, for the hardware test's own drawing.
    pub fn driver(&mut self) -> &mut st7796::Display<'static> {
        &mut self.lcd
    }
}

impl Display for Panel {
    fn size(&self) -> Size {
        SIZE
    }

    fn blit(&mut self, rect: Rect, pixels: &[u16]) -> Result<(), Error> {
        self.check(rect, Some(pixels))?;
        self.lcd
            .push_pixels(rect.x, rect.y, rect.width, rect.height, pixels)
            .map_err(|_| Error::Io)
    }

    fn fill(&mut self, rect: Rect, color: u16) -> Result<(), Error> {
        self.check(rect, None)?;
        self.lcd
            .fill_rect(rect.x, rect.y, rect.width, rect.height, color)
            .map_err(|_| Error::Io)
    }

    /// Through the LED PWM controller on GPIO28: see [`crate::backlight`].
    fn set_backlight(&mut self, level: Backlight) -> Result<(), Error> {
        crate::backlight::set(level);
        Ok(())
    }
}
