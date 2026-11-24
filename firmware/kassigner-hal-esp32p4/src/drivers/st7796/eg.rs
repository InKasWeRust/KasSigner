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

//! `embedded-graphics` `DrawTarget` for the panel: fonts and primitives in
//! `no_std` Rust without allocation, for text such as an address the user
//! checks character by character.
//!
//! * `fill_solid` -> one window, one colour repeated
//! * `fill_contiguous` -> one window of streamed pixels if all on the
//!   panel, else per pixel
//! * `draw_iter` -> one window per pixel (slow; for scattered pixels)
//!
//! Colours are packed by `cmds::rgb565`, so the byte order is decided in
//! one place.

use super::{cmds, Display, NotDrawn};
use crate::board::{LCD_H, LCD_W};
use embedded_graphics::{
    pixelcolor::{Rgb565, RgbColor},
    prelude::*,
    primitives::Rectangle,
};

#[inline]
fn pack(c: Rgb565) -> u16 {
    cmds::rgb565(c.r() << 3, c.g() << 2, c.b() << 3)
}

impl OriginDimensions for Display<'_> {
    fn size(&self) -> Size {
        Size::new(LCD_W as u32, LCD_H as u32)
    }
}

impl DrawTarget for Display<'_> {
    type Color = Rgb565;
    type Error = NotDrawn;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(p, c) in pixels {
            if p.x < 0 || p.y < 0 || p.x >= LCD_W as i32 || p.y >= LCD_H as i32 {
                continue;
            }
            let (x, y) = (p.x as u16, p.y as u16);
            self.window(x, y, x, y)?;
            self.stream(core::iter::once(pack(c)))?;
        }
        Ok(())
    }

    fn fill_contiguous<I>(&mut self, area: &Rectangle, colors: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Self::Color>,
    {
        let bb = self.bounding_box();
        if area.size.width == 0 || area.size.height == 0 {
            return Ok(());
        }
        if bb.intersection(area) != *area {
            // Partly off the panel: the colours cover the whole area, so
            // go pixel by pixel, clipped.
            return self.draw_iter(area.points().zip(colors).map(|(p, c)| Pixel(p, c)));
        }
        let x0 = area.top_left.x as u16;
        let y0 = area.top_left.y as u16;
        let x1 = x0 + area.size.width as u16 - 1;
        let y1 = y0 + area.size.height as u16 - 1;
        let n = (area.size.width * area.size.height) as usize;
        self.window(x0, y0, x1, y1)?;
        self.stream(colors.into_iter().take(n).map(pack))
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Self::Color) -> Result<(), Self::Error> {
        let a = self.bounding_box().intersection(area);
        if a.size.width == 0 || a.size.height == 0 {
            return Ok(());
        }
        self.fill_rect(
            a.top_left.x as u16,
            a.top_left.y as u16,
            a.size.width as u16,
            a.size.height as u16,
            pack(color),
        )
    }

    fn clear(&mut self, color: Self::Color) -> Result<(), Self::Error> {
        self.fill(pack(color))
    }
}
