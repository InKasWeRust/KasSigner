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

//! The band: a strip of rows composed in RAM, then sent to the panel whole,
//! so nothing is seen half drawn.
//!
//! Drawing calls take panel coordinates and clip to the band: a screen is
//! one function that draws everything, and [`render`] calls it once per band.

use kassigner_hal::display::{Display, Error, Rect};

use super::color::blend;
use super::font::Font;
use super::gen::Icon;
use super::image::{Image, Sheet};

/// Rows of a region, in RAM.
pub struct Band<'b> {
    px: &'b mut [u16],
    x: i32,
    y: i32,
    width: i32,
    rows: i32,
    /// Where stretched pictures are kept, if the unit gave a store.
    stretched: Option<&'b mut Stretched>,
}

/// A span, clipped: `start..end` on one axis.
fn clip(from: i32, len: i32, lo: i32, hi: i32) -> Option<(i32, i32)> {
    let start = from.max(lo);
    let end = from.saturating_add(len).min(hi);
    (start < end).then_some((start, end))
}

impl Band<'_> {
    /// Whether any row from `top` to `bottom`, exclusive, is in this band.
    pub fn crosses(&self, top: i32, bottom: i32) -> bool {
        top < self.y + self.rows && bottom > self.y
    }

    /// The index of a panel pixel known to be inside.
    fn at(&self, x: i32, y: i32) -> usize {
        ((y - self.y) * self.width + (x - self.x)) as usize
    }

    /// Fill a rectangle.
    pub fn fill(&mut self, x: i32, y: i32, width: i32, height: i32, color: u16) {
        let (Some((x0, x1)), Some((y0, y1))) = (
            clip(x, width, self.x, self.x + self.width),
            clip(y, height, self.y, self.y + self.rows),
        ) else {
            return;
        };
        for row in y0..y1 {
            let (a, b) = (self.at(x0, row), self.at(x1 - 1, row) + 1);
            self.px[a..b].fill(color);
        }
    }

    /// Lay `color` over one pixel, `alpha` from 0 to 255.
    pub fn blend(&mut self, x: i32, y: i32, color: u16, alpha: u8) {
        if x < self.x || x >= self.x + self.width || y < self.y || y >= self.y + self.rows {
            return;
        }
        let at = self.at(x, y);
        self.px[at] = blend(self.px[at], color, alpha);
    }

    /// Fill a rectangle with rounded corners, their edges smoothed. Only
    /// corner pixels are sampled; the rest, most of a card, is filled a span
    /// at a time.
    ///
    /// An empty box returns first: a width or height of -2 or less would put
    /// the clamp's upper bound below its lower, a panic.
    pub fn rounded(&mut self, x: i32, y: i32, width: i32, height: i32, radius: i32, color: u16) {
        if width <= 0 || height <= 0 {
            return;
        }
        let r = radius.clamp(0, width.min(height) / 2);
        let (Some((x0, x1)), Some((y0, y1))) = (
            clip(x, width, self.x, self.x + self.width),
            clip(y, height, self.y, self.y + self.rows),
        ) else {
            return;
        };
        let (left, right) = (x + r, x + width - r);
        for row in y0..y1 {
            // The corner circle's centre row, if this row is in a corner.
            let cy = if row < y + r {
                y + r
            } else if row >= y + height - r {
                y + height - r
            } else {
                // Between the corners: the whole row is solid.
                let (a, b) = (self.at(x0, row), self.at(x1 - 1, row) + 1);
                self.px[a..b].fill(color);
                continue;
            };
            // The solid middle, then the two corners' columns.
            let (m0, m1) = (left.max(x0), right.min(x1));
            if m0 < m1 {
                let (a, b) = (self.at(m0, row), self.at(m1 - 1, row) + 1);
                self.px[a..b].fill(color);
            }
            for (from, to, cx) in [(x0, left.min(x1), left), (right.max(x0), x1, right)] {
                for col in from..to {
                    let alpha = covered(col, row, |sx, sy| {
                        let (dx, dy) = (sx - cx * 8, sy - cy * 8);
                        dx * dx + dy * dy <= r * r * 64
                    });
                    if alpha != 0 {
                        let at = self.at(col, row);
                        self.px[at] = blend(self.px[at], color, alpha);
                    }
                }
            }
        }
    }

    /// Fill a disc `diameter` pixels across with its box's top left at `x`,
    /// `y`, the edge smoothed.
    pub fn disc(&mut self, x: i32, y: i32, diameter: i32, color: u16) {
        // In eighths: the centre is the middle of the box, whatever the
        // diameter's parity.
        let (cx, cy, r) = (x * 8 + diameter * 4, y * 8 + diameter * 4, diameter * 4);
        self.shape(x, y, diameter, diameter, color, |sx, sy| {
            let (dx, dy) = (sx - cx, sy - cy);
            dx * dx + dy * dy <= r * r
        });
    }

    /// Fill a triangle between three pixel centres, the edges smoothed.
    pub fn triangle(&mut self, points: [(i32, i32); 3], color: u16) {
        let [a, b, c] = points.map(|(x, y)| (x * 8 + 4, y * 8 + 4));
        // Twice the signed area: which way round the points go.
        let turn = (b.0 - a.0) * (c.1 - a.1) - (b.1 - a.1) * (c.0 - a.0);
        if turn == 0 {
            return;
        }
        let side = |p: (i32, i32), q: (i32, i32), sx: i32, sy: i32| {
            let s = (q.0 - p.0) * (sy - p.1) - (q.1 - p.1) * (sx - p.0);
            if turn > 0 {
                s >= 0
            } else {
                s <= 0
            }
        };
        let (x0, y0) = (a.0.min(b.0).min(c.0) / 8, a.1.min(b.1).min(c.1) / 8);
        let (x1, y1) = (a.0.max(b.0).max(c.0) / 8, a.1.max(b.1).max(c.1) / 8);
        self.shape(x0, y0, x1 - x0 + 1, y1 - y0 + 1, color, |sx, sy| {
            side(a, b, sx, sy) && side(b, c, sx, sy) && side(c, a, sx, sy)
        });
    }

    /// Cover the pixels of a box by how much of each `inside` holds for,
    /// sampled as [`covered`] does.
    fn shape(
        &mut self,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        color: u16,
        inside: impl Fn(i32, i32) -> bool,
    ) {
        let (Some((x0, x1)), Some((y0, y1))) = (
            clip(x, width, self.x, self.x + self.width),
            clip(y, height, self.y, self.y + self.rows),
        ) else {
            return;
        };
        for row in y0..y1 {
            for col in x0..x1 {
                let alpha = covered(col, row, &inside);
                if alpha != 0 {
                    let at = self.at(col, row);
                    self.px[at] = blend(self.px[at], color, alpha);
                }
            }
        }
    }

    /// Lay `color` over a box, each pixel by the coverage `level` gives it,
    /// 0 to 15: a glyph or an icon.
    fn tint(
        &mut self,
        x: i32,
        y: i32,
        width: u8,
        height: u8,
        color: u16,
        level: impl Fn(u8, u8) -> u8,
    ) {
        for gr in 0..height {
            let row = y + i32::from(gr);
            if row < self.y || row >= self.y + self.rows {
                continue;
            }
            for gc in 0..width {
                let l = level(gc, gr);
                if l != 0 {
                    self.blend(x + i32::from(gc), row, color, l * 17);
                }
            }
        }
    }

    /// Draw an icon in `color`, its top left at `x`, `y`.
    pub fn icon(&mut self, x: i32, y: i32, sheet: &Sheet, icon: Icon, color: u16) {
        let side = sheet.side;
        self.tint(x, y, side, side, color, |cx, cy| {
            sheet.coverage(icon as usize, cx, cy)
        });
    }

    /// Draw a picture with its top left at `x`, `y`.
    pub fn image(&mut self, x: i32, y: i32, image: &Image) {
        let (Some((x0, x1)), Some((y0, y1))) = (
            clip(x, i32::from(image.width), self.x, self.x + self.width),
            clip(y, i32::from(image.height), self.y, self.y + self.rows),
        ) else {
            return;
        };
        for row in y0..y1 {
            for col in x0..x1 {
                let at = self.at(col, row);
                self.px[at] = image.pixel((col - x) as u16, (row - y) as u16);
            }
        }
    }

    /// Draw a picture stretched to `w` by `h`, each pixel blended from the
    /// four nearest. A larger panel's pictures are the smaller panel's
    /// stretched: softer than artwork cut at the size, but no second copy in
    /// flash.
    pub fn image_sized(&mut self, x: i32, y: i32, w: i32, h: i32, image: &Image) {
        let (sw, sh) = (i32::from(image.width), i32::from(image.height));
        if (w, h) == (sw, sh) {
            self.image(x, y, image);
            return;
        }
        if w <= 0 || h <= 0 || sw == 0 || sh == 0 {
            return;
        }
        let (Some((x0, x1)), Some((y0, y1))) = (
            clip(x, w, self.x, self.x + self.width),
            clip(y, h, self.y, self.y + self.rows),
        ) else {
            return;
        };
        // From the store, if the unit gave one, clipped to the band.
        let (bx, by, bw) = (self.x, self.y, self.width);
        if let Some(store) = self.stretched.as_deref_mut() {
            if let Some(start) = store.find_or_make(image, w, h) {
                let n = (x1 - x0) as usize;
                for row in y0..y1 {
                    let from = start + ((row - y) * w + (x0 - x)) as usize;
                    let to = ((row - by) * bw + (x0 - bx)) as usize;
                    self.px[to..to + n].copy_from_slice(&store.pixels[from..from + n]);
                }
                return;
            }
        }
        let (sx, sy) = (Stride::new(w, sw), Stride::new(h, sh));
        for row in y0..y1 {
            for col in x0..x1 {
                let at = self.at(col, row);
                self.px[at] = stretched(image, sx, sy, col - x, row - y);
            }
        }
    }

    /// Draw text with its pen starting at `x` and its baseline at `y`.
    /// Returns how far the pen moved.
    pub fn text(&mut self, font: &Font, x: i32, y: i32, color: u16, text: &str) -> i32 {
        if !self.crosses(y - i32::from(font.ascent), y + i32::from(font.descent)) {
            return font.width(text);
        }
        let mut pen = x;
        for c in text.chars() {
            let g = font.glyph(c);
            let (gx, gy) = (pen + i32::from(g.left), y - i32::from(g.top));
            self.tint(gx, gy, g.width, g.height, color, |cx, cy| {
                font.coverage(&g, cx, cy)
            });
            pen += i32::from(g.advance);
        }
        pen - x
    }

    /// [`Band::text`] with `gap` more pixels between characters, for an
    /// amount read digit by digit. Returns how far the pen moved.
    pub fn text_spaced(
        &mut self,
        font: &Font,
        x: i32,
        y: i32,
        color: u16,
        text: &str,
        gap: i32,
    ) -> i32 {
        let mut pen = x;
        for (i, c) in text.chars().enumerate() {
            if i > 0 {
                pen += gap;
            }
            let mut one = [0u8; 4];
            pen += self.text(font, pen, y, color, c.encode_utf8(&mut one));
        }
        pen - x
    }

    /// Draw text centred on `center`, baseline at `y`.
    pub fn text_centered(&mut self, font: &Font, center: i32, y: i32, color: u16, text: &str) {
        let x = center - font.width(text) / 2;
        self.text(font, x, y, color, text);
    }
}

/// How much of pixel `col`, `row` a shape covers, 0 to 255, from `inside`
/// asked at sixteen points. Samples are in eighths of a pixel, so every
/// test is integer arithmetic.
fn covered(col: i32, row: i32, inside: impl Fn(i32, i32) -> bool) -> u8 {
    let mut n = 0u32;
    for sy in 0..4 {
        for sx in 0..4 {
            if inside(col * 8 + sx * 2 + 1, row * 8 + sy * 2 + 1) {
                n += 1;
            }
        }
    }
    (n * 255 / 16) as u8
}

/// Draw a region of the panel, a band at a time.
///
/// `buf` holds as many whole rows of `area` as fit, at least one. Each band
/// starts as `background`, `paint` draws into it, and it goes to the panel
/// in one transfer. `paint` runs once per band and must draw the same
/// screen each time.
///
/// # Errors
///
/// `OutOfBounds` if `area` leaves the panel, `WrongLength` if `buf` cannot
/// hold one row of it, and whatever the panel returns.
pub fn render<D>(
    lcd: &mut D,
    area: Rect,
    background: u16,
    buf: &mut [u16],
    paint: impl FnMut(&mut Band<'_>),
) -> Result<(), Error>
where
    D: Display + ?Sized,
{
    render_with(lcd, area, background, buf, None, paint)
}

/// [`render`], with a store for stretched pictures.
pub fn render_with<D>(
    lcd: &mut D,
    area: Rect,
    background: u16,
    buf: &mut [u16],
    mut stretched: Option<&mut Stretched>,
    mut paint: impl FnMut(&mut Band<'_>),
) -> Result<(), Error>
where
    D: Display + ?Sized,
{
    lcd.check(area, None)?;
    let width = usize::from(area.width);
    if width == 0 || area.height == 0 {
        return Ok(());
    }
    let per = buf.len() / width;
    if per == 0 {
        return Err(Error::WrongLength {
            expected: width,
            got: buf.len(),
        });
    }
    let bottom = area.y + area.height;
    let mut y = area.y;
    while y < bottom {
        let rows = u16::try_from(per).unwrap_or(u16::MAX).min(bottom - y);
        let px = &mut buf[..width * usize::from(rows)];
        px.fill(background);
        let mut band = Band {
            px,
            x: i32::from(area.x),
            y: i32::from(y),
            width: i32::from(area.width),
            rows: i32::from(rows),
            stretched: stretched.as_deref_mut(),
        };
        paint(&mut band);
        lcd.blit(Rect::new(area.x, y, area.width, rows), band.px)?;
        y += rows;
    }
    Ok(())
}

/// How `dst` pixels map onto `src`, in 16.16 fixed point: one division per
/// picture drawn, not one per pixel.
#[derive(Clone, Copy)]
struct Stride {
    step: i32,
    start: i32,
    last: i32,
}

impl Stride {
    fn new(dst: i32, src: i32) -> Self {
        let step = (src << 16) / dst;
        Self {
            step,
            // Centre to centre: pixel 0's centre is half a step in, less
            // half a source pixel.
            start: step / 2 - 0x8000,
            last: src - 1,
        }
    }

    /// Where pixel `d` falls: the source pixels either side and how far
    /// toward the second, in 256ths.
    fn at(self, d: i32) -> (u16, u16, i32) {
        let at = (self.start + d * self.step).clamp(0, self.last << 16);
        let a = at >> 16;
        let b = (a + 1).min(self.last);
        (a as u16, b as u16, (at >> 8) & 0xFF)
    }
}

/// Pixel (`c`, `r`) of `image` stretched by `sx` and `sy`.
fn stretched(image: &Image, sx: Stride, sy: Stride, c: i32, r: i32) -> u16 {
    let (ya, yb, fy) = sy.at(r);
    let (xa, xb, fx) = sx.at(c);
    let top = mix(image.pixel(xa, ya), image.pixel(xb, ya), fx);
    let bottom = mix(image.pixel(xa, yb), image.pixel(xb, yb), fx);
    mix(top, bottom, fy)
}

// ── Stretched pictures, kept ────────────────────────────────────────────────

/// Pictures stretched to a panel's sizes, each made the first time it is
/// drawn and copied from then on: stretching on every redraw was half the
/// P4's home screen drawing. The store is in PSRAM; a picture that does not
/// fit is stretched each time instead, to the same pixels. Given to
/// [`render_with`].
pub struct Stretched {
    pixels: &'static mut [u16],
    used: usize,
    kept: [(usize, i32, i32, usize); STRETCHED_MOST],
    count: usize,
}

/// Pictures a store remembers: more than the screens draw at one size.
const STRETCHED_MOST: usize = 48;

impl Stretched {
    /// A store over `pixels`, for the life of the unit.
    pub fn new(pixels: &'static mut [u16]) -> Self {
        Self {
            pixels,
            used: 0,
            kept: [(0, 0, 0, 0); STRETCHED_MOST],
            count: 0,
        }
    }

    /// Pictures kept so far, and the pixels they take.
    pub fn kept(&self) -> (usize, usize) {
        (self.count, self.used)
    }

    /// Where `image` at `w` by `h` starts in the store, made now if it is
    /// not there yet; `None` if it does not fit.
    fn find_or_make(&mut self, image: &Image, w: i32, h: i32) -> Option<usize> {
        let id = image.id();
        if let Some(&(_, _, _, start)) = self.kept[..self.count]
            .iter()
            .find(|&&(i, kw, kh, _)| (i, kw, kh) == (id, w, h))
        {
            return Some(start);
        }
        let len = (w * h) as usize;
        if self.count == STRETCHED_MOST || self.used + len > self.pixels.len() {
            return None;
        }
        let start = self.used;
        let (sx, sy) = (
            Stride::new(w, i32::from(image.width)),
            Stride::new(h, i32::from(image.height)),
        );
        for r in 0..h {
            for c in 0..w {
                self.pixels[start + (r * w + c) as usize] = stretched(image, sx, sy, c, r);
            }
        }
        self.used += len;
        self.kept[self.count] = (id, w, h, start);
        self.count += 1;
        Some(start)
    }
}

/// Two RGB565 colours, `t` 256ths of the way from `a` to `b`.
fn mix(a: u16, b: u16, t: i32) -> u16 {
    let channel = |shift: u16, mask: u16| {
        let (ca, cb) = (
            i32::from((a >> shift) & mask),
            i32::from((b >> shift) & mask),
        );
        (((ca * (256 - t) + cb * t + 128) >> 8) as u16 & mask) << shift
    };
    channel(11, 0x1F) | channel(5, 0x3F) | channel(0, 0x1F)
}
