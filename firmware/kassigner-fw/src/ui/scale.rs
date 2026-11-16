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

//! Where a screen's pixels go on a panel, and what it is drawn with.
//!
//! Every screen is drawn for the 320 by 240 [`DESIGN`], scaled to fit a
//! larger panel ([`Scale`]) and centred, with a [`Kit`] of fonts and icons
//! cut for its size. A picture has one bitmap, resampled on a larger panel
//! (`Band::image_sized`): softer, but no second copy in flash.

use kassigner_hal::display::Size;

use super::font::Font;
use super::gen;
use super::image::Sheet;
use crate::touch::Zone;

/// The panel every screen is drawn for.
pub const DESIGN: Size = Size::new(320, 240);

/// From design pixels to a panel's: the largest fraction at which the
/// screen fits, and the offset that centres it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scale {
    num: i32,
    den: i32,
    dx: i32,
    dy: i32,
    /// The panel's own width, for what reaches its edge.
    width: i32,
}

impl Scale {
    /// The scale for a panel of `size`.
    pub const fn for_panel(size: Size) -> Self {
        let (w, h) = (size.width as i32, size.height as i32);
        let (dw, dh) = (DESIGN.width as i32, DESIGN.height as i32);
        // Whichever side runs out first sets the factor.
        let (num, den) = if w * dh <= h * dw { (w, dw) } else { (h, dh) };
        // The design's size on the panel, rounded as `len` rounds.
        let (sw, sh) = ((dw * num + den / 2) / den, (dh * num + den / 2) / den);
        Self {
            num,
            den,
            dx: (w - sw) / 2,
            dy: (h - sh) / 2,
            width: w,
        }
    }

    /// The panel's width, in its own pixels.
    pub const fn panel_width(&self) -> i32 {
        self.width
    }

    /// A length, rounded to the nearest pixel.
    pub const fn len(&self, v: i32) -> i32 {
        (v * self.num + self.den / 2) / self.den
    }

    /// A design column on the panel.
    pub const fn x(&self, v: i32) -> i32 {
        self.dx + self.len(v)
    }

    /// A design row on the panel.
    pub const fn y(&self, v: i32) -> i32 {
        self.dy + self.len(v)
    }

    /// A design rectangle on the panel, as a touch zone.
    pub const fn zone(&self, x: i32, y: i32, width: i32, height: i32) -> Zone {
        let (x0, y0) = (self.x(x), self.y(y));
        Zone::new(
            x0 as u16,
            y0 as u16,
            (self.x(x + width) - x0) as u16,
            (self.y(y + height) - y0) as u16,
        )
    }
}

/// A zone as signed panel coordinates for drawing: x, y, width, height.
pub const fn bounds(z: Zone) -> (i32, i32, i32, i32) {
    (z.x as i32, z.y as i32, z.width as i32, z.height as i32)
}

/// The fonts and icons cut for one panel size.
#[derive(Clone, Copy, Debug)]
pub struct Kit {
    /// Small print: the unit, the link, a mark on a row.
    pub hint: &'static Font,
    /// Body text.
    pub body: &'static Font,
    /// Titles and labels.
    pub title: &'static Font,
    /// Screen headers.
    pub header: &'static Font,
    /// Row icons.
    pub icons: &'static Sheet,
    /// The keyboard's keys and the text typed on it.
    pub key: &'static Font,
    /// A word shown on its own, large.
    pub word: &'static Font,
}

/// For a 320 by 240 panel, Iconoir at its own 24 pixels.
pub static SMALL: Kit = Kit {
    hint: &gen::LATO_12,
    body: &gen::LATO_15,
    title: &gen::LATO_BOLD_18,
    header: &gen::OSWALD_BOLD_22,
    icons: &gen::ICONS_24,
    key: &gen::LATO_22,
    word: &gen::RUBIK_BOLD_26,
};

/// For a 480 by 320 panel: the same at four thirds, the scale that fits.
pub static LARGE: Kit = Kit {
    hint: &gen::LATO_16,
    body: &gen::LATO_20,
    title: &gen::LATO_BOLD_24,
    header: &gen::OSWALD_BOLD_29,
    icons: &gen::ICONS_32,
    key: &gen::LATO_29,
    word: &gen::RUBIK_BOLD_35,
};
