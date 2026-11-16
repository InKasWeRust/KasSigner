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

//! What the screens share: the header, the back and home buttons, a list's
//! rows with their page arrows and dots, and the card everything tappable
//! is drawn as.
//!
//! Positions are in the design's 320 by 240 pixels, through a [`Scale`].
//! Each tappable thing has one function saying where it is, which drawing
//! and touch both call.

use super::band::Band;
use super::color::{ACCENT, CARD, SHADOW_EDGE, SHADOW_FACE, SHADOW_TEXT, TEAL, TEAL_DARK, TEXT};
use super::font::Font;
use super::image::Image;
use super::scale::{bounds, Kit, Scale, DESIGN};
use crate::touch::Zone;

/// The controls every list screen has around its rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nav {
    /// Top left: one screen back.
    Back,
    /// Top right: the home grid.
    Home,
    /// The strip left of the rows: the page before.
    PageUp,
    /// The strip right of them: the page after.
    PageDown,
}

/// The back button: a teal disc with an arrow, 34 pixels.
static BACK: Image = Image::new(
    34,
    34,
    include_bytes!("../../assets/images/icon_back_34.raw"),
);

/// The home button, the same size.
static HOME: Image = Image::new(
    34,
    34,
    include_bytes!("../../assets/images/icon_home_34.raw"),
);

/// How far a row is from the next, top to top: 42 pixels of row and 4 of
/// gap.
pub(crate) const ROW_PITCH: i32 = 46;

/// The rows of a list: where the first is, and how many a page holds.
/// Every row is 232 by 42, between the two page strips.
#[derive(Clone, Copy, Debug)]
pub struct List {
    /// The first row's top, in design pixels.
    pub top: i32,
    /// Rows on a page.
    pub rows: usize,
}

impl List {
    /// From the first row's top to the last one's bottom.
    pub const fn height(&self) -> i32 {
        self.rows as i32 * ROW_PITCH - 4
    }

    /// Where row `slot` of the page is drawn.
    pub const fn row(&self, scale: Scale, slot: usize) -> Zone {
        scale.zone(44, self.top + slot as i32 * ROW_PITCH, 232, 42)
    }

    /// Where a touch on row `slot` counts: the drawn row grown by 2 on every
    /// side, half the gap to its neighbours, so no touch between rows is
    /// lost.
    pub const fn touch(&self, scale: Scale, slot: usize) -> Zone {
        scale.zone(
            SIDE_COLUMN,
            self.top - 2 + slot as i32 * ROW_PITCH,
            RIGHT_COLUMN - SIDE_COLUMN,
            ROW_PITCH,
        )
    }

    /// The design row that row `slot` starts at.
    pub const fn row_top(&self, slot: usize) -> i32 {
        self.top + slot as i32 * ROW_PITCH
    }

    /// A page strip at `x`: 42 wide, from the rows' top, or from under the
    /// corner if that is lower, to the rows' foot.
    const fn strip(&self, scale: Scale, x: i32) -> Zone {
        let top = self.top - 2;
        let from = if top > CORNER_DEPTH {
            top
        } else {
            CORNER_DEPTH
        };
        scale.zone(x, from, SIDE_COLUMN, self.height() + 4 - (from - top))
    }

    /// Where a touch on a navigation control beside this list counts: the
    /// page strips meet the rows' touch zones and run as tall; the back and
    /// home buttons are [`corner`]'s.
    pub const fn nav(&self, scale: Scale, nav: Nav) -> Zone {
        match nav {
            Nav::Back | Nav::Home => corner(scale, nav),
            Nav::PageUp => self.strip(scale, 0),
            Nav::PageDown => self.strip(scale, RIGHT_COLUMN),
        }
    }
}

/// Where the back or home button counts: [`SIDE_COLUMN`] by
/// [`CORNER_DEPTH`] from the panel's own corner, taking in any margin beside
/// the design on a wider panel. Touches aimed at the 34 pixel pictures land
/// up to 20 pixels short. Anything but `Back` is `Home`.
pub const fn corner(scale: Scale, nav: Nav) -> Zone {
    let (w, h) = (scale.panel_width(), scale.y(CORNER_DEPTH));
    match nav {
        Nav::Back => Zone::new(0, 0, scale.x(SIDE_COLUMN) as u16, h as u16),
        _ => {
            let x = scale.x(RIGHT_COLUMN);
            Zone::new(x as u16, 0, (w - x) as u16, h as u16)
        }
    }
}

/// How far down the back and home buttons count, in design pixels: on the
/// Waveshare, taps aimed at Home land as low as 53. So that no two targets
/// overlap, the page strips start under the corners, and so do the seeds
/// screen's two buttons and list and both viewfinders.
pub const CORNER_DEPTH: i32 = 54;

/// The side columns' width, in design pixels: Back and Home at the top, the
/// page strips under them, one width for both.
pub const SIDE_COLUMN: i32 = 42;

/// Where the right side column starts, in design pixels.
pub const RIGHT_COLUMN: i32 = DESIGN.width as i32 - SIDE_COLUMN;

/// How thick the edge of a card under a finger is.
pub const fn lit_edge(scale: Scale) -> i32 {
    let t = scale.len(2);
    if t < 2 {
        2
    } else {
        t
    }
}

/// A title, centred, and the teal rule under it.
pub fn header(band: &mut Band<'_>, scale: Scale, kit: &Kit, title: &str) {
    header_in(band, scale, kit, title, TEXT, TEAL);
}

/// A title in `ink` and its rule in `rule`: a warning's header.
pub fn header_in(band: &mut Band<'_>, scale: Scale, kit: &Kit, title: &str, ink: u16, rule: u16) {
    header_at(band, scale, kit, title, (ink, rule), (30, 40));
}

/// A header with its title's baseline and its rule at the design rows
/// given: the keyboard's sits higher, at 26 and 36, to leave room for the
/// line being typed.
pub fn header_at(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    title: &str,
    (ink, rule): (u16, u16),
    (baseline, rule_y): (i32, i32),
) {
    band.text_centered(kit.header, scale.x(160), scale.y(baseline), ink, title);
    let (x, y, w) = (scale.x(20), scale.y(rule_y), scale.len(281));
    band.fill(x, y, w, scale.len(1).max(1), rule);
}

/// A picture centred on a zone, scaled with the panel.
pub fn place(band: &mut Band<'_>, scale: Scale, image: &Image, zone: Zone) {
    let (x, y, w, h) = bounds(zone);
    let (iw, ih) = (
        scale.len(i32::from(image.width)),
        scale.len(i32::from(image.height)),
    );
    band.image_sized(x + (w - iw) / 2, y + (h - ih) / 2, iw, ih, image);
}

/// The back and home buttons, their pictures in the design's corners.
pub fn buttons(band: &mut Band<'_>, scale: Scale) {
    place_back(band, scale);
    place(band, scale, &HOME, scale.zone(286, 0, 34, 34));
}

/// The back button's picture alone, for a screen with no home button.
pub fn place_back(band: &mut Band<'_>, scale: Scale) {
    place(band, scale, &BACK, scale.zone(0, 0, 34, 34));
}

/// `said` in `font`, centred in `z`: across it, and down it on the font's
/// ascent.
pub fn centred(band: &mut Band<'_>, font: &Font, z: Zone, ink: u16, said: &str) {
    let (x, y, w, h) = bounds(z);
    let base = y + (h + i32::from(font.ascent)) / 2;
    band.text_centered(font, x + w / 2, base, ink, said);
}

/// A stepper's "-" or "+", dimmed like a keyboard key where it goes no
/// further.
pub fn step_button(band: &mut Band<'_>, scale: Scale, kit: &Kit, z: Zone, sign: &str, live: bool) {
    let (face, edge, ink) = if live {
        (CARD, TEAL, TEXT)
    } else {
        (SHADOW_FACE, SHADOW_EDGE, SHADOW_TEXT)
    };
    card(band, z, scale.len(6), face, edge, 1);
    centred(band, kit.title, z, ink, sign);
}

/// A card: a rounded box, `thick` pixels of `edge` around `fill`.
pub fn card(band: &mut Band<'_>, zone: Zone, radius: i32, fill: u16, edge: u16, thick: i32) {
    let (x, y, w, h) = bounds(zone);
    band.rounded(x, y, w, h, radius, edge);
    band.rounded(
        x + thick,
        y + thick,
        w - 2 * thick,
        h - 2 * thick,
        radius - thick,
        fill,
    );
}

/// The page arrows in their strips, teal when there is a page that way,
/// all but dark when there is not, and bright under a finger.
pub fn arrows(
    band: &mut Band<'_>,
    scale: Scale,
    list: &List,
    up: bool,
    down: bool,
    lit: Option<Nav>,
) {
    let cy = list.top + list.height() / 2;
    let color = |live: bool, nav: Nav| match (live, lit == Some(nav)) {
        (true, true) => ACCENT,
        (true, false) => TEAL,
        (false, _) => TEAL_DARK,
    };
    let point = |x: i32, y: i32| (scale.x(x), scale.y(y));
    band.triangle(
        [point(5, cy), point(30, cy - 17), point(30, cy + 17)],
        color(up, Nav::PageUp),
    );
    band.triangle(
        [point(315, cy), point(290, cy - 17), point(290, cy + 17)],
        color(down, Nav::PageDown),
    );
}

/// A dot per page along the bottom, the current one bright. Nothing for a
/// single page.
pub fn dots(band: &mut Band<'_>, scale: Scale, page: usize, pages: usize) {
    if pages < 2 {
        return;
    }
    let (d, gap) = (scale.len(7), scale.len(8));
    let n = pages as i32;
    let x0 = scale.x(160) - (n * d + (n - 1) * gap) / 2;
    for p in 0..pages {
        let color = if p == page { ACCENT } else { TEAL_DARK };
        band.disc(x0 + p as i32 * (d + gap), scale.y(232), d, color);
    }
}

/// How many pages `items` rows take at `per` a page: always at least one.
pub const fn pages(items: usize, per: usize) -> usize {
    if items == 0 {
        1
    } else {
        items.div_ceil(per)
    }
}
