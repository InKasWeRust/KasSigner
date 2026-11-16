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

//! The Settings screens that set a level, Display (the backlight) and Audio
//! (the volume): a bar between minus and plus, which move the level a
//! [`STEP`], and its percentage. A new level redraws only [`level_area`];
//! the flow decides how far the level may go.

use super::band::Band;
use super::chrome::{buttons, card, corner, header, lit_edge, Nav};
use super::color::{ACCENT, CARD, TEAL, TEXT};
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;

/// What a level screen says: its title and the label over the bar.
pub type Text = (&'static str, &'static str);

/// The Display screen's.
pub const DISPLAY: Text = ("DISPLAY", "Brightness:");
/// The Audio screen's.
pub const AUDIO: Text = ("AUDIO", "Volume:");

/// How far minus and plus move the level.
pub const STEP: u8 = 25;

/// What a touch on a level screen can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    Minus,
    Plus,
    Bar,
}

/// The bar, in design pixels.
const BAR: (i32, i32, i32, i32) = (70, 85, 180, 20);

/// Where a target counts: minus and plus out to the panel's edges, the bar
/// between them, all short of the corners.
pub const fn zone(scale: Scale, target: Target) -> Option<Zone> {
    match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        Target::Nav(_) => None,
        Target::Minus => Some(scale.zone(0, 70, 69, 50)),
        Target::Plus => Some(scale.zone(251, 70, 69, 50)),
        Target::Bar => Some(scale.zone(69, 75, 182, 40)),
    }
}

/// What is under a point, if anything.
pub fn target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Minus,
        Target::Plus,
        Target::Bar,
    ]
    .into_iter()
    .find(|&t| zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// The level a touch at column `x` on the bar stands for, 0 to 255 from
/// left to right.
pub fn level_at(scale: Scale, x: u16) -> u8 {
    let (x0, w) = (scale.x(BAR.0), scale.len(BAR.2));
    let along = (i32::from(x) - x0).clamp(0, w);
    (along * 255 / w.max(1)) as u8
}

/// Where the bar and the percentage are: all a new level changes.
pub const fn level_area(scale: Scale) -> Zone {
    scale.zone(BAR.0, BAR.1, BAR.2, 60)
}

/// A level screen. `lit` is what is under a finger, if anything.
pub fn level(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    (title, label): Text,
    value: u8,
    lit: Option<Target>,
) {
    header(band, scale, kit, title);
    buttons(band, scale);
    let mid = scale.x(160);
    band.text_centered(kit.body, mid, scale.y(65), TEXT, label);

    // Minus and plus: a teal edge on the card colour.
    let r = scale.len(6);
    for (t, x, sign) in [(Target::Minus, 20, "-"), (Target::Plus, 260, "+")] {
        let z = scale.zone(x, 80, 40, 30);
        let (edge, thick) = if lit == Some(t) {
            (ACCENT, lit_edge(scale))
        } else {
            (TEAL, 1)
        };
        card(band, z, r, CARD, edge, thick);
        let (bx, by, bw, _) = bounds(z);
        band.text_centered(kit.title, bx + bw / 2, by + scale.len(21), TEXT, sign);
    }

    // The bar: a white outline, filled as far as the level.
    let (x, y, w, h) = (
        scale.x(BAR.0),
        scale.y(BAR.1),
        scale.len(BAR.2),
        scale.len(BAR.3),
    );
    let line = scale.len(1).max(1);
    band.fill(x, y, w, h, TEXT);
    band.fill(x + line, y + line, w - 2 * line, h - 2 * line, CARD);
    let filled = w * i32::from(value) / 255;
    band.fill(x, y, filled, h, ACCENT);

    let mut buf = [0u8; 4];
    band.text_centered(kit.title, mid, scale.y(135), TEXT, percent(value, &mut buf));
}

/// A level as a percentage of 255, into `out`: `0%` to `100%`.
pub fn percent(value: u8, out: &mut [u8; 4]) -> &str {
    percent_of(value, 255, out)
}

/// `value` as a percentage of `max`, into `out`: `0%` to `100%`. A `max`
/// of zero reads as full.
pub fn percent_of(value: u8, max: u8, out: &mut [u8; 4]) -> &str {
    let pct = (u32::from(value.min(max)) * 100)
        .checked_div(u32::from(max))
        .unwrap_or(100);
    let mut n = 0;
    if pct >= 100 {
        out[n] = b'1';
        n += 1;
    }
    if pct >= 10 {
        out[n] = b'0' + (pct / 10 % 10) as u8;
        n += 1;
    }
    out[n] = b'0' + (pct % 10) as u8;
    out[n + 1] = b'%';
    core::str::from_utf8(&out[..n + 2]).unwrap_or("")
}
