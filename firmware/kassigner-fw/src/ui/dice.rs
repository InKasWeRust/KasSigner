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

//! Seed Tools' Dice Seed: DICE n/99 (n/198 for 24 words) over a bar, a
//! button per face, and UNDO. The rolls are the seed: the screen shows only
//! how many.

use super::band::Band;
use super::camera::Part;
use super::chrome::{buttons, card, corner, header_at, Nav};
use super::color::{
    ACCENT, BACKGROUND, CARD, RED_BUTTON, SHADOW_EDGE, SHADOW_FACE, SHADOW_TEXT, TEAL, TEXT,
};
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;

/// What a touch on the dice screen can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    /// The face rolled, 1 to 6.
    Face(u8),
    /// Take the last roll back.
    Undo,
}

/// The grid: columns from x 10, 110, 210, rows from y 70, 135, each cell
/// 100 by 65, the button drawn 2 inside.
const COLS: [i32; 3] = [10, 110, 210];
const ROWS: [i32; 2] = [70, 135];
const CELL: (i32, i32) = (100, 65);
const UNDO_AT: (i32, i32, i32, i32) = (100, 200, 120, 38);

/// Where a target counts; UNDO only with a roll to take back.
pub fn zone(scale: Scale, rolled: usize, target: Target) -> Option<Zone> {
    match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        Target::Nav(_) => None,
        Target::Face(f @ 1..=6) => {
            let i = usize::from(f - 1);
            Some(scale.zone(COLS[i % 3], ROWS[i / 3], CELL.0, CELL.1))
        }
        Target::Face(_) => None,
        Target::Undo if rolled > 0 => {
            Some(scale.zone(UNDO_AT.0, UNDO_AT.1, UNDO_AT.2, 240 - UNDO_AT.1))
        }
        Target::Undo => None,
    }
}

/// What is under a point.
pub fn target(scale: Scale, rolled: usize, x: u16, y: u16) -> Option<Target> {
    [Target::Nav(Nav::Back), Target::Nav(Nav::Home), Target::Undo]
        .into_iter()
        .chain((1..=6).map(Target::Face))
        .find(|&t| zone(scale, rolled, t).is_some_and(|z| z.contains(x, y)))
}

/// A teal die showing `value`, `s` square at `x`, `y`, as on the buttons
/// and the Dice Seed row.
pub fn die(band: &mut Band<'_>, x: i32, y: i32, s: i32, value: u8) {
    band.rounded(x, y, s, s, s / 6, TEAL);
    let (cx, cy, q, d) = (x + s / 2, y + s / 2, s / 4, s * 5 / 24);
    let pips: &[(i32, i32)] = match value {
        1 => &[(0, 0)],
        2 => &[(-q, -q), (q, q)],
        3 => &[(-q, -q), (0, 0), (q, q)],
        4 => &[(-q, -q), (q, -q), (-q, q), (q, q)],
        5 => &[(-q, -q), (q, -q), (0, 0), (-q, q), (q, q)],
        _ => &[(-q, -q), (q, -q), (-q, 0), (q, 0), (-q, q), (q, q)],
    };
    for &(px, py) in pips {
        band.disc(cx + px - d / 2, cy + py - d / 2, d, BACKGROUND);
    }
}

/// The dice screen: `rolled` of `target` rolls.
pub fn draw(band: &mut Band<'_>, scale: Scale, kit: &Kit, rolled: usize, target: usize) {
    let mut t = [0u8; 16];
    let mut n = Part::Text("DICE ").write(&mut t, 0);
    n = Part::Number(rolled).write(&mut t, n);
    n = Part::Text("/").write(&mut t, n);
    n = Part::Number(target).write(&mut t, n);
    // The title sits higher, the bar where a rule would be.
    let title = core::str::from_utf8(&t[..n]).unwrap_or("");
    header_at(band, scale, kit, title, (TEXT, BACKGROUND), (25, 33));
    buttons(band, scale);
    // The bar: its outline, and how far.
    let bar = scale.zone(30, 35, 260, 8);
    card(band, bar, 0, BACKGROUND, TEAL, 1);
    let (bx, by, bw, bh) = bounds(bar);
    let done = bw * rolled.min(target) as i32 / target.max(1) as i32;
    if done > 0 {
        band.fill(bx, by, done, bh, ACCENT);
    }
    band.text_centered(
        kit.body,
        scale.x(160),
        scale.y(62),
        TEXT,
        "Tap the dice value you rolled:",
    );
    for f in 1..=6u8 {
        let i = usize::from(f - 1);
        let z = scale.zone(COLS[i % 3] + 2, ROWS[i / 3] + 2, 91, 54);
        card(band, z, scale.len(6), CARD, CARD, 1);
        let (x, y, w, h) = bounds(z);
        let s = h.min(w) - scale.len(10);
        die(band, x + (w - s) / 2, y + (h - s) / 2, s, f);
    }
    let z = scale.zone(UNDO_AT.0, UNDO_AT.1, UNDO_AT.2, UNDO_AT.3);
    let (face, ink) = if rolled > 0 {
        (RED_BUTTON, TEXT)
    } else {
        (SHADOW_FACE, SHADOW_TEXT)
    };
    card(
        band,
        z,
        scale.len(6),
        face,
        if rolled > 0 { face } else { SHADOW_EDGE },
        1,
    );
    let (x, y, w, h) = bounds(z);
    band.text_centered(
        kit.body,
        x + w / 2,
        y + (h + i32::from(kit.body.ascent)) / 2,
        ink,
        "UNDO",
    );
}

/// Rolls refused as not dice, already wiped, on the ERROR screen.
pub fn refused(band: &mut Band<'_>, scale: Scale, kit: &Kit) {
    super::refusal::draw(band, scale, kit, super::refusal::NOT_DICE);
}
