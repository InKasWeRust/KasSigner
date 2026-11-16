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

//! Settings' Camera: the tuning screen.
//!
//! The board paints the viewfinder, top left, every frame; nothing here
//! overlaps it, so it never waits. On the right, a red EXIT and, two to a
//! row, the exposure loop's switch (if any) and a button per setting, up to
//! eight. Along the foot, the setting picked: label, value in hex and
//! percent (a count in decimal, out of its top), and minus, a track and plus.

use kassigner_hal::tune::Knob;

use super::band::Band;
use super::chrome::{card, lit_edge};
use super::color::{
    ACCENT, BACKGROUND, CARD, RED_BUTTON, SHADOW_EDGE, SHADOW_FACE, SHADOW_TEXT, TEAL, TEAL_BUTTON,
    TEXT, TEXT_DIM,
};
use super::font::Font;
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;

/// What a touch on the tuning screen can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Back to Settings.
    Exit,
    /// The exposure loop's switch.
    Auto,
    /// A setting's button, by its place in the board's list.
    Knob(usize),
    Minus,
    Plus,
    /// The track between them.
    Track,
}

/// The track, in design pixels.
const TRACK: (i32, i32, i32, i32) = (56, 210, 208, 10);

/// Where the viewfinder is painted: the top left, 198 by 178.
pub const fn viewfinder(scale: Scale) -> Zone {
    scale.zone(0, 0, 198, 178)
}

/// The right side: the switch and the buttons.
pub const fn panel_area(scale: Scale) -> Zone {
    scale.zone(198, 0, 122, 180)
}

/// The foot: the setting picked and its track.
pub const fn slider_area(scale: Scale) -> Zone {
    scale.zone(0, 180, 320, 60)
}

/// Buttons under EXIT: one per setting, and the switch if there is one.
const fn cells(knobs: usize, auto: bool) -> usize {
    knobs + auto as usize
}

/// Rows `cells` buttons take, two to a row.
const fn rows(cells: usize) -> i32 {
    cells.div_ceil(2) as i32
}

/// Button `i` of `cells` as drawn, in design pixels: 56 wide, and as tall
/// as the rows allow under EXIT, 44 for up to three rows.
const fn button(cells: usize, i: usize) -> (i32, i32, i32, i32) {
    let n = rows(cells);
    let pitch = if n <= 3 { 47 } else { 142 / n };
    let (col, row) = ((i % 2) as i32, (i / 2) as i32);
    (202 + col * 60, 38 + row * pitch, 56, pitch - 3)
}

/// Where a target counts, for `knobs` settings, with or without the switch;
/// `None` for a target the screen lacks. Minus and plus reach the sides, and
/// the track its whole length, so a finger reaches both ends of the range.
pub const fn zone(scale: Scale, knobs: usize, auto: bool, target: Target) -> Option<Zone> {
    let n = cells(knobs, auto);
    match target {
        Target::Exit => Some(scale.zone(198, 0, 122, 36)),
        Target::Auto if auto => Some(cell(scale, n, 0)),
        Target::Auto => None,
        Target::Knob(i) if i < knobs => Some(cell(scale, n, i + auto as usize)),
        Target::Knob(_) => None,
        Target::Minus => Some(scale.zone(0, 190, TRACK.0, 50)),
        Target::Plus => Some(scale.zone(TRACK.0 + TRACK.2, 190, 320 - TRACK.0 - TRACK.2, 50)),
        Target::Track => Some(scale.zone(TRACK.0, 190, TRACK.2, 50)),
    }
}

/// Where a touch on button `i` counts, built from [`button`] so the two
/// agree: across, to the panel's side and the line between the columns;
/// down, two pixels of the gap above and one below, so the rows meet and
/// the first reaches EXIT. Under the last row, one pixel only.
const fn cell(scale: Scale, cells: usize, i: usize) -> Zone {
    let (x, y, _, height) = button(cells, i);
    let (left, width) = if x < 260 { (198, 62) } else { (260, 60) };
    scale.zone(left, y - 2, width, height + 3)
}

/// What is under a point, if anything.
pub fn target(scale: Scale, knobs: usize, auto: bool, x: u16, y: u16) -> Option<Target> {
    [
        Target::Exit,
        Target::Auto,
        Target::Minus,
        Target::Plus,
        Target::Track,
    ]
    .into_iter()
    .chain((0..knobs).map(Target::Knob))
    .find(|&t| zone(scale, knobs, auto, t).is_some_and(|z| z.contains(x, y)))
}

/// The value a touch at column `x` on the track stands for, 0 at its first
/// column and `max` at its last.
pub fn value_at(scale: Scale, max: u8, x: u16) -> u8 {
    let (x0, last) = (scale.x(TRACK.0), scale.len(TRACK.2) - 1);
    let along = (i32::from(x) - x0).clamp(0, last);
    (along * i32::from(max) / last.max(1)) as u8
}

/// What the screen shows: the settings, the one picked, its value, and the
/// switch if any.
#[derive(Clone, Copy, Debug)]
pub struct Tuning<'a> {
    pub knobs: &'a [Knob],
    pub picked: usize,
    pub value: u8,
    pub auto: Option<bool>,
}

/// How a button looks: fill, edge and its thickness, label colour and font.
#[derive(Clone, Copy)]
struct Face<'f> {
    fill: u16,
    edge: u16,
    thick: i32,
    ink: u16,
    font: &'f Font,
}

/// The screen around the viewfinder. `lit` is what is under a finger, if
/// anything.
pub fn draw(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    tuning: &Tuning<'_>,
    lit: Option<Target>,
) {
    let Tuning {
        knobs,
        picked,
        value,
        auto,
    } = *tuning;
    let edge = |t: Target| {
        if lit == Some(t) {
            (ACCENT, lit_edge(scale))
        } else {
            (TEAL, 1)
        }
    };

    // EXIT across the top, red.
    let exit = (202, 2, 116, 32);
    let (e, thick) = edge(Target::Exit);
    let edge_exit = if lit == Some(Target::Exit) {
        e
    } else {
        RED_BUTTON
    };
    let look = Face {
        fill: RED_BUTTON,
        edge: edge_exit,
        thick,
        ink: TEXT,
        font: kit.title,
    };
    face(band, scale, exit, look, "EXIT");

    // Every label under it in one font: the body's if all fit, else the
    // hint's.
    let inner = scale.len(56) - scale.len(6);
    let fits = |label: &str| kit.body.width(label) <= inner;
    let font = if knobs.iter().all(|k| fits(k.label)) && fits("AUTO") && fits("MANU") {
        kit.body
    } else {
        kit.hint
    };
    let n = cells(knobs.len(), auto.is_some());

    // The switch, teal while the loop runs. Its label stays white: black
    // does not read on the dark teal at this size.
    if let Some(on) = auto {
        let (e, thick) = edge(Target::Auto);
        let (fill, label) = if on {
            (TEAL_BUTTON, "AUTO")
        } else {
            (CARD, "MANU")
        };
        let look = Face {
            fill,
            edge: e,
            thick,
            ink: TEXT,
            font,
        };
        face(band, scale, button(n, 0), look, label);
    }

    // A button per setting after it, the one picked filled teal.
    let first = usize::from(auto.is_some());
    // A setting that does nothing in the switch's mode is dimmed (the
    // loop's target and ceilings while it is off, the exposure and gain it
    // sets while on), but can still be picked to see its value.
    for (i, k) in knobs.iter().enumerate() {
        let dimmed = i != picked && !k.acts_in(auto);
        let (fill, ink) = if i == picked {
            (TEAL, BACKGROUND)
        } else if dimmed {
            (SHADOW_FACE, SHADOW_TEXT)
        } else {
            (CARD, TEXT)
        };
        let (e, thick) = if dimmed && lit != Some(Target::Knob(i)) {
            (SHADOW_EDGE, 1)
        } else {
            edge(Target::Knob(i))
        };
        let look = Face {
            fill,
            edge: e,
            thick,
            ink,
            font,
        };
        face(band, scale, button(n, first + i), look, k.label);
    }

    // The foot: label, hex and percentage centred together, then minus, the
    // track and plus.
    let Some(k) = knobs.get(picked) else {
        return;
    };
    // A register in hex and percent; a count in decimal, out of its top.
    let mut hex = [0u8; 4];
    let mut pct = [0u8; 4];
    let mut of = [0u8; 6];
    let (hex, pct) = if k.count {
        (decimal_of(value, &mut hex), out_of(k.max, &mut of))
    } else {
        (
            hex_of(value, &mut hex),
            super::settings::percent_of(value, k.max, &mut pct),
        )
    };
    let gap = scale.len(6);
    let widths = [
        kit.body.width(k.label),
        kit.title.width(hex),
        kit.body.width(pct),
    ];
    let mut x = scale.x(160) - (widths.iter().sum::<i32>() + 2 * gap) / 2;
    let y = scale.y(193);
    x += band.text(kit.body, x, y, TEAL, k.label) + gap;
    x += band.text(kit.title, x, y, TEXT, hex) + gap;
    band.text(kit.body, x, y, TEXT_DIM, pct);

    for (t, rect, sign) in [
        (Target::Minus, (2, 200, 50, 34), "-"),
        (Target::Plus, (268, 200, 50, 34), "+"),
    ] {
        let (e, thick) = edge(t);
        let look = Face {
            fill: CARD,
            edge: e,
            thick,
            ink: TEXT,
            font: kit.title,
        };
        face(band, scale, rect, look, sign);
    }

    let (tx, ty, tw, th) = (
        scale.x(TRACK.0),
        scale.y(TRACK.1),
        scale.len(TRACK.2),
        scale.len(TRACK.3),
    );
    let tr = th / 2;
    band.rounded(tx, ty, tw, th, tr, TEXT_DIM);
    let line = scale.len(1).max(1);
    band.rounded(
        tx + line,
        ty + line,
        tw - 2 * line,
        th - 2 * line,
        tr - line,
        BACKGROUND,
    );
    let max = i32::from(k.max.max(1));
    let filled = tw * i32::from(value.min(k.max)) / max;
    if filled > 0 {
        band.rounded(tx, ty, filled, th, tr, ACCENT);
    }
    let thumb = scale.len(12);
    let at = tx + (tw - thumb) * i32::from(value.min(k.max)) / max;
    band.rounded(
        at,
        ty - scale.len(4),
        thumb,
        th + scale.len(8),
        thumb / 2,
        TEAL,
    );
}

/// A button: a rounded box, filled and edged, its label centred.
fn face(
    band: &mut Band<'_>,
    scale: Scale,
    (x, y, w, h): (i32, i32, i32, i32),
    look: Face<'_>,
    label: &str,
) {
    let z = scale.zone(x, y, w, h);
    card(band, z, scale.len(6), look.fill, look.edge, look.thick);
    let (bx, by, bw, bh) = bounds(z);
    let f = look.font;
    let base = by + (bh + i32::from(f.ascent) - i32::from(f.descent)) / 2;
    band.text_centered(f, bx + bw / 2, base, look.ink, label);
}

/// `4`, written into `out`.
fn decimal_of(value: u8, out: &mut [u8; 4]) -> &str {
    let mut n = 0;
    let mut started = false;
    for place in [100, 10, 1] {
        let digit = value / place % 10;
        if digit != 0 || started || place == 1 {
            out[n] = b'0' + digit;
            n += 1;
            started = true;
        }
    }
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// `of 4`, written into `out`.
fn out_of(max: u8, out: &mut [u8; 6]) -> &str {
    let mut digits = [0u8; 4];
    let d = decimal_of(max, &mut digits).as_bytes();
    out[..3].copy_from_slice(b"of ");
    out[3..3 + d.len()].copy_from_slice(d);
    core::str::from_utf8(&out[..3 + d.len()]).unwrap_or("")
}

/// `0x58`, written into `out`.
fn hex_of(value: u8, out: &mut [u8; 4]) -> &str {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    *out = [
        b'0',
        b'x',
        DIGITS[usize::from(value >> 4)],
        DIGITS[usize::from(value & 0x0F)],
    ];
    core::str::from_utf8(out).unwrap_or("")
}
