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

//! QR Export's grid view, for copying a SeedQR by hand: 7 by 7 modules at a
//! time, columns numbered and rows lettered ([`row_label`]). The left strip
//! moves the view left and right, the right strip up and down, an arrow
//! dark where it cannot go. The whole code is drawn by `paint::draw_code`.

use super::chrome::{corner, Nav, CORNER_DEPTH};
use super::scale::Scale;
use super::{
    band::Band,
    camera::Part,
    chrome::buttons,
    color::{rgb565, BACKGROUND, TEAL, TEXT},
    scale::Kit,
};
use crate::touch::Zone;
use kassigner_qr::encode::QrMatrix;

/// Modules shown a side, and their size in design pixels.
pub const VIEW: u8 = 7;
const CELL: i32 = 24;
/// The grid's top left.
const GRID: (i32, i32) = (70, 38);
/// How far left of the grid a row's label starts, in design pixels; the
/// label must end before the grid starts.
pub const ROW_LABEL_DX: i32 = 16;
/// A cell's edge.
const EDGE: u16 = rgb565(8, 20, 8);
/// An arrow where the view cannot go: a dim teal, brighter than the shared
/// [`super::color::TEAL_DARK`] on purpose.
const ARROW_DARK: u16 = rgb565(0, 20, 10);

/// What a touch on the grid view can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    Left,
    Right,
    Up,
    Down,
}

/// Where a target counts: the left strip's upper half left, lower half
/// right; the right strip's upper half up, lower half down.
pub fn zone(scale: Scale, target: Target) -> Option<Zone> {
    let top = CORNER_DEPTH;
    let at = match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => return Some(corner(scale, nav)),
        Target::Nav(_) => return None,
        Target::Left => (0, top, 55, 130 - top),
        Target::Right => (0, 130, 55, 70),
        Target::Up => (265, top, 55, 130 - top),
        Target::Down => (265, 130, 55, 70),
    };
    Some(scale.zone(at.0, at.1, at.2, at.3))
}

/// What is under a point.
pub fn target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Left,
        Target::Right,
        Target::Up,
        Target::Down,
    ]
    .into_iter()
    .find(|&t| zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// A row's label, written into `out`: `A` to `Z`, then `a'`, `b'` and `c'`.
///
/// A 24-word Standard SeedQR is 29 modules a side; lower case and a mark
/// keep its last three rows apart from `A`, `B` and `C` at a glance. No
/// SeedQR is larger; past `z'` is `?`.
pub fn row_label(row: u8, out: &mut [u8; 2]) -> &str {
    let n = match row {
        0..=25 => {
            out[0] = b'A' + row;
            1
        }
        26..=51 => {
            out[0] = b'a' + (row - 26);
            out[1] = b'\'';
            2
        }
        _ => {
            out[0] = b'?';
            1
        }
    };
    core::str::from_utf8(&out[..n]).unwrap_or("?")
}

/// The grid view of `code` from module `x`, `y`.
pub fn draw(band: &mut Band<'_>, scale: Scale, kit: &Kit, code: &QrMatrix, (x, y): (u8, u8)) {
    buttons(band, scale);
    let size = usize::from(code.size);
    let mut t = [0u8; 32];
    let mut n = Part::Text("Grid ").write(&mut t, 0);
    n = Part::Number(usize::from(x) + 1).write(&mut t, n);
    n = Part::Text(",").write(&mut t, n);
    n = Part::Number(usize::from(y) + 1).write(&mut t, n);
    n = Part::Text(" of ").write(&mut t, n);
    n = Part::Number(size).write(&mut t, n);
    n = Part::Text("x").write(&mut t, n);
    n = Part::Number(size).write(&mut t, n);
    let title = core::str::from_utf8(&t[..n]).unwrap_or("");
    band.text_centered(kit.hint, scale.x(160), scale.y(18), TEAL, title);

    let (gx, gy) = GRID;
    for c in 0..VIEW {
        let col = x + c;
        if col >= code.size {
            break;
        }
        let mut l = [0u8; 4];
        let m = Part::Number(usize::from(col) + 1).write(&mut l, 0);
        let cx = gx + i32::from(c) * CELL + CELL / 2;
        let label = core::str::from_utf8(&l[..m]).unwrap_or("");
        band.text_centered(kit.hint, scale.x(cx), scale.y(gy - 3), TEAL, label);
    }
    for r in 0..VIEW {
        let row = y + r;
        if row >= code.size {
            break;
        }
        let mut letter = [0u8; 2];
        let label = row_label(row, &mut letter);
        let ry = gy + i32::from(r) * CELL + CELL / 2 + 4;
        band.text(
            kit.hint,
            scale.x(gx - ROW_LABEL_DX),
            scale.y(ry),
            TEAL,
            label,
        );
    }
    let cell = scale.len(CELL);
    for r in 0..VIEW {
        for c in 0..VIEW {
            let (col, row) = (x + c, y + r);
            if col >= code.size || row >= code.size {
                continue;
            }
            let px = scale.x(gx + i32::from(c) * CELL);
            let py = scale.y(gy + i32::from(r) * CELL);
            let fill = if code.get(col, row) { BACKGROUND } else { TEXT };
            band.fill(px, py, cell, cell, EDGE);
            band.fill(px + 1, py + 1, cell - 2, cell - 2, fill);
        }
    }

    // The arrows, dark where the view cannot go.
    let max = code.size.saturating_sub(VIEW);
    let ink = |can: bool| if can { TEAL } else { ARROW_DARK };
    let p = |px: i32, py: i32| (scale.x(px), scale.y(py));
    let (lx, rx, top, bot) = (18, 302, 80, 160);
    band.triangle(
        [p(lx - 12, top), p(lx + 12, top - 15), p(lx + 12, top + 15)],
        ink(x > 0),
    );
    band.triangle(
        [p(lx + 12, bot), p(lx - 12, bot - 15), p(lx - 12, bot + 15)],
        ink(x < max),
    );
    band.triangle(
        [p(rx, top - 12), p(rx - 15, top + 12), p(rx + 15, top + 12)],
        ink(y > 0),
    );
    band.triangle(
        [p(rx, bot + 12), p(rx - 15, bot - 12), p(rx + 15, bot - 12)],
        ink(y < max),
    );
}
