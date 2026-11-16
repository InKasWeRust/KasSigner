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

//! The numeric keypad for an index (Address's and BIP85 Child's): the
//! number typed, 1 to 9, C, 0 and GO, and a hint.

use super::band::Band;
use super::chrome::{buttons, card, corner, header, Nav};
use super::color::{CARD, TEAL, TEXT, TEXT_DIM};
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;

/// A keypad key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Digit(u8),
    /// Clear what is typed.
    Clear,
    /// Done.
    Go,
}

/// What a touch on the keypad's screen can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    Key(Key),
}

/// The grid, row by row.
const KEYS: [Key; 12] = [
    Key::Digit(1),
    Key::Digit(2),
    Key::Digit(3),
    Key::Digit(4),
    Key::Digit(5),
    Key::Digit(6),
    Key::Digit(7),
    Key::Digit(8),
    Key::Digit(9),
    Key::Clear,
    Key::Digit(0),
    Key::Go,
];

/// A key's place: 65 by 30, columns 75 apart from x 55, rows 34 apart from
/// y 76.
fn face(key: Key) -> (i32, i32, i32, i32) {
    let i = KEYS.iter().position(|&k| k == key).unwrap_or(0) as i32;
    (55 + (i % 3) * 75, 76 + (i / 3) * 34, 65, 30)
}

/// Where a target counts: a key as drawn and half the gaps around it.
pub fn zone(scale: Scale, target: Target) -> Option<Zone> {
    match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        Target::Nav(_) => None,
        Target::Key(key) => {
            let (x, y, w, h) = face(key);
            Some(scale.zone(x - 5, y - 2, w + 10, h + 4))
        }
    }
}

/// What is under a point.
pub fn target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    [Target::Nav(Nav::Back), Target::Nav(Nav::Home)]
        .into_iter()
        .chain(KEYS.map(Target::Key))
        .find(|&t| zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// Address's keypad title: the index to go to.
pub const ADDRESS_TITLE: &str = "GO TO ADDRESS #";
/// BIP85 Child's keypad title: the child's index.
pub const CHILD_TITLE: &str = "CHILD INDEX #";
/// The hint under either keypad.
pub const HINT: &str = "Type index, tap GO";

/// The keypad's screen: `title`, `typed` ("_" when empty), the keys, and
/// `hint`.
pub fn draw(band: &mut Band<'_>, scale: Scale, kit: &Kit, title: &str, typed: &str, hint: &str) {
    header(band, scale, kit, title);
    buttons(band, scale);
    let mid = scale.x(160);
    let field = scale.zone(80, 42, 160, 28);
    card(band, field, scale.len(4), CARD, TEAL, 1);
    let shown = if typed.is_empty() { "_" } else { typed };
    band.text_centered(kit.title, mid, scale.y(62), TEXT, shown);
    for key in KEYS {
        let (x, y, w, h) = face(key);
        let z = scale.zone(x, y, w, h);
        let go = key == Key::Go;
        card(
            band,
            z,
            scale.len(4),
            CARD,
            TEAL,
            if go { scale.len(2).max(2) } else { 1 },
        );
        let mut digit = [0u8; 1];
        let said = match key {
            Key::Digit(d) => {
                digit[0] = b'0' + d;
                core::str::from_utf8(&digit).unwrap_or("")
            }
            Key::Clear => "C",
            Key::Go => "GO",
        };
        let (px, py, pw, ph) = bounds(z);
        let base = py + (ph + i32::from(kit.title.ascent)) / 2;
        band.text_centered(
            kit.title,
            px + pw / 2,
            base,
            if go { TEAL } else { TEXT },
            said,
        );
    }
    band.text_centered(kit.hint, mid, scale.y(228), TEXT_DIM, hint);
}
