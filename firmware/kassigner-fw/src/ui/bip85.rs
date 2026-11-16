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

//! Seed Tools' BIP85 Child: the child's length, its index between "-"
//! (dimmed at 0) and "+", and DERIVE. A tap on the index opens the keypad,
//! for an index up to 99,999; its box holds five digits.

use super::band::Band;
use super::camera::Part;
use super::chrome::{buttons, card, centred, corner, header, step_button, Nav};
use super::color::{BACKGROUND, CARD, ORANGE, TEAL, TEXT, TEXT_DIM};
use super::scale::{Kit, Scale};
use crate::touch::Zone;

/// What a touch on the BIP85 screen can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    Minus,
    /// The index: the keypad.
    Index,
    Plus,
    Derive,
}

const MINUS_AT: (i32, i32, i32, i32) = (70, 98, 44, 34);
const INDEX_AT: (i32, i32, i32, i32) = (120, 98, 80, 34);
const PLUS_AT: (i32, i32, i32, i32) = (206, 98, 44, 34);
const DERIVE_AT: (i32, i32, i32, i32) = (90, 150, 140, 32);

/// Where a target counts; "-" not at index 0.
pub fn zone(scale: Scale, first: bool, target: Target) -> Option<Zone> {
    let at = match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => return Some(corner(scale, nav)),
        Target::Nav(_) => return None,
        Target::Minus if first => return None,
        Target::Minus => MINUS_AT,
        Target::Index => INDEX_AT,
        Target::Plus => PLUS_AT,
        Target::Derive => DERIVE_AT,
    };
    Some(scale.zone(at.0, at.1, at.2, at.3))
}

/// What is under a point.
pub fn target(scale: Scale, first: bool, x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Minus,
        Target::Index,
        Target::Plus,
        Target::Derive,
    ]
    .into_iter()
    .find(|&t| zone(scale, first, t).is_some_and(|z| z.contains(x, y)))
}

/// The screen: a `words`-word child at `index`.
pub fn draw(band: &mut Band<'_>, scale: Scale, kit: &Kit, words: usize, index: u32) {
    header(band, scale, kit, "BIP85 CHILD");
    buttons(band, scale);
    let mid = scale.x(160);
    let mut said = [0u8; 16];
    let mut k = Part::Number(words).write(&mut said, 0);
    k = Part::Text("-word child").write(&mut said, k);
    band.text_centered(
        kit.body,
        mid,
        scale.y(58),
        TEXT_DIM,
        core::str::from_utf8(&said[..k]).unwrap_or(""),
    );
    band.text_centered(kit.body, mid, scale.y(85), ORANGE, "Child Index");
    for (at, label, live) in [(MINUS_AT, "-", index > 0), (PLUS_AT, "+", true)] {
        step_button(
            band,
            scale,
            kit,
            scale.zone(at.0, at.1, at.2, at.3),
            label,
            live,
        );
    }
    let z = scale.zone(INDEX_AT.0, INDEX_AT.1, INDEX_AT.2, INDEX_AT.3);
    card(band, z, scale.len(4), CARD, TEAL, 1);
    let mut num = [0u8; 8];
    let m = Part::Number(index as usize).write(&mut num, 0);
    centred(
        band,
        kit.header,
        z,
        TEXT,
        core::str::from_utf8(&num[..m]).unwrap_or(""),
    );
    let z = scale.zone(DERIVE_AT.0, DERIVE_AT.1, DERIVE_AT.2, DERIVE_AT.3);
    card(band, z, scale.len(6), TEAL, TEAL, 1);
    centred(band, kit.title, z, BACKGROUND, "DERIVE");
}
