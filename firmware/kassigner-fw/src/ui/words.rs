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

//! The word tools' own screens: choosing 12 or 24 words; the last word Calc
//! Last Word works out; and the backup check's CHECK n/3 and BACKUP CHECKED.

use super::band::Band;
use super::brand;
use super::camera::Part;
use super::chrome::{arrows, buttons, card, corner, header, lit_edge, Nav};
use super::color::{ACCENT, CARD, CARD_EDGE, GREEN_BUTTON, HINT, TEAL, TEXT, TEXT_DIM};
use super::menu::LIST;
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;

/// What a touch on these screens can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    /// A phrase this many words long.
    Words(u8),
    /// The last word's OK.
    Ok,
}

/// The count's two cards, and the last word's OK.
const TWELVE_AT: (i32, i32, i32, i32) = (30, 70, 260, 60);
const TWENTY_FOUR_AT: (i32, i32, i32, i32) = (30, 150, 260, 60);
const OK_AT: (i32, i32, i32, i32) = (110, 192, 100, 38);

/// Where a target counts on the count's screen.
pub fn count_zone(scale: Scale, target: Target) -> Option<Zone> {
    let at = match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => return Some(corner(scale, nav)),
        Target::Words(12) => TWELVE_AT,
        Target::Words(24) => TWENTY_FOUR_AT,
        _ => return None,
    };
    Some(scale.zone(at.0, at.1, at.2, at.3))
}

/// What is under a point on the count's screen.
pub fn count_target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Words(12),
        Target::Words(24),
    ]
    .into_iter()
    .find(|&t| count_zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// Where a target counts on the last word's screen.
pub fn last_zone(scale: Scale, target: Target) -> Option<Zone> {
    match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        Target::Nav(nav @ (Nav::PageUp | Nav::PageDown)) => Some(LIST.nav(scale, nav)),
        Target::Ok => Some(scale.zone(OK_AT.0, OK_AT.1, OK_AT.2, OK_AT.3)),
        _ => None,
    }
}

/// What is under a point on the last word's screen.
pub fn last_target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    [Nav::Back, Nav::Home, Nav::PageUp, Nav::PageDown]
        .map(Target::Nav)
        .into_iter()
        .chain([Target::Ok])
        .find(|&t| last_zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// 12 or 24 words, under `title`.
pub fn count(band: &mut Band<'_>, scale: Scale, kit: &Kit, title: &str) {
    header(band, scale, kit, title);
    buttons(band, scale);
    for (at, label) in [(TWELVE_AT, "12 Words"), (TWENTY_FOUR_AT, "24 Words")] {
        let z = scale.zone(at.0, at.1, at.2, at.3);
        card(band, z, scale.len(8), CARD, TEAL, 1);
        let (x, y, w, h) = bounds(z);
        let base = y + (h + i32::from(kit.title.ascent)) / 2;
        band.text_centered(kit.title, x + w / 2, base, TEXT, label);
    }
}

/// A word screen's title: `heading` and the place, "IMPORT 3/12".
pub fn title<'o>(out: &'o mut [u8; 24], heading: &str, pos: u8, of: u8) -> &'o str {
    let mut n = Part::Text(heading).write(out, 0);
    n = Part::Text(" ").write(out, n);
    n = Part::Number(usize::from(pos) + 1).write(out, n);
    n = Part::Text("/").write(out, n);
    n = Part::Number(usize::from(of)).write(out, n);
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// The word screen, the template for every screen showing a word alone:
/// WORD 3/12 a little lower than a header, a short teal rule, the place in
/// teal, and the word large. `place` counts from 0; `of` is the phrase's
/// length.
fn word_card(band: &mut Band<'_>, scale: Scale, kit: &Kit, place: usize, of: usize, word: &str) {
    let mut t = [0u8; 16];
    let mut n = Part::Text("WORD ").write(&mut t, 0);
    n = Part::Number(place + 1).write(&mut t, n);
    n = Part::Text("/").write(&mut t, n);
    n = Part::Number(of).write(&mut t, n);
    let mid = scale.x(160);
    band.text_centered(
        kit.header,
        mid,
        scale.y(40),
        TEXT,
        core::str::from_utf8(&t[..n]).unwrap_or(""),
    );
    band.fill(scale.x(60), scale.y(55), scale.len(200), 1, TEAL);
    buttons(band, scale);
    let mut p = [0u8; 8];
    let hash = Part::Text("#").write(&mut p, 0);
    let m = Part::Number(place + 1).write(&mut p, hash);
    band.text_centered(
        kit.title,
        mid,
        scale.y(100),
        TEAL,
        core::str::from_utf8(&p[..m]).unwrap_or(""),
    );
    band.text_centered(kit.word, mid, scale.y(135), TEXT, word);
}

/// A new seed's words one at a time, to write down; a tap for the next.
pub fn show(band: &mut Band<'_>, scale: Scale, kit: &Kit, place: usize, of: usize, word: &str) {
    word_card(band, scale, kit, place, of, word);
    band.text_centered(
        kit.hint,
        scale.x(160),
        scale.y(210),
        HINT,
        "Write it down! Tap for next.",
    );
}

/// The last word of `of`, which of the valid `choices` it is, the arrows to
/// step through them and OK to take it.
pub fn last(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    of: u8,
    word: &str,
    (choice, choices): (u16, u16),
) {
    let of = usize::from(of);
    word_card(band, scale, kit, of - 1, of, word);
    let mid = scale.x(160);
    let mut w = [0u8; 16];
    let mut k = Part::Number(usize::from(choice) + 1).write(&mut w, 0);
    k = Part::Text(" of ").write(&mut w, k);
    k = Part::Number(usize::from(choices)).write(&mut w, k);
    band.text_centered(
        kit.body,
        mid,
        scale.y(168),
        TEXT_DIM,
        core::str::from_utf8(&w[..k]).unwrap_or(""),
    );
    arrows(band, scale, &LIST, true, true, None);
    let z = scale.zone(OK_AT.0, OK_AT.1, OK_AT.2, OK_AT.3);
    card(band, z, scale.len(5), GREEN_BUTTON, GREEN_BUTTON, 1);
    let (x, y, bw, h) = bounds(z);
    let base = y + (h + i32::from(kit.title.ascent)) / 2;
    band.text_centered(kit.title, x + bw / 2, base, TEXT, "OK");
}

/// Words CHECK offers for a place: the right one and three others.
pub const CHOICES: usize = 4;

/// What a touch on CHECK can land on: back, home, or the `n`th word, left
/// to right then down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckTarget {
    Nav(Nav),
    Choice(usize),
}

/// The four words' cards, two rows of two under the place.
const CHOICE_AT: [(i32, i32); CHOICES] = [(25, 102), (165, 102), (25, 152), (165, 152)];
const CHOICE_SIZE: (i32, i32) = (130, 42);

/// Where a target counts on CHECK.
pub fn check_zone(scale: Scale, target: CheckTarget) -> Option<Zone> {
    match target {
        CheckTarget::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        CheckTarget::Nav(_) => None,
        CheckTarget::Choice(k) => {
            let (x, y) = *CHOICE_AT.get(k)?;
            Some(scale.zone(x, y, CHOICE_SIZE.0, CHOICE_SIZE.1))
        }
    }
}

/// What is under a point on CHECK.
pub fn check_target(scale: Scale, x: u16, y: u16) -> Option<CheckTarget> {
    [CheckTarget::Nav(Nav::Back), CheckTarget::Nav(Nav::Home)]
        .into_iter()
        .chain((0..CHOICES).map(CheckTarget::Choice))
        .find(|&t| check_zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// CHECK `round`/3: the place asked in teal, the four words as cards, and
/// the hint. `round` and `place` count from 0.
pub fn check(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    (round, rounds): (u8, u8),
    place: u8,
    words: [&str; CHOICES],
    lit: Option<CheckTarget>,
) {
    let mid = scale.x(160);
    let mut t = [0u8; 24];
    let title = title(&mut t, "CHECK", round, rounds);
    band.text_centered(kit.header, mid, scale.y(40), TEXT, title);
    band.fill(scale.x(60), scale.y(55), scale.len(200), 1, TEAL);
    buttons(band, scale);
    let mut p = [0u8; 8];
    let hash = Part::Text("#").write(&mut p, 0);
    let m = Part::Number(usize::from(place) + 1).write(&mut p, hash);
    band.text_centered(
        kit.title,
        mid,
        scale.y(88),
        TEAL,
        core::str::from_utf8(&p[..m]).unwrap_or(""),
    );
    for (k, word) in words.iter().enumerate() {
        let Some(z) = check_zone(scale, CheckTarget::Choice(k)) else {
            continue;
        };
        let (edge, thick) = if lit == Some(CheckTarget::Choice(k)) {
            (ACCENT, lit_edge(scale))
        } else {
            (CARD_EDGE, 1)
        };
        card(band, z, scale.len(6), CARD, edge, thick);
        let (x, y, w, h) = bounds(z);
        let base = y + (h + i32::from(kit.title.ascent)) / 2;
        band.text_centered(kit.title, x + w / 2, base, TEXT, word);
    }
    band.text_centered(
        kit.hint,
        mid,
        scale.y(216),
        HINT,
        "Tap the word your copy has there.",
    );
}

/// BACKUP CHECKED: the mark and the words in teal.
pub fn checked(band: &mut Band<'_>, scale: Scale, kit: &Kit) {
    brand::mark(band, scale);
    band.text_centered(kit.title, scale.x(160), scale.y(150), TEAL, CHECKED);
}

/// What BACKUP CHECKED says.
pub const CHECKED: &str = "!! Backup checked !!";
