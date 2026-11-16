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

//! Multisig's screens.
//!
//! - CREATE MULTISIG: M of N, each between "-" and "+", and NEXT; N up to
//!   [`MAX_MULTISIG_KEYS`], 1-of-1 included as in rusty-kaspa. Every "-"
//!   and "+" is always lit and a target, doing nothing at its limit:
//!   buttons that change look draw the eye.
//! - KEY k/N: where each cosigner's key comes from, and how many are in.
//! - DESCRIPTOR: the held group's M of N and keys, Save to SD and Show QR.
//! - LOAD MULTISIG?, drawn as LOAD SEED? is: a group read from a descriptor
//!   file.
//!
//! [`MAX_MULTISIG_KEYS`]: crate::limits::MAX_MULTISIG_KEYS

use super::band::Band;
use super::camera::Part;
use super::chrome::{buttons, card, centred, corner, header, step_button, Nav};
use super::color::{ACCENT, BACKGROUND, ORANGE, TEAL, TEXT, TEXT_DIM};
use super::dialog;
use super::menu::{self, Menu, LIST};
use super::scale::{Kit, Scale};
use crate::touch::Zone;

/// Which of CREATE MULTISIG's two numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    /// M: signatures required.
    Required,
    /// N: keys in the group.
    Total,
}

/// What a touch on CREATE MULTISIG can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    Minus(Row),
    Plus(Row),
    Next,
}

const ROW_Y: [i32; 2] = [70, 136];
const LABEL_Y: [i32; 2] = [62, 128];
const MINUS_X: i32 = 70;
const PLUS_X: i32 = 206;
const STEP: (i32, i32) = (44, 34);
const NEXT_AT: (i32, i32, i32, i32) = (80, 188, 160, 34);

const fn row_of(row: Row) -> usize {
    match row {
        Row::Required => 0,
        Row::Total => 1,
    }
}

/// Where a target counts; the page arrows nowhere, as the screen has none.
pub fn zone(scale: Scale, target: Target) -> Option<Zone> {
    let (x, y, w, h) = match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => return Some(corner(scale, nav)),
        Target::Nav(_) => return None,
        Target::Minus(row) => (MINUS_X, ROW_Y[row_of(row)], STEP.0, STEP.1),
        Target::Plus(row) => (PLUS_X, ROW_Y[row_of(row)], STEP.0, STEP.1),
        Target::Next => NEXT_AT,
    };
    Some(scale.zone(x, y, w, h))
}

/// What is under a point.
pub fn target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Minus(Row::Required),
        Target::Plus(Row::Required),
        Target::Minus(Row::Total),
        Target::Plus(Row::Total),
        Target::Next,
    ]
    .into_iter()
    .find(|&t| zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// CREATE MULTISIG with `m` of `n`.
pub fn draw_create(band: &mut Band<'_>, scale: Scale, kit: &Kit, m: usize, n: usize) {
    header(band, scale, kit, "CREATE MULTISIG");
    buttons(band, scale);
    let mid = scale.x(160);
    for (row, label, value) in [
        (Row::Required, "Required sigs (M):", m),
        (Row::Total, "Total keys (N):", n),
    ] {
        let i = row_of(row);
        band.text_centered(kit.body, mid, scale.y(LABEL_Y[i]), TEXT_DIM, label);
        for (x, sign) in [(MINUS_X, "-"), (PLUS_X, "+")] {
            let z = scale.zone(x, ROW_Y[i], STEP.0, STEP.1);
            step_button(band, scale, kit, z, sign, true);
        }
        let mut num = [0u8; 4];
        let k = Part::Number(value).write(&mut num, 0);
        let said = core::str::from_utf8(&num[..k]).unwrap_or("");
        let z = scale.zone(
            MINUS_X + STEP.0,
            ROW_Y[i],
            PLUS_X - MINUS_X - STEP.0,
            STEP.1,
        );
        centred(band, kit.word, z, ACCENT, said);
    }
    let z = scale.zone(NEXT_AT.0, NEXT_AT.1, NEXT_AT.2, NEXT_AT.3);
    card(band, z, scale.len(6), TEAL, TEAL, 1);
    centred(band, kit.title, z, BACKGROUND, "NEXT");
}

/// KEY k/N's titles, `KEY 1/1` to `KEY 5/5`, by N then k.
const KEY_TITLES: [&str; 15] = [
    "KEY 1/1", "KEY 1/2", "KEY 2/2", "KEY 1/3", "KEY 2/3", "KEY 3/3", "KEY 1/4", "KEY 2/4",
    "KEY 3/4", "KEY 4/4", "KEY 1/5", "KEY 2/5", "KEY 3/5", "KEY 4/5", "KEY 5/5",
];

/// SELECT SEED's titles, `SELECT SEED (1/1)` to `(5/5)`, in
/// [`KEY_TITLES`]' order.
const SELECT_TITLES: [&str; 15] = [
    "SELECT SEED (1/1)",
    "SELECT SEED (1/2)",
    "SELECT SEED (2/2)",
    "SELECT SEED (1/3)",
    "SELECT SEED (2/3)",
    "SELECT SEED (3/3)",
    "SELECT SEED (1/4)",
    "SELECT SEED (2/4)",
    "SELECT SEED (3/4)",
    "SELECT SEED (4/4)",
    "SELECT SEED (1/5)",
    "SELECT SEED (2/5)",
    "SELECT SEED (3/5)",
    "SELECT SEED (4/5)",
    "SELECT SEED (5/5)",
];

/// Where `key` of `of`, counted from 1, sits in the title tables.
const fn title_at(key: usize, of: usize) -> Option<usize> {
    if key >= 1 && key <= of && of <= 5 {
        Some(of * (of - 1) / 2 + key - 1)
    } else {
        None
    }
}

/// SELECT SEED's title, for key `key` of `of`, counted from 1.
pub const fn select_seed(key: usize, of: usize) -> &'static str {
    match title_at(key, of) {
        Some(i) => SELECT_TITLES[i],
        None => "SELECT SEED",
    }
}

/// KEY k/N's count of keys already in.
const ADDED: [&str; 5] = [
    "",
    "1 key added",
    "2 keys added",
    "3 keys added",
    "4 keys added",
];

/// KEY k/N, `key` of `of` counted from 1: a menu of [`menu::ADD_KEY`].
pub const fn add_key(key: usize, of: usize) -> Menu {
    let title = match title_at(key, of) {
        Some(i) => KEY_TITLES[i],
        None => "KEY",
    };
    Menu {
        title,
        items: menu::ADD_KEY,
    }
}

/// KEY k/N: [`add_key`]'s menu and, where a fourth row would be, how many
/// keys are in, in the accent.
pub fn draw_add_key(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    (key, of): (usize, usize),
    lit: Option<menu::Target>,
) {
    menu::draw(band, scale, kit, &add_key(key, of), 0, lit);
    let added = ADDED.get(key.saturating_sub(1)).copied().unwrap_or("");
    if !added.is_empty() {
        let y = LIST.row_top(menu::ADD_KEY.len()) + 26;
        band.text_centered(kit.body, scale.x(160), scale.y(y), ACCENT, added);
    }
}

/// DESCRIPTOR's title.
pub const DESCRIPTOR_TITLE: &str = "DESCRIPTOR";

/// Its two answers, placed as a dialog's: the file on the left, as on every
/// export dialog.
pub const DESCRIPTOR_ANSWERS: (&str, &str) = ("Save to SD", "Show QR");

/// Characters of a key DESCRIPTOR shows from its start (`kpub` and six) and
/// its end. Measured: a line fits the panel less ten each side on both
/// panels, even for a key of only the widest letter.
pub const KEY_HEAD: usize = 10;
pub const KEY_TAIL: usize = 6;

/// The room for DESCRIPTOR's key lines, design rows from and to, and a
/// line's height: five keys fill it; fewer are centred in it.
const KEYS_FROM: i32 = 70;
const KEYS_TO: i32 = 182;
const KEY_LINE: i32 = 22;
/// The M of N line's baseline.
const NOTE_BASE: i32 = 60;

/// Where LOAD MULTISIG? says the seed in use is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedIn {
    /// No seed in use.
    NoSeed,
    /// One in use, none of the group's keys its own.
    Not,
    /// Its key is the group's cosigner at this number, from 0.
    Cosigner(usize),
}

/// What LOAD MULTISIG? says of the group the unit holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// None held: nothing is replaced.
    Nothing,
    /// The very group read: nothing changes.
    Same,
    /// Another, of this M and N, to be replaced.
    Other(usize, usize),
}

/// LOAD MULTISIG?'s lines, each into its buffer: what was read, where the
/// seed in use is among its keys, and what it does to the group held.
pub fn load_lines(
    (m, n): (usize, usize),
    seed: SeedIn,
    held: Held,
    out: &mut [[u8; 40]; 3],
) -> [&str; 3] {
    let [read, own, replaces] = out;
    let mut k = Part::Number(m).write(read, 0);
    k = Part::Text("-of-").write(read, k);
    k = Part::Number(n).write(read, k);
    k = Part::Text(" multisig read.").write(read, k);
    let read = core::str::from_utf8(&read[..k]).unwrap_or("");

    let k = match seed {
        SeedIn::NoSeed => Part::Text("No seed in use.").write(own, 0),
        SeedIn::Not => Part::Text("The seed in use is not in it.").write(own, 0),
        SeedIn::Cosigner(i) => {
            let k = Part::Text("The seed in use is cosigner ").write(own, 0);
            let k = Part::Number(i).write(own, k);
            Part::Text(".").write(own, k)
        }
    };
    let own = core::str::from_utf8(&own[..k]).unwrap_or("");

    let k = match held {
        Held::Nothing => 0,
        Held::Same => Part::Text("It is the group held already.").write(replaces, 0),
        Held::Other(hm, hn) => {
            let k = Part::Text("It replaces the ").write(replaces, 0);
            let k = Part::Number(hm).write(replaces, k);
            let k = Part::Text("-of-").write(replaces, k);
            let k = Part::Number(hn).write(replaces, k);
            Part::Text(" held.").write(replaces, k)
        }
    };
    let replaces = core::str::from_utf8(&replaces[..k]).unwrap_or("");
    [read, own, replaces]
}

/// LOAD MULTISIG? for an `m`-of-`n` group: [`load_lines`], the last in
/// orange, and CANCEL and LOAD, `lit` the one under a finger.
pub fn draw_load(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    (m, n): (usize, usize),
    (seed, held): (SeedIn, Held),
    lit: Option<dialog::Target>,
) {
    let mut out = [[0u8; 40]; 3];
    let [read, own, replaces] = load_lines((m, n), seed, held, &mut out);
    dialog::draw(
        band,
        scale,
        kit,
        &dialog::load_group(read, own, replaces),
        lit,
    );
}

/// A key as DESCRIPTOR shows it, `n: kpub2JKepG...Lq8y14`, into `out`; a
/// text too short to cut, whole.
pub fn key_line<'o>(n: usize, kpub: &str, out: &'o mut [u8; 32]) -> &'o str {
    let mut k = Part::Number(n).write(out, 0);
    k = Part::Text(": ").write(out, k);
    match (kpub.get(..KEY_HEAD), kpub.len().checked_sub(KEY_TAIL)) {
        (Some(head), Some(from)) if from > KEY_HEAD => {
            k = Part::Text(head).write(out, k);
            k = Part::Text("...").write(out, k);
            k = Part::Text(kpub.get(from..).unwrap_or("")).write(out, k);
        }
        _ => k = Part::Text(kpub).write(out, k),
    }
    core::str::from_utf8(&out[..k]).unwrap_or("")
}

/// DESCRIPTOR: `m`-of-`n` in the group's orange, `keys` a line each from
/// 0 as on the address screen, the seed in use's (`own`) in the accent,
/// and the two answers. The lines share a left edge, numbers in a column.
pub fn draw_descriptor(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    (m, n): (usize, usize),
    keys: &[&str],
    own: Option<usize>,
    lit: Option<dialog::Target>,
) {
    header(band, scale, kit, DESCRIPTOR_TITLE);
    buttons(band, scale);

    let mut note = [0u8; 24];
    let mut k = Part::Number(m).write(&mut note, 0);
    k = Part::Text("-of-").write(&mut note, k);
    k = Part::Number(n).write(&mut note, k);
    k = Part::Text(" multisig").write(&mut note, k);
    let note = core::str::from_utf8(&note[..k]).unwrap_or("");
    band.text_centered(kit.body, scale.x(160), scale.y(NOTE_BASE), ORANGE, note);

    let shown = keys.len().min(n).min(5);
    let mut widest = 0;
    for (i, kpub) in keys.iter().take(shown).enumerate() {
        let mut line = [0u8; 32];
        widest = widest.max(kit.title.width(key_line(i, kpub, &mut line)));
    }
    let x = scale.x(160) - widest / 2;
    let top = KEYS_FROM + (KEYS_TO - KEYS_FROM - shown as i32 * KEY_LINE) / 2;
    for (i, kpub) in keys.iter().take(shown).enumerate() {
        let mut line = [0u8; 32];
        let line = key_line(i, kpub, &mut line);
        let ink = if own == Some(i) { ACCENT } else { TEXT };
        let base = top + (i as i32 + 1) * KEY_LINE - 5;
        band.text(kit.title, x, scale.y(base), ink, line);
    }

    dialog::choice(band, scale, kit, DESCRIPTOR_ANSWERS, lit);
}
