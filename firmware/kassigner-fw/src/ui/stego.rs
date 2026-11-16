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

//! Steganography's screens: the carrier cards and the dialogs around hiding
//! a backup in a photo; and Stego Import's: the seed found, and its hint.

use super::band::Band;
use super::chrome::{buttons, card, corner, header, Nav};
use super::color::{CARD, GREEN_BUTTON, ORANGE, RED_BUTTON, TEAL, TEXT, TEXT_DIM};
use super::dialog::Dialog;
use super::gen::Icon;
use super::menu::LIST;
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;
use kassigner_protocol::stego::Carrier;

/// What a touch on STEGANOGRAPHY can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    /// The card of this carrier, by its place in [`Carrier::ALL`].
    Carrier(usize),
}

/// The cards, in design pixels: a menu row's 232 from x 44, clear of the
/// corners; 56 tall, 60 apart from y 46.
const CARD_X: i32 = 44;
const CARD_W: i32 = 232;
const CARD_H: i32 = 56;
const CARD_Y: i32 = 46;
const CARD_PITCH: i32 = 60;
/// Design pixels between a card's name and the line under it.
pub const CARD_GAP: i32 = 8;

/// Where a target counts.
pub const fn zone(scale: Scale, target: Target) -> Option<Zone> {
    match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        Target::Nav(_) => None,
        Target::Carrier(i) if i < Carrier::ALL.len() => {
            Some(scale.zone(CARD_X, CARD_Y + CARD_PITCH * i as i32, CARD_W, CARD_H))
        }
        Target::Carrier(_) => None,
    }
}

/// What is under a point.
pub fn target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    [Target::Nav(Nav::Back), Target::Nav(Nav::Home)]
        .into_iter()
        .chain((0..Carrier::ALL.len()).map(Target::Carrier))
        .find(|&t| zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// STEGANOGRAPHY: a card per carrier (Both is the other two together), its
/// name and, [`CARD_GAP`] under, where it hides the backup, in the body
/// font: small print is hard to read on the units.
pub fn draw(band: &mut Band<'_>, scale: Scale, kit: &Kit) {
    header(band, scale, kit, "STEGANOGRAPHY");
    buttons(band, scale);
    for (i, c) in Carrier::ALL.iter().enumerate() {
        let Some(z) = zone(scale, Target::Carrier(i)) else {
            continue;
        };
        card(band, z, scale.len(8), CARD, TEAL, 1);
        let (x, y, _, h) = bounds(z);
        let left = x + scale.len(12);
        let (up, down) = (i32::from(kit.title.ascent), i32::from(kit.body.ascent));
        let gap = scale.len(CARD_GAP);
        let top = y + (h - (up + gap + down)) / 2;
        band.text(kit.title, left, top + up, TEAL, c.label());
        band.text(kit.body, left, top + up + gap + down, TEXT, c.description());
    }
}

/// Characters of the descriptor a preview line holds, as dialog lines run
/// in the body font.
const LINE: usize = 24;

/// The descriptor over the preview's four lines, cut at the last space that
/// fits, else at the width: 64 characters take three lines, four at worst.
/// `text` is printable ASCII, so any byte is a boundary.
pub fn lines(text: &str) -> [&str; 4] {
    let mut out = [""; 4];
    let mut rest = text;
    for line in out.iter_mut() {
        if rest.is_empty() {
            break;
        }
        let cut = if rest.len() <= LINE {
            rest.len()
        } else {
            rest.as_bytes()[..=LINE]
                .iter()
                .rposition(|&c| c == b' ')
                .filter(|&at| at > 0)
                .unwrap_or(LINE)
        };
        *line = rest[..cut].trim_end();
        rest = rest[cut..].trim_start();
    }
    out
}

/// IMAGE DESCRIPTOR's preview: the text over up to four lines and, if one
/// is free, that it is the password. EDIT goes back to the keyboard.
pub fn preview(text: &str) -> Dialog<'_> {
    let [a, b, c, d] = lines(text);
    let d = if d.is_empty() {
        ("This caption is the password", TEXT_DIM)
    } else {
        (d, TEXT)
    };
    Dialog {
        title: "IMAGE DESCRIPTOR",
        title_ink: TEXT,
        rule: TEAL,
        lines: [(a, TEXT), (b, TEXT), (c, TEXT), d],
        cancel: "EDIT",
        accept: "USE",
        accept_face: TEAL,
        hold: None,
        choice: false,
    }
}

/// ADD HINT?: whether a recovery hint goes into the photo with the seed.
pub const fn add_hint() -> Dialog<'static> {
    Dialog {
        title: "ADD HINT?",
        title_ink: TEXT,
        rule: TEAL,
        lines: [
            ("A question whose answer", TEXT),
            ("is your 25th word, shown", TEXT),
            ("only after the photo opens.", TEXT),
            ("The word itself is never stored.", TEXT_DIM),
        ],
        cancel: "NO",
        accept: "YES",
        accept_face: TEAL,
        hold: None,
        choice: false,
    }
}

/// Bytes a photo's name takes on a dialog line: the card's longest name and
/// the cut's three dots.
pub const PHOTO_LINE: usize = kassigner_fat32::fat32::MAX_LONG_NAME + 3;

/// Design pixels a photo's name may take: every dialog line's width.
const LINE_ROOM: i32 = 300;

/// The photo's name as the list showed it, for HIDE BACKUP?, OVERWRITE?
/// and BACKUP HIDDEN: as much as fits, cut in the middle, into `out`.
pub fn photo_line<'o>(
    kit: &Kit,
    scale: Scale,
    name: &str,
    out: &'o mut [u8; PHOTO_LINE],
) -> &'o str {
    kit.body.fit(name, scale.len(LINE_ROOM), out)
}

/// HIDE BACKUP?: the photo, the carrier, the descriptor's first line, and
/// whether a hint goes too. Nothing is written before CONFIRM; CANCEL
/// drops everything.
pub fn confirm<'a>(
    photo: &'a str,
    carrier: Carrier,
    descriptor: &'a str,
    hint: bool,
) -> Dialog<'a> {
    let [first, ..] = lines(descriptor);
    Dialog {
        title: "HIDE BACKUP?",
        title_ink: TEXT,
        rule: TEAL,
        lines: [
            (photo, TEXT),
            (carrier.label(), TEAL),
            (first, TEXT_DIM),
            (
                if hint {
                    "With recovery hint"
                } else {
                    "No recovery hint"
                },
                TEXT_DIM,
            ),
        ],
        cancel: "CANCEL",
        accept: "CONFIRM",
        accept_face: TEAL,
        hold: None,
        choice: false,
    }
}

/// The preset hints: each a question whose answer is the 25th word.
pub const HINTS: [&str; 3] = [
    "My favorite place I lived?",
    "Name of my loved one?",
    "Song I can't stop humming?",
];

/// RECOVERY HINT's rows: the three presets, and Custom.
pub const HINT_ROWS: usize = HINTS.len() + 1;

/// What a touch on RECOVERY HINT can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintTarget {
    Nav(Nav),
    /// A preset, by its place in [`HINTS`]; `HINTS.len()` is Custom.
    Row(usize),
}

/// Where a target counts on RECOVERY HINT: the menus' rows.
pub const fn hint_zone(scale: Scale, target: HintTarget) -> Option<Zone> {
    match target {
        HintTarget::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        HintTarget::Nav(_) => None,
        HintTarget::Row(i) if i < HINT_ROWS => Some(LIST.touch(scale, i)),
        HintTarget::Row(_) => None,
    }
}

/// What is under a point on RECOVERY HINT.
pub fn hint_target(scale: Scale, x: u16, y: u16) -> Option<HintTarget> {
    [HintTarget::Nav(Nav::Back), HintTarget::Nav(Nav::Home)]
        .into_iter()
        .chain((0..HINT_ROWS).map(HintTarget::Row))
        .find(|&t| hint_zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// RECOVERY HINT: the presets in the body font their length needs (so not
/// a menu), and Custom.
pub fn draw_hints(band: &mut Band<'_>, scale: Scale, kit: &Kit) {
    header(band, scale, kit, "RECOVERY HINT");
    buttons(band, scale);
    for i in 0..HINT_ROWS {
        let z = LIST.row(scale, i);
        card(band, z, scale.len(6), CARD, TEAL, 1);
        let (x, y, _, h) = bounds(z);
        let side = i32::from(kit.icons.side);
        let (icon, label) = match HINTS.get(i) {
            Some(&hint) => (Icon::HelpCircle, hint),
            None => (Icon::EditPencil, "Custom hint"),
        };
        band.icon(x + scale.len(8), y + (h - side) / 2, kit.icons, icon, TEAL);
        band.text(kit.body, x + scale.len(42), y + scale.len(27), TEXT, label);
    }
}

/// LOAD SEED?: a seed Stego Import found, asked as a SeedQR's is, with
/// where it was. If the photo held a second, different backup, it says so,
/// and OTHER replaces CANCEL to open that one. Nothing is stored until LOAD.
pub const fn found(words: u8, carrier: Carrier, two: bool) -> Dialog<'static> {
    let read = match words {
        12 => "12-word seed found.",
        24 => "24-word seed found.",
        _ => "Seed found.",
    };
    Dialog {
        title: "LOAD SEED?",
        title_ink: TEXT,
        rule: TEAL,
        lines: [
            (read, TEXT),
            (carrier.description(), TEAL),
            (
                if two {
                    "The photo holds two backups"
                } else {
                    ""
                },
                ORANGE,
            ),
            ("It goes into a free slot", TEXT_DIM),
        ],
        cancel: if two { "OTHER" } else { "CANCEL" },
        accept: "LOAD",
        accept_face: GREEN_BUTTON,
        hold: None,
        choice: false,
    }
}

/// RECOVERY HINT: the seed's hint and, if a line is free, what it is for.
/// NEXT is the passphrase.
pub fn hint_shown(hint: &str) -> Dialog<'_> {
    let [a, b, c, d] = lines(hint);
    let d = if d.is_empty() {
        ("Its answer is your 25th word", TEXT_DIM)
    } else {
        (d, TEXT)
    };
    Dialog {
        title: "RECOVERY HINT",
        title_ink: TEXT,
        rule: TEAL,
        lines: [(a, TEXT), (b, TEXT), (c, TEXT), d],
        cancel: "CANCEL",
        accept: "NEXT",
        accept_face: TEAL,
        hold: None,
        choice: false,
    }
}

/// OVERWRITE?: the photo's metadata already holds a backup. Drawn in the
/// colours of overwriting a card file; the photo's own descriptor is
/// asked next, as that file's password is.
pub const fn overwrite(photo: &str) -> Dialog<'_> {
    Dialog {
        title: "OVERWRITE?",
        title_ink: ORANGE,
        rule: RED_BUTTON,
        lines: [
            (photo, TEXT),
            ("holds a backup already.", TEXT_DIM),
            ("Overwriting replaces it.", TEXT_DIM),
            ("Its descriptor is asked first.", TEXT_DIM),
        ],
        cancel: "CANCEL",
        accept: "OVERWRITE",
        accept_face: RED_BUTTON,
        hold: None,
        choice: false,
    }
}

/// BACKUP HIDDEN. DONE is the Export menu; MORE the carriers again, to hide
/// the same seed in another photo or carrier.
pub fn done<'a>(photo: &'a str, carrier: Carrier) -> Dialog<'a> {
    Dialog {
        title: "BACKUP HIDDEN",
        title_ink: TEXT,
        rule: TEAL,
        lines: [
            (photo, TEXT),
            (carrier.label(), TEAL),
            ("Import it back to check it,", TEXT_DIM),
            ("and keep the descriptor safe.", TEXT_DIM),
        ],
        cancel: "DONE",
        accept: "MORE",
        accept_face: TEAL,
        hold: None,
        choice: false,
    }
}
