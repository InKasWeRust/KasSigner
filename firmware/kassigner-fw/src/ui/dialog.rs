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

//! A question with two answers under up to four lines: Cancel on the left
//! and the answer that acts on the right, or two choices
//! ([`Dialog::choice`]). Back and Home both mean Cancel.

use super::band::Band;
use super::chrome::{buttons, card, corner, header_in, lit_edge, Nav};
use super::color::{
    ACCENT, BACKGROUND, CARD, CARD_EDGE, DANGER, GREEN_BUTTON, ORANGE, RED, RED_BUTTON, TEAL, TEXT,
    TEXT_DIM,
};
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;

/// What a dialog says and how its answer looks.
#[derive(Clone, Copy, Debug)]
pub struct Dialog<'a> {
    pub title: &'a str,
    /// The title's colour, and the rule's under it.
    pub title_ink: u16,
    pub rule: u16,
    /// Four lines, each in its colour; an empty one is left out.
    pub lines: [(&'a str, u16); 4],
    /// The left answer's label: CANCEL, or the first of two choices.
    pub cancel: &'a str,
    /// The answer that acts: its label and its face.
    pub accept: &'a str,
    pub accept_face: u16,
    /// How far an armed answer has been held, 0 to 100: the button then
    /// reads `HOLD 4s` and fills from the left.
    pub hold: Option<u8>,
    /// Two choices rather than a cancel and an action, drawn by
    /// [`choice()`]; `accept_face` is then not used.
    pub choice: bool,
}

/// Load a SeedQR of `words` words: nothing is stored until this is
/// answered.
pub const fn load(words: usize) -> Dialog<'static> {
    let read = match words {
        12 => "12-word SeedQR read.",
        24 => "24-word SeedQR read.",
        _ => "SeedQR read.",
    };
    Dialog {
        title: "LOAD SEED?",
        title_ink: TEXT,
        rule: TEAL,
        lines: [
            (read, TEXT),
            ("It goes into a free slot", TEXT_DIM),
            ("and becomes the seed in use.", TEXT_DIM),
            ("", TEXT),
        ],
        cancel: "CANCEL",
        accept: "LOAD",
        accept_face: GREEN_BUTTON,
        hold: None,
        choice: false,
    }
}

/// Load a multisig group read from a descriptor: nothing changes until
/// this is answered. `read` says what was read (`2-of-3 multisig read.`),
/// `seed` where the seed in use is among its keys, `held` that it replaces
/// the group held, or `""`.
pub const fn load_group<'a>(read: &'a str, seed: &'a str, held: &'a str) -> Dialog<'a> {
    Dialog {
        title: "LOAD MULTISIG?",
        title_ink: TEXT,
        rule: TEAL,
        lines: [(read, TEXT), (seed, TEXT_DIM), (held, ORANGE), ("", TEXT)],
        cancel: "CANCEL",
        accept: "LOAD",
        accept_face: GREEN_BUTTON,
        hold: None,
        choice: false,
    }
}

/// Import Raw Key's check, before the key is stored: the address it
/// controls, to compare with the one the funds are on. A raw key has no
/// checksum, so a typo is another key with another address.
/// [`super::address::draw_ask`] draws the address under the first line.
pub const fn import_key() -> Dialog<'static> {
    Dialog {
        title: "IMPORT KEY?",
        title_ink: TEXT,
        rule: TEAL,
        lines: [
            ("This key's address:", TEXT_DIM),
            ("", TEXT),
            ("", TEXT),
            ("", TEXT),
        ],
        cancel: "CANCEL",
        accept: "IMPORT",
        accept_face: GREEN_BUTTON,
        hold: None,
        choice: false,
    }
}

/// Sign Message's question: the address that signs, drawn under the first
/// line.
pub const fn sign_with() -> Dialog<'static> {
    Dialog {
        title: "SIGN MESSAGE?",
        title_ink: TEXT,
        rule: TEAL,
        lines: [
            ("Sign with this address:", TEXT_DIM),
            ("", TEXT),
            ("", TEXT),
            ("", TEXT),
        ],
        cancel: "CANCEL",
        accept: "SIGN",
        accept_face: GREEN_BUTTON,
        hold: None,
        choice: false,
    }
}

/// A signed message read back and checked: valid, not, or signed by an
/// address that carries no key to check with (a script's). DETAILS shows
/// the signature and the address.
pub const fn checked(valid: Option<bool>) -> Dialog<'static> {
    let (title, ink) = match valid {
        Some(true) => ("VALID SIGNATURE", TEAL),
        Some(false) => ("INVALID SIGNATURE", DANGER),
        None => ("CANNOT CHECK", ORANGE),
    };
    Dialog {
        title,
        title_ink: ink,
        rule: ink,
        lines: [("Signed by:", TEXT_DIM), ("", TEXT), ("", TEXT), ("", TEXT)],
        cancel: "BACK",
        accept: "DETAILS",
        accept_face: GREEN_BUTTON,
        hold: None,
        choice: false,
    }
}

/// A request none of whose inputs is among the addresses checked so far:
/// search the next batch, or not. `checked` says how many, as
/// `first 225 addresses.`
pub const fn search(checked: &str) -> Dialog<'_> {
    Dialog {
        title: "NOT FOUND",
        title_ink: ORANGE,
        rule: TEAL,
        lines: [
            ("No input is in this seed's", TEXT),
            (checked, TEXT),
            ("Search 200 more?", TEXT),
            ("It takes a few seconds.", TEXT_DIM),
        ],
        cancel: "CANCEL",
        accept: "SEARCH",
        accept_face: GREEN_BUTTON,
        hold: None,
        choice: false,
    }
}

/// The warning before a cosigner's key is scanned: a watch-only kpub
/// (`44'`) and a cosigner's (`45'`) cannot be told apart on the wire, so
/// this is said where the mistake would be made.
pub const fn cosigner_key() -> Dialog<'static> {
    Dialog {
        title: "COSIGNER KEY",
        title_ink: ORANGE,
        rule: TEAL,
        lines: [
            ("Scan the kpub MULTISIG QR only.", TEXT),
            ("A watch-only 44' kpub makes a", ORANGE),
            ("wallet no one can ever spend.", ORANGE),
            ("", TEXT),
        ],
        cancel: "CANCEL",
        accept: "SCAN",
        accept_face: GREEN_BUTTON,
        hold: None,
        choice: false,
    }
}

/// Delete the slot `slot` names: once Delete is tapped, `hold` says how
/// long it has been held.
pub const fn delete(slot: &str, hold: Option<u8>) -> Dialog<'_> {
    Dialog {
        title: "DELETE SEED?",
        title_ink: ORANGE,
        rule: RED_BUTTON,
        lines: [
            (slot, TEXT),
            ("This action is irreversible.", ORANGE),
            ("Without a backup, your funds", TEXT),
            ("will be permanently lost.", TEXT),
        ],
        cancel: "CANCEL",
        accept: "DELETE",
        accept_face: RED_BUTTON,
        hold,
        choice: false,
    }
}

/// Format the card in the slot, asked as the delete is.
///
/// A format writes a new file system and leaves the data area as it was,
/// so the words promise the loss of the files and no more: what they held
/// stays on the card until something is written over it.
pub const fn format(hold: Option<u8>) -> Dialog<'static> {
    Dialog {
        title: "WARNING",
        title_ink: ORANGE,
        rule: RED_BUTTON,
        lines: [
            ("ALL FILES WILL BE LOST", ORANGE),
            ("Every file is removed.", TEXT_DIM),
            ("Old data is not wiped.", TEXT_DIM),
            ("", TEXT),
        ],
        cancel: "CANCEL",
        accept: "FORMAT",
        accept_face: RED_BUTTON,
        hold,
        choice: false,
    }
}

/// A seed with a passphrase, its backup about to be saved with no password
/// (ENCRYPT FILE?'s No): what then protects it, and what does not. The file
/// holds the words, which with no passphrase open a wallet too, so the last
/// line says the words alone are exposed. Asked as a format is, SAVE held:
/// the one save a card's finder could read.
pub const fn no_password(hold: Option<u8>) -> Dialog<'static> {
    Dialog {
        title: "WARNING",
        title_ink: ORANGE,
        rule: RED_BUTTON,
        lines: [
            ("NO PASSWORD ON THIS FILE", ORANGE),
            ("Only your passphrase", TEXT_DIM),
            ("protects this backup.", TEXT_DIM),
            ("The words alone are exposed.", TEXT_DIM),
        ],
        cancel: "CANCEL",
        accept: "SAVE",
        accept_face: RED_BUTTON,
        hold,
        choice: false,
    }
}

/// A backup's file name is on the card already: overwrite it, or not.
/// `name` is as the screen shows it, `NAME.KAS`.
pub const fn overwrite(name: &str) -> Dialog<'_> {
    Dialog {
        title: "OVERWRITE?",
        title_ink: ORANGE,
        rule: RED_BUTTON,
        lines: [
            (name, TEXT),
            ("is on the card already.", TEXT_DIM),
            ("Overwriting replaces it.", TEXT_DIM),
            ("", TEXT),
        ],
        cancel: "CANCEL",
        accept: "OVERWRITE",
        accept_face: RED_BUTTON,
        hold: None,
        choice: false,
    }
}

/// Delete a backup from the card, `name` as the screen shows it, asked as
/// a seed's delete is.
pub const fn delete_backup(name: &str, hold: Option<u8>) -> Dialog<'_> {
    Dialog {
        title: "DELETE BACKUP?",
        title_ink: ORANGE,
        rule: RED_BUTTON,
        lines: [
            (name, TEXT),
            ("This action is irreversible.", ORANGE),
            ("The backup file will be", TEXT),
            ("permanently deleted from SD.", TEXT),
        ],
        cancel: "CANCEL",
        accept: "DELETE",
        accept_face: RED_BUTTON,
        hold,
        choice: false,
    }
}

/// A question between two choices ([`Dialog::choice`]): two lines of
/// `body` over two dim lines of `hints`.
const fn ask<'a>(
    title: &'a str,
    body: [&'a str; 2],
    hints: [&'a str; 2],
    (left, right): (&'a str, &'a str),
) -> Dialog<'a> {
    Dialog {
        title,
        title_ink: TEAL,
        rule: TEAL,
        lines: [
            (body[0], TEXT),
            (body[1], TEXT),
            (hints[0], TEXT_DIM),
            (hints[1], TEXT_DIM),
        ],
        cancel: left,
        accept: right,
        accept_face: CARD,
        hold: None,
        choice: true,
    }
}

/// A kpub in two frames: cycle them, or tap for each.
pub const fn qr_mode() -> Dialog<'static> {
    ask(
        "QR DISPLAY MODE",
        ["Multiple QR frames required.", "Choose display mode:"],
        [
            "Auto: frames cycle automatically",
            "Manual: tap to advance frames",
        ],
        ("Auto Cycle", "Manual"),
    )
}

/// The kpub has been shown: save it to the card, or show it again.
pub const fn kpub_exported() -> Dialog<'static> {
    let mut d = ask(
        "KPUB EXPORTED",
        ["Watch-only key exported.", "Save to SD card or return"],
        ["", ""],
        ("Save to SD", "Back to QR"),
    );
    d.lines[2] = ("to view the QR code.", TEXT);
    d
}

/// The signed transaction has been shown: save it to the card, or show it
/// again.
pub const fn signed_tx() -> Dialog<'static> {
    let mut d = ask(
        "SIGNED TX",
        [
            "Transaction signed successfully.",
            "Save to SD card or return",
        ],
        ["", ""],
        ("Save to SD", "Back to QR"),
    );
    d.lines[2] = ("to view the QR code.", TEXT);
    d
}

/// The signed message has been shown: save it to the card, or show it
/// again.
pub const fn message_exported() -> Dialog<'static> {
    let mut d = ask(
        "MESSAGE EXPORTED",
        ["Signed message exported.", "Save to SD card or return"],
        ["", ""],
        ("Save to SD", "Back to QR"),
    );
    d.lines[2] = ("to view the QR code.", TEXT);
    d
}

/// An address has been shown: save it to the card, or show it again.
pub const fn address_exported() -> Dialog<'static> {
    let mut d = ask(
        "ADDRESS EXPORTED",
        ["Address exported.", "Save to SD card or return"],
        ["", ""],
        ("Save to SD", "Back to QR"),
    );
    d.lines[2] = ("to view the QR code.", TEXT);
    d
}

/// A seed has been shown: its backup to the card, or the code again. Not
/// called encrypted: a seed with a passphrase may be saved with no password
/// ([`no_password`]).
pub const fn seed_exported() -> Dialog<'static> {
    let mut d = ask(
        "SEED EXPORTED",
        ["Seed exported.", "Save a backup to the card"],
        ["", ""],
        ("Save to SD", "Back to QR"),
    );
    d.lines[2] = ("or return to the QR code.", TEXT);
    d
}

/// A kpub the camera read: save it to the card, or show it. Save to SD on
/// the left, as on every export dialog.
pub const fn kpub_scanned() -> Dialog<'static> {
    ask(
        "KPUB SCANNED",
        ["Watch-only key received.", "Save to SD or display as QR."],
        ["", ""],
        ("Save to SD", "Show QR"),
    )
}

/// A file about to be written: sealed under a password, or plain.
pub const fn encrypt_file() -> Dialog<'static> {
    ask(
        "ENCRYPT FILE?",
        ["Encrypt the file with a", "password before saving?"],
        ["", ""],
        ("Yes", "No"),
    )
}

/// BACKUP CHECK: a seed made on this unit, its words or its code (`qr`)
/// just shown, checked now or later; until it is, the seed is not used.
pub const fn backup_check(qr: bool) -> Dialog<'static> {
    let body = if qr {
        ["Scan the copy you made", "of this code to check it."]
    } else {
        ["Pick three of the words", "from the copy you wrote."]
    };
    let mut d = ask("BACKUP CHECK", body, ["", ""], ("Check", "Later"));
    d.lines[2] = ("Until checked, the seed is", ORANGE);
    d.lines[3] = ("only backed up, never used.", ORANGE);
    d
}

/// UNEVEN ROLLS: a face of the dice came up under eight percent of the
/// rolls, `count` times in `rolls`. A warning, not a refusal: roll again or
/// use them. `first` and `second` hold the two lines saying so.
pub fn uneven_rolls<'a>(
    (face, count, rolls): (u8, usize, usize),
    first: &'a mut [u8; 32],
    second: &'a mut [u8; 16],
) -> Dialog<'a> {
    use super::camera::Part;
    let mut n = Part::Text("Face ").write(first, 0);
    n = Part::Number(usize::from(face)).write(first, n);
    n = Part::Text(" came up ").write(first, n);
    n = Part::Number(count).write(first, n);
    n = Part::Text(if count == 1 { " time" } else { " times" }).write(first, n);
    let mut m = Part::Text("in ").write(second, 0);
    m = Part::Number(rolls).write(second, m);
    m = Part::Text(" rolls.").write(second, m);
    let lines = [
        core::str::from_utf8(&first[..n]).unwrap_or(""),
        core::str::from_utf8(&second[..m]).unwrap_or(""),
    ];
    let mut d = ask("UNEVEN ROLLS", lines, ["", ""], ("Roll again", "Use them"));
    d.lines[2] = ("Fair dice rarely do this.", ORANGE);
    d
}

/// What a touch on a dialog can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    Cancel,
    Accept,
}

/// The lines' baselines, in design rows.
const LINES: [i32; 4] = [65, 95, 120, 145];

/// Where a target is. The page arrows are not on a dialog.
pub const fn zone(scale: Scale, target: Target) -> Option<Zone> {
    match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        Target::Nav(_) => None,
        Target::Cancel => Some(scale.zone(30, 185, 120, 40)),
        Target::Accept => Some(scale.zone(170, 185, 120, 40)),
    }
}

/// What is under a point, if anything.
pub fn target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Cancel,
        Target::Accept,
    ]
    .into_iter()
    .find(|&t| zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// A dialog. `lit` is what is under a finger, if anything.
pub fn draw(band: &mut Band<'_>, scale: Scale, kit: &Kit, d: &Dialog<'_>, lit: Option<Target>) {
    header_in(band, scale, kit, d.title, d.title_ink, d.rule);
    buttons(band, scale);
    for ((text, ink), y) in d.lines.iter().zip(LINES) {
        if !text.is_empty() {
            band.text_centered(kit.body, scale.x(160), scale.y(y), *ink, text);
        }
    }

    let edge = |t: Target| lit == Some(t);
    let r = scale.len(8);
    let thick = lit_edge(scale);

    if d.choice {
        return choice(band, scale, kit, (d.cancel, d.accept), lit);
    }

    // Cancel: a teal outline, lit brighter.
    if let Some(z) = zone(scale, Target::Cancel) {
        let ink = if edge(Target::Cancel) { ACCENT } else { TEAL };
        card(band, z, r, BACKGROUND, ink, thick);
        let (x, y, w, _) = bounds(z);
        band.text_centered(kit.title, x + w / 2, y + scale.len(27), ink, d.cancel);
    }
    // The answer that acts: filled, edged when lit; armed for a hold, it
    // fills from the left as the finger stays.
    if let Some(z) = zone(scale, Target::Accept) {
        let ink = if edge(Target::Accept) {
            ACCENT
        } else {
            d.accept_face
        };
        card(band, z, r, d.accept_face, ink, thick);
        let (x, y, w, h) = bounds(z);
        let label = match d.hold {
            Some(held) => {
                let inset = scale.len(5);
                let fill = (w - 2 * inset) * i32::from(held.min(100)) / 100;
                band.fill(x + inset, y + inset, fill, h - 2 * inset, RED);
                "HOLD 4s"
            }
            None => d.accept,
        };
        // Black on teal, as on every teal button; white on green and red.
        let ink = if d.accept_face == TEAL {
            BACKGROUND
        } else {
            TEXT
        };
        band.text_centered(kit.title, x + w / 2, y + scale.len(27), ink, label);
    }
}

/// Two choices where a dialog's answers are, `left` filled teal and
/// `right` a card, each lit under a finger: for a dialog that asks between
/// two, and screens such as DESCRIPTOR.
pub fn choice(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    (left, right): (&str, &str),
    lit: Option<Target>,
) {
    let edge = |t: Target| lit == Some(t);
    let r = scale.len(8);
    let thick = lit_edge(scale);
    if let Some(z) = zone(scale, Target::Cancel) {
        let e = if edge(Target::Cancel) { ACCENT } else { TEAL };
        card(band, z, r, TEAL, e, thick);
        let (x, y, w, _) = bounds(z);
        band.text_centered(kit.title, x + w / 2, y + scale.len(27), BACKGROUND, left);
    }
    if let Some(z) = zone(scale, Target::Accept) {
        let (e, t) = if edge(Target::Accept) {
            (ACCENT, thick)
        } else {
            (CARD_EDGE, 1)
        };
        card(band, z, r, CARD, e, t);
        let (x, y, w, _) = bounds(z);
        band.text_centered(kit.title, x + w / 2, y + scale.len(27), TEXT, right);
    }
}
