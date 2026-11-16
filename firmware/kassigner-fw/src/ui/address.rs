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

//! Seed Tools' Address: the address at an index, on a chain.
//!
//! The address, a Receive or Change switch, and "<", the index, ">" at the
//! foot; the index opens the keypad, and a tap on the address shows its
//! code as large as the panel allows. A raw key has one address: no switch,
//! no foot row.
//!
//! The same screen shows the seed's KCC-3 addresses, a multisig group's
//! address with an orange line under the title (M of N and the cosigner
//! whose branch every key is derived at, between "-" and "+"), Signing
//! Keys' private keys, and kprv Master and kprv Account as text alone.

use super::band::Band;
use super::camera::Part;
use super::chrome::{buttons, card, centred, corner, header, Nav, CORNER_DEPTH};
use super::color::{
    BACKGROUND, CARD, ORANGE, SHADOW_EDGE, SHADOW_FACE, SHADOW_TEXT, TEAL, TEXT, TEXT_DIM,
};
use super::scale::{bounds, Kit, Scale, LARGE, SMALL};
use crate::touch::Zone;
use kassigner_hal::display::Size;

/// What a touch on the address screen can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    /// The address itself: shown as a code.
    Address,
    /// Receive or Change.
    Chain,
    /// The index before.
    Before,
    /// The index: the keypad.
    Index,
    /// The index after.
    After,
    /// A group's "-", under the title: the cosigner before.
    CosignerBefore,
    /// Its "+": the cosigner after.
    CosignerAfter,
}

/// Places in design pixels. The address counts from under Back and Home to
/// the switch.
const ADDRESS_AT: (i32, i32, i32, i32) = (0, CORNER_DEPTH, 320, 174 - CORNER_DEPTH);
/// A group's "-", line and "+", between Back and Home; its address, from
/// under the line to the switch.
const COSIGNER_BEFORE_AT: (i32, i32, i32, i32) = (44, 46, 40, 28);
const COSIGNER_LINE_AT: (i32, i32, i32, i32) = (84, 46, 152, 28);
const COSIGNER_AFTER_AT: (i32, i32, i32, i32) = (236, 46, 40, 28);
const GROUP_ADDRESS_AT: (i32, i32, i32, i32) = (0, 76, 320, 98);
/// Where a group's "-" and "+" count: in over the line's ends and 22 below
/// them, as taps aimed at them land low; the address counts under that.
const COSIGNER_BEFORE_TOUCH: (i32, i32, i32, i32) = (42, 40, 74, 56);
const COSIGNER_AFTER_TOUCH: (i32, i32, i32, i32) = (204, 40, 74, 56);
const GROUP_ADDRESS_TOUCH: (i32, i32, i32, i32) = (0, 96, 320, 78);
/// Where a group's "<" and ">" count: from under the address to the foot,
/// beside the switch.
const GROUP_BEFORE_TOUCH: (i32, i32, i32, i32) = (0, 174, 90, 66);
const GROUP_AFTER_TOUCH: (i32, i32, i32, i32) = (230, 174, 90, 66);
const CHAIN_AT: (i32, i32, i32, i32) = (90, 176, 140, 28);
const BEFORE_AT: (i32, i32, i32, i32) = (10, 210, 50, 28);
const INDEX_AT: (i32, i32, i32, i32) = (110, 210, 100, 28);
const AFTER_AT: (i32, i32, i32, i32) = (260, 210, 50, 28);
/// Where "<" and ">" count: from the edge to ten short of the index, and
/// from under the switch to the foot.
const BEFORE_TOUCH: (i32, i32, i32, i32) = (0, 206, 100, 34);
const AFTER_TOUCH: (i32, i32, i32, i32) = (220, 206, 100, 34);
/// Characters a line of a private key's hex, and a line's height. Addresses
/// break by [`address_per_line`].
const KEY_PER_LINE: usize = 25;
const LINE_H: i32 = 26;
/// Lines an address takes, at the fewest and the most.
const ADDRESS_LINES: usize = 3;
const ADDRESS_LINES_MAX: usize = 4;
/// How wide a line of an address or a kprv may run, in design pixels: the
/// panel less ten each side.
const TEXT_W: i32 = 300;
/// Lines a kprv may take: as many as fit between the header and the foot.
pub const TEXT_LINES: usize = 6;

/// Import from SD's Multisig Address title.
pub const FILE_ADDRESS_TITLE: &str = "MULTISIG ADDRESS";
/// Where a file's address stops, and its file name's baseline.
const FILE_LINES_TO: i32 = 185;
const FILE_NAME_BASE: i32 = 210;

/// kprv Master's title.
pub const KPRV_MASTER: &str = "KPRV MASTER";
/// kprv Account's title.
pub const KPRV_ACCOUNT: &str = "KPRV ACCOUNT";

/// Where a target counts. `single` is a raw key's one address; `first`
/// that the index is 0, where "<" does nothing.
pub fn zone(scale: Scale, single: bool, first: bool, target: Target) -> Option<Zone> {
    let at = match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => return Some(corner(scale, nav)),
        Target::Nav(_) => return None,
        Target::Address => ADDRESS_AT,
        Target::CosignerBefore | Target::CosignerAfter => return None,
        _ if single => return None,
        Target::Chain => CHAIN_AT,
        Target::Before if first => return None,
        Target::Before => BEFORE_TOUCH,
        Target::Index => INDEX_AT,
        Target::After => AFTER_TOUCH,
    };
    Some(scale.zone(at.0, at.1, at.2, at.3))
}

/// Where a target counts on a group's address screen: the address, "-" and
/// "+", and "<" and ">" beside the switch have their own places; the rest
/// are as on [`zone`]'s.
pub fn group_zone(scale: Scale, first: bool, target: Target) -> Option<Zone> {
    let at = match target {
        Target::Address => GROUP_ADDRESS_TOUCH,
        Target::CosignerBefore => COSIGNER_BEFORE_TOUCH,
        Target::CosignerAfter => COSIGNER_AFTER_TOUCH,
        Target::Before if first => return None,
        Target::Before => GROUP_BEFORE_TOUCH,
        Target::After => GROUP_AFTER_TOUCH,
        _ => return zone(scale, false, first, target),
    };
    Some(scale.zone(at.0, at.1, at.2, at.3))
}

/// What is under a point on a group's address screen.
pub fn group_target(scale: Scale, first: bool, x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::CosignerBefore,
        Target::CosignerAfter,
        Target::Address,
        Target::Chain,
        Target::Before,
        Target::Index,
        Target::After,
    ]
    .into_iter()
    .find(|&t| group_zone(scale, first, t).is_some_and(|z| z.contains(x, y)))
}

/// What is under a point.
pub fn target(scale: Scale, single: bool, first: bool, x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Address,
        Target::Chain,
        Target::Before,
        Target::Index,
        Target::After,
    ]
    .into_iter()
    .find(|&t| zone(scale, single, first, t).is_some_and(|z| z.contains(x, y)))
}

/// The screen: `address` at `index` on the change chain or not, or a raw
/// key's one address when `single`.
pub fn draw(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    address: &str,
    change: bool,
    index: u32,
    single: bool,
) {
    let name = if change { "CHANGE #" } else { "RECEIVE #" };
    let per = address_per_line(scale, kit, address);
    body(
        band,
        scale,
        kit,
        (name, "ADDRESS"),
        (address, per),
        (change, index, single),
        None,
    );
}

/// The seed's KCC-3 address at `index`, on the change chain or not. A raw
/// key has no KCC-3 address, so there is no single form.
pub fn draw_kcc3(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    address: &str,
    change: bool,
    index: u32,
) {
    let name = if change {
        "KCC-3 CHANGE #"
    } else {
        "KCC-3 RECEIVE #"
    };
    let per = address_per_line(scale, kit, address);
    body(
        band,
        scale,
        kit,
        (name, "ADDRESS"),
        (address, per),
        (change, index, false),
        None,
    );
}

/// A multisig group's address at `index`, on the change chain or not, with
/// the line `m`-of-`n` and `cosigner` under the title.
pub fn draw_group(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    address: &str,
    (change, index): (bool, u32),
    (m, n, cosigner): (usize, usize, usize),
) {
    let mut note = [0u8; 32];
    let mut k = Part::Number(m).write(&mut note, 0);
    k = Part::Text("-of-").write(&mut note, k);
    k = Part::Number(n).write(&mut note, k);
    k = Part::Text(", cosigner ").write(&mut note, k);
    k = Part::Number(cosigner).write(&mut note, k);
    let note = core::str::from_utf8(&note[..k]).unwrap_or("");
    let name = if change { "CHANGE #" } else { "RECEIVE #" };
    let per = address_per_line(scale, kit, address);
    body(
        band,
        scale,
        kit,
        (name, "ADDRESS"),
        (address, per),
        (change, index, false),
        Some(note),
    );
}

/// Private Key: the hex `key` of the address at `index`, or a raw key's one
/// key when `single`.
pub fn draw_key(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    key: &str,
    change: bool,
    index: u32,
    single: bool,
) {
    let name = if change {
        "CHANGE KEY #"
    } else {
        "RECEIVE KEY #"
    };
    body(
        band,
        scale,
        kit,
        (name, "PRIVATE KEY"),
        (key, KEY_PER_LINE),
        (change, index, single),
        None,
    );
}

/// An address read from a file (`MSnnnn.TXT`), the file's `name` dimmed
/// under it so it reads as what the file says, not one this unit worked
/// out. No foot row: a file holds no index.
pub fn draw_file(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    title: &str,
    address: &str,
    name: &str,
) {
    header(band, scale, kit, title);
    buttons(band, scale);
    let per = address_per_line(scale, kit, address);
    lines(band, scale, kit, address, per, FILE_LINES_TO);
    band.text_centered(
        kit.hint,
        scale.x(160),
        scale.y(FILE_NAME_BASE),
        TEXT_DIM,
        name,
    );
}

/// A kprv: `title` over `text`, in [`text_per_line`] characters a line, no
/// foot row.
pub fn draw_text(band: &mut Band<'_>, scale: Scale, kit: &Kit, title: &str, text: &str) {
    header(band, scale, kit, title);
    buttons(band, scale);
    lines(band, scale, kit, text, text_per_line(scale, kit, text), 205);
}

/// The characters a line of `text` takes: spread evenly over the fewest
/// lines, at most [`TEXT_LINES`], that keep every line within the panel. A
/// kprv mixes capitals and lower case, so a fixed count could run past it.
pub fn text_per_line(scale: Scale, kit: &Kit, text: &str) -> usize {
    let room = scale.len(TEXT_W);
    let len = text.len().max(1);
    (1..=TEXT_LINES)
        .map(|n| len.div_ceil(n))
        .find(|&per| {
            text.as_bytes()
                .chunks(per)
                .all(|c| kit.title.width(core::str::from_utf8(c).unwrap_or("")) <= room)
        })
        .unwrap_or_else(|| len.div_ceil(TEXT_LINES))
}

/// The characters a line of `address` takes: spread evenly over the fewest
/// lines, from three, that keep every line within the panel (a mainnet
/// address is 23, 23, 21). One rule, so every screen breaks it the same.
pub fn address_per_line(scale: Scale, kit: &Kit, address: &str) -> usize {
    let room = scale.len(TEXT_W);
    let len = address.len().max(1);
    (ADDRESS_LINES..=ADDRESS_LINES_MAX)
        .map(|n| len.div_ceil(n))
        .find(|&per| {
            address
                .as_bytes()
                .chunks(per)
                .all(|c| kit.title.width(core::str::from_utf8(c).unwrap_or("")) <= room)
        })
        .unwrap_or_else(|| len.div_ceil(ADDRESS_LINES_MAX))
}

/// The address screen over `text`, `per` characters a line: titled `name`
/// and the index, or `plain` and no controls when `single`; a group's
/// `note` under the title.
fn body(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    (name, plain): (&str, &str),
    (text, per): (&str, usize),
    (change, index, single): (bool, u32, bool),
    note: Option<&str>,
) {
    let mut title = [0u8; 24];
    let mut k = Part::Text(name).write(&mut title, 0);
    k = Part::Number(index as usize).write(&mut title, k);
    let title = if single {
        plain
    } else {
        core::str::from_utf8(&title[..k]).unwrap_or("")
    };
    header(band, scale, kit, title);
    buttons(band, scale);

    // A group's line, in orange, then the text.
    let bottom = if single { 205 } else { 175 };
    match note {
        Some(note) => {
            for (at, sign) in [(COSIGNER_BEFORE_AT, "-"), (COSIGNER_AFTER_AT, "+")] {
                let z = scale.zone(at.0, at.1, at.2, at.3);
                card(band, z, scale.len(6), CARD, ORANGE, 1);
                centred(band, kit.title, z, ORANGE, sign);
            }
            let (x, y, w, h) = COSIGNER_LINE_AT;
            centred(band, kit.body, scale.zone(x, y, w, h), ORANGE, note);
            lines_between(band, scale, kit, text, per, (GROUP_ADDRESS_AT.1, bottom));
        }
        None => lines(band, scale, kit, text, per, bottom),
    }
    if single {
        return;
    }

    // Receive or Change: teal when on change, so the chain is plain to see.
    let z = scale.zone(CHAIN_AT.0, CHAIN_AT.1, CHAIN_AT.2, CHAIN_AT.3);
    let (face, ink, said) = if change {
        (TEAL, BACKGROUND, "Change")
    } else {
        (CARD, TEAL, "Receive")
    };
    card(band, z, scale.len(6), face, TEAL, 1);
    label(band, kit, z, ink, said);

    let mut shown = [0u8; 12];
    let hash = Part::Text("#").write(&mut shown, 0);
    let len = Part::Number(index as usize).write(&mut shown, hash);
    let middle = core::str::from_utf8(&shown[..len]).unwrap_or("");
    foot(band, scale, kit, (index > 0, (middle, true), true));
}

/// The foot row: "<", the middle, ">", each dimmed when it would do
/// nothing.
fn foot(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    (before, (middle, live), after): (bool, (&str, bool), bool),
) {
    for (at, said, live) in [
        (BEFORE_AT, "<", before),
        (INDEX_AT, middle, live),
        (AFTER_AT, ">", after),
    ] {
        let z = scale.zone(at.0, at.1, at.2, at.3);
        let (face, edge, ink) = if live {
            (CARD, TEAL, TEAL)
        } else {
            (SHADOW_FACE, SHADOW_EDGE, SHADOW_TEXT)
        };
        card(band, z, scale.len(6), face, edge, 1);
        label(band, kit, z, ink, said);
    }
}

/// Characters a message line takes at most, in the address font (the body
/// font is too small to read). Twenty `W`s, 19 pixels each on the small
/// panel, do not fit: a line that fails [`message_line_fits`] is shorter.
const MESSAGE_PER_LINE: usize = 20;
/// A message's lines a page.
pub const MESSAGE_LINES: usize = 5;

/// The room a message line has on each panel: the design's width less 10
/// pixels each side, as for a refusal.
const SMALL_ROOM: i32 = Scale::for_panel(Size::new(320, 240)).len(300);
const LARGE_ROOM: i32 = Scale::for_panel(Size::new(480, 320)).len(300);

/// Whether `line` fits the message screen on both panels, so a message
/// breaks into the same lines and pages on every unit.
pub fn message_line_fits(line: &str) -> bool {
    SMALL.title.width(line) <= SMALL_ROOM && LARGE.title.width(line) <= LARGE_ROOM
}

/// A message's lines: split at its line breaks, each broken at the last
/// space within the most characters that fit. The text passed
/// [`crate::text::is_message`]: printable ASCII, so a character is a byte,
/// and a carriage return only before a line break, where it is dropped.
pub fn message_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n').flat_map(|line| {
        let mut rest = line.strip_suffix('\r').unwrap_or(line);
        let mut first = true;
        core::iter::from_fn(move || {
            if rest.is_empty() && !first {
                return None;
            }
            first = false;
            if rest.len() <= MESSAGE_PER_LINE && message_line_fits(rest) {
                return Some(core::mem::take(&mut rest));
            }
            // The most characters that fit. One always does: the widest
            // glyph is a fraction of the room.
            let most = (1..=MESSAGE_PER_LINE.min(rest.len()))
                .rev()
                .find(|&n| message_line_fits(&rest[..n]))
                .unwrap_or(1);
            let cut = rest[..most].rfind(' ').map_or(most, |i| i + 1);
            let (head, tail) = rest.split_at(cut);
            rest = tail;
            Some(head)
        })
    })
}

/// The pages a message takes, at least one.
pub fn message_pages(text: &str) -> usize {
    message_lines(text).count().div_ceil(MESSAGE_LINES).max(1)
}

/// Sign Message's MESSAGE: `page` of `pages`, SIGN between the arrows; or,
/// for a message read back already `signed`, SIGNED MESSAGE with CHECK. The
/// button is dimmed unless `live`: SIGN until the last page has been shown.
pub fn draw_message(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    text: &str,
    (page, pages): (usize, usize),
    (signed, live): (bool, bool),
) {
    let (title, action) = if signed {
        ("SIGNED MESSAGE", "CHECK")
    } else {
        ("MESSAGE", "SIGN")
    };
    header(band, scale, kit, title);
    buttons(band, scale);
    let mid = scale.x(160);
    for (i, line) in message_lines(text)
        .skip(page * MESSAGE_LINES)
        .take(MESSAGE_LINES)
        .enumerate()
    {
        let y = 44 + (i as i32 + 1) * LINE_H - 6;
        band.text_centered(kit.title, mid, scale.y(y), TEXT, line);
    }
    foot(
        band,
        scale,
        kit,
        (page > 0, (action, live), page + 1 < pages),
    );
}

/// Sign Message's SIGN WITH: the address that signs; a tap on it picks it.
pub fn draw_sign_with(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    address: &str,
    change: bool,
    index: u32,
) {
    let per = address_per_line(scale, kit, address);
    body(
        band,
        scale,
        kit,
        ("SIGN WITH #", "SIGN WITH"),
        (address, per),
        (change, index, false),
        None,
    );
}

/// Characters a line of a signature takes: its 128 in five lines.
const SIGNATURE_PER_LINE: usize = 26;

/// Sign Message's result: the signature, then the address that signed, a
/// page each; a tap on the text shows its code.
pub fn draw_signed(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    page: u8,
    signature: &str,
    address: &str,
) {
    let (title, text, per) = if page == 0 {
        ("SIGNATURE", signature, SIGNATURE_PER_LINE)
    } else {
        ("SIGNED BY", address, address_per_line(scale, kit, address))
    };
    header(band, scale, kit, title);
    buttons(band, scale);
    lines(band, scale, kit, text, per, 175);
    foot(band, scale, kit, (page > 0, ("SAVE SD", true), page == 0));
}

/// A question about an address (Import Raw Key's, Sign Message's): `d`, and
/// `address` centred between its first line and the answers.
pub fn draw_ask(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    d: &super::dialog::Dialog<'_>,
    address: &str,
) {
    super::dialog::draw(band, scale, kit, d, None);
    let per = address_per_line(scale, kit, address);
    lines_between(band, scale, kit, address, per, (72, 182));
}

/// `text`, `per` characters a line, centred in the room between the header
/// and design row `bottom`.
fn lines(band: &mut Band<'_>, scale: Scale, kit: &Kit, text: &str, per: usize, bottom: i32) {
    lines_between(band, scale, kit, text, per, (44, bottom));
}

/// `text`, `per` characters a line, centred between design rows `top` and
/// `bottom`.
fn lines_between(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    text: &str,
    per: usize,
    (top, bottom): (i32, i32),
) {
    let count = text.len().div_ceil(per) as i32;
    let top = top + (bottom - top - count * LINE_H) / 2;
    let mid = scale.x(160);
    for (i, line) in text.as_bytes().chunks(per).enumerate() {
        let y = top + (i as i32 + 1) * LINE_H - 6;
        let line = core::str::from_utf8(line).unwrap_or("");
        band.text_centered(kit.title, mid, scale.y(y), TEXT, line);
    }
}

/// `said` centred in `z`.
fn label(band: &mut Band<'_>, kit: &Kit, z: Zone, ink: u16, said: &str) {
    let (x, y, w, h) = bounds(z);
    let base = y + (h + i32::from(kit.title.ascent)) / 2;
    band.text_centered(kit.title, x + w / 2, base, ink, said);
}
