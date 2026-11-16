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

//! SAVINGS CARD: a Time-Locked Savings card read from its backup line,
//! scanned on Home or opened from a `CVnnnn.TXT` on the SD card.
//!
//! Its pages, turned with the side arrows as the review's are so none is
//! packed too small to read: the card (the day it opens, day first as every
//! date on the units, and its address), the owner's key, and the recovery
//! wallet's key if it has one. Over a key's address, whether the seed in use
//! holds it ([`Seen`]).
//!
//! Under every page, Save to SD and Show QR where a dialog's answers are,
//! Save on the left as on every export dialog; Show QR alone for a card
//! read from a file. A tap on the first page's address, where UTXOs are sent
//! to be locked, shows its code.

use super::band::Band;
use super::camera::Part;
use super::chrome::{
    buttons, card, corner, dots, header, lit_edge, Nav, RIGHT_COLUMN, SIDE_COLUMN,
};
use super::color::{ACCENT, BACKGROUND, CARD, CARD_EDGE, ORANGE, TEAL, TEXT_DIM};
use super::dialog;
use super::review::{self, LOCK_TIME_MAX};
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;
use kassigner_kaspa::address::MAX_ADDRESS_LEN;

/// Where a key of the card is among the seed in use's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// No seed in use: nothing said.
    NoSeed,
    /// Not among the seed's first [`crate::limits::SEARCH_DEPTH`] receive
    /// keys, or not the one key of a seed with no chains.
    NotFound,
    /// Its receive key at this index.
    At(u32),
    /// Not among the receive keys searched, those before this index: a
    /// search past them is a tap away.
    Missed(u32),
    /// Being searched for, at this receive index.
    Searching(u32),
}

/// What SAVINGS CARD shows.
#[derive(Clone, Copy, Debug)]
pub struct Shown<'a> {
    /// The card's own address, `kaspa:p…`.
    pub address: &'a str,
    /// The moment it opens, in milliseconds since the Unix epoch: a whole
    /// minute.
    pub unlock: u64,
    /// The owner's key, as its `kaspa:q` address.
    pub owner: &'a str,
    /// The recovery wallet's key the same way, if the card has one.
    pub recovery: Option<&'a str>,
    /// Where the owner's key is in the seed in use.
    pub owner_seen: Seen,
    /// Where the recovery wallet's is.
    pub recovery_seen: Seen,
    /// Read from a file: Show QR alone, no Save to SD.
    pub file: bool,
}

/// Room for the card's, the owner's and the recovery wallet's addresses as
/// text, in that order.
pub type Texts = [[u8; MAX_ADDRESS_LEN]; 3];

/// [`Texts`], empty, for the flow to write into.
pub const NO_TEXTS: Texts = [[0; MAX_ADDRESS_LEN]; 3];

/// How many pages: three for a card with a recovery wallet, else two.
pub const fn pages(recovery: bool) -> usize {
    if recovery {
        3
    } else {
        2
    }
}

/// Its pages' titles, in order.
pub const TITLES: [&str; 3] = ["SAVINGS CARD", "OWNER", "RECOVERY"];

/// What a touch on SAVINGS CARD can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Back and Home.
    Nav(Nav),
    /// The left arrow: the page before.
    Previous,
    /// The right arrow: the page after.
    Next,
    /// The card's address, on the first page: its code.
    Address,
    /// Save to SD, for a card scanned.
    Save,
    /// Show QR: the backup line's code.
    Show,
    /// A key's `SEARCH PAST #n`: the next [`crate::flow::BATCH`] receive
    /// keys searched.
    Search,
}

/// The card every page is drawn in, in design pixels: between the arrows,
/// from under the header to over the answers.
const CARD_AT: (i32, i32, i32, i32) = (30, 52, 260, 126);

/// Show QR alone, for a card read from a file: in the middle of the
/// answers' row.
const ONLY_AT: (i32, i32, i32, i32) = (100, 185, 120, 40);

/// The arrows' middle, in design rows: the card's.
const SIDES_MID: i32 = 114;

/// The first page's day line, its baseline; the address's lines under it.
const DAY_BASE: i32 = 84;
const ADDRESS_TOP: i32 = 118;

/// A key's address with a pill over it, and with none.
const KEY_TOP: i32 = 108;
const KEY_TOP_BARE: i32 = 94;

/// The pill's top and height, in design rows.
const PILL_TOP: i32 = 60;
const PILL_HEIGHT: i32 = 20;

/// The search's button where the pill is, in design pixels: fixed, wide
/// enough on either panel for the longest label, SEARCHING at index 999, so
/// nothing moves as its number goes up.
const SEARCH_AT: (i32, i32, i32, i32) = (75, 57, 170, 26);

/// Its touch, wider: across the card between the arrows' columns, from the
/// card's top to the address's.
const SEARCH_TOUCH: (i32, i32, i32, i32) = (SIDE_COLUMN, 52, RIGHT_COLUMN - SIDE_COLUMN, 36);

/// Lines of an address on a page, apart, in design rows.
const LINE_STEP: i32 = 24;

/// Where `target` counts on `page`, for a card read from a file or not.
pub const fn zone(scale: Scale, (page, file): (usize, bool), target: Target) -> Option<Zone> {
    let (_, cy, _, ch) = CARD_AT;
    let (ox, oy, ow, oh) = ONLY_AT;
    match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        Target::Nav(_) => None,
        Target::Previous => review::zone(scale, false, review::Target::Previous),
        Target::Next => review::zone(scale, false, review::Target::Next),
        Target::Address if page == 0 => {
            Some(scale.zone(SIDE_COLUMN, cy, RIGHT_COLUMN - SIDE_COLUMN, ch))
        }
        Target::Address => None,
        Target::Save if file => None,
        Target::Save => dialog::zone(scale, dialog::Target::Cancel),
        Target::Show if file => Some(scale.zone(ox, oy, ow, oh)),
        Target::Show => dialog::zone(scale, dialog::Target::Accept),
        Target::Search if page > 0 => {
            let (x, y, w, h) = SEARCH_TOUCH;
            Some(scale.zone(x, y, w, h))
        }
        Target::Search => None,
    }
}

/// The search's button, as drawn: what is redrawn as its number goes up.
pub const fn search_area(scale: Scale) -> Zone {
    let (x, y, w, h) = SEARCH_AT;
    scale.zone(x, y, w, h)
}

/// What is under a point on `page`.
pub fn target(scale: Scale, (page, file): (usize, bool), x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Previous,
        Target::Next,
        Target::Address,
        Target::Save,
        Target::Show,
        Target::Search,
    ]
    .into_iter()
    .find(|&t| zone(scale, (page, file), t).is_some_and(|z| z.contains(x, y)))
}

/// A pill: `label` black on teal, or dim in an outline.
fn pill(band: &mut Band<'_>, scale: Scale, kit: &Kit, label: &str, filled: bool) {
    let w = kit.hint.width(label) + scale.len(14);
    let (x, y, h) = (
        scale.x(160) - w / 2,
        scale.y(PILL_TOP),
        scale.len(PILL_HEIGHT),
    );
    let (face, edge, ink) = if filled {
        (TEAL, TEAL, BACKGROUND)
    } else {
        (CARD, CARD_EDGE, TEXT_DIM)
    };
    let z = Zone::new(x as u16, y as u16, w as u16, h as u16);
    card(band, z, h / 2, face, edge, 1);
    band.text_centered(kit.hint, x + w / 2, y + scale.len(15), ink, label);
}

/// The first page: the lock, the day and its time, then the address.
fn first(band: &mut Band<'_>, scale: Scale, kit: &Kit, s: &Shown<'_>) {
    use super::gen::Icon;
    let mut buf = [0u8; LOCK_TIME_MAX];
    let when = review::lock_time(s.unlock, &mut buf);
    // `DD/MM/YYYY HH:MM:SS UTC`: the day, and the time to the minute, as a
    // card's seconds are zero.
    let mut parts = when.split(' ');
    let day = parts.next().unwrap_or(when);
    let clock = parts.next().and_then(|t| t.get(..5)).unwrap_or("");
    let mut text = [0u8; 9];
    let n = Part::Text(clock).write(&mut text, 0);
    let n = Part::Text(" UTC").write(&mut text, n);
    let hour = core::str::from_utf8(&text[..n]).unwrap_or("");
    let icon = i32::from(kit.icons.side);
    let gap = scale.len(6);
    let w = icon + gap + kit.title.width(day) + gap + kit.body.width(hour);
    let x = scale.x(160) - w / 2;
    let base = scale.y(DAY_BASE);
    band.icon(x, base - icon + scale.len(4), kit.icons, Icon::Lock, ORANGE);
    let x = x + icon + gap;
    let x = x + band.text(kit.title, x, base, ORANGE, day) + gap;
    band.text(kit.body, x, base, TEXT_DIM, hour);
    review::address_lines(band, scale, kit, s.address, (ADDRESS_TOP, LINE_STEP));
}

/// The search's button: `label` in `ink`, outlined in it, the edge lit
/// when `lit`.
fn search(band: &mut Band<'_>, scale: Scale, kit: &Kit, label: &str, ink: u16, lit: bool) {
    let z = search_area(scale);
    let (edge, width) = if lit {
        (ACCENT, lit_edge(scale))
    } else {
        (ink, 1)
    };
    card(band, z, scale.len(6), CARD, edge, width);
    let (x, y, w, _) = bounds(z);
    band.text_centered(kit.body, x + w / 2, y + scale.len(19), ink, label);
}

/// `head`, `n` and `tail` written into `tag`, as one line.
fn numbered<'t>(tag: &'t mut [u8; 24], (head, n, tail): (&str, u32, &str)) -> &'t str {
    let mut k = Part::Text(head).write(tag, 0);
    k = Part::Number(n as usize).write(tag, k);
    k = Part::Text(tail).write(tag, k);
    core::str::from_utf8(&tag[..k]).unwrap_or("")
}

/// A key's page: where the seed in use holds it, or the search for it,
/// then its address. `lit` when a finger is on the button while it can be
/// tapped.
fn key(band: &mut Band<'_>, scale: Scale, kit: &Kit, (address, seen): (&str, Seen), lit: bool) {
    let mut tag = [0u8; 24];
    match seen {
        Seen::At(i) => pill(
            band,
            scale,
            kit,
            numbered(&mut tag, ("THIS SEED #", i, "")),
            true,
        ),
        Seen::NotFound => pill(band, scale, kit, "NOT IN THIS SEED", false),
        Seen::Missed(to) => {
            let label = numbered(&mut tag, ("SEARCH PAST #", to.saturating_sub(1), ""));
            search(band, scale, kit, label, TEAL, lit);
        }
        Seen::Searching(at) => {
            let label = numbered(&mut tag, ("SEARCHING #", at, "..."));
            search(band, scale, kit, label, ORANGE, false);
        }
        Seen::NoSeed => {
            review::address_lines(band, scale, kit, address, (KEY_TOP_BARE, LINE_STEP));
            return;
        }
    }
    review::address_lines(band, scale, kit, address, (KEY_TOP, LINE_STEP));
}

/// SAVINGS CARD at `page`, `lit` the answer under a finger.
pub fn draw(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    s: &Shown<'_>,
    page: usize,
    lit: Option<Target>,
) {
    let count = pages(s.recovery.is_some());
    let page = page.min(count - 1);
    let lit_search = lit == Some(Target::Search);
    header(band, scale, kit, TITLES[page]);
    buttons(band, scale);
    let (x, y, w, h) = CARD_AT;
    card(
        band,
        scale.zone(x, y, w, h),
        scale.len(10),
        CARD,
        CARD_EDGE,
        1,
    );
    match (page, s.recovery) {
        (0, _) => first(band, scale, kit, s),
        (1, _) => key(band, scale, kit, (s.owner, s.owner_seen), lit_search),
        (_, Some(recovery)) => key(band, scale, kit, (recovery, s.recovery_seen), lit_search),
        (_, None) => {}
    }
    review::sides(band, scale, (page > 0, page + 1 < count), SIDES_MID);
    if s.file {
        let (x, y, w, h) = ONLY_AT;
        let z = scale.zone(x, y, w, h);
        let edge = if lit == Some(Target::Show) {
            ACCENT
        } else {
            TEAL
        };
        card(band, z, scale.len(8), TEAL, edge, lit_edge(scale));
        let (x, y, w, _) = bounds(z);
        band.text_centered(
            kit.title,
            x + w / 2,
            y + scale.len(27),
            BACKGROUND,
            "Show QR",
        );
    } else {
        let lit = match lit {
            Some(Target::Save) => Some(dialog::Target::Cancel),
            Some(Target::Show) => Some(dialog::Target::Accept),
            _ => None,
        };
        dialog::choice(band, scale, kit, ("Save to SD", "Show QR"), lit);
    }
    dots(band, scale, page, count);
}
