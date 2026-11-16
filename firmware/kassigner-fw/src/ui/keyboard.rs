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

//! The keyboard: one grid of keys for every kind of typing, each switching
//! off the keys it does not need ([`Mode`]). A key that cannot type is drawn
//! dimmed and does nothing. Numbers are in 320 by 240 design pixels.
//!
//! The zones meet, so no touch between two keys is lost: each key counts
//! half the gap past its face on either side and half the gap between rows;
//! the bottom row counts down to the screen's edge, Delete and OK out to its
//! sides.

use super::band::Band;
use super::camera::Part;
use super::chrome::{buttons, card, corner, header_at, place, Nav};
use super::color::{
    BACKGROUND, CARD, CARD_EDGE, DANGER, GREEN_BUTTON, ORANGE, RED_BUTTON, SHADOW_EDGE,
    SHADOW_FACE, SHADOW_TEXT, TEAL, TEXT, TEXT_DIM,
};
use super::gen::{self, Icon};
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;
use crate::words::SHOWN;

/// A key and what it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Types this character.
    Char(u8),
    /// Turns to the next page.
    Page,
    /// Removes the character before the cursor.
    Delete,
    /// Moves the cursor back.
    Left,
    /// Moves the cursor on.
    Right,
    Space,
    Ok,
}

/// What a touch on the keyboard's screen can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    Key(Key),
    /// A word's suggestion, by its place in the row.
    Chip(u8),
}

/// Which keys type, by what is being typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Any printable character, and Space.
    Text,
    /// A file name: letters and digits, and none once `full`.
    Name { full: bool },
    /// A BIP39 word on the compact grid, lower-case letters only. Left moves
    /// to the word before when `back`, Right to the next when `on`; OK takes
    /// the word when `take`; `chips` suggestions sit over the keys.
    Word {
        back: bool,
        on: bool,
        take: bool,
        chips: u8,
    },
    /// A private key in hex, on [`HEX_PAGE`]: the digits and A to F until
    /// it is `full`, and OK only then.
    Hex { full: bool },
}

impl Mode {
    /// Whether `key` does anything in this mode.
    pub const fn takes(self, key: Key) -> bool {
        match (self, key) {
            (Mode::Text, _) => true,
            (Mode::Name { full }, Key::Char(c)) => !full && c.is_ascii_alphanumeric(),
            (Mode::Name { .. }, Key::Space) => false,
            (Mode::Name { .. }, _) => true,
            (Mode::Word { .. }, Key::Char(c)) => c.is_ascii_lowercase(),
            (Mode::Word { .. }, Key::Page | Key::Space) => false,
            (Mode::Word { back, .. }, Key::Left) => back,
            (Mode::Word { on, .. }, Key::Right) => on,
            (Mode::Word { take, .. }, Key::Ok) => take,
            (Mode::Word { .. }, Key::Delete) => true,
            (Mode::Hex { full }, Key::Char(c)) => {
                !full && (c.is_ascii_digit() || matches!(c, b'A'..=b'F'))
            }
            (Mode::Hex { .. }, Key::Page | Key::Space) => false,
            (Mode::Hex { full }, Key::Ok) => full,
            (Mode::Hex { .. }, _) => true,
        }
    }

    /// The grid this mode is drawn on.
    const fn grid(self) -> Grid {
        match self {
            Mode::Word { .. } => COMPACT,
            _ => FULL,
        }
    }
}

/// What the line shows at its right: a password's strength, a prompt, or a
/// file name's count. A password is taken only from Fair up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// Under twelve characters.
    TooShort,
    /// Long enough, but too few kinds of character or too few different.
    Weak,
    Fair,
    Good,
    Strong,
    /// Type it a second time.
    Again,
    /// The second did not match the first; both start again.
    NoMatch,
    /// A file name's length and its limit.
    Count {
        used: u8,
        of: u8,
    },
}

impl Note {
    /// Its words, written into `out` when they hold a number, and their colour.
    pub fn shown(self, out: &mut [u8; 8]) -> (&str, u16) {
        match self {
            Note::TooShort => ("Too short", DANGER),
            Note::Weak => ("Weak", DANGER),
            Note::Fair => ("Fair", ORANGE),
            Note::Good => ("Good", TEAL),
            Note::Strong => ("Strong", TEAL),
            Note::Again => ("Again", TEXT_DIM),
            Note::NoMatch => ("No match", DANGER),
            Note::Count { used, of } => {
                let mut n = Part::Number(usize::from(used)).write(out, 0);
                n = Part::Text("/").write(out, n);
                n = Part::Number(usize::from(of)).write(out, n);
                let ink = if used >= of { ORANGE } else { TEXT_DIM };
                (core::str::from_utf8(&out[..n]).unwrap_or(""), ink)
            }
        }
    }
}

/// The keyboard's pages.
pub const PAGES: u8 = 4;

/// The page after `page`, round to the first.
pub const fn next_page(page: u8) -> u8 {
    (page + 1) % PAGES
}

/// Import Raw Key's own page, which the page key does not turn to.
pub const HEX_PAGE: u8 = PAGES;

/// The three rows of a page.
fn rows(page: u8) -> [&'static [u8]; 3] {
    if page == HEX_PAGE {
        return [b"123456789", b"0ABCDEF", b""];
    }
    match page % PAGES {
        0 => [b"abcdefghi", b"jklmnopqr", b"stuvwxyz"],
        1 => [b"ABCDEFGHI", b"JKLMNOPQR", b"STUVWXYZ"],
        2 => [b"123456789", b"0!@#$%^&*", b"()-_=+.,"],
        _ => [b"?/\\|~`<>;", b"\"'{}[]:-!", b"@#$%^&*+"],
    }
}

/// What the page key says on a page, shift's picture on the first.
fn page_label(page: u8) -> &'static str {
    match page % PAGES {
        1 => "#",
        2 => "@",
        _ => "ab",
    }
}

// The grid, in design pixels.
const WIDTH: i32 = 320;
const KEY_W: i32 = 33;
const GAP: i32 = 2;
const DELETE_W: i32 = 50;
const OK_W: i32 = 50;
const ARROW_W: i32 = 38;

/// A grid's rows: the three key rows' tops and height, then the bottom
/// row's.
#[derive(Clone, Copy)]
struct Grid {
    rows: [i32; 3],
    key_h: i32,
    action_y: i32,
    action_h: i32,
}

impl Grid {
    /// Where a row's zones reach past its keys: half the gap between rows,
    /// so the rows meet.
    const fn reach(self) -> i32 {
        (self.rows[1] - self.rows[0] - self.key_h) / 2
    }

    /// Where the bottom row starts counting: 4 above its keys.
    const fn action_top(self) -> i32 {
        self.action_y - 4
    }
}

/// The full grid, for everything typed but a word.
const FULL: Grid = Grid {
    rows: [80, 118, 156],
    key_h: 34,
    action_y: 194,
    action_h: 38,
};

/// The compact grid, for a word: lower and thinner, under the suggestions.
const COMPACT: Grid = Grid {
    rows: [96, 130, 164],
    key_h: 28,
    action_y: 196,
    action_h: 32,
};

/// The suggestions' row: up to three, each this wide, from x 4.
const CHIP_Y: i32 = 72;
const CHIP_H: i32 = 24;
const CHIP_W: i32 = 102;
const CHIP_PITCH: i32 = 106;

/// The left edge of key `i` in a row of `n` that starts with `lead` keys'
/// room (the page key's, on the third row).
fn key_x(n: usize, lead: usize, i: usize) -> i32 {
    let total = (n + lead) as i32 * (KEY_W + GAP) - GAP;
    (WIDTH - total) / 2 + (lead + i) as i32 * (KEY_W + GAP)
}

/// A bottom-row key's left edge and width.
fn action(key: Key) -> Option<(i32, i32)> {
    let left = 2 + DELETE_W + GAP;
    let space = WIDTH - 4 - DELETE_W - OK_W - 2 * ARROW_W - 4 * GAP;
    let right = left + ARROW_W + GAP + space + GAP;
    let ok = right + ARROW_W + GAP;
    Some(match key {
        Key::Delete => (2, DELETE_W),
        Key::Left => (left, ARROW_W),
        Key::Space => (left + ARROW_W + GAP, space),
        Key::Right => (right, ARROW_W),
        Key::Ok => (ok, OK_W),
        _ => return None,
    })
}

/// Where `key` is drawn on `page` of `grid`, if it is on it.
fn face(page: u8, key: Key, grid: Grid) -> Option<(i32, i32, i32, i32)> {
    if let Some((x, w)) = action(key) {
        return Some((x, grid.action_y, w, grid.action_h));
    }
    let rows = rows(page);
    let h = grid.key_h;
    match key {
        // The third row's first place: the row is its keys and this one.
        Key::Page => Some((key_x(rows[2].len() + 1, 0, 0), grid.rows[2], KEY_W, h)),
        Key::Char(c) => rows.iter().enumerate().find_map(|(r, row)| {
            let i = row.iter().position(|&k| k == c)?;
            let lead = usize::from(r == 2);
            Some((key_x(row.len(), lead, i), grid.rows[r], KEY_W, h))
        }),
        _ => None,
    }
}

/// Where a suggestion is drawn and counts, in design pixels.
const fn chip(i: u8) -> (i32, i32, i32, i32) {
    (4 + i as i32 * CHIP_PITCH, CHIP_Y, CHIP_W, CHIP_H)
}

/// Where a target counts on `page` of the full grid, if it is on it.
pub fn zone(scale: Scale, page: u8, target: Target) -> Option<Zone> {
    zone_in(scale, page, Mode::Text, target)
}

/// Where a target counts on `page` in `mode`'s grid, if it is on it.
pub fn zone_in(scale: Scale, page: u8, mode: Mode, target: Target) -> Option<Zone> {
    let grid = mode.grid();
    let key = match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => return Some(corner(scale, nav)),
        Target::Nav(_) => return None,
        Target::Chip(i) => {
            let Mode::Word { chips, .. } = mode else {
                return None;
            };
            if i >= chips {
                return None;
            }
            let (x, y, w, h) = chip(i);
            return Some(scale.zone(x, y, w, h));
        }
        Target::Key(key) => key,
    };
    let (x, y, w, h) = face(page, key, grid)?;
    let (x, w) = match key {
        Key::Delete => (0, x + w + GAP / 2),
        Key::Ok => (x - GAP / 2, WIDTH - (x - GAP / 2)),
        _ => (x - GAP / 2, w + GAP),
    };
    let (reach, action_top) = (grid.reach(), grid.action_top());
    let (y, h) = if y == grid.action_y {
        (action_top, 240 - action_top)
    } else {
        // Half the gap above and below, but the third row stops where the
        // bottom row's touch area starts, and the compact grid's first row
        // where the suggestions end.
        let top = if y == grid.rows[0] && matches!(mode, Mode::Word { .. }) {
            y
        } else {
            y - reach
        };
        (top, (y + h + reach).min(action_top) - top)
    };
    Some(scale.zone(x, y, w, h))
}

/// Every key on `page`.
pub fn keys(page: u8) -> impl Iterator<Item = Key> {
    rows(page)
        .into_iter()
        .flat_map(|row| row.iter().map(|&c| Key::Char(c)))
        .chain([
            Key::Page,
            Key::Delete,
            Key::Left,
            Key::Space,
            Key::Right,
            Key::Ok,
        ])
}

/// What is under a point on `page`, if anything that acts in `mode`: a
/// dimmed key is not there to touch.
pub fn target(scale: Scale, page: u8, mode: Mode, x: u16, y: u16) -> Option<Target> {
    [Target::Nav(Nav::Back), Target::Nav(Nav::Home)]
        .into_iter()
        .chain((0..SHOWN as u8).map(Target::Chip))
        .chain(keys(page).map(Target::Key))
        .find(|&t| zone_in(scale, page, mode, t).is_some_and(|z| z.contains(x, y)))
        .filter(|&t| match t {
            Target::Key(key) => mode.takes(key),
            Target::Nav(_) | Target::Chip(_) => true,
        })
}

/// The line being typed and what goes with it.
#[derive(Clone, Copy, Debug)]
pub struct Line<'t> {
    pub text: &'t str,
    pub cursor: usize,
    pub note: Option<Note>,
    pub mode: Mode,
    pub word: Option<WordLine<'t>>,
}

/// What a word's line shows besides its letters: the word they complete,
/// and the suggestions when several match, or else a status.
#[derive(Clone, Copy, Debug)]
pub struct WordLine<'t> {
    pub completes: Option<&'t str>,
    pub chips: [&'t str; SHOWN],
    pub shown: usize,
    pub status: Option<(&'t str, u16)>,
}

/// The keyboard's screen: `title`, the line, and `page`'s keys.
pub fn draw(band: &mut Band<'_>, scale: Scale, kit: &Kit, title: &str, page: u8, typed: Line<'_>) {
    let Line {
        text,
        cursor,
        note,
        mode,
        word,
    } = typed;
    header_at(band, scale, kit, title, (TEXT, TEAL), (26, 36));
    buttons(band, scale);
    // The note at the line's right end, the line stopping short of it.
    let mut right = scale.x(310);
    let mut number = [0u8; 8];
    if let Some(note) = note {
        let (said, ink) = note.shown(&mut number);
        let width = kit.hint.width(said);
        band.text(kit.hint, right - width, scale.y(64), ink, said);
        right -= width + scale.len(6);
    }
    let end = line(band, scale, kit, text, cursor, right);
    if let Some(word) = word {
        word_extras(band, scale, kit, end, word);
    }
    for key in keys(page) {
        draw_key(band, scale, kit, page, key, mode);
    }
}

/// A word's completion after its letters, from `end`, and its suggestions
/// or status in the row over the keys.
fn word_extras(band: &mut Band<'_>, scale: Scale, kit: &Kit, end: i32, word: WordLine<'_>) {
    if let Some(full) = word.completes {
        let mut said = [0u8; 12];
        let mut n = Part::Text("= ").write(&mut said, 0);
        n = Part::Text(full).write(&mut said, n);
        let shown = core::str::from_utf8(&said[..n]).unwrap_or("");
        band.text(kit.key, end + scale.len(6), scale.y(64), TEAL, shown);
    }
    if word.shown > 1 {
        for (i, &w) in word.chips.iter().take(word.shown).enumerate() {
            let (x, y, cw, ch) = chip(i as u8);
            let z = scale.zone(x, y, cw, ch);
            card(band, z, scale.len(4), CARD, TEAL, 1);
            let (px, py, pw, ph) = bounds(z);
            let base = py + (ph + i32::from(kit.title.ascent)) / 2;
            band.text_centered(kit.title, px + pw / 2, base, TEXT, w);
        }
    } else if let Some((said, ink)) = word.status {
        band.text_centered(kit.body, scale.x(160), scale.y(CHIP_Y + 18), ink, said);
    }
}

/// The line being typed, as much as fits with the cursor in view, and a `<`
/// when text is hidden before it. Returns where the text shown ends.
fn line(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    text: &str,
    cursor: usize,
    right: i32,
) -> i32 {
    let font = kit.key;
    let (left, base) = (scale.x(10), scale.y(64));
    let room = right - left;
    let cursor = cursor.min(text.len());
    // The first character shown: the earliest from which the text up to the
    // cursor fits.
    let start = (0..=cursor)
        .find(|&s| font.width(&text[s..cursor]) <= room)
        .unwrap_or(cursor);
    let end = (cursor..=text.len())
        .rev()
        .find(|&e| font.width(&text[start..e]) <= room)
        .unwrap_or(cursor);
    band.text(font, left, base, TEXT, &text[start..end]);
    if start > 0 {
        band.text(kit.hint, scale.x(2), scale.y(56), TEAL, "<");
    }
    let x = left + font.width(&text[start..cursor]);
    let up = i32::from(font.ascent);
    band.fill(x, base - up, scale.len(2).max(2), up + scale.len(2), TEAL);
    left + font.width(&text[start..end])
}

/// One key's face in `mode`'s grid, dimmed when it does not act there.
fn draw_key(band: &mut Band<'_>, scale: Scale, kit: &Kit, page: u8, key: Key, mode: Mode) {
    let live = mode.takes(key);
    let Some((x, y, w, h)) = face(page, key, mode.grid()) else {
        return;
    };
    let z = scale.zone(x, y, w, h);
    let (px, py, pw, ph) = bounds(z);
    let (small, round) = (scale.len(4), scale.len(5));
    let label = |band: &mut Band<'_>, font: &super::font::Font, ink: u16, text: &str| {
        let base = py + (ph + i32::from(font.ascent)) / 2;
        band.text_centered(font, px + pw / 2, base, ink, text);
    };
    match key {
        Key::Char(c) => {
            let (face, edge, ink) = if live {
                (CARD, CARD_EDGE, TEXT)
            } else {
                (SHADOW_FACE, SHADOW_EDGE, SHADOW_TEXT)
            };
            card(band, z, small, face, edge, 1);
            let glyph = [c];
            label(
                band,
                kit.key,
                ink,
                core::str::from_utf8(&glyph).unwrap_or(""),
            );
        }
        // Dimmed: the shadow, empty.
        Key::Page if !live => card(band, z, round, SHADOW_FACE, SHADOW_EDGE, 1),
        Key::Page => {
            card(band, z, round, BACKGROUND, TEAL, scale.len(2).max(2));
            if page.is_multiple_of(PAGES) {
                place(band, scale, &gen::KEY_SHIFT, z);
            } else {
                let base = py + ph - scale.len(8);
                band.text_centered(kit.header, px + pw / 2, base, TEAL, page_label(page));
            }
        }
        Key::Delete => {
            card(band, z, round, RED_BUTTON, RED_BUTTON, 1);
            place(band, scale, &gen::KEY_DELETE, z);
        }
        Key::Left | Key::Right => {
            let (face, edge, ink) = if live {
                (CARD, CARD_EDGE, TEAL)
            } else {
                (SHADOW_FACE, SHADOW_EDGE, SHADOW_TEXT)
            };
            card(band, z, round, face, edge, 1);
            let icon = if key == Key::Left {
                Icon::ArrowLeft
            } else {
                Icon::ArrowRight
            };
            let side = i32::from(kit.icons.side);
            band.icon(
                px + (pw - side) / 2,
                py + (ph - side) / 2,
                kit.icons,
                icon,
                ink,
            );
        }
        Key::Space if live => {
            card(band, z, round, CARD, CARD_EDGE, 1);
            label(band, kit.title, TEXT_DIM, "SPACE");
        }
        Key::Space => {
            card(band, z, round, SHADOW_FACE, SHADOW_EDGE, 1);
            label(band, kit.title, SHADOW_TEXT, "SPACE");
        }
        Key::Ok if live => {
            card(band, z, round, GREEN_BUTTON, GREEN_BUTTON, 1);
            label(band, kit.title, TEXT, "OK");
        }
        Key::Ok => {
            card(band, z, round, SHADOW_FACE, SHADOW_EDGE, 1);
            label(band, kit.title, SHADOW_TEXT, "OK");
        }
    }
}
