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

//! Tools' Import / Export (two big teal buttons) and the backup's own
//! screens: the amber warning with the password rule, and the backup list.

use super::band::Band;
use super::chrome::{
    arrows, buttons, card, corner, dots, header, header_at, place, Nav, ROW_PITCH,
};
use super::color::{AMBER, CARD, RED_BUTTON, TEAL, TEAL_FACE, TEXT, TEXT_DIM, WARN};
use super::gen::Icon;
use super::menu::LIST;
use super::scale::{bounds, Kit, Scale};
use super::seeds::TRASH;
use crate::card::{long_name, shown_name};
use crate::touch::Zone;

/// What a touch on these screens can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    Import,
    Export,
    /// The warning's I understand.
    Understand,
}

/// Import / Export's buttons as drawn, in design pixels: the two-card
/// screen's.
const IMPORT_AT: (i32, i32, i32, i32) = super::kpub::card_at(false);
const EXPORT_AT: (i32, i32, i32, i32) = super::kpub::card_at(true);
/// The warning's button.
const UNDERSTAND_AT: (i32, i32, i32, i32) = (85, 205, 150, 32);

/// Where a target counts.
pub const fn zone(scale: Scale, target: Target) -> Option<Zone> {
    let at = match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => return Some(corner(scale, nav)),
        Target::Nav(_) => return None,
        Target::Import => IMPORT_AT,
        Target::Export => EXPORT_AT,
        // To the panel's foot.
        Target::Understand => (UNDERSTAND_AT.0, UNDERSTAND_AT.1, UNDERSTAND_AT.2, 35),
    };
    Some(scale.zone(at.0, at.1, at.2, at.3))
}

/// What is under a point on Import / Export.
pub fn target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    find(scale, &[Target::Import, Target::Export], x, y)
}

/// What is under a point on the warning.
pub fn warning_target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    find(scale, &[Target::Understand], x, y)
}

fn find(scale: Scale, own: &[Target], x: u16, y: u16) -> Option<Target> {
    [Target::Nav(Nav::Back), Target::Nav(Nav::Home)]
        .iter()
        .chain(own)
        .copied()
        .find(|&t| zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// Tools' Import / Export.
pub fn import_export(band: &mut Band<'_>, scale: Scale, kit: &Kit) {
    super::kpub::pair(
        band,
        scale,
        kit,
        "IMPORT / EXPORT",
        ("Import", "Export"),
        ("", ""),
        (true, true),
    );
}

/// Backup to SD's warning.
pub fn warning(band: &mut Band<'_>, scale: Scale, kit: &Kit) {
    header_at(band, scale, kit, "! WARNING !", (AMBER, AMBER), (25, 40));
    buttons(band, scale);
    let mid = scale.x(160);
    for (y, ink, line) in [
        (60, WARN, "Choose a STRONG password:"),
        (85, TEXT, "12+ characters minimum"),
        (105, TEXT, "3 of: a-z, A-Z, 0-9, symbols"),
        (125, WARN, "NOT your BIP39 passphrase"),
        (155, TEXT, "If you lose this password,"),
        (175, WARN, "the backup is UNRECOVERABLE."),
    ] {
        band.text_centered(kit.body, mid, scale.y(y), ink, line);
    }
    let z = scale.zone(
        UNDERSTAND_AT.0,
        UNDERSTAND_AT.1,
        UNDERSTAND_AT.2,
        UNDERSTAND_AT.3,
    );
    card(band, z, scale.len(8), TEAL_FACE, TEAL, scale.len(2).max(2));
    band.text_centered(kit.body, mid, scale.y(226), TEAL, "I understand");
}

/// What a touch on the backup list can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    Nav(Nav),
    /// The backup at this place in the list.
    Row(usize),
    /// Its delete button, at the row's right end.
    Trash(usize),
}

/// The delete button as drawn, in design pixels, on a row at `top`.
const fn trash_face(top: i32) -> (i32, i32, i32, i32) {
    (236, top + 3, 36, 36)
}

/// Where the delete button counts on a row at `top`: from 8 pixels left of
/// it to the row's end, full height, so a tap beside it never restores. It
/// wins over its row; the arrows' column stays theirs.
const fn trash_touch(top: i32) -> (i32, i32, i32, i32) {
    let (x, _, _, _) = trash_face(top);
    let left = x - 8;
    // As the row's touch zone: 2 past its drawn edges (to 44 + 232 + 2),
    // a pitch high.
    (left, top - 2, 278 - left, ROW_PITCH)
}

/// Where a target counts on the list's `page`, of `count` backups: rows
/// and arrows as in the menus, four to a page.
pub fn pick_zone(scale: Scale, count: usize, page: usize, pick: Pick) -> Option<Zone> {
    pick_zone_in(scale, count, page, true, pick)
}

/// [`pick_zone`], with delete buttons only when `trash`: a photo is the
/// user's, not a backup to delete.
pub fn pick_zone_in(
    scale: Scale,
    count: usize,
    page: usize,
    trash: bool,
    pick: Pick,
) -> Option<Zone> {
    let rows = LIST.rows;
    match pick {
        Pick::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        Pick::Nav(Nav::PageUp) if page > 0 => Some(LIST.nav(scale, Nav::PageUp)),
        Pick::Nav(Nav::PageDown) if (page + 1) * rows < count => {
            Some(LIST.nav(scale, Nav::PageDown))
        }
        Pick::Nav(_) => None,
        Pick::Row(i) if i < count && i / rows == page => Some(LIST.touch(scale, i % rows)),
        Pick::Trash(i) if trash && i < count && i / rows == page => {
            let (x, y, w, h) = trash_touch(LIST.row_top(i % rows));
            Some(scale.zone(x, y, w, h))
        }
        Pick::Row(_) | Pick::Trash(_) => None,
    }
}

/// What is under a point on the list; a delete button wins over its row.
pub fn pick(scale: Scale, count: usize, page: usize, x: u16, y: u16) -> Option<Pick> {
    pick_in(scale, count, page, true, x, y)
}

/// [`pick`], with the delete buttons only when `trash`.
pub fn pick_in(
    scale: Scale,
    count: usize,
    page: usize,
    trash: bool,
    x: u16,
    y: u16,
) -> Option<Pick> {
    [Nav::Back, Nav::Home, Nav::PageUp, Nav::PageDown]
        .map(Pick::Nav)
        .into_iter()
        .chain((0..count).map(Pick::Trash))
        .chain((0..count).map(Pick::Row))
        .find(|&p| pick_zone_in(scale, count, page, trash, p).is_some_and(|z| z.contains(x, y)))
}

/// Bytes a long name takes in a row: the longest the card holds, and the
/// cut's three dots.
const LONG_SHOWN: usize = kassigner_fat32::fat32::MAX_LONG_NAME + 3;

/// Pages past which the list says `3 / 16` instead of a dot each: a full
/// card's sixteen dots would fill the foot, where "+N more files" goes.
const DOTS_MOST: usize = 8;

/// SELECT BACKUP, or SELECT FILE for Sign Message's text files (`title`):
/// the card's backups at `page`, by name, and at the foot how many more
/// files (`extra`) the list could not hold.
pub fn list(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    title: &str,
    (page, names): (usize, &[[u8; 11]]),
    extra: u16,
) {
    list_with(
        band,
        scale,
        kit,
        title,
        (page, names, &[]),
        extra,
        (Icon::FloppyDisk, true),
    );
}

/// [`list`], with each row's `icon`, and delete buttons only when `trash`
/// (not on SELECT PHOTO). A name in `long` ([`crate::card::long_name`])
/// shows as much as fits, cut in the middle; the rest show 8.3 names.
pub fn list_with(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    title: &str,
    (page, names, long): (usize, &[[u8; 11]], &[u8]),
    extra: u16,
    (icon, trash): (Icon, bool),
) {
    header(band, scale, kit, title);
    buttons(band, scale);
    let rows = LIST.rows;
    for (i, name) in names.iter().enumerate().skip(page * rows).take(rows) {
        let z = LIST.row(scale, i % rows);
        card(band, z, scale.len(6), CARD, TEAL, 1);
        let (x, y, _, h) = bounds(z);
        let side = i32::from(kit.icons.side);
        band.icon(x + scale.len(8), y + (h - side) / 2, kit.icons, icon, TEAL);
        let left = x + scale.len(42);
        // To the delete button, or the row's end.
        let right = if trash {
            scale.x(trash_face(LIST.row_top(i % rows)).0) - scale.len(4)
        } else {
            x + bounds(z).2 - scale.len(8)
        };
        let mut shown = [0u8; 12];
        let mut fitted = [0u8; LONG_SHOWN];
        let text = match long_name(long, i) {
            Some(full) => kit.title.fit(full, right - left, &mut fitted),
            None => {
                let n = shown_name(name, &mut shown);
                core::str::from_utf8(&shown[..n]).unwrap_or("")
            }
        };
        band.text(kit.title, left, y + scale.len(28), TEXT, text);
        if trash {
            let (tx, ty, tw, th) = trash_face(LIST.row_top(i % rows));
            let d = scale.zone(tx, ty, tw, th);
            card(band, d, scale.len(4), RED_BUTTON, RED_BUTTON, 1);
            place(band, scale, &TRASH, d);
        }
    }
    // Arrows always, dimmed with no page to go to; dots past one page, the
    // page's number past `DOTS_MOST`.
    let pages = names.len().div_ceil(rows).max(1);
    arrows(band, scale, &LIST, page > 0, page + 1 < pages, None);
    if pages > DOTS_MOST {
        let mut said = [0u8; 16];
        let line = page_of(page, pages, &mut said);
        band.text_centered(kit.hint, scale.x(160), scale.y(236), TEXT_DIM, line);
    } else if pages > 1 {
        dots(band, scale, page, pages);
    }
    if extra > 0 {
        let mut said = [0u8; 24];
        let line = more_files(extra, &mut said);
        band.text(kit.hint, scale.x(6), scale.y(236), TEXT_DIM, line);
    }
}

/// `3 / 16`, page `page` counted from one of `pages`, into `out`.
fn page_of(page: usize, pages: usize, out: &mut [u8; 16]) -> &str {
    use super::camera::Part;
    let mut n = Part::Number(page + 1).write(out, 0);
    n = Part::Text(" / ").write(out, n);
    n = Part::Number(pages).write(out, n);
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// `+N more files`, into `out`.
fn more_files(extra: u16, out: &mut [u8; 24]) -> &str {
    use super::camera::Part;
    let mut n = Part::Text("+").write(out, 0);
    n = Part::Number(usize::from(extra)).write(out, n);
    n = Part::Text(" more files").write(out, n);
    core::str::from_utf8(&out[..n]).unwrap_or("")
}
