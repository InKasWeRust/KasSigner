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

//! The seeds screen: three seeds a page under Address and Export, the seed
//! in use lit, and `+` rows up to the unit's capacity. [`Seed`] rows hold
//! nothing secret: a fingerprint is public by design.

use super::band::Band;
use super::chrome::{self, arrows, buttons, card, dots, header, lit_edge, place, List, Nav};
use super::color::{
    ACCENT, BACKGROUND, CARD, CARD_EDGE, ORANGE, RED_BUTTON, SHADOW_EDGE, SHADOW_FACE, SHADOW_TEXT,
    TEAL, TEAL_BUTTON, TEXT, TEXT_DIM,
};
use super::gen::Icon;
use super::image::Image;
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;

/// What a slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A mnemonic of twelve words.
    Words12,
    /// Of twenty-four.
    Words24,
    /// An extended private key.
    Xprv,
    /// A raw key.
    Key,
}

impl Kind {
    /// The short label a row shows.
    pub const fn label(self) -> &'static str {
        match self {
            Kind::Words12 => "12w",
            Kind::Words24 => "24w",
            Kind::Xprv => "xprv",
            Kind::Key => "KEY",
        }
    }

    /// The longer name a confirmation uses.
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Words12 => "12-word seed",
            Kind::Words24 => "24-word seed",
            Kind::Xprv => "xprv",
            Kind::Key => "KEY",
        }
    }
}

/// One seed, as its row shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seed {
    pub fingerprint: [u8; 4],
    pub kind: Kind,
    /// Whether a passphrase is set on it.
    pub passphrase: bool,
    /// Whether it is the seed in use.
    pub active: bool,
    /// False for a seed made here whose backup is not checked yet.
    pub backed: bool,
}

/// Rows for the probe and the tests: each kind, the first in use, one with
/// a passphrase; the first fingerprint the twelve-word `abandon` vector's,
/// the rest made up. With [`SAMPLE_CAPACITY`], two pages.
pub const SAMPLE: [Seed; 5] = [
    sample([0x73, 0xc5, 0xda, 0x0a], Kind::Words12, false, true),
    sample([0x0a, 0x1b, 0x2c, 0x3d], Kind::Words24, true, false),
    sample([0x5e, 0x6f, 0x7a, 0x8b], Kind::Xprv, false, false),
    sample([0x9c, 0x0d, 0x1e, 0x2f], Kind::Key, false, false),
    sample([0x44, 0x55, 0x66, 0x77], Kind::Words12, false, false),
];

/// Slots the sample assumes: the units', [`crate::limits::SLOTS`].
pub const SAMPLE_CAPACITY: usize = crate::limits::SLOTS;

const fn sample(fingerprint: [u8; 4], kind: Kind, passphrase: bool, active: bool) -> Seed {
    Seed {
        fingerprint,
        kind,
        passphrase,
        active,
        backed: true,
    }
}

/// A row's text, in place of the fingerprint, for a seed with no backup.
pub const NO_BACKUP: &str = "NO BACKUP";

impl Seed {
    /// Its line on a confirmation, `Slot: 73c5da0a (12-word seed)`, into
    /// `out`.
    pub fn describe<'a>(&self, out: &'a mut [u8; 40]) -> &'a str {
        let digits = hex(self.fingerprint);
        let name: &[u8] = if self.backed {
            &digits
        } else {
            NO_BACKUP.as_bytes()
        };
        let parts: [&[u8]; 4] = [b"Slot: ", name, b" (", self.kind.name().as_bytes()];
        let mut n = 0;
        for p in parts.iter().chain([b")".as_slice()].iter()) {
            out[n..n + p.len()].copy_from_slice(p);
            n += p.len();
        }
        core::str::from_utf8(&out[..n]).unwrap_or("Slot")
    }
}

/// What a touch on the seeds screen can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    Address,
    Export,
    /// A row, by its place on the page: a seed or a `+`.
    Row(usize),
    /// A seed row's delete button, by the row's place.
    Delete(usize),
}

/// Rows on a page.
pub const ROWS: usize = 3;

/// A slot's name where its seed cannot be described, DELETE's fallback.
pub const SLOT: &str = "Slot";

/// Where the rows are: three to a page, under the buttons.
const LIST: List = List {
    top: 88,
    rows: ROWS,
};

/// The delete button's bin, the backup list's too.
pub(crate) static TRASH: Image = Image::new(
    20,
    24,
    include_bytes!("../../assets/images/icon_trash_20x24.raw"),
);

/// How many rows the list runs to: every seed, and one `+` if another fits.
const fn listed(seeds: usize, capacity: usize) -> usize {
    if seeds < capacity {
        seeds + 1
    } else {
        capacity
    }
}

/// How many pages the seeds take.
pub const fn pages(seeds: &[Seed], capacity: usize) -> usize {
    chrome::pages(listed(seeds.len(), capacity), LIST.rows)
}

/// The Address button.
const ADDRESS_AT: (i32, i32, i32, i32) = (11, 54, 146, 28);

/// Whether Address is dimmed, doing nothing: the seed in use has no backup.
pub const fn address_dimmed(seeds: &[Seed]) -> bool {
    let mut i = 0;
    while i < seeds.len() {
        if seeds[i].active {
            return !seeds[i].backed;
        }
        i += 1;
    }
    false
}

/// Where a target is on `page`, if there: a delete button only on a seed's
/// row, an arrow only with a page behind it, Address only when not dimmed.
pub const fn zone(
    scale: Scale,
    seeds: &[Seed],
    capacity: usize,
    page: usize,
    target: Target,
) -> Option<Zone> {
    let n = pages(seeds, capacity);
    match target {
        Target::Nav(Nav::PageUp) if page == 0 => None,
        Target::Nav(Nav::PageDown) if page + 1 >= n => None,
        Target::Nav(nav) => Some(LIST.nav(scale, nav)),
        Target::Address if address_dimmed(seeds) => None,
        Target::Address => Some(scale.zone(ADDRESS_AT.0, ADDRESS_AT.1, ADDRESS_AT.2, ADDRESS_AT.3)),
        Target::Export => Some(scale.zone(163, 54, 146, 28)),
        Target::Row(slot) if slot < LIST.rows && page * LIST.rows + slot < capacity => {
            Some(LIST.touch(scale, slot))
        }
        Target::Delete(slot) if slot < LIST.rows && page * LIST.rows + slot < seeds.len() => {
            Some(scale.zone(232, LIST.row_top(slot) + 3, 38, 36))
        }
        Target::Row(_) | Target::Delete(_) => None,
    }
}

/// What is under a point on `page`; a delete button wins over its row.
pub fn target(
    scale: Scale,
    seeds: &[Seed],
    capacity: usize,
    page: usize,
    x: u16,
    y: u16,
) -> Option<Target> {
    let fixed = [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Nav(Nav::PageUp),
        Target::Nav(Nav::PageDown),
        Target::Address,
        Target::Export,
    ];
    fixed
        .into_iter()
        .chain((0..LIST.rows).map(Target::Delete))
        .chain((0..LIST.rows).map(Target::Row))
        .find(|&t| zone(scale, seeds, capacity, page, t).is_some_and(|z| z.contains(x, y)))
}

/// Eight hex digits.
fn hex(fingerprint: [u8; 4]) -> [u8; 8] {
    let mut out = [0u8; 8];
    crate::text::write_hex(&fingerprint, &mut out);
    out
}

/// The seeds screen at `page`, `lit` what is under a finger.
pub fn draw(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    seeds: &[Seed],
    capacity: usize,
    page: usize,
    lit: Option<Target>,
) {
    header(band, scale, kit, "SEEDS");
    buttons(band, scale);
    let edge_of = |t: Target, edge: u16| {
        if lit == Some(t) {
            (ACCENT, lit_edge(scale))
        } else {
            (edge, 1)
        }
    };

    // Address dimmed while the seed in use has no backup.
    if address_dimmed(seeds) {
        let (x, y, w, h) = ADDRESS_AT;
        let z = scale.zone(x, y, w, h);
        card(band, z, scale.len(6), SHADOW_FACE, SHADOW_EDGE, 1);
        let (x, y, w, _) = bounds(z);
        band.text_centered(
            kit.title,
            x + w / 2,
            y + scale.len(20),
            SHADOW_TEXT,
            "Address",
        );
    }
    // The buttons: dark teal faces, black labels.
    for (t, label) in [(Target::Address, "Address"), (Target::Export, "Export")] {
        let Some(z) = zone(scale, seeds, capacity, page, t) else {
            continue;
        };
        let (edge, thick) = edge_of(t, TEAL);
        card(band, z, scale.len(6), TEAL_BUTTON, edge, thick);
        let (x, y, w, _) = bounds(z);
        band.text_centered(kit.title, x + w / 2, y + scale.len(20), BACKGROUND, label);
    }

    // Every row on the page up to the capacity: a seed or a `+`.
    for slot in 0..LIST.rows.min(capacity.saturating_sub(page * LIST.rows)) {
        let z = LIST.row(scale, slot);
        let (x, y, w, _) = bounds(z);
        let base = scale.len(28);
        match seeds.get(page * LIST.rows + slot) {
            Some(seed) => {
                let lit = lit == Some(Target::Row(slot));
                seed_row(band, scale, kit, z, seed, lit);
                if let Some(d) = zone(scale, seeds, capacity, page, Target::Delete(slot)) {
                    let (edge, thick) = edge_of(Target::Delete(slot), RED_BUTTON);
                    card(band, d, scale.len(4), RED_BUTTON, edge, thick);
                    place(band, scale, &TRASH, d);
                }
            }
            None => {
                let (edge, thick) = edge_of(Target::Row(slot), CARD_EDGE);
                card(band, z, scale.len(6), CARD, edge, thick);
                band.text_centered(kit.title, x + w / 2, y + base, TEXT_DIM, "+");
            }
        }
    }

    // Arrows always, dim with no page behind them; dots past one page.
    let n = pages(seeds, capacity);
    let lit = match lit {
        Some(Target::Nav(nav)) => Some(nav),
        _ => None,
    };
    arrows(band, scale, &LIST, page > 0, page + 1 < n, lit);
    dots(band, scale, page, n);
}

/// A seed's row in `z`, on the seeds screen and SELECT SEED: lit under a
/// finger, teal while in use; the fingerprint icon and digits, or NO BACKUP;
/// its kind, and `PP` for a passphrase.
fn seed_row(band: &mut Band<'_>, scale: Scale, kit: &Kit, z: Zone, seed: &Seed, lit: bool) {
    let (x, y, _, h) = bounds(z);
    let base = scale.len(28);
    let (fill, edge) = if seed.active {
        (CARD_EDGE, TEAL)
    } else {
        (CARD, CARD_EDGE)
    };
    let (edge, thick) = if lit {
        (ACCENT, lit_edge(scale))
    } else {
        (edge, 1)
    };
    card(band, z, scale.len(6), fill, edge, thick);

    let ink = if seed.active { TEAL } else { TEXT };
    // No backup yet: NO BACKUP, in orange, for the fingerprint.
    if seed.backed {
        let side = i32::from(kit.icons.side);
        band.icon(
            x + scale.len(6),
            y + (h - side) / 2,
            kit.icons,
            Icon::Fingerprint,
            ink,
        );
        let digits = hex(seed.fingerprint);
        let digits = core::str::from_utf8(&digits).unwrap_or("????????");
        band.text(kit.title, x + scale.len(36), y + base, ink, digits);
    } else {
        band.text(kit.title, x + scale.len(8), y + base, ORANGE, NO_BACKUP);
    }
    band.text(
        kit.body,
        x + scale.len(130),
        y + base,
        ink,
        seed.kind.label(),
    );
    if seed.passphrase {
        band.text(
            kit.hint,
            x + scale.len(170),
            y + scale.len(26),
            ORANGE,
            "PP",
        );
    }
}

/// What a touch on SELECT SEED can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    Nav(Nav),
    /// A seed, by its row's place on the page.
    Row(usize),
}

/// SELECT SEED's rows: three a page, from under the rule.
const PICK: List = List {
    top: 46,
    rows: ROWS,
};

/// How many pages SELECT SEED takes for `seeds` seeds.
pub const fn pick_pages(seeds: usize) -> usize {
    chrome::pages(seeds, PICK.rows)
}

/// Where a target is on SELECT SEED's `page`: a row only for a seed, an
/// arrow only with a page behind it.
pub const fn pick_zone(scale: Scale, seeds: usize, page: usize, target: Pick) -> Option<Zone> {
    match target {
        Pick::Nav(Nav::PageUp) if page == 0 => None,
        Pick::Nav(Nav::PageDown) if page + 1 >= pick_pages(seeds) => None,
        Pick::Nav(nav) => Some(PICK.nav(scale, nav)),
        Pick::Row(slot) if slot < PICK.rows && page * PICK.rows + slot < seeds => {
            Some(PICK.touch(scale, slot))
        }
        Pick::Row(_) => None,
    }
}

/// What is under a point on SELECT SEED's `page`, if anything.
pub fn pick_target(scale: Scale, seeds: usize, page: usize, x: u16, y: u16) -> Option<Pick> {
    [Nav::Back, Nav::Home, Nav::PageUp, Nav::PageDown]
        .map(Pick::Nav)
        .into_iter()
        .chain((0..PICK.rows).map(Pick::Row))
        .find(|&t| pick_zone(scale, seeds, page, t).is_some_and(|z| z.contains(x, y)))
}

/// SELECT SEED at `page`, under `title`: the seeds as on the seeds screen,
/// with no delete buttons and no `+`.
pub fn draw_pick(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    title: &str,
    seeds: &[Seed],
    page: usize,
    lit: Option<Pick>,
) {
    header(band, scale, kit, title);
    buttons(band, scale);
    for slot in 0..PICK.rows {
        if let Some(seed) = seeds.get(page * PICK.rows + slot) {
            let z = PICK.row(scale, slot);
            seed_row(band, scale, kit, z, seed, lit == Some(Pick::Row(slot)));
        }
    }
    let n = pick_pages(seeds.len());
    let lit = match lit {
        Some(Pick::Nav(nav)) => Some(nav),
        _ => None,
    };
    arrows(band, scale, &PICK, page > 0, page + 1 < n, lit);
    dots(band, scale, page, n);
}
