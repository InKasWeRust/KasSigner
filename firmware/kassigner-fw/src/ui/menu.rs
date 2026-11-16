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

//! The list menus: a title, and rows of an icon and a label, four to a
//! page, with back and home and, past one page, the arrows and dots. A menu
//! says only which row was tapped, and a Settings row which setting it is
//! (each unit has its own Settings rows).

use super::band::Band;
use super::chrome::{self, arrows, buttons, card, dots, header, lit_edge, List, Nav};
use super::color::{ACCENT, CARD, SHADOW_EDGE, SHADOW_FACE, SHADOW_TEXT, TEAL, TEXT};
use super::gen::Icon;
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;

/// What a row shows left of its label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glyph {
    /// An icon from the kit's sheet.
    Icon(Icon),
    /// A die showing five, filled, drawn: Iconoir's dice are outlines.
    Dice,
}

/// A Settings row: which setting it opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    Display,
    Audio,
    Camera,
    SdCard,
    About,
}

/// One row: its label, its glyph, and on Settings the setting it opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub label: &'static str,
    pub icon: Glyph,
    pub setting: Option<Setting>,
}

/// A menu: its title and its rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Menu {
    pub title: &'static str,
    pub items: &'static [Item],
}

/// Where the rows are: four to a page, the first under the rule.
pub(crate) const LIST: List = List { top: 46, rows: 4 };

const fn item(label: &'static str, icon: Icon) -> Item {
    Item {
        label,
        icon: Glyph::Icon(icon),
        setting: None,
    }
}

const fn drawn(label: &'static str, icon: Glyph) -> Item {
    Item {
        label,
        icon,
        setting: None,
    }
}

const fn setting(label: &'static str, icon: Icon, setting: Setting) -> Item {
    Item {
        label,
        icon: Glyph::Icon(icon),
        setting: Some(setting),
    }
}

/// Tools. Sign Message opens its three sources directly.
pub static TOOLS: Menu = Menu {
    title: "TOOLS",
    items: &[
        item("Seed Tools", Icon::GitFork),
        item("Import / Export", Icon::UploadSquare),
        item("Sign Message", Icon::PasswordCursor),
        item("Multisig", Icon::Group),
    ],
};

/// Seed Tools, under Tools. One New Seed, from every source the unit has at
/// once. KCC-3 Address gives the seed's hidden-key addresses.
pub static SEED_TOOLS: Menu = Menu {
    title: "SEED TOOLS",
    items: &[
        item("New Seed", Icon::Leaf),
        drawn("Dice Seed", Glyph::Dice),
        item("Import Words", Icon::Download),
        item("Address", Icon::AppleWallet),
        item("KCC-3 Address", Icon::EyeOff),
        item("BIP85 Child", Icon::GitFork),
        item("Calc Last Word", Icon::NumberedListRight),
    ],
};

/// Multisig, under Tools: Create Multisig, and the held group's address and
/// descriptor, dimmed while there is none.
pub static MULTISIG: Menu = Menu {
    title: "MULTISIG",
    items: &[
        item("Create Multisig", Icon::Group),
        item("Multisig Address", Icon::QrCode),
        item("Multisig Descriptor", Icon::Page),
    ],
};

/// KEY k/N's rows, under CREATE MULTISIG: a cosigner's key scanned, the
/// loaded seed's, or a kpub saved to the card (`KMnnnn.TXT`). The title is
/// [`super::multisig::add_key`]'s.
pub static ADD_KEY: &[Item] = &[
    item("Scan Multisig kpub", Icon::QrCode),
    item("Use Loaded Seed", Icon::Fingerprint),
    item("Load kpub from SD", Icon::AddFolder),
];

/// Import, under Tools' Import / Export.
pub static IMPORT: Menu = Menu {
    title: "IMPORT",
    items: &[
        item("Import from SD", Icon::AddFolder),
        item("Stego Import", Icon::EyeOff),
        item("Import Raw Key", Icon::Lock),
        item("Covenant Restore", Icon::ShieldCheck),
    ],
};

/// Sign Message's three sources, under Tools: typed, a `.TXT` on the card,
/// or text scanned in one code or in frames.
pub static SIGN_MESSAGE: Menu = Menu {
    title: "SIGN MESSAGE",
    items: &[
        item("Type manually", Icon::EditPencil),
        item("Load .TXT from SD", Icon::Page),
        item("Scan text QR", Icon::QrCode),
    ],
};

/// IMAGE DESCRIPTOR's source, under Steganography and Stego Import: typed,
/// or a card `.TXT`'s first line.
pub static DESCRIPTOR_SOURCE: Menu = Menu {
    title: "IMAGE DESCRIPTOR",
    items: &[
        item("Type manually", Icon::EditPencil),
        item("Load .TXT from SD", Icon::Page),
    ],
};

/// Import from SD, under Import.
pub static IMPORT_SD: Menu = Menu {
    title: "IMPORT FROM SD",
    items: &[
        item("Seed Backup", Icon::Upload),
        item("Transaction", Icon::Coin),
        item("kpub (Watch-Only)", Icon::EyeEmpty),
        item("Multisig Address", Icon::QrCode),
        item("Multisig Descriptor", Icon::Page),
        item("Covenant Restore", Icon::ShieldCheck),
    ],
};

/// Export, under Tools' Import / Export: what the seed in use can give.
pub static EXPORT: Menu = Menu {
    title: "EXPORT",
    items: &[
        item("Seed Backup", Icon::Upload),
        item("Watch-Only", Icon::EyeEmpty),
        item("Signing Keys", Icon::EditPencil),
        item("Steganography", Icon::EyeOff),
    ],
};

/// Seed Backup, under Export.
pub static SEED_BACKUP: Menu = Menu {
    title: "SEED BACKUP",
    items: &[
        item("Show Seed Words", Icon::OpenNewWindow),
        item("QR Export", Icon::QrCode),
        item("Backup to SD", Icon::FloppyDisk),
    ],
};

/// QR Export, under Seed Backup.
pub static QR_EXPORT: Menu = Menu {
    title: "QR EXPORT",
    items: &[
        item("CompactSeedQR", Icon::QrCode),
        item("Standard SeedQR", Icon::QrCode),
        item("Plain Text QR", Icon::QrCode),
    ],
};

/// Watch-Only, under Export.
pub static WATCH_ONLY: Menu = Menu {
    title: "WATCH-ONLY",
    items: &[
        item("kpub as QR", Icon::QrCode),
        item("kpub to SD", Icon::AppleWallet),
        item("kpub Multisig QR", Icon::Group),
    ],
};

/// Signing Keys, under Export: the seed in use's master key `m`, account
/// `m/44'/111111'/0'` and one address's key, shown as text and as a code,
/// never stored or written to the card. Both extended keys are `kprv`,
/// rusty-kaspa's prefix, which gives the network, not the level.
pub static SIGNING_KEYS: Menu = Menu {
    title: "SIGNING KEYS",
    items: &[
        item("kprv Master", Icon::Fingerprint),
        item("kprv Account", Icon::Lock),
        item("Private Key", Icon::PasswordCursor),
    ],
};

const DISPLAY: Item = setting("Display", Icon::Laptop, Setting::Display);
const AUDIO: Item = setting("Audio", Icon::SoundHigh, Setting::Audio);
const CAMERA: Item = setting("Camera", Icon::Camera, Setting::Camera);
const SD_CARD: Item = setting("SD Card", Icon::FloppyDisk, Setting::SdCard);
const ABOUT: Item = setting("About", Icon::HelpCircle, Setting::About);

/// Settings on a unit with a speaker: the M5Stack and the P4.
pub static SETTINGS: Menu = Menu {
    title: "SETTINGS",
    items: &[DISPLAY, AUDIO, CAMERA, SD_CARD, ABOUT],
};

/// Settings on a unit without a speaker: the Waveshare ESP32-S3.
pub static SETTINGS_NO_AUDIO: Menu = Menu {
    title: "SETTINGS",
    items: &[DISPLAY, CAMERA, SD_CARD, ABOUT],
};

/// What a touch on a menu can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    /// A row, by its place in the menu's items.
    Item(usize),
}

/// How many pages a menu takes.
pub const fn pages(menu: &Menu) -> usize {
    chrome::pages(menu.items.len(), LIST.rows)
}

/// Where a target is on `page`, if there: not a row on another page, nor
/// an arrow with no page behind it.
pub const fn zone(scale: Scale, menu: &Menu, page: usize, target: Target) -> Option<Zone> {
    let n = pages(menu);
    match target {
        Target::Nav(Nav::PageUp) if page == 0 => None,
        Target::Nav(Nav::PageDown) if page + 1 >= n => None,
        Target::Nav(nav) => Some(LIST.nav(scale, nav)),
        Target::Item(i) => match slot_of(menu, page, i) {
            Some(slot) => Some(LIST.touch(scale, slot)),
            None => None,
        },
    }
}

/// The page `setting`'s row is on in `menu`, for its screen to go back to;
/// the first if there is none.
pub fn page_of(menu: &Menu, setting: Setting) -> usize {
    menu.items
        .iter()
        .position(|it| it.setting == Some(setting))
        .map_or(0, |i| i / LIST.rows)
}

/// Where item `i` sits on `page`, if it is on it.
const fn slot_of(menu: &Menu, page: usize, i: usize) -> Option<usize> {
    if i < menu.items.len() && i / LIST.rows == page {
        Some(i % LIST.rows)
    } else {
        None
    }
}

/// What is under a point on `page`, if anything.
pub fn target(scale: Scale, menu: &Menu, page: usize, x: u16, y: u16) -> Option<Target> {
    let navs = [Nav::Back, Nav::Home, Nav::PageUp, Nav::PageDown].map(Target::Nav);
    navs.into_iter()
        .chain((0..menu.items.len()).map(Target::Item))
        .find(|&t| zone(scale, menu, page, t).is_some_and(|z| z.contains(x, y)))
}

/// A menu at `page`. `lit` is what is under a finger, if anything.
pub fn draw(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    menu: &Menu,
    page: usize,
    lit: Option<Target>,
) {
    draw_dimmed(band, scale, kit, menu, page, lit, 0);
}

/// [`draw`], with the rows whose bit is set in `dimmed` dimmed: rows with
/// nothing behind them for now. The caller ignores a tap on one.
pub fn draw_dimmed(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    menu: &Menu,
    page: usize,
    lit: Option<Target>,
    dimmed: u32,
) {
    header(band, scale, kit, menu.title);
    buttons(band, scale);

    for (i, it) in menu.items.iter().enumerate() {
        let Some(slot) = slot_of(menu, page, i) else {
            continue;
        };
        let z = LIST.row(scale, slot);
        let dim = i < 32 && dimmed & (1 << i) != 0;
        let (face, edge, thick, ink) = if dim {
            (SHADOW_FACE, SHADOW_EDGE, 1, SHADOW_TEXT)
        } else if lit == Some(Target::Item(i)) {
            (CARD, ACCENT, lit_edge(scale), TEXT)
        } else {
            (CARD, TEAL, 1, TEXT)
        };
        card(band, z, scale.len(6), face, edge, thick);
        let (x, y, _, h) = bounds(z);
        let side = i32::from(kit.icons.side);
        let tint = if dim { SHADOW_TEXT } else { TEAL };
        glyph(
            band,
            kit,
            it.icon,
            x + scale.len(8),
            y + (h - side) / 2,
            tint,
        );
        band.text(
            kit.title,
            x + scale.len(42),
            y + scale.len(28),
            ink,
            it.label,
        );
    }

    let n = pages(menu);
    if n > 1 {
        let lit = match lit {
            Some(Target::Nav(nav)) => Some(nav),
            _ => None,
        };
        arrows(band, scale, &LIST, page > 0, page + 1 < n, lit);
        dots(band, scale, page, n);
    }
}

/// A row's glyph, icon-sized, its top left at `x`, `y`, an icon in `tint`.
fn glyph(band: &mut Band<'_>, kit: &Kit, g: Glyph, x: i32, y: i32, tint: u16) {
    let s = i32::from(kit.icons.side);
    match g {
        Glyph::Icon(icon) => band.icon(x, y, kit.icons, icon, tint),
        Glyph::Dice => super::dice::die(band, x, y, s, 5),
    }
}
