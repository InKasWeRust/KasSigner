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

//! KPUB EXPORT QR and the other screens choosing how a code is shown:
//! Wallet (one code, for phones, kassigner.org and other wallets) or
//! KasSigner (version-3 frames, which every unit's camera reads off
//! another's screen); and the frame and signature counters beside a code in
//! frames. A card with more frames than a unit reassembles is dimmed.

use super::band::Band;
use super::camera::Part;
use super::chrome::{buttons, card, corner, header_at, Nav};
use super::color::{BACKGROUND, ORANGE, SHADOW_EDGE, SHADOW_FACE, SHADOW_TEXT, TEAL, TEXT_DIM};
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;

/// What a touch on KPUB EXPORT QR can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    /// The kpub's text, one code.
    Wallet,
    /// The raw form, two frames.
    KasSigner,
}

/// The two cards: 130 by 55 from y 100, 16 apart, centred.
const CARD: (i32, i32) = (130, 55);
const CARD_Y: i32 = 100;
const GAP: i32 = 16;

/// A card's left edge.
const fn card_x(right: bool) -> i32 {
    let x0 = (320 - 2 * CARD.0 - GAP) / 2;
    if right {
        x0 + CARD.0 + GAP
    } else {
        x0
    }
}

/// Where a target counts.
pub const fn zone(scale: Scale, target: Target) -> Option<Zone> {
    let right = match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => return Some(corner(scale, nav)),
        Target::Nav(_) => return None,
        Target::Wallet => false,
        Target::KasSigner => true,
    };
    let at = card_at(right);
    Some(scale.zone(at.0, at.1, at.2, at.3))
}

/// What is under a point.
pub fn target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Wallet,
        Target::KasSigner,
    ]
    .into_iter()
    .find(|&t| zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// Frames of a kpub's raw form for another unit (`Format::Kpub`, 38 bytes
/// and 41). The flow and Raw's hint both take the count from here.
pub const KPUB_FRAMES: usize = 2;
const _: () = assert!(
    KPUB_FRAMES >= 1 && KPUB_FRAMES <= 9,
    "one digit in the hint"
);
/// Raw's hint, its count [`KPUB_FRAMES`].
const RAW_HINT: [u8; 9] = {
    let mut b = *b"Raw, 0 QR";
    b[5] = b'0' + KPUB_FRAMES as u8;
    b
};

/// Watch-Only's kpub: its title and its cards' hints.
pub const KPUB_TITLE: &str = "KPUB EXPORT QR";
pub const KPUB_HINTS: (&str, &str) = (
    "ASCII, 1 QR",
    match core::str::from_utf8(&RAW_HINT) {
        Ok(hint) => hint,
        Err(_) => panic!("the hint is ASCII"),
    },
);
/// The signed message's.
pub const MESSAGE_TITLE: &str = "MESSAGE QR";
/// A multisig descriptor's, its hints as a signed message's.
pub const DESCRIPTOR_TITLE: &str = "DESCRIPTOR QR";
/// Plain Text QR's.
pub const PLAIN_TITLE: &str = "PLAIN TEXT QR";
/// A covenant card's backup line's, its hints as a signed message's.
pub const SAVINGS_TITLE: &str = "SAVINGS CARD QR";
/// The signing reply's.
pub const REPLY_TITLE: &str = "SIGNED TX QR";
/// What the signed message's and Plain Text QR's cards say they hold.
pub const TEXT: &str = "Text";

/// What a reply's cards say it is: a bundle's answer, or a KSPT.
pub const fn reply_what(bundle: bool) -> &'static str {
    if bundle {
        "PSKB"
    } else {
        "KSPT"
    }
}

/// What Wallet's card says of a reply in v1.0.7's form, written for a
/// wallet built on that release.
pub const REPLY_V107: &str = "KSPT v1.0.7";

/// KPUB EXPORT QR, or another code's screen with its own `title` and
/// `hints`: the title and two cards in teal, each card's hint under it.
pub fn format(band: &mut Band<'_>, scale: Scale, kit: &Kit, title: &str, hints: (&str, &str)) {
    format_live(band, scale, kit, title, hints, (true, true));
}

/// The same, each card dimmed unless `live` says it acts (Wallet's, then
/// KasSigner's).
pub fn format_live(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    title: &str,
    hints: (&str, &str),
    live: (bool, bool),
) {
    pair(
        band,
        scale,
        kit,
        title,
        ("Wallet", "KasSigner"),
        hints,
        live,
    );
}

/// A card of a two-card screen, left or right, in design pixels: x, y,
/// width, height. Import / Export's too.
pub(super) const fn card_at(right: bool) -> (i32, i32, i32, i32) {
    (card_x(right), CARD_Y, CARD.0, CARD.1)
}

/// A two-card screen, Format's and Import / Export's: `title` in teal, the
/// cards `labels`, left then right, each dimmed unless `live` says it acts,
/// each `hints`' line under its card (an empty one draws nothing).
pub(super) fn pair(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    title: &str,
    labels: (&str, &str),
    hints: (&str, &str),
    live: (bool, bool),
) {
    header_at(band, scale, kit, title, (TEAL, TEAL), (30, 40));
    buttons(band, scale);
    for (right, label, hint, live) in [
        (false, labels.0, hints.0, live.0),
        (true, labels.1, hints.1, live.1),
    ] {
        let x = card_x(right);
        let z = scale.zone(x, CARD_Y, CARD.0, CARD.1);
        let (fill, edge, ink) = if live {
            (TEAL, TEAL, BACKGROUND)
        } else {
            (SHADOW_FACE, SHADOW_EDGE, SHADOW_TEXT)
        };
        card(band, z, scale.len(6), fill, edge, 1);
        let (zx, zy, zw, _) = bounds(z);
        band.text_centered(kit.title, zx + zw / 2, zy + scale.len(35), ink, label);
        let mid = scale.x(x + CARD.0 / 2);
        band.text_centered(kit.hint, mid, scale.y(CARD_Y + CARD.1 + 14), TEXT_DIM, hint);
    }
}

/// A card's hint, `Text, N QR`, `KSPT, N QR`, `PSKB, N QR` or
/// `KSPT v1.0.7, N QR`, into `out`.
pub fn codes_hint<'o>(what: &str, frames: usize, out: &'o mut [u8; 24]) -> &'o str {
    let mut n = Part::Text(what).write(out, 0);
    n = Part::Text(", ").write(out, n);
    n = Part::Number(frames).write(out, n);
    n = Part::Text(" QR").write(out, n);
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// The frame counter, FRAMES and which of how many, in the column right of
/// the code's square. `panel` is the panel's width and height.
pub fn counter(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    panel: (u16, u16),
    (frame, total): (usize, usize),
) {
    let column = (i32::from(panel.0) + i32::from(panel.1)) / 2;
    band.text_centered(kit.hint, column, scale.y(160), TEXT_DIM, "FRAMES");
    let mut t = [0u8; 8];
    let mut n = Part::Number(frame + 1).write(&mut t, 0);
    n = Part::Text("/").write(&mut t, n);
    n = Part::Number(total).write(&mut t, n);
    band.text_centered(
        kit.title,
        column,
        scale.y(190),
        TEAL,
        core::str::from_utf8(&t[..n]).unwrap_or(""),
    );
}

/// A multisig reply's SIGNER count above the frame counter: orange while a
/// signature is missing, teal once fully signed. `panel` as for
/// [`counter`].
pub fn signer(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    panel: (u16, u16),
    (present, required): (usize, usize),
) {
    let column = (i32::from(panel.0) + i32::from(panel.1)) / 2;
    band.text_centered(kit.hint, column, scale.y(40), TEXT_DIM, "SIGNER");
    let mut t = [0u8; 16];
    let mut n = Part::Number(present).write(&mut t, 0);
    n = Part::Text("/").write(&mut t, n);
    n = Part::Number(required).write(&mut t, n);
    let color = if present >= required { TEAL } else { ORANGE };
    band.text_centered(
        kit.title,
        column,
        scale.y(70),
        color,
        core::str::from_utf8(&t[..n]).unwrap_or(""),
    );
}
