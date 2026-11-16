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

//! The loading screen: a teal title, a line under it, and a bar that says
//! how far. Only the bar is redrawn while it moves.

use super::band::Band;
use super::color::{CARD, TEAL, TEXT_DIM};
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;

/// A wallet being opened.
pub const OPENING: (&str, &str) = ("LOADING", "Deriving addresses...");
/// The search for a request's keys, with a back button.
pub const SEARCHING: (&str, &str) = ("SEARCHING", "Checking this seed's addresses...");

/// A request being checked before its review: one call, the bar held at
/// half so the scan screen does not look frozen after a large request.
pub const CHECKING: (&str, &str) = ("CHECKING", "Reading the transaction...");

/// A transaction being signed after CONFIRM: one call, the bar held at
/// half.
pub const SIGNING: (&str, &str) = ("SIGNING", "Signing the transaction...");

/// A message being signed after SIGN, likewise.
pub const SIGNING_MESSAGE: (&str, &str) = ("SIGNING", "Signing the message...");

/// A BIP85 child being derived.
pub const DERIVING: (&str, &str) = ("DERIVING", "The child seed");

/// kprv Master's key being derived.
pub const MASTER: (&str, &str) = ("DERIVING", "The master key");

/// Private Key's key being derived, for the chain and index shown.
pub const PRIVATE_KEY: (&str, &str) = ("DERIVING", "The private key");

/// Multisig Address opening a group the first time: every cosigner's key
/// derived for both chains.
pub const GROUP_ADDRESS: (&str, &str) = ("DERIVING", "The multisig address");

/// A backup being sealed.
pub const ENCRYPTING: (&str, &str) = ("ENCRYPTING", "This can take a while");

/// A backup being opened.
pub const DECRYPTING: (&str, &str) = ("DECRYPTING", "This can take a while");

/// Argon2id encryption on the P4: one call, so the bar is held at half and
/// the line says how long.
pub const ENCRYPTING_WAIT: (&str, &str) = ("ENCRYPTING", "Please wait, about 25 s");
/// Steganography's payload going into the photo (a few seconds with the
/// Picture carrier), the bar held at half.
pub const EMBEDDING: (&str, &str) = ("EMBEDDING", "Hiding the backup in the photo");
/// Stego Import reading both carriers: one pass, the bar held at half.
pub const READING: (&str, &str) = ("READING", "Looking for the backup");

/// Decrypting under Argon2id, as [`ENCRYPTING_WAIT`].
pub const DECRYPTING_WAIT: (&str, &str) = ("DECRYPTING", "Please wait, about 25 s");

/// Where the bar is.
pub const fn bar_area(scale: Scale) -> Zone {
    scale.zone(40, 145, 240, 10)
}

/// The whole screen: `title`, `line`, and the bar at `done` of `total`.
pub fn draw(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    (title, line): (&str, &str),
    done: usize,
    total: usize,
) {
    band.text_centered(kit.header, scale.x(160), scale.y(90), TEAL, title);
    band.text_centered(kit.body, scale.x(160), scale.y(125), TEXT_DIM, line);
    bar(band, scale, done, total);
}

/// The bar alone.
pub fn bar(band: &mut Band<'_>, scale: Scale, done: usize, total: usize) {
    let (x, y, w, h) = bounds(bar_area(scale));
    band.fill(x, y, w, h, CARD);
    let filled = w * done.min(total) as i32 / (total.max(1) as i32);
    band.fill(x, y, filled, h, TEAL);
}
