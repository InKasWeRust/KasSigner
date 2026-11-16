// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Steganography: a sealed seed backup hidden in a JPEG photograph.
//!
//! What is hidden is a sealed container, never the seed, keyed from the
//! **descriptor**, a line that reads as a photo caption and is the
//! password. This module hides and recovers the container's bytes, less
//! those the same in every photo ([`blob`]); level 2 opens them.
//!
//! - **Descriptor**: the payload in EXIF `UserComment`, the descriptor in
//!   `ImageDescription`. Survives a re-save, not metadata stripping.
//! - **Picture**: the payload in the quantized coefficients, in an order
//!   keyed from the descriptor, written nowhere. Survives metadata
//!   stripping, not re-compression.
//! - **Both**: lost only when both happen.
//!
//! An import reads both carriers; whichever opens, opens. No decryption key
//! is here, only the walk key level 2 derives, and the descriptor as a
//! caption. No allocator: the window and every output are the caller's.

pub mod blob;
pub mod carrier;
pub mod exif;
pub mod picture;
pub mod walk;

pub use carrier::{export, extract, Carrier, Export, Extracted, StegoError};

/// Whether `c` may be in a descriptor: printable ASCII, as the passphrase
/// keyboard offers.
pub const fn descriptor_char(c: u8) -> bool {
    c >= 0x20 && c <= 0x7E
}

/// Longest descriptor a unit writes into a photo, typed or read from a file.
pub const DESCRIPTOR_WRITE_MAX: usize = 64;

/// Longest descriptor a unit accepts when opening a photo: the most v1.0.7
/// wrote, so its photos still open.
pub const DESCRIPTOR_READ_MAX: usize = 128;

/// Whether `d` can be written as a descriptor: its length and characters.
pub fn descriptor_ok(d: &[u8]) -> bool {
    !d.is_empty() && d.len() <= DESCRIPTOR_WRITE_MAX && d.iter().all(|&c| descriptor_char(c))
}

/// Largest payload a photo carries: v1.0.7's take at most 202 bytes,
/// v1.1.0's 160.
pub const PAYLOAD_MAX: usize = 256;
