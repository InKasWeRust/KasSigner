// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KCC-1's hash (3.2.1), BLAKE3 with a 32-byte output, and a template's hash
//! (3.7.3). The P2SH commitment to a redeem script stays BLAKE2b, as consensus
//! has it.

/// Length of every KCC-1 hash.
pub const HASH_LEN: usize = 32;

/// Longest key the keyed form takes; it is padded to 32 bytes.
pub const KEY_MAX: usize = 32;

/// `Hash(x)`: unkeyed BLAKE3 of `x`.
#[must_use]
pub fn hash(x: &[u8]) -> [u8; HASH_LEN] {
    *blake3::hash(x).as_bytes()
}

/// A key longer than [`KEY_MAX`] bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyTooLong;

/// `Key32(key)`: `key` followed by zeros to 32 bytes.
///
/// # Errors
///
/// [`KeyTooLong`] for a key longer than [`KEY_MAX`] bytes.
pub fn key32(key: &[u8]) -> Result<[u8; KEY_MAX], KeyTooLong> {
    let mut out = [0u8; KEY_MAX];
    out.get_mut(..key.len())
        .ok_or(KeyTooLong)?
        .copy_from_slice(key);
    Ok(out)
}

/// `Hash(x, key)`: BLAKE3's keyed mode over `x`, under `Key32(key)`.
///
/// # Errors
///
/// [`KeyTooLong`] for a key longer than [`KEY_MAX`] bytes.
pub fn keyed_hash(x: &[u8], key: &[u8]) -> Result<[u8; HASH_LEN], KeyTooLong> {
    Ok(*blake3::keyed_hash(&key32(key)?, x).as_bytes())
}

/// `TemplateHash(prefix, suffix)`:
/// `Hash(LE64(len(prefix)) || prefix || LE64(len(suffix)) || suffix)`. The
/// lengths bind where the prefix ends; KCC-1 forbids `Hash(prefix || suffix)`.
#[must_use]
pub fn template_hash(prefix: &[u8], suffix: &[u8]) -> [u8; HASH_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(&(prefix.len() as u64).to_le_bytes());
    h.update(prefix);
    h.update(&(suffix.len() as u64).to_le_bytes());
    h.update(suffix);
    *h.finalize().as_bytes()
}
