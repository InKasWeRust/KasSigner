// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The ECIES envelope.
//!
//! ```text
//! ephemeral_key  33   compressed secp256k1 point
//! nonce          12   AES-GCM
//! ciphertext      n
//! tag            16   AES-GCM
//! ```
//!
//! 61 bytes of overhead. Framing only, every field in the clear; the key
//! derivation is in `kassigner_crypto::ecies`, split where the first secret
//! appears, as the container is.
//!
//! The 45-byte header, `ephemeral_key || nonce` as written, is AES-GCM's
//! additional authenticated data, part of the format: the derived key binds
//! the ephemeral key but not the nonce, which would otherwise travel
//! unauthenticated.

/// Length of the compressed ephemeral public key.
pub const EPHEMERAL_SIZE: usize = 33;
/// Length of the AES-GCM nonce.
pub const NONCE_SIZE: usize = 12;
/// Length of the AES-GCM tag.
pub const TAG_SIZE: usize = 16;
/// Bytes an envelope adds to its plaintext.
pub const OVERHEAD: usize = EPHEMERAL_SIZE + NONCE_SIZE + TAG_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EciesError {
    /// Shorter than the overhead, so it cannot hold even an empty plaintext.
    TooShort { len: usize },
    /// The ephemeral key lacks a compressed-point prefix: a framing error,
    /// which one byte comparison tells apart from a curve error.
    BadEphemeralPrefix(u8),
    /// The caller's buffer is too small.
    BufferTooSmall { needed: usize },
}

/// A parsed envelope, borrowing the bytes it was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope<'a> {
    pub ephemeral_key: &'a [u8; EPHEMERAL_SIZE],
    pub nonce: &'a [u8; NONCE_SIZE],
    pub ciphertext: &'a [u8],
    pub tag: &'a [u8; TAG_SIZE],
}

/// Parse an envelope.
///
/// # Errors
///
/// `TooShort` below [`OVERHEAD`], `BadEphemeralPrefix` for a first byte that
/// is not `0x02` or `0x03`.
pub fn parse(wire: &[u8]) -> Result<Envelope<'_>, EciesError> {
    if wire.len() < OVERHEAD {
        return Err(EciesError::TooShort { len: wire.len() });
    }
    if !matches!(wire[0], 0x02 | 0x03) {
        return Err(EciesError::BadEphemeralPrefix(wire[0]));
    }

    let ct_at = EPHEMERAL_SIZE + NONCE_SIZE;
    let ct_len = wire.len() - OVERHEAD;
    let tag_at = ct_at + ct_len;

    Ok(Envelope {
        ephemeral_key: wire[..EPHEMERAL_SIZE]
            .try_into()
            .map_err(|_| EciesError::TooShort { len: wire.len() })?,
        nonce: wire[EPHEMERAL_SIZE..ct_at]
            .try_into()
            .map_err(|_| EciesError::TooShort { len: wire.len() })?,
        ciphertext: &wire[ct_at..tag_at],
        tag: wire[tag_at..tag_at + TAG_SIZE]
            .try_into()
            .map_err(|_| EciesError::TooShort { len: wire.len() })?,
    })
}

/// Bytes an envelope of `plaintext_len` occupies.
pub const fn wire_size(plaintext_len: usize) -> usize {
    OVERHEAD + plaintext_len
}

/// Offset of the ciphertext within an envelope, where a caller encrypting
/// in place writes the plaintext.
pub const fn ciphertext_offset() -> usize {
    EPHEMERAL_SIZE + NONCE_SIZE
}

/// Write the header, leaving the rest as it was, and return the envelope's
/// length. The caller encrypts in place at [`ciphertext_offset`] with the
/// header as AAD, then writes the tag.
///
/// # Errors
///
/// `BufferTooSmall` if `out` cannot hold the envelope.
pub fn write_header(
    ephemeral_key: &[u8; EPHEMERAL_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext_len: usize,
    out: &mut [u8],
) -> Result<usize, EciesError> {
    let needed = wire_size(plaintext_len);
    if out.len() < needed {
        return Err(EciesError::BufferTooSmall { needed });
    }
    out[..EPHEMERAL_SIZE].copy_from_slice(ephemeral_key);
    out[EPHEMERAL_SIZE..ciphertext_offset()].copy_from_slice(nonce);
    Ok(needed)
}
