// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The payload: a sealed container with its constant head removed.
//!
//! Every container begins with the same magic, version and purpose bytes, a
//! string a text search finds in a folder of photos. So that head is taken
//! off going in and put back coming out.
//!
//! # Three shapes, one written
//!
//! | shape | written by | begins with | what follows |
//! |---|---|---|---|
//! | v3 | v1.1.0 | the kdf byte, 1 or 2 | one `KAS\x06` container: length, salt, nonce, ciphertext, tag |
//! | v2 | v1.0.7 | the seed's length, 24 or 48 | a `KAS\x04` seed container from its length byte on, then a hint container the same way, or nothing |
//! | v1 | v1.0.5, v1.0.6 | `S0FT`, `KAS` in base64 | base64 of the whole seed container, `\|`, base64 of the hint's |
//!
//! v3 keeps the kdf byte v2 dropped, as there are two derivations. The
//! first byte tells the shapes apart without a key. v2 and v1 are only
//! read; level 2 opens the rebuilt containers.

use crate::container::{
    Kdf, Layout, Purpose, MAGIC_LEGACY, MAGIC_V1, NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};
use core::ops::Range;

/// Head bytes v3 takes off a `KAS\x06` container: magic, version, purpose.
pub const V3_HEAD: usize = 6;

/// Head bytes v2 took off a `KAS\x04` container: magic, version, purpose,
/// kdf.
pub const V2_HEAD: usize = 7;

/// The version byte a `KAS\x04` container carries.
const LEGACY_VERSION: u8 = 3;

/// A v2 blob's bytes besides its ciphertext: length, salt, nonce, tag.
const V2_FIXED: usize = 1 + SALT_SIZE + NONCE_SIZE + TAG_SIZE;

/// Which shape a payload is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// v1.1.0's: one container.
    V3,
    /// v1.0.7's: a seed container, and a hint's after it or not.
    V2,
    /// v1.0.5's and v1.0.6's: base64, a `|` between seed and hint.
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobError {
    /// Not a shape this reader knows: no payload, or not ours.
    Unknown,
    /// A known shape cut short, or with lengths that do not add up.
    Short,
    /// Base64 with a character outside the alphabet.
    Encoding,
    /// The caller's buffer cannot hold the result.
    BufferTooSmall,
}

/// The shape of a payload, from its first bytes and no key.
pub fn shape(payload: &[u8]) -> Result<Shape, BlobError> {
    match payload.first() {
        Some(1) | Some(2) => Ok(Shape::V3),
        Some(24) | Some(48) => Ok(Shape::V2),
        Some(b'S') if payload.starts_with(b"S0FT") => Ok(Shape::V1),
        _ => Err(BlobError::Unknown),
    }
}

/// The v3 blob of a `KAS\x06` container into `out`: its length.
///
/// # Errors
///
/// `Unknown` for anything but a version-1 `KAS\x06` container;
/// `BufferTooSmall`.
pub fn strip(container: &[u8], out: &mut [u8]) -> Result<usize, BlobError> {
    if container.len() < Layout::V1.overhead() || container[..4] != MAGIC_V1 || container[4] != 1 {
        return Err(BlobError::Unknown);
    }
    let n = container.len() - V3_HEAD;
    if out.len() < n {
        return Err(BlobError::BufferTooSmall);
    }
    out[..n].copy_from_slice(&container[V3_HEAD..]);
    Ok(n)
}

/// Where the rebuilt containers sit in the caller's buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unpacked {
    pub shape: Shape,
    /// The seed's container: [`Purpose::Stego`] with the hint inside for
    /// v3, [`Purpose::Seed`] for v2 and v1.
    pub seed: Range<usize>,
    /// The hint's [`Purpose::Raw`] container, if a v2 or v1 photo carried
    /// one; `None` for v3.
    pub hint: Option<Range<usize>>,
}

/// The payload's containers, heads put back, into `out` one after another.
///
/// # Errors
///
/// `Unknown` for a payload of no known shape; `Short` for one cut off or
/// claiming more than it holds; `Encoding` for bad base64;
/// `BufferTooSmall`.
pub fn unpack(payload: &[u8], out: &mut [u8]) -> Result<Unpacked, BlobError> {
    match shape(payload)? {
        Shape::V3 => {
            let n = payload.len() + V3_HEAD;
            if payload.len() < Layout::V1.overhead() - V3_HEAD {
                return Err(BlobError::Short);
            }
            if out.len() < n {
                return Err(BlobError::BufferTooSmall);
            }
            out[..4].copy_from_slice(&MAGIC_V1);
            out[4] = 1;
            out[5] = Purpose::Stego as u8;
            out[V3_HEAD..n].copy_from_slice(payload);
            Ok(Unpacked {
                shape: Shape::V3,
                seed: 0..n,
                hint: None,
            })
        }
        Shape::V2 => {
            let seed_len = v2_len(payload).ok_or(BlobError::Short)?;
            let seed_n = restore_v2(&payload[..seed_len], Purpose::Seed, out)?;
            let rest = &payload[seed_len..];
            let hint = if rest.is_empty() {
                None
            } else {
                let hint_len = v2_len(rest).ok_or(BlobError::Short)?;
                let (_, tail) = out.split_at_mut(seed_n);
                let hint_n = restore_v2(&rest[..hint_len], Purpose::Raw, tail)?;
                Some(seed_n..seed_n + hint_n)
            };
            Ok(Unpacked {
                shape: Shape::V2,
                seed: 0..seed_n,
                hint,
            })
        }
        Shape::V1 => {
            let bar = payload.iter().position(|&c| c == b'|');
            let (seed_text, hint_text) = match bar {
                Some(i) => (&payload[..i], Some(&payload[i + 1..])),
                None => (payload, None),
            };
            let seed_n = base64_decode(seed_text, out)?;
            if seed_n < Layout::Legacy.overhead() {
                return Err(BlobError::Short);
            }
            let hint = match hint_text {
                Some(t) if !t.is_empty() => {
                    let (_, tail) = out.split_at_mut(seed_n);
                    let n = base64_decode(t, tail)?;
                    Some(seed_n..seed_n + n)
                }
                _ => None,
            };
            Ok(Unpacked {
                shape: Shape::V1,
                seed: 0..seed_n,
                hint,
            })
        }
    }
}

/// Bytes a v2 blob occupies, from its own length byte: `None` for a zero
/// length or a blob that does not hold that many.
fn v2_len(blob: &[u8]) -> Option<usize> {
    let len = usize::from(*blob.first()?);
    if len == 0 {
        return None;
    }
    let n = V2_FIXED + len;
    (blob.len() >= n).then_some(n)
}

/// A `KAS\x04` container from a v2 blob, under `purpose`, into `out`.
fn restore_v2(blob: &[u8], purpose: Purpose, out: &mut [u8]) -> Result<usize, BlobError> {
    let n = blob.len() + V2_HEAD;
    if out.len() < n {
        return Err(BlobError::BufferTooSmall);
    }
    out[..4].copy_from_slice(&MAGIC_LEGACY);
    out[4] = LEGACY_VERSION;
    out[5] = purpose as u8;
    out[6] = Kdf::Pbkdf2Sha256 as u8;
    out[V2_HEAD..n].copy_from_slice(blob);
    Ok(n)
}

/// Standard base64 (RFC 4648) into `out`, skipping padding, spaces, line
/// breaks and NULs. Only for reading v1 artifacts.
pub fn base64_decode(text: &[u8], out: &mut [u8]) -> Result<usize, BlobError> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut n = 0usize;
    for &c in text {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' | 0 => continue,
            _ => return Err(BlobError::Encoding),
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if n >= out.len() {
                return Err(BlobError::BufferTooSmall);
            }
            out[n] = (acc >> bits) as u8;
            n += 1;
            acc &= (1 << bits) - 1;
        }
    }
    Ok(n)
}
