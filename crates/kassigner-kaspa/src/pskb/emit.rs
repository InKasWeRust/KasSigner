// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Writing a bundle back out: the original copied through, only the bytes
//! with a reason to change changed.
//!
//! A rebuild would need every field understood, and one that reordered
//! keys, renormalised a number or dropped another role's field would still
//! parse; with splices, every byte not named in one is the byte that
//! arrived.
//!
//! A splice is a position, a count of bytes to remove and bytes to put
//! there; an insertion removes nothing. The caller's slice of them is
//! checked sorted and non-overlapping before anything is written.

use super::schema::Span;
use crate::bip32_public::PUBLIC_KEY_SIZE;

/// Bytes of a Schnorr signature.
pub const SIGNATURE_LEN: usize = 64;

const SCHNORR_OPEN: &[u8] = b"{\"schnorr\":\"";
const SCHNORR_CLOSE: &[u8] = b"\"}";

/// Bytes of `"<public key hex>":`.
pub(crate) const KEY_PREFIX_LEN: usize = 1 + PUBLIC_KEY_SIZE * 2 + 1 + 1;

/// Bytes of `{"schnorr":"<signature hex>"}`.
pub(crate) const SCHNORR_VALUE_LEN: usize =
    SCHNORR_OPEN.len() + SIGNATURE_LEN * 2 + SCHNORR_CLOSE.len();

/// Bytes [`write_partial_sig`] writes.
pub const PARTIAL_SIG_MEMBER_LEN: usize = KEY_PREFIX_LEN + SCHNORR_VALUE_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmitError {
    /// Splices are not in ascending order, or two overlap. Refused, not
    /// sorted: overlapping edits are two intentions for the same bytes.
    UnorderedOrOverlapping { index: usize },
    /// A splice points past the end of the document.
    OutOfBounds { index: usize },
    /// The output buffer is too small. `emitted_len` gives the size needed.
    BufferTooSmall,
}

/// One edit: replace `len` bytes at `at` with `insert`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Splice<'a> {
    pub at: usize,
    pub len: usize,
    pub insert: &'a [u8],
}

impl<'a> Splice<'a> {
    /// Insert without removing anything.
    pub const fn insert_at(at: usize, bytes: &'a [u8]) -> Self {
        Self {
            at,
            len: 0,
            insert: bytes,
        }
    }

    /// Replace the whole of a span.
    pub const fn replace(span: Span, bytes: &'a [u8]) -> Self {
        Self {
            at: span.start,
            len: span.end - span.start,
            insert: bytes,
        }
    }
}

/// Bytes `emit` will produce, without producing them.
pub fn emitted_len(doc: &[u8], splices: &[Splice]) -> Result<usize, EmitError> {
    check(doc, splices)?;
    let mut n = doc.len();
    for s in splices {
        n = n - s.len + s.insert.len();
    }
    Ok(n)
}

/// Copy `doc` into `out`, applying `splices`; every other byte unchanged.
pub fn emit(doc: &[u8], splices: &[Splice], out: &mut [u8]) -> Result<usize, EmitError> {
    let needed = emitted_len(doc, splices)?;
    if out.len() < needed {
        return Err(EmitError::BufferTooSmall);
    }

    let mut read = 0usize;
    let mut write = 0usize;
    for s in splices {
        let gap = s.at - read;
        out[write..write + gap].copy_from_slice(&doc[read..read + gap]);
        write += gap;
        read += gap;

        out[write..write + s.insert.len()].copy_from_slice(s.insert);
        write += s.insert.len();
        read += s.len;
    }
    let tail = doc.len() - read;
    out[write..write + tail].copy_from_slice(&doc[read..]);
    Ok(write + tail)
}

fn check(doc: &[u8], splices: &[Splice]) -> Result<(), EmitError> {
    let mut prev_end = 0usize;
    for (i, s) in splices.iter().enumerate() {
        let end =
            s.at.checked_add(s.len)
                .ok_or(EmitError::OutOfBounds { index: i })?;
        if end > doc.len() {
            return Err(EmitError::OutOfBounds { index: i });
        }
        if s.at < prev_end {
            return Err(EmitError::UnorderedOrOverlapping { index: i });
        }
        prev_end = end;
    }
    Ok(())
}

/// Write a `partialSigs` member for a Schnorr signature, ready to splice:
/// `"<public key hex>":{"schnorr":"<signature hex>"}`, as upstream's
/// `PartialSigs` serializes one (`wallet/pskt/src/pskt.rs`), the key
/// compressed, lowercase. No sighash byte: a bundle keeps it per input in
/// `sighashType`. Returns [`PARTIAL_SIG_MEMBER_LEN`].
pub fn write_partial_sig(
    public_key: &[u8; PUBLIC_KEY_SIZE],
    signature: &[u8; SIGNATURE_LEN],
    out: &mut [u8],
) -> Result<usize, EmitError> {
    let out = out
        .get_mut(..PARTIAL_SIG_MEMBER_LEN)
        .ok_or(EmitError::BufferTooSmall)?;
    let n = write_key_prefix(public_key, out);
    Ok(n + write_schnorr_value(signature, &mut out[n..]))
}

/// Write `"<public key hex>":`. `out` must hold [`KEY_PREFIX_LEN`].
pub(crate) fn write_key_prefix(public_key: &[u8; PUBLIC_KEY_SIZE], out: &mut [u8]) -> usize {
    out[0] = b'"';
    let n = 1 + crate::hex::write(public_key, &mut out[1..]);
    out[n..n + 2].copy_from_slice(b"\":");
    n + 2
}

/// Write `{"schnorr":"<signature hex>"}`. `out` must hold
/// [`SCHNORR_VALUE_LEN`].
pub(crate) fn write_schnorr_value(signature: &[u8; SIGNATURE_LEN], out: &mut [u8]) -> usize {
    let mut n = SCHNORR_OPEN.len();
    out[..n].copy_from_slice(SCHNORR_OPEN);
    n += crate::hex::write(signature, &mut out[n..]);
    out[n..n + SCHNORR_CLOSE.len()].copy_from_slice(SCHNORR_CLOSE);
    n + SCHNORR_CLOSE.len()
}
