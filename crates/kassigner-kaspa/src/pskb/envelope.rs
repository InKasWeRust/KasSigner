// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The PSKB envelope: a four-byte tag then hex of UTF-8 JSON (upstream
//! `wallet/pskt/src/bundle.rs`:
//! `format!("PSKB{}", hex::encode(serde_json::to_string(self)?))`).

/// The tag every bundle begins with.
pub const MAGIC: &[u8; 4] = b"PSKB";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Shorter than the tag.
    TooShort,
    /// Does not begin with `PSKB`.
    BadMagic,
    /// The hex body has an odd number of characters.
    OddLength,
    /// A character outside `0-9`, `a-f` and `A-F`. As upstream's `hex`, this
    /// reads either case and writes lowercase.
    BadHexChar,
    /// The caller's buffer cannot hold the decoded body.
    BufferTooSmall,
}

/// Decode a bundle envelope into `out`: the JSON document's length. Its
/// contents are not checked here.
pub fn decode_envelope(bundle: &[u8], out: &mut [u8]) -> Result<usize, EnvelopeError> {
    if bundle.len() < MAGIC.len() {
        return Err(EnvelopeError::TooShort);
    }
    if &bundle[..MAGIC.len()] != MAGIC {
        return Err(EnvelopeError::BadMagic);
    }
    let body = &bundle[MAGIC.len()..];
    if !body.len().is_multiple_of(2) {
        return Err(EnvelopeError::OddLength);
    }
    let n = body.len() / 2;
    if out.len() < n {
        return Err(EnvelopeError::BufferTooSmall);
    }
    for i in 0..n {
        let hi = crate::hex::nibble(body[i * 2]).ok_or(EnvelopeError::BadHexChar)?;
        let lo = crate::hex::nibble(body[i * 2 + 1]).ok_or(EnvelopeError::BadHexChar)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(n)
}

/// Encode a JSON document into a bundle envelope in `out`, which needs
/// `4 + 2 * json.len()`: the bytes written.
pub fn encode_envelope(json: &[u8], out: &mut [u8]) -> Result<usize, EnvelopeError> {
    let total = MAGIC.len() + json.len() * 2;
    if out.len() < total {
        return Err(EnvelopeError::BufferTooSmall);
    }
    out[..MAGIC.len()].copy_from_slice(MAGIC);
    crate::hex::write(json, &mut out[MAGIC.len()..]);
    Ok(total)
}

/// Bytes the decoded document will occupy, without decoding it.
pub fn decoded_len(bundle: &[u8]) -> Result<usize, EnvelopeError> {
    if bundle.len() < MAGIC.len() {
        return Err(EnvelopeError::TooShort);
    }
    if &bundle[..MAGIC.len()] != MAGIC {
        return Err(EnvelopeError::BadMagic);
    }
    let body = bundle.len() - MAGIC.len();
    if !body.is_multiple_of(2) {
        return Err(EnvelopeError::OddLength);
    }
    Ok(body / 2)
}
