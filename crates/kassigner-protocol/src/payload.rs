// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Payload envelopes: two small formats of ours.
//!
//! The covenant payload, `[version][type][params...]`, encrypted before it
//! travels, records which construction made an output and with what
//! parameters, so a wallet can recover its covenants from the seed alone.
//! Nothing here reads `type` or the parameters: a signer that did would
//! trust a label from the party it exists to distrust. The device shows
//! scripts through a disassembler instead.
//!
//! The QR blob prefix, one byte, says whether a blob is raw bytes or legacy
//! ASCII. No legacy payload begins with `0x01`: base58 runs `0x31` to
//! `0x7A`, hex `0x30` to `0x66`, a mnemonic `0x61` to `0x7A`.

/// Smallest covenant payload: a version and a type, with no parameters.
pub const COVENANT_MIN_LEN: usize = 2;

/// The only covenant payload version defined.
pub const COVENANT_VERSION: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadError {
    /// Shorter than a version and a type.
    TooShort,
    /// A version byte this reader does not implement.
    UnsupportedVersion(u8),
    /// The caller's buffer cannot hold the result.
    BufferTooSmall,
}

/// A covenant payload, borrowing its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CovenantPayload<'a> {
    pub version: u8,
    /// Which construction produced this. Carried, never interpreted here.
    pub covenant_type: u8,
    /// Opaque here; their meaning belongs to whoever defined the type.
    pub params: &'a [u8],
}

/// Parse a decrypted covenant payload.
///
/// # Errors
///
/// `TooShort` below two bytes, `UnsupportedVersion` for a version this reader
/// does not implement.
pub fn parse_covenant(blob: &[u8]) -> Result<CovenantPayload<'_>, PayloadError> {
    if blob.len() < COVENANT_MIN_LEN {
        return Err(PayloadError::TooShort);
    }
    let version = blob[0];
    if version != COVENANT_VERSION {
        return Err(PayloadError::UnsupportedVersion(version));
    }
    Ok(CovenantPayload {
        version,
        covenant_type: blob[1],
        params: &blob[COVENANT_MIN_LEN..],
    })
}

/// Bytes a covenant payload with `params_len` parameters occupies.
pub const fn covenant_len(params_len: usize) -> usize {
    COVENANT_MIN_LEN + params_len
}

/// Write a covenant payload into `out`, returning bytes written.
///
/// # Errors
///
/// `BufferTooSmall` if `out` cannot hold it.
pub fn write_covenant(
    covenant_type: u8,
    params: &[u8],
    out: &mut [u8],
) -> Result<usize, PayloadError> {
    let n = covenant_len(params.len());
    if out.len() < n {
        return Err(PayloadError::BufferTooSmall);
    }
    out[0] = COVENANT_VERSION;
    out[1] = covenant_type;
    out[COVENANT_MIN_LEN..n].copy_from_slice(params);
    Ok(n)
}

/// How a QR blob is framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobFormat {
    /// No prefix. Base58, hex or text, read whole.
    LegacyAscii,
    /// Prefixed with `0x01`. Raw bytes, whose meaning the caller tracks.
    Raw,
}

/// The prefix byte marking a raw blob.
pub const BLOB_RAW_PREFIX: u8 = 0x01;

/// Classify a QR blob and return its body. An empty blob is `LegacyAscii`
/// with an empty body, not an error.
pub fn classify_blob(blob: &[u8]) -> (BlobFormat, &[u8]) {
    match blob.first() {
        Some(&BLOB_RAW_PREFIX) => (BlobFormat::Raw, &blob[1..]),
        _ => (BlobFormat::LegacyAscii, blob),
    }
}

/// Write a raw blob with its prefix, returning bytes written.
///
/// # Errors
///
/// `BufferTooSmall` if `out` cannot hold the prefix and the body.
pub fn write_raw_blob(body: &[u8], out: &mut [u8]) -> Result<usize, PayloadError> {
    let n = 1 + body.len();
    if out.len() < n {
        return Err(PayloadError::BufferTooSmall);
    }
    out[0] = BLOB_RAW_PREFIX;
    out[1..n].copy_from_slice(body);
    Ok(n)
}
