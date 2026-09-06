//! Canonical raw-binary QR payload envelope.
//!
//! This public wire module is intentionally licensed with the surrounding
//! `kassigner-protocol` crate under MIT OR Apache-2.0. It was moved from
//! `shared-signer` so the public envelope has one explicit
//! permissive owner instead of carrying a stale GPL-only source header inside
//! a permissively licensed crate.

/// Raw-binary QR payload header.
pub const PAYLOAD_V1_RAW: u8 = 0x01;

/// Maximum payload size supported by the QR encoder's V40 byte-mode ceiling.
pub const MAX_RAW_LEN: usize = 2_953;

/// Return the raw body of a framed binary QR payload.
///
/// Unframed, empty, and unknown-version payloads are rejected. Callers that
/// accept textual input must route it through an explicit text parser rather
/// than silently treating an arbitrary QR blob as another format.
#[must_use]
#[inline]
pub fn unwrap_v1_raw(blob: &[u8]) -> Option<&[u8]> {
    match blob.split_first() {
        Some((&PAYLOAD_V1_RAW, body)) if !body.is_empty() => Some(body),
        _ => None,
    }
}

/// Wrap raw bytes with the binary QR payload header.
///
/// `out` must be at least `data.len() + 1` bytes. Empty and oversized payloads
/// are rejected so a successfully framed value always has a usable body.
pub fn wrap_v1_raw(data: &[u8], out: &mut [u8]) -> Option<usize> {
    if data.is_empty() || data.len() > MAX_RAW_LEN {
        return None;
    }
    let needed = data.len() + 1;
    if out.len() < needed {
        return None;
    }
    out[0] = PAYLOAD_V1_RAW;
    out[1..needed].copy_from_slice(data);
    Some(needed)
}
