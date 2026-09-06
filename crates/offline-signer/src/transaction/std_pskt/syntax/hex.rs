//! Strict lowercase hexadecimal conversion.

use super::super::PskError;
use shared_signer::bytes::{decode_lower_hex_nibble, encode_lower_hex};

// ═══════════════════════════════════════════════════════════════════════
// Strict hex decoder
// ═══════════════════════════════════════════════════════════════════════

/// Map the shared canonical lowercase nibble primitive into the PSKT error.
#[inline]
fn decode_nibble(value: u8) -> Result<u8, PskError> {
    decode_lower_hex_nibble(value).ok_or(PskError::BadHexChar)
}

/// Strict lowercase-hex decoder.
///
/// Writes decoded bytes into `dst`, returns the number of bytes
/// written. Fails on:
///   - odd length `src` (can't form whole bytes)
///   - any character outside `0-9a-f` (uppercase, whitespace, `0x` prefix all rejected)
///   - `dst.len() < src.len() / 2`
///
/// No allocation. Single pass. Safe to call on the signing path — no
/// panics, no unwraps.
///
/// Example:
/// ```ignore
/// let mut out = [0u8; 4];
/// let n = hex_decode_strict(b"deadbeef", &mut out)?;
/// assert_eq!(n, 4);
/// assert_eq!(&out[..n], &[0xde, 0xad, 0xbe, 0xef]);
/// ```
pub fn hex_decode_strict(src: &[u8], dst: &mut [u8]) -> Result<usize, PskError> {
    if src.len() & 1 != 0 {
        return Err(PskError::OddHexLength);
    }
    let need = src.len() / 2;
    if dst.len() < need {
        return Err(PskError::ScratchBufferTooSmall);
    }
    for (index, pair) in src.chunks_exact(2).enumerate() {
        let hi = decode_nibble(pair[0])?;
        let lo = decode_nibble(pair[1])?;
        dst[index] = hi * 16 + lo;
    }
    Ok(need)
}

/// Encode bytes as lowercase hex into `dst`, returning the number of
/// ASCII chars written. Used by the serializer; defined here
/// because it's the natural inverse of `hex_decode_strict` and sharing
/// a file keeps both sides of the conversion in one review surface.
///
/// Fails with `OutputBufferTooSmall` if `dst.len() < src.len() * 2`.
pub fn hex_encode_lower(src: &[u8], dst: &mut [u8]) -> Result<usize, PskError> {
    encode_lower_hex(src, dst).ok_or(PskError::OutputBufferTooSmall)
}
