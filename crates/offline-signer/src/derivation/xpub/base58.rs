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

// Pure Base58 and Base58Check codec.

use sha2::{Digest, Sha256};

/// Bitcoin base58 alphabet
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ─── Base58 Encoding ──────────────────────────────────────────────────

/// Encode bytes as base58 string. Returns the number of chars written to `out`.
///
/// Algorithm: repeatedly divmod by 58 on the big-endian integer,
/// then reverse. Leading zero bytes become '1' characters.
pub(super) fn base58_encode(data: &[u8], out: &mut [u8]) -> usize {
    let leading_zeros = data.iter().take_while(|byte| **byte == 0).count();
    let mut buf = [0u8; 128];
    let len = data.len().min(buf.len());
    buf[..len].copy_from_slice(&data[..len]);

    let mut encoded = [0u8; 128];
    let mut encoded_len = 0usize;
    let mut start = leading_zeros.min(len);
    for _ in 0..len.saturating_mul(2).saturating_add(1) {
        start = buf
            .get(start..len)
            .and_then(|slice| slice.iter().position(|byte| *byte != 0))
            .and_then(|relative| start.checked_add(relative))
            .unwrap_or(len);
        if start >= len {
            break;
        }

        let mut remainder: u32 = 0;
        for byte in &mut buf[start..len] {
            let value = remainder.wrapping_shl(8).wrapping_add(u32::from(*byte));
            *byte = (value / 58) as u8;
            remainder = value % 58;
        }
        if encoded_len >= encoded.len() {
            return 0;
        }
        encoded[encoded_len] = BASE58_ALPHABET[remainder as usize];
        encoded_len += 1;
    }

    let mut pos = leading_zeros.min(out.len());
    out[..pos].fill(b'1');
    for digit in encoded[..encoded_len].iter().rev().copied() {
        let Some(slot) = out.get_mut(pos) else {
            break;
        };
        *slot = digit;
        pos += 1;
    }
    pos
}

/// SHA256 double hash (SHA256d): SHA256(SHA256(data))
pub(super) fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize()
    };
    let mut h = Sha256::new();
    h.update(first);
    let result: [u8; 32] = h.finalize().into();
    result
}

/// Base58Check encode: data + 4-byte SHA256d checksum → base58 string.
/// Returns the number of chars written to `out`.
pub(super) fn base58check_encode(data: &[u8], out: &mut [u8]) -> usize {
    // Compute checksum
    let checksum = sha256d(data);

    // Build payload + checksum
    let total_len = data.len() + 4;
    let mut buf = [0u8; 128];
    buf[..data.len()].copy_from_slice(data);
    buf[data.len()..total_len].copy_from_slice(&checksum[..4]);

    base58_encode(&buf[..total_len], out)
}

// ─── Base58 Decode ───────────────────────────────────────────────────

/// Reverse lookup: base58 char → value (0-57), or 0xFF for invalid.
fn base58_char_value(ch: u8) -> u8 {
    for (i, &c) in BASE58_ALPHABET.iter().enumerate() {
        if c == ch {
            return i as u8;
        }
    }
    0xFF
}

/// Base58 decode. Returns number of bytes written to `out`, or 0 on error.
fn base58_decode(input: &[u8], out: &mut [u8; 128]) -> usize {
    if input.is_empty() {
        return 0;
    }
    let leading_ones = input.iter().take_while(|byte| **byte == b'1').count();
    let mut buf = [0u8; 128];
    let mut buf_len = 0usize;
    for &ch in input {
        let value = base58_char_value(ch);
        if value == 0xFF || !accumulate_base58_digit(&mut buf, &mut buf_len, value) {
            return 0;
        }
    }
    copy_decoded_base58(&buf, buf_len, leading_ones, out)
}

fn accumulate_base58_digit(buf: &mut [u8; 128], buf_len: &mut usize, value: u8) -> bool {
    let carry = multiply_base58_bytes(&mut buf[..*buf_len], u32::from(value));
    if !prepend_base256_carry(buf, buf_len, carry) {
        return false;
    }
    true
}

fn multiply_base58_bytes(bytes: &mut [u8], mut carry: u32) -> u32 {
    for byte in bytes.iter_mut().rev() {
        carry = carry.saturating_add(u32::from(*byte) * 58);
        *byte = (carry & 0xFF) as u8;
        carry >>= 8;
    }
    carry
}

fn prepend_base256_carry(buf: &mut [u8; 128], buf_len: &mut usize, mut carry: u32) -> bool {
    while carry != 0 {
        if *buf_len >= buf.len() {
            return false;
        }
        buf.copy_within(0..*buf_len, 1);
        buf[0] = (carry & 0xFF) as u8;
        carry >>= 8;
        *buf_len += 1;
    }
    true
}

fn copy_decoded_base58(
    buf: &[u8; 128],
    buf_len: usize,
    leading_ones: usize,
    out: &mut [u8; 128],
) -> usize {
    let position = leading_ones.min(out.len());
    out[..position].fill(0);
    let copied = buf_len.min(out.len().saturating_sub(position));
    out[position..position + copied].copy_from_slice(&buf[..copied]);
    position + copied
}

/// Base58Check decode: verify checksum, return payload bytes.
/// Returns payload length, or 0 on error.
pub(super) fn base58check_decode(input: &[u8], out: &mut [u8; 128]) -> usize {
    let mut raw = [0u8; 128];
    let raw_len = base58_decode(input, &mut raw);
    if raw_len < 5 {
        return 0;
    }

    let payload_len = raw_len - 4;
    let checksum = sha256d(&raw[..payload_len]);

    if raw[payload_len] != checksum[0]
        || raw[payload_len + 1] != checksum[1]
        || raw[payload_len + 2] != checksum[2]
        || raw[payload_len + 3] != checksum[3]
    {
        return 0;
    }

    out[..payload_len].copy_from_slice(&raw[..payload_len]);
    payload_len
}
