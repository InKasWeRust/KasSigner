// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Hex digits, read and written, once for the crate: the bundle reader and
//! envelope, the JSON of a node's messages, and the writers of both.
//!
//! Each reader keeps its own rule for what surrounds the digits: a bundle
//! string's escapes, the position a node message's error names, a plain yes
//! or no. These are the digits themselves.

/// The digits rusty-kaspa writes: lowercase.
const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// A hex digit's value, in either case, as serde reads hex; `None` for any
/// other byte.
pub(crate) const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Four digits, in either case, as one UTF-16 code unit: a JSON `\u`
/// escape's.
pub(crate) fn hex4(digits: &[u8]) -> Option<u16> {
    digits
        .iter()
        .try_fold(0u16, |acc, &c| Some((acc << 4) | u16::from(nibble(c)?)))
}

/// A byte as two lowercase digits.
pub(crate) fn digits(b: u8) -> [u8; 2] {
    [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 0x0f)]]
}

/// `bytes` as lowercase hex at the front of `out`, which must hold twice as
/// many: the bytes written.
pub(crate) fn write(bytes: &[u8], out: &mut [u8]) -> usize {
    let out = &mut out[..bytes.len() * 2];
    for (pair, &b) in out.chunks_exact_mut(2).zip(bytes) {
        pair.copy_from_slice(&digits(b));
    }
    out.len()
}
