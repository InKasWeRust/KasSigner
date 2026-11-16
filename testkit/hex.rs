// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Hex text to bytes and back, for the tests: the vectors, the fixtures and
//! the JSON the tests check carry their bytes in hex. One copy for every
//! crate's tests, included by path like `vectors.rs`, as a `pub mod` so a
//! test that uses one of these is not warned about the others:
//!
//! ```ignore
//! #[path = "../../../testkit/hex.rs"]
//! pub mod hex;
//! use hex::{hex, unhex};
//! ```

/// The bytes `text` spells, two digits a byte, either case. A test's own
/// fixture that is not hex stops the test, naming it.
pub fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex: {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16).unwrap_or_else(|_| panic!("not hex: {text}"))
        })
        .collect()
}

/// [`unhex`] into an array, for a key, a hash or a signature: `text` must
/// spell exactly `N` bytes.
pub fn unhex_array<const N: usize>(text: &str) -> [u8; N] {
    unhex(text)
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("{} bytes, not {N}: {text}", v.len()))
}

/// `bytes` in lowercase hex, two digits a byte.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
