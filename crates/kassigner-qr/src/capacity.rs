// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! QR version capacities at error correction level L: ISO/IEC 18004's
//! numbers.

/// Highest version this crate can encode: the last whose length field is
/// eight bits in byte mode and ten in numeric, as the encoder writes them.
/// From version 10 they widen to sixteen and twelve. A limit of the code,
/// not of a device.
pub const MAX_VERSION: u8 = 9;

/// Bytes storable at each version, byte mode, error correction level L.
const BYTE: [usize; MAX_VERSION as usize] = [17, 32, 53, 78, 106, 134, 154, 192, 230];

/// Digits storable at each version, numeric mode, error correction level L.
const NUMERIC: [usize; MAX_VERSION as usize] = [41, 77, 127, 187, 255, 322, 370, 461, 552];

/// Matrix side length for a version. `17 + 4v`, from the standard.
pub const fn side(version: u8) -> u8 {
    17 + version * 4
}

/// Bytes storable at `version`, or `None` if out of range.
pub const fn byte_capacity(version: u8) -> Option<usize> {
    if version == 0 || version > MAX_VERSION {
        None
    } else {
        Some(BYTE[version as usize - 1])
    }
}

/// Digits storable at `version`, or `None` if out of range.
pub const fn numeric_capacity(version: u8) -> Option<usize> {
    if version == 0 || version > MAX_VERSION {
        None
    } else {
        Some(NUMERIC[version as usize - 1])
    }
}

/// Smallest version holding `len` bytes.
pub const fn select_version(len: usize) -> Option<u8> {
    let mut v = 0;
    while v < MAX_VERSION as usize {
        if len <= BYTE[v] {
            return Some(v as u8 + 1);
        }
        v += 1;
    }
    None
}

/// Smallest version holding `digits` numerals.
pub const fn select_version_numeric(digits: usize) -> Option<u8> {
    let mut v = 0;
    while v < MAX_VERSION as usize {
        if digits <= NUMERIC[v] {
            return Some(v as u8 + 1);
        }
        v += 1;
    }
    None
}
