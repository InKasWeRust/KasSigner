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

// KasSigner — Constant-Time Operations
// 100% Rust, no-std
//
// NEVER use == to compare cryptographic material.
// The == operator short-circuits on the first different byte,
// enabling timing attacks that deduce how many bytes match.
//
// All functions here iterate over ALL bytes every time,
// taking the same time regardless of content.


use core::sync::atomic::{compiler_fence, Ordering};

/// Compares two byte slices in constant time.
/// Returns true if and only if they are identical byte-by-byte.
/// Always iterates all bytes — never short-circuits.
#[inline(never)]
/// Constant-time equality comparison for byte slices.
/// Returns false if lengths differ. Prevents timing side-channels.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff: u8 = 0;

    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }

    compiler_fence(Ordering::SeqCst);
    diff == 0
}
/// Checks if a slice is all zeros in constant time.
/// Useful for detecting uninitialized buffers.
#[inline(never)]
/// Constant-time check if all bytes are zero.
pub fn is_zero(data: &[u8]) -> bool {
    let mut acc: u8 = 0;

    for &byte in data {
        acc |= byte;
    }

    compiler_fence(Ordering::SeqCst);
    acc == 0
}

/// Select condicional en tiempo constante.
/// Returns `a` if `condition` is true, `b` if false.
/// No branches — operates with bit masks.
#[inline(never)]
/// Constant-time conditional select: returns `a` if condition is true, `b` otherwise.
pub fn select(condition: bool, a: u8, b: u8) -> u8 {
    // Convert bool to mask: true → 0xFF, false → 0x00
    let mask = (-(condition as i8)) as u8;
    compiler_fence(Ordering::SeqCst);
    (a & mask) | (b & !mask)
}
