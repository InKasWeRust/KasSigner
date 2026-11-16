// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The order the Picture carrier visits coefficients in: a keyed
//! permutation of their positions, held in no memory at all.
//!
//! A payload in the first positions would leave the picture's head
//! statistically unlike its tail, for a chi-square test to find; so the key
//! scatters it over the whole picture.
//!
//! An index of every position would take millions of four-byte entries,
//! more memory than a unit has, and a scan cannot be visited out of order
//! anyway. So the permutation is a four-round Feistel network, a bijection
//! for any round function, over an even number of bits covering the
//! positions; a result past the count is encrypted again until inside
//! (cycle walking). The scan is visited in order and each position asked
//! its place: [`Walk::rank`].
//!
//! The 32-byte key is derived from the descriptor as v1.0.7 derived it, so
//! v1.0.7's photos read with the same walk. The walk protects nothing (the
//! payload is sealed); a wrong descriptor just finds nothing. The round
//! function is an integer mixer, not a hash, as it runs for every non-zero
//! coefficient of every pass.

/// The label of the walk key, `SHA-256(KEY_LABEL || descriptor)`, as in
/// v1.0.7.
pub const KEY_LABEL: &[u8] = b"KasSigner-stego-perm-v1";

/// Bytes of a walk key.
pub const KEY_SIZE: usize = 32;

const ROUNDS: usize = 4;

/// A keyed bijection on `[0, n)`.
#[derive(Clone, Copy)]
pub struct Walk {
    n: u32,
    half: u32,
    mask: u32,
    keys: [u32; ROUNDS],
}

impl Walk {
    /// Over `n` positions, at least two, under `key`.
    pub fn new(n: u32, key: &[u8; KEY_SIZE]) -> Option<Walk> {
        if n < 2 {
            return None;
        }
        let mut bits = 1u32;
        while bits < 32 && (1u64 << bits) < u64::from(n) {
            bits += 1;
        }
        if bits % 2 == 1 {
            bits += 1;
        }
        if bits > 32 {
            return None;
        }
        let half = bits / 2;
        let mut keys = [0u32; ROUNDS];
        for (i, k) in keys.iter_mut().enumerate() {
            *k = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        Some(Walk {
            n,
            half,
            // `bits` is at most 32, so `half` is at most 16.
            mask: (1u32 << half) - 1,
            keys,
        })
    }

    /// Positions.
    pub const fn len(&self) -> u32 {
        self.n
    }

    pub const fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Round function: a 32-bit avalanche finaliser's three stages.
    #[inline]
    fn mix(&self, round: usize, x: u32) -> u32 {
        let mut v = x ^ self.keys[round];
        v = v.wrapping_mul(0x9E37_79B1);
        v ^= v >> 15;
        v = v.wrapping_mul(0x85EB_CA6B);
        v ^= v >> 13;
        v = v.wrapping_mul(0xC2B2_AE35);
        v ^= v >> 16;
        v & self.mask
    }

    #[inline]
    fn encrypt(&self, v: u32) -> u32 {
        let mut left = v >> self.half;
        let mut right = v & self.mask;
        for round in 0..ROUNDS {
            let next = right;
            right = left ^ self.mix(round, right);
            left = next;
        }
        (left << self.half) | right
    }

    /// Where position `pos` falls in the permuted order.
    #[inline]
    pub fn rank(&self, pos: u32) -> u32 {
        let mut v = pos;
        loop {
            v = self.encrypt(v);
            if v < self.n {
                return v;
            }
        }
    }
}
