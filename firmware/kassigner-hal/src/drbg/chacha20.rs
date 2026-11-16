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

//! `ChaCha20` block function: RFC 8439, 20 rounds, 32-byte key, 96-bit nonce.
//! Written out, about 60 lines, so the whole path from ADC to key material
//! can be read in this repository.

use zeroize::Zeroize;

/// Keystream block size in bytes.
pub const BLOCK: usize = 64;

/// `ChaCha20` state: 4 constants, 8 key words, counter, 3 nonce words.
pub struct ChaCha20 {
    state: [u32; 16],
}

// `inline(always)`: the inner loop, 80 calls a block, too costly on a 32-bit
// core to leave to the heuristic. The one-letter names are RFC 8439's.
#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

impl ChaCha20 {
    /// Key `key`, counter 0, nonce 0.
    ///
    /// A zero nonce is safe **only** because the DRBG makes one block per
    /// key, whose first 32 bytes are the next key (fast key erasure).
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let mut state = [0u32; 16];
        // "expand 32-byte k"
        state[0] = 0x6170_7865;
        state[1] = 0x3320_646e;
        state[2] = 0x7962_2d32;
        state[3] = 0x6b20_6574;
        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        Self { state }
    }

    /// Key, counter and nonce as RFC 8439's vectors give them, for the second
    /// vector in [`known_answer`]. The generator never uses it.
    fn with(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> Self {
        let mut c = Self::new(key);
        c.state[12] = counter;
        for i in 0..3 {
            c.state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        c
    }

    /// Produce the next 64-byte keystream block and advance the counter.
    pub fn block(&mut self, out: &mut [u8; BLOCK]) {
        let mut w = self.state;
        for _ in 0..10 {
            quarter_round(&mut w, 0, 4, 8, 12);
            quarter_round(&mut w, 1, 5, 9, 13);
            quarter_round(&mut w, 2, 6, 10, 14);
            quarter_round(&mut w, 3, 7, 11, 15);
            quarter_round(&mut w, 0, 5, 10, 15);
            quarter_round(&mut w, 1, 6, 11, 12);
            quarter_round(&mut w, 2, 7, 8, 13);
            quarter_round(&mut w, 3, 4, 9, 14);
        }
        for i in 0..16 {
            let v = w[i].wrapping_add(self.state[i]);
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        w.zeroize();
        // RFC 8439's 32-bit counter, word 12 only: no carry into the nonce's
        // word 13. The wrap is never reached: one block is made per key.
        self.state[12] = self.state[12].wrapping_add(1);
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

/// RFC 8439 A.1, test vector 1, the whole block: key, nonce and counter 0,
/// as [`ChaCha20::new`] builds.
const ZERO_BLOCK: [u8; BLOCK] = [
    0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
    0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
    0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
    0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
];

/// RFC 8439 §2.3.2: key 00..1f, nonce 00 00 00 09 00 00 00 4a 00 00 00 00,
/// counter 1. Every key word, the counter and two nonce words are not zero.
const RFC_KEY_NONCE: ([u8; 32], u32, [u8; 12]) = (
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ],
    1,
    [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0],
);
const RFC_BLOCK: [u8; BLOCK] = [
    0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
];

/// Known-answer test: RFC 8439's all-zero and §2.3.2 vectors, each block
/// whole, since the generator hands out a block's second 32 bytes. The
/// second sets key, counter and nonce; the first leaves them zero.
///
/// Worth more than any statistical check: run it in CI and on the device
/// before trusting the DRBG. It costs two blocks.
#[must_use = "a failed known-answer test means the cipher is broken; the result must be acted on"]
pub fn known_answer() -> bool {
    let mut block = [0u8; BLOCK];
    ChaCha20::new(&[0u8; 32]).block(&mut block);
    let zero = block == ZERO_BLOCK;
    let (key, counter, nonce) = RFC_KEY_NONCE;
    ChaCha20::with(&key, counter, &nonce).block(&mut block);
    let rfc = block == RFC_BLOCK;
    zero & rfc
}

#[cfg(test)]
mod tests {
    use super::{known_answer, ChaCha20, BLOCK, RFC_BLOCK, ZERO_BLOCK};

    /// Both RFC 8439 blocks, whole: a block's second half is what the
    /// generator hands out.
    #[test]
    fn the_known_answer_is_both_blocks_whole() {
        assert!(known_answer());
        let mut block = [0u8; BLOCK];
        ChaCha20::new(&[0u8; 32]).block(&mut block);
        assert_eq!(block, ZERO_BLOCK);
        let (key, counter, nonce) = super::RFC_KEY_NONCE;
        ChaCha20::with(&key, counter, &nonce).block(&mut block);
        assert_eq!(block, RFC_BLOCK);
    }

    /// The counter is RFC 8439's, 32 bits: at its last value it wraps to zero
    /// and leaves the nonce alone.
    #[test]
    fn the_counter_wraps_and_leaves_the_nonce_alone() {
        let mut c = ChaCha20::new(&[7u8; 32]);
        c.state[12] = u32::MAX;
        let mut block = [0u8; BLOCK];
        c.block(&mut block);
        assert_eq!(c.state[12], 0);
        assert_eq!(c.state[13..], [0, 0, 0]);
    }
}
