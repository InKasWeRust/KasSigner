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

// Blake2b primitives used by Kaspa signing hashes.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::transaction::model::Hash256;

type Blake2b256 = Blake2b<U32>;

/// Blake2b-256 IV constants
const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Kaspa sighash domain-separation key.
/// ALL sighash hashing (sub-hashes and final digest) uses the SAME key.
/// This matches the Rusty Kaspa reference: every hasher in sighash.rs
/// is created via `TransactionSigningHash::new()`.
pub(super) const KEY_SIGNING_HASH: &[u8] = b"TransactionSigningHash";

// The `blake2` 0.10 crate doesn't cleanly expose keyed hashing through
// the high-level Digest API. Rather than fighting the API or adding a new
// dependency, we implement a minimal keyed Blake2b-256 from scratch.
// This is ~100 lines of pure Rust, no_std, no_alloc.

/// Blake2b-256 sigma permutation table (12 rounds x 16 entries)
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Blake2b G mixing function
#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Blake2b compress function
pub(super) fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..16].copy_from_slice(&IV);

    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }

    // Parse message block as 16 u64 LE words
    let mut m = [0u64; 16];
    for (word, bytes) in m.iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
    }

    // 12 rounds
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Keyed Blake2b-256 hasher (no_std, no_alloc, streaming).
///
/// Matches the Rusty Kaspa node's `blake2b_simd::Params::new().hash_length(32).key(k).to_state()`.
pub struct KaspaBlake2b {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total: u128,
}

impl Default for KaspaBlake2b {
    fn default() -> Self {
        Self::new()
    }
}

impl KaspaBlake2b {
    /// Create a new Kaspa transaction-signing Blake2b-256 hasher.
    ///
    /// This type is deliberately specialized to the one consensus domain key
    /// used by transaction sighashes. A generic keyed constructor only added
    /// invalid-key-length states that production never needs.
    pub fn new() -> Self {
        let mut h = IV;

        // XOR parameter block word 0 into h[0]:
        //   byte 0 = digest_length = 32 (0x20)
        //   byte 1 = key_length
        //   byte 2 = fanout = 1
        //   byte 3 = depth = 1
        let parameter_word = u64::from_le_bytes([
            0x20, 0x16, // 22-byte "TransactionSigningHash" domain key
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        h[0] ^= parameter_word;

        // Buffer the zero-padded key as the first 128-byte block.
        // Don't compress yet — it might be the only (last) block.
        let mut buf = [0u8; 128];
        buf[..KEY_SIGNING_HASH.len()].copy_from_slice(KEY_SIGNING_HASH);

        Self {
            h,
            buf,
            buf_len: 128, // key block fills the entire buffer
            total: 0,
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }

        while !data.is_empty() {
            let before_remaining = data.len();
            // A full block is final only when no more input follows. Flushing at
            // the beginning of the next non-empty iteration expresses that rule
            // without the redundant post-copy condition that admitted an
            // equivalent `==` -> `!=` mutant.
            if self.buf_len == 128 {
                self.flush_nonfinal_block();
                self.buf_len = 0;
            }
            let space = 128 - self.buf_len;
            let take = data.len().min(space);
            let end = self.buf_len + take;
            self.buf[self.buf_len..end].copy_from_slice(&data[..take]);
            self.buf_len = end;
            data = &data[take..];
            // Internal streaming state must always consume input. Keep this
            // independent of the full-buffer branch so a corrupted/mutated
            // branch fails closed instead of hanging the signer or mutation run.
            assert_ne!(
                data.len(),
                before_remaining,
                "Blake2b update made no forward progress"
            );
        }
    }

    fn flush_nonfinal_block(&mut self) {
        debug_assert_eq!(self.buf_len, 128);
        self.total = self.total.saturating_add(128);
        let block: [u8; 128] = self.buf;
        compress(&mut self.h, &block, self.total, false);
    }

    /// Finalize and return the 32-byte hash.
    pub fn finalize(mut self) -> Hash256 {
        self.total += self.buf_len as u128;

        // Zero-pad the remaining buffer
        for i in self.buf_len..128 {
            self.buf[i] = 0;
        }

        let block: [u8; 128] = self.buf;
        compress(&mut self.h, &block, self.total, true);

        // Extract first 32 bytes (4 u64 words) as the hash
        let mut hash = [0u8; 32];
        for i in 0..4 {
            let bytes = self.h[i].to_le_bytes();
            hash[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }
        hash
    }
}

// ═══════════════════════════════════════════════════════════════════
// Public API: hash helpers
// ═══════════════════════════════════════════════════════════════════

/// Hash Blake2b-256 of a buffer (unkeyed — for non-sighash uses)
pub fn blake2b_hash(data: &[u8]) -> Hash256 {
    let mut hasher = Blake2b256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
