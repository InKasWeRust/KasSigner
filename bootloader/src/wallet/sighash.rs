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

// KasSigner — Kaspa SigHash Calculation
// 100% Rust, no-std, no-alloc
//
// Implements sighash computation per the Kaspa specification:
//   https://kaspa-mdbook.aspectron.com/transactions/sighashes.html
//
// Similar to BIP-143 (Bitcoin) but uses keyed Blake2b instead of SHA256.
// Each sub-hash uses a domain-separated Blake2b-256 with a unique domain key
// string matching the Rusty Kaspa consensus implementation.
//
// The sighash is the 32-byte message signed with Schnorr.
//
// Flow:
//   Transaction + input_index + sighash_type
//     -> serialize fields per spec
//     -> Blake2b(keyed)(serialization)
//     -> 32 bytes = sighash
//     -> schnorr_sign(private_key, sighash)


use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

/// Blake2b with 32-byte (256-bit) output — used only for non-sighash hashing
type Blake2b256 = Blake2b<U32>;
use super::transaction::*;

/// Format first 8 bytes of a hash as hex for debug (no alloc needed).
/// Only used by the verbose-boot sighash debug dump below.
#[cfg(feature = "verbose-boot")]
fn hex8(h: &[u8; 32]) -> [u8; 16] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 16];
    for i in 0..8 {
        out[i * 2] = HEX[(h[i] >> 4) as usize];
        out[i * 2 + 1] = HEX[(h[i] & 0xf) as usize];
    }
    out
}

// ═══════════════════════════════════════════════════════════════════
// Keyed Blake2b-256 for Kaspa consensus sighash
// ═══════════════════════════════════════════════════════════════════
//
// Kaspa uses KEYED Blake2b-256 for domain separation in sighash.
// Each sub-hash uses a different ASCII key string (up to 64 bytes).
// This matches Rusty Kaspa's
// `blake2b_simd::Params::new().hash_length(32).key(key).to_state()`.
//
// Keyed Blake2b:
//   - Parameter block byte 1 = key_length (nonzero)
//   - Key is zero-padded to 128 bytes and compressed as the first block
//   - h[0] = IV[0] ^ (digest_len | key_len<<8 | fanout<<16 | depth<<24)

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
const KEY_SIGNING_HASH: &[u8] = b"TransactionSigningHash";

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
fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
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
    for i in 0..16 {
        let off = i * 8;
        m[i] = u64::from_le_bytes([
            block[off], block[off+1], block[off+2], block[off+3],
            block[off+4], block[off+5], block[off+6], block[off+7],
        ]);
    }

    // 12 rounds
    for i in 0..12 {
        let s = &SIGMA[i];
        g(&mut v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        g(&mut v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        g(&mut v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        g(&mut v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        g(&mut v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
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

impl KaspaBlake2b {
    /// Create a new keyed Blake2b-256 hasher.
    /// The key can be 1..=64 bytes. Kaspa domain keys are ~20-22 ASCII bytes.
    pub fn new(key: &[u8]) -> Self {
        let key_len = key.len();

        let mut h = IV;

        // XOR parameter block word 0 into h[0]:
        //   byte 0 = digest_length = 32 (0x20)
        //   byte 1 = key_length
        //   byte 2 = fanout = 1
        //   byte 3 = depth = 1
        h[0] ^= 0x20 | ((key_len as u64) << 8) | (1 << 16) | (1 << 24);

        // Buffer the zero-padded key as the first 128-byte block.
        // Don't compress yet — it might be the only (last) block.
        let mut buf = [0u8; 128];
        buf[..key_len].copy_from_slice(key);

        Self {
            h,
            buf,
            buf_len: 128, // key block fills the entire buffer
            total: 0,
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        // If buffer is full (key block or prior data) and new data is arriving,
        // flush the buffer first — it's not the last block anymore.
        if self.buf_len == 128 {
            self.total += 128;
            let block: [u8; 128] = self.buf;
            compress(&mut self.h, &block, self.total, false);
            self.buf_len = 0;
        }

        let mut offset = 0;
        let len = data.len();

        // Fill partial buffer from data
        if self.buf_len > 0 {
            let space = 128 - self.buf_len;
            let take = if len < space { len } else { space };
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset += take;
        }

        // Process data: flush full buffer when more data follows
        while offset < len {
            if self.buf_len == 128 {
                self.total += 128;
                let block: [u8; 128] = self.buf;
                compress(&mut self.h, &block, self.total, false);
                self.buf_len = 0;
            }

            let space = 128 - self.buf_len;
            let remaining = len - offset;
            let take = if remaining < space { remaining } else { space };
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[offset..offset + take]);
            self.buf_len += take;
            offset += take;
        }
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

/// Hash Blake2b-256 with a Kaspa domain key (one-shot convenience)
fn blake2b_keyed(key: &[u8], data: &[u8]) -> Hash256 {
    let mut h = KaspaBlake2b::new(key);
    h.update(data);
    h.finalize()
}

/// Incremental keyed Blake2b-256 hasher for the final sighash digest.
struct SigHasher {
    hasher: KaspaBlake2b,
}

impl SigHasher {
    fn new() -> Self {
        Self {
            hasher: KaspaBlake2b::new(KEY_SIGNING_HASH),
        }
    }

    fn update_u8(&mut self, val: u8) {
        self.hasher.update(&[val]);
    }

    fn update_u16_le(&mut self, val: u16) {
        self.hasher.update(&val.to_le_bytes());
    }

    fn update_u32_le(&mut self, val: u32) {
        self.hasher.update(&val.to_le_bytes());
    }

    fn update_u64_le(&mut self, val: u64) {
        self.hasher.update(&val.to_le_bytes());
    }

    fn update_hash(&mut self, hash: &Hash256) {
        self.hasher.update(hash);
    }

    fn update_bytes(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> Hash256 {
        self.hasher.finalize()
    }
}

// ─── previousOutputsHash ──────────────────────────────────────────────

/// Blake2b("TransactionOutpoints", serialization of all outpoints)
/// If ANYONECANPAY -> 0x0000...0000
fn previous_outputs_hash(tx: &Transaction, sighash_type: SigHashType) -> Hash256 {
    if sighash_type.is_anyone_can_pay() {
        return [0u8; 32];
    }

    let mut hasher = KaspaBlake2b::new(KEY_SIGNING_HASH);
    for input in tx.inputs() {
        hasher.update(&input.previous_outpoint.transaction_id);
        hasher.update(&input.previous_outpoint.index.to_le_bytes());
    }
    hasher.finalize()
}

// ─── sequencesHash ────────────────────────────────────────────────────

/// Blake2b("TransactionSequences", serialization of all sequences)
/// If ANYONECANPAY, SINGLE or NONE -> 0x0000...0000
fn sequences_hash(tx: &Transaction, sighash_type: SigHashType) -> Hash256 {
    if sighash_type.is_anyone_can_pay()
        || sighash_type.is_sighash_single()
        || sighash_type.is_sighash_none()
    {
        return [0u8; 32];
    }

    let mut hasher = KaspaBlake2b::new(KEY_SIGNING_HASH);
    for input in tx.inputs() {
        hasher.update(&input.sequence.to_le_bytes());
    }
    hasher.finalize()
}

// ─── sigOpCountsHash ──────────────────────────────────────────────────

/// Blake2b("TransactionSigOpCounts", serialization of all sigOpCounts)
/// If ANYONECANPAY -> 0x0000...0000
fn sig_op_counts_hash(tx: &Transaction, sighash_type: SigHashType) -> Hash256 {
    if sighash_type.is_anyone_can_pay() {
        return [0u8; 32];
    }

    let mut hasher = KaspaBlake2b::new(KEY_SIGNING_HASH);
    for input in tx.inputs() {
        hasher.update(&[input.sig_op_count]);
    }
    hasher.finalize()
}

// ─── outputsHash ──────────────────────────────────────────────────────

/// Blake2b("TransactionOutputs", serialization of outputs)
///
/// - NONE or (SINGLE with input_index >= num_outputs) -> 0x0000...0000
/// - SINGLE with input_index < num_outputs -> hash of output[input_index]
/// - Others -> hash of all outputs
fn outputs_hash(
    tx: &Transaction,
    sighash_type: SigHashType,
    input_index: usize,
) -> Hash256 {
    if sighash_type.is_sighash_none() {
        return [0u8; 32];
    }

    if sighash_type.is_sighash_single() {
        if input_index >= tx.num_outputs {
            return [0u8; 32];
        }
        // Only the output with the same index
        let output = &tx.outputs[input_index];
        let mut hasher = KaspaBlake2b::new(KEY_SIGNING_HASH);
        hash_output(&mut hasher, output, tx.version);
        return hasher.finalize();
    }

    // SigHashAll: hash of all outputs
    let mut hasher = KaspaBlake2b::new(KEY_SIGNING_HASH);
    for output in tx.outputs() {
        hash_output(&mut hasher, output, tx.version);
    }
    hasher.finalize()
}

/// Serialize an output for hashing.
/// Matches Rusty Kaspa's `hash_output` which calls `hash_script_public_key`,
/// which uses `write_var_bytes` (u64 LE length prefix + raw bytes).
/// For tx version >= 1, also includes covenant binding data.
fn hash_output(hasher: &mut KaspaBlake2b, output: &TransactionOutput, tx_version: u16) {
    hasher.update(&output.value.to_le_bytes());
    // hash_script_public_key: version(u16 LE) + write_var_bytes(script)
    hasher.update(&output.script_public_key.version.to_le_bytes());
    hasher.update(&(output.script_public_key.script_len as u64).to_le_bytes());
    hasher.update(output.script_public_key.script_bytes());

    // Covenant binding (tx version >= 1)
    if tx_version >= 1 {
        if output.has_covenant {
            hasher.update(&[1u8]); // write_bool(true)
            hasher.update(&output.covenant_auth_input.to_le_bytes()); // write_u16
            hasher.update(&output.covenant_id); // update(Hash)
        } else {
            hasher.update(&[0u8]); // write_bool(false)
        }
    }
}

// ─── payloadHash ──────────────────────────────────────────────────────

/// If native with empty payload -> 0x0000...0000
/// Otherwise -> keyed Blake2b(write_var_bytes(payload))
fn payload_hash(tx: &Transaction) -> Hash256 {
    if tx.is_native() && tx.payload_len == 0 {
        return [0u8; 32];
    }
    let mut hasher = KaspaBlake2b::new(KEY_SIGNING_HASH);
    // write_var_bytes: length prefix (u64 LE) + raw bytes
    hasher.update(&(tx.payload_len as u64).to_le_bytes());
    hasher.update(&tx.payload[..tx.payload_len]);
    hasher.finalize()
}

// ═══════════════════════════════════════════════════════════════════════
// Public API: calculate_sighash
// ═══════════════════════════════════════════════════════════════════════

/// Compute the sighash for a specific transaction input.
///
/// This is the 32-byte message signed with Schnorr.
///
/// `tx`: the complete transaction
/// `input_index`: index of the input being signed
/// `sighash_type`: sighash type (normally SigHashAll)
///
/// Returns 32 bytes = keyed Blake2b of the sighash digest.
/// Input-independent sub-hashes of the sighash, computed ONCE per
/// (transaction, sighash_type) and reused across every input. Under
/// SIGHASH_ALL (the standard spend) prev-outputs, sequences, sig-op-counts,
/// outputs and payload are identical for all inputs — the per-input
/// recomputation walked the whole transaction N times (N inputs = O(N^2)
/// hashing) and nested an extra hasher frame inside the deep signing chain.
pub struct SighashReuse {
    prev_outputs: Hash256,
    sequences: Hash256,
    sig_op_counts: Hash256,
    outputs_all: Hash256,
    payload: Hash256,
    single: bool,
}

impl SighashReuse {
    pub fn compute(tx: &Transaction, sighash_type: SigHashType) -> Self {
        let single = sighash_type.is_sighash_single();
        SighashReuse {
            prev_outputs: previous_outputs_hash(tx, sighash_type),
            sequences: sequences_hash(tx, sighash_type),
            sig_op_counts: if tx.version < 1 {
                sig_op_counts_hash(tx, sighash_type)
            } else {
                [0u8; 32]
            },
            // SINGLE's outputs hash depends on the input index; computed
            // per input in that (rare) case, cached for everything else.
            outputs_all: if single { [0u8; 32] } else { outputs_hash(tx, sighash_type, 0) },
            payload: payload_hash(tx),
            single,
        }
    }
}

pub fn calculate_sighash(
    tx: &Transaction,
    input_index: usize,
    sighash_type: SigHashType,
) -> Hash256 {
    // Uncached path: identical bytes by construction — the cache is
    // computed from the same functions the old body called per input.
    let reuse = SighashReuse::compute(tx, sighash_type);
    calculate_sighash_cached(tx, input_index, sighash_type, &reuse)
}

pub fn calculate_sighash_cached(
    tx: &Transaction,
    input_index: usize,
    sighash_type: SigHashType,
    reuse: &SighashReuse,
) -> Hash256 {
    let input = &tx.inputs[input_index];

    let prev_outputs = reuse.prev_outputs;
    let sequences = reuse.sequences;
    let outputs = if reuse.single {
        outputs_hash(tx, sighash_type, input_index)
    } else {
        reuse.outputs_all
    };
    let payload = reuse.payload;

    // Build the final digest with "TransactionSigningHash" domain key
    let mut h = SigHasher::new();

    // 1. tx.Version (2 bytes LE)
    h.update_u16_le(tx.version);

    // 2. previousOutputsHash (32 bytes)
    h.update_hash(&prev_outputs);

    // 3. sequencesHash (32 bytes)
    h.update_hash(&sequences);

    // 4. sigOpCountsHash (32 bytes) — only for version 0
    if tx.version < 1 {
        h.update_hash(&reuse.sig_op_counts);
    }

    // 5. txIn.PreviousOutpoint.TransactionID (32 bytes)
    h.update_hash(&input.previous_outpoint.transaction_id);

    // 6. txIn.PreviousOutpoint.Index (4 bytes LE)
    h.update_u32_le(input.previous_outpoint.index);

    // 7. txIn.PreviousOutput.ScriptPubKeyVersion (2 bytes LE)
    h.update_u16_le(input.utxo_entry.script_public_key.version);

    // 8. txIn.PreviousOutput.ScriptPubKey.length (8 bytes LE)
    h.update_u64_le(input.utxo_entry.script_public_key.script_len as u64);

    // 9. txIn.PreviousOutput.ScriptPubKey (variable)
    h.update_bytes(input.utxo_entry.script_public_key.script_bytes());

    // 10. txIn.PreviousOutput.Value (8 bytes LE)
    h.update_u64_le(input.utxo_entry.amount);

    // 11. txIn.Sequence (8 bytes LE)
    h.update_u64_le(input.sequence);

    // 12. txIn.SigOpCount (1 byte) — only for version 0
    if tx.version < 1 {
        h.update_u8(input.sig_op_count);
    }

    // 13. outputsHash (32 bytes)
    h.update_hash(&outputs);

    // 14. tx.Locktime (8 bytes LE)
    h.update_u64_le(tx.locktime);

    // 15. tx.SubnetworkID (20 bytes)
    h.update_bytes(&tx.subnetwork_id);

    // 16. tx.Gas (8 bytes LE)
    h.update_u64_le(tx.gas);

    // 17. payloadHash (32 bytes)
    h.update_hash(&payload);

    // 18. SigHash type (1 byte)
    h.update_u8(sighash_type.to_byte());

    let result = h.finalize();

    // Debug: dump intermediate hashes for sighash comparison.
    // Gated behind verbose-boot: this ran on EVERY signing in any
    // non-silent build, revealing tx contents (covenant ids, output
    // structure, final sighash) to a USB host before broadcast.
    #[cfg(feature = "verbose-boot")]
    {
        crate::log!("[SIGHASH-DBG] tx_version={} input_idx={}", tx.version, input_index);
        crate::log!("[SIGHASH-DBG] prev_outputs={}", core::str::from_utf8(&hex8(&prev_outputs)).unwrap_or("?"));
        crate::log!("[SIGHASH-DBG] sequences={}", core::str::from_utf8(&hex8(&sequences)).unwrap_or("?"));
        crate::log!("[SIGHASH-DBG] outputs={}", core::str::from_utf8(&hex8(&outputs)).unwrap_or("?"));
        crate::log!("[SIGHASH-DBG] payload={}", core::str::from_utf8(&hex8(&payload)).unwrap_or("?"));
        if tx.num_outputs > 0 {
            crate::log!("[SIGHASH-DBG] out[0] has_cov={} auth={}", tx.outputs[0].has_covenant, tx.outputs[0].covenant_auth_input);
            crate::log!("[SIGHASH-DBG] out[0] cov_id={}", core::str::from_utf8(&hex8(&tx.outputs[0].covenant_id)).unwrap_or("?"));
        }
        if tx.num_outputs > 1 {
            crate::log!("[SIGHASH-DBG] out[1] has_cov={}", tx.outputs[1].has_covenant);
        }
        crate::log!("[SIGHASH-DBG] FINAL={}", core::str::from_utf8(&hex8(&result)).unwrap_or("?"));
    }

    result
}

// ═══════════════════════════════════════════════════════════════════════
// Full flow: sighash -> Schnorr sign
// ═══════════════════════════════════════════════════════════════════════

/// Sign a Kaspa transaction input.
///
/// Compute the sighash and sign with Schnorr.
///
/// `tx`: complete transaction
/// `input_index`: input to sign
/// `private_key`: 32-byte private key (from BIP32 derivation)
/// `sighash_type`: type (normally SigHashAll)
///
/// Returns the 64-byte Schnorr signature.
pub fn sign_input(
    tx: &Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
) -> Result<super::schnorr::SchnorrSignature, super::schnorr::SchnorrError> {
    let sighash = calculate_sighash(tx, input_index, sighash_type);
    super::schnorr::schnorr_sign(private_key, &sighash)
}

/// sign_input with a precomputed SighashReuse — for multi-input passes.
pub fn sign_input_cached(
    tx: &Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    reuse: &SighashReuse,
) -> Result<super::schnorr::SchnorrSignature, super::schnorr::SchnorrError> {
    let sighash = calculate_sighash_cached(tx, input_index, sighash_type, reuse);
    super::schnorr::schnorr_sign(private_key, &sighash)
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: Keyed Blake2b produces different output than unkeyed.
pub fn test_keyed_differs() -> bool {
    let data = b"test data for keyed hash check";

    // Unkeyed
    let plain = blake2b_hash(data);

    // Keyed with signing hash domain key
    let mut h = KaspaBlake2b::new(KEY_SIGNING_HASH);
    h.update(data);
    let keyed = h.finalize();

    // They MUST differ — if they're the same, keying is not working
    plain != keyed
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: basic sighash computation for a single-input transaction.
pub fn test_sighash_basic() -> bool {
    // Create a simple transaction: 1 input, 1 output
    // Heap, not stack. `Transaction` is 78,952 bytes and the frame that holds
    // it is reserved on entry, so a stack local here claimed the space for the
    // whole call whether or not it was still needed. Measured 2026-08-14 on
    // M5Stack: `verbose-boot` tripped the ProCpu stack guard inside
    // `self_test::test_sram`'s 2 KB buffer at test 1 of 5, SP 81,776 bytes
    // below the floor, 186,272 bytes of depth against 105,008 usable. These
    // tests never reached their own bodies in any build. See N-15.
    let mut tx = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 1;

    // Input: UTXO with 5 KAS (500_000_000 sompi)
    tx.inputs[0].previous_outpoint.transaction_id = [0xAA; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 500_000_000;
    // Script P2PK: OP_DATA_32 <pubkey_x> OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20; // OP_DATA_32
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xBB; 32]);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC; // OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Output: send 4.99 KAS
    tx.outputs[0].value = 499_000_000;
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xCC; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    // Compute sighash
    let sighash = calculate_sighash(&tx, 0, SigHashType::All);

    // The sighash must not be all zeros
    let all_zero = sighash.iter().all(|&b| b == 0);
    if all_zero {
        return false;
    }

    // Must be deterministic
    let sighash2 = calculate_sighash(&tx, 0, SigHashType::All);
    sighash == sighash2
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: different inputs produce different sighashes.
pub fn test_sighash_different_inputs() -> bool {
    // Transaction with 2 inputs — each must have a different sighash
    // Heap, not stack: see the note on the first boxed transaction in this file. N-15.
    let mut tx = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
    tx.version = 0;
    tx.num_inputs = 2;
    tx.num_outputs = 1;

    // Input 0
    tx.inputs[0].previous_outpoint.transaction_id = [0x11; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 100_000_000;
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xAA; 32]);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Input 1
    tx.inputs[1].previous_outpoint.transaction_id = [0x22; 32];
    tx.inputs[1].previous_outpoint.index = 1;
    tx.inputs[1].sequence = u64::MAX;
    tx.inputs[1].sig_op_count = 1;
    tx.inputs[1].utxo_entry.amount = 200_000_000;
    tx.inputs[1].utxo_entry.script_public_key.version = 0;
    tx.inputs[1].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[1].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xBB; 32]);
    tx.inputs[1].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[1].utxo_entry.script_public_key.script_len = 34;

    // Output
    tx.outputs[0].value = 290_000_000;
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xCC; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    let sighash0 = calculate_sighash(&tx, 0, SigHashType::All);
    let sighash1 = calculate_sighash(&tx, 1, SigHashType::All);

    // Must differ (each input has different outpoint, amount, script)
    sighash0 != sighash1
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: complete transaction signing pipeline.
pub fn test_sign_transaction_complete() -> bool {
    use super::bip39;
    use super::bip32;
    use super::schnorr;

    // 1. Generate wallet
    let entropy = [0u8; 16];
    let mnemonic = bip39::mnemonic_from_entropy_12(&entropy);
    let seed = bip39::seed_from_mnemonic_12(&mnemonic, "");
    let key = match bip32::derive_path(&seed.bytes, bip32::KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let pubkey_x = match key.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // 2. Create transaction: 1 input (our UTXO), 1 output
    // Heap, not stack: see the note on the first boxed transaction in this file. N-15.
    let mut tx = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 1;

    tx.inputs[0].previous_outpoint.transaction_id = [0x42; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = 0;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 1_000_000_000; // 10 KAS

    // Script of the UTXO = P2PK with our pubkey
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20; // OP_DATA_32
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&pubkey_x);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC; // OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Output: send to another destination
    tx.outputs[0].value = 999_000_000; // 9.99 KAS (fee = 0.01 KAS)
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xFF; 32]); // destination
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    // 3. Compute sighash
    let sighash = calculate_sighash(&tx, 0, SigHashType::All);

    // 4. Sign with Schnorr
    let sig = match schnorr::schnorr_sign(key.private_key_bytes(), &sighash) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 5. Verify signature
    schnorr::schnorr_verify(&pubkey_x, &sighash, &sig).is_ok()
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: KAS amount formatting.
pub fn test_format_kas() -> bool {
    let mut buf = [0u8; 32];

    // 1.0 KAS = 100_000_000 sompi
    let len = Transaction::format_kas(100_000_000, &mut buf);
    if &buf[..len] != b"1.00" {
        return false;
    }

    // 10.5 KAS
    let len = Transaction::format_kas(1_050_000_000, &mut buf);
    if &buf[..len] != b"10.5" {
        return false;
    }

    // 0.001 KAS
    let len = Transaction::format_kas(100_000, &mut buf);
    if &buf[..len] != b"0.001" {
        return false;
    }

    true
}


// ═══════════════════════════════════════════════════════════════════
// Consensus known-answer vectors, ported from rusty-kaspa 2.0.1
// ═══════════════════════════════════════════════════════════════════
//
// Source: `consensus/core/src/hashing/sighash.rs`, `mod tests`,
// `fn test_signature_hash`. The transaction, its UTXO entries, the
// modifications and the expected digests are reproduced from upstream. Only
// the representation differs: our `Transaction` is one fixed-size struct
// carrying its own UTXO entries, where upstream pairs a `Transaction` with a
// separate entry vector in `PopulatedTransaction`.
//
// WHY. Before this, `test_sighash_basic` checked that the digest was not all
// zeros. That catches a hasher that returns nothing, and nothing else. A
// sighash that is internally consistent but disagrees with consensus by one
// field, one byte order or one length prefix passes it every time. These are
// external truth: the node computed them, and if our keyed Blake2b, our field
// order or our sub-hash gating diverges, one of these fails and names itself.
//
// WHAT IS COVERED. All six sighash types, both transaction versions, native
// and subnetwork. Cases come in two kinds and the second kind is the one with
// teeth: digests that MUST change when a field is modified, and digests that
// MUST NOT. A hasher that simply mixed every field in would pass every case of
// the first kind and fail every case of the second.
//
// Production signing is `SigHashType::All` at every call site, so the other
// five types are unreachable on this device today. They are tested anyway.
// `SigHashType::from_byte` accepts all six when parsing a SignedResponse, and
// an unreachable branch that is wrong is a trap for whoever makes it reachable.

/// `880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3`
#[cfg(any(test, not(feature = "skip-tests")))]
const VEC_PREV_TX_ID: [u8; 32] = [
    0x88,0x0e,0xb9,0x81,0x9a,0x31,0x82,0x1d,0x9d,0x23,0x99,0xe2,0xf3,0x5e,0x24,0x33,
    0xb7,0x26,0x37,0xe3,0x93,0xd7,0x1e,0xcc,0x9b,0x8d,0x02,0x50,0xf4,0x91,0x53,0xc3,
];

/// `208325613d2eeaf7176ac6c670b13c0043156c427438ed72d74b7800862ad884e8ac`
#[cfg(any(test, not(feature = "skip-tests")))]
const VEC_SPK1: [u8; 34] = [
    0x20,0x83,0x25,0x61,0x3d,0x2e,0xea,0xf7,0x17,0x6a,0xc6,0xc6,0x70,0xb1,0x3c,0x00,
    0x43,0x15,0x6c,0x42,0x74,0x38,0xed,0x72,0xd7,0x4b,0x78,0x00,0x86,0x2a,0xd8,0x84,
    0xe8,0xac,
];

/// `20fcef4c106cf11135bbd70f02a726a92162d2fb8b22f0469126f800862ad884e8ac`
#[cfg(any(test, not(feature = "skip-tests")))]
const VEC_SPK2: [u8; 34] = [
    0x20,0xfc,0xef,0x4c,0x10,0x6c,0xf1,0x11,0x35,0xbb,0xd7,0x0f,0x02,0xa7,0x26,0xa9,
    0x21,0x62,0xd2,0xfb,0x8b,0x22,0xf0,0x46,0x91,0x26,0xf8,0x00,0x86,0x2a,0xd8,0x84,
    0xe8,0xac,
];

/// Upstream's modified payload, `vec![6, 6, 6, 4, 2, 0, 1, 3, 3, 7]`.
#[cfg(any(test, not(feature = "skip-tests")))]
const VEC_MOD_PAYLOAD: [u8; 10] = [6, 6, 6, 4, 2, 0, 1, 3, 3, 7];

/// Set a script public key from a slice, version 0.
#[cfg(any(test, not(feature = "skip-tests")))]
fn vec_set_spk(spk: &mut ScriptPublicKey, bytes: &[u8]) {
    spk.version = 0;
    spk.script[..bytes.len()].copy_from_slice(bytes);
    spk.script_len = bytes.len();
}

/// Build the reference transaction.
///
/// Three inputs spending the same previous transaction at indices 0, 1 and 2,
/// with sequences 0, 1 and 2 and amounts 100, 200 and 300. Input 0 spends
/// SPK1, inputs 1 and 2 spend SPK2. Two outputs of 300, paying SPK2 then SPK1.
///
/// `sig_op_count` is 0 on every input, matching upstream's
/// `ComputeCommit::SigopCount(0)`. That is NOT our own default of 1, and
/// getting it wrong changes every version-0 digest here.
///
/// `version` selects the consensus branch: 0 hashes the sig-op-count material,
/// 1 skips it and commits covenant presence per output instead. Upstream's
/// version-1 transaction carries `ComputeCommit::ComputeBudget` values, which
/// do not enter the digest at version 1 at all, which is why its four v1
/// vectors share one expected hash. We have no compute-commit field and at
/// version 1 we do not need one.
#[cfg(any(test, not(feature = "skip-tests")))]
fn vec_build_native(version: u16) -> Option<alloc::boxed::Box<Transaction>> {
    let mut tx = Transaction::new_boxed()?;
    tx.version = version;
    tx.num_inputs = 3;
    tx.num_outputs = 2;
    tx.locktime = 1_615_462_089_000;
    tx.gas = 0;
    tx.payload_len = 0;

    let amounts = [100u64, 200u64, 300u64];
    for i in 0..3usize {
        let inp = &mut tx.inputs[i];
        inp.previous_outpoint.transaction_id = VEC_PREV_TX_ID;
        inp.previous_outpoint.index = i as u32;
        inp.sequence = i as u64;
        inp.sig_op_count = 0;
        inp.utxo_entry.amount = amounts[i];
        let spk: &[u8] = if i == 0 { &VEC_SPK1 } else { &VEC_SPK2 };
        vec_set_spk(&mut inp.utxo_entry.script_public_key, spk);
    }

    tx.outputs[0].value = 300;
    vec_set_spk(&mut tx.outputs[0].script_public_key, &VEC_SPK2);
    tx.outputs[1].value = 300;
    vec_set_spk(&mut tx.outputs[1].script_public_key, &VEC_SPK1);

    Some(tx)
}

/// The same transaction moved off the native subnetwork, with gas and payload.
#[cfg(any(test, not(feature = "skip-tests")))]
fn vec_build_subnetwork() -> Option<alloc::boxed::Box<Transaction>> {
    let mut tx = vec_build_native(0)?;
    tx.subnetwork_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    tx.gas = 250;
    tx.payload[..11].copy_from_slice(&[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
    tx.payload_len = 11;
    Some(tx)
}

// ─── Named modifications, for the cases a closure cannot express inline ───

/// No modification: hash the transaction exactly as built.
#[cfg(any(test, not(feature = "skip-tests")))]
fn nop(_: &mut Transaction) {}

#[cfg(any(test, not(feature = "skip-tests")))]
fn vec_set_payload(tx: &mut Transaction) {
    tx.payload[..VEC_MOD_PAYLOAD.len()].copy_from_slice(&VEC_MOD_PAYLOAD);
    tx.payload_len = VEC_MOD_PAYLOAD.len();
}

/// Append `[1, 2, 3]` to the script being spent by input 0.
#[cfg(any(test, not(feature = "skip-tests")))]
fn vec_extend_spk0(tx: &mut Transaction) {
    let spk = &mut tx.inputs[0].utxo_entry.script_public_key;
    let n = spk.script_len;
    spk.script[n..n + 3].copy_from_slice(&[1, 2, 3]);
    spk.script_len = n + 3;
}

#[cfg(any(test, not(feature = "skip-tests")))]
fn vec_set_subnetwork_id(tx: &mut Transaction) {
    tx.subnetwork_id = [6, 6, 6, 4, 2, 0, 1, 3, 3, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
}

/// Compare one computed digest against its expected value, naming it on failure.
#[cfg(any(test, not(feature = "skip-tests")))]
fn vec_check(
    name: &str,
    tx: &Transaction,
    input_index: usize,
    sighash_type: SigHashType,
    expected: &[u8; 32],
) -> bool {
    let got = calculate_sighash(tx, input_index, sighash_type);
    if &got == expected {
        return true;
    }
    crate::log!(
        "   [sighash-vec] FAIL {}: got {:02x}{:02x}{:02x}{:02x} want {:02x}{:02x}{:02x}{:02x}",
        name, got[0], got[1], got[2], got[3],
        expected[0], expected[1], expected[2], expected[3]
    );
    false
}

/// Consensus vectors from rusty-kaspa 2.0.1. Returns (passed, total).
#[cfg(any(test, not(feature = "skip-tests")))]
pub fn run_sighash_vectors() -> (u32, u32) {
    let mut passed = 0u32;
    let mut total = 0u32;

    // Every case rebuilds its own transaction rather than mutating and
    // restoring a shared one. A missed restore would make a later case pass or
    // fail for a reason unrelated to what it tests, and these are the tests
    // that are supposed to be trustworthy. Each box is freed at the end of its
    // case, so peak heap is one transaction, not twenty-seven.
    macro_rules! case {
        ($name:expr, $build:expr, $idx:expr, $ty:expr, $exp:expr, $mutate:expr) => {{
            total += 1;
            match $build {
                Some(mut tx) => {
                    const EXPECTED: [u8; 32] = $exp;
                    #[allow(clippy::redundant_closure_call)]
                    ($mutate)(&mut *tx);
                    if vec_check($name, &tx, $idx, $ty, &EXPECTED) {
                        passed += 1;
                    }
                }
                None => crate::log!("   [sighash-vec] SKIP {}: allocation failed", $name),
            }
        }};
    }

    // ── SIG_HASH_ALL, version 0 ─────────────────────────────────
    case!("native-all-0", vec_build_native(0), 0, SigHashType::All,
        [
          0x03,0xb7,0xac,0x69,0x27,0xb2,0xb6,0x71,0x00,0x73,0x4c,0x3c,0xc3,0x13,0xff,0x8c,
          0x2e,0x8b,0x3c,0xe3,0xe7,0x46,0xd4,0x6d,0xd6,0x60,0xb7,0x06,0xa9,0x16,0xb1,0xf5,
        ],
        nop);

    // Another input's outpoint MUST change the digest: under ALL every
    // input's previous outpoint is committed.
    case!("native-all-0-modify-input-1", vec_build_native(0), 0, SigHashType::All,
        [
          0xa9,0xf5,0x63,0xd8,0x6c,0x0e,0xf1,0x9e,0xc2,0xe4,0xf4,0x83,0x90,0x1d,0x20,0x2e,
          0x90,0x15,0x05,0x80,0xb6,0x12,0x3c,0x3d,0x49,0x2e,0x26,0xe7,0x96,0x5f,0x48,0x8c,
        ],
        |tx: &mut Transaction| tx.inputs[1].previous_outpoint.index = 2);

    case!("native-all-0-modify-output-1", vec_build_native(0), 0, SigHashType::All,
        [
          0xaa,0xd2,0xb6,0x1b,0xd2,0x40,0x5d,0xfc,0xf7,0x29,0x4f,0xc2,0xbe,0x85,0xf3,0x25,
          0x69,0x4f,0x02,0xdd,0xa2,0x2d,0x0a,0xf3,0x03,0x81,0xcb,0x50,0xd8,0x29,0x5e,0x0a,
        ],
        |tx: &mut Transaction| tx.outputs[1].value = 100);

    case!("native-all-0-modify-sequence-1", vec_build_native(0), 0, SigHashType::All,
        [
          0x08,0x18,0xbd,0x0a,0x37,0x03,0x63,0x8d,0x4f,0x01,0x01,0x4c,0x92,0xcf,0x86,0x6a,
          0x89,0x03,0xca,0xb3,0x6d,0xf2,0xfa,0x25,0x06,0xdc,0x0d,0x06,0xb9,0x42,0x95,0xe8,
        ],
        |tx: &mut Transaction| tx.inputs[1].sequence = 12345);

    // A native transaction with an empty payload hashes the zero hash;
    // giving it a payload must leave that branch.
    case!("native-all-0-modify-payload", vec_build_native(0), 0, SigHashType::All,
        [
          0x72,0xea,0x6c,0x28,0x71,0xe0,0xf4,0x44,0x99,0xf1,0xc2,0xb5,0x56,0xf2,0x65,0xd9,
          0x42,0x4b,0xfe,0xa6,0x7c,0xca,0x9c,0xb3,0x43,0xb4,0xb0,0x40,0xea,0xd6,0x55,0x25,
        ],
        vec_set_payload);

    // ── Version 1: the sig-op-count material leaves the digest ──
    // Version 1 is the covenant branch, live on mainnet since June 2026.
    case!("native-v1-all-0", vec_build_native(1), 0, SigHashType::All,
        [
          0x5b,0x26,0x57,0x52,0x4b,0xe6,0x72,0xe0,0x19,0x89,0x76,0x46,0xb5,0x6d,0xa3,0xd1,
          0x92,0xb4,0x53,0xd7,0x8a,0xe5,0xe6,0xe5,0xc0,0x7f,0x02,0x9a,0x69,0xf5,0xf0,0x75,
        ],
        nop);

    // Same digest: at version 1 sig-op counts are not hashed at all, so
    // changing one must be invisible. Catches a version gate that still
    // hashes them.
    case!("native-v1-all-0-modify-sigopcount-1", vec_build_native(1), 0, SigHashType::All,
        [
          0x5b,0x26,0x57,0x52,0x4b,0xe6,0x72,0xe0,0x19,0x89,0x76,0x46,0xb5,0x6d,0xa3,0xd1,
          0x92,0xb4,0x53,0xd7,0x8a,0xe5,0xe6,0xe5,0xc0,0x7f,0x02,0x9a,0x69,0xf5,0xf0,0x75,
        ],
        |tx: &mut Transaction| tx.inputs[1].sig_op_count = 123);

    // ── ALL | ANYONECANPAY ──────────────────────────────────────
    case!("native-all-acp-0", vec_build_native(0), 0, SigHashType::AllAnyOneCanPay,
        [
          0x24,0x82,0x1e,0x46,0x6e,0x53,0xff,0x8e,0x5f,0xa9,0x32,0x57,0xcb,0x17,0xbb,0x06,
          0x13,0x1a,0x48,0xbe,0x4e,0xf2,0x82,0xe8,0x7f,0x59,0xd2,0xbd,0xc9,0xaf,0xeb,0xc2,
        ],
        nop);

    // Our OWN input still counts under ANYONECANPAY.
    case!("native-all-acp-0-modify-input-0", vec_build_native(0), 0, SigHashType::AllAnyOneCanPay,
        [
          0xd0,0x9c,0xb6,0x39,0xf3,0x35,0xee,0x69,0xac,0x71,0xf2,0xad,0x43,0xfd,0x9e,0x59,
          0x05,0x2d,0x38,0xa7,0xd0,0x63,0x8d,0xe4,0xcf,0x98,0x93,0x46,0x58,0x8a,0x7c,0x38,
        ],
        |tx: &mut Transaction| tx.inputs[0].previous_outpoint.index = 2);

    // Other inputs must NOT. This is the point of ANYONECANPAY and the
    // case a hasher that commits to everything gets wrong.
    case!("native-all-acp-0-modify-input-1", vec_build_native(0), 0, SigHashType::AllAnyOneCanPay,
        [
          0x24,0x82,0x1e,0x46,0x6e,0x53,0xff,0x8e,0x5f,0xa9,0x32,0x57,0xcb,0x17,0xbb,0x06,
          0x13,0x1a,0x48,0xbe,0x4e,0xf2,0x82,0xe8,0x7f,0x59,0xd2,0xbd,0xc9,0xaf,0xeb,0xc2,
        ],
        |tx: &mut Transaction| tx.inputs[1].previous_outpoint.index = 2);

    case!("native-all-acp-0-modify-sequence-1", vec_build_native(0), 0, SigHashType::AllAnyOneCanPay,
        [
          0x24,0x82,0x1e,0x46,0x6e,0x53,0xff,0x8e,0x5f,0xa9,0x32,0x57,0xcb,0x17,0xbb,0x06,
          0x13,0x1a,0x48,0xbe,0x4e,0xf2,0x82,0xe8,0x7f,0x59,0xd2,0xbd,0xc9,0xaf,0xeb,0xc2,
        ],
        |tx: &mut Transaction| tx.inputs[1].sequence = 12345);

    // ── NONE ────────────────────────────────────────────────────
    case!("native-none-0", vec_build_native(0), 0, SigHashType::None,
        [
          0x38,0xce,0x4b,0xc9,0x3c,0xf9,0x11,0x6d,0x2e,0x37,0x7b,0x33,0xff,0x84,0x49,0xc6,
          0x65,0xb7,0xb5,0xe2,0xf2,0xe6,0x53,0x03,0xc5,0x43,0xb9,0xaf,0xda,0xa4,0xbb,0xba,
        ],
        nop);

    // Outputs are not committed under NONE.
    case!("native-none-0-modify-output-1", vec_build_native(0), 0, SigHashType::None,
        [
          0x38,0xce,0x4b,0xc9,0x3c,0xf9,0x11,0x6d,0x2e,0x37,0x7b,0x33,0xff,0x84,0x49,0xc6,
          0x65,0xb7,0xb5,0xe2,0xf2,0xe6,0x53,0x03,0xc5,0x43,0xb9,0xaf,0xda,0xa4,0xbb,0xba,
        ],
        |tx: &mut Transaction| tx.outputs[1].value = 100);

    // Our own sequence is still committed, through the per-input field
    // rather than the sequences sub-hash.
    case!("native-none-0-modify-sequence-0", vec_build_native(0), 0, SigHashType::None,
        [
          0xd9,0xef,0xdd,0x5e,0xda,0xa0,0xd3,0xfd,0x01,0x33,0xee,0x3a,0xb7,0x31,0xd8,0xc2,
          0x0e,0x0a,0x1b,0x9f,0x3c,0x05,0x81,0x60,0x1a,0xe2,0x07,0x5d,0xb1,0x10,0x92,0x68,
        ],
        |tx: &mut Transaction| tx.inputs[0].sequence = 12345);

    // Other sequences are not: the sequences sub-hash is zeroed.
    case!("native-none-0-modify-sequence-1", vec_build_native(0), 0, SigHashType::None,
        [
          0x38,0xce,0x4b,0xc9,0x3c,0xf9,0x11,0x6d,0x2e,0x37,0x7b,0x33,0xff,0x84,0x49,0xc6,
          0x65,0xb7,0xb5,0xe2,0xf2,0xe6,0x53,0x03,0xc5,0x43,0xb9,0xaf,0xda,0xa4,0xbb,0xba,
        ],
        |tx: &mut Transaction| tx.inputs[1].sequence = 12345);

    // ── NONE | ANYONECANPAY ─────────────────────────────────────
    case!("native-none-acp-0", vec_build_native(0), 0, SigHashType::NoneAnyOneCanPay,
        [
          0x06,0xaa,0x9f,0x42,0x39,0x49,0x1e,0x07,0xbb,0x2b,0x6b,0xda,0x6b,0x06,0x57,0xb9,
          0x21,0xae,0xae,0x51,0xe1,0x93,0xd2,0xc5,0xbf,0x9e,0x81,0x43,0x9c,0xfe,0xaf,0xa0,
        ],
        nop);

    // The amount being spent is committed per input, which is what stops
    // a signature being replayed against a different UTXO.
    case!("native-none-acp-0-modify-amount-spent", vec_build_native(0), 0, SigHashType::NoneAnyOneCanPay,
        [
          0xf0,0x7f,0x45,0xf3,0x63,0x4d,0x3e,0xa8,0xc0,0xf2,0xcb,0x67,0x6f,0x56,0xe2,0x09,
          0x93,0xed,0xf9,0xbe,0x07,0xa8,0x3b,0xf0,0xdf,0xdb,0x3d,0xeb,0xcf,0x14,0x41,0xbf,
        ],
        |tx: &mut Transaction| tx.inputs[0].utxo_entry.amount = 666);

    // So is the script being spent, length prefix included.
    case!("native-none-acp-0-modify-prev-spk", vec_build_native(0), 0, SigHashType::NoneAnyOneCanPay,
        [
          0x20,0xa5,0x25,0xc5,0x4d,0xc3,0x3b,0x2a,0x61,0x20,0x1f,0x05,0x23,0x3c,0x08,0x6d,
          0xbe,0x8e,0x06,0xe9,0x51,0x57,0x75,0x18,0x1e,0xd9,0x65,0x50,0xb4,0xf2,0xd7,0x14,
        ],
        vec_extend_spk0);

    // ── SINGLE ──────────────────────────────────────────────────
    case!("native-single-0", vec_build_native(0), 0, SigHashType::Single,
        [
          0x44,0xa0,0xb4,0x07,0xff,0x7b,0x23,0x9d,0x44,0x77,0x43,0xdd,0x50,0x3f,0x7a,0xd2,
          0x3d,0xb5,0xb2,0xee,0x4d,0x25,0x27,0x9b,0xd3,0xdf,0xfa,0xf6,0xb4,0x74,0xe0,0x05,
        ],
        nop);

    // Only the output at our own index is committed.
    case!("native-single-0-modify-output-1", vec_build_native(0), 0, SigHashType::Single,
        [
          0x44,0xa0,0xb4,0x07,0xff,0x7b,0x23,0x9d,0x44,0x77,0x43,0xdd,0x50,0x3f,0x7a,0xd2,
          0x3d,0xb5,0xb2,0xee,0x4d,0x25,0x27,0x9b,0xd3,0xdf,0xfa,0xf6,0xb4,0x74,0xe0,0x05,
        ],
        |tx: &mut Transaction| tx.outputs[1].value = 100);

    // Input 2 has no output 2. The outputs sub-hash must be the zero hash,
    // not an out-of-bounds read and not a panic.
    case!("native-single-2-no-corresponding-output", vec_build_native(0), 2, SigHashType::Single,
        [
          0x02,0x2a,0xd9,0x67,0x19,0x2f,0x39,0xd8,0xd5,0x89,0x5d,0x24,0x3e,0x02,0x5e,0xc1,
          0x4c,0xc7,0xa7,0x97,0x08,0xc5,0xe3,0x64,0x89,0x4d,0x4e,0xff,0x3c,0xec,0xb1,0xb0,
        ],
        nop);

    case!("native-single-acp-0", vec_build_native(0), 0, SigHashType::SingleAnyOneCanPay,
        [
          0x43,0xb2,0x0a,0xba,0x77,0x50,0x50,0xcf,0x9b,0xa8,0xd5,0xe4,0x8f,0xc7,0xed,0x2d,
          0xc6,0xc0,0x71,0xd2,0x3f,0x30,0x38,0x2a,0xea,0x58,0xb7,0xc5,0x9c,0xfb,0x8e,0xd7,
        ],
        nop);

    case!("native-single-acp-2-no-corresponding-output", vec_build_native(0), 2, SigHashType::SingleAnyOneCanPay,
        [
          0x84,0x66,0x89,0x13,0x1f,0xb0,0x8b,0x77,0xf8,0x3a,0xf1,0xd3,0x90,0x10,0x76,0x73,
          0x2e,0xf0,0x9d,0x3f,0x8f,0xdf,0xf9,0x45,0xbe,0x89,0xaa,0x43,0x00,0x56,0x2e,0x5f,
        ],
        nop);

    // ── Subnetwork: gas, payload and subnetwork id enter the digest ──
    case!("subnetwork-all-0", vec_build_subnetwork(), 0, SigHashType::All,
        [
          0xb2,0xf4,0x21,0xc9,0x33,0xeb,0x7e,0x1a,0x91,0xf1,0xd9,0xe1,0xef,0xa3,0xf1,0x20,
          0xfe,0x41,0x93,0x26,0xc0,0xdb,0xac,0x48,0x77,0x52,0x18,0x95,0x22,0x55,0x0e,0x0c,
        ],
        nop);

    case!("subnetwork-all-modify-payload", vec_build_subnetwork(), 0, SigHashType::All,
        [
          0x12,0xab,0x63,0xb9,0xae,0xa3,0xd5,0x8d,0xb3,0x39,0x24,0x5a,0x9b,0x6e,0x9c,0xb6,
          0x07,0x5b,0x22,0x53,0x61,0x5c,0xe0,0xfb,0x18,0x10,0x4d,0x28,0xde,0x44,0x35,0xa1,
        ],
        vec_set_payload);

    case!("subnetwork-all-modify-gas", vec_build_subnetwork(), 0, SigHashType::All,
        [
          0x25,0x01,0xed,0xfc,0x00,0x68,0xd5,0x91,0x16,0x0c,0x4b,0xd9,0x86,0x46,0xc6,0xe6,
          0x89,0x2c,0xdc,0x05,0x11,0x82,0xa8,0xbe,0x3c,0xcd,0x6d,0x67,0xf1,0x04,0xfd,0x17,
        ],
        |tx: &mut Transaction| tx.gas = 1234);

    case!("subnetwork-all-modify-subnetwork-id", vec_build_subnetwork(), 0, SigHashType::All,
        [
          0xa5,0xd1,0x23,0x0e,0xde,0x0d,0xfc,0xfd,0x52,0x2e,0x04,0x12,0x3a,0x7b,0xcd,0x72,
          0x14,0x62,0xfe,0xd1,0xd3,0xa8,0x73,0x52,0x03,0x1a,0x4f,0x6e,0x3c,0x43,0x89,0xb6,
        ],
        vec_set_subnetwork_id);

    (passed, total)
}

/// Runs all sighash tests: the local self-consistency checks first, then the
/// consensus vectors.
///
/// The five local tests answer "does this module behave sensibly"; the vectors
/// answer "does it agree with the node". Only the second question protects
/// funds, but the first localises a failure faster when both fail together.
#[cfg(any(test, feature = "verbose-boot"))]
pub fn run_sighash_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    if test_keyed_differs() { passed += 1; }
    if test_sighash_basic() { passed += 1; }
    if test_sighash_different_inputs() { passed += 1; }
    if test_sign_transaction_complete() { passed += 1; }
    if test_format_kas() { passed += 1; }

    // The consensus vectors are NOT run here. They moved to
    // `boot_test::run_crypto_kats` so they execute in builds that ship, not
    // only in `verbose-boot` builds that must never ship. Running them in both
    // places would just hash the same 27 transactions twice per boot.

    (passed, total)
}
