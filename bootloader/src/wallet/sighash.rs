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

// ═══════════════════════════════════════════════════════════════════
// Keyed Blake2b-256 for Kaspa consensus sighash
// ═══════════════════════════════════════════════════════════════════
//
// Kaspa uses KEYED Blake2b-256 for domain separation in sighash.
// Each sub-hash uses a different ASCII key string (up to 64 bytes).
// This matches Go kaspad's `blake2b.New256(key)` and Rusty Kaspa's
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
        hash_output(&mut hasher, output);
        return hasher.finalize();
    }

    // SigHashAll: hash of all outputs
    let mut hasher = KaspaBlake2b::new(KEY_SIGNING_HASH);
    for output in tx.outputs() {
        hash_output(&mut hasher, output);
    }
    hasher.finalize()
}

/// Serialize an output for hashing.
/// Matches Rusty Kaspa's `hash_output` which calls `hash_script_public_key`,
/// which uses `write_var_bytes` (u64 LE length prefix + raw bytes).
fn hash_output(hasher: &mut KaspaBlake2b, output: &TransactionOutput) {
    hasher.update(&output.value.to_le_bytes());
    // hash_script_public_key: version(u16 LE) + write_var_bytes(script)
    hasher.update(&output.script_public_key.version.to_le_bytes());
    hasher.update(&(output.script_public_key.script_len as u64).to_le_bytes());
    hasher.update(output.script_public_key.script_bytes());
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
pub fn calculate_sighash(
    tx: &Transaction,
    input_index: usize,
    sighash_type: SigHashType,
) -> Hash256 {
    let input = &tx.inputs[input_index];

    let prev_outputs = previous_outputs_hash(tx, sighash_type);
    let sequences = sequences_hash(tx, sighash_type);
    let sig_op_counts = sig_op_counts_hash(tx, sighash_type);
    let outputs = outputs_hash(tx, sighash_type, input_index);
    let payload = payload_hash(tx);

    // Build the final digest with "TransactionSigningHash" domain key
    let mut h = SigHasher::new();

    // 1. tx.Version (2 bytes LE)
    h.update_u16_le(tx.version);

    // 2. previousOutputsHash (32 bytes)
    h.update_hash(&prev_outputs);

    // 3. sequencesHash (32 bytes)
    h.update_hash(&sequences);

    // 4. sigOpCountsHash (32 bytes)
    h.update_hash(&sig_op_counts);

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

    // 12. txIn.SigOpCount (1 byte)
    h.update_u8(input.sig_op_count);

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

    h.finalize()
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
    let mut tx = Transaction::new();
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
    let mut tx = Transaction::new();
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
    let mut tx = Transaction::new();
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

/// Runs all sighash tests
#[cfg(any(test, feature = "verbose-boot"))]
/// Run all sighash test vectors.
pub fn run_sighash_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    if test_keyed_differs() { passed += 1; }
    if test_sighash_basic() { passed += 1; }
    if test_sighash_different_inputs() { passed += 1; }
    if test_sign_transaction_complete() { passed += 1; }
    if test_format_kas() { passed += 1; }

    (passed, total)
}
