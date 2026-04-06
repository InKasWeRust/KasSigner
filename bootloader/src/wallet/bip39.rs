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

// KasSigner — BIP39 Mnemonic Generation & Seed Derivation
// 100% Rust, no-std, no-alloc
//
// Complete BIP39 standard implementation:
//   1. Entropy (128/256 bits) → SHA256 checksum → 11-bit indices
//   2. Indices → English wordlist words
//   3. Mnemonic + passphrase → PBKDF2-HMAC-SHA512 (2048 iterations) → 512-bit seed
//
// Security:
//   - All sensitive memory is zeroized on completion
//   - No heap/alloc — all in stack arrays
//   - Compatible with official BIP39 test vectors


use sha2::{Sha256, Digest};
use super::bip39_wordlist::WORDLIST;
use super::hmac::{hmac_sha512, zeroize_buf};

// ─── Errores ──────────────────────────────────────────────────────────

/// Possible BIP39 operation errors
#[derive(Debug, PartialEq)]
/// Errors during mnemonic generation or validation (BIP39).
pub enum Bip39Error {
    /// Invalid entropy length (must be 16 or 32 bytes)
    InvalidEntropyLength,
    /// Mnemonic checksum mismatch
    InvalidChecksum,
    /// Invalid word count (must be 12 or 24)
    InvalidWordCount,
    /// Palabra no encontrada en la wordlist
    WordNotFound,
}

// ─── Tipos ────────────────────────────────────────────────────────────

/// 12-word mnemonic (128 bits of entropy)
/// Stores wordlist indices (0-2047), not words as strings
pub struct Mnemonic12 {
    /// BIP39 wordlist indices (each 0..2047)
    pub indices: [u16; 12],
}

/// 24-word mnemonic (256 bits of entropy)
pub struct Mnemonic24 {
    pub indices: [u16; 24],
}

/// Seed BIP39 de 512 bits (64 bytes)
/// Result of PBKDF2-HMAC-SHA512
pub struct Seed {
    pub bytes: [u8; 64],
}

impl Seed {
    /// Securely zeroize the seed
    pub fn zeroize(&mut self) {
        for b in self.bytes.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ─── Mnemonic generation from entropy ───────────────────────────

/// Generate a 12-word mnemonic from 16 bytes of entropy.
///
/// Proceso BIP39:
///   1. SHA256(entropy) → take first 4 bits as checksum
///   2. Concatenar entropy (128 bits) + checksum (4 bits) = 132 bits
///   3. Split into 12 groups of 11 bits → 12 indices (0-2047)
///   4. Each index maps to a wordlist word
pub fn mnemonic_from_entropy_12(entropy: &[u8; 16]) -> Mnemonic12 {
    let checksum_byte = sha256_first_byte(entropy);
    // For 128 bits: checksum = 4 bits (first nibble of hash)
    let indices = entropy_to_indices_12(entropy, checksum_byte);
    Mnemonic12 { indices }
}

/// Generate a 24-word mnemonic from 32 bytes of entropy.
///
/// Proceso BIP39:
///   1. SHA256(entropy) → take first byte as checksum (8 bits)
///   2. Concatenar entropy (256 bits) + checksum (8 bits) = 264 bits
///   3. Split into 24 groups of 11 bits → 24 indices
pub fn mnemonic_from_entropy_24(entropy: &[u8; 32]) -> Mnemonic24 {
    let checksum_byte = sha256_first_byte(entropy);
    // For 256 bits: checksum = 8 bits (full byte of hash)
    let indices = entropy_to_indices_24(entropy, checksum_byte);
    Mnemonic24 { indices }
}

// ─── Mnemonic validation ──────────────────────────────────────────

/// Validate a 12-word mnemonic.
/// Reconstructs entropy from indices and verifies the SHA256 checksum.
pub fn validate_mnemonic_12(mnemonic: &Mnemonic12) -> Result<(), Bip39Error> {
    // Reconstruct 132 bits (128 entropy + 4 checksum) from 12 indices
    let (entropy, checksum_bits) = indices_to_entropy_12(&mnemonic.indices);

    // Calcular checksum esperado
    let hash_byte = sha256_first_byte(&entropy);
    let expected_checksum = hash_byte >> 4; // Primeros 4 bits

    if checksum_bits != expected_checksum {
        return Err(Bip39Error::InvalidChecksum);
    }

    Ok(())
}

/// Validate a 24-word mnemonic.
pub fn validate_mnemonic_24(mnemonic: &Mnemonic24) -> Result<(), Bip39Error> {
    let (entropy, checksum_byte) = indices_to_entropy_24(&mnemonic.indices);

    let hash_byte = sha256_first_byte(&entropy);

    if checksum_byte != hash_byte {
        return Err(Bip39Error::InvalidChecksum);
    }

    Ok(())
}

// ─── Word ↔ index conversion ────────────────────────────────────

/// Look up a word in the wordlist and return its index.
/// Binary search O(log n) since the wordlist is alphabetically sorted.
pub fn word_to_index(word: &str) -> Result<u16, Bip39Error> {
    // BIP39 wordlist is sorted → binary search
    let mut low: usize = 0;
    let mut high: usize = 2047;

    while low <= high {
        let mid = low + (high - low) / 2;
        let mid_word = WORDLIST[mid];

        match str_cmp(word, mid_word) {
            core::cmp::Ordering::Equal => return Ok(mid as u16),
            core::cmp::Ordering::Less => {
                if mid == 0 {
                    break;
                }
                high = mid - 1;
            }
            core::cmp::Ordering::Greater => low = mid + 1,
        }
    }

    Err(Bip39Error::WordNotFound)
}

/// Return the word corresponding to an index (0-2047).
pub fn index_to_word(index: u16) -> &'static str {
    WORDLIST[index as usize]
}

// ─── Seed derivation (PBKDF2-HMAC-SHA512) ─────────────────────────────

/// Derive a 512-bit seed from a 12-word mnemonic + passphrase.
///
/// BIP39 spec: PBKDF2(password=mnemonic_sentence, salt="mnemonic"+passphrase, iterations=2048, dklen=64)
///
/// The mnemonic is serialized as a string: space-separated words.
/// The salt is "mnemonic" + passphrase (passphrase may be empty).
pub fn seed_from_mnemonic_12(mnemonic: &Mnemonic12, passphrase: &str) -> Seed {
    // Build the mnemonic phrase as a string (in a stack buffer)
    // 24 words * max 8 chars + 23 spaces = ~215 bytes max for 24 words
    // For 12 words: ~107 bytes max
    let mut phrase_buf = [0u8; 256];
    let phrase_len = serialize_mnemonic_12(&mnemonic.indices, &mut phrase_buf);

    // Salt: "mnemonic" + passphrase
    let mut salt_buf = [0u8; 256];
    let salt_len = build_salt(passphrase, &mut salt_buf);

    let seed = pbkdf2_hmac_sha512(
        &phrase_buf[..phrase_len],
        &salt_buf[..salt_len],
        2048,
    );

    // Zeroize temporary buffers
    zeroize_buf(&mut phrase_buf);
    zeroize_buf(&mut salt_buf);

    seed
}

/// Derive a 512-bit seed from a 24-word mnemonic + passphrase.
pub fn seed_from_mnemonic_24(mnemonic: &Mnemonic24, passphrase: &str) -> Seed {
    let mut phrase_buf = [0u8; 512];
    let phrase_len = serialize_mnemonic_24(&mnemonic.indices, &mut phrase_buf);

    let mut salt_buf = [0u8; 256];
    let salt_len = build_salt(passphrase, &mut salt_buf);

    let seed = pbkdf2_hmac_sha512(
        &phrase_buf[..phrase_len],
        &salt_buf[..salt_len],
        2048,
    );

    zeroize_buf(&mut phrase_buf);
    zeroize_buf(&mut salt_buf);

    seed
}

// ═══════════════════════════════════════════════════════════════════════
// Funciones internas
// ═══════════════════════════════════════════════════════════════════════

/// SHA256 of input, returns only the first byte of the hash.
fn sha256_first_byte(data: &[u8]) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result[0]
}

/// Extract 12 eleven-bit indices from 128 bits of entropy + 4-bit checksum.
///
/// Layout de bits: [entropy: 128 bits][checksum: 4 bits] = 132 bits
/// Each index: 11 bits → 12 indices × 11 = 132 bits ✓
fn entropy_to_indices_12(entropy: &[u8; 16], checksum_byte: u8) -> [u16; 12] {
    let mut combined = [0u8; 17];
    combined[..16].copy_from_slice(entropy);
    combined[16] = checksum_byte & 0xF0; // Only first 4 bits

    let mut indices = [0u16; 12];
    for i in 0..12 {
        indices[i] = extract_bits(&combined, i * 11, 11);
    }
    indices
}

/// Extract 24 eleven-bit indices from 256 bits of entropy + 8-bit checksum.
///
/// Layout: [entropy: 256 bits][checksum: 8 bits] = 264 bits
/// Each index: 11 bits → 24 × 11 = 264 bits ✓
fn entropy_to_indices_24(entropy: &[u8; 32], checksum_byte: u8) -> [u16; 24] {
    let mut combined = [0u8; 33];
    combined[..32].copy_from_slice(entropy);
    combined[32] = checksum_byte;

    let mut indices = [0u16; 24];
    for i in 0..24 {
        indices[i] = extract_bits(&combined, i * 11, 11);
    }
    indices
}

/// Extrae `num_bits` bits empezando en `bit_offset` de un array de bytes.
/// Big-endian bit ordering (MSB first, per BIP39 spec).
fn extract_bits(data: &[u8], bit_offset: usize, num_bits: usize) -> u16 {
    let mut value: u16 = 0;
    for i in 0..num_bits {
        let byte_idx = (bit_offset + i) / 8;
        let bit_idx = 7 - ((bit_offset + i) % 8); // MSB first
        let bit = (data[byte_idx] >> bit_idx) & 1;
        value = (value << 1) | (bit as u16);
    }
    value
}

/// Reconstruct 16 bytes of entropy + 4-bit checksum from 12 indices.
fn indices_to_entropy_12(indices: &[u16; 12]) -> ([u8; 16], u8) {
    // 12 indices × 11 bits = 132 bits = 128 bits entropy + 4 bits checksum
    let mut bits = [0u8; 17]; // 132 bits caben en 17 bytes
    let mut bit_pos = 0;

    for &idx in indices.iter() {
        write_bits(&mut bits, bit_pos, idx, 11);
        bit_pos += 11;
    }

    let mut entropy = [0u8; 16];
    entropy.copy_from_slice(&bits[..16]);

    // Checksum: bits 128..131 (4 bits) = first 4 bits of bits[16]
    let checksum = bits[16] >> 4;

    (entropy, checksum)
}

/// Reconstruct 32 bytes of entropy + 8-bit checksum from 24 indices.
fn indices_to_entropy_24(indices: &[u16; 24]) -> ([u8; 32], u8) {
    // 24 × 11 = 264 bits = 256 entropy + 8 checksum
    let mut bits = [0u8; 33];
    let mut bit_pos = 0;

    for &idx in indices.iter() {
        write_bits(&mut bits, bit_pos, idx, 11);
        bit_pos += 11;
    }

    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&bits[..32]);

    let checksum = bits[32];

    (entropy, checksum)
}

/// Write `num_bits` bits of `value` at `bit_offset` position (big-endian).
fn write_bits(data: &mut [u8], bit_offset: usize, value: u16, num_bits: usize) {
    for i in 0..num_bits {
        let bit = (value >> (num_bits - 1 - i)) & 1;
        let byte_idx = (bit_offset + i) / 8;
        let bit_idx = 7 - ((bit_offset + i) % 8);
        if bit == 1 {
            data[byte_idx] |= 1 << bit_idx;
        }
        // No clear needed — data starts zeroed
    }
}

/// Serialize a 12-word mnemonic as a space-separated UTF-8 string.
fn serialize_mnemonic_12(indices: &[u16; 12], buf: &mut [u8]) -> usize {
    let mut pos = 0;
    for (i, &idx) in indices.iter().enumerate() {
        if i > 0 {
            buf[pos] = b' ';
            pos += 1;
        }
        let word = WORDLIST[idx as usize];
        let word_bytes = word.as_bytes();
        buf[pos..pos + word_bytes.len()].copy_from_slice(word_bytes);
        pos += word_bytes.len();
    }
    pos
}

/// Serialize a 24-word mnemonic as a space-separated UTF-8 string.
fn serialize_mnemonic_24(indices: &[u16; 24], buf: &mut [u8]) -> usize {
    let mut pos = 0;
    for (i, &idx) in indices.iter().enumerate() {
        if i > 0 {
            buf[pos] = b' ';
            pos += 1;
        }
        let word = WORDLIST[idx as usize];
        let word_bytes = word.as_bytes();
        buf[pos..pos + word_bytes.len()].copy_from_slice(word_bytes);
        pos += word_bytes.len();
    }
    pos
}

/// Builds the BIP39 salt: "mnemonic" + passphrase
fn build_salt(passphrase: &str, buf: &mut [u8]) -> usize {
    let prefix = b"mnemonic";
    buf[..8].copy_from_slice(prefix);
    let pp_bytes = passphrase.as_bytes();
    buf[8..8 + pp_bytes.len()].copy_from_slice(pp_bytes);
    8 + pp_bytes.len()
}

/// no-std string comparison (lexicographic, byte-by-byte).
fn str_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let min_len = if a_bytes.len() < b_bytes.len() {
        a_bytes.len()
    } else {
        b_bytes.len()
    };

    for i in 0..min_len {
        match a_bytes[i].cmp(&b_bytes[i]) {
            core::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    a_bytes.len().cmp(&b_bytes.len())
}

// ═══════════════════════════════════════════════════════════════════════
// PBKDF2-HMAC-SHA512 — manual no-std implementation
// ═══════════════════════════════════════════════════════════════════════
//
// HMAC-SHA512 from wallet::hmac (shared with BIP32).
// Only PBKDF2 here, which is BIP39-specific.

/// PBKDF2-HMAC-SHA512 (RFC 2898)
///
/// DK = T1 || T2 || ... (we only need T1 for 64 bytes = 512 bits)
/// Ti = U1 ⊕ U2 ⊕ ... ⊕ Uc
/// U1 = HMAC(password, salt || INT(i))
/// Uj = HMAC(password, U_{j-1})
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32) -> Seed {
    // For BIP39 we only need 64 bytes = one SHA512 block
    // So we only compute T1 (block_index = 1)

    // U1 = HMAC(password, salt || BE32(1))
    let mut salt_with_index = [0u8; 260]; // 256 max salt + 4 bytes index
    salt_with_index[..salt.len()].copy_from_slice(salt);
    // Append block index as big-endian u32
    let idx_bytes = 1u32.to_be_bytes();
    salt_with_index[salt.len()..salt.len() + 4].copy_from_slice(&idx_bytes);

    let mut u_prev = hmac_sha512(password, &salt_with_index[..salt.len() + 4]);
    let mut result = [0u8; 64];
    result.copy_from_slice(&u_prev);

    // U2..Uc
    for _ in 1..iterations {
        let u_next = hmac_sha512(password, &u_prev);
        for j in 0..64 {
            result[j] ^= u_next[j];
        }
        u_prev = u_next;
    }

    // Zeroize temporaries
    zeroize_buf(&mut u_prev);
    zeroize_buf(&mut salt_with_index);

    Seed { bytes: result }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests with official BIP39 vectors
// ═══════════════════════════════════════════════════════════════════════
//
// These tests use vectors from the official repository:
// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
//
// To run: called from self_test or from an external test harness.

/// Test vector 1: entropy all zeros → "abandon" × 11 + "about"
/// Entropy: 00000000000000000000000000000000 (16 bytes)
/// Expected mnemonic: "abandon abandon abandon abandon abandon abandon
///                     abandon abandon abandon abandon abandon about"
#[cfg(any(test, feature = "verbose-boot"))]
/// BIP39 test: 12-word mnemonic from all-zero entropy.
pub fn test_vector_12_zeros() -> bool {
    let entropy = [0u8; 16];
    let mnemonic = mnemonic_from_entropy_12(&entropy);

    // "abandon" = index 0, "about" = index 3
    let expected: [u16; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];

    for i in 0..12 {
        if mnemonic.indices[i] != expected[i] {
            return false;
        }
    }

    // Validate roundtrip
    validate_mnemonic_12(&mnemonic).is_ok()
}

/// Test vector 2: entropy all ones → known mnemonic
/// Entropy: 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
/// Expected: "legal winner thank year wave sausage worth useful
///            legal winner thank yellow"
#[cfg(any(test, feature = "verbose-boot"))]
/// BIP39 test: 12-word mnemonic from 0x7F entropy.
pub fn test_vector_12_7f() -> bool {
    let entropy: [u8; 16] = [
        0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
        0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
    ];
    let mnemonic = mnemonic_from_entropy_12(&entropy);

    // Verify first and last word
    let first_word = index_to_word(mnemonic.indices[0]);
    let last_word = index_to_word(mnemonic.indices[11]);

    if first_word != "legal" {
        return false;
    }
    if last_word != "yellow" {
        return false;
    }

    validate_mnemonic_12(&mnemonic).is_ok()
}

/// Test vector 3: 24-word mnemonic (256 bits entropy all zeros)
/// Entropy: 0000...0000 (32 bytes)
/// Expected: "abandon" × 23 + "art"
#[cfg(any(test, feature = "verbose-boot"))]
/// BIP39 test: 24-word mnemonic from all-zero entropy.
pub fn test_vector_24_zeros() -> bool {
    let entropy = [0u8; 32];
    let mnemonic = mnemonic_from_entropy_24(&entropy);

    // First 23 words should be "abandon" (index 0)
    for i in 0..23 {
        if mnemonic.indices[i] != 0 {
            return false;
        }
    }

    // Last word: "art" = index 104
    let last_word = index_to_word(mnemonic.indices[23]);
    if last_word != "art" {
        return false;
    }

    validate_mnemonic_24(&mnemonic).is_ok()
}

/// Test: seed derivation with known vector
/// Mnemonic: "abandon abandon abandon abandon abandon abandon
///            abandon abandon abandon abandon abandon about"
/// Passphrase: "TREZOR"
/// Expected seed (hex):
///   c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e7e24052f0b7c87c5
///   67a677d12fbc157e164023a3cf9b11f9c7cf61e3da79e1c6aba8e9e5c369c429
#[cfg(any(test, feature = "verbose-boot"))]
/// BIP39 test: seed derivation matches Trezor test vectors.
pub fn test_seed_derivation_trezor() -> bool {
    let entropy = [0u8; 16];
    let mnemonic = mnemonic_from_entropy_12(&entropy);
    let mut seed = seed_from_mnemonic_12(&mnemonic, "TREZOR");

    let expected: [u8; 64] = [
        0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72,
        0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c, 0x05, 0xed,
        0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e,
        0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34, 0x95, 0x53,
        0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82,
        0x64, 0xc1, 0xe1, 0xc9, 0x2f, 0x2c, 0xf1, 0x41,
        0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b,
        0x2f, 0x00, 0x16, 0x98, 0xe7, 0x46, 0x3b, 0x04,
    ];

    let matches = seed.bytes == expected;
    seed.zeroize();
    matches
}

/// Test: word lookup (binary search)
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_word_lookup() -> bool {
    // Test first word
    if word_to_index("abandon") != Ok(0) {
        return false;
    }
    // Test last word
    if word_to_index("zoo") != Ok(2047) {
        return false;
    }
    // Test middle word
    if word_to_index("middle") != Ok(1122) {
        return false;
    }
    // Test nonexistent word
    if word_to_index("zzzzz") != Err(Bip39Error::WordNotFound) {
        return false;
    }
    true
}

/// Run all BIP39 tests.
/// Returns (passed, total).
#[cfg(any(test, feature = "verbose-boot"))]
pub fn run_bip39_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    if test_vector_12_zeros() { passed += 1; }
    if test_vector_12_7f() { passed += 1; }
    if test_vector_24_zeros() { passed += 1; }
    if test_seed_derivation_trezor() { passed += 1; }
    if test_word_lookup() { passed += 1; }

    (passed, total)
}
