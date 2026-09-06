// BIP39 entropy encoding and checksum validation.

use super::{Bip39Error, Mnemonic12, Mnemonic24};
use sha2::{Digest, Sha256};

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
    for (index, value) in indices.iter_mut().enumerate() {
        *value = extract_bits(&combined, index * 11, 11);
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
    for (index, value) in indices.iter_mut().enumerate() {
        *value = extract_bits(&combined, index * 11, 11);
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
        value = (value << 1).wrapping_add(bit as u16);
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
            // Each destination bit is written exactly once into a zeroed
            // buffer, so addition expresses the non-overlapping bit lanes
            // without creating an equivalent OR/XOR mutation surface.
            data[byte_idx] = data[byte_idx].wrapping_add(1 << bit_idx);
        }
        // No clear needed — data starts zeroed
    }
}
