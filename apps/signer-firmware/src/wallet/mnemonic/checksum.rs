//! BIP39 final-word checksum calculation.

use sha2::{Digest, Sha256};

fn append_word_bits(bits: &mut [u8; 33], bit_position: &mut usize, word_index: u16) {
    for bit in (0..11).rev() {
        let byte_index = *bit_position / 8;
        let bit_index = 7 - (*bit_position % 8);
        if (word_index >> bit) & 1 == 1 {
            bits[byte_index] |= 1 << bit_index;
        } else {
            bits[byte_index] &= !(1 << bit_index);
        }
        *bit_position += 1;
    }
}

fn checksum_matches(bits: &[u8; 33], entropy_bytes: usize, checksum_bits: u8) -> bool {
    let hash = Sha256::digest(&bits[..entropy_bytes]);
    match checksum_bits {
        4 => hash[0] >> 4 == (bits[entropy_bytes] >> 4) & 0x0f,
        8 => hash[0] == bits[entropy_bytes],
        _ => false,
    }
}

fn calculate_last_word(indices: &[u16], entropy_bytes: usize, checksum_bits: u8) -> u16 {
    let mut prefix = [0u8; 33];
    let mut bit_position = 0usize;
    for &index in indices {
        append_word_bits(&mut prefix, &mut bit_position, index);
    }

    for candidate in 0u16..2048 {
        let mut complete = prefix;
        let mut candidate_position = bit_position;
        append_word_bits(&mut complete, &mut candidate_position, candidate);
        if checksum_matches(&complete, entropy_bytes, checksum_bits) {
            return candidate;
        }
    }
    0
}

/// Calculate the checksum-bearing twelfth word from the first eleven words.
pub fn calc_last_word_12(indices: &[u16; 11]) -> u16 {
    calculate_last_word(indices, 16, 4)
}

/// Calculate the checksum-bearing twenty-fourth word from the first twenty-three words.
pub fn calc_last_word_24(indices: &[u16; 23]) -> u16 {
    calculate_last_word(indices, 32, 8)
}
