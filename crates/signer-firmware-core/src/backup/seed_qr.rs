// SeedSigner-compatible SeedQR and CompactSeedQR codecs. These live in the
// shared crate so camera/SD import fuzzing exercises the exact firmware parser.

use sha2::{Digest, Sha256};

fn validated_word_count(indices_len: usize, word_count: u8) -> Option<usize> {
    let count = match word_count {
        12 => 12usize,
        24 => 24usize,
        _ => return None,
    };
    (indices_len >= count).then_some(count)
}

/// Encode word indices as a SeedQR numeric string. Returns zero for an invalid
/// word count, short input, or an out-of-range BIP39 index.
pub fn encode_seedqr(indices: &[u16], word_count: u8, buf: &mut [u8; 96]) -> usize {
    let Some(count) = validated_word_count(indices.len(), word_count) else {
        return 0;
    };
    if indices[..count].iter().any(|index| *index >= 2048) {
        return 0;
    }
    for (position, index) in indices[..count].iter().copied().enumerate() {
        let offset = position * 4;
        buf[offset] = b'0' + ((index / 1000) % 10) as u8;
        buf[offset + 1] = b'0' + ((index / 100) % 10) as u8;
        buf[offset + 2] = b'0' + ((index / 10) % 10) as u8;
        buf[offset + 3] = b'0' + (index % 10) as u8;
    }
    count * 4
}

/// Decode a standard SeedQR numeric string. Returns 12/24, or zero on error.
pub fn decode_seedqr(data: &[u8], indices: &mut [u16; 24]) -> u8 {
    let count = match data.len() {
        48 => 12usize,
        96 => 24usize,
        _ => return 0,
    };
    if !data.iter().all(u8::is_ascii_digit) {
        return 0;
    }
    for (position, chunk) in data.chunks_exact(4).take(count).enumerate() {
        let value = u16::from(chunk[0] - b'0') * 1000
            + u16::from(chunk[1] - b'0') * 100
            + u16::from(chunk[2] - b'0') * 10
            + u16::from(chunk[3] - b'0');
        if value >= 2048 {
            return 0;
        }
        indices[position] = value;
    }
    count as u8
}

/// Encode CompactSeedQR entropy. Returns zero for invalid/short mnemonic input.
pub fn encode_compact_seedqr(indices: &[u16], word_count: u8, buf: &mut [u8; 32]) -> usize {
    let Some(count) = validated_word_count(indices.len(), word_count) else {
        return 0;
    };
    if indices[..count].iter().any(|index| *index >= 2048) {
        return 0;
    }
    let mut bits = [0u8; 33];
    let mut bit_position = 0usize;
    for index in indices[..count].iter().copied() {
        for bit in (0..11).rev() {
            let byte_index = bit_position / 8;
            let bit_index = 7 - (bit_position % 8);
            if (index >> bit) & 1 == 1 {
                bits[byte_index] |= 1 << bit_index;
            }
            bit_position += 1;
        }
    }
    let output_len = if count == 12 { 16 } else { 32 };
    buf[..output_len].copy_from_slice(&bits[..output_len]);
    output_len
}

/// Decode CompactSeedQR entropy into BIP39 word indices. Returns 12/24, or zero.
pub fn decode_compact_seedqr(data: &[u8], indices: &mut [u16; 24]) -> u8 {
    let (count, entropy_len, total_bits) = match data.len() {
        16 => (12usize, 16usize, 132usize),
        32 => (24usize, 32usize, 264usize),
        _ => return 0,
    };
    let checksum = Sha256::digest(&data[..entropy_len])[0];
    let mut combined = [0u8; 34];
    combined[..entropy_len].copy_from_slice(&data[..entropy_len]);
    if count == 12 {
        combined[16] = checksum & 0xF0;
    } else {
        combined[32] = checksum;
    }
    for (position, output) in indices[..count].iter_mut().enumerate() {
        let mut value = 0u16;
        let bit_start = position * 11;
        for bit in 0..11 {
            let absolute = bit_start + bit;
            if absolute >= total_bits {
                return 0;
            }
            let byte_index = absolute / 8;
            let bit_index = 7 - (absolute % 8);
            if (combined[byte_index] >> bit_index) & 1 == 1 {
                value |= 1 << (10 - bit);
            }
        }
        *output = value;
    }
    count as u8
}
