//! Constant-memory keyed permutation for JPEG coefficient positions.

use sha2::{Digest, Sha256};

const ROUNDS: u8 = 4;

pub(super) struct PositionPermutation {
    domain_size: u32,
    half_bits: u32,
    mask: u32,
    round_keys: [u32; ROUNDS as usize],
}

impl PositionPermutation {
    pub(super) fn new(domain_size: u32, key_material: &[u8]) -> Option<Self> {
        if domain_size < 2 {
            return None;
        }
        let mut bits = 1u32;
        while bits < 32 && (1u32 << bits) < domain_size {
            bits += 1;
        }
        if bits % 2 == 1 {
            bits += 1;
        }
        if bits > 32 {
            return None;
        }
        let half_bits = bits / 2;
        let mut hasher = Sha256::new();
        hasher.update(b"KasSigner-stego-perm-v1");
        hasher.update(key_material);
        let digest = hasher.finalize();
        let mut round_keys = [0u32; ROUNDS as usize];
        for (index, key) in round_keys.iter_mut().enumerate() {
            let offset = index * 4;
            *key = u32::from_le_bytes([
                digest[offset],
                digest[offset + 1],
                digest[offset + 2],
                digest[offset + 3],
            ]);
        }
        Some(Self {
            domain_size,
            half_bits,
            mask: (1u32 << half_bits) - 1,
            round_keys,
        })
    }

    #[inline]
    fn round(&self, round: u8, input: u32) -> u32 {
        let mut value = input ^ self.round_keys[round as usize];
        value = value.wrapping_mul(0x9E37_79B1);
        value ^= value >> 15;
        value = value.wrapping_mul(0x85EB_CA6B);
        value ^= value >> 13;
        value = value.wrapping_mul(0xC2B2_AE35);
        value ^= value >> 16;
        value & self.mask
    }

    #[inline]
    fn encrypt(&self, value: u32) -> u32 {
        let mut left = value >> self.half_bits;
        let mut right = value & self.mask;
        for round in 0..ROUNDS {
            let next_left = right;
            right = left ^ self.round(round, right);
            left = next_left;
        }
        (left << self.half_bits) | right
    }

    pub(super) fn rank(&self, position: u32) -> u32 {
        let mut value = position;
        loop {
            value = self.encrypt(value);
            if value < self.domain_size {
                return value;
            }
        }
    }
}
