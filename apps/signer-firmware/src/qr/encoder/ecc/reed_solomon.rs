use super::gf::gf_mul;

/// Generate Reed-Solomon error-correction codewords.
pub(super) fn encode(data: &[u8], ec_count: usize, ec_out: &mut [u8]) {
    let mut generator = [0u8; 37];
    generator[0] = 1;
    let mut generator_len = 1usize;

    for i in 0..ec_count {
        let mut alpha_i = 1u8;
        for _ in 0..i {
            alpha_i = gf_mul(alpha_i, 2);
        }

        let mut next = [0u8; 37];
        next[0] = generator[0];
        for j in 1..generator_len {
            next[j] = generator[j] ^ gf_mul(generator[j - 1], alpha_i);
        }
        next[generator_len] = gf_mul(generator[generator_len - 1], alpha_i);
        generator_len += 1;
        generator[..generator_len].copy_from_slice(&next[..generator_len]);
    }

    let mut remainder = [0u8; 180];
    remainder[..data.len()].copy_from_slice(data);

    for i in 0..data.len() {
        let coefficient = remainder[i];
        if coefficient != 0 {
            for j in 1..=ec_count {
                remainder[i + j] ^= gf_mul(generator[j], coefficient);
            }
        }
    }

    ec_out[..ec_count]
        .copy_from_slice(&remainder[data.len()..data.len() + ec_count]);
}
