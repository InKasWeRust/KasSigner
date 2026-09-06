use crate::{anti_klepto, covenant_sign};

#[test]
fn externally_controlled_shared_wire_parsers_are_total_over_truncated_and_noise_inputs() {
    let mut seed = 0x6a09_e667_f3bc_c909u64;
    for len in 0..=600usize {
        let mut bytes = std::vec![0u8; len];
        for byte in &mut bytes {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (seed >> 32) as u8;
        }
        let data = bytes.as_slice();
        let result = std::panic::catch_unwind(|| {
            let _ = anti_klepto::parse_request(data);
            let _ = anti_klepto::parse_reveal(data);
            let _ = covenant_sign::parse_request(data);
            let _ = covenant_sign::parse_reveal(data);
            let _ = covenant_sign::private_swap::parse_request(data);
            let _ = covenant_sign::private_swap::parse_reveal(data);
        });
        assert!(
            result.is_ok(),
            "external shared parser panicked at length {len}"
        );
    }
}
