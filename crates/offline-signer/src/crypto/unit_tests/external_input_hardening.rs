use super::{container_framing, password_kdf};
use crate::{
    derivation::xpub,
    transaction::{private_swap, std_pskt},
};

#[test]
fn externally_controlled_offline_parsers_are_total_over_truncated_and_noise_inputs() {
    let mut seed = 0x3c6e_f372_fe94_f82bu64;
    for len in 0..=600usize {
        let mut bytes = alloc::vec![0u8; len];
        for byte in &mut bytes {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (seed >> 32) as u8;
        }
        let data = bytes.as_slice();
        let result = std::panic::catch_unwind(|| {
            let _ = container_framing::parse_backup_header(data);
            let _ = container_framing::parse_transport_header(data, data.len());
            let _ = password_kdf::parse_metadata(data);
            let _ = private_swap::parse_private_swap_script(data);
            let _ = std_pskt::detect_tx_format(data);
            let mut out = [0u8; 78];
            let _ = xpub::decode_kpub_compatible(data, &mut out);
            let _ = xpub::parse_kpub_parts(data);
        });
        assert!(
            result.is_ok(),
            "external offline parser panicked at length {len}"
        );
    }
}
