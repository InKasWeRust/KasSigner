#![no_main]

use libfuzzer_sys::fuzz_target;
use offline_signer::derivation::bip32::{
    derive_account_key, derive_address_key, derive_change_key,
};

fuzz_target!(|data: &[u8]| {
    let mut seed = [0u8; 64];
    let copied = data.len().min(seed.len());
    seed[..copied].copy_from_slice(&data[..copied]);
    let index = u32::from_le_bytes([
        data.get(64).copied().unwrap_or(0),
        data.get(65).copied().unwrap_or(0),
        data.get(66).copied().unwrap_or(0),
        data.get(67).copied().unwrap_or(0),
    ]) & 0x7fff_ffff;

    if let Ok(first) = derive_account_key(&seed) {
        let second = derive_account_key(&seed).expect("account derivation must be deterministic");
        assert_eq!(first.private_key_bytes(), second.private_key_bytes());
        assert_eq!(first.chain_code_bytes(), second.chain_code_bytes());
        if let (Ok(receive), Ok(change)) = (
            derive_address_key(&first, index),
            derive_change_key(&first, index),
        ) {
            assert_ne!(receive.private_key_bytes(), change.private_key_bytes());
        }
    }
});
