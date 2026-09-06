use super::*;

// ─── Tests ──────────────────────────────────────────────────────────

/// BIP85 test using precomputed seed (skips PBKDF2 — runs in <1s).
/// Master: "install scatter logic circle pencil average fall shoe quantum disease suspect usage"
/// Expected child at index 0: "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
pub fn test_bip85_12word_index0() -> bool {
    // Precomputed BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase)
    let seed: [u8; 64] = [
        0x37, 0x48, 0x34, 0x72, 0xa6, 0xaf, 0x7f, 0xd1, 0x07, 0xfb, 0x5f, 0x5a, 0xaa, 0xa7, 0xbd,
        0xdc, 0x89, 0x69, 0x03, 0x53, 0x36, 0x92, 0x29, 0x77, 0x1c, 0x32, 0x81, 0x2f, 0x71, 0x12,
        0x07, 0xc8, 0x73, 0x98, 0xa8, 0xd4, 0x4c, 0xfc, 0x76, 0x3a, 0x81, 0x85, 0xff, 0x34, 0x62,
        0x72, 0xe8, 0xf1, 0x45, 0x51, 0x70, 0xde, 0xca, 0xe7, 0x12, 0x59, 0x8f, 0x59, 0x90, 0xc1,
        0x20, 0x7d, 0x2f, 0x88,
    ];

    match derive_mnemonic_12(&seed, 0) {
        Ok(child) => child.indices[0] == 786, // "girl"
        Err(_) => false,
    }
}

#[test]
fn bip85_vector_passes() {
    assert!(test_bip85_12word_index0());
}

#[test]
fn bip85_twenty_four_word_derivation_is_deterministic_and_indexed() {
    let seed = [0x35u8; 64];
    let first = derive_mnemonic_24(&seed, 0).expect("first child mnemonic");
    let repeated = derive_mnemonic_24(&seed, 0).expect("repeated child mnemonic");
    let second = derive_mnemonic_24(&seed, 1).expect("second child mnemonic");
    assert_eq!(first.indices, repeated.indices);
    assert_ne!(first.indices, second.indices);
    assert!(crate::derivation::bip39::validate_mnemonic_24(&first).is_ok());
}
