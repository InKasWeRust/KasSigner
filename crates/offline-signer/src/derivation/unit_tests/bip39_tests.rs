use super::*;

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

    if mnemonic.indices != expected {
        return false;
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
        0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
        0x7f,
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
        0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c, 0x05,
        0xed, 0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e, 0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34,
        0x95, 0x53, 0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82, 0x64, 0xc1, 0xe1, 0xc9, 0x2f,
        0x2c, 0xf1, 0x41, 0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b, 0x2f, 0x00, 0x16, 0x98,
        0xe7, 0x46, 0x3b, 0x04,
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

    if test_vector_12_zeros() {
        passed += 1;
    }
    if test_vector_12_7f() {
        passed += 1;
    }
    if test_vector_24_zeros() {
        passed += 1;
    }
    if test_seed_derivation_trezor() {
        passed += 1;
    }
    if test_word_lookup() {
        passed += 1;
    }

    (passed, total)
}

#[test]
fn bip39_vectors_pass() {
    let (passed, total) = run_bip39_tests();
    assert_eq!(passed, total);
}

#[test]
fn twenty_four_word_seed_derivation_wrapper_is_covered() {
    let mnemonic = mnemonic_from_entropy_24(&[0u8; 32]);
    let mut seed = seed_from_mnemonic_24(&mnemonic, "KasSigner");
    assert!(seed.bytes.iter().any(|byte| *byte != 0));
    seed.zeroize();
    assert_eq!(seed.bytes, [0u8; 64]);
}

#[test]
fn mnemonic_validation_rejects_checksum_bit_flips_and_word_index_overflow() {
    let mut twelve = mnemonic_from_entropy_12(&[0u8; 16]);
    twelve.indices[11] ^= 1;
    assert_eq!(
        validate_mnemonic_12(&twelve),
        Err(Bip39Error::InvalidChecksum)
    );

    let mut twenty_four = mnemonic_from_entropy_24(&[0u8; 32]);
    twenty_four.indices[23] ^= 1;
    assert_eq!(
        validate_mnemonic_24(&twenty_four),
        Err(Bip39Error::InvalidChecksum)
    );

    assert_eq!(index_to_word(2047), "zoo");
    assert_eq!(index_to_word(2048), "???");
}

#[test]
fn mnemonic_and_seed_zeroization_is_explicitly_observable() {
    let mut twelve = mnemonic_from_entropy_12(&[0x11u8; 16]);
    assert!(twelve.indices.iter().any(|value| *value != 0));
    twelve.zeroize();
    assert_eq!(twelve.indices, [0u16; 12]);

    let mut twenty_four = mnemonic_from_entropy_24(&[0x22u8; 32]);
    assert!(twenty_four.indices.iter().any(|value| *value != 0));
    twenty_four.zeroize();
    assert_eq!(twenty_four.indices, [0u16; 24]);

    let mut seed = Seed {
        bytes: [0x5au8; 64],
    };
    seed.zeroize();
    assert_eq!(seed.bytes, [0u8; 64]);
}

#[test]
fn word_lookup_comparison_covers_prefix_and_length_ordering() {
    assert_eq!(word_to_index("abandon"), Ok(0));
    assert_eq!(word_to_index("ability"), Ok(1));
    assert_eq!(word_to_index("zoo"), Ok(2047));
    assert_eq!(word_to_index("aban"), Err(Bip39Error::WordNotFound));
    assert_eq!(word_to_index("abandonx"), Err(Bip39Error::WordNotFound));
}

#[test]
fn checkpointed_seed_derivation_matches_normal_seed() {
    let mnemonic = mnemonic_from_entropy_12(&[0x42u8; 16]);
    let mut checkpoints = 0u32;
    let mut callback = || checkpoints += 1;
    let mut checkpointed =
        seed_from_mnemonic_12_with_checkpoint(&mnemonic, "KasSigner", &mut callback);
    let mut normal = seed_from_mnemonic_12(&mnemonic, "KasSigner");
    assert_eq!(checkpointed.bytes, normal.bytes);
    assert_eq!(checkpoints, 33);
    checkpointed.zeroize();
    normal.zeroize();
}

#[test]
fn resumable_seed_derivation_zero_budget_stays_not_started() {
    let mnemonic = mnemonic_from_entropy_12(&[0x33u8; 16]);
    let mut work = SeedDerivation::from_mnemonic_12(&mnemonic, "");
    assert_eq!(work.progress_percent(), 0);
    assert!(work.advance(0).is_none());
    assert_eq!(work.progress_percent(), 0);
    assert!(work.advance(1).is_none());
    assert_eq!(work.progress_percent(), 1);
}

#[test]
fn resumable_twenty_four_word_seed_matches_normal_seed() {
    let mnemonic = mnemonic_from_entropy_24(&[0x55u8; 32]);
    let mut work = SeedDerivation::from_mnemonic_24(&mnemonic, "KasSigner-24");
    assert!(work.advance(0).is_none());
    assert_eq!(work.progress_percent(), 0);
    let mut stepped = (0..=2048u16)
        .find_map(|_| work.advance(17))
        .expect("bounded resumable 24-word derivation must complete");
    let mut normal = seed_from_mnemonic_24(&mnemonic, "KasSigner-24");
    assert_eq!(stepped.bytes, normal.bytes);
    assert_eq!(work.progress_percent(), 100);
    stepped.zeroize();
    normal.zeroize();
}

#[test]
fn resumable_seed_derivation_matches_normal_seed() {
    let mnemonic = mnemonic_from_entropy_12(&[0x24u8; 16]);
    let mut work = SeedDerivation::from_mnemonic_12(&mnemonic, "KasSigner");
    assert!(work.advance(8).is_none());
    assert!(work.progress_percent() > 0);
    let mut stepped = (0..=2048u16)
        .find_map(|_| work.advance(8))
        .expect("bounded resumable derivation must complete");
    let mut normal = seed_from_mnemonic_12(&mnemonic, "KasSigner");
    assert_eq!(stepped.bytes, normal.bytes);
    assert_eq!(work.progress_percent(), 100);
    assert!(work.advance(8).is_none());
    stepped.zeroize();
    normal.zeroize();
}

#[test]
fn resumable_seed_progress_exact_boundaries_and_completion_wipe() {
    let mnemonic = mnemonic_from_entropy_12(&[0x61u8; 16]);
    let mut work = SeedDerivation::from_mnemonic_12(&mnemonic, "progress-boundary");

    assert!(work.advance(1).is_none());
    assert_eq!(work.progress_percent(), 1);
    assert!(work.advance(1023).is_none());
    assert_eq!(work.progress_percent(), 50);
    assert!(work.advance(1023).is_none());
    assert_eq!(work.progress_percent(), 99);
    let mut seed = work.advance(1).expect("round 2048 completes exactly");
    assert_eq!(work.progress_percent(), 100);
    assert!(work.sensitive_state_is_zeroized());
    assert!(work.advance(1).is_none());
    seed.zeroize();
}
