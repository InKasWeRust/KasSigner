use super::*;
#[cfg(test)]
use crate::derivation::bip32::Bip32Error;
#[cfg(test)]
use crate::derivation::hmac::{sha256, zeroize_buf};

// Tests con vectores BIP32 conocidos
// ═══════════════════════════════════════════════════════════════════════
//
// Vectores de: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//
// Test Vector 1:
//   Seed: 000102030405060708090a0b0c0d0e0f
//   Master key: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
//   Master chain: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
//   Master pubkey (compressed): 0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2

/// Test vector 1: Master key from seed
#[cfg(any(test, feature = "verbose-boot"))]
/// BIP32 test vector 1: master key derivation.
pub fn test_vector1_master() -> bool {
    // Known seed (abandon×11 + about, no passphrase):
    let known_seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];

    let master = match master_key_from_seed(&known_seed) {
        Ok(m) => m,
        Err(_) => return false,
    };

    // Verify master key is valid (non-zero, < n)
    if is_zero(&master.key) {
        return false;
    }
    if !is_less_than_order(&master.key) {
        return false;
    }
    if master.depth != 0 {
        return false;
    }

    // Verify public key can be computed
    master.public_key_compressed().is_ok()
}

/// Test: BIP32 test vector 1 con seed hex 000102030405060708090a0b0c0d0e0f
/// We use HMAC-SHA512 directly to verify against the official test vector.
#[cfg(any(test, feature = "verbose-boot"))]
/// BIP32 test vector 1: official test vectors.
pub fn test_vector1_official() -> bool {
    // BIP32 Test Vector 1 seed (16 bytes — la spec dice que se pasa tal cual a HMAC)
    let seed_short: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // I = HMAC-SHA512("Bitcoin seed", seed)
    let i = hmac_sha512(BITCOIN_SEED, &seed_short);

    // Expected master private key
    let expected_key: [u8; 32] = [
        0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05, 0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93, 0xc9,
        0xc5, 0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a, 0x14, 0x94, 0xb9, 0x17, 0xc8, 0x43,
        0x6b, 0x35,
    ];

    // Expected master chain code
    let expected_chain: [u8; 32] = [
        0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56, 0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e, 0xac,
        0x3a, 0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4, 0x2e, 0xe2, 0x27, 0xff, 0xed, 0x37,
        0xd5, 0x08,
    ];

    if i[..32] != expected_key {
        return false;
    }
    if i[32..] != expected_chain {
        return false;
    }

    // Verify public key derivation
    let sk: SecretKey = match SecretKey::from_slice(&expected_key) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let point = pk.to_encoded_point(true);
    let pk_bytes = point.as_bytes();

    // Expected compressed public key
    let expected_pub: [u8; 33] = [
        0x03, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0,
        0x2c, 0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x05, 0x0e, 0x2e, 0x8f, 0xf4,
        0x9c, 0x85, 0xc2,
    ];

    pk_bytes == expected_pub
}

/// Test: child derivation hardened (m/0')
/// BIP32 Test Vector 1, Chain m/0':
///   key:   edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
///   chain: 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
#[cfg(any(test, feature = "verbose-boot"))]
/// BIP32 test vector 1: hardened child derivation.
pub fn test_vector1_child_hardened() -> bool {
    let seed_short: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // Generate master key manually (16-byte seed, not 64)
    let i = hmac_sha512(BITCOIN_SEED, &seed_short);
    let mut master_key = [0u8; 32];
    let mut master_chain = [0u8; 32];
    master_key.copy_from_slice(&i[..32]);
    master_chain.copy_from_slice(&i[32..]);

    let master = ExtendedPrivKey {
        key: master_key,
        chain_code: master_chain,
        depth: 0,
    };

    // Derive m/0' (hardened)
    let child = match derive_child(&master, HARDENED_BIT) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let expected_child_key: [u8; 32] = [
        0xed, 0xb2, 0xe1, 0x4f, 0x9e, 0xe7, 0x7d, 0x26, 0xdd, 0x93, 0xb4, 0xec, 0xed, 0xe8, 0xd1,
        0x6e, 0xd4, 0x08, 0xce, 0x14, 0x9b, 0x6c, 0xd8, 0x0b, 0x07, 0x15, 0xa2, 0xd9, 0x11, 0xa0,
        0xaf, 0xea,
    ];

    let expected_child_chain: [u8; 32] = [
        0x47, 0xfd, 0xac, 0xbd, 0x0f, 0x10, 0x97, 0x04, 0x3b, 0x78, 0xc6, 0x3c, 0x20, 0xc3, 0x4e,
        0xf4, 0xed, 0x9a, 0x11, 0x1d, 0x98, 0x00, 0x47, 0xad, 0x16, 0x28, 0x2c, 0x7a, 0xe6, 0x23,
        0x61, 0x41,
    ];

    if child.key != expected_child_key {
        return false;
    }
    if child.chain_code != expected_child_chain {
        return false;
    }
    if child.depth != 1 {
        return false;
    }

    true
}

/// Test: Kaspa path derivation (m/44'/111111'/0'/0/0)
/// Verify that full Kaspa path derivation does not fail
/// and produces a valid key.
#[cfg(any(test, feature = "verbose-boot"))]
/// Kaspa-specific path derivation (m/44'/111111'/0').
pub fn test_kaspa_path_derivation() -> bool {
    // Use known seed (abandon×11 + about, no passphrase)
    let seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];

    // Derivar path completo de Kaspa mainnet
    let result = derive_path(&seed, KASPA_MAINNET_PATH);
    let key = match result {
        Ok(k) => k,
        Err(_) => return false,
    };

    // The key must be valid
    if is_zero(&key.key) {
        return false;
    }
    if !is_less_than_order(&key.key) {
        return false;
    }
    if key.depth != 5 {
        return false;
    }

    // Must be able to generate public key
    let pubkey = match key.public_key_compressed() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Compressed pubkey: 33 bytes, prefix 02 o 03
    if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
        return false;
    }

    // x-only pubkey (for Kaspa Schnorr): 32 bytes
    key.public_key_x_only().is_ok()
}

/// Test: modular arithmetic
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_scalar_arithmetic() -> bool {
    // Test 1: 1 + 1 = 2
    let one = {
        let mut a = [0u8; 32];
        a[31] = 1;
        a
    };
    let two = scalar_add_mod_n(&one, &one);
    if two[31] != 2 {
        return false;
    }

    // Test 2: (n-1) + 1 = 0 mod n
    let n_minus_1 = {
        let mut a = SECP256K1_ORDER;
        // Restar 1
        let mut borrow: i16 = 1;
        for i in (0..32).rev() {
            let diff = (a[i] as i16) - borrow;
            if diff < 0 {
                a[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                a[i] = diff as u8;
                borrow = 0;
            }
        }
        a
    };
    let should_be_zero = scalar_add_mod_n(&n_minus_1, &one);
    if !is_zero(&should_be_zero) {
        return false;
    }

    // Test 3: (n-1) + 2 = 1 mod n
    let two_val = {
        let mut a = [0u8; 32];
        a[31] = 2;
        a
    };
    let should_be_one = scalar_add_mod_n(&n_minus_1, &two_val);
    if should_be_one[31] != 1 {
        return false;
    }
    // Check rest is zero
    if should_be_one.iter().take(31).any(|byte| *byte != 0) {
        return false;
    }

    true
}

/// Test: Multi-address derivation — derive_path_for_index matches derive_path
/// Verifies that derive_path_for_index(seed, 0) == derive_path(seed, KASPA_MAINNET_PATH)
/// and that different indices produce different keys.
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_multi_address_derivation() -> bool {
    let seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];

    // 1. derive_path_for_index(seed, 0) must match KASPA_MAINNET_PATH
    let key_idx0 = match derive_path_for_index(&seed, 0) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let key_mainnet = match derive_path(&seed, KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if key_idx0.private_key_bytes() != key_mainnet.private_key_bytes() {
        return false;
    }

    // 2. derive_account_key + derive_address_key must match derive_path_for_index
    let acct = match derive_account_key(&seed) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let key_idx0_via_acct = match derive_address_key(&acct, 0) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if key_idx0_via_acct.private_key_bytes() != key_idx0.private_key_bytes() {
        return false;
    }

    // 3. Different indices produce different keys
    let key_idx1 = match derive_address_key(&acct, 1) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if key_idx1.private_key_bytes() == key_idx0.private_key_bytes() {
        return false; // indices 0 and 1 must differ
    }

    // 4. find_address_index_for_pubkey works
    let pk0 = match key_idx0.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let pk1 = match key_idx1.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    if find_address_index_for_pubkey(&acct, &pk0) != Some((0, false)) {
        return false;
    }
    if find_address_index_for_pubkey(&acct, &pk1) != Some((1, false)) {
        return false;
    }

    // 5. Non-existent pubkey returns None
    let fake_pk = [0xFFu8; 32];
    if find_address_index_for_pubkey(&acct, &fake_pk).is_some() {
        return false;
    }

    true
}

/// Self-consistency: public-key child derivation must produce the same
/// pubkey as private-key child derivation at the same index.
///
/// Strategy — don't hard-code external BIP32 test vectors (typo risk).
/// Instead, derive an account-level private key (proven infrastructure),
/// export it to xpub, derive a child at index 5 via BOTH paths, and
/// verify pubkey + chain code + depth all match. Also verify that
/// hardened indices are correctly rejected on the public path (BIP32
/// public derivation is only defined for non-hardened indices).
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_derive_child_pub_consistency() -> bool {
    // Known seed (BIP39 "abandon × 11 + about" → BIP32 master seed bytes)
    let seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];
    // Account key at m/44'/111111'/0' (hardened, private-only)
    let acct = match derive_account_key(&seed) {
        Ok(k) => k,
        Err(_) => return false,
    };
    // Export as xpub for public-derivation path
    let acct_xpub = match acct.to_xpub() {
        Ok(x) => x,
        Err(_) => return false,
    };
    // Derive child at index 5 via BOTH paths — must agree
    let priv_child = match derive_child(&acct, 5) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let pub_child = match derive_child_pub(&acct_xpub, 5) {
        Ok(x) => x,
        Err(_) => return false,
    };
    // Compressed pubkey of private-derived must match the public-derived
    let priv_pk_compressed = match priv_child.public_key_compressed() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if priv_pk_compressed != pub_child.pubkey {
        return false;
    }
    if priv_child.chain_code != pub_child.chain_code {
        return false;
    }
    if priv_child.depth != pub_child.depth {
        return false;
    }

    // Also verify index 0 agrees (edge case — first address)
    let priv0 = match derive_child(&acct, 0) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let pub0 = match derive_child_pub(&acct_xpub, 0) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let priv0_pk = match priv0.public_key_compressed() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if priv0_pk != pub0.pubkey {
        return false;
    }
    if priv0.chain_code != pub0.chain_code {
        return false;
    }

    // Hardened indices MUST be rejected on the public path
    if derive_child_pub(&acct_xpub, 0x8000_0000).is_ok() {
        return false;
    }
    if derive_child_pub(&acct_xpub, HARDENED_BIT | 5).is_ok() {
        return false;
    }

    true
}

/// Run all BIP32 tests.
/// Returns (passed, total).
#[cfg(any(test, feature = "verbose-boot"))]
pub fn run_bip32_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 7u32;

    if test_vector1_master() {
        passed += 1;
    }
    if test_vector1_official() {
        passed += 1;
    }
    if test_vector1_child_hardened() {
        passed += 1;
    }
    if test_kaspa_path_derivation() {
        passed += 1;
    }
    if test_scalar_arithmetic() {
        passed += 1;
    }
    if test_multi_address_derivation() {
        passed += 1;
    }
    if test_derive_child_pub_consistency() {
        passed += 1;
    }

    (passed, total)
}

#[test]
fn bip32_vectors_pass() {
    let (passed, total) = run_bip32_tests();
    assert_eq!(passed, total);
}

#[test]
fn scalar_order_comparison_handles_boundaries() {
    let mut below = SECP256K1_ORDER;
    below[31] = below[31].wrapping_sub(1);
    assert!(is_less_than_order(&below));
    assert!(!is_less_than_order(&SECP256K1_ORDER));
    assert!(is_less_than_order(&[0u8; 32]));
    assert!(!super::scalar::is_valid_secret_scalar(&[0u8; 32]));
    assert!(!super::scalar::is_valid_secret_scalar(&SECP256K1_ORDER));
    assert!(super::scalar::is_valid_secret_scalar(&below));

    let mut two_equal_bits = [0u8; 32];
    two_equal_bits[3] = 0x04;
    two_equal_bits[19] = 0x04;
    assert!(
        !is_zero(&two_equal_bits),
        "non-zero bytes must not cancel in the zero test"
    );
}

#[test]
fn scalar_addition_reduces_order_without_secret_branch() {
    let mut order_minus_one = SECP256K1_ORDER;
    order_minus_one[31] = order_minus_one[31].wrapping_sub(1);
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(scalar_add_mod_n(&order_minus_one, &one), [0u8; 32]);
}

#[test]
fn hmac_and_sha_known_answers_cover_key_block_boundary_and_zeroization() {
    const SHA256_ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    const HMAC_128: [u8; 64] = [
        0x39, 0x53, 0x6a, 0x4e, 0xfe, 0xbd, 0x4c, 0xd8, 0x36, 0xd9, 0xae, 0x3a, 0xe6, 0x93, 0x62,
        0xa3, 0xc3, 0xa1, 0x29, 0x59, 0x4d, 0xab, 0x19, 0x1d, 0x17, 0xfc, 0x6f, 0xe5, 0x4e, 0xdb,
        0xb3, 0x18, 0xcc, 0x9b, 0x96, 0x8a, 0xf7, 0xfa, 0x8c, 0x1a, 0x8c, 0x8f, 0x3b, 0xc7, 0x8b,
        0x64, 0x86, 0x50, 0x84, 0x75, 0x1b, 0x73, 0x23, 0xf2, 0x70, 0x19, 0xda, 0x0f, 0x32, 0x3f,
        0xad, 0xc2, 0xfa, 0x61,
    ];
    const HMAC_129: [u8; 64] = [
        0x13, 0xa1, 0x4e, 0xdc, 0xcc, 0x65, 0x3a, 0x2a, 0x51, 0x39, 0xc0, 0xaf, 0xe9, 0xc1, 0xc5,
        0xd0, 0x03, 0xf0, 0xec, 0x64, 0xfa, 0x3a, 0xef, 0xf2, 0xb3, 0x27, 0xef, 0xb1, 0x3e, 0x95,
        0xe9, 0x6f, 0x4f, 0x53, 0x49, 0xc1, 0x55, 0x04, 0x4d, 0xcf, 0x09, 0x2e, 0x9f, 0x5b, 0x8f,
        0xbc, 0x9e, 0xfd, 0xb3, 0x72, 0xf4, 0x92, 0x26, 0xfd, 0x19, 0x4c, 0x69, 0xa9, 0x06, 0xfc,
        0x54, 0x24, 0x90, 0x81,
    ];

    assert_eq!(sha256(b"abc"), SHA256_ABC);
    assert_eq!(
        hmac_sha512(&[0xaau8; 128], b"KasSigner HMAC boundary"),
        HMAC_128,
    );
    assert_eq!(
        hmac_sha512(&[0xaau8; 129], b"KasSigner HMAC boundary"),
        HMAC_129,
    );
    assert_ne!(
        HMAC_128, HMAC_129,
        "128 and 129-byte keys take different RFC 2104 paths"
    );

    let mut secret = [0x5au8; 65];
    zeroize_buf(&mut secret);
    assert_eq!(secret, [0u8; 65]);
}

#[test]
fn address_pubkey_table_covers_receive_and_change_chains() {
    let seed = [0x5au8; 64];
    let account = derive_account_key(&seed).expect("account derivation");
    let table = AddrPubkeyTable::build(&account);
    assert_eq!(table.filled, (ADDR_SCAN_DEPTH as usize) * 2);

    let receive = derive_address_key(&account, 3)
        .expect("receive key")
        .public_key_x_only()
        .expect("receive public key");
    let change = derive_change_key(&account, 4)
        .expect("change key")
        .public_key_x_only()
        .expect("change public key");

    assert_eq!(table.find_by_pubkey(&receive), Some((3, false)));
    assert_eq!(table.find_by_pubkey(&change), Some((4, true)));
    assert_eq!(table.find_by_pubkey(&[0xff; 32]), None);
}

#[test]
fn extended_private_raw_roundtrip_and_raw_pubkey_helpers_are_covered() {
    let key = ExtendedPrivKey::from_parts([1u8; 32], [2u8; 32], 7);
    let raw = key.to_raw();
    let restored = ExtendedPrivKey::from_raw(&raw);
    assert_eq!(restored.private_key_bytes(), &[1u8; 32]);
    assert_eq!(restored.chain_code_bytes(), &[2u8; 32]);
    assert_eq!(restored.depth, 7);

    let compressed = compressed_pubkey_from_raw_key(&[1u8; 32]).expect("compressed key");
    let xonly = pubkey_from_raw_key(&[1u8; 32]).expect("x-only key");
    assert_eq!(&compressed[1..], xonly.as_slice());
    assert_eq!(pubkey_from_raw_key(&[0u8; 32]), Err(Bip32Error::CurveError));
}

#[test]
fn kaspa_bip32_path_constants_are_exact_hardened_indices() {
    assert_eq!(
        KASPA_MAINNET_PATH,
        &[0x8000_002c, 0x8001_b207, 0x8000_0000, 0, 0],
    );
    assert_eq!(
        KASPA_TESTNET_PATH,
        &[0x8000_002c, 0x8000_0001, 0x8000_0000, 0, 0],
    );
    assert_eq!(
        super::constants::KASPA_ACCOUNT_PATH,
        [0x8000_002c, 0x8001_b207, 0x8000_0000],
    );
}

#[test]
fn empty_derivation_paths_and_invalid_accounts_fail_closed() {
    let seed = [0x71u8; 64];
    assert!(matches!(
        derive_path(&seed, &[]),
        Err(Bip32Error::EmptyPath)
    ));

    let invalid = ExtendedPrivKey::from_parts([0u8; 32], [0u8; 32], 3);
    assert_eq!(find_address_index_for_pubkey(&invalid, &[0x42; 32]), None);
    let table = AddrPubkeyTable::build(&invalid);
    assert_eq!(table.filled, 0);
    assert_eq!(table.find_by_pubkey(&[0x42; 32]), None);
}

#[test]
fn public_child_derivation_rejects_malformed_parent_encodings() {
    let malformed_encoding = ExtendedPubKey {
        pubkey: [0xff; 33],
        chain_code: [0x11; 32],
        depth: 3,
    };
    assert!(matches!(
        derive_child_pub(&malformed_encoding, 0),
        Err(Bip32Error::CurveError)
    ));

    let mut off_curve = [0xff; 33];
    off_curve[0] = 0x02;
    let off_curve_parent = ExtendedPubKey {
        pubkey: off_curve,
        chain_code: [0x22; 32],
        depth: 3,
    };
    assert!(matches!(
        derive_child_pub(&off_curve_parent, 0),
        Err(Bip32Error::CurveError)
    ));
}

#[test]
fn extended_keys_zeroize_and_xonly_projection_are_exact() {
    let mut private = ExtendedPrivKey::from_parts([1u8; 32], [2u8; 32], 7);
    let mut public = private.to_xpub().expect("extended public key");
    let compressed = public.pubkey;
    let expected_x: [u8; 32] = compressed[1..33].try_into().expect("x-only slice");
    assert_eq!(public.x_only(), expected_x);
    assert_ne!(public.x_only(), [0u8; 32]);
    assert_ne!(public.x_only(), [1u8; 32]);

    public.zeroize();
    assert_eq!(public.pubkey, [0u8; 33]);
    assert_eq!(public.chain_code, [0u8; 32]);
    assert_eq!(public.depth, 0);

    private.zeroize();
    let raw = private.to_raw();
    assert_eq!(&raw[..64], &[0u8; 64]);
    assert_eq!(raw[64], 0);
}

#[test]
fn child_point_validation_rejects_identity_and_zeroizes_chain_code() {
    use k256::ProjectivePoint;

    let mut invalid_chain_code = [0x5au8; 32];
    assert_eq!(
        super::child::validate_child_point(&ProjectivePoint::IDENTITY, &mut invalid_chain_code),
        Err(Bip32Error::InvalidKey)
    );
    assert_eq!(invalid_chain_code, [0u8; 32]);

    let mut valid_chain_code = [0x6bu8; 32];
    assert_eq!(
        super::child::validate_child_point(&ProjectivePoint::GENERATOR, &mut valid_chain_code),
        Ok(())
    );
    assert_eq!(valid_chain_code, [0x6bu8; 32]);
}

#[test]
fn hd45_account_and_address_derivation_cover_valid_and_invalid_components() {
    let seed = [0x72u8; 64];
    let account = derive_multisig_account_key(&seed, 0).expect("45' account");
    assert_eq!(account.depth, 3);
    assert!(matches!(
        derive_multisig_account_key(&seed, 0x8000_0000),
        Err(Bip32Error::InvalidKey)
    ));

    let child = derive_multisig_address_key(&account, 2, 1, 7).expect("45' child");
    assert_eq!(child.depth, 6);
    assert!(child.public_key_compressed().is_ok());

    for (cosigner, chain, index) in [(0x8000_0000, 0, 0), (0, 2, 0), (0, 0, 0x8000_0000)] {
        assert!(matches!(
            derive_multisig_address_key(&account, cosigner, chain, index),
            Err(Bip32Error::InvalidKey)
        ));
    }
}

#[test]
fn resumable_account_derivation_matches_monolithic_account_key() {
    let seed = [0x42u8; 64];
    let expected = derive_account_key(&seed).expect("account key").to_raw();
    let mut work = AccountKeyDerivation::new(&seed).expect("resumable start");
    assert_eq!(work.completed_steps(), 0);
    assert!(!work.is_complete());
    assert!(!work.advance_one().expect("purpose child"));
    assert_eq!(work.completed_steps(), 1);
    assert!(!work.advance_one().expect("coin child"));
    assert_eq!(work.completed_steps(), 2);
    assert!(work.advance_one().expect("account child"));
    assert!(work.is_complete());
    assert!(work.advance_one().expect("completed work stays complete"));
    assert_eq!(work.finish().expect("finished account").to_raw(), expected);
}

#[test]
fn resumable_account_derivation_rejects_incomplete_finish() {
    let seed = [0x24u8; 64];
    let work = AccountKeyDerivation::new(&seed).expect("resumable start");
    assert!(matches!(work.finish(), Err(Bip32Error::InvalidKey)));
}

#[test]
fn multisig_account_nonzero_index_is_hardened_by_addition() {
    let seed = [0x6du8; 64];
    let account_number = 7u32;
    let derived = derive_multisig_account_key(&seed, account_number).expect("45' account 7");
    let expected_path = [0x8000_002d, 0x8001_b207, 0x8000_0007];
    let expected = derive_path(&seed, &expected_path).expect("explicit 45' path");
    assert_eq!(derived.to_raw(), expected.to_raw());
}
