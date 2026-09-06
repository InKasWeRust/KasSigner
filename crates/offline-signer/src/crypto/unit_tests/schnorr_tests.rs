use super::*;
#[cfg(test)]
use alloc::string::ToString;
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};

// Tests
// ═══════════════════════════════════════════════════════════════════════

/// Test: sign and verify roundtrip
#[cfg(any(test, feature = "verbose-boot"))]
/// Test: sign then verify succeeds.
pub fn test_sign_verify_roundtrip() -> bool {
    // Test private key (DO NOT use in production)
    let privkey: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ];

    // Test message (32 bytes)
    let message: [u8; 32] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xAA, 0xBB,
    ];

    // Sign
    let sig = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verify that the signature is 64 bytes
    if sig.bytes.len() != 64 {
        return false;
    }

    // Get x-only public key
    let sk = match SecretKey::from_slice(&privkey) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let pk_point = pk.to_encoded_point(true);
    let mut pubkey_x = [0u8; 32];
    pubkey_x.copy_from_slice(&pk_point.as_bytes()[1..33]);

    // Verify signature
    schnorr_verify(&pubkey_x, &message, &sig).is_ok()
}

/// Test: deterministic signing (same key + message = same signature)
#[cfg(any(test, feature = "verbose-boot"))]
/// Test: deterministic signing (same key + message = same signature).
pub fn test_deterministic_signature() -> bool {
    let privkey: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];

    let message = [0x42u8; 32];

    let sig1 = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let sig2 = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Must be identical (deterministic nonce)
    sig1.bytes == sig2.bytes
}

/// Test: invalid signature must fail verification
#[cfg(any(test, feature = "verbose-boot"))]
/// Test: invalid signature must fail verification.
pub fn test_invalid_signature_fails() -> bool {
    let privkey: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ];

    let message = [0x55u8; 32];
    let wrong_message = [0x66u8; 32];

    let sig = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Get pubkey
    let sk = match SecretKey::from_slice(&privkey) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let pk_point = pk.to_encoded_point(true);
    let mut pubkey_x = [0u8; 32];
    pubkey_x.copy_from_slice(&pk_point.as_bytes()[1..33]);

    // Verify with correct message → OK
    if schnorr_verify(&pubkey_x, &message, &sig).is_err() {
        return false;
    }

    // Verify with incorrect message → must fail
    schnorr_verify(&pubkey_x, &wrong_message, &sig).is_err()
}

/// Test: sign with BIP32-derived key
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_sign_with_bip32_key() -> bool {
    use crate::derivation::bip32;
    use crate::derivation::bip39;

    // Generate seed from known mnemonic
    let entropy = [0u8; 16]; // "abandon...about"
    let mnemonic = bip39::mnemonic_from_entropy_12(&entropy);
    let seed = bip39::seed_from_mnemonic_12(&mnemonic, "");

    // Derive Kaspa key
    let key = match bip32::derive_path(&seed.bytes, bip32::KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // x-only pubkey
    let pubkey_x = match key.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Sign a dummy sighash
    let sighash = [0xABu8; 32];
    let sig = match schnorr_sign(key.private_key_bytes(), &sighash) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verify
    schnorr_verify(&pubkey_x, &sighash, &sig).is_ok()
}

/// Runs all Schnorr tests.
/// Returns (passed, total).
#[cfg(any(test, feature = "verbose-boot"))]
pub fn run_schnorr_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 4u32;

    if test_sign_verify_roundtrip() {
        passed += 1;
    }
    if test_deterministic_signature() {
        passed += 1;
    }
    if test_invalid_signature_fails() {
        passed += 1;
    }
    if test_sign_with_bip32_key() {
        passed += 1;
    }

    (passed, total)
}

#[test]
fn schnorr_vectors_pass() {
    let (passed, total) = run_schnorr_tests();
    assert_eq!(passed, total);
}

#[test]
fn schnorr_accessors_errors_and_known_answer_are_covered() {
    let mut bytes = [0u8; 64];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let signature = SchnorrSignature { bytes };
    assert_eq!(signature.r_bytes(), &bytes[..32]);
    assert_eq!(signature.s_bytes(), &bytes[32..]);

    assert_eq!(
        SchnorrError::InvalidPrivateKey.to_string(),
        "invalid BIP340 private key"
    );
    assert_eq!(
        SchnorrError::SigningFailed.to_string(),
        "BIP340 signing failed"
    );
    assert_eq!(
        SchnorrError::InvalidSignature.to_string(),
        "invalid BIP340 public key or signature"
    );

    assert!(bip340_known_answer(&BIP340_VECTOR0_EXPECTED));

    let mut wrong_signature = BIP340_VECTOR0_EXPECTED;
    wrong_signature.signature[0] ^= 1;
    assert!(!bip340_known_answer(&wrong_signature));

    let mut wrong_public_key = BIP340_VECTOR0_EXPECTED;
    wrong_public_key.public_key_x[0] ^= 1;
    assert!(!bip340_known_answer(&wrong_public_key));
    assert_eq!(
        schnorr_sign(&[0u8; 32], &[0u8; 32]),
        Err(SchnorrError::InvalidPrivateKey)
    );
    assert_eq!(
        schnorr_verify(&[0u8; 32], &[0u8; 32], &signature),
        Err(SchnorrError::InvalidSignature)
    );
    assert!(!known_answer_matches(
        Err(SchnorrError::SigningFailed),
        &BIP340_VECTOR0_EXPECTED,
    ));
}
