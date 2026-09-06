use super::*;

#[test]
fn roundtrip() {
    // Generate a "recipient" keypair
    let priv_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let sk = SecretKey::from_slice(&priv_bytes).unwrap();
    let scalar: Scalar = *sk.to_nonzero_scalar();
    let pub_point = (ProjectivePoint::GENERATOR * scalar).to_affine();
    let pub_encoded = pub_point.to_encoded_point(false);
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&pub_encoded.as_bytes()[1..33]);

    // 44 bytes of "random" data for ephemeral key + nonce
    let mut rng = [0u8; 44];
    rng[0] = 0xAA;
    rng[1] = 0xBB;
    rng[2] = 0xCC;
    for (index, byte) in rng.iter_mut().enumerate().skip(3) {
        *byte = (index as u8).wrapping_mul(7);
    }

    let plaintext = b"KasSigner ECIES test message";
    let ct = encrypt(&xonly, plaintext, &rng).unwrap();

    // Verify wire format size
    assert_eq!(ct.len(), 33 + 12 + plaintext.len() + 16);

    // Decrypt
    let pt = decrypt(&priv_bytes, &ct).unwrap();
    assert_eq!(&pt, plaintext);
}

#[test]
fn wrong_key_fails() {
    let priv_bytes: [u8; 32] = [0x42; 32];
    let sk = SecretKey::from_slice(&priv_bytes).unwrap();
    let scalar: Scalar = *sk.to_nonzero_scalar();
    let pub_point = (ProjectivePoint::GENERATOR * scalar).to_affine();
    let pub_encoded = pub_point.to_encoded_point(false);
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&pub_encoded.as_bytes()[1..33]);

    let mut rng = [0u8; 44];
    for (index, byte) in rng.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(0x55);
    }

    let ct = encrypt(&xonly, b"secret", &rng).unwrap();

    // Try decrypting with a different key
    let wrong_key: [u8; 32] = [0x99; 32];
    assert!(decrypt(&wrong_key, &ct).is_err());
}

#[test]
fn malformed_key_and_ciphertext_boundaries_fail_closed() {
    assert_eq!(decrypt(&[1u8; 32], &[]), Err("ciphertext too short"));

    let mut invalid_ephemeral = [0u8; 61];
    invalid_ephemeral[0] = 0x02;
    invalid_ephemeral[1..33].fill(0xff);
    assert!(matches!(
        decrypt(&[1u8; 32], &invalid_ephemeral),
        Err("invalid ephemeral point") | Err("bad ephemeral pubkey")
    ));

    let rng = [0x5au8; 44];
    assert_eq!(
        encrypt(&[0xff; 32], b"message", &rng),
        Err("invalid recipient pubkey")
    );
}
