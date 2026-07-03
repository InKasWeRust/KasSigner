// ═══════════════════════════════════════════════════════════════════════
// ECIES — Elliptic Curve Integrated Encryption Scheme
// ═══════════════════════════════════════════════════════════════════════
//
// Encrypt with a secp256k1 public key, decrypt with the corresponding
// private key.  Uses:
//   - ECDH (k256 scalar * point) for shared secret
//   - BLAKE2B-256 for key derivation from shared secret
//   - AES-256-GCM for authenticated encryption
//
// Wire format:
//   [ephemeral_pubkey: 33 bytes compressed]
//   [nonce: 12 bytes]
//   [ciphertext + auth_tag: N + 16 bytes]
//
// Total overhead: 33 + 12 + 16 = 61 bytes over plaintext.

use k256::{
    SecretKey,
    elliptic_curve::sec1::ToEncodedPoint,
    Scalar,
    ProjectivePoint,
    AffinePoint,
};
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
};
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

type Blake2b256 = Blake2b<U32>;

/// Encrypt plaintext for a recipient identified by their 32-byte x-only pubkey.
/// Returns the ciphertext in wire format (33 + 12 + N + 16 bytes).
///
/// `rng_bytes` must be 44 bytes of random data:
///   - bytes [0..32]:  ephemeral private key scalar
///   - bytes [32..44]: AES-GCM nonce
///
/// The caller provides randomness so this function stays no_std-friendly
/// (the ESP32 RNG is accessed at the caller level).
pub fn encrypt(
    recipient_xonly: &[u8; 32],
    plaintext: &[u8],
    rng_bytes: &[u8; 44],
) -> Result<alloc::vec::Vec<u8>, &'static str> {
    // 1. Build ephemeral keypair from rng_bytes[0..32]
    let eph_sk = SecretKey::from_slice(&rng_bytes[..32])
        .map_err(|_| "bad ephemeral key")?;
    let eph_scalar: Scalar = *eph_sk.to_nonzero_scalar();
    let eph_pub_point = (ProjectivePoint::GENERATOR * eph_scalar).to_affine();

    // Compressed ephemeral public key (33 bytes: 0x02/0x03 + x)
    let eph_pub_encoded = eph_pub_point.to_encoded_point(true);
    let eph_pub_bytes: &[u8] = eph_pub_encoded.as_bytes(); // 33 bytes

    // 2. Reconstruct recipient public key from x-only (assume even Y)
    let recipient_point = lift_x(recipient_xonly)
        .ok_or("invalid recipient pubkey")?;

    // 3. ECDH: shared = eph_priv * recipient_pub
    let shared_point = (ProjectivePoint::from(recipient_point) * eph_scalar).to_affine();
    let shared_encoded = shared_point.to_encoded_point(false);
    let shared_x = &shared_encoded.as_bytes()[1..33]; // x-coordinate only

    // 4. Key derivation: aes_key = BLAKE2B-256(shared_x)
    let mut hasher = Blake2b256::new();
    hasher.update(b"KasSigner-ECIES-v1");
    hasher.update(shared_x);
    let aes_key: [u8; 32] = hasher.finalize().into();

    // 5. AES-256-GCM encrypt (detached: ciphertext in-place, tag returned separately)
    let nonce_bytes: &[u8; 12] = rng_bytes[32..44].try_into().unwrap();
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let mut ct_buf = alloc::vec![0u8; plaintext.len()];
    ct_buf.copy_from_slice(plaintext);
    let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut ct_buf)
        .map_err(|_| "encryption failed")?;

    // 6. Wire format: eph_pub(33) + nonce(12) + ciphertext(N) + tag(16)
    let mut out = alloc::vec::Vec::with_capacity(33 + 12 + ct_buf.len() + 16);
    out.extend_from_slice(eph_pub_bytes);
    out.extend_from_slice(nonce_bytes);
    out.extend_from_slice(&ct_buf);
    out.extend_from_slice(tag.as_slice());
    Ok(out)
}

/// Decrypt ciphertext that was encrypted with `encrypt()`.
///
/// `private_key` is the 32-byte secret scalar corresponding to the
/// x-only pubkey used as `recipient_xonly` during encryption.
pub fn decrypt(
    private_key: &[u8; 32],
    ciphertext_wire: &[u8],
) -> Result<alloc::vec::Vec<u8>, &'static str> {
    // Minimum: 33 (eph_pub) + 12 (nonce) + 16 (tag) = 61 bytes
    if ciphertext_wire.len() < 61 {
        return Err("ciphertext too short");
    }

    // 1. Parse wire format
    let eph_pub_bytes = &ciphertext_wire[..33];
    let nonce_bytes = &ciphertext_wire[33..45];

    // 2. Reconstruct ephemeral public key
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;
    let eph_encoded = EncodedPoint::from_bytes(eph_pub_bytes)
        .map_err(|_| "bad ephemeral pubkey")?;
    let eph_point_opt = AffinePoint::from_encoded_point(&eph_encoded);
    if (!eph_point_opt.is_some()).into() {
        return Err("invalid ephemeral point");
    }
    let eph_point: AffinePoint = eph_point_opt.expect("checked is_some");

    // 3. ECDH: shared = priv * eph_pub
    let sk = SecretKey::from_slice(private_key)
        .map_err(|_| "bad private key")?;
    let priv_scalar: Scalar = *sk.to_nonzero_scalar();
    let shared_point = (ProjectivePoint::from(eph_point) * priv_scalar).to_affine();
    let shared_encoded = shared_point.to_encoded_point(false);
    let shared_x = &shared_encoded.as_bytes()[1..33];

    // 4. Key derivation (same as encrypt)
    let mut hasher = Blake2b256::new();
    hasher.update(b"KasSigner-ECIES-v1");
    hasher.update(shared_x);
    let aes_key: [u8; 32] = hasher.finalize().into();

    // 5. AES-256-GCM decrypt (detached: split ciphertext and tag)
    let encrypted = &ciphertext_wire[45..];
    if encrypted.len() < 16 {
        return Err("ciphertext too short for tag");
    }
    let ct_len = encrypted.len() - 16;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let tag = GenericArray::from_slice(&encrypted[ct_len..]);
    let mut buf = alloc::vec![0u8; ct_len];
    buf.copy_from_slice(&encrypted[..ct_len]);
    cipher.decrypt_in_place_detached(nonce, b"", &mut buf, tag)
        .map_err(|_| "decryption failed")?;

    Ok(buf)
}

/// Reconstruct AffinePoint from x-only 32 bytes (even Y assumed).
fn lift_x(x_bytes: &[u8; 32]) -> Option<AffinePoint> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..33].copy_from_slice(x_bytes);

    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;
    let encoded = EncodedPoint::from_bytes(compressed).ok()?;
    let point = AffinePoint::from_encoded_point(&encoded);
    if point.is_some().into() {
        Some(point.expect("verified is_some"))
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        // Generate a "recipient" keypair
        let priv_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let sk = SecretKey::from_slice(&priv_bytes).unwrap();
        let scalar: Scalar = *sk.to_nonzero_scalar();
        let pub_point = (ProjectivePoint::GENERATOR * scalar).to_affine();
        let pub_encoded = pub_point.to_encoded_point(false);
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&pub_encoded.as_bytes()[1..33]);

        // 44 bytes of "random" data for ephemeral key + nonce
        let mut rng = [0u8; 44];
        rng[0] = 0xAA; rng[1] = 0xBB; rng[2] = 0xCC;
        for i in 3..44 { rng[i] = (i as u8).wrapping_mul(7); }

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
        for i in 0..44 { rng[i] = (i as u8).wrapping_add(0x55); }

        let ct = encrypt(&xonly, b"secret", &rng).unwrap();

        // Try decrypting with a different key
        let wrong_key: [u8; 32] = [0x99; 32];
        assert!(decrypt(&wrong_key, &ct).is_err());
    }
}
