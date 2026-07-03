// KasSee Web — Adaptor Signatures for Private Atomic Swaps
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// adaptor.rs — Schnorr adaptor signatures using k256 (BIP340-compatible).
//
// Adaptor signatures enable private atomic swaps where:
//   - Both TXs look like normal P2PK spends on-chain
//   - No hash preimage is revealed (unlike HTLC)
//   - No visible link between the two swap transactions
//   - Uses OpCheckSigFromStack (0xd7) on Kaspa TN12/Toccata
//
// Protocol:
//   Alice has secret t, publishes T = t*G (adaptor point).
//   Both parties create UTXOs with script: <their_pk> OP_CHECKSIGFROMSTACK
//
//   Bob creates adaptor sig on Alice's UTXO:
//     R' = k*G + T  (tweaked nonce)
//     e  = BIP340_challenge(R', Bob_pk, msg)
//     s' = k + e*bob_sk  (incomplete)
//     adaptor = (R', s')
//
//   Alice verifies the adaptor, then completes it:
//     s  = s' + t
//     completed = (R', s)  <- valid BIP340 signature
//
//   Alice broadcasts completed sig, claiming Bob's UTXO.
//   Bob extracts: t = s - s'
//   Bob completes his own adaptor on Alice's UTXO.
//
// BIP340 Schnorr specifics:
//   - Signature: 64 bytes = R.x (32) || s (32)
//   - Challenge: e = tagged_hash("BIP0340/challenge", R.x || P.x || msg)
//   - Verification: s*G == R + e*P
//   - x-only pubkeys (even Y parity enforced)

//! Adaptor signatures (BIP-340 Schnorr) for atomic swaps: secret and keypair
//! generation, adaptor sign/verify/complete, and secret extraction.

use k256::elliptic_curve::ops::{Neg, Reduce};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::ScalarPrimitive;
use k256::{ProjectivePoint, Scalar, Secp256k1, U256};
use sha2::{Digest, Sha256};

// BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
fn bip340_tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

// BIP340 challenge: e = tagged_hash("BIP0340/challenge", R.x || P.x || msg)
fn bip340_challenge(rx: &[u8; 32], px: &[u8; 32], msg: &[u8; 32]) -> Scalar {
    let mut data = [0u8; 96];
    data[0..32].copy_from_slice(rx);
    data[32..64].copy_from_slice(px);
    data[64..96].copy_from_slice(msg);
    let hash = bip340_tagged_hash(b"BIP0340/challenge", &data);
    <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
}

// Extract x-only pubkey bytes (32 bytes) from a ProjectivePoint.
// Negates the point if Y is odd (BIP340 even-Y convention).
#[allow(deprecated)]
pub fn point_to_xonly(point: &ProjectivePoint) -> ([u8; 32], bool) {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(false); // uncompressed: 04 || x || y
    let x_bytes: [u8; 32] = encoded
        .x()
        .expect("not identity")
        .as_slice()
        .try_into()
        .unwrap();
    let y_bytes: [u8; 32] = encoded
        .y()
        .expect("not identity")
        .as_slice()
        .try_into()
        .unwrap();
    let y_is_odd = y_bytes[31] & 1 == 1;
    (x_bytes, y_is_odd)
}

// Negate scalar if the corresponding point has odd Y (BIP340 convention).
fn ensure_even_y(secret: &Scalar, pubpoint: &ProjectivePoint) -> (Scalar, ProjectivePoint) {
    let (_, y_odd) = point_to_xonly(pubpoint);
    if y_odd {
        (secret.neg(), pubpoint.neg())
    } else {
        (*secret, *pubpoint)
    }
}

// Parse a 32-byte scalar from hex.
pub fn scalar_from_hex(hex: &str) -> Result<Scalar, String> {
    if hex.len() != 64 {
        return Err(format!("Expected 64 hex chars, got {}", hex.len()));
    }
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| format!("Bad hex: {}", e))?;
    let arr: [u8; 32] = bytes.try_into().unwrap();
    let primitive = ScalarPrimitive::<Secp256k1>::from_slice(&arr)
        .map_err(|e| format!("Invalid scalar: {}", e))?;
    Ok(Scalar::from(primitive))
}

// Serialize scalar to 32 bytes big-endian.
pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    let repr = s.to_bytes();
    repr.into()
}

// Derive x-only public key from a secret scalar.
pub fn pubkey_from_secret(sk: &Scalar) -> [u8; 32] {
    let pk_point = ProjectivePoint::GENERATOR * sk;
    let (xonly, _) = point_to_xonly(&pk_point);
    xonly
}

// Negate a scalar (additive inverse mod curve order).
pub fn negate_scalar(s: &Scalar) -> Scalar {
    s.neg()
}

// Parse a 32-byte x-only public key into a ProjectivePoint.
// Assumes even Y (BIP340 convention).
pub fn xonly_to_point(xonly: &[u8; 32]) -> Result<ProjectivePoint, String> {
    // Construct compressed key: 02 || x (even Y)
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..33].copy_from_slice(xonly);
    let pk = k256::PublicKey::from_sec1_bytes(&compressed)
        .map_err(|e| format!("Invalid x-only pubkey: {}", e))?;
    Ok(pk.to_projective())
}

// Generate a random adaptor secret.
// Returns (t_scalar, T_point_xonly_hex)
pub fn generate_adaptor_secret() -> Result<(Scalar, [u8; 32]), String> {
    let mut t_bytes = [0u8; 32];
    getrandom::getrandom(&mut t_bytes).map_err(|e| format!("RNG failed: {}", e))?;
    let t = scalar_from_hex(&hex::encode(t_bytes))?;
    let t_point = ProjectivePoint::GENERATOR * t;
    let (t_xonly, y_odd) = point_to_xonly(&t_point);
    // Negate t if T has odd Y so T always has even Y
    let t_final = if y_odd { t.neg() } else { t };
    Ok((t_final, t_xonly))
}

// BIP340 Schnorr sign (for PoC, both sides in browser).
// secret_key: 32-byte private key scalar
// msg: 32-byte message hash
// Returns: 64-byte signature (R.x || s)
pub fn bip340_sign(secret_key: &Scalar, msg: &[u8; 32]) -> Result<[u8; 64], String> {
    let pubpoint = ProjectivePoint::GENERATOR * secret_key;
    let (sk, _pk) = ensure_even_y(secret_key, &pubpoint);
    let (px, _) = point_to_xonly(&(ProjectivePoint::GENERATOR * sk));

    // Deterministic nonce: k = tagged_hash("BIP0340/aux", sk || msg)
    // Simplified: use random nonce for PoC
    let mut aux_bytes = [0u8; 32];
    getrandom::getrandom(&mut aux_bytes).map_err(|e| format!("RNG failed: {}", e))?;
    let nonce_hash = bip340_tagged_hash(b"BIP0340/nonce", &{
        let mut data = [0u8; 96];
        data[0..32].copy_from_slice(&scalar_to_bytes(&sk));
        data[32..64].copy_from_slice(&aux_bytes);
        data[64..96].copy_from_slice(msg);
        data
    });
    let k_full = <Scalar as Reduce<U256>>::reduce_bytes(&nonce_hash.into());

    let r_point = ProjectivePoint::GENERATOR * k_full;
    let (rx, r_odd) = point_to_xonly(&r_point);
    let k = if r_odd { k_full.neg() } else { k_full };

    let e = bip340_challenge(&rx, &px, msg);
    let s = k + e * sk;

    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&rx);
    sig[32..64].copy_from_slice(&scalar_to_bytes(&s));
    Ok(sig)
}

// BIP340 Schnorr verify.
pub fn bip340_verify(
    pubkey_xonly: &[u8; 32],
    msg: &[u8; 32],
    sig: &[u8; 64],
) -> Result<bool, String> {
    let rx: [u8; 32] = sig[0..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig[32..64].try_into().unwrap();

    let p = xonly_to_point(pubkey_xonly)?;
    let s = scalar_from_hex(&hex::encode(s_bytes))?;
    let e = bip340_challenge(&rx, pubkey_xonly, msg);

    // s*G == R + e*P
    let sg = ProjectivePoint::GENERATOR * s;
    let r = xonly_to_point(&rx)?;
    let rhs = r + p * e;

    let (sg_x, _) = point_to_xonly(&sg);
    let (rhs_x, _) = point_to_xonly(&rhs);
    Ok(sg_x == rhs_x)
}

// ─── Adaptor Signature Functions ───

// Create an adaptor signature.
//
// signer_sk: signer's secret key (scalar)
// msg: 32-byte message hash
// adaptor_point_T: the adaptor point (x-only, 32 bytes) shared by the secret holder
//
// Returns: (adaptor_sig: 64 bytes [R'.x || s'], nonce_k for extraction)
// The adaptor_sig is NOT a valid BIP340 signature.
// It becomes valid when s' is adjusted by the adaptor secret t.
pub fn create_adaptor_sig(
    signer_sk: &Scalar,
    msg: &[u8; 32],
    adaptor_point_xonly: &[u8; 32],
) -> Result<([u8; 64], Scalar), String> {
    let pubpoint = ProjectivePoint::GENERATOR * signer_sk;
    let (sk, _pk) = ensure_even_y(signer_sk, &pubpoint);
    let (px, _) = point_to_xonly(&(ProjectivePoint::GENERATOR * sk));

    let t_point = xonly_to_point(adaptor_point_xonly)?;

    // Random nonce k
    let mut k_bytes = [0u8; 32];
    getrandom::getrandom(&mut k_bytes).map_err(|e| format!("RNG failed: {}", e))?;
    let mut k = scalar_from_hex(&hex::encode(k_bytes))?;

    // BIP340: R' = k*G + T must have even Y.
    // But we also need to negate T's contribution. Since T has even Y (from generate_adaptor_secret),
    // negating R' means: -R' = -(k*G + T) = (-k)*G + (-T)
    // The completed sig will be s = s' + (-t) instead of s' + t
    // To keep the protocol simple, we instead just pick a new k if R' has odd Y.
    // Retry loop (statistically ~2 iterations max):
    while {
        let check = ProjectivePoint::GENERATOR * k + t_point;
        let (_, odd) = point_to_xonly(&check);
        odd
    } {
        let mut new_k_bytes = [0u8; 32];
        getrandom::getrandom(&mut new_k_bytes).map_err(|e| format!("RNG failed: {}", e))?;
        k = scalar_from_hex(&hex::encode(new_k_bytes))?;
    }

    // Now R' = k*G + T has even Y
    let r_prime_final = ProjectivePoint::GENERATOR * k + t_point;
    let (r_prime_x, _) = point_to_xonly(&r_prime_final);

    // Challenge: e = H(R'.x || P.x || msg)
    let e = bip340_challenge(&r_prime_x, &px, msg);

    // s' = k + e*sk (partial: to complete, add t)
    let s_prime = k + e * sk;

    let mut adaptor_sig = [0u8; 64];
    adaptor_sig[0..32].copy_from_slice(&r_prime_x);
    adaptor_sig[32..64].copy_from_slice(&scalar_to_bytes(&s_prime));

    Ok((adaptor_sig, k))
}

// Verify an adaptor signature.
//
// Checks that the adaptor becomes a valid BIP340 signature when the secret t is added.
// Verification: s'*G == R' - T + e*P
// (because s' = k + e*sk, and R' = k*G + T, so s'*G = k*G + e*P = R' - T + e*P)
pub fn verify_adaptor_sig(
    pubkey_xonly: &[u8; 32],
    msg: &[u8; 32],
    adaptor_sig: &[u8; 64],
    adaptor_point_xonly: &[u8; 32],
) -> Result<bool, String> {
    let r_prime_x: [u8; 32] = adaptor_sig[0..32].try_into().unwrap();
    let s_prime_bytes: [u8; 32] = adaptor_sig[32..64].try_into().unwrap();

    let p = xonly_to_point(pubkey_xonly)?;
    let t_point = xonly_to_point(adaptor_point_xonly)?;
    let s_prime = scalar_from_hex(&hex::encode(s_prime_bytes))?;

    let e = bip340_challenge(&r_prime_x, pubkey_xonly, msg);

    // s'*G should equal R' - T + e*P
    let sp_g = ProjectivePoint::GENERATOR * s_prime;
    let r_prime = xonly_to_point(&r_prime_x)?;
    let rhs = r_prime + t_point.neg() + p * e;

    let (lhs_x, _) = point_to_xonly(&sp_g);
    let (rhs_x, _) = point_to_xonly(&rhs);
    Ok(lhs_x == rhs_x)
}

// Complete an adaptor signature using the adaptor secret.
//
// adaptor_sig: (R'.x || s'), 64 bytes
// adaptor_secret: scalar t
//
// Returns: completed signature (R'.x || s), 64 bytes
// where s = s' + t, which is a valid BIP340 signature.
pub fn complete_adaptor_sig(adaptor_sig: &[u8; 64], adaptor_secret: &Scalar) -> [u8; 64] {
    let r_prime_x: [u8; 32] = adaptor_sig[0..32].try_into().unwrap();
    let s_prime_bytes: [u8; 32] = adaptor_sig[32..64].try_into().unwrap();

    // Parse s' and add t
    let s_prime_primitive =
        ScalarPrimitive::<Secp256k1>::from_slice(&s_prime_bytes).expect("valid scalar");
    let s_prime = Scalar::from(s_prime_primitive);
    let s = s_prime + adaptor_secret;

    let mut completed = [0u8; 64];
    completed[0..32].copy_from_slice(&r_prime_x);
    completed[32..64].copy_from_slice(&scalar_to_bytes(&s));
    completed
}

// Extract the adaptor secret from a completed signature and the original adaptor.
//
// completed_sig: (R'.x || s), 64 bytes (from on-chain TX)
// adaptor_sig: (R'.x || s'), 64 bytes (kept from exchange)
//
// Returns: t = s - s'
pub fn extract_adaptor_secret(
    completed_sig: &[u8; 64],
    adaptor_sig: &[u8; 64],
) -> Result<Scalar, String> {
    let s_bytes: [u8; 32] = completed_sig[32..64].try_into().unwrap();
    let s_prime_bytes: [u8; 32] = adaptor_sig[32..64].try_into().unwrap();

    let s = scalar_from_hex(&hex::encode(s_bytes))?;
    let s_prime = scalar_from_hex(&hex::encode(s_prime_bytes))?;

    Ok(s + s_prime.neg())
}
