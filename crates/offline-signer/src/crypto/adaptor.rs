//! Transaction-bound BIP340 adaptor-signature primitives for Private Swap v2.
//!
//! Private signing lives exclusively in the offline signer. The browser receives
//! only public adaptor arithmetic (verification/completion/extraction) and never
//! receives a claim private key. A pre-signature is bound to the exact 32-byte
//! Kaspa transaction sighash supplied by the caller after transaction parsing.

use k256::elliptic_curve::{
    group::Group,
    ops::{Neg, Reduce},
    sec1::ToEncodedPoint,
    ScalarPrimitive,
};
use k256::{ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptorError {
    InvalidPrivateKey,
    InvalidAdaptorPoint,
    InvalidNonce,
    InvalidPreSignature,
    InvalidCompletedSignature,
    InvalidHostContribution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptorPreSignature {
    pub bytes: [u8; 64],
    /// +1 when false, -1 when true. Completion adds q*t to s'.
    pub negated: bool,
}

const NONCE_DOMAIN: &[u8] = b"KasSigner Private Swap Adaptor Nonce v2\0";
const HOST_DOMAIN: &[u8] = b"KasSigner Private Swap Anti-Klepto v2\0";

pub fn adaptor_point_from_secret(secret: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), AdaptorError> {
    let raw = scalar_from_canonical(secret).ok_or(AdaptorError::InvalidPrivateKey)?;
    if bool::from(raw.is_zero()) {
        return Err(AdaptorError::InvalidPrivateKey);
    }
    let point = ProjectivePoint::GENERATOR * raw;
    let (x, odd) = point_x_and_parity(&point).ok_or(AdaptorError::InvalidAdaptorPoint)?;
    let normalized = if odd { raw.neg() } else { raw };
    Ok((normalized.to_bytes().into(), x))
}

/// Return the device's committed base nonce point before the host reveals its
/// nonce contribution. The point is compressed and may have either parity.
pub fn adaptor_base_nonce_point(
    private_key: &[u8; 32],
    message: &[u8; 32],
    adaptor_point_x: &[u8; 32],
    session_id: &[u8; 16],
    aux_rand: &[u8; 32],
) -> Result<[u8; 33], AdaptorError> {
    let (secret, public_x) = normalized_secret_and_public_x(private_key)?;
    xonly_to_point(adaptor_point_x)?;
    let nonce = base_nonce_scalar(
        &secret,
        &public_x,
        message,
        adaptor_point_x,
        session_id,
        aux_rand,
    )?;
    let point = ProjectivePoint::GENERATOR * nonce;
    let encoded = point.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    Ok(out)
}

/// Finalize a transaction-bound adaptor pre-signature after the host reveals
/// the secret committed to in the first protocol round.
pub fn create_adaptor_presignature(
    private_key: &[u8; 32],
    message: &[u8; 32],
    adaptor_point_x: &[u8; 32],
    session_id: &[u8; 16],
    aux_rand: &[u8; 32],
    host_secret: &[u8; 32],
) -> Result<AdaptorPreSignature, AdaptorError> {
    let (secret, public_x) = normalized_secret_and_public_x(private_key)?;
    let t_point = xonly_to_point(adaptor_point_x)?;
    let base_nonce = base_nonce_scalar(
        &secret,
        &public_x,
        message,
        adaptor_point_x,
        session_id,
        aux_rand,
    )?;
    let base_point = ProjectivePoint::GENERATOR * base_nonce;
    let base_encoded = base_point.to_affine().to_encoded_point(true);
    let mut base_nonce_point = [0u8; 33];
    base_nonce_point.copy_from_slice(base_encoded.as_bytes());
    let host = host_scalar(
        session_id,
        host_secret,
        &public_x,
        &base_nonce_point,
        message,
        adaptor_point_x,
    )?;
    let combined = nonzero_scalar_sum(base_nonce, host, AdaptorError::InvalidHostContribution)?;

    let candidate = ProjectivePoint::GENERATOR * combined + t_point;
    let (rx, odd) = point_x_and_parity(&candidate).ok_or(AdaptorError::InvalidNonce)?;
    // If the candidate has odd Y, negate the entire adaptor nonce expression:
    // R' = -(K*G + T), s' = -K + e*x, completion uses s = s' - t.
    let signed_nonce = if odd { combined.neg() } else { combined };
    let challenge = challenge(&rx, &public_x, message);
    let response = signed_nonce + challenge * secret;
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&rx);
    bytes[32..].copy_from_slice(&response.to_bytes());
    let presig = AdaptorPreSignature {
        bytes,
        negated: odd,
    };
    verify_adaptor_presignature(&public_x, message, &presig, adaptor_point_x)?;
    Ok(presig)
}

pub fn complete_adaptor_presignature(
    presig: &AdaptorPreSignature,
    adaptor_secret: &[u8; 32],
) -> Result<[u8; 64], AdaptorError> {
    let t = scalar_from_canonical(adaptor_secret).ok_or(AdaptorError::InvalidAdaptorPoint)?;
    if bool::from(t.is_zero()) {
        return Err(AdaptorError::InvalidAdaptorPoint);
    }
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&presig.bytes[32..]);
    let s_prime = scalar_from_canonical(&s_bytes).ok_or(AdaptorError::InvalidPreSignature)?;
    let completed = if presig.negated {
        s_prime - t
    } else {
        s_prime + t
    };
    let mut signature = presig.bytes;
    signature[32..].copy_from_slice(&completed.to_bytes());
    Ok(signature)
}

pub fn verify_adaptor_presignature(
    public_x: &[u8; 32],
    message: &[u8; 32],
    presig: &AdaptorPreSignature,
    adaptor_point_x: &[u8; 32],
) -> Result<(), AdaptorError> {
    let p = xonly_to_point(public_x)?;
    let t = xonly_to_point(adaptor_point_x)?;
    let r = xonly_to_point(
        presig.bytes[..32]
            .try_into()
            .map_err(|_| AdaptorError::InvalidPreSignature)?,
    )?;
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&presig.bytes[32..]);
    let s = scalar_from_canonical(&s_bytes).ok_or(AdaptorError::InvalidPreSignature)?;
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&presig.bytes[..32]);
    let e = challenge(&rx, public_x, message);
    let signed_t = if presig.negated { t.neg() } else { t };
    let lhs = ProjectivePoint::GENERATOR * s;
    let rhs = r + signed_t.neg() + p * e;
    if points_equal(&lhs, &rhs) {
        Ok(())
    } else {
        Err(AdaptorError::InvalidPreSignature)
    }
}

/// Host-side anti-klepto verification relation. This is public-only math but
/// lives here as a reference implementation for native tests.
pub fn verify_host_nonce_relation(
    public_x: &[u8; 32],
    message: &[u8; 32],
    adaptor_point_x: &[u8; 32],
    session_id: &[u8; 16],
    host_secret: &[u8; 32],
    base_nonce_point: &[u8; 33],
    presig: &AdaptorPreSignature,
) -> Result<(), AdaptorError> {
    let base = public_key_to_point(base_nonce_point)?;
    let t = xonly_to_point(adaptor_point_x)?;
    let r = xonly_to_point(
        presig.bytes[..32]
            .try_into()
            .map_err(|_| AdaptorError::InvalidPreSignature)?,
    )?;
    let host = host_scalar(
        session_id,
        host_secret,
        public_x,
        base_nonce_point,
        message,
        adaptor_point_x,
    )?;
    let expected = base + ProjectivePoint::GENERATOR * host;
    let signed_t = if presig.negated { t.neg() } else { t };
    let recovered = if presig.negated {
        (r + signed_t.neg()).neg()
    } else {
        r + signed_t.neg()
    };
    if points_equal(&expected, &recovered) {
        Ok(())
    } else {
        Err(AdaptorError::InvalidHostContribution)
    }
}

fn base_nonce_scalar(
    secret: &Scalar,
    public_x: &[u8; 32],
    message: &[u8; 32],
    adaptor_point_x: &[u8; 32],
    session_id: &[u8; 16],
    aux_rand: &[u8; 32],
) -> Result<Scalar, AdaptorError> {
    let mut hasher = Sha256::new();
    hasher.update(NONCE_DOMAIN);
    hasher.update(secret.to_bytes());
    hasher.update(public_x);
    hasher.update(message);
    hasher.update(adaptor_point_x);
    hasher.update(session_id);
    hasher.update(aux_rand);
    let digest: [u8; 32] = hasher.finalize().into();
    nonzero_reduced_scalar(&digest, AdaptorError::InvalidNonce)
}

fn host_scalar(
    session_id: &[u8; 16],
    host_secret: &[u8; 32],
    public_x: &[u8; 32],
    base_nonce_point: &[u8; 33],
    message: &[u8; 32],
    adaptor_point_x: &[u8; 32],
) -> Result<Scalar, AdaptorError> {
    let mut hasher = Sha256::new();
    hasher.update(HOST_DOMAIN);
    hasher.update(session_id);
    hasher.update(host_secret);
    hasher.update(public_x);
    hasher.update(base_nonce_point);
    hasher.update(message);
    hasher.update(adaptor_point_x);
    let digest: [u8; 32] = hasher.finalize().into();
    nonzero_reduced_scalar(&digest, AdaptorError::InvalidHostContribution)
}

fn nonzero_reduced_scalar(digest: &[u8; 32], error: AdaptorError) -> Result<Scalar, AdaptorError> {
    let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&(*digest).into());
    if bool::from(scalar.is_zero()) {
        Err(error)
    } else {
        Ok(scalar)
    }
}

fn nonzero_scalar_sum(
    left: Scalar,
    right: Scalar,
    error: AdaptorError,
) -> Result<Scalar, AdaptorError> {
    let sum = left + right;
    if bool::from(sum.is_zero()) {
        Err(error)
    } else {
        Ok(sum)
    }
}

fn normalized_secret_and_public_x(
    private_key: &[u8; 32],
) -> Result<(Scalar, [u8; 32]), AdaptorError> {
    let primitive = ScalarPrimitive::<k256::Secp256k1>::from_slice(private_key)
        .map_err(|_| AdaptorError::InvalidPrivateKey)?;
    let raw = Scalar::from(primitive);
    if bool::from(raw.is_zero()) {
        return Err(AdaptorError::InvalidPrivateKey);
    }
    let encoded = (ProjectivePoint::GENERATOR * raw)
        .to_affine()
        .to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let normalized = if bytes[0] == 0x03 { raw.neg() } else { raw };
    let mut x = [0u8; 32];
    x.copy_from_slice(&bytes[1..]);
    Ok((normalized, x))
}

fn xonly_to_point(x: &[u8; 32]) -> Result<ProjectivePoint, AdaptorError> {
    let mut encoded = [0u8; 33];
    encoded[0] = 0x02;
    encoded[1..].copy_from_slice(x);
    public_key_to_point(&encoded).map_err(|_| AdaptorError::InvalidAdaptorPoint)
}

fn public_key_to_point(encoded: &[u8; 33]) -> Result<ProjectivePoint, AdaptorError> {
    k256::PublicKey::from_sec1_bytes(encoded)
        .map(|key| key.to_projective())
        .map_err(|_| AdaptorError::InvalidNonce)
}

fn challenge(rx: &[u8; 32], px: &[u8; 32], message: &[u8; 32]) -> Scalar {
    let mut data = [0u8; 96];
    data[..32].copy_from_slice(rx);
    data[32..64].copy_from_slice(px);
    data[64..].copy_from_slice(message);
    let tag = Sha256::digest(b"BIP0340/challenge");
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    hasher.update(data);
    let digest: [u8; 32] = hasher.finalize().into();
    <Scalar as Reduce<U256>>::reduce_bytes(&digest.into())
}

fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Scalar> {
    ScalarPrimitive::<k256::Secp256k1>::from_slice(bytes)
        .ok()
        .map(Scalar::from)
}

fn point_x_and_parity(point: &ProjectivePoint) -> Option<([u8; 32], bool)> {
    if bool::from(point.is_identity()) {
        return None;
    }
    let encoded = point.to_affine().to_encoded_point(false);
    let x = encoded.x()?;
    let y = encoded.y()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x);
    Some((out, y[31] & 1 == 1))
}

fn points_equal(left: &ProjectivePoint, right: &ProjectivePoint) -> bool {
    left.to_affine() == right.to_affine()
}

#[cfg(test)]
#[path = "unit_tests/adaptor_tests.rs"]
mod adaptor_tests;
