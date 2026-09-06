//! Public-only adaptor-signature arithmetic for Private Swap v2.
//!
//! This module never creates an adaptor pre-signature and never handles a
//! claim private key. KasSee may verify pre-signatures, verify the host nonce
//! contribution, complete a stored pre-signature after the adaptor secret is
//! revealed on-chain, and extract that public secret from a completed signature.

use k256::elliptic_curve::{
    ops::{Neg, Reduce},
    sec1::ToEncodedPoint,
    ScalarPrimitive,
};
use k256::{ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};

const HOST_DOMAIN: &[u8] = b"KasSigner Private Swap Anti-Klepto v2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdaptorPreSignature {
    pub bytes: [u8; 64],
    pub negated: bool,
}

pub(crate) fn verify_presignature(
    public_x: &[u8; 32],
    message: &[u8; 32],
    presig: &AdaptorPreSignature,
    adaptor_point_x: &[u8; 32],
) -> Result<(), String> {
    let p = xonly_to_point(public_x)?;
    let t = xonly_to_point(adaptor_point_x)?;
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&presig.bytes[..32]);
    let r = xonly_to_point(&rx)?;
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&presig.bytes[32..]);
    let s = scalar_from_canonical(&s_bytes)
        .ok_or_else(|| "invalid adaptor response scalar".to_string())?;
    let e = challenge(&rx, public_x, message);
    let signed_t = if presig.negated { t.neg() } else { t };
    let lhs = ProjectivePoint::GENERATOR * s;
    let rhs = r + signed_t.neg() + p * e;
    points_equal(&lhs, &rhs)
        .then_some(())
        .ok_or_else(|| "invalid adaptor pre-signature".to_string())
}

pub(crate) fn verify_host_nonce_relation(
    public_x: &[u8; 32],
    message: &[u8; 32],
    adaptor_point_x: &[u8; 32],
    session_id: &[u8; 16],
    host_secret: &[u8; 32],
    base_nonce_point: &[u8; 33],
    presig: &AdaptorPreSignature,
) -> Result<(), String> {
    let base = public_key_to_point(base_nonce_point)?;
    let t = xonly_to_point(adaptor_point_x)?;
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&presig.bytes[..32]);
    let r = xonly_to_point(&rx)?;
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
    points_equal(&expected, &recovered)
        .then_some(())
        .ok_or_else(|| "adaptor nonce does not include host contribution".to_string())
}

pub(crate) fn complete_presignature(
    presig: &AdaptorPreSignature,
    adaptor_secret: &[u8; 32],
) -> Result<[u8; 64], String> {
    let t = scalar_from_canonical(adaptor_secret)
        .ok_or_else(|| "invalid adaptor secret".to_string())?;
    if bool::from(t.is_zero()) {
        return Err("invalid adaptor secret".into());
    }
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&presig.bytes[32..]);
    let s_prime = scalar_from_canonical(&s_bytes)
        .ok_or_else(|| "invalid adaptor response scalar".to_string())?;
    let completed = if presig.negated {
        s_prime - t
    } else {
        s_prime + t
    };
    let mut out = presig.bytes;
    out[32..].copy_from_slice(&completed.to_bytes());
    Ok(out)
}

pub(crate) fn extract_secret(
    completed: &[u8; 64],
    presig: &AdaptorPreSignature,
) -> Result<[u8; 32], String> {
    if completed[..32] != presig.bytes[..32] {
        return Err("completed signature nonce does not match adaptor pre-signature".into());
    }
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&completed[32..]);
    let mut sp_bytes = [0u8; 32];
    sp_bytes.copy_from_slice(&presig.bytes[32..]);
    let s = scalar_from_canonical(&s_bytes)
        .ok_or_else(|| "invalid completed signature scalar".to_string())?;
    let sp = scalar_from_canonical(&sp_bytes)
        .ok_or_else(|| "invalid adaptor response scalar".to_string())?;
    let delta = s - sp;
    if bool::from(delta.is_zero()) {
        return Err("extracted adaptor secret is zero".into());
    }
    let secret = if presig.negated { delta.neg() } else { delta };
    Ok(secret.to_bytes().into())
}

pub(crate) fn verify_bip340(
    public_x: &[u8; 32],
    message: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), String> {
    let p = xonly_to_point(public_x)?;
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&signature[..32]);
    let r = xonly_to_point(&rx)?;
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let s =
        scalar_from_canonical(&s_bytes).ok_or_else(|| "invalid signature scalar".to_string())?;
    let e = challenge(&rx, public_x, message);
    let candidate = ProjectivePoint::GENERATOR * s - p * e;
    if !points_equal(&candidate, &r) {
        return Err("invalid completed BIP340 signature".into());
    }
    let encoded = candidate.to_affine().to_encoded_point(false);
    let y = encoded
        .y()
        .ok_or_else(|| "invalid signature nonce".to_string())?;
    if y[31] & 1 != 0 {
        return Err("BIP340 nonce has odd Y".into());
    }
    Ok(())
}

fn host_scalar(
    session_id: &[u8; 16],
    host_secret: &[u8; 32],
    public_x: &[u8; 32],
    base_nonce_point: &[u8; 33],
    message: &[u8; 32],
    adaptor_point_x: &[u8; 32],
) -> Result<Scalar, String> {
    let mut hasher = Sha256::new();
    hasher.update(HOST_DOMAIN);
    hasher.update(session_id);
    hasher.update(host_secret);
    hasher.update(public_x);
    hasher.update(base_nonce_point);
    hasher.update(message);
    hasher.update(adaptor_point_x);
    let digest: [u8; 32] = hasher.finalize().into();
    let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&digest.into());
    if bool::from(scalar.is_zero()) {
        Err("invalid host contribution".into())
    } else {
        Ok(scalar)
    }
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

fn xonly_to_point(x: &[u8; 32]) -> Result<ProjectivePoint, String> {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    bytes[1..].copy_from_slice(x);
    public_key_to_point(&bytes)
}
fn public_key_to_point(bytes: &[u8; 33]) -> Result<ProjectivePoint, String> {
    k256::PublicKey::from_sec1_bytes(bytes)
        .map(|p| p.to_projective())
        .map_err(|_| "invalid secp256k1 point".into())
}
fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Scalar> {
    ScalarPrimitive::<k256::Secp256k1>::from_slice(bytes)
        .ok()
        .map(Scalar::from)
}
fn points_equal(a: &ProjectivePoint, b: &ProjectivePoint) -> bool {
    a.to_affine() == b.to_affine()
}

#[cfg(test)]
mod unit_tests;
