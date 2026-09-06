//! BIP340-compatible nonce contribution for KasSee anti-klepto signing.
//!
//! This module does not define a new signature algorithm. It transforms a
//! provisional, valid BIP340 signature into another valid BIP340 signature by
//! adding a host-contributed scalar to the provisional nonce and recomputing
//! the challenge/response. The final 64-byte signature is ordinary BIP340.

use k256::elliptic_curve::{
    group::Group,
    ops::{Neg, Reduce},
    sec1::ToEncodedPoint,
};
use k256::{ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};

use super::schnorr::{SchnorrError, SchnorrSignature};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AntiKleptoError {
    InvalidPrivateKey,
    InvalidProvisionalSignature,
    InvalidHostContribution,
    InvalidNoncePoint,
    InvalidFinalSignature,
}

pub fn provisional_nonce_point(signature: &SchnorrSignature) -> [u8; 33] {
    // BIP340 signatures normalize R to even Y, therefore the compressed point
    // is unambiguously 0x02 || R.x.
    let mut point = [0u8; 33];
    point[0] = 0x02;
    point[1..].copy_from_slice(&signature.r_bytes());
    point
}

pub fn host_scalar(
    session_id: &[u8; shared_signer::anti_klepto::SESSION_ID_LEN],
    host_secret: &[u8; 32],
    input_index: u32,
    signature_slot: u8,
    public_key: &[u8; 33],
    nonce_point: &[u8; 33],
) -> Result<Scalar, AntiKleptoError> {
    let material = shared_signer::anti_klepto::host_scalar_material(
        session_id,
        host_secret,
        input_index,
        signature_slot,
        public_key,
        nonce_point,
    );
    nonzero_host_scalar(&material)
}

fn nonzero_host_scalar(material: &[u8; 32]) -> Result<Scalar, AntiKleptoError> {
    let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&(*material).into());
    if bool::from(scalar.is_zero()) {
        Err(AntiKleptoError::InvalidHostContribution)
    } else {
        Ok(scalar)
    }
}

fn nonzero_nonce_sum(left: Scalar, right: Scalar) -> Result<Scalar, AntiKleptoError> {
    let sum = left + right;
    if bool::from(sum.is_zero()) {
        Err(AntiKleptoError::InvalidHostContribution)
    } else {
        Ok(sum)
    }
}

pub fn tweak_provisional_signature(
    private_key: &[u8; 32],
    message: &[u8; 32],
    provisional: &SchnorrSignature,
    session_id: &[u8; shared_signer::anti_klepto::SESSION_ID_LEN],
    host_secret: &[u8; 32],
    input_index: u32,
    signature_slot: u8,
) -> Result<SchnorrSignature, AntiKleptoError> {
    let (secret, public_x) = normalized_secret_and_public_x(private_key)?;
    let public_key = canonical_public_key(&public_x);
    let nonce_point = provisional_nonce_point(provisional);

    let response = scalar_from_canonical(&provisional.s_bytes())
        .ok_or(AntiKleptoError::InvalidProvisionalSignature)?;
    let first_challenge = challenge(&provisional.r_bytes(), &public_x, message);
    let provisional_nonce = response - first_challenge * secret;
    if bool::from(provisional_nonce.is_zero()) {
        return Err(AntiKleptoError::InvalidProvisionalSignature);
    }

    let contribution = host_scalar(
        session_id,
        host_secret,
        input_index,
        signature_slot,
        &public_key,
        &nonce_point,
    )?;
    let combined = nonzero_nonce_sum(provisional_nonce, contribution)?;

    let combined_point = ProjectivePoint::GENERATOR * combined;
    let (nonce_x, odd_y) =
        point_x_and_parity(&combined_point).ok_or(AntiKleptoError::InvalidNoncePoint)?;
    let normalized_nonce = if odd_y { combined.neg() } else { combined };
    let final_challenge = challenge(&nonce_x, &public_x, message);
    let final_response = normalized_nonce + final_challenge * secret;

    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&nonce_x);
    bytes[32..].copy_from_slice(&final_response.to_bytes());
    let signature = SchnorrSignature { bytes };
    super::schnorr::schnorr_verify(&public_x, message, &signature)
        .map_err(|_| AntiKleptoError::InvalidFinalSignature)?;
    Ok(signature)
}

/// Return the BIP340-normalized secret scalar and x-only public key.
///
/// BIP340 signs with `d` when `dG` has even Y and with `n-d` otherwise.
/// Recovering the provisional nonce from `s - e*d` therefore has to use the
/// same normalized scalar rather than the raw 32-byte private-key scalar.
fn normalized_secret_and_public_x(
    private_key: &[u8; 32],
) -> Result<(Scalar, [u8; 32]), AntiKleptoError> {
    use k256::elliptic_curve::ScalarPrimitive;

    let primitive = ScalarPrimitive::<k256::Secp256k1>::from_slice(private_key)
        .map_err(|_| AntiKleptoError::InvalidPrivateKey)?;
    let raw_secret = Scalar::from(primitive);
    if bool::from(raw_secret.is_zero()) {
        return Err(AntiKleptoError::InvalidPrivateKey);
    }

    let encoded = (ProjectivePoint::GENERATOR * raw_secret)
        .to_affine()
        .to_encoded_point(true);
    // k256 guarantees a compressed, non-identity secp256k1 point here. The
    // encoded point is therefore exactly prefix || x, where prefix is 0x02/0x03.
    let bytes = encoded.as_bytes();
    let secret = if bytes[0] == 0x03 {
        raw_secret.neg()
    } else {
        raw_secret
    };
    let mut public_x = [0u8; 32];
    public_x.copy_from_slice(&bytes[1..33]);
    Ok((secret, public_x))
}

/// Verify the anti-klepto nonce relation independent of transaction parsing.
/// Normal BIP340 signature verification must also be performed by the caller.
pub fn verify_nonce_relation(
    provisional_nonce_point: &[u8; 33],
    final_signature: &SchnorrSignature,
    session_id: &[u8; shared_signer::anti_klepto::SESSION_ID_LEN],
    host_secret: &[u8; 32],
    input_index: u32,
    signature_slot: u8,
    public_key: &[u8; 33],
) -> Result<(), AntiKleptoError> {
    if public_key[0] != 0x02 || provisional_nonce_point[0] != 0x02 {
        return Err(AntiKleptoError::InvalidNoncePoint);
    }
    let provisional_key = k256::PublicKey::from_sec1_bytes(provisional_nonce_point)
        .map_err(|_| AntiKleptoError::InvalidNoncePoint)?;
    k256::PublicKey::from_sec1_bytes(public_key).map_err(|_| AntiKleptoError::InvalidNoncePoint)?;
    let contribution = host_scalar(
        session_id,
        host_secret,
        input_index,
        signature_slot,
        public_key,
        provisional_nonce_point,
    )?;
    let expected = provisional_key.to_projective() + ProjectivePoint::GENERATOR * contribution;
    let (expected_x, _) =
        point_x_and_parity(&expected).ok_or(AntiKleptoError::InvalidNoncePoint)?;
    if shared_signer::bytes::constant_time_eq_32(&expected_x, &final_signature.r_bytes()) {
        Ok(())
    } else {
        Err(AntiKleptoError::InvalidFinalSignature)
    }
}

fn canonical_public_key(public_x: &[u8; 32]) -> [u8; 33] {
    let mut public_key = [0u8; 33];
    public_key[0] = 0x02;
    public_key[1..].copy_from_slice(public_x);
    public_key
}

fn challenge(nonce_x: &[u8; 32], public_x: &[u8; 32], message: &[u8; 32]) -> Scalar {
    let mut data = [0u8; 96];
    data[..32].copy_from_slice(nonce_x);
    data[32..64].copy_from_slice(public_x);
    data[64..].copy_from_slice(message);
    let digest = tagged_hash(b"BIP0340/challenge", &data);
    <Scalar as Reduce<U256>>::reduce_bytes(&digest.into())
}

fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Scalar> {
    use k256::elliptic_curve::ScalarPrimitive;
    let primitive = ScalarPrimitive::<k256::Secp256k1>::from_slice(bytes).ok()?;
    Some(Scalar::from(primitive))
}

fn point_x_and_parity(point: &ProjectivePoint) -> Option<([u8; 32], bool)> {
    if bool::from(point.is_identity()) {
        return None;
    }
    let encoded = point.to_affine().to_encoded_point(false);
    let x = encoded.x()?;
    let y = encoded.y()?;
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(x);
    Some((x_bytes, y[31] & 1 == 1))
}

impl From<SchnorrError> for AntiKleptoError {
    fn from(error: SchnorrError) -> Self {
        match error {
            SchnorrError::InvalidPrivateKey => Self::InvalidPrivateKey,
            SchnorrError::SigningFailed | SchnorrError::InvalidSignature => {
                Self::InvalidFinalSignature
            }
        }
    }
}

#[cfg(test)]
#[path = "unit_tests/anti_klepto_tests.rs"]
mod anti_klepto_tests;
