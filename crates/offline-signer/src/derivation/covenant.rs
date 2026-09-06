//! Isolated deterministic key hierarchy for universal covenant signing.
//!
//! Covenant keys never derive from the normal Kaspa spending account path.
//! The private hierarchy is rooted at:
//!
//! ```text
//! m/10016'/111111'/0'/i0'/i1'/i2'/i3'/i4'
//! ```
//!
//! where i0..i4 are hardened 31-bit indices deterministically derived from a
//! caller-supplied 32-byte covenant instance ID. Every instance component is
//! hardened, so disclosure of one covenant child key cannot be used with
//! public hierarchy material to walk toward the master or sibling covenants.
//! Five components retain ~155 bits of instance separation.

use sha2::{Digest, Sha256};

use super::bip32::{derive_child, derive_path, Bip32Error, ExtendedPrivKey};
use crate::crypto::{
    anti_klepto,
    schnorr::{self, SchnorrError, SchnorrSignature},
};

const HARDENED: u32 = 0x8000_0000;
const COVENANT_PURPOSE: u32 = 0x8000_2720;
const KASPA_COIN_TYPE: u32 = 0x8001_b207;
const COVENANT_ACCOUNT: u32 = HARDENED;
const COVENANT_BINDING_ACCOUNT: u32 = 0x8000_0001;
const PRIVATE_SWAP_CLAIM_ACCOUNT: u32 = 0x8000_0003;
const PRIVATE_SWAP_BINDING_ACCOUNT: u32 = 0x8000_0004;
const PRIVATE_SWAP_ADAPTOR_ACCOUNT: u32 = 0x8000_0005;
const INSTANCE_DOMAIN: &[u8] = b"KasSigner Covenant Key v1\0";
const BINDING_DOMAIN: &[u8] = b"KasSigner Covenant Binding Record v1\0";
const PRIVATE_SWAP_BINDING_DOMAIN: &[u8] = b"KasSigner Private Swap Binding Record v2\0";

#[derive(Debug, PartialEq)]
pub enum CovenantKeyError {
    InvalidInstanceId,
    Derivation(Bip32Error),
    Signing(SchnorrError),
    AntiKlepto(anti_klepto::AntiKleptoError),
}

impl From<Bip32Error> for CovenantKeyError {
    fn from(value: Bip32Error) -> Self {
        Self::Derivation(value)
    }
}

impl From<SchnorrError> for CovenantKeyError {
    fn from(value: SchnorrError) -> Self {
        Self::Signing(value)
    }
}

impl From<anti_klepto::AntiKleptoError> for CovenantKeyError {
    fn from(value: anti_klepto::AntiKleptoError) -> Self {
        Self::AntiKlepto(value)
    }
}

#[must_use]
pub fn covenant_instance_indices(instance_id: &[u8; 32]) -> Option<[u32; 5]> {
    if *instance_id == [0u8; 32] {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(INSTANCE_DOMAIN);
    hasher.update(instance_id);
    let digest: [u8; 32] = hasher.finalize().into();
    Some([
        u32::from_be_bytes(digest[0..4].try_into().ok()?) & 0x7fff_ffff,
        u32::from_be_bytes(digest[4..8].try_into().ok()?) & 0x7fff_ffff,
        u32::from_be_bytes(digest[8..12].try_into().ok()?) & 0x7fff_ffff,
        u32::from_be_bytes(digest[12..16].try_into().ok()?) & 0x7fff_ffff,
        u32::from_be_bytes(digest[16..20].try_into().ok()?) & 0x7fff_ffff,
    ])
}

pub fn covenant_public_key(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
) -> Result<[u8; 32], CovenantKeyError> {
    let key = derive_covenant_key(seed, instance_id)?;
    key.public_key_x_only()
        .map_err(CovenantKeyError::Derivation)
}

/// Produce the portable, mnemonic-authenticated binding record that ties one
/// covenant instance ID to one exact redeem-script fingerprint. The binding
/// key lives under a separate hardened account and is never exposed through
/// COVENANT SIGN, so an opaque covenant signature cannot forge or rebind this
/// record.
pub fn covenant_binding_token(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
    script_hash: &[u8; 32],
) -> Result<[u8; 32], CovenantKeyError> {
    let mut binding_key = derive_covenant_binding_key(seed, instance_id)?;
    let signing_pubkey = covenant_public_key(seed, instance_id)?;
    let token = hmac_sha256(
        binding_key.private_key_bytes(),
        &[BINDING_DOMAIN, instance_id, script_hash, &signing_pubkey],
    );
    binding_key.zeroize();
    Ok(token)
}

/// Verify a binding record without exposing the internal binding key.
pub fn covenant_binding_matches(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
    script_hash: &[u8; 32],
    token: &[u8; 32],
) -> Result<bool, CovenantKeyError> {
    let expected = covenant_binding_token(seed, instance_id, script_hash)?;
    Ok(constant_time_eq(&expected, token))
}

/// Produce the provisional BIP340 signature used by the covenant anti-klepto
/// exchange. The exact third-party commitment is consumed as-is.
pub fn provisional_covenant_signature(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
    commitment: &[u8; 32],
    aux_rand: &[u8; 32],
) -> Result<SchnorrSignature, CovenantKeyError> {
    let key = derive_covenant_key(seed, instance_id)?;
    schnorr::schnorr_sign_with_aux_rand(key.private_key_bytes(), commitment, aux_rand)
        .map_err(CovenantKeyError::Signing)
}

/// Finalize the exact same commitment after the host reveals its previously
/// committed nonce contribution. This transforms the provisional signature
/// into an ordinary BIP340 signature without changing the covenant message.
pub fn finalize_covenant_signature(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
    commitment: &[u8; 32],
    provisional: &SchnorrSignature,
    session_id: &[u8; shared_signer::covenant_sign::SESSION_ID_LEN],
    host_secret: &[u8; 32],
) -> Result<SchnorrSignature, CovenantKeyError> {
    let key = derive_covenant_key(seed, instance_id)?;
    anti_klepto::tweak_provisional_signature(
        key.private_key_bytes(),
        commitment,
        provisional,
        session_id,
        host_secret,
        0,
        0,
    )
    .map_err(CovenantKeyError::AntiKlepto)
}

/// Derive the isolated Private Swap claim public key. Private Swap does not
/// reuse the universal COVENANT SIGN key branch: doing so would let a participant
/// bypass adaptor-secret revelation by requesting an ordinary opaque covenant
/// signature with the same key.
pub fn private_swap_public_key(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
) -> Result<[u8; 32], CovenantKeyError> {
    let key = derive_private_swap_claim_key(seed, instance_id)?;
    key.public_key_x_only()
        .map_err(CovenantKeyError::Derivation)
}

/// Portable binding record for the Private Swap claim key. This uses a
/// different hardened binding account and domain from universal covenant
/// signing, so a COVENANT SIGN binding token cannot authorize a swap claim.
pub fn private_swap_binding_token(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
    script_hash: &[u8; 32],
) -> Result<[u8; 32], CovenantKeyError> {
    let mut binding_key = derive_covenant_branch(seed, instance_id, PRIVATE_SWAP_BINDING_ACCOUNT)?;
    let claim_pubkey = private_swap_public_key(seed, instance_id)?;
    let token = hmac_sha256(
        binding_key.private_key_bytes(),
        &[
            PRIVATE_SWAP_BINDING_DOMAIN,
            instance_id,
            script_hash,
            &claim_pubkey,
        ],
    );
    binding_key.zeroize();
    Ok(token)
}

pub fn private_swap_binding_matches(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
    script_hash: &[u8; 32],
    token: &[u8; 32],
) -> Result<bool, CovenantKeyError> {
    let expected = private_swap_binding_token(seed, instance_id, script_hash)?;
    Ok(constant_time_eq(&expected, token))
}

/// Derive the per-instance Private Swap adaptor secret under its own hardened
/// account. The returned scalar is BIP340-normalized so its x-only adaptor
/// point always represents an even-Y point.
pub fn private_swap_adaptor_secret_and_point(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), CovenantKeyError> {
    let mut key = derive_covenant_branch(seed, instance_id, PRIVATE_SWAP_ADAPTOR_ACCOUNT)?;
    let result = crate::crypto::adaptor::adaptor_point_from_secret(key.private_key_bytes())
        .map_err(|_| CovenantKeyError::Signing(SchnorrError::SigningFailed));
    key.zeroize();
    result
}

pub fn private_swap_adaptor_point(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
) -> Result<[u8; 32], CovenantKeyError> {
    private_swap_adaptor_secret_and_point(seed, instance_id).map(|(_, point)| point)
}

pub fn private_swap_adaptor_base_nonce_point(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
    message: &[u8; 32],
    adaptor_point_x: &[u8; 32],
    session_id: &[u8; 16],
    aux_rand: &[u8; 32],
) -> Result<[u8; 33], CovenantKeyError> {
    let mut key = derive_private_swap_claim_key(seed, instance_id)?;
    let result = crate::crypto::adaptor::adaptor_base_nonce_point(
        key.private_key_bytes(),
        message,
        adaptor_point_x,
        session_id,
        aux_rand,
    )
    .map_err(|_| CovenantKeyError::Signing(SchnorrError::SigningFailed));
    key.zeroize();
    result
}

pub fn create_private_swap_adaptor_presignature(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
    message: &[u8; 32],
    adaptor_point_x: &[u8; 32],
    session_id: &[u8; 16],
    aux_rand: &[u8; 32],
    host_secret: &[u8; 32],
) -> Result<crate::crypto::adaptor::AdaptorPreSignature, CovenantKeyError> {
    let mut key = derive_private_swap_claim_key(seed, instance_id)?;
    let result = crate::crypto::adaptor::create_adaptor_presignature(
        key.private_key_bytes(),
        message,
        adaptor_point_x,
        session_id,
        aux_rand,
        host_secret,
    )
    .map_err(|_| CovenantKeyError::Signing(SchnorrError::SigningFailed));
    key.zeroize();
    result
}

pub fn complete_private_swap_adaptor_presignature(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
    presig: &crate::crypto::adaptor::AdaptorPreSignature,
) -> Result<[u8; 64], CovenantKeyError> {
    let (mut secret, _) = private_swap_adaptor_secret_and_point(seed, instance_id)?;
    let result = crate::crypto::adaptor::complete_adaptor_presignature(presig, &secret)
        .map_err(|_| CovenantKeyError::Signing(SchnorrError::SigningFailed));
    shared_signer::bytes::zeroize_bytes(&mut secret);
    result
}

fn derive_covenant_key(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
) -> Result<ExtendedPrivKey, CovenantKeyError> {
    derive_covenant_branch(seed, instance_id, COVENANT_ACCOUNT)
}

fn derive_private_swap_claim_key(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
) -> Result<ExtendedPrivKey, CovenantKeyError> {
    derive_covenant_branch(seed, instance_id, PRIVATE_SWAP_CLAIM_ACCOUNT)
}

fn derive_covenant_binding_key(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
) -> Result<ExtendedPrivKey, CovenantKeyError> {
    derive_covenant_branch(seed, instance_id, COVENANT_BINDING_ACCOUNT)
}

fn derive_covenant_branch(
    seed: &[u8; 64],
    instance_id: &[u8; 32],
    account: u32,
) -> Result<ExtendedPrivKey, CovenantKeyError> {
    let indices =
        covenant_instance_indices(instance_id).ok_or(CovenantKeyError::InvalidInstanceId)?;
    let mut current = derive_path(seed, &[COVENANT_PURPOSE, KASPA_COIN_TYPE, account])?;
    for index in indices {
        let child = derive_child(&current, HARDENED + index)?;
        current.zeroize();
        current = child;
    }
    Ok(current)
}

fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for index in 0..key.len() {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    for part in parts {
        inner.update(part);
    }
    let digest = inner.finalize();
    let mut inner_hash = [0u8; 32];
    inner_hash.copy_from_slice(&digest);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    let result: [u8; 32] = outer.finalize().into();
    inner_pad.fill(0);
    outer_pad.fill(0);
    inner_hash.fill(0);
    result
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

#[cfg(test)]
mod unit_tests;
