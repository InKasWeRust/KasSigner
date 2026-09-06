//! Shared release-tool entry points.
//!
//! Firmware release signatures delegate to the same BIP340 implementation and
//! public signing identity used by production firmware verification.

/// Sign any 32-byte digest through the shared BIP340 implementation.
///
/// This lower-level entry point exists for standards vectors. Release tooling
/// must call [`sign_firmware_hash`], which additionally verifies the configured
/// production release identity.
pub fn sign_bip340_hash(
    private_key: &[u8; 32],
    message: &[u8; 32],
) -> Result<[u8; 64], offline_signer::crypto::schnorr::SchnorrError> {
    let signature = offline_signer::crypto::schnorr::schnorr_sign(private_key, message)?;
    let signing_key = k256::schnorr::SigningKey::from_bytes(private_key)
        .map_err(|_| offline_signer::crypto::schnorr::SchnorrError::InvalidPrivateKey)?;
    let public_key: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    offline_signer::crypto::schnorr::schnorr_verify(&public_key, message, &signature)?;
    Ok(signature.bytes)
}

/// Sign a firmware hash and verify it against the exact public key compiled
/// into both firmware-integrity and firmware-update verification.
fn sign_digest_for_identity(
    private_key: &[u8; 32],
    digest: &[u8; 32],
    public_key: &[u8; 32],
) -> Result<[u8; 64], offline_signer::crypto::schnorr::SchnorrError> {
    let signature = offline_signer::crypto::schnorr::schnorr_sign(private_key, digest)?;
    offline_signer::crypto::schnorr::schnorr_verify(public_key, digest, &signature)?;
    Ok(signature.bytes)
}

pub fn sign_release_digest(
    private_key: &[u8; 32],
    digest: &[u8; 32],
) -> Result<[u8; 64], offline_signer::crypto::schnorr::SchnorrError> {
    sign_digest_for_identity(private_key, digest, &signer_firmware_core::update::release::PRODUCTION_RELEASE_PUBKEY)
}

/// Sign a development firmware hash with the repository-public TEST identity.
/// Production build tooling must never call this entry point.
pub fn sign_test_firmware_hash(
    private_key: &[u8; 32],
    firmware_hash: &[u8; 32],
) -> Result<[u8; 64], offline_signer::crypto::schnorr::SchnorrError> {
    sign_digest_for_identity(
        private_key,
        firmware_hash,
        &signer_firmware_core::update::release::DEV_TEST_PUBKEY,
    )
}

pub fn sign_firmware_hash(
    private_key: &[u8; 32],
    firmware_hash: &[u8; 32],
) -> Result<[u8; 64], offline_signer::crypto::schnorr::SchnorrError> {
    sign_release_digest(private_key, firmware_hash)
}
