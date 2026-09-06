//! Device-bound AES-256-GCM key derivation for persisted wallet state.
//!
//! The user's PIN/password is stretched by the versioned outer credential KDF
//! before entering this module. Current formats use Argon2id; explicit legacy
//! readers may supply a legacy-stretched credential. The stretched credential is mixed
//! with a hardware HMAC result produced from a non-exportable device secret.
//! The raw hardware secret is never part of this API.

use crate::crypto::credential::{CredentialKind, SALT_SIZE};
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    Aes256Gcm,
};
use sha2::{Digest, Sha256};

use crate::derivation::hmac::zeroize_buf;

pub const FORMAT_VERSION: u8 = 3;
pub const KDF_ID_DEVICE_HMAC_SHA256: u8 = 2;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

const CONTEXT_DOMAIN: &[u8] = b"KasSigner/device-bound-wallet/context/v1";
const HMAC_DOMAIN: &[u8] = b"KasSigner/device-bound-wallet/device-mix/v1";
const AES_DOMAIN: &[u8] = b"KasSigner/device-bound-wallet/aes-256-gcm/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StoragePurpose {
    InternalWallet = 1,
    SdWallet = 2,
    /// User-created device-bound mnemonic backup on removable SD media.
    SdSeedBackup = 3,
    /// User-created device-bound account-XPrv backup on removable SD media.
    SdXprvBackup = 4,
    /// Device-bound JPEG steganographic mnemonic backup.
    StegoWallet = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParameters {
    pub format_version: u8,
    pub kdf_id: u8,
    pub purpose: StoragePurpose,
    pub credential_kind: CredentialKind,
}

impl KdfParameters {
    pub const fn current(purpose: StoragePurpose, credential_kind: CredentialKind) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            kdf_id: KDF_ID_DEVICE_HMAC_SHA256,
            purpose,
            credential_kind,
        }
    }

    fn validate(self) -> Result<(), DeviceBoundError> {
        if self.format_version != FORMAT_VERSION || self.kdf_id != KDF_ID_DEVICE_HMAC_SHA256 {
            return Err(DeviceBoundError::UnsupportedParameters);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceBoundError {
    HardwareHmacUnavailable,
    UnsupportedParameters,
    EntropyUnavailable,
    EncryptionFailed,
    AuthenticationFailed,
}

/// Minimal hardware boundary required by device-bound storage.
///
/// Implementations expose only an HMAC operation. There is deliberately no API
/// for returning, reading, cloning, or serializing the underlying hardware key.
pub trait HardwareHmac {
    fn hmac_sha256(
        &mut self,
        message: &[u8],
        output: &mut [u8; KEY_SIZE],
    ) -> Result<(), DeviceBoundError>;
}

pub trait EntropySource {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), DeviceBoundError>;
}

pub fn generate_fresh_material(
    entropy: &mut impl EntropySource,
    salt: &mut [u8; SALT_SIZE],
    nonce: &mut [u8; NONCE_SIZE],
) -> Result<(), DeviceBoundError> {
    if entropy.fill(salt).is_err() || entropy.fill(nonce).is_err() {
        zeroize_buf(salt);
        zeroize_buf(nonce);
        return Err(DeviceBoundError::EntropyUnavailable);
    }
    if salt.iter().all(|byte| *byte == 0) || nonce.iter().all(|byte| *byte == 0) {
        zeroize_buf(salt);
        zeroize_buf(nonce);
        return Err(DeviceBoundError::EntropyUnavailable);
    }
    Ok(())
}

pub fn derive_aes_key(
    hmac: &mut impl HardwareHmac,
    parameters: KdfParameters,
    stretched_credential: &[u8; KEY_SIZE],
    salt: &[u8; SALT_SIZE],
    authenticated_header: &[u8],
) -> Result<[u8; KEY_SIZE], DeviceBoundError> {
    parameters.validate()?;
    let mut context = context_digest(parameters, salt, authenticated_header);
    let mut challenge = [0u8; 32 + 32 + 4];
    challenge[..32].copy_from_slice(&context);
    challenge[32..64].copy_from_slice(stretched_credential);
    challenge[64] = parameters.format_version;
    challenge[65] = parameters.kdf_id;
    challenge[66] = parameters.purpose as u8;
    challenge[67] = parameters.credential_kind as u8;

    let mut device_mix = [0u8; KEY_SIZE];
    let hmac_result = hmac.hmac_sha256_with_domain(HMAC_DOMAIN, &challenge, &mut device_mix);
    zeroize_buf(&mut challenge);
    if let Err(error) = hmac_result {
        zeroize_buf(&mut context);
        zeroize_buf(&mut device_mix);
        return Err(error);
    }

    let mut hasher = Sha256::new();
    hasher.update(AES_DOMAIN);
    hasher.update(context);
    hasher.update(stretched_credential);
    hasher.update(device_mix);
    let mut key: [u8; KEY_SIZE] = hasher.finalize().into();
    zeroize_buf(&mut context);
    zeroize_buf(&mut device_mix);
    // Prevent an optimizer from treating the returned value as derived from a
    // mutable alias that remains live in this frame.
    let result = key;
    zeroize_buf(&mut key);
    Ok(result)
}

pub fn seal_in_place(
    hmac: &mut impl HardwareHmac,
    parameters: KdfParameters,
    stretched_credential: &[u8; KEY_SIZE],
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    authenticated_header: &[u8],
    plaintext: &mut [u8],
) -> Result<[u8; TAG_SIZE], DeviceBoundError> {
    let mut key = match derive_aes_key(
        hmac,
        parameters,
        stretched_credential,
        salt,
        authenticated_header,
    ) {
        Ok(key) => key,
        Err(error) => {
            zeroize_buf(plaintext);
            return Err(error);
        }
    };
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let result = cipher.encrypt_in_place_detached(
        GenericArray::from_slice(nonce),
        authenticated_header,
        plaintext,
    );
    zeroize_buf(&mut key);
    match result {
        Ok(tag) => {
            let mut output = [0u8; TAG_SIZE];
            output.copy_from_slice(tag.as_ref());
            Ok(output)
        }
        Err(_) => {
            zeroize_buf(plaintext);
            Err(DeviceBoundError::EncryptionFailed)
        }
    }
}

pub struct OpenRequest<'a> {
    pub parameters: KdfParameters,
    pub stretched_credential: &'a [u8; KEY_SIZE],
    pub salt: &'a [u8; SALT_SIZE],
    pub nonce: &'a [u8; NONCE_SIZE],
    pub authenticated_header: &'a [u8],
    pub tag: &'a [u8; TAG_SIZE],
}

pub fn open_in_place(
    hmac: &mut impl HardwareHmac,
    request: OpenRequest<'_>,
    ciphertext: &mut [u8],
) -> Result<(), DeviceBoundError> {
    let mut key = match derive_aes_key(
        hmac,
        request.parameters,
        request.stretched_credential,
        request.salt,
        request.authenticated_header,
    ) {
        Ok(key) => key,
        Err(error) => {
            zeroize_buf(ciphertext);
            return Err(error);
        }
    };
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let result = cipher.decrypt_in_place_detached(
        GenericArray::from_slice(request.nonce),
        request.authenticated_header,
        ciphertext,
        GenericArray::from_slice(request.tag),
    );
    zeroize_buf(&mut key);
    if result.is_err() {
        zeroize_buf(ciphertext);
        return Err(DeviceBoundError::AuthenticationFailed);
    }
    Ok(())
}

fn context_digest(
    parameters: KdfParameters,
    salt: &[u8; SALT_SIZE],
    authenticated_header: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_DOMAIN);
    hasher.update([
        parameters.format_version,
        parameters.kdf_id,
        parameters.purpose as u8,
        parameters.credential_kind as u8,
    ]);
    hasher.update(salt);
    hasher.update((authenticated_header.len() as u32).to_le_bytes());
    hasher.update(authenticated_header);
    hasher.finalize().into()
}

trait DomainSeparatedHmac: HardwareHmac {
    fn hmac_sha256_with_domain(
        &mut self,
        domain: &[u8],
        message: &[u8],
        output: &mut [u8; KEY_SIZE],
    ) -> Result<(), DeviceBoundError> {
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update((message.len() as u32).to_le_bytes());
        digest.update(message);
        let mut request: [u8; 32] = digest.finalize().into();
        let result = self.hmac_sha256(&request, output);
        zeroize_buf(&mut request);
        result
    }
}

impl<T: HardwareHmac + ?Sized> DomainSeparatedHmac for T {}

#[cfg(test)]
#[path = "unit_tests/device_bound_storage_tests.rs"]
mod unit_tests;
