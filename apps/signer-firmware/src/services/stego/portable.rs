//! Password-only cross-device Portable JPEG protection.
//!
//! The versioned payload header supplies authenticated Argon2id parameters and
//! a random salt. The password is the only secret required to restore; there is
//! deliberately no recovery-key factor and no legacy two-factor fallback.

use aes_gcm::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    Aes256Gcm,
};
use offline_signer::crypto::{
    device_bound_storage::{NONCE_SIZE, TAG_SIZE},
    password_kdf::{PasswordKdfParams, PasswordKdfPurpose, SALT_SIZE},
};
use shared_signer::bytes::zeroize_bytes;
use crate::services::credential_policy::{self, CredentialKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PortableError {
    InvalidPassword,
    UnsupportedKdf,
    EncryptionFailed,
    AuthenticationFailed,
}

pub(super) fn validate_password(password: &[u8]) -> Result<(), PortableError> {
    credential_policy::validate(CredentialKind::Password, password)
        .map_err(|_| PortableError::InvalidPassword)
}

pub(super) fn seal(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    plaintext: &mut [u8],
) -> Result<[u8; TAG_SIZE], PortableError> {
    validate_password(password)?;
    let mut key = crate::services::memory::password_kdf::derive_key_32(
        PasswordKdfPurpose::PortableBackup,
        password,
        salt,
    )
    .map_err(|_| PortableError::UnsupportedKdf)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let result = cipher.encrypt_in_place_detached(
        GenericArray::from_slice(nonce),
        aad,
        plaintext,
    );
    zeroize_bytes(&mut key);

    match result {
        Ok(tag) => {
            let mut out = [0u8; TAG_SIZE];
            out.copy_from_slice(tag.as_ref());
            Ok(out)
        }
        Err(_) => {
            zeroize_bytes(plaintext);
            Err(PortableError::EncryptionFailed)
        }
    }
}

pub(super) fn open(
    password: &[u8],
    parameters: PasswordKdfParams,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8; TAG_SIZE],
) -> Result<(), PortableError> {
    validate_password(password)?;
    let mut key = crate::services::memory::password_kdf::derive_key_32_with_params(
        PasswordKdfPurpose::PortableBackup,
        password,
        salt,
        parameters,
    )
    .map_err(|_| PortableError::UnsupportedKdf)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let result = cipher.decrypt_in_place_detached(
        GenericArray::from_slice(nonce),
        aad,
        ciphertext,
        GenericArray::from_slice(tag),
    );
    zeroize_bytes(&mut key);

    if result.is_err() {
        zeroize_bytes(ciphertext);
        Err(PortableError::AuthenticationFailed)
    } else {
        Ok(())
    }
}
