//! Narrow capability boundary for removable wallet-secret backup encryption.
//!
//! Password stretching belongs to the versioned backup container. This trait
//! receives only a 32-byte stretched credential and mixes it with the
//! non-exportable device HMAC key. The device secret is never exposed.

use offline_signer::crypto::device_bound_storage::{NONCE_SIZE, StoragePurpose, TAG_SIZE};
use crate::services::credential_policy::SALT_SIZE;

use super::BackupError;

pub trait BackupDevice {
    fn seal_backup_key(
        &mut self,
        purpose: StoragePurpose,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<[u8; TAG_SIZE], BackupError>;

    fn open_backup_key(
        &mut self,
        purpose: StoragePurpose,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), BackupError>;
}

impl BackupDevice for crate::services::persistent_wallet::PersistentWallet<'_> {
    fn seal_backup_key(
        &mut self,
        purpose: StoragePurpose,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<[u8; TAG_SIZE], BackupError> {
        self.seal_backup_key(purpose, credential_key, salt, nonce, aad, ciphertext)
            .map_err(map_persist_error)
    }

    fn open_backup_key(
        &mut self,
        purpose: StoragePurpose,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), BackupError> {
        self.open_backup_key(purpose, credential_key, salt, nonce, aad, ciphertext, tag)
            .map_err(map_persist_error)
    }
}

fn map_persist_error(error: crate::services::persistent_wallet::PersistError) -> BackupError {
    use crate::services::persistent_wallet::PersistError;
    match error {
        PersistError::DeviceKeyMissing => BackupError::DeviceKeyUnavailable,
        PersistError::Entropy => BackupError::EntropyUnavailable,
        PersistError::Authentication => BackupError::AuthenticationFailed,
        _ => BackupError::EncryptionFailed,
    }
}
