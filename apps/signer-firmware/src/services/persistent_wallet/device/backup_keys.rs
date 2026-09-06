//! Device-bound backup sealing boundary.

use super::super::{PersistError, PersistentWallet};
use crate::services::credential_policy::SALT_SIZE;

impl PersistentWallet<'_> {
    /// Mix an already-stretched backup credential with the non-exportable
    /// device HMAC key and seal a device-bound backup. Password KDF selection
    /// belongs to the authenticated outer backup format, not this hardware
    /// boundary.
    pub(crate) fn seal_backup_key(
        &mut self,
        purpose: offline_signer::crypto::device_bound_storage::StoragePurpose,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        nonce: &[u8; offline_signer::crypto::device_bound_storage::NONCE_SIZE],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<[u8; offline_signer::crypto::device_bound_storage::TAG_SIZE], PersistError> {
        self.crypto.seal_backup(purpose, credential_key, salt, nonce, aad, ciphertext)
    }

    pub(crate) fn open_backup_key(
        &mut self,
        purpose: offline_signer::crypto::device_bound_storage::StoragePurpose,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        nonce: &[u8; offline_signer::crypto::device_bound_storage::NONCE_SIZE],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; offline_signer::crypto::device_bound_storage::TAG_SIZE],
    ) -> Result<(), PersistError> {
        self.crypto.open_backup(purpose, credential_key, salt, nonce, aad, ciphertext, tag)
    }


}
