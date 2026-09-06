//! Checked per-container salt/nonce generation for SD wallet-secret backups.

use offline_signer::crypto::device_bound_storage::NONCE_SIZE;
use shared_signer::bytes::zeroize_bytes;
use crate::services::credential_policy::SALT_SIZE;

use super::BackupError;

pub(crate) struct BackupRandomness {
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
}

impl BackupRandomness {
    pub(crate) fn collect() -> Result<Self, BackupError> {
        let mut material = [0u8; SALT_SIZE + NONCE_SIZE];
        crate::services::entropy::fill(&mut material)
            .map_err(|_| BackupError::EntropyUnavailable)?;
        let mut salt = [0u8; SALT_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];
        salt.copy_from_slice(&material[..SALT_SIZE]);
        nonce.copy_from_slice(&material[SALT_SIZE..]);
        zeroize_bytes(&mut material);
        if salt.iter().all(|byte| *byte == 0) || nonce.iter().all(|byte| *byte == 0) {
            zeroize_bytes(&mut salt);
            zeroize_bytes(&mut nonce);
            return Err(BackupError::EntropyUnavailable);
        }
        Ok(Self { salt, nonce })
    }

    pub(crate) const fn salt(&self) -> &[u8; SALT_SIZE] { &self.salt }
    pub(crate) const fn nonce(&self) -> &[u8; NONCE_SIZE] { &self.nonce }
}

impl Drop for BackupRandomness {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.salt);
        zeroize_bytes(&mut self.nonce);
    }
}
