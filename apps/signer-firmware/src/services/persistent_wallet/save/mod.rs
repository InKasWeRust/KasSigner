//! Persistent-wallet credential save operations.

use offline_signer::crypto::password_kdf::PasswordKdfPurpose;
use crate::services::credential_policy::{self, CredentialKind, SALT_SIZE};
use crate::wallet::seed_manager::SeedManager;
use super::{journal, kdf, PersistError, PersistentWallet, StorageMode};

impl PersistentWallet<'_> {
    pub(crate) fn prepare_async_save(
        &mut self,
        kind: CredentialKind,
        secret: &[u8],
        recovery_words_acknowledged: bool,
    ) -> Result<[u8; SALT_SIZE], PersistError> {
        if !recovery_words_acknowledged {
            return Err(PersistError::RecoveryAcknowledgementRequired);
        }
        if self.mode == Some(StorageMode::SdCard) {
            return Err(PersistError::AdvancedAlreadyEnabled);
        }
        credential_policy::validate(kind, secret)?;
        if self.crypto.available_key_slot().is_none() {
            return Err(PersistError::DeviceKeyMissing);
        }
        let mut salt = [0u8; SALT_SIZE];
        crate::services::entropy::fill(&mut salt).map_err(|_| PersistError::Entropy)?;
        Ok(salt)
    }

    pub(crate) fn derive_async_save_key(
        &self,
        secret: &[u8],
        salt: &[u8; SALT_SIZE],
        liveness: &mut (impl FnMut() + ?Sized),
    ) -> Result<[u8; 32], PersistError> {
        kdf::derive(
            kdf::CredentialKdf::current(),
            PasswordKdfPurpose::PersistentWallet,
            secret,
            salt,
            liveness,
        )
    }

    pub(crate) fn finish_async_save(
        &mut self,
        kind: CredentialKind,
        salt: [u8; SALT_SIZE],
        key: [u8; 32],
        manager: &SeedManager,
        progress: &mut dyn FnMut(u8),
    ) -> Result<(), PersistError> {
        self.clear_credential();
        self.credential_kind = Some(kind);
        self.device_only = false;
        self.credential_salt = salt;
        self.credential_key = Some(key);
        self.credential_kdf = kdf::CredentialKdf::current();
        self.mode = Some(StorageMode::SaveWallet);
        progress(82);
        if let Err(error) = journal::erase_wallet(&mut self.flash) {
            self.mode = None;
            self.clear_credential();
            return Err(error.into());
        }
        progress(88);
        if let Err(error) = self.save_flash_snapshot(manager) {
            self.mode = None;
            self.clear_credential();
            return Err(error);
        }
        progress(96);
        if let Err(error) = journal::write_mode(&mut self.flash, StorageMode::SaveWallet) {
            self.mode = None;
            self.clear_credential();
            return Err(error.into());
        }
        progress(100);
        Ok(())
    }

    #[cfg(feature = "workflow-test-auto")]
    pub fn save_with_credential(
        &mut self,
        kind: CredentialKind,
        secret: &[u8],
        manager: &SeedManager,
        recovery_words_acknowledged: bool,
        progress: &mut dyn FnMut(u8),
    ) -> Result<(), PersistError> {
        if !recovery_words_acknowledged { return Err(PersistError::RecoveryAcknowledgementRequired); }
        if self.mode == Some(StorageMode::SdCard) { return Err(PersistError::AdvancedAlreadyEnabled); }
        credential_policy::validate(kind, secret)?;
        if self.crypto.available_key_slot().is_none() { return Err(PersistError::DeviceKeyMissing); }

        progress(1);
        let mut salt = [0u8; SALT_SIZE];
        crate::services::entropy::fill(&mut salt).map_err(|_| PersistError::Entropy)?;
        progress(4);
        let key = kdf::derive(
            kdf::CredentialKdf::current(),
            PasswordKdfPurpose::PersistentWallet,
            secret,
            &salt,
            &mut || progress(40),
        )?;
        progress(82);
        self.clear_credential();
        self.credential_kind = Some(kind);
        self.device_only = false;
        self.credential_salt = salt;
        self.credential_key = Some(key);
        self.credential_kdf = kdf::CredentialKdf::current();
        self.mode = Some(StorageMode::SaveWallet);

        // v1/v2 password-only or device-only journal records are intentionally
        // incompatible. Erase both wallet slots before creating the first v3
        // device-bound record so no weaker ciphertext remains recoverable.
        journal::erase_wallet(&mut self.flash)?;
        progress(88);
        if let Err(error) = self.save_flash_snapshot(manager) {
            self.mode = None;
            self.clear_credential();
            return Err(error);
        }
        progress(96);
        if let Err(error) = journal::write_mode(&mut self.flash, StorageMode::SaveWallet) {
            self.mode = None;
            self.clear_credential();
            return Err(error.into());
        }
        progress(100);
        Ok(())
    }

    /// Save a persistent wallet without a user-entered credential.  The all-zero
    /// software credential component is never an encryption key by itself: the
    /// device-bound storage KDF mixes it with random salt and the read-protected
    /// ESP32-S3 HMAC/eFuse identity before AES authentication/encryption.
    pub fn save_device_only(
        &mut self,
        manager: &SeedManager,
        recovery_words_acknowledged: bool,
        progress: &mut dyn FnMut(u8),
    ) -> Result<(), PersistError> {
        if !recovery_words_acknowledged { return Err(PersistError::RecoveryAcknowledgementRequired); }
        if self.mode == Some(StorageMode::SdCard) { return Err(PersistError::AdvancedAlreadyEnabled); }
        if self.crypto.available_key_slot().is_none() { return Err(PersistError::DeviceKeyMissing); }
        let mut salt = [0u8; SALT_SIZE];
        crate::services::entropy::fill(&mut salt).map_err(|_| PersistError::Entropy)?;
        self.clear_credential();
        // Password is only the domain tag for the existing device-bound KDF.
        // `device_only` is independently authenticated in header byte 59.
        self.credential_kind = Some(CredentialKind::Password);
        self.device_only = true;
        self.credential_salt = salt;
        self.credential_key = Some([0u8; 32]);
        self.credential_kdf = kdf::CredentialKdf::current();
        self.mode = Some(StorageMode::SaveWallet);
        self.security_policy = super::security_policy::SecurityPolicy::disabled();
        self.security_integrity_ok = true;
        progress(82);
        if let Err(error) = journal::erase_wallet(&mut self.flash) {
            self.mode = None;
            self.clear_credential();
            return Err(error.into());
        }
        progress(88);
        if let Err(error) = self.save_flash_snapshot(manager) {
            self.mode = None;
            self.clear_credential();
            return Err(error);
        }
        progress(96);
        if let Err(error) = journal::write_mode(&mut self.flash, StorageMode::SaveWallet) {
            self.mode = None;
            self.clear_credential();
            return Err(error.into());
        }
        progress(100);
        Ok(())
    }

    /// Re-key an already-unlocked internal store to the current device-only outer envelope.
    ///
    /// Per-wallet PIN/password activation is the only current user-credential boundary.
    /// Older credential-encrypted outer records (including PBKDF2 records) may still be
    /// opened for recovery/migration, but current snapshots never retain a global wallet
    /// activation credential after a successful unlock.
    pub(crate) fn migrate_outer_to_device_only(
        &mut self,
        manager: &SeedManager,
    ) -> Result<(), PersistError> {
        if self.mode != Some(StorageMode::SaveWallet) { return Ok(()); }
        if self.device_only { return Ok(()); }
        if self.crypto.available_key_slot().is_none() { return Err(PersistError::DeviceKeyMissing); }

        let mut salt = [0u8; SALT_SIZE];
        crate::services::entropy::fill(&mut salt).map_err(|_| PersistError::Entropy)?;
        self.clear_credential();
        self.credential_kind = Some(CredentialKind::Password);
        self.device_only = true;
        self.credential_salt = salt;
        self.credential_key = Some([0u8; 32]);
        self.credential_kdf = kdf::CredentialKdf::current();

        // Commit the new device-only snapshot first so a reset at any point
        // still leaves at least one decryptable copy. Only then remove stale
        // user-credential envelopes.
        if let Err(error) = self.save_flash_snapshot(manager) {
            self.clear_credential();
            return Err(error);
        }
        journal::write_mode(&mut self.flash, StorageMode::SaveWallet)?;
        journal::erase_non_device_only_wallet_records(&mut self.flash)?;
        Ok(())
    }

}
