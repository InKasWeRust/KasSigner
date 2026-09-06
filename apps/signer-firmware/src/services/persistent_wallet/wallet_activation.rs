//! Per-wallet activation credential derivation and device-bound verification.

use offline_signer::crypto::password_kdf::PasswordKdfPurpose;
use crate::services::credential_policy::{self, CredentialKind, SALT_SIZE};

use crate::wallet::seed_manager::WalletProtection;

use super::{journal, kdf, PersistError, PersistentWallet};

impl PersistentWallet<'_> {
    pub(crate) fn prepare_wallet_activation_salt(
        &mut self,
        kind: CredentialKind,
        secret: &[u8],
    ) -> Result<[u8; SALT_SIZE], PersistError> {
        credential_policy::validate(kind, secret)?;
        if self.crypto.available_key_slot().is_none() {
            return Err(PersistError::DeviceKeyMissing);
        }
        let mut salt = [0u8; SALT_SIZE];
        crate::services::entropy::fill(&mut salt).map_err(|_| PersistError::Entropy)?;
        Ok(salt)
    }

    pub(crate) fn derive_wallet_activation_key(
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

    pub(crate) fn make_wallet_activation_verifier(
        &mut self,
        slot: usize,
        kind: CredentialKind,
        salt: &[u8; SALT_SIZE],
        stretched_key: &[u8; 32],
    ) -> Result<[u8; 32], PersistError> {
        let slot = u8::try_from(slot).map_err(|_| PersistError::InvalidWallet)?;
        self.crypto.wallet_activation_verifier(slot, kind, salt, stretched_key)
    }

    pub(crate) fn stage_wallet_activation_record(
        &mut self,
        slot: usize,
        protection: WalletProtection,
        salt: [u8; SALT_SIZE],
        verifier: [u8; 32],
    ) -> Result<(), PersistError> {
        let mut records = journal::read_wallet_activation(&mut self.flash)?;
        match protection {
            WalletProtection::Pin | WalletProtection::Password => {
                if !records.set(slot, journal::WalletActivationRecord { salt, verifier }) {
                    return Err(PersistError::InvalidWallet);
                }
            }
            WalletProtection::DeviceOnly => records.clear(slot),
        }
        journal::write_wallet_activation(&mut self.flash, records)?;
        Ok(())
    }

    pub(crate) fn clear_wallet_activation_record(&mut self, slot: usize) -> Result<(), PersistError> {
        let mut records = journal::read_wallet_activation(&mut self.flash)?;
        records.clear(slot);
        journal::write_wallet_activation(&mut self.flash, records)?;
        Ok(())
    }

    pub(crate) fn wallet_activation_material(
        &mut self,
        slot: usize,
    ) -> Result<([u8; SALT_SIZE], [u8; 32]), PersistError> {
        let record = journal::read_wallet_activation(&mut self.flash)?
            .get(slot)
            .ok_or(PersistError::Authentication)?;
        Ok((record.salt, record.verifier))
    }

    pub(crate) fn verify_wallet_activation_key(
        &mut self,
        slot: usize,
        kind: CredentialKind,
        salt: &[u8; SALT_SIZE],
        expected: &[u8; 32],
        stretched_key: &[u8; 32],
    ) -> Result<(), PersistError> {
        let actual = self.make_wallet_activation_verifier(slot, kind, salt, stretched_key)?;
        let matches = shared_signer::bytes::constant_time_eq_32(expected, &actual);
        if matches { Ok(()) } else { Err(PersistError::Authentication) }
    }
}
