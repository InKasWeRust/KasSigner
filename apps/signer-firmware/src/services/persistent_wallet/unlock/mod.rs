//! Credential unlock and duress handling for flash and SD persistence backends.

use crate::services::credential_policy::CredentialKind;

use crate::runtime::data::AppData;
use super::{PersistError, PersistentWallet, StorageMode, crypto, journal, sd_backend};

#[cfg(feature = "workflow-test-auto")]
use offline_signer::{crypto::password_kdf::PasswordKdfPurpose, derivation::hmac::zeroize_buf};
#[cfg(feature = "workflow-test-auto")]
use crate::services::credential_policy::SALT_SIZE;
#[cfg(feature = "workflow-test-auto")]
use crate::services::wallet_session;
#[cfg(feature = "workflow-test-auto")]
use super::{
    crypto::RECORD_SIZE,
    kdf, flash::AlignedBytes, security_policy,
};

impl PersistentWallet<'_> {
    pub(crate) fn trigger_duress(
        &mut self,
        ad: &mut AppData,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(), PersistError> {
        crate::services::device_wipe::zeroize_volatile(ad);
        let sd_erased = self.mode != Some(StorageMode::SdCard)
            || sd_backend::erase_files(i2c, delay).is_ok();
        let internal_erased = journal::erase_all_user_data(&mut self.flash).is_ok();
        self.mode = None;
        self.clear_credential();
        self.security_policy = super::security_policy::SecurityPolicy::disabled();
        self.security_integrity_ok = true;
        self.sync_security_mirror(ad);
        if sd_erased && internal_erased {
            Err(PersistError::DuressTriggered)
        } else {
            Err(PersistError::DeviceWipeFailed)
        }
    }
}

#[cfg(feature = "workflow-test-auto")]
enum UnlockAttempt {
    Unlocked,
    Skipped,
    Failed(PersistError),
}

#[cfg(feature = "workflow-test-auto")]
impl PersistentWallet<'_> {
    pub fn unlock_saved(
        &mut self,
        kind: CredentialKind,
        secret: &[u8],
        ad: &mut AppData,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
        liveness: &mut dyn FnMut(),
    ) -> Result<(), PersistError> {
        // Creation-time credential policy must never disclose rule details
        // during unlock. Every guess is handled as an authentication attempt.
        liveness();
        if self.duress_entered(kind, secret, liveness)? { return self.trigger_duress(ad, i2c, delay); }
        if self.mode == Some(StorageMode::SdCard) {
            self.unlock_from_sd(kind, secret, ad, i2c, delay, liveness)
        } else {
            self.unlock_from_journal(kind, secret, ad, liveness)
        }
    }

    fn unlock_from_sd(
        &mut self,
        kind: CredentialKind,
        secret: &[u8],
        ad: &mut AppData,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
        liveness: &mut dyn FnMut(),
    ) -> Result<(), PersistError> {
        if self.credential_kind != Some(kind) { return Err(PersistError::Authentication); }
        let mut key = derive_unlock_key(self.credential_kdf, secret, &self.credential_salt, liveness)?;
        let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
        let read = sd_backend::read_slot(
            &mut self.crypto, kind, self.credential_kdf, &key, &self.credential_salt, self.sd_active_slot,
            &mut record, i2c, delay,
        );
        if let Err(error) = read {
            zeroize_buf(&mut key);
            zeroize_buf(&mut record.0);
            return Err(error);
        }
        let Some(header) = crypto::parse_header(&record) else {
            zeroize_buf(&mut key);
            zeroize_buf(&mut record.0);
            return Err(PersistError::SdStorageCorrupt);
        };
        if !sd_header_matches(self, header, kind) {
            zeroize_buf(&mut key);
            zeroize_buf(&mut record.0);
            return Err(PersistError::SdStorageCorrupt);
        }
        let policy = match security_policy::decode(&mut self.crypto, header, &record) {
            security_policy::DecodeResult::Valid(policy) => policy,
            _ => {
                zeroize_buf(&mut key);
                zeroize_buf(&mut record.0);
                return Err(PersistError::SdStorageCorrupt);
            }
        };
        if policy.duress != self.security_policy.duress {
            zeroize_buf(&mut key);
            zeroize_buf(&mut record.0);
            return Err(PersistError::SdStorageCorrupt);
        }
        let restored = self.restore_record_with_key(&record, &key, ad);
        zeroize_buf(&mut record.0);
        if let Err(error) = restored {
            zeroize_buf(&mut key);
            return Err(error);
        }
        if let Err(error) = journal::erase_wallet(&mut self.flash) {
            zeroize_buf(&mut key);
            ad.wallet.seeds.seed_mgr.zeroize_all();
            wallet_session::clear_active_wallet(ad);
            return Err(error.into());
        }
        let migrate_legacy = self.credential_kdf.is_legacy();
        let final_key = if migrate_legacy {
            let current = derive_unlock_key(
                super::kdf::CredentialKdf::current(), secret, &header.salt, liveness,
            )?;
            zeroize_buf(&mut key);
            current
        } else {
            key
        };
        self.clear_credential();
        self.credential_kind = Some(kind);
        self.credential_salt = header.salt;
        self.credential_kdf = super::kdf::CredentialKdf::current();
        self.credential_key = Some(final_key);
        self.security_policy = policy;
        self.security_integrity_ok = true;
        self.mode = Some(StorageMode::SdCard);
        self.sync_security_mirror(ad);
        if migrate_legacy {
            self.save_sd_snapshot(&ad.wallet.seeds.seed_mgr, i2c, delay)?;
        } else {
            self.accept_revision(&ad.wallet.seeds.seed_mgr);
        }
        Ok(())
    }

    fn unlock_from_journal(
        &mut self,
        kind: CredentialKind,
        secret: &[u8],
        ad: &mut AppData,
        liveness: &mut dyn FnMut(),
    ) -> Result<(), PersistError> {
        let order = journal::wallet_order(&mut self.flash)?;
        let mut first_error = None;
        for address in order.into_iter().flatten() {
            match self.try_unlock_address(address, kind, secret, ad, liveness)? {
                UnlockAttempt::Unlocked => return Ok(()),
                UnlockAttempt::Skipped => {}
                UnlockAttempt::Failed(error) if first_error.is_none() => first_error = Some(error),
                UnlockAttempt::Failed(_) => {}
            }
        }
        Err(first_error.unwrap_or(PersistError::Authentication))
    }

    fn try_unlock_address(
        &mut self,
        address: u32,
        kind: CredentialKind,
        secret: &[u8],
        ad: &mut AppData,
        liveness: &mut dyn FnMut(),
    ) -> Result<UnlockAttempt, PersistError> {
        let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
        let header = journal::read_wallet(&mut self.flash, address, &mut record)?
            .ok_or(PersistError::InvalidWallet)?;
        if header.credential_kind != kind {
            zeroize_buf(&mut record.0);
            return Ok(UnlockAttempt::Skipped);
        }
        let mut key = derive_unlock_key(header.credential_kdf, secret, &header.salt, liveness)?;
        let restored = self.restore_record_with_key(&record, &key, ad);
        zeroize_buf(&mut record.0);
        match restored {
            Ok(()) => self.finish_flash_unlock(header, kind, secret, key, ad, liveness),
            Err(error) => {
                zeroize_buf(&mut key);
                Ok(UnlockAttempt::Failed(error))
            }
        }
    }

    fn finish_flash_unlock(
        &mut self,
        header: crypto::RecordHeader,
        kind: CredentialKind,
        secret: &[u8],
        mut key: [u8; 32],
        ad: &mut AppData,
        liveness: &mut dyn FnMut(),
    ) -> Result<UnlockAttempt, PersistError> {
        let mut credential_kdf = header.credential_kdf;
        if credential_kdf.is_legacy() {
            let current = kdf::CredentialKdf::current();
            let migrated = kdf::derive(
                current, PasswordKdfPurpose::PersistentWallet, secret, &header.salt, liveness,
            )?;
            zeroize_buf(&mut key);
            key = migrated;
            credential_kdf = current;
        }
        self.clear_credential();
        self.credential_kind = Some(kind);
        self.credential_salt = header.salt;
        self.credential_key = Some(key);
        self.credential_kdf = credential_kdf;
        self.mode = Some(StorageMode::SaveWallet);
        self.load_security_policy(ad)?;
        self.accept_revision(&ad.wallet.seeds.seed_mgr);
        if header.credential_kdf.is_legacy() {
            self.save_flash_snapshot(&ad.wallet.seeds.seed_mgr)?;
        }
        Ok(UnlockAttempt::Unlocked)
    }
}

pub(super) fn sd_header_matches(
    wallet: &PersistentWallet<'_>,
    header: crypto::RecordHeader,
    kind: CredentialKind,
) -> bool {
    header.sequence == wallet.sd_wallet_sequence
        && header.credential_kind == kind
        && header.salt == wallet.credential_salt
}

#[cfg(feature = "workflow-test-auto")]
fn derive_unlock_key(
    credential_kdf: kdf::CredentialKdf,
    secret: &[u8],
    salt: &[u8; SALT_SIZE],
    liveness: &mut dyn FnMut(),
) -> Result<[u8; 32], PersistError> {
    kdf::derive(
        credential_kdf,
        PasswordKdfPurpose::PersistentWallet,
        unlock_secret_for_kdf(secret),
        salt,
        liveness,
    )
}

// The current Argon2 reader rejects an empty byte string before doing KDF
// work. An empty unlock submission is still just a wrong credential, so feed
// one impossible-to-create sentinel byte into the KDF rather than exposing a
// password-length/policy distinction. Credential creation rejects empty values.
fn unlock_secret_for_kdf(secret: &[u8]) -> &[u8] {
    if secret.is_empty() { b"\0" } else { secret }
}

pub(crate) mod asynchronous;
