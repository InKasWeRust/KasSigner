//! Event-loop-friendly persistent-wallet unlock transaction.

use offline_signer::{crypto::password_kdf::PasswordKdfPurpose, derivation::hmac::zeroize_buf};
use crate::services::credential_policy::{CredentialKind, SALT_SIZE};

use crate::{runtime::data::AppData, services::wallet_session};

use super::super::{
    PersistError, PersistentWallet, StorageMode,
    crypto::{self, RECORD_SIZE}, flash::AlignedBytes, journal, kdf, sd_backend, security_policy,
};


struct SecretKey([u8; 32]);

impl SecretKey {
    fn new(key: [u8; 32]) -> Self { Self(key) }
    fn take(&mut self) -> [u8; 32] { core::mem::replace(&mut self.0, [0u8; 32]) }
}

impl core::ops::Deref for SecretKey {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl core::ops::DerefMut for SecretKey {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl Drop for SecretKey {
    fn drop(&mut self) { zeroize_buf(&mut self.0); }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnlockKdfRequest {
    pub(crate) kdf: kdf::CredentialKdf,
    pub(crate) salt: [u8; SALT_SIZE],
}

impl UnlockKdfRequest {
    pub(crate) fn derive(
        self,
        secret: &[u8],
        liveness: &mut (impl FnMut() + ?Sized),
    ) -> Result<[u8; 32], PersistError> {
        kdf::derive(
            self.kdf,
            PasswordKdfPurpose::PersistentWallet,
            super::unlock_secret_for_kdf(secret),
            &self.salt,
            liveness,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AsyncUnlockPhase {
    Duress,
    Wallet,
    Migration,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AsyncUnlockPending {
    None,
    Duress(security_policy::DuressPolicy),
    Flash { address: u32, header: crypto::RecordHeader },
    Sd,
    MigrationFlash(crypto::RecordHeader),
    MigrationSd { header: crypto::RecordHeader, policy: security_policy::SecurityPolicy },
}

pub(crate) struct AsyncUnlockSession {
    kind: CredentialKind,
    phase: AsyncUnlockPhase,
    order: [Option<u32>; 2],
    wallet_index: usize,
    pending: AsyncUnlockPending,
    first_error: Option<PersistError>,
}

pub(crate) enum AsyncUnlockApply {
    Continue,
    Complete(Result<(), PersistError>),
}

impl PersistentWallet<'_> {
    pub(crate) fn begin_async_unlock(
        &mut self,
        kind: CredentialKind,
        secret: &[u8],
    ) -> Result<AsyncUnlockSession, PersistError> {
        // Unlock guesses are authentication inputs, not credential-creation
        // candidates. Applying creation policy here leaks password/PIN rules
        // and routes short or otherwise malformed guesses to a policy error
        // instead of the ordinary invalid-credential retry surface.
        let _ = secret;
        let order = if self.mode == Some(StorageMode::SdCard) {
            [None, None]
        } else {
            journal::wallet_order(&mut self.flash)?
        };
        Ok(AsyncUnlockSession {
            kind,
            phase: AsyncUnlockPhase::Duress,
            order,
            wallet_index: 0,
            pending: AsyncUnlockPending::None,
            first_error: None,
        })
    }

    pub(crate) fn next_async_unlock_kdf(
        &mut self,
        session: &mut AsyncUnlockSession,
    ) -> Result<Option<UnlockKdfRequest>, PersistError> {
        loop {
            match session.phase {
                AsyncUnlockPhase::Duress => {
                    if let Some(request) = self.next_duress_kdf(session) {
                        return Ok(Some(request));
                    }
                }
                AsyncUnlockPhase::Wallet => return self.next_wallet_kdf(session),
                AsyncUnlockPhase::Migration => return self.next_migration_kdf(session).map(Some),
                AsyncUnlockPhase::Complete => return Ok(None),
            }
        }
    }

    fn next_duress_kdf(&self, session: &mut AsyncUnlockSession) -> Option<UnlockKdfRequest> {
        let policy = self.security_policy.duress;
        session.phase = AsyncUnlockPhase::Wallet;
        if !policy.enabled || policy.kind != session.kind {
            return None;
        }
        session.pending = AsyncUnlockPending::Duress(policy);
        Some(UnlockKdfRequest { kdf: self.credential_kdf, salt: policy.salt })
    }

    fn next_wallet_kdf(
        &mut self,
        session: &mut AsyncUnlockSession,
    ) -> Result<Option<UnlockKdfRequest>, PersistError> {
        if self.mode == Some(StorageMode::SdCard) {
            return Ok(self.next_sd_wallet_kdf(session));
        }
        self.next_flash_wallet_kdf(session)
    }

    fn next_sd_wallet_kdf(&self, session: &mut AsyncUnlockSession) -> Option<UnlockKdfRequest> {
        if self.credential_kind != Some(session.kind) {
            session.phase = AsyncUnlockPhase::Complete;
            return None;
        }
        session.pending = AsyncUnlockPending::Sd;
        Some(UnlockKdfRequest { kdf: self.credential_kdf, salt: self.credential_salt })
    }

    fn next_flash_wallet_kdf(
        &mut self,
        session: &mut AsyncUnlockSession,
    ) -> Result<Option<UnlockKdfRequest>, PersistError> {
        loop {
            let Some(address) = session.order.get(session.wallet_index).copied().flatten() else {
                session.phase = AsyncUnlockPhase::Complete;
                return Ok(None);
            };
            session.wallet_index = session.wallet_index.saturating_add(1);
            let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
            let header = journal::read_wallet(&mut self.flash, address, &mut record)?;
            zeroize_buf(&mut record.0);
            let Some(header) = header else { continue; };
            if header.credential_kind != session.kind { continue; }
            session.pending = AsyncUnlockPending::Flash { address, header };
            return Ok(Some(UnlockKdfRequest { kdf: header.credential_kdf, salt: header.salt }));
        }
    }

    fn next_migration_kdf(
        &self,
        session: &AsyncUnlockSession,
    ) -> Result<UnlockKdfRequest, PersistError> {
        let header = match session.pending {
            AsyncUnlockPending::MigrationFlash(header) => header,
            AsyncUnlockPending::MigrationSd { header, .. } => header,
            _ => return Err(PersistError::InvalidWallet),
        };
        Ok(UnlockKdfRequest { kdf: kdf::CredentialKdf::current(), salt: header.salt })
    }

    pub(crate) fn apply_async_unlock_key(
        &mut self,
        session: &mut AsyncUnlockSession,
        key: [u8; 32],
        ad: &mut AppData,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<AsyncUnlockApply, PersistError> {
        let key = SecretKey::new(key);
        let pending = core::mem::replace(&mut session.pending, AsyncUnlockPending::None);
        match pending {
            AsyncUnlockPending::Duress(policy) => {
                self.apply_duress_key(session, policy, key, ad, i2c, delay)
            }
            AsyncUnlockPending::Flash { address, header } => {
                self.apply_flash_key(session, address, header, key, ad)
            }
            AsyncUnlockPending::Sd => self.apply_sd_key(session, key, ad, i2c, delay),
            AsyncUnlockPending::MigrationFlash(header) => {
                self.apply_migration_flash_key(session, header, key, ad)
            }
            AsyncUnlockPending::MigrationSd { header, policy } => {
                self.apply_migration_sd_key(session, header, policy, key, ad, i2c, delay)
            }
            AsyncUnlockPending::None => Err(PersistError::InvalidWallet),
        }
    }

    fn apply_duress_key(
        &mut self,
        session: &mut AsyncUnlockSession,
        policy: security_policy::DuressPolicy,
        mut key: SecretKey,
        ad: &mut AppData,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<AsyncUnlockApply, PersistError> {
        let actual = self.crypto.duress_verifier(
            policy.key_slot, policy.kind, &policy.salt, &*key,
        );
        zeroize_buf(&mut *key);
        let matched = actual
            .map(|value| shared_signer::bytes::constant_time_eq(&value, &policy.verifier))
            .unwrap_or(false);
        if !matched {
            return Ok(AsyncUnlockApply::Continue);
        }
        session.phase = AsyncUnlockPhase::Complete;
        Ok(AsyncUnlockApply::Complete(self.trigger_duress(ad, i2c, delay)))
    }

    fn apply_flash_key(
        &mut self,
        session: &mut AsyncUnlockSession,
        address: u32,
        header: crypto::RecordHeader,
        mut key: SecretKey,
        ad: &mut AppData,
    ) -> Result<AsyncUnlockApply, PersistError> {
        let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
        let read = journal::read_wallet(&mut self.flash, address, &mut record)?;
        let result = if read == Some(header) {
            self.restore_record_with_key(&record, &*key, ad)
        } else {
            Err(PersistError::InvalidWallet)
        };
        zeroize_buf(&mut record.0);
        if let Err(error) = result {
            zeroize_buf(&mut *key);
            if session.first_error.is_none() { session.first_error = Some(error); }
            return Ok(AsyncUnlockApply::Continue);
        }
        if header.credential_kdf.is_legacy() {
            zeroize_buf(&mut *key);
            session.phase = AsyncUnlockPhase::Migration;
            session.pending = AsyncUnlockPending::MigrationFlash(header);
            return Ok(AsyncUnlockApply::Continue);
        }
        self.finish_async_flash_unlock(header, session.kind, key.take(), ad)?;
        session.phase = AsyncUnlockPhase::Complete;
        Ok(AsyncUnlockApply::Complete(Ok(())))
    }

    fn apply_sd_key(
        &mut self,
        session: &mut AsyncUnlockSession,
        mut key: SecretKey,
        ad: &mut AppData,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<AsyncUnlockApply, PersistError> {
        let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
        let validated = self.read_validated_sd_record(session.kind, &key, &mut record, i2c, delay);
        let (header, policy) = match validated {
            Ok(value) => value,
            Err(error) => {
                zeroize_buf(&mut record.0);
                return Ok(complete_apply_error(session, error));
            }
        };
        let restored = self.restore_record_with_key(&record, &*key, ad);
        zeroize_buf(&mut record.0);
        if let Err(error) = restored {
            return Ok(complete_apply_error(session, error));
        }
        if let Err(error) = journal::erase_wallet(&mut self.flash) {
            zeroize_buf(&mut *key);
            ad.wallet.seeds.seed_mgr.zeroize_all();
            wallet_session::clear_active_wallet(ad);
            return Ok(complete_apply_error(session, error.into()));
        }
        if self.credential_kdf.is_legacy() {
            zeroize_buf(&mut *key);
            session.phase = AsyncUnlockPhase::Migration;
            session.pending = AsyncUnlockPending::MigrationSd { header, policy };
            return Ok(AsyncUnlockApply::Continue);
        }
        self.finish_async_sd_unlock(header, session.kind, key.take(), policy, ad)?;
        session.phase = AsyncUnlockPhase::Complete;
        Ok(AsyncUnlockApply::Complete(Ok(())))
    }

    fn read_validated_sd_record(
        &mut self,
        kind: CredentialKind,
        key: &SecretKey,
        record: &mut AlignedBytes<RECORD_SIZE>,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(crypto::RecordHeader, security_policy::SecurityPolicy), PersistError> {
        sd_backend::read_slot(
            &mut self.crypto,
            kind,
            self.credential_kdf,
            &**key,
            &self.credential_salt,
            self.sd_active_slot,
            record,
            i2c,
            delay,
        )?;
        let header = crypto::parse_header(record).ok_or(PersistError::SdStorageCorrupt)?;
        if !super::sd_header_matches(self, header, kind) {
            return Err(PersistError::SdStorageCorrupt);
        }
        let policy = match security_policy::decode(&mut self.crypto, header, record) {
            security_policy::DecodeResult::Valid(policy) => policy,
            _ => return Err(PersistError::SdStorageCorrupt),
        };
        if policy.duress != self.security_policy.duress {
            return Err(PersistError::SdStorageCorrupt);
        }
        Ok((header, policy))
    }

    fn apply_migration_flash_key(
        &mut self,
        session: &mut AsyncUnlockSession,
        header: crypto::RecordHeader,
        mut key: SecretKey,
        ad: &mut AppData,
    ) -> Result<AsyncUnlockApply, PersistError> {
        self.finish_async_flash_unlock(header, session.kind, key.take(), ad)?;
        self.save_flash_snapshot(&ad.wallet.seeds.seed_mgr)?;
        session.phase = AsyncUnlockPhase::Complete;
        Ok(AsyncUnlockApply::Complete(Ok(())))
    }

    fn apply_migration_sd_key(
        &mut self,
        session: &mut AsyncUnlockSession,
        header: crypto::RecordHeader,
        policy: security_policy::SecurityPolicy,
        mut key: SecretKey,
        ad: &mut AppData,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<AsyncUnlockApply, PersistError> {
        self.finish_async_sd_unlock(header, session.kind, key.take(), policy, ad)?;
        self.save_sd_snapshot(&ad.wallet.seeds.seed_mgr, i2c, delay)?;
        session.phase = AsyncUnlockPhase::Complete;
        Ok(AsyncUnlockApply::Complete(Ok(())))
    }

    pub(crate) fn async_unlock_terminal_error(
        &self,
        session: &AsyncUnlockSession,
    ) -> PersistError {
        session.first_error.unwrap_or(PersistError::Authentication)
    }

    fn finish_async_flash_unlock(
        &mut self,
        header: crypto::RecordHeader,
        kind: CredentialKind,
        key: [u8; 32],
        ad: &mut AppData,
    ) -> Result<(), PersistError> {
        self.clear_credential();
        self.credential_kind = Some(kind);
        self.credential_salt = header.salt;
        self.credential_key = Some(key);
        self.credential_kdf = kdf::CredentialKdf::current();
        self.mode = Some(StorageMode::SaveWallet);
        self.load_security_policy(ad)?;
        self.migrate_outer_to_device_only(&ad.wallet.seeds.seed_mgr)?;
        self.sync_security_mirror(ad);
        Ok(())
    }

    fn finish_async_sd_unlock(
        &mut self,
        header: crypto::RecordHeader,
        kind: CredentialKind,
        key: [u8; 32],
        policy: security_policy::SecurityPolicy,
        ad: &mut AppData,
    ) -> Result<(), PersistError> {
        self.clear_credential();
        self.credential_kind = Some(kind);
        self.credential_salt = header.salt;
        self.credential_kdf = kdf::CredentialKdf::current();
        self.credential_key = Some(key);
        self.security_policy = policy;
        self.security_integrity_ok = true;
        self.mode = Some(StorageMode::SdCard);
        self.sync_security_mirror(ad);
        self.accept_revision(&ad.wallet.seeds.seed_mgr);
        Ok(())
    }
}

fn complete_apply_error(
    session: &mut AsyncUnlockSession,
    error: PersistError,
) -> AsyncUnlockApply {
    session.phase = AsyncUnlockPhase::Complete;
    AsyncUnlockApply::Complete(Err(error))
}

