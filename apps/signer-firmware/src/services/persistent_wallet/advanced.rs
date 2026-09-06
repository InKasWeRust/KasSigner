//! Immutable advanced security-policy persistence and authenticated journal merging.

use offline_signer::derivation::hmac::zeroize_buf;
use crate::services::credential_policy;
use signer_firmware_core::advanced_policy::SigningPolicy;
#[cfg(feature = "m5stack")]
use signer_firmware_core::advanced_policy::{SigningWindow, MAX_WEEKLY_WINDOWS};

use crate::{
    runtime::data::{AdvancedAvailability, AppData, DuressActivation, PersistenceBackendState, PolicyIntegrity},
    wallet::seed_manager::SeedManager,
};

use super::{
    crypto::RECORD_SIZE,
    flash::AlignedBytes,
    journal,
    security_policy::{self, DecodeResult, SecurityPolicy},
    CredentialKind, PersistError, PersistentWallet, StorageMode,
};

impl<'d> PersistentWallet<'d> {
    pub fn advanced_available(&self) -> bool {
        matches!(self.mode, Some(StorageMode::SaveWallet) | Some(StorageMode::SdCard))
            && self.credential_key.is_some()
    }

    pub const fn signing_policy(&self) -> SigningPolicy {
        self.security_policy.signing
    }

    pub const fn security_integrity_ok(&self) -> bool {
        self.security_integrity_ok
    }

    pub fn enable_duress(
        &mut self,
        secret: &[u8],
        manager: &SeedManager,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(), PersistError> {
        let kind = self.require_advanced_available(manager)?;
        if !self.security_integrity_ok {
            return Err(PersistError::PolicyIntegrity);
        }
        if self.security_policy.duress.enabled {
            return Err(PersistError::AdvancedAlreadyEnabled);
        }
        credential_policy::validate(kind, secret)?;
        if self.credential_matches_active_wallet(kind, secret, manager)? {
            return Err(PersistError::DuressMatchesUnlockCredential);
        }
        let key_slot = self
            .crypto
            .available_key_slot()
            .ok_or(PersistError::DeviceKeyMissing)?;
        self.security_policy.duress =
            security_policy::create_duress(&mut self.crypto, key_slot, kind, secret)?;
        self.persist_security_redundantly(manager, i2c, delay)
    }

    #[cfg(feature = "m5stack")]
    pub fn enable_not_before(
        &mut self,
        not_before_unix: u64,
        now_unix: u64,
        manager: &SeedManager,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(), PersistError> {
        let _ = self.require_advanced_available(manager)?;
        if !self.security_integrity_ok {
            return Err(PersistError::PolicyIntegrity);
        }
        if self.security_policy.signing.not_before_unix != 0 {
            return Err(PersistError::AdvancedAlreadyEnabled);
        }
        if not_before_unix <= now_unix {
            return Err(PersistError::InvalidSecurityPolicy);
        }
        signer_firmware_core::advanced_policy::UtcDateTime::from_unix_seconds(not_before_unix)
            .map_err(|_| PersistError::InvalidSecurityPolicy)?;
        self.security_policy.signing.not_before_unix = not_before_unix;
        self.security_policy.signing.rtc_floor_unix = self
            .security_policy
            .signing
            .rtc_floor_unix
            .max(now_unix);
        self.security_policy
            .signing
            .validate()
            .map_err(|_| PersistError::InvalidSecurityPolicy)?;
        self.persist_security_redundantly(manager, i2c, delay)
    }

    #[cfg(feature = "m5stack")]
    pub fn enable_weekly_windows(
        &mut self,
        windows: [SigningWindow; MAX_WEEKLY_WINDOWS],
        count: u8,
        now_unix: u64,
        manager: &SeedManager,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(), PersistError> {
        let _ = self.require_advanced_available(manager)?;
        if !self.security_integrity_ok {
            return Err(PersistError::PolicyIntegrity);
        }
        if self.security_policy.signing.weekly_enabled {
            return Err(PersistError::AdvancedAlreadyEnabled);
        }
        self.security_policy.signing.weekly_enabled = true;
        self.security_policy.signing.weekly_count = count;
        self.security_policy.signing.windows = windows;
        self.security_policy.signing.rtc_floor_unix = self
            .security_policy
            .signing
            .rtc_floor_unix
            .max(now_unix);
        self.security_policy
            .signing
            .validate()
            .map_err(|_| PersistError::InvalidSecurityPolicy)?;
        self.persist_security_redundantly(manager, i2c, delay)
    }

    pub fn record_rtc_floor(
        &mut self,
        now_unix: u64,
        manager: &SeedManager,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(), PersistError> {
        if !self.security_policy.signing.has_time_policy() {
            return Ok(());
        }
        if !self.security_integrity_ok {
            return Err(PersistError::PolicyIntegrity);
        }
        if now_unix <= self.security_policy.signing.rtc_floor_unix {
            return Ok(());
        }
        self.security_policy.signing.rtc_floor_unix = now_unix;
        self.persist_security_once(manager, i2c, delay)
    }

    pub fn enable_sd_storage(
        &mut self,
        manager: &SeedManager,
        recovery_words_acknowledged: bool,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(), PersistError> {
        if !recovery_words_acknowledged { return Err(PersistError::RecoveryAcknowledgementRequired); }
        let _ = self.require_advanced_available(manager)?;
        if self.device_only { return Err(PersistError::SdStorageUnavailable); }
        if self.mode == Some(StorageMode::SdCard) { return Err(PersistError::AdvancedAlreadyEnabled); }
        if !self.security_integrity_ok { return Err(PersistError::PolicyIntegrity); }
        let kind = self.credential_kind.ok_or(PersistError::CredentialRequired)?;
        let mut key = *self.credential_key.as_ref().ok_or(PersistError::CredentialRequired)?;
        let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
        self.build_record_into(manager, 1, &mut record)?;
        let write = super::sd_backend::write_slot(
            &mut self.crypto, kind, &key, &self.credential_salt, 0, &record, i2c, delay,
        );
        zeroize_buf(&mut key);
        zeroize_buf(&mut record.0);
        write?;
        journal::write_sd_anchor(&mut self.flash, journal::SdAnchor {
            credential_kind: kind,
            salt: self.credential_salt,
            active_slot: 0,
            wallet_sequence: 1,
            duress: self.security_policy.duress,
            credential_kdf: self.credential_kdf,
        })?;
        self.mode = Some(StorageMode::SdCard);
        self.sd_active_slot = 0;
        self.sd_wallet_sequence = 1;
        journal::erase_wallet(&mut self.flash)?;
        self.accept_revision(manager);
        Ok(())
    }

    pub fn refresh_security_mirror(&self, ad: &mut AppData) {
        self.sync_security_mirror(ad);
    }

    pub(crate) fn duress_entered(
        &mut self,
        kind: CredentialKind,
        secret: &[u8],
        liveness: &mut (impl FnMut() + ?Sized),
    ) -> Result<bool, PersistError> {
        if self.mode == Some(StorageMode::SdCard) {
            let anchor = journal::read_sd_anchor(&mut self.flash)?
                .ok_or(PersistError::SdStorageCorrupt)?;
            return Ok(
                anchor.duress.enabled
                    && anchor.duress.kind == kind
                    && security_policy::duress_matches(
                        &mut self.crypto,
                        anchor.credential_kdf,
                        anchor.duress,
                        secret,
                        liveness,
                    ),
            );
        }
        let order = journal::wallet_order(&mut self.flash)?;
        for address in order.into_iter().flatten() {
            let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
            let Some(header) = journal::read_wallet(&mut self.flash, address, &mut record)? else {
                continue;
            };
            let decoded = security_policy::decode(&mut self.crypto, header, &record);
            let matched = match decoded {
                DecodeResult::Valid(policy)
                    if policy.duress.enabled && policy.duress.kind == kind =>
                {
                    security_policy::duress_matches(
                        &mut self.crypto,
                        header.credential_kdf,
                        policy.duress,
                        secret,
                        liveness,
                    )
                }
                _ => false,
            };
            zeroize_buf(&mut record.0);
            if matched {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn load_security_policy(&mut self, ad: &mut AppData) -> Result<(), PersistError> {
        let order = journal::wallet_order(&mut self.flash)?;
        let mut merged: Option<SecurityPolicy> = None;
        let mut integrity_ok = true;
        for address in order.into_iter().flatten() {
            let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
            let Some(header) = journal::read_wallet(&mut self.flash, address, &mut record)? else {
                continue;
            };
            match security_policy::decode(&mut self.crypto, header, &record) {
                DecodeResult::Absent => {}
                DecodeResult::Corrupt => integrity_ok = false,
                DecodeResult::Valid(candidate) => {
                    merge_security_policy(&mut merged, candidate, &mut integrity_ok)
                }
            }
            zeroize_buf(&mut record.0);
        }
        self.security_policy = merged.unwrap_or_else(SecurityPolicy::disabled);
        self.security_integrity_ok = integrity_ok;
        self.sync_security_mirror(ad);
        Ok(())
    }

    pub(super) fn sync_security_mirror(&self, ad: &mut AppData) {
        let active_kind = ad
            .wallet
            .seeds
            .seed_mgr
            .active_slot()
            .and_then(|slot| slot.protection.credential_kind());
        let saved_wallet = self.advanced_available();
        ad.storage.persistence.advanced.saved_wallet = saved_wallet;
        ad.storage.persistence.advanced.outer_device_only = self.device_only;
        ad.storage.persistence.advanced.availability = if saved_wallet && active_kind.is_some() {
            AdvancedAvailability::Available
        } else {
            AdvancedAvailability::Unavailable
        };
        ad.storage.persistence.advanced.persistence_backend = if self.mode == Some(StorageMode::SdCard) {
            PersistenceBackendState::SdCard
        } else {
            PersistenceBackendState::InternalFlash
        };
        ad.storage.persistence.advanced.credential_kind = active_kind;
        ad.storage.persistence.advanced.duress = if self.security_policy.duress.enabled {
            DuressActivation::Enabled
        } else {
            DuressActivation::Disabled
        };
        ad.storage.persistence.advanced.policy = self.security_policy.signing;
        ad.storage.persistence.advanced.policy_integrity = if self.security_integrity_ok {
            PolicyIntegrity::Valid
        } else {
            PolicyIntegrity::Invalid
        };
    }

    fn require_advanced_available(
        &self,
        manager: &SeedManager,
    ) -> Result<CredentialKind, PersistError> {
        if !self.advanced_available() {
            return Err(PersistError::AdvancedRequiresSavedWallet);
        }
        manager
            .active_slot()
            .and_then(|slot| slot.protection.credential_kind())
            .ok_or(PersistError::AdvancedRequiresSavedWallet)
    }

    fn persist_security_once(
        &mut self,
        manager: &SeedManager,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(), PersistError> {
        if self.mode == Some(StorageMode::SdCard) {
            self.save_sd_snapshot(manager, i2c, delay)
        } else {
            self.save_flash_snapshot(manager)
        }
    }

    fn persist_security_redundantly(
        &mut self,
        manager: &SeedManager,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(), PersistError> {
        if self.mode == Some(StorageMode::SdCard) {
            self.save_sd_snapshot(manager, i2c, delay)?;
            if let Err(error) = self.save_sd_snapshot(manager, i2c, delay) {
                log!("Advanced SD policy redundant write failed: {:?}", error);
            }
        } else {
            self.save_flash_snapshot(manager)?;
            if let Err(error) = self.save_flash_snapshot(manager) {
                log!("Advanced policy redundant journal write failed: {:?}", error);
            }
        }
        Ok(())
    }

    fn credential_matches_active_wallet(
        &mut self,
        kind: CredentialKind,
        secret: &[u8],
        manager: &SeedManager,
    ) -> Result<bool, PersistError> {
        let slot = usize::from(manager.active);
        let active = manager.active_slot().ok_or(PersistError::InvalidWallet)?;
        if active.protection.credential_kind() != Some(kind) {
            return Ok(false);
        }
        let (salt, verifier) = self.wallet_activation_material(slot)?;
        let mut stretched = self.derive_wallet_activation_key(secret, &salt, &mut || {})?;
        let actual = self.make_wallet_activation_verifier(slot, kind, &salt, &stretched)?;
        zeroize_buf(&mut stretched);
        Ok(shared_signer::bytes::constant_time_eq_32(&verifier, &actual))
    }
}

fn merge_security_policy(
    merged: &mut Option<SecurityPolicy>,
    candidate: SecurityPolicy,
    integrity_ok: &mut bool,
) {
    let Some(current) = merged.as_mut() else {
        *merged = Some(candidate);
        return;
    };

    if current.duress.enabled && candidate.duress.enabled {
        if current.duress != candidate.duress {
            *integrity_ok = false;
        }
    } else if candidate.duress.enabled {
        current.duress = candidate.duress;
    }

    merge_not_before(current, candidate, integrity_ok);
    merge_weekly(current, candidate, integrity_ok);
    current.signing.rtc_floor_unix = current
        .signing
        .rtc_floor_unix
        .max(candidate.signing.rtc_floor_unix);
}

fn merge_not_before(
    current: &mut SecurityPolicy,
    candidate: SecurityPolicy,
    integrity_ok: &mut bool,
) {
    let current_value = current.signing.not_before_unix;
    let candidate_value = candidate.signing.not_before_unix;
    if current_value != 0 && candidate_value != 0 && current_value != candidate_value {
        *integrity_ok = false;
    } else if current_value == 0 {
        current.signing.not_before_unix = candidate_value;
    }
}

fn merge_weekly(
    current: &mut SecurityPolicy,
    candidate: SecurityPolicy,
    integrity_ok: &mut bool,
) {
    if current.signing.weekly_enabled && candidate.signing.weekly_enabled {
        if current.signing.weekly_count != candidate.signing.weekly_count
            || current.signing.windows != candidate.signing.windows
        {
            *integrity_ok = false;
        }
    } else if candidate.signing.weekly_enabled {
        current.signing.weekly_enabled = true;
        current.signing.weekly_count = candidate.signing.weekly_count;
        current.signing.windows = candidate.signing.windows;
    }
}

