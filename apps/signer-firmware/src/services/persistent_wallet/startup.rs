//! Startup selection and recovery for persistent wallet backends.
//!
//! Each stage is deliberately small because firmware code is assessed from
//! source complexity when host coverage is unavailable.

use crate::runtime::data::AppData;
use offline_signer::derivation::hmac::zeroize_buf;

use super::{
    PersistError, PersistentWallet, StartupState, StorageMode,
    crypto::{RecordHeader, RECORD_SIZE},
    flash::AlignedBytes,
    journal::{self, SdAnchor},
    security_policy::SecurityPolicy,
};

impl PersistentWallet<'_> {
    pub fn initialize(&mut self, ad: &mut AppData) -> Result<StartupState, PersistError> {
        journal::read_mode(&mut self.flash)
            .map_err(PersistError::from)
            .and_then(|configured| self.initialize_configured(ad, configured))
    }

    fn initialize_configured(
        &mut self,
        ad: &mut AppData,
        configured: Option<StorageMode>,
    ) -> Result<StartupState, PersistError> {
        if configured == Some(StorageMode::SdCard) { return self.initialize_sd(ad); }
        self.initialize_internal(ad, configured)
    }

    fn initialize_sd(&mut self, ad: &mut AppData) -> Result<StartupState, PersistError> {
        self.mode = Some(StorageMode::SdCard);
        self.require_device_key().and_then(|()| self.read_sd_anchor(ad))
    }

    fn require_device_key(&mut self) -> Result<(), PersistError> {
        self.crypto.available_key_slot()
            .map(|_| ())
            .ok_or(PersistError::DeviceKeyMissing)
    }

    fn read_sd_anchor(&mut self, ad: &mut AppData) -> Result<StartupState, PersistError> {
        journal::read_sd_anchor(&mut self.flash)
            .map_err(PersistError::from)
            .and_then(|anchor| anchor.ok_or(PersistError::SdStorageCorrupt))
            .map(|anchor| self.apply_sd_anchor(ad, anchor))
    }

    fn apply_sd_anchor(&mut self, ad: &mut AppData, anchor: SdAnchor) -> StartupState {
        self.credential_kind = Some(anchor.credential_kind);
        self.credential_salt = anchor.salt;
        self.credential_kdf = anchor.credential_kdf;
        self.sd_active_slot = anchor.active_slot;
        self.sd_wallet_sequence = anchor.wallet_sequence;
        self.security_policy = SecurityPolicy {
            duress: anchor.duress,
            signing: signer_firmware_core::advanced_policy::SigningPolicy::disabled(),
        };
        self.security_integrity_ok = true;
        self.sync_security_mirror(ad);
        StartupState::UnlockRequired(anchor.credential_kind)
    }

    fn initialize_internal(
        &mut self,
        ad: &mut AppData,
        configured: Option<StorageMode>,
    ) -> Result<StartupState, PersistError> {
        journal::latest_wallet_header(&mut self.flash)
            .map_err(PersistError::from)
            .and_then(|latest| self.initialize_wallet_or_empty(ad, configured, latest))
    }

    fn initialize_wallet_or_empty(
        &mut self,
        ad: &mut AppData,
        configured: Option<StorageMode>,
        latest: Option<RecordHeader>,
    ) -> Result<StartupState, PersistError> {
        match latest {
            Some(header) => self.initialize_saved(ad, configured, header),
            None => self.initialize_empty(ad),
        }
    }

    fn initialize_saved(
        &mut self,
        ad: &mut AppData,
        configured: Option<StorageMode>,
        header: RecordHeader,
    ) -> Result<StartupState, PersistError> {
        self.require_device_key()
            .and_then(|()| self.prepare_save_wallet_mode(configured))
            .and_then(|()| self.initialize_saved_header(ad, header))
    }

    fn prepare_save_wallet_mode(
        &mut self,
        configured: Option<StorageMode>,
    ) -> Result<(), PersistError> {
        self.mode = Some(StorageMode::SaveWallet);
        if configured == Some(StorageMode::SaveWallet) { return Ok(()); }
        journal::write_mode(&mut self.flash, StorageMode::SaveWallet).map_err(PersistError::from)
    }

    fn initialize_saved_header(
        &mut self,
        ad: &mut AppData,
        header: RecordHeader,
    ) -> Result<StartupState, PersistError> {
        self.credential_kdf = header.credential_kdf;
        if header.device_only {
            return self.initialize_device_only(ad);
        }
        self.device_only = false;
        self.initialize_credential_kind(ad, header.credential_kind)
    }

    fn initialize_device_only(
        &mut self,
        ad: &mut AppData,
    ) -> Result<StartupState, PersistError> {
        let key = [0u8; 32];
        let order = journal::wallet_order(&mut self.flash)?;
        let mut first_error = None;
        for address in order.into_iter().flatten() {
            let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
            let Some(header) = journal::read_wallet(&mut self.flash, address, &mut record)? else {
                zeroize_buf(&mut record.0);
                continue;
            };
            if !header.device_only {
                zeroize_buf(&mut record.0);
                continue;
            }
            let restored = self.restore_record_with_key(&record, &key, ad);
            zeroize_buf(&mut record.0);
            if let Err(error) = restored {
                if first_error.is_none() { first_error = Some(error); }
                continue;
            }
            self.clear_credential();
            self.credential_kind = Some(header.credential_kind);
            self.device_only = true;
            self.credential_salt = header.salt;
            self.credential_key = Some(key);
            self.credential_kdf = header.credential_kdf;
            self.mode = Some(StorageMode::SaveWallet);
            self.load_security_policy(ad)?;
            self.accept_revision(&ad.wallet.seeds.seed_mgr);
            return Ok(StartupState::Ready);
        }
        Err(first_error.unwrap_or(PersistError::Authentication))
    }

    fn initialize_credential_kind(
        &mut self,
        ad: &mut AppData,
        kind: crate::services::credential_policy::CredentialKind,
    ) -> Result<StartupState, PersistError> {
        self.credential_kind = Some(kind);
        self.load_security_policy(ad).map(|()| StartupState::UnlockRequired(kind))
    }

    fn initialize_empty(&mut self, ad: &mut AppData) -> Result<StartupState, PersistError> {
        // No saved wallet means there is no persistence policy to resume. Even
        // if a previous RAM-only session wrote AlwaysStartFresh, boot must let
        // the user choose RAM-only or Device-Bound storage before seed setup.
        self.initialize_choice(ad)
    }

    fn initialize_choice(&mut self, ad: &mut AppData) -> Result<StartupState, PersistError> {
        self.require_choice(&ad.wallet.seeds.seed_mgr);
        Ok(StartupState::ChoiceRequired)
    }
}
