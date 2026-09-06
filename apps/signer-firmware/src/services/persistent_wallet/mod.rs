//! Hardware-only encrypted wallet persistence facade.
//!
//! Saved wallets require two independent factors: a user PIN/password and a
//! read-protected ESP32-S3 eFuse HMAC key. CoreS3 development firmware may
//! use an explicitly non-production software TEST HMAC identity when no hardware
//! key exists so persistence workflows can be exercised; production never does.
//! The raw credential is stretched only during setup or unlock and is not retained.

mod codec;
mod crypto;
mod flash;
mod journal;
mod kdf;
mod security_policy;
mod save;
mod sd_backend;
mod snapshot;
mod startup;
mod unlock;
mod wallet_activation;
mod advanced;
mod device;

#[cfg(not(feature = "hardware-tests"))]
pub(crate) use unlock::asynchronous::{AsyncUnlockApply, AsyncUnlockSession, UnlockKdfRequest};

use esp_hal::peripherals::{FLASH, HMAC};
use offline_signer::derivation::hmac::zeroize_buf;
pub use crate::services::credential_policy::CredentialKind;
use crate::services::credential_policy::{self, SALT_SIZE};

use crate::{
    runtime::data::AppData,
    services::wallet_session,
    wallet::seed_manager::SeedManager,
};

use crypto::DeviceCrypto;
use security_policy::SecurityPolicy;
use flash::DeviceFlash;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StorageMode {
    AlwaysStartFresh = 1,
    SaveWallet = 2,
    SdCard = 3,
}

impl StorageMode {
    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::AlwaysStartFresh),
            2 => Some(Self::SaveWallet),
            3 => Some(Self::SdCard),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupState {
    ChoiceRequired,
    Ready,
    UnlockRequired(CredentialKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupDisposition {
    ChoiceRequired,
    Ready,
    UnlockRequired(CredentialKind),
    SdFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PersistError {
    Flash,
    DeviceKeyMissing,
    Entropy,
    Crypto,
    Authentication,
    InvalidWallet,
    CredentialRequired,
    PinTooShort,
    PinTooLong,
    PinNotNumeric,
    PasswordTooShort,
    PasswordTooLong,
    PasswordNeedsLetter,
    PasswordNeedsDigit,
    AdvancedRequiresSavedWallet,
    RecoveryAcknowledgementRequired,
    AdvancedAlreadyEnabled,
    InvalidSecurityPolicy,
    PolicyIntegrity,
    DuressMatchesUnlockCredential,
    DuressTriggered,
    DeviceWipeFailed,
    SdStorageUnavailable,
    SdStorageCorrupt,
    SdStorageWrite,
    #[cfg(feature = "provisioning-ui")]
    OwnerFirmwareInvalid,
}

const PERSIST_ERROR_MESSAGES: &[&str] = &[
    "Device storage failed",
    "Device key not provisioned",
    "Hardware RNG failed",
    "Wallet encryption failed",
    "Incorrect credential or damaged wallet",
    "Saved wallet data invalid",
    "PIN or password required",
    "PIN must be at least 6 digits",
    "PIN must be 12 digits or fewer",
    "PIN must contain digits only",
    "Password must be at least 8 characters",
    "Password is too long",
    "Password needs at least one letter",
    "Password needs at least one number",
    "Advanced security requires a wallet PIN or password",
    "Confirm your recovery words are backed up",
    "This permanent feature is already enabled",
    "Advanced security policy is invalid",
    "Advanced security policy integrity failure",
    "Duress credential must differ from wallet unlock credential",
    "Incorrect credential or damaged wallet",
    "Secure device wipe failed",
    "Required SD persistence card is missing or unreadable",
    "Device-bound SD storage is corrupted or unauthenticated",
    "Device-bound SD storage write failed",
    #[cfg(feature = "provisioning-ui")]
    "Owner firmware image is invalid or too large",
];

impl PersistError {
    pub const fn message(self) -> &'static str {
        PERSIST_ERROR_MESSAGES[self as usize]
    }
}

impl From<flash::FlashError> for PersistError {
    fn from(_: flash::FlashError) -> Self { Self::Flash }
}

impl From<credential_policy::CredentialError> for PersistError {
    fn from(error: credential_policy::CredentialError) -> Self {
        use credential_policy::CredentialError::*;
        match error {
            PinTooShort => Self::PinTooShort,
            PinTooLong => Self::PinTooLong,
            PinNotNumeric => Self::PinNotNumeric,
            PasswordTooShort => Self::PasswordTooShort,
            PasswordTooLong => Self::PasswordTooLong,
            PasswordNeedsLetter => Self::PasswordNeedsLetter,
            PasswordNeedsDigit => Self::PasswordNeedsDigit,
        }
    }
}

pub struct PersistentWallet<'d> {
    crypto: DeviceCrypto<'d>,
    flash: DeviceFlash<'d>,
    mode: Option<StorageMode>,
    credential_kind: Option<CredentialKind>,
    /// Device-bound persistence without a user-entered PIN/password.
    device_only: bool,
    credential_salt: [u8; SALT_SIZE],
    credential_key: Option<[u8; 32]>,
    credential_kdf: kdf::CredentialKdf,
    saved_revision: u32,
    saved_name_revision: u32,
    failed_revision: Option<u32>,
    security_policy: SecurityPolicy,
    security_integrity_ok: bool,
    sd_active_slot: u8,
    sd_wallet_sequence: u32,
}

impl<'d> PersistentWallet<'d> {
    pub fn new(hmac: HMAC<'d>, flash: FLASH<'d>) -> Self {
        Self {
            crypto: DeviceCrypto::new(hmac),
            flash: DeviceFlash::new(flash),
            mode: None,
            credential_kind: None,
            device_only: false,
            credential_salt: [0u8; SALT_SIZE],
            credential_key: None,
            credential_kdf: kdf::CredentialKdf::current(),
            saved_revision: 0,
            saved_name_revision: 0,
            failed_revision: None,
            security_policy: SecurityPolicy::disabled(),
            security_integrity_ok: true,
            sd_active_slot: 0,
            sd_wallet_sequence: 0,
        }
    }

    /// Erase all signer-owned user persistence while preserving firmware and
    /// the non-exportable eFuse/HMAC device identity. If persistent storage
    /// has been migrated to SD, erase the device-bound SD wallet slots first;
    /// failure to erase those slots aborts before the internal anchor is lost.
    pub fn factory_reset(
        &mut self,
        ad: &mut AppData,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(), PersistError> {
        if self.mode == Some(StorageMode::SdCard) {
            sd_backend::erase_files(i2c, delay)?;
        }
        journal::erase_all_user_data(&mut self.flash)?;
        crate::services::device_wipe::zeroize_volatile(ad);
        self.mode = None;
        self.clear_credential();
        self.security_policy = SecurityPolicy::disabled();
        self.security_integrity_ok = true;
        self.sd_active_slot = 0;
        self.sd_wallet_sequence = 0;
        self.saved_revision = 0;
        self.saved_name_revision = 0;
        self.failed_revision = None;
        self.sync_security_mirror(ad);
        Ok(())
    }


    #[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
    pub(crate) fn workflow_reset_qa_storage(
        &mut self,
        ad: &mut AppData,
    ) -> Result<(), PersistError> {
        journal::erase_all_user_data(&mut self.flash)?;
        self.mode = None;
        self.clear_credential();
        self.security_policy = SecurityPolicy::disabled();
        self.security_integrity_ok = true;
        self.sd_active_slot = 0;
        self.sd_wallet_sequence = 0;
        self.saved_revision = 0;
        self.saved_name_revision = 0;
        self.failed_revision = None;
        self.sync_security_mirror(ad);
        Ok(())
    }

    #[inline(never)]
    pub fn prepare_startup(&mut self, ad: &mut AppData) -> StartupDisposition {
        match self.initialize(ad) {
            Ok(StartupState::ChoiceRequired) => StartupDisposition::ChoiceRequired,
            Ok(StartupState::Ready) => StartupDisposition::Ready,
            Ok(StartupState::UnlockRequired(kind)) => StartupDisposition::UnlockRequired(kind),
            Err(error) => {
                log!("Persistent wallet startup failed: {:?}", error);
                ad.wallet.seeds.seed_mgr.zeroize_all();
                wallet_session::clear_active_wallet(ad);
                if self.mode == Some(StorageMode::SdCard) {
                    StartupDisposition::SdFailure
                } else {
                    self.require_choice(&ad.wallet.seeds.seed_mgr);
                    StartupDisposition::ChoiceRequired
                }
            }
        }
    }



    /// Select the RAM-only policy. Device-bound storage is intentionally not available
    /// through this method because saving without a credential must be impossible.
    /// Report whether a device-storage HMAC identity is available. Production
    /// requires a read-protected hardware key; CoreS3 development may use its
    /// explicitly non-production software TEST identity when hardware is absent.
    pub fn device_key_available(&mut self) -> bool {
        self.crypto.available_key_slot().is_some()
    }

    pub fn select_fresh(&mut self, manager: &SeedManager) -> Result<(), PersistError> {
        if self.mode == Some(StorageMode::SdCard) { return Err(PersistError::AdvancedAlreadyEnabled); }
        journal::erase_wallet(&mut self.flash)?;
        journal::write_mode(&mut self.flash, StorageMode::AlwaysStartFresh)?;
        journal::write_wallet_labels(&mut self.flash, journal::WalletLabels::empty())?;
        self.mode = Some(StorageMode::AlwaysStartFresh);
        self.clear_credential();
        self.security_policy = SecurityPolicy::disabled();
        self.security_integrity_ok = true;
        self.accept_revision(manager);
        Ok(())
    }

    pub fn sync_if_needed(
        &mut self,
        manager: &SeedManager,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<bool, PersistError> {
        if !matches!(self.mode, Some(StorageMode::SaveWallet) | Some(StorageMode::SdCard)) {
            return Ok(false);
        }
        let wallet_dirty = manager.revision() != self.saved_revision;
        let labels_dirty = manager.name_revision() != self.saved_name_revision;
        if !wallet_dirty && !labels_dirty { return Ok(false); }
        if wallet_dirty
            && self.mode == Some(StorageMode::SaveWallet)
            && !self.device_only
        {
            self.migrate_outer_to_device_only(manager)?;
            return Ok(true);
        }
        if self.credential_key.is_none() { return Err(PersistError::CredentialRequired); }
        if wallet_dirty && self.failed_revision == Some(manager.revision()) { return Ok(false); }
        let result = self.persist_dirty_state(manager, i2c, delay, wallet_dirty);
        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                if wallet_dirty { self.failed_revision = Some(manager.revision()); }
                Err(error)
            }
        }
    }

    fn persist_dirty_state(
        &mut self,
        manager: &SeedManager,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
        wallet_dirty: bool,
    ) -> Result<(), PersistError> {
        if wallet_dirty {
            return if self.mode == Some(StorageMode::SdCard) {
                self.save_sd_snapshot(manager, i2c, delay)
            } else {
                self.save_flash_snapshot(manager)
            };
        }
        journal::write_wallet_labels(&mut self.flash, journal::WalletLabels::from_manager(manager))?;
        self.saved_name_revision = manager.name_revision();
        Ok(())
    }

    pub const fn is_sd_mode(&self) -> bool {
        matches!(self.mode, Some(StorageMode::SdCard))
    }

    pub fn require_choice(&mut self, manager: &SeedManager) {
        self.mode = None;
        self.clear_credential();
        self.security_policy = SecurityPolicy::disabled();
        self.security_integrity_ok = true;
        self.accept_revision(manager);
    }

    fn clear_credential(&mut self) {
        if let Some(mut key) = self.credential_key.take() { zeroize_buf(&mut key); }
        zeroize_buf(&mut self.credential_salt);
        self.credential_kind = None;
        self.device_only = false;
        self.credential_kdf = kdf::CredentialKdf::current();
    }

    fn accept_revision(&mut self, manager: &SeedManager) {
        self.saved_revision = manager.revision();
        self.saved_name_revision = manager.name_revision();
        self.failed_revision = None;
    }
}

impl Drop for PersistentWallet<'_> {
    fn drop(&mut self) { self.clear_credential(); }
}

