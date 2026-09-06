//! Runtime state for saved-wallet credentials and immutable advanced security UI flows.

use crate::services::credential_policy::CredentialKind;
use signer_firmware_core::advanced_policy::{SigningPolicy, SigningWindow, MAX_WEEKLY_WINDOWS};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStorageIntent {
    None,
    StartFresh,
    CreateInternal,
    EnableSd,
}

impl DeviceStorageIntent {
    pub const fn is_seed_onboarding(self) -> bool {
        matches!(self, Self::StartFresh | Self::CreateInternal)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnlockFeedback {
    None,
    WrongPin,
    WrongPassword,
}

impl UnlockFeedback {
    pub const fn pin_title(self) -> &'static str {
        match self {
            Self::WrongPin => "Invalid PIN",
            Self::None | Self::WrongPassword => "UNLOCK PIN",
        }
    }

    pub const fn password_title(self) -> &'static str {
        match self {
            Self::WrongPassword => "Invalid password",
            Self::None | Self::WrongPin => "UNLOCK PASSWORD",
        }
    }
}

pub struct PersistenceCredentialState {
    pub kind: Option<CredentialKind>,
    pub device_storage_intent: DeviceStorageIntent,
    pub recovery_words_acknowledged: bool,
    pub onboarding_imported_mnemonic: bool,
    pub confirmation_digest: [u8; 32],
    pub confirmation_pending: bool,
    pub unlock_failures: u8,
    pub unlock_feedback: UnlockFeedback,
    pub unlock_retry_after_ms: u64,
    pub pending_rtc_floor_unix: u64,
    pub advanced: AdvancedSecurityState,
}

impl PersistenceCredentialState {
    pub(super) const fn new() -> Self {
        Self {
            kind: None,
            device_storage_intent: DeviceStorageIntent::None,
            recovery_words_acknowledged: false,
            onboarding_imported_mnemonic: false,
            confirmation_digest: [0u8; 32],
            confirmation_pending: false,
            unlock_failures: 0,
            unlock_feedback: UnlockFeedback::None,
            unlock_retry_after_ms: 0,
            pending_rtc_floor_unix: 0,
            advanced: AdvancedSecurityState::new(),
        }
    }

    pub fn reset(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.confirmation_digest);
        self.kind = None;
        self.device_storage_intent = DeviceStorageIntent::None;
        self.recovery_words_acknowledged = false;
        self.onboarding_imported_mnemonic = false;
        self.confirmation_pending = false;
        self.unlock_failures = 0;
        self.unlock_feedback = UnlockFeedback::None;
        self.unlock_retry_after_ms = 0;
        self.pending_rtc_floor_unix = 0;
        self.advanced.clear_pending();
        #[cfg(feature = "m5stack")]
        {
            self.advanced.rtc_verification = RtcVerification::Unverified;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvancedAvailability {
    Unavailable,
    Available,
}

impl AdvancedAvailability {
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceBackendState {
    InternalFlash,
    SdCard,
}

impl PersistenceBackendState {
    pub const fn is_sd(self) -> bool { matches!(self, Self::SdCard) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuressActivation {
    Disabled,
    Enabled,
}

impl DuressActivation {
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyIntegrity {
    Invalid,
    Valid,
}

impl PolicyIntegrity {
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmationState {
    Idle,
    Pending,
}

impl ConfirmationState {
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }
}

#[cfg(feature = "m5stack")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtcVerification {
    Unverified,
    Verified,
}

#[cfg(feature = "m5stack")]
impl RtcVerification {
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }
}

pub struct AdvancedSecurityState {
    /// True whenever a persistent wallet backend is active. This is independent
    /// of whether the currently selected wallet has a user credential.
    pub saved_wallet: bool,
    /// True when the outer persistence envelope is device-bound and per-wallet
    /// credentials provide the user-presence boundary.
    pub outer_device_only: bool,
    pub availability: AdvancedAvailability,
    pub persistence_backend: PersistenceBackendState,
    pub credential_kind: Option<CredentialKind>,
    pub duress: DuressActivation,
    pub policy: SigningPolicy,
    pub policy_integrity: PolicyIntegrity,
    pub pending_confirmation_digest: [u8; 32],
    pub confirmation: ConfirmationState,
    pub pending_not_before_unix: u64,
    pub pending_windows: [SigningWindow; MAX_WEEKLY_WINDOWS],
    pub pending_weekly_count: u8,
    #[cfg(feature = "m5stack")]
    pub rtc_verification: RtcVerification,
}

impl AdvancedSecurityState {
    const fn new() -> Self {
        Self {
            saved_wallet: false,
            outer_device_only: false,
            availability: AdvancedAvailability::Unavailable,
            persistence_backend: PersistenceBackendState::InternalFlash,
            credential_kind: None,
            duress: DuressActivation::Disabled,
            policy: SigningPolicy::disabled(),
            policy_integrity: PolicyIntegrity::Valid,
            pending_confirmation_digest: [0u8; 32],
            confirmation: ConfirmationState::Idle,
            pending_not_before_unix: 0,
            pending_windows: [SigningWindow::EMPTY; MAX_WEEKLY_WINDOWS],
            pending_weekly_count: 0,
            #[cfg(feature = "m5stack")]
            rtc_verification: RtcVerification::Unverified,
        }
    }

    pub fn clear_pending(&mut self) {
        self.pending_confirmation_digest.fill(0);
        self.confirmation = ConfirmationState::Idle;
        self.pending_not_before_unix = 0;
        self.pending_windows.fill(SigningWindow::EMPTY);
        self.pending_weekly_count = 0;
    }
}
