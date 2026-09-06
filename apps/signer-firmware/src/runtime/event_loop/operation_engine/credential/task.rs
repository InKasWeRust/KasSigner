//! Foreground-exclusive credential task state for the unified operation engine.
//!
//! Argon2 uses a multi-megabyte PSRAM workspace and executes synchronously in
//! the foreground event-loop operation lane. Each subtask performs at most one
//! KDF per engine service call so multi-candidate unlock returns to the outer
//! liveness boundary between attempts.

use crate::{
    hw::display::BootDisplay,
    runtime::data::{AppData, OperationKind},
    services::persistent_wallet::{CredentialKind, PersistError, PersistentWallet},
};

mod activation;
mod begin;
mod save;
mod secret;
mod unlock;

use activation::{WalletActivationMode, WalletActivationTask};
use save::SaveTask;
use secret::SecretBuffer;
use unlock::{next_unlock_request, UnlockTask};

pub(super) enum Task {
    Save(SaveTask),
    Unlock(UnlockTask),
    WalletActivation(WalletActivationTask),
}

impl Task {
    pub(super) fn begin(
        ad: &mut AppData,
        operation: OperationKind,
        persistence: &mut PersistentWallet<'_>,
    ) -> Result<Self, PersistError> {
        begin::begin(ad, operation, persistence)
    }

    pub(super) fn step(
        &mut self,
        ad: &mut AppData,
        persistence: &mut PersistentWallet<'_>,
        display: &mut BootDisplay<'_>,
        delay: &mut esp_hal::delay::Delay,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        liveness: &mut (impl FnMut() + ?Sized),
    ) -> Step {
        match self {
            Self::Save(task) => task.step(ad, persistence, display, liveness),
            Self::Unlock(task) => task.step(ad, persistence, delay, i2c, liveness),
            Self::WalletActivation(task) => task.step(ad, persistence, delay, i2c, liveness),
        }
    }

    pub(super) fn cancel(mut self) {
        match &mut self {
            Self::Save(task) => task.secret.clear(),
            Self::Unlock(task) => task.secret.clear(),
            Self::WalletActivation(task) => task.secret.clear(),
        }
    }
}

pub(super) enum Step {
    Continue,
    Complete {
        kind: OperationKind,
        result: Result<(), PersistError>,
    },
}

pub(super) const fn credential_kind(operation: OperationKind) -> Option<(CredentialKind, bool)> {
    match operation {
        OperationKind::SaveWalletPin => Some((CredentialKind::Pin, false)),
        OperationKind::SaveWalletPassword => Some((CredentialKind::Password, false)),
        OperationKind::UnlockWalletPin => Some((CredentialKind::Pin, true)),
        OperationKind::UnlockWalletPassword => Some((CredentialKind::Password, true)),
        OperationKind::ConnectKasSee
        | OperationKind::DeriveMultisigKpub
        | OperationKind::SignTransaction => None,
    }
}
