//! Long-running operation kinds and application-level execution/liveness policy.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    SaveWalletPin,
    SaveWalletPassword,
    UnlockWalletPin,
    UnlockWalletPassword,
    ConnectKasSee,
    DeriveMultisigKpub,
    SignTransaction,
}

/// How one operation advances once its loading surface has been presented.
/// Every kind uses the same lifecycle; the execution policy only determines
/// whether the engine runs a foreground-exclusive heavy operation or repeated
/// short steps. Foreground-exclusive operations render their loading surface
/// first, then own subsequent runtime frames until completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationExecution {
    ForegroundExclusive,
    Stepped,
}

impl OperationKind {
    pub(crate) const fn is_credential(self) -> bool {
        matches!(
            self,
            Self::SaveWalletPin
                | Self::SaveWalletPassword
                | Self::UnlockWalletPin
                | Self::UnlockWalletPassword
        )
    }

    pub(crate) const fn credential_marker(self) -> &'static str {
        match self {
            Self::SaveWalletPin => "save pin",
            Self::SaveWalletPassword => "save password",
            Self::UnlockWalletPin => "unlock pin",
            Self::UnlockWalletPassword => "unlock password",
            Self::ConnectKasSee | Self::DeriveMultisigKpub | Self::SignTransaction => "non-credential",
        }
    }

    pub(crate) const fn execution(self) -> OperationExecution {
        match self {
            Self::SaveWalletPin
            | Self::SaveWalletPassword
            | Self::UnlockWalletPin
            | Self::UnlockWalletPassword => OperationExecution::ForegroundExclusive,
            Self::ConnectKasSee | Self::DeriveMultisigKpub | Self::SignTransaction => {
                OperationExecution::Stepped
            }
        }
    }

    pub(crate) const fn stepped(self) -> bool {
        matches!(self.execution(), OperationExecution::Stepped)
    }

    pub(crate) const fn asynchronous(self) -> bool {
        matches!(self.execution(), OperationExecution::ForegroundExclusive | OperationExecution::Stepped)
    }

    /// Maximum wall-clock duration for one asynchronous operation. The hardware
    /// watchdog remains a final liveness backstop, not the application deadline.
    pub(crate) const fn total_budget_ms(self) -> u64 {
        match self {
            Self::ConnectKasSee | Self::DeriveMultisigKpub => 75_000,
            Self::SignTransaction => 180_000,
            Self::SaveWalletPin
            | Self::SaveWalletPassword
            | Self::UnlockWalletPin
            | Self::UnlockWalletPassword => 85_000,
        }
    }

    pub(crate) const fn stall_budget_ms(self) -> u64 {
        match self {
            Self::ConnectKasSee | Self::DeriveMultisigKpub | Self::SignTransaction => 20_000,
            Self::SaveWalletPin
            | Self::SaveWalletPassword
            | Self::UnlockWalletPin
            | Self::UnlockWalletPassword => 85_000,
        }
    }
}
