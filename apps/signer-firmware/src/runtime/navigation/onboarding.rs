//! Explicit first-wallet onboarding transition matrix.

use crate::runtime::{data::DeviceStorageIntent, input::AppState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnboardingRoute {
    Persistence,
    Generation,
    Dice,
    SeedEntry,
    RecoveryWords,
    Scan,
    Sd,
    Stego,
}

pub(super) fn route_for(intent: DeviceStorageIntent, state: AppState) -> Option<OnboardingRoute> {
    use AppState::*;
    use OnboardingRoute::*;
    let fixed = match state {
        StorageModeChoice | StorageSeedSourceChoice | AdvancedRestoreMenu
        | RestoreWord12Detected | StorageFinalizeChoice | StorageProtectionChoice
        | StorageCredentialType | StoragePinEntry | StoragePinConfirm
        | StoragePasswordEntry | StoragePasswordConfirm
        | StorageSeedWordCountChoice { .. } => Some(Persistence),
        _ => None,
    };
    if fixed.is_some() { return fixed; }
    if !intent.is_seed_onboarding() { return None; }
    match state {
        StorageRecoveryAcknowledgement => Some(Persistence),
        SeedEntropyUnavailable { .. } | StorageSeedDiceChoice | StorageSeedDiceCountChoice
        | StorageSeedTouchChoice | TouchEntropy => Some(Generation),
        DiceRoll => Some(Dice),
        RestoreWord { .. } | ImportWord { .. } | PassphraseChoice | PassphraseEntry | ImportPrivKey
        | WalletNameEntry { purpose: 0 | 3 } => Some(SeedEntry),
        SeedBackup { .. } => Some(RecoveryWords),
        ScanQR => Some(Scan),
        SdWalletBackupFileList | SdWalletBackupImportPassphrase => Some(Sd),
        StegoImportPick | StegoImportDescChoice | StegoImportDescFile | StegoImportPass
        | StegoImportPortablePassword | StegoHintReveal
        | StegoHintPassphrase => Some(Stego),
        _ => None,
    }
}

pub(super) fn owns_state(intent: DeviceStorageIntent, state: AppState) -> bool {
    route_for(intent, state).is_some()
}

pub(super) fn transition_allowed(from: AppState, to: AppState) -> bool {
    from == to
        || source_transition_allowed(from, to)
        || entropy_transition_allowed(from, to)
        || seed_entry_transition_allowed(from, to)
        || restore_transport_transition_allowed(from, to)
        || recovery_transition_allowed(from, to)
        || credential_transition_allowed(from, to)
}

fn source_transition_allowed(from: AppState, to: AppState) -> bool {
    use AppState::*;
    match from {
        StorageModeChoice => matches!(to, StorageSeedSourceChoice | WalletNameEntry { purpose: 0 }),
        WalletNameEntry { purpose: 0 } => matches!(to, StorageModeChoice | StorageSeedWordCountChoice { action: 0 }),
        WalletNameEntry { purpose: 3 } => matches!(to, PassphraseChoice | StorageFinalizeChoice),
        StorageSeedSourceChoice => matches!(to,
            StorageModeChoice | RestoreWord { word_idx: 0 } | ScanQR
            | SdWalletBackupFileList | AdvancedRestoreMenu
        ),
        AdvancedRestoreMenu => matches!(to, StorageSeedSourceChoice | ScanQR | ImportPrivKey | StegoImportPick),
        RestoreWord12Detected => matches!(to, RestoreWord { word_idx: 11 | 12 } | PassphraseChoice),
        _ => false,
    }
}

fn entropy_transition_allowed(from: AppState, to: AppState) -> bool {
    use AppState::*;
    match from {
        StorageSeedWordCountChoice { action: 0 } => matches!(to,
            StorageModeChoice | StorageSeedDiceChoice | SeedEntropyUnavailable { word_count: 12 | 24 }
        ),
        SeedEntropyUnavailable { word_count } => match to {
            StorageSeedWordCountChoice { action: 0 } | StorageSeedDiceChoice => true,
            SeedEntropyUnavailable { word_count: retry_count } => retry_count == word_count,
            _ => false,
        },
        StorageSeedWordCountChoice { .. } => matches!(to, StorageModeChoice),
        StorageSeedDiceChoice => matches!(to,
            StorageSeedWordCountChoice { action: 0 } | StorageSeedDiceCountChoice | StorageSeedTouchChoice
        ),
        StorageSeedDiceCountChoice => matches!(to, StorageSeedDiceChoice | StorageModeChoice | DiceRoll),
        DiceRoll => matches!(to, StorageSeedDiceCountChoice | StorageSeedTouchChoice | StorageModeChoice),
        StorageSeedTouchChoice => matches!(to,
            StorageSeedWordCountChoice { action: 0 } | StorageModeChoice | TouchEntropy | PassphraseChoice
        ),
        TouchEntropy => matches!(to,
            StorageSeedTouchChoice | StorageSeedWordCountChoice { action: 0 } | StorageModeChoice | PassphraseChoice
        ),
        _ => false,
    }
}

fn seed_entry_transition_allowed(from: AppState, to: AppState) -> bool {
    restore_word_transition_allowed(from, to)
        || imported_word_transition_allowed(from, to)
        || passphrase_transition_allowed(from, to)
}

fn restore_word_transition_allowed(from: AppState, to: AppState) -> bool {
    use AppState::*;
    match from {
        RestoreWord { word_idx } => match to {
            RestoreWord { word_idx: next } => {
                next == word_idx.saturating_add(1) || next.saturating_add(1) == word_idx
            }
            RestoreWord12Detected if word_idx == 11 => true,
            StorageSeedSourceChoice | PassphraseChoice => true,
            _ => false,
        },
        _ => false,
    }
}

fn imported_word_transition_allowed(from: AppState, to: AppState) -> bool {
    use AppState::*;
    match from {
        ImportWord { word_idx: from_idx, word_count: from_count } => match to {
            ImportWord { word_idx: to_idx, word_count: to_count } => {
                from_count == to_count && to_idx == from_idx.saturating_add(1)
            }
            StorageSeedSourceChoice | PassphraseChoice => true,
            _ => false,
        },
        ImportPrivKey => matches!(to, AdvancedRestoreMenu | StorageRecoveryAcknowledgement | StorageFinalizeChoice | MainMenu),
        _ => false,
    }
}

fn passphrase_transition_allowed(from: AppState, to: AppState) -> bool {
    use AppState::*;
    match from {
        PassphraseChoice => matches!(to,
            StorageSeedSourceChoice | StorageSeedWordCountChoice { action: 0 }
            | StorageSeedTouchChoice | PassphraseEntry | SeedBackup { word_idx: 0 }
            | StorageRecoveryAcknowledgement | StorageFinalizeChoice | WalletNameEntry { purpose: 3 }
        ),
        PassphraseEntry => matches!(to,
            PassphraseChoice | StorageSeedSourceChoice | StorageSeedWordCountChoice { action: 0 }
            | SeedBackup { word_idx: 0 } | StorageRecoveryAcknowledgement
            | StorageFinalizeChoice | WalletNameEntry { purpose: 3 }
        ),
        _ => false,
    }
}

fn restore_transport_transition_allowed(from: AppState, to: AppState) -> bool {
    use AppState::*;
    match from {
        ScanQR => matches!(to, StorageSeedSourceChoice | AdvancedRestoreMenu | PassphraseChoice),
        SdWalletBackupFileList => matches!(to, StorageSeedSourceChoice | SdWalletBackupImportPassphrase),
        SdWalletBackupImportPassphrase => matches!(to, SdWalletBackupFileList | PassphraseChoice),
        StegoImportPick => matches!(to, AdvancedRestoreMenu | StegoImportDescChoice),
        StegoImportDescChoice => matches!(to, StegoImportPick | StegoImportDescFile | StegoImportPass),
        StegoImportDescFile => matches!(to, StegoImportDescChoice | StegoImportPass),
        StegoImportPass => matches!(to,
            StegoImportDescChoice | StegoImportPortablePassword | StegoHintReveal
            | PassphraseChoice | StorageRecoveryAcknowledgement
        ),
        StegoImportPortablePassword => matches!(to,
            StegoImportDescChoice | StegoHintReveal | PassphraseChoice | StorageRecoveryAcknowledgement
        ),
        StegoHintReveal => matches!(to,
            StegoHintPassphrase | PassphraseChoice | StorageRecoveryAcknowledgement
        ),
        StegoHintPassphrase => matches!(to, PassphraseChoice | StorageRecoveryAcknowledgement),
        _ => false,
    }
}

fn recovery_transition_allowed(from: AppState, to: AppState) -> bool {
    use AppState::*;
    match from {
        SeedBackup { word_idx: from_idx } => match to {
            SeedBackup { word_idx: to_idx } => to_idx == from_idx.saturating_add(1) || from_idx == to_idx.saturating_add(1),
            PassphraseChoice => from_idx == 0,
            StorageModeChoice => from_idx == 0,
            StorageRecoveryAcknowledgement => true,
            _ => false,
        },
        StorageRecoveryAcknowledgement => matches!(to, SeedBackup { .. } | StorageSeedSourceChoice | StorageFinalizeChoice | StorageProtectionChoice),
        StorageFinalizeChoice => matches!(to, StorageRecoveryAcknowledgement | PassphraseChoice | WalletNameEntry { purpose: 3 } | AdvancedRestoreMenu | StorageProtectionChoice | MainMenu),
        StorageProtectionChoice => matches!(to, StorageFinalizeChoice | StorageCredentialType | MainMenu),
        _ => false,
    }
}

fn credential_transition_allowed(from: AppState, to: AppState) -> bool {
    use AppState::*;
    match from {
        StorageCredentialType => matches!(to, StorageProtectionChoice | StoragePinEntry | StoragePasswordEntry),
        StoragePinEntry => matches!(to, StorageCredentialType | StoragePinConfirm),
        StoragePinConfirm => matches!(to, StoragePinEntry | MainMenu),
        StoragePasswordEntry => matches!(to, StorageCredentialType | StoragePasswordConfirm),
        StoragePasswordConfirm => matches!(to, StoragePasswordEntry | MainMenu),
        _ => false,
    }
}
