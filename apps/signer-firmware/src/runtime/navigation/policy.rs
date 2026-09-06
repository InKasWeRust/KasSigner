//! Navigation ownership and cross-workflow transition policy.

use crate::runtime::{data::DeviceStorageIntent, input::{AppState, HandlerGroup}};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NavigationOwner {
    Onboarding,
    Main,
    Seeds,
    Settings,
    Signing,
    Export,
    Storage,
    Stego,
    Multisig,
    #[cfg(feature = "workflow-tests")]
    WorkflowTests,
}


pub(super) fn owner_for_intent(intent: DeviceStorageIntent, state: AppState, current: NavigationOwner) -> NavigationOwner {
    if intent == DeviceStorageIntent::EnableSd && is_sd_enable_state(state) {
        return NavigationOwner::Settings;
    }
    // QR presentation belongs to the workflow that produced the payload. A
    // stale seed-onboarding storage intent must not steal a later Signing,
    // Export, Storage, or Multisig result screen. Active onboarding still
    // retains QR ownership because its current owner is already Onboarding.
    if is_qr_state(state) {
        if current == NavigationOwner::Onboarding && super::onboarding::owns_state(intent, state) {
            return NavigationOwner::Onboarding;
        }
        return qr_owner(current);
    }
    if super::onboarding::owns_state(intent, state) {
        return NavigationOwner::Onboarding;
    }
    if state == AppState::StorageSdFailure && current == NavigationOwner::Settings {
        return NavigationOwner::Settings;
    }
    fixed_owner(state, current).unwrap_or_else(|| owner_from_handler(state.handler_group(), current))
}

pub(crate) fn transition_allowed(
    from: NavigationOwner,
    to: NavigationOwner,
    from_state: AppState,
    to_state: AppState,
) -> bool {
    if special_transition_allowed(from, to, from_state, to_state) {
        return true;
    }
    if from == to {
        return from != NavigationOwner::Onboarding
            || super::onboarding::transition_allowed(from_state, to_state);
    }
    if from_state == AppState::MainMenu
        && matches!(to_state, AppState::StorageModeChoice | AppState::StorageUnlockPin | AppState::StorageUnlockPassword)
    {
        return true;
    }
    if from_state == AppState::MainMenu {
        return super::root::transition_allowed(to_state) && owner_transition_allowed(from, to);
    }
    if to_state == AppState::MainMenu { return from != NavigationOwner::Onboarding; }
    owner_transition_allowed(from, to)
}

fn special_transition_allowed(
    from: NavigationOwner,
    to: NavigationOwner,
    from_state: AppState,
    to_state: AppState,
) -> bool {
    // Add Wallet reuses the hardened persistence credential screens without
    // becoming first-device onboarding. Keep only the exact bridges required
    // by recovery acknowledgement -> protection -> credential -> WALLETS.
    if add_wallet_restore_transport_bridge(from, to, from_state, to_state) { return true; }
    if add_wallet_persistence_bridge(from_state, to_state) { return true; }
    if wallet_protection_persistence_bridge(from_state, to_state) { return true; }
    // Advanced Backup is Seeds-owned, while the steganographic export flow is
    // Stego-owned. Permit only this explicit production entry edge; do not
    // broaden Seeds -> Stego transitions generally.
    if backup_recovery_stego_entry_allowed(from, to, from_state, to_state) { return true; }
    // Recovery-word viewing reuses the SeedBackup pager, but ordinary Wallet/
    // export callers are not onboarding. Permit only its explicit bounded
    // return destinations so Back cannot fall through to onboarding recovery.
    seed_backup_return_allowed(from, from_state, to_state)
}

pub(crate) fn safe_recovery(owner: NavigationOwner) -> AppState {
    use NavigationOwner::*;
    match owner {
        Onboarding => AppState::StorageModeChoice,
        Settings => AppState::SettingsMenu,
        Seeds => AppState::SeedsMenu,
        Multisig => AppState::MultisigMenu,
        #[cfg(feature = "workflow-tests")]
        WorkflowTests => AppState::WorkflowTestsMenu,
        Main | Signing | Export | Storage | Stego => AppState::MainMenu,
    }
}

pub(crate) fn recovery_owner(owner: NavigationOwner) -> NavigationOwner {
    use NavigationOwner::*;
    match owner {
        Onboarding => Onboarding,
        Settings => Settings,
        Seeds => Seeds,
        Multisig => Multisig,
        #[cfg(feature = "workflow-tests")]
        WorkflowTests => WorkflowTests,
        _ => Main,
    }
}



fn add_wallet_restore_transport_bridge(
    from: NavigationOwner,
    to: NavigationOwner,
    from_state: AppState,
    to_state: AppState,
) -> bool {
    use AppState::*;
    use NavigationOwner::*;
    matches!(
        (from, to, from_state, to_state),
        (Onboarding, Seeds, StorageSeedSourceChoice, AddWalletChoice)
            | (Onboarding, Seeds, StorageSeedSourceChoice, RestoreWord { word_idx: 0 })
            | (Seeds, Onboarding, RestoreWord { .. }, StorageSeedSourceChoice)
            | (Seeds, Onboarding, PassphraseChoice, StorageSeedSourceChoice)
            | (Seeds, Onboarding, RestoreWord { word_idx: 11 }, RestoreWord12Detected)
            | (Onboarding, Seeds, RestoreWord12Detected, RestoreWord { word_idx: 11 | 12 })
            | (Onboarding, Seeds, RestoreWord12Detected, PassphraseChoice)
            | (Onboarding, Signing, StorageSeedSourceChoice, ScanQR)
            | (Signing, Onboarding, ScanQR, StorageSeedSourceChoice)
            | (Onboarding, Storage, StorageSeedSourceChoice, SdWalletBackupFileList)
            | (Storage, Onboarding, SdWalletBackupFileList, StorageSeedSourceChoice)
            | (Onboarding, Signing, AdvancedRestoreMenu, ScanQR)
            | (Signing, Onboarding, ScanQR, AdvancedRestoreMenu)
            | (Onboarding, Stego, AdvancedRestoreMenu, StegoImportPick)
            | (Stego, Onboarding, StegoImportPick, AdvancedRestoreMenu)
            | (Onboarding, Seeds, AdvancedRestoreMenu, ImportPrivKey)
            | (Seeds, Onboarding, ImportPrivKey, AdvancedRestoreMenu)
    )
}

fn add_wallet_persistence_bridge(from_state: AppState, to_state: AppState) -> bool {
    use AppState::*;
    matches!(
        (from_state, to_state),
        (StorageRecoveryAcknowledgement, StorageProtectionChoice)
            | (StorageProtectionChoice, StorageRecoveryAcknowledgement)
            | (WalletNameEntry { purpose: 3 }, StorageFinalizeChoice)
            | (StorageFinalizeChoice, WalletNameEntry { purpose: 3 })
            | (StorageFinalizeChoice, PassphraseChoice)
            | (StorageFinalizeChoice, SeedList)
            | (StorageProtectionChoice, SeedList)
            | (StoragePinConfirm, SeedList)
            | (StoragePasswordConfirm, SeedList)
    )
}

fn wallet_protection_persistence_bridge(from_state: AppState, to_state: AppState) -> bool {
    use AppState::*;
    matches!(
        (from_state, to_state),
        (WalletDetails, StorageCredentialType)
            | (StorageCredentialType, WalletDetails)
            | (StoragePinConfirm, WalletDetails)
            | (StoragePasswordConfirm, WalletDetails)
    )
}

fn backup_recovery_stego_entry_allowed(
    from: NavigationOwner,
    to: NavigationOwner,
    from_state: AppState,
    to_state: AppState,
) -> bool {
    (from == NavigationOwner::Seeds
        && to == NavigationOwner::Stego
        && from_state == AppState::BackupRecoveryMenu
        && to_state == AppState::StegoModeSelect)
        || (from == NavigationOwner::Export
            && to == NavigationOwner::Stego
            && from_state == AppState::ImportMenu
            && to_state == AppState::StegoImportPick)
}

fn seed_backup_return_allowed(
    from: NavigationOwner,
    from_state: AppState,
    to_state: AppState,
) -> bool {
    from == NavigationOwner::Onboarding
        && matches!(from_state, AppState::SeedBackup { .. })
        && matches!(to_state, AppState::WalletBackupMethodsMenu | AppState::SeedBackupMenu | AppState::SeedList)
}

fn fixed_owner(state: AppState, current: NavigationOwner) -> Option<NavigationOwner> {
    use AppState::*;
    use NavigationOwner::*;
    if matches!(state, StorageUnlockPin | StorageUnlockPassword) { return Some(Storage); }
    if state == MainMenu { return Some(Main); }
    if matches!(state, SeedsMenu | SeedList | AddWalletChoice | WalletNameEntry { .. } | ConfirmDeleteSeed
        | WalletBackupMethodsMenu | WalletDetails | WalletAdvancedMenu | BackupRecoveryMenu | SeedToolsMenu)
    {
        return Some(Seeds);
    }
    if matches!(state, ImportExportChoice | ImportMenu) { return Some(Export); }
    if state == SingleSigMenu { return Some(Signing); }
    #[cfg(feature = "workflow-tests")]
    if matches!(state, WorkflowTestsMenu | WorkflowTestsCategory { .. } | WorkflowTestsResult) { return Some(WorkflowTests); }
    if is_multisig_menu_state(state) { return Some(Multisig); }
    if is_settings_state(state) { return Some(Settings); }
    if is_qr_state(state) { return Some(qr_owner(current)); }
    if state == ShowQrPopup { return Some(Signing); }
    None
}

fn owner_transition_allowed(from: NavigationOwner, to: NavigationOwner) -> bool {
    use NavigationOwner::*;
    #[cfg(feature = "workflow-tests")]
    if matches!((from, to), (Settings, WorkflowTests) | (WorkflowTests, Settings)) { return true; }
    match from {
        Onboarding => matches!(to, Onboarding | Main),
        Settings => matches!(to, Main | Seeds | Signing | Export | Storage | Stego | Multisig),
        Main => matches!(to, Seeds | Settings | Signing | Export),
        Seeds => matches!(to, Main | Settings | Signing | Export | Storage | Multisig | Onboarding),
        Signing => matches!(to, Main | Seeds | Export | Storage | Multisig),
        Export => matches!(to, Main | Seeds | Signing | Storage | Multisig),
        Storage => matches!(to, Main | Seeds | Signing | Export | Multisig | Stego),
        Stego => matches!(to, Main | Seeds | Storage | Export),
        Multisig => matches!(to, Main | Seeds | Signing | Export | Storage),
        #[cfg(feature = "workflow-tests")]
        WorkflowTests => matches!(to, Settings),
    }
}

fn is_qr_state(state: AppState) -> bool {
    matches!(
        state,
        AppState::ShowQR
            | AppState::ShowQrModeChoice
    )
}

fn qr_owner(current: NavigationOwner) -> NavigationOwner {
    use NavigationOwner::*;
    if matches!(current, Signing | Export | Storage | Multisig) { current } else { Signing }
}

fn owner_from_handler(group: HandlerGroup, current: NavigationOwner) -> NavigationOwner {
    use NavigationOwner::*;
    match group {
        HandlerGroup::Settings => Settings,
        HandlerGroup::Persistence => Storage,
        HandlerGroup::Seed => Seeds,
        HandlerGroup::Export => Export,
        HandlerGroup::Sd => Storage,
        HandlerGroup::Stego => Stego,
        HandlerGroup::Tx => Signing,
        #[cfg(feature = "workflow-tests")]
        HandlerGroup::WorkflowTests => WorkflowTests,
        HandlerGroup::Menu => menu_handler_owner(current),
    }
}

fn menu_handler_owner(current: NavigationOwner) -> NavigationOwner {
    use NavigationOwner::*;
    if matches!(current, Onboarding | Main | Seeds | Settings | Signing | Export | Multisig) {
        current
    } else {
        Main
    }
}

fn is_sd_enable_state(state: AppState) -> bool {
    matches!(state, AppState::StorageRecoveryAcknowledgement | AppState::StorageSdFailure)
}

fn is_multisig_menu_state(state: AppState) -> bool {
    use AppState::*;
    matches!(state, MultisigMenu | MultisigChooseMN | MultisigPickSeed { .. } | MultisigAddKey { .. }
        | MultisigShowAddress | MultisigShowAddressQR | MultisigDescriptor | MultisigSaveAddrAsk)
}

fn is_settings_state(state: AppState) -> bool {
    use AppState::*;
    if matches!(state, SettingsMenu | AdvancedMenu | FactoryResetWarning | FactoryResetConfirm
        | DisplaySettings | SdCardSettings | SdCardUnlockPassword | AdvancedFeatures
        | AdvancedDuressWarning | AdvancedDuressEntry | AdvancedDuressConfirm
        | AdvancedSdStorageWarning | FirmwareUpdateReady | About)
    {
        return true;
    }
    #[cfg(feature = "provisioning-ui")]
    if matches!(state, PopItPrompt | PopItExplain | PopItConfirm
        | OwnerFirmwareMenu | OwnerKeyWarning | OwnerKeyConfirm
        | OwnerInstallWarning | OwnerInstallConfirm) { return true; }
    #[cfg(feature = "developer-ui")]
    if matches!(state, DeveloperMenu | NetworkMenu | DiagnosticInfo) { return true; }
    #[cfg(feature = "m5stack")]
    if matches!(state, AudioSettings | AdvancedRtcEntry | AdvancedTimeLockWarning
        | AdvancedTimeLockEntry | AdvancedTimeLockConfirm | AdvancedWeeklyWarning
        | AdvancedWeeklyEntry | AdvancedWeeklyConfirm)
    {
        return true;
    }
    #[cfg(feature = "waveshare")]
    if state == CameraSettings { return true; }
    false
}
