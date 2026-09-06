//! Centralized hierarchy/menu Back reducer support.
//!
//! Stage 2 separates domain cleanup (`prepare`) from route selection (`target`).
//! The navigation kernel owns the actual Back commit and uses bounded history
//! whenever a shared screen has a caller-dependent return route.

use crate::runtime::{data::AppData, input::AppState};

pub(super) fn prepare(ad: &mut AppData) {
    use AppState::*;
    match ad.navigation.app.state {
        SeedList => ad.wallet.seeds.seed_list_scroll = 0,
        ConfirmDeleteSeed => ad.wallet.seeds.pending_delete_slot = 0xFF,
        MultisigChooseMN => ad.signing.multisig.creating.n = 0,
        MultisigAddKey { key_idx: 0 } => ad.signing.multisig.creating.n = 0,
        PassphraseEntry => ad.wallet.seeds.pp_input.reset(),
        _ => {}
    }
}

pub(super) fn target(ad: &AppData) -> Option<AppState> {
    seed_or_multisig_target(ad)
        .or_else(|| production_target(ad))
        .or_else(|| platform_target(ad))
        .or_else(|| developer_target(ad))
}

fn seed_or_multisig_target(ad: &AppData) -> Option<AppState> {
    use AppState::*;
    Some(match ad.navigation.app.state {
        SeedList => SeedsMenu,
        ConfirmDeleteSeed => SeedList,
        MultisigChooseMN => MultisigMenu,
        MultisigAddKey { key_idx: 0 } => MultisigChooseMN,
        MultisigAddKey { key_idx } => MultisigAddKey { key_idx: key_idx - 1 },
        MultisigPickSeed { key_idx } => MultisigAddKey { key_idx },
        MultisigDescriptor if ad.signing.multisig.creating.active => MultisigShowAddress,
        MultisigDescriptor => SdImportMenu,
        _ => return None,
    })
}

fn production_target(ad: &AppData) -> Option<AppState> {
    use AppState::*;
    Some(match ad.navigation.app.state {
        DisplaySettings => SettingsMenu,
        WalletBackupMethodsMenu | WalletDetails => SeedsMenu,
        AdvancedMenu => SettingsMenu,
        FirmwareUpdateReady | FactoryResetWarning | FactoryResetConfirm => AdvancedMenu,
        SettingsMenu | SeedsMenu => MainMenu,
        // Caller-dependent shared screens intentionally fall through to the
        // bounded navigation history: WalletAdvancedMenu, BackupRecoveryMenu,
        // MultisigMenu, SdCardSettings, SdCardUnlockPassword, AdvancedFeatures, About, SdImportMenu.
        _ => return None,
    })
}

fn platform_target(ad: &AppData) -> Option<AppState> {
    use AppState::*;
    Some(match ad.navigation.app.state {
        #[cfg(feature = "m5stack")]
        AudioSettings => SettingsMenu,
        #[cfg(feature = "waveshare")]
        CameraSettings => SettingsMenu,
        PassphraseEntry => PassphraseChoice,
        _ => return None,
    })
}

fn developer_target(ad: &AppData) -> Option<AppState> {
    use AppState::*;
    Some(match ad.navigation.app.state {
        SeedToolsMenu | ImportExportChoice | SingleSigMenu => SeedsMenu,
        ImportMenu => ImportExportChoice,
        #[cfg(feature = "workflow-tests")]
        WorkflowTestsMenu => ad.navigation.workflow_tests_return.state(),
        #[cfg(feature = "workflow-tests")]
        WorkflowTestsCategory { .. } => WorkflowTestsMenu,
        #[cfg(feature = "workflow-tests")]
        WorkflowTestsResult if ad.workflow_tests.result.ran_all => WorkflowTestsMenu,
        #[cfg(feature = "workflow-tests")]
        WorkflowTestsResult => WorkflowTestsCategory { category: ad.workflow_tests.selected_category },
        _ => return None,
    })
}
