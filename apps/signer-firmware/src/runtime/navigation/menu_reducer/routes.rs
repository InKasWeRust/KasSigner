use crate::runtime::input::AppState;

pub(super) fn destination(state: AppState, index: u8) -> Option<AppState> {
    root_settings(state, index)
        .or_else(|| wallet_a(state, index))
        .or_else(|| wallet_b(state, index))
        .or_else(|| wallet_advanced(state, index))
        .or_else(|| seed_tools(state, index))
        .or_else(|| signing(state, index))
        .or_else(|| export_a(state, index))
        .or_else(|| export_b(state, index))
        .or_else(|| restore(state, index))
        .or_else(|| imports(state, index))
}

fn root_settings(state: AppState, index: u8) -> Option<AppState> {
    use AppState::*;
    Some(match (state, index) {
        (MainMenu, 0) => SeedsMenu,
        (MainMenu, 1) => ScanQR,
        (MainMenu, 2) => SeedsMenu,
        (MainMenu, 3) => SettingsMenu,
        (SettingsMenu, 0) => DisplaySettings,
        #[cfg(feature = "m5stack")]
        (SettingsMenu, 1) => AudioSettings,
        #[cfg(feature = "waveshare")]
        (SettingsMenu, 1) => return None,
        (SettingsMenu, 2) => AdvancedFeatures,
        (SettingsMenu, 3) => SdCardSettings,
        (SettingsMenu, 4) => AdvancedMenu,
        (SettingsMenu, 5) => About,
        _ => return None,
    })
}

fn wallet_a(state: AppState, index: u8) -> Option<AppState> {
    use AppState::*;
    Some(match (state, index) {
        (AdvancedMenu, 0) => FirmwareUpdateReady,
        (AdvancedMenu, 1) => FactoryResetWarning,
        #[cfg(feature = "provisioning-ui")]
        (AdvancedMenu, 2) => OwnerFirmwareMenu,
        #[cfg(feature = "provisioning-ui")]
        (AdvancedMenu, 3) => PopItPrompt,
        #[cfg(feature = "provisioning-ui")]
        (OwnerFirmwareMenu, 0) => OwnerKeyWarning,
        #[cfg(feature = "provisioning-ui")]
        (OwnerFirmwareMenu, 1) => OwnerInstallWarning,
        (SeedsMenu, 0) => ShowAddress,
        (SeedsMenu, 1) => WalletBackupMethodsMenu,
        (SeedsMenu, 2) => SdImportMenu,
        (SeedsMenu, 3) => WalletDetails,
        (SeedsMenu, 4) => SeedList,
        (SeedsMenu, 5) => MultisigMenu,
        (SeedsMenu, 6) => WalletAdvancedMenu,
        _ => return None,
    })
}

fn wallet_b(state: AppState, index: u8) -> Option<AppState> {
    use AppState::*;
    Some(match (state, index) {
        (WalletBackupMethodsMenu, 0) => SeedBackup { word_idx: 0 },
        (WalletBackupMethodsMenu, 1) => ExportSeedQR,
        (WalletBackupMethodsMenu, 2) => SdBackupWarning,
        (WalletBackupMethodsMenu, 3) => BackupRecoveryMenu,
        (BackupRecoveryMenu, 0) => ExportCompactSeedQR,
        (BackupRecoveryMenu, 1) => ExportPlainWordsQR,
        (BackupRecoveryMenu, 2) => StegoModeSelect,
        (BackupRecoveryMenu, 3) => XprvExportMenu,
        (BackupRecoveryMenu, 4) => ExportPrivKeyIndex,
        _ => return None,
    })
}

fn wallet_advanced(state: AppState, index: u8) -> Option<AppState> {
    use AppState::*;
    Some(match (state, index) {
        (WalletAdvancedMenu, 0) => ChooseWordCount { action: 4 },
        (WalletAdvancedMenu, 1) => ChooseWordCount { action: 3 },
        (WalletAdvancedMenu, 2) => SignMsgChoice,
        (WalletAdvancedMenu, 3) => CommitRevealType,
        (WalletAdvancedMenu, 4) => DecryptSecretScan,
        _ => return None,
    })
}

fn seed_tools(state: AppState, index: u8) -> Option<AppState> {
    use AppState::*;
    Some(match (state, index) {
        (SeedToolsMenu, 0) => ChooseWordCount { action: 0 },
        (SeedToolsMenu, 1) => ChooseWordCount { action: 1 },
        (SeedToolsMenu, 2) => ChooseWordCount { action: 5 },
        (SeedToolsMenu, 3) => ChooseWordCount { action: 2 },
        (SeedToolsMenu, 4) => ShowAddress,
        (SeedToolsMenu, 5) => ChooseWordCount { action: 4 },
        (SeedToolsMenu, 6) => ChooseWordCount { action: 3 },
        _ => return None,
    })
}

fn signing(state: AppState, index: u8) -> Option<AppState> {
    use AppState::*;
    Some(match (state, index) {
        (SingleSigMenu, 0) => SignTxGuide,
        (SingleSigMenu, 1) => SignMsgChoice,
        (SingleSigMenu, 2) => ScanQR,
        (SingleSigMenu, 3) => CommitRevealType,
        (SingleSigMenu, 4) => DecryptSecretScan,
        (MultisigMenu, 0) => MultisigChooseMN,
        (MultisigMenu, 1) => MultisigMenu,
        (ConfirmTx, 0) => ConfirmTx,
        (ConfirmTx, 1) => Rejected,
        (ConfirmTx, 2) => ReviewTx { page: 0 },
        _ => return None,
    })
}

fn export_a(state: AppState, index: u8) -> Option<AppState> {
    use AppState::*;
    Some(match (state, index) {
        (ExportChoice, 0) => SeedBackupMenu,
        (ExportChoice, 1) => WatchOnlyMenu,
        (ExportChoice, 2) => SigningKeysMenu,
        (ExportChoice, 3) => StegoModeSelect,
        (SeedBackupMenu, 0) => SeedBackup { word_idx: 0 },
        (SeedBackupMenu, 1) => QrExportMenu,
        (SeedBackupMenu, 2) => SdBackupWarning,
        (WatchOnlyMenu, 0) => ExportKpub,
        (WatchOnlyMenu, 1) => SdKpubFilename,
        (WatchOnlyMenu, 2) => WatchOnlyMenu,
        _ => return None,
    })
}

fn export_b(state: AppState, index: u8) -> Option<AppState> {
    use AppState::*;
    Some(match (state, index) {
        (SigningKeysMenu, 0) => XprvExportMenu,
        (SigningKeysMenu, 1) => ExportPrivKeyIndex,
        (QrExportMenu, 0) => ExportCompactSeedQR,
        (QrExportMenu, 1) => ExportSeedQR,
        (QrExportMenu, 2) => ExportPlainWordsQR,
        (XprvExportMenu, 0) => ExportXprv,
        (XprvExportMenu, 1) => SdXprvFilename,
        _ => return None,
    })
}

fn restore(state: AppState, index: u8) -> Option<AppState> {
    use AppState::*;
    Some(match (state, index) {
        (StorageSeedSourceChoice, 0) => RestoreWord { word_idx: 0 },
        (StorageSeedSourceChoice, 1) => ScanQR,
        (StorageSeedSourceChoice, 2) => SdWalletBackupFileList,
        (StorageSeedSourceChoice, 3) => AdvancedRestoreMenu,
        (AdvancedRestoreMenu, 0) => ScanQR,
        (AdvancedRestoreMenu, 1) => ScanQR,
        (AdvancedRestoreMenu, 2) => StegoImportPick,
        (AdvancedRestoreMenu, 3) => ImportPrivKey,
        (ImportMenu, 0) => SdImportMenu,
        (ImportMenu, 1) => StegoImportPick,
        (ImportMenu, 2) => ImportPrivKey,
        (ImportMenu, 3) => SdFileList,
        _ => return None,
    })
}

fn imports(state: AppState, index: u8) -> Option<AppState> {
    use AppState::*;
    Some(match (state, index) {
        (SdImportMenu, 0) => SdWalletBackupFileList,
        (SdImportMenu, 1) => SdKsptFileList,
        (SdImportMenu, 2) => SdKpubFileList,
        (SdImportMenu, 3) => SdKpubFileList,
        (SdImportMenu, 4) => SdKpubFileList,
        (SdImportMenu, 5) => SdFileList,
        (SdImportMenu, 6) => ImportPrivKey,
        _ => return None,
    })
}
