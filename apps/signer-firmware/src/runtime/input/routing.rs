// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Maps application states to their owning touch-controller subsystem.

use super::state::AppState;

// ─── Handler group dispatch ──────────────────────────────────────────
//
// Maps each AppState to the handler module responsible for its touch events.
// Used by main.rs to route taps without listing every variant inline.

#[derive(Debug, Clone, Copy, PartialEq)]
/// Groups AppState variants by their touch handler module.
pub enum HandlerGroup {
    Menu,
    Stego,
    Sd,
    Seed,
    Export,
    Settings,
    Persistence,
    Tx,
    #[cfg(feature = "workflow-tests")]
    WorkflowTests,
}

impl AppState {
    /// Map this AppState to its responsible handler module.
    pub fn handler_group(&self) -> HandlerGroup {
        use AppState::*;
        match self {
            // Menu screens
            MainMenu | SeedsMenu | SeedToolsMenu | ImportExportChoice
            | ImportMenu | SingleSigMenu | MultisigMenu | WalletBackupMethodsMenu
            | WalletDetails | AdvancedMenu | WalletAdvancedMenu | BackupRecoveryMenu
            | DiceRoll | TouchEntropy
            | ChooseWordCount { .. } | StorageSeedWordCountChoice { .. } | SeedEntropyUnavailable { .. } | StorageSeedDiceChoice | StorageSeedDiceCountChoice | StorageSeedTouchChoice | ShowQR | Rejected
            | CovBackupName
                => HandlerGroup::Menu,
            #[cfg(feature = "developer-ui")]
            DeveloperMenu | NetworkMenu => HandlerGroup::Menu,
            #[cfg(feature = "developer-ui")]
            DiagnosticInfo => HandlerGroup::Settings,

            // JPEG steganographic wallet-backup workflow
            StegoModeSelect | StegoSecuritySelect | StegoResult | StegoJpegPick
            | StegoJpegDescChoice | StegoJpegDescFile | StegoJpegDesc
            | StegoJpegDescPreview | StegoJpegPpAsk | StegoJpegPpInfo
            | StegoJpegPpEntry | StegoPortablePassword | StegoPortablePasswordConfirm
            | StegoJpegConfirm | StegoImportPick
            | StegoImportDescChoice | StegoImportDescFile
            | StegoImportPass | StegoImportPortablePassword | StegoHintReveal | StegoHintPassphrase
                => HandlerGroup::Stego,

            // SD backup/restore
            SdFileList | SdDeleteConfirm | SdBackupWarning | SdSeedFilename | SdSeedExportPassphrase
            | SdXprvExportPassphrase | SdWalletBackupFileList | SdWalletBackupImportPassphrase
            | SdImportMenu | SdKsptFileList | SdKpubFileList
            | ShowQrPopup | SdKsptFilename | SdKpubFilename
            | SdSigFilename | SdXprvFilename | SdMsAddrFilename
            | SdMsAddrEncryptAsk
            | SdMsDescFilename | SdMsDescEncryptAsk
            | SdKsptEncryptAsk | SdKsptEncryptPass
            | SdOverwriteWarning | SdKpubEncryptAsk
            | ShowQrModeChoice
                => HandlerGroup::Sd,

            // Seed management
            Bip85Index { .. } | Bip85ShowWord { .. }
            | ImportPrivKey | ImportWord { .. } | RestoreWord { .. } | CalcLastWord { .. }
            | PassphraseChoice | PassphraseEntry | SeedList | AddWalletChoice | WalletNameEntry { .. } | ConfirmDeleteSeed
                => HandlerGroup::Seed,

            // Export/display
            SeedBackup { .. } | ShowAddress | ShowAddressQR | AddrIndexPicker
            | ExportSeedQR | ExportCompactSeedQR | SeedQrGrid { .. }
            | QrExportMenu | XprvExportMenu | SeedBackupMenu | WatchOnlyMenu | SigningKeysMenu | ExportPlainWordsQR
            | ExportKpub | ExportKpubPopup | KpubScannedPopup | ExportXprv | ExportChoice | ExportPrivKey
            | ExportPrivKeyIndex
                => HandlerGroup::Export,

            #[cfg(feature = "workflow-tests")]
            WorkflowTestsMenu | WorkflowTestsCategory { .. } | WorkflowTestsResult
                => HandlerGroup::WorkflowTests,

            // Settings
            SettingsMenu | DisplaySettings | SdCardSettings | SdCardUnlockPassword | About
            | FactoryResetWarning | FactoryResetConfirm | FirmwareUpdateReady
            | AdvancedFeatures | AdvancedDuressWarning | AdvancedDuressEntry | AdvancedDuressConfirm
            | AdvancedSdStorageWarning
                => HandlerGroup::Settings,
            #[cfg(feature = "provisioning-ui")]
            OwnerFirmwareMenu | PopItPrompt | PopItExplain | PopItConfirm
            | OwnerKeyWarning | OwnerKeyConfirm | OwnerInstallWarning | OwnerInstallConfirm
                => provisioning_handler_group(self),


            #[cfg(feature = "m5stack")]
            AdvancedRtcEntry | AdvancedTimeLockWarning | AdvancedTimeLockEntry | AdvancedTimeLockConfirm
            | AdvancedWeeklyWarning | AdvancedWeeklyEntry | AdvancedWeeklyConfirm
            | AudioSettings => HandlerGroup::Settings,

            #[cfg(feature = "waveshare")]
            CameraSettings => HandlerGroup::Settings,

            // Transaction / multisig / camera / message signing
            ScanQR | ReviewTx { .. } | InspectUtxoSummary | InspectUtxo { .. } | ConfirmTx | SignTxGuide | AntiKleptoRevealGuide
            | MultisigChooseMN | MultisigPickSeed { .. }
            | MultisigAddKey { .. } | MultisigShowAddress | MultisigShowAddressQR
            | MultisigSaveAddrAsk | MultisigDescriptor
            | SignMsgChoice | SignMsgType | SignMsgScan | SignMsgFile | SignMsgPreview | SignMsgResult | SignMsgResultQr
            | CovenantSignReview | CovenantSignOpaqueWarning | CovenantSignOpaqueConfirm
            | CovenantKeyResult | CovenantKeyResultQr | CovenantSignResult | CovenantSignResultQr
            | PrivateSwapReview | PrivateSwapKeyResult | PrivateSwapKeyResultQr | PrivateSwapResult | PrivateSwapResultQr
            | CommitRevealType | CommitRevealPreview | CommitRevealResult | CommitRevealResultQr
            | DecryptSecretScan | DecryptSecretResult | DecryptSecretResultQr
                => HandlerGroup::Tx,

            // Persistent-wallet policy/setup/unlock states. Onboarding-owned
            // variants are intercepted by the authoritative onboarding facade
            // before this generic group is consulted.
            StorageModeChoice | StorageSeedSourceChoice | AdvancedRestoreMenu | RestoreWord12Detected
            | StorageRecoveryAcknowledgement | StorageFinalizeChoice | StorageProtectionChoice | StorageCredentialType
            | StoragePinEntry | StoragePinConfirm
            | StoragePasswordEntry | StoragePasswordConfirm | StorageUnlockPin | StorageUnlockPassword
            | StorageSdFailure => HandlerGroup::Persistence,

            // Transient signing step; no direct touch handler.
        }
    }
}

#[cfg(feature = "provisioning-ui")]
fn provisioning_handler_group(state: &AppState) -> HandlerGroup {
    if matches!(state, AppState::OwnerFirmwareMenu) {
        HandlerGroup::Menu
    } else {
        HandlerGroup::Settings
    }
}

