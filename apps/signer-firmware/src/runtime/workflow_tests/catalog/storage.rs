use super::{WorkflowFixtures as F, WorkflowSpec, WorkflowTerminal::Ordinary};
use crate::runtime::{data::DeviceStorageIntent, input::AppState::*};

pub(super) const WORKFLOWS: &[WorkflowSpec] = &[
    WorkflowSpec{id:"sd-settings",label:"SD Card Settings",intent:DeviceStorageIntent::None,fixtures:F::SD_CARD,terminal:Ordinary,states:&[MainMenu,SettingsMenu,SdCardSettings,SdCardUnlockPassword,SdCardSettings,SettingsMenu]},
    WorkflowSpec{id:"sd-wallet-backup",label:"Seed Backup to SD",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::SD_CARD),terminal:Ordinary,states:&[SeedBackupMenu,SdBackupWarning,SdSeedFilename,SdSeedExportPassphrase,SdOverwriteWarning,SeedBackupMenu]},
    WorkflowSpec{id:"sd-wallet-restore",label:"Wallet Restore SD",intent:DeviceStorageIntent::None,fixtures:F::SD_CARD,terminal:Ordinary,states:&[ImportExportChoice,ImportMenu,SdWalletBackupFileList,SdWalletBackupImportPassphrase,MainMenu]},
    WorkflowSpec{id:"sd-import-transaction",label:"Import TX from SD",intent:DeviceStorageIntent::None,fixtures:F::SD_CARD.union(F::SEED),terminal:Ordinary,states:&[ImportMenu,SdImportMenu,SdKsptFileList,ReviewTx{page:0},ConfirmTx,SdSigFilename,MainMenu]},
    WorkflowSpec{id:"sd-import-kpub",label:"Import kpub from SD",intent:DeviceStorageIntent::None,fixtures:F::SD_CARD,terminal:Ordinary,states:&[ImportMenu,SdImportMenu,SdKpubFileList,KpubScannedPopup,MainMenu]},
    WorkflowSpec{id:"sd-generic-files",label:"SD File Browser",intent:DeviceStorageIntent::None,fixtures:F::SD_CARD,terminal:Ordinary,states:&[SdImportMenu,SdFileList,SdDeleteConfirm,SdImportMenu]},
    WorkflowSpec{id:"sd-save-kspt",label:"Save KSPT to SD",intent:DeviceStorageIntent::None,fixtures:F::SD_CARD,terminal:Ordinary,states:&[ShowQrPopup,SdKsptFilename,SdKsptEncryptAsk,SdKsptEncryptPass,SdOverwriteWarning,ShowQrPopup]},
    WorkflowSpec{id:"sd-save-multisig",label:"Save Multisig SD",intent:DeviceStorageIntent::None,fixtures:F::SD_CARD,terminal:Ordinary,states:&[MultisigSaveAddrAsk,SdMsAddrFilename,SdMsAddrEncryptAsk,SdMsDescFilename,SdMsDescEncryptAsk,MultisigDescriptor]},
    WorkflowSpec{id:"sd-enable-storage",label:"Enable SD Storage",intent:DeviceStorageIntent::EnableSd,fixtures:F::SAVED_WALLET.union(F::SD_CARD),terminal:Ordinary,states:&[SettingsMenu,AdvancedFeatures,AdvancedSdStorageWarning,StorageRecoveryAcknowledgement,SettingsMenu]},
    WorkflowSpec{id:"firmware-update-ready",label:"Firmware Update USB Guidance",intent:DeviceStorageIntent::None,fixtures:F::NONE,terminal:Ordinary,states:&[AdvancedMenu,FirmwareUpdateReady,AdvancedMenu]},
];
