use super::{WorkflowFixtures as F, WorkflowSpec, WorkflowTerminal::Ordinary};
use crate::runtime::{data::DeviceStorageIntent, input::AppState::*};

pub(super) const WORKFLOWS: &[WorkflowSpec] = &[
    WorkflowSpec{id:"backup-words",label:"Show Recovery Words",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[ImportExportChoice,SeedBackupMenu,SeedBackup{word_idx:0},SeedBackupMenu]},
    WorkflowSpec{id:"backup-seedqr",label:"SeedQR Export",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[ImportExportChoice,SeedBackupMenu,QrExportMenu,ExportSeedQR,SeedQrGrid{pan_x:0,pan_y:0,compact:false},QrExportMenu]},
    WorkflowSpec{id:"backup-compact-qr",label:"Compact SeedQR",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[QrExportMenu,ExportCompactSeedQR,SeedQrGrid{pan_x:0,pan_y:0,compact:true},QrExportMenu]},
    WorkflowSpec{id:"backup-plain-qr",label:"Plain Words QR",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[QrExportMenu,ExportPlainWordsQR,QrExportMenu]},
    WorkflowSpec{id:"watch-kpub-qr",label:"kpub QR",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[ImportExportChoice,WatchOnlyMenu,ExportKpub,ExportKpubPopup,WatchOnlyMenu]},
    WorkflowSpec{id:"watch-kpub-sd",label:"kpub to SD",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::SD_CARD),terminal:Ordinary,states:&[WatchOnlyMenu,SdKpubFilename,SdKpubEncryptAsk,SdOverwriteWarning,WatchOnlyMenu]},
    WorkflowSpec{id:"xprv-export",label:"xprv QR / SD",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::SD_CARD),terminal:Ordinary,states:&[ImportExportChoice,SigningKeysMenu,XprvExportMenu,ExportChoice,ExportXprv,SdXprvFilename,SdXprvExportPassphrase,SigningKeysMenu]},
    WorkflowSpec{id:"private-key-export",label:"Private Key Export",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[SigningKeysMenu,ExportPrivKeyIndex,ExportPrivKey,SigningKeysMenu]},
    WorkflowSpec{id:"raw-key-import",label:"Raw Key Import",intent:DeviceStorageIntent::None,fixtures:F::NONE,terminal:Ordinary,states:&[ImportExportChoice,ImportMenu,ImportPrivKey,KpubScannedPopup,MainMenu]},
];
