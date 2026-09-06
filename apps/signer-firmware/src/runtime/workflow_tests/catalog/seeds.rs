use super::{WorkflowFixtures as F, WorkflowSpec, WorkflowTerminal::Ordinary};
use crate::runtime::{data::DeviceStorageIntent, input::AppState::*};

pub(super) const WORKFLOWS: &[WorkflowSpec] = &[
    WorkflowSpec{id:"wallet-connect-kassee",label:"Connect KasSee",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[MainMenu,SeedsMenu,ExportKpub,ExportKpubPopup,MainMenu]},
    WorkflowSpec{id:"wallet-home",label:"Wallet Home",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[MainMenu,SeedsMenu,WalletDetails,SeedsMenu,SeedList,SeedsMenu,MainMenu]},
    WorkflowSpec{id:"wallet-backup",label:"Wallet Backup",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[SeedsMenu,WalletBackupMethodsMenu,BackupRecoveryMenu,WalletBackupMethodsMenu,SeedsMenu,SdImportMenu,SeedsMenu]},
    WorkflowSpec{id:"wallet-advanced",label:"Wallet Advanced",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[SeedsMenu,WalletAdvancedMenu,SeedsMenu]},
    WorkflowSpec{id:"seed-list-delete",label:"List / Delete Wallet",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[SeedsMenu,SeedList,ConfirmDeleteSeed,SeedList,SeedsMenu]},
    WorkflowSpec{id:"seed-new-hardware",label:"Add Wallet",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[SeedList,AddWalletChoice,WalletNameEntry{purpose:1},ChooseWordCount{action:0},PassphraseChoice,SeedBackup{word_idx:0},StorageProtectionChoice,SeedList]},
    WorkflowSpec{id:"seed-bip85",label:"BIP85 Child",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[WalletAdvancedMenu,ChooseWordCount{action:4},Bip85Index{word_count:12},Bip85ShowWord{word_idx:0,word_count:12},SeedToolsMenu]},
    WorkflowSpec{id:"seed-calc-last",label:"Calculate Last Word",intent:DeviceStorageIntent::None,fixtures:F::NONE,terminal:Ordinary,states:&[WalletAdvancedMenu,ChooseWordCount{action:3},CalcLastWord{word_idx:0,word_count:12},SeedBackup{word_idx:0},SeedToolsMenu]},
    WorkflowSpec{id:"advanced-import-words",label:"Advanced Import Words",intent:DeviceStorageIntent::None,fixtures:F::NONE,terminal:Ordinary,states:&[SeedToolsMenu,ChooseWordCount{action:2},ImportWord{word_idx:0,word_count:12},PassphraseChoice,SeedToolsMenu]},
    WorkflowSpec{id:"receive-address",label:"Receive Address",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[MainMenu,SeedsMenu,ShowAddress,ShowAddressQR,ShowAddress,MainMenu]},
    WorkflowSpec{id:"receive-index-advanced",label:"Receive Address Index",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[SeedToolsMenu,AddrIndexPicker,ShowAddress,SeedToolsMenu]},
];
