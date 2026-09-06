use super::{WorkflowFixtures as F, WorkflowSpec, WorkflowTerminal::Ordinary};
use crate::runtime::{data::DeviceStorageIntent, input::AppState::*};

pub(super) const WORKFLOWS: &[WorkflowSpec] = &[
    WorkflowSpec{id:"multisig-kpub-qr",label:"kpub Multisig QR",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[MainMenu,SeedsMenu,MultisigMenu,ExportKpub,ExportKpubPopup,MultisigMenu]},
    WorkflowSpec{id:"multisig-local",label:"Create Multisig Local",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[MainMenu,SeedsMenu,MultisigMenu,MultisigChooseMN,MultisigPickSeed{key_idx:0},MultisigAddKey{key_idx:1},MultisigShowAddress,MultisigShowAddressQR,MultisigSaveAddrAsk,MultisigDescriptor,SeedsMenu]},
    WorkflowSpec{id:"multisig-import-save",label:"Multisig Import / Save",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::SD_CARD).union(F::CAMERA_QR),terminal:Ordinary,states:&[MultisigMenu,MultisigChooseMN,MultisigAddKey{key_idx:0},MultisigShowAddress,SdMsAddrFilename,SdMsAddrEncryptAsk,SdMsDescFilename,SdMsDescEncryptAsk,MultisigDescriptor,SeedsMenu]},
];
