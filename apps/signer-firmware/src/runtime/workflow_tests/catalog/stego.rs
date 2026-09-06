use super::{WorkflowFixtures as F, WorkflowSpec, WorkflowTerminal::Ordinary};
use crate::runtime::{data::DeviceStorageIntent, input::AppState::*};

pub(super) const WORKFLOWS: &[WorkflowSpec] = &[
    WorkflowSpec{id:"stego-device-export",label:"Stego Device Export",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::SD_CARD),terminal:Ordinary,states:&[ImportExportChoice,StegoModeSelect,StegoSecuritySelect,StegoJpegPick,StegoJpegDescChoice,StegoJpegDesc,StegoJpegDescPreview,StegoJpegPpAsk,StegoJpegPpInfo,StegoJpegPpEntry,StegoJpegConfirm,StegoResult,MainMenu]},
    WorkflowSpec{id:"stego-desc-file",label:"Stego Descriptor File",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::SD_CARD),terminal:Ordinary,states:&[StegoJpegDescChoice,StegoJpegDescFile,StegoJpegDescPreview,StegoJpegConfirm,StegoResult]},
    WorkflowSpec{id:"stego-portable-export",label:"Stego Portable Export",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::SD_CARD),terminal:Ordinary,states:&[StegoModeSelect,StegoSecuritySelect,StegoPortablePassword,StegoPortablePasswordConfirm,StegoJpegPick,StegoJpegConfirm,StegoResult]},
    WorkflowSpec{id:"stego-device-import",label:"Stego Device Import",intent:DeviceStorageIntent::None,fixtures:F::SD_CARD,terminal:Ordinary,states:&[ImportMenu,StegoImportPick,StegoImportDescChoice,StegoImportDescFile,StegoImportPass,StegoHintReveal,StegoHintPassphrase,MainMenu]},
    WorkflowSpec{id:"stego-portable-import",label:"Stego Portable Import",intent:DeviceStorageIntent::None,fixtures:F::SD_CARD,terminal:Ordinary,states:&[StegoImportPick,StegoImportDescChoice,StegoImportPass,StegoImportPortablePassword,MainMenu]},
];
