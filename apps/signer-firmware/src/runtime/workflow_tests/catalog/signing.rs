use super::{WorkflowFixtures as F, WorkflowSpec, WorkflowTerminal::Ordinary};
use crate::runtime::{data::DeviceStorageIntent, input::AppState::*};

pub(super) const WORKFLOWS: &[WorkflowSpec] = &[
    WorkflowSpec{id:"sign-tx",label:"Sign Transaction",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::CAMERA_QR),terminal:Ordinary,states:&[MainMenu,SingleSigMenu,SignTxGuide,ScanQR,AntiKleptoRevealGuide,ConfirmTx,ReviewTx{page:0},InspectUtxoSummary,InspectUtxo{index:0,address_page:false},ConfirmTx,ShowQR,ShowQrModeChoice,ShowQrPopup,MainMenu]},
    WorkflowSpec{id:"reject-tx",label:"Reject Transaction",intent:DeviceStorageIntent::None,fixtures:F::CAMERA_QR,terminal:Ordinary,states:&[SingleSigMenu,SignTxGuide,ScanQR,ConfirmTx,Rejected,MainMenu]},
    WorkflowSpec{id:"sign-message-type",label:"Sign Message Typed",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[SeedsMenu,WalletAdvancedMenu,SignMsgChoice,SignMsgType,SignMsgPreview,SignMsgResult,SignMsgResultQr,MainMenu]},
    WorkflowSpec{id:"sign-message-qr",label:"Sign Message QR",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::CAMERA_QR),terminal:Ordinary,states:&[SeedsMenu,WalletAdvancedMenu,SignMsgChoice,SignMsgScan,SignMsgPreview,SignMsgResult,SignMsgResultQr,MainMenu]},
    WorkflowSpec{id:"sign-message-file",label:"Sign Message File",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::SD_CARD),terminal:Ordinary,states:&[SeedsMenu,WalletAdvancedMenu,SignMsgChoice,SignMsgFile,SignMsgPreview,SignMsgResult,SignMsgResultQr,MainMenu]},
    WorkflowSpec{id:"covenant-sign",label:"Covenant Sign",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::CAMERA_QR),terminal:Ordinary,states:&[SingleSigMenu,ScanQR,CovenantSignReview,CovenantSignOpaqueWarning,CovenantSignOpaqueConfirm,CovenantSignResult,CovenantSignResultQr,CovBackupName,MainMenu]},
    WorkflowSpec{id:"covenant-key",label:"Covenant Key",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::CAMERA_QR),terminal:Ordinary,states:&[ScanQR,CovenantSignReview,CovenantKeyResult,CovenantKeyResultQr,MainMenu]},
    WorkflowSpec{id:"private-swap",label:"Private Swap",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::CAMERA_QR),terminal:Ordinary,states:&[ScanQR,PrivateSwapReview,PrivateSwapKeyResult,PrivateSwapKeyResultQr,PrivateSwapResult,PrivateSwapResultQr,MainMenu]},
    WorkflowSpec{id:"commit-secret",label:"Commit Secret",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[SeedsMenu,WalletAdvancedMenu,CommitRevealType,CommitRevealPreview,CommitRevealResult,CommitRevealResultQr,MainMenu]},
    WorkflowSpec{id:"decrypt-secret",label:"Decrypt Secret",intent:DeviceStorageIntent::None,fixtures:F::SEED.union(F::CAMERA_QR),terminal:Ordinary,states:&[SeedsMenu,WalletAdvancedMenu,DecryptSecretScan,DecryptSecretResult,DecryptSecretResultQr,MainMenu]},
    WorkflowSpec{id:"qr-display-modes",label:"Signed QR Modes",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[ShowQR,ShowQrModeChoice,ShowQrPopup]},
];
