// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use crate::runtime::navigation::ContinuationRoute;

mod persistence;
mod security;
pub use persistence::{
    AdvancedAvailability, ConfirmationState, DeviceStorageIntent, DuressActivation,
    PersistenceCredentialState, PersistenceBackendState, PolicyIntegrity, UnlockFeedback,
};
#[cfg(feature = "m5stack")]
pub use persistence::RtcVerification;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFileKind {
    Kpub,
    MultisigAddress,
    MultisigDescriptor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedPayloadKind {
    Transaction,
    Text(TextFileKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedFileOperation {
    None,
    Import {
        kind: EncryptedPayloadKind,
        back_state: ContinuationRoute,
    },
    Export {
        kind: EncryptedPayloadKind,
        filename: [u8; 11],
        back_state: ContinuationRoute,
        success_state: ContinuationRoute,
    },
}

impl EncryptedFileOperation {
    pub const fn back_state(self) -> ContinuationRoute {
        match self {
            Self::Import { back_state, .. } | Self::Export { back_state, .. } => back_state,
            Self::None => crate::runtime::navigation::continuation!(SdImportMenu),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingStorageAction {
    Navigate(ContinuationRoute),
    SaveSignature,
}

pub struct StorageState {
    pub persistence: PersistenceCredentialState,
    pub browser: FileBrowserState,
    pub export_file: ExportFileState,
    pub confirmation: StorageConfirmationState,
    pub text_files: TextFileList,
}


pub struct FileBrowserState {
    pub file_list: [[u8; 11]; 8],
    pub file_count: u8,
    pub file_scroll: u8,
    pub selected_file: [u8; 11],
    pub text_import_kind: Option<TextFileKind>,
}

pub struct ExportFileState {
    pub filename: [u8; 11],
    pub overwrite_prompt: [u8; 32],
    pub overwrite_prompt_len: u8,
    pub encrypted_operation: EncryptedFileOperation,
}

#[derive(Clone, Copy)]
pub struct TextFileList {
    pub file_names: [[u8; 11]; 8],
    pub display_names: [[u8; 32]; 8],
    pub display_lens: [u8; 8],
    pub file_count: u8,
}

impl TextFileList {
    pub const fn empty() -> Self {
        Self {
            file_names: [[0; 11]; 8],
            display_names: [[0; 32]; 8],
            display_lens: [0; 8],
            file_count: 0,
        }
    }
}

pub struct StorageConfirmationState {
    pub overwrite_action: PendingStorageAction,
    pub overwrite_back: ContinuationRoute,
    pub delete_return: ContinuationRoute,
}

impl StorageState {
    pub(super) fn new() -> Self {
        Self {
            persistence: PersistenceCredentialState::new(),
            browser: FileBrowserState {
                file_list: [[b' '; 11]; 8],
                file_count: 0,
                file_scroll: 0,
                selected_file: [b' '; 11],
                text_import_kind: None,
            },
            export_file: ExportFileState {
                filename: [b' '; 11],
                overwrite_prompt: [0; 32],
                overwrite_prompt_len: 0,
                encrypted_operation: EncryptedFileOperation::None,
            },
            confirmation: StorageConfirmationState {
                overwrite_action: PendingStorageAction::Navigate(crate::runtime::navigation::continuation!(MainMenu)),
                overwrite_back: crate::runtime::navigation::continuation!(MainMenu),
                delete_return: crate::runtime::navigation::continuation!(MainMenu),
            },
            text_files: TextFileList::empty(),
        }
    }
}


#[cfg(test)]
#[path = "unit_tests/storage_tests.rs"]
mod unit_tests;
