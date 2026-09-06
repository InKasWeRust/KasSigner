//! Storage-domain volatile metadata scrubbing.

use super::{EncryptedFileOperation, StorageState};

impl StorageState {
    pub fn clear_transient(&mut self) {
        self.persistence.reset();
        for name in &mut self.browser.file_list {
            shared_signer::bytes::zeroize_bytes(name);
        }
        shared_signer::bytes::zeroize_bytes(&mut self.browser.selected_file);
        self.browser.file_count = 0;
        self.browser.file_scroll = 0;
        self.browser.text_import_kind = None;

        shared_signer::bytes::zeroize_bytes(&mut self.export_file.filename);
        shared_signer::bytes::zeroize_bytes(&mut self.export_file.overwrite_prompt);
        self.export_file.overwrite_prompt_len = 0;
        self.export_file.encrypted_operation = EncryptedFileOperation::None;

        for name in &mut self.text_files.file_names {
            shared_signer::bytes::zeroize_bytes(name);
        }
        for name in &mut self.text_files.display_names {
            shared_signer::bytes::zeroize_bytes(name);
        }
        shared_signer::bytes::zeroize_bytes(&mut self.text_files.display_lens);
        self.text_files.file_count = 0;
    }
}
