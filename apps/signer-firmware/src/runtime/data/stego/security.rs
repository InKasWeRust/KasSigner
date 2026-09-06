//! Steganography-domain volatile secret and metadata scrubbing.

use super::StegoState;

impl StegoState {
    pub fn zeroize_sensitive(&mut self) {
        self.session.portable.clear();
        self.session.result_ok = false;
        self.session.auto_scan = false;

        self.export_flow.clear_portable_confirmation();
        for name in &mut self.export_flow.jpeg_file_names {
            shared_signer::bytes::zeroize_bytes(name);
        }
        for name in &mut self.export_flow.jpeg_display_names {
            shared_signer::bytes::zeroize_bytes(name);
        }
        shared_signer::bytes::zeroize_bytes(&mut self.export_flow.jpeg_display_lens);
        shared_signer::bytes::zeroize_bytes(&mut self.export_flow.jpeg_desc_buf);
        self.export_flow.jpeg_file_count = 0;
        self.export_flow.jpeg_selected = 0;
        self.export_flow.jpeg_desc_len = 0;

        shared_signer::bytes::zeroize_bytes(&mut self.hint.buffer);
        self.hint.length = 0;

        self.import.clear_descriptor();
        for name in &mut self.import.jpeg_names {
            shared_signer::bytes::zeroize_bytes(name);
        }
        for name in &mut self.import.jpeg_display {
            shared_signer::bytes::zeroize_bytes(name);
        }
        shared_signer::bytes::zeroize_bytes(&mut self.import.jpeg_display_lens);
        shared_signer::bytes::zeroize_bytes(&mut self.import.embedded_payload);
        shared_signer::bytes::zeroize_bytes(&mut self.import.recovered_hint);
        self.import.jpeg_count = 0;
        self.import.jpeg_selected = 0;
        self.import.carrier = None;
        self.import.embedded_payload_len = 0;
        self.import.recovered_hint_len = 0;
    }
}
