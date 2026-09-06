// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use crate::services::stego::{StegoCarrier, StegoSecurity};

mod portable;
mod security;
pub use portable::PortableCredentialState;

pub struct StegoState {
    pub session: StegoSessionState,
    pub export_flow: StegoExportState,
    pub hint: StegoHintState,
    pub import: StegoImportState,
}


pub struct StegoSessionState {
    pub result_ok: bool,
    pub auto_scan: bool,
    pub portable: PortableCredentialState,
}

pub struct StegoExportState {
    pub carrier: StegoCarrier,
    pub security: StegoSecurity,
    pub portable_confirmation_digest: [u8; 32],
    pub portable_confirmation_pending: bool,
    pub jpeg_file_names: [[u8; 11]; 8],
    pub jpeg_display_names: [[u8; 32]; 8],
    pub jpeg_display_lens: [u8; 8],
    pub jpeg_file_count: u8,
    pub jpeg_selected: u8,
    pub jpeg_desc_buf: [u8; 256],
    pub jpeg_desc_len: usize,
}

pub struct StegoHintState {
    pub buffer: [u8; 64],
    pub length: usize,
}

pub struct StegoImportState {
    pub descriptor_buf: [u8; 96],
    pub descriptor_len: usize,
    pub jpeg_names: [[u8; 11]; 8],
    pub jpeg_display: [[u8; 32]; 8],
    pub jpeg_display_lens: [u8; 8],
    pub jpeg_count: u8,
    pub jpeg_selected: u8,
    pub carrier: Option<StegoCarrier>,
    pub embedded_payload: [u8; 256],
    pub embedded_payload_len: usize,
    pub recovered_hint: [u8; 64],
    pub recovered_hint_len: usize,
}

impl StegoState {
    pub(super) fn new() -> Self {
        Self {
            session: StegoSessionState {
                result_ok: false,
                auto_scan: false,
                portable: PortableCredentialState::new(),
            },
            export_flow: StegoExportState {
                carrier: StegoCarrier::Descriptor,
                security: StegoSecurity::DeviceBound,
                portable_confirmation_digest: [0; 32],
                portable_confirmation_pending: false,
                jpeg_file_names: [[0; 11]; 8],
                jpeg_display_names: [[0; 32]; 8],
                jpeg_display_lens: [0; 8],
                jpeg_file_count: 0,
                jpeg_selected: 0,
                jpeg_desc_buf: [0; 256],
                jpeg_desc_len: 0,
            },
            hint: StegoHintState {
                buffer: [0; 64],
                length: 0,
            },
            import: StegoImportState {
                descriptor_buf: [0; 96],
                descriptor_len: 0,
                jpeg_names: [[0; 11]; 8],
                jpeg_display: [[0; 32]; 8],
                jpeg_display_lens: [0; 8],
                jpeg_count: 0,
                jpeg_selected: 0,
                carrier: None,
                embedded_payload: [0; 256],
                embedded_payload_len: 0,
                recovered_hint: [0; 64],
                recovered_hint_len: 0,
            },
        }
    }
}

impl StegoExportState {
    pub fn clear_portable_confirmation(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.portable_confirmation_digest);
        self.portable_confirmation_pending = false;
    }
}

impl StegoImportState {
    pub fn clear_descriptor(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.descriptor_buf);
        self.descriptor_len = 0;
    }
}

