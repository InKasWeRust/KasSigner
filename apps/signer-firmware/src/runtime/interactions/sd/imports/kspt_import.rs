//! Import transaction, multisig descriptor, or address payloads from SD.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound, show_success};
use super::super::{
    common::context::SdFileListContext, parse_descriptor, run_sd_file_list_context,
    sdcard, FileListWorkflow,
};
use crate::runtime::{
    data::{AppData, EncryptedFileOperation, EncryptedPayloadKind},
    input::AppState,
};

const MAX_IMPORT_BYTES: usize = 1_024;
const ENCRYPTED_HEADERS: [&[u8; 4]; 2] = [b"KAS\x04", b"KAS\x03"];

pub(crate) fn handle_sd_kspt_file_list(context: SdFileListContext<'_, '_, '_>) -> bool {
    run_sd_file_list_context(
        context,
        FileListWorkflow {
            allow_delete: true,
            current_state: AppState::SdKsptFileList,
            back_state: crate::runtime::navigation::continuation!(SdImportMenu),
        },
        import_selected_payload,
    )
}

fn import_selected_payload(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
    let _ = &mut *i2c;
    boot_display.draw_loading_screen("Loading TX...");
    match read_selected_payload(ad, delay, i2c) {
        Ok((payload, length)) if ENCRYPTED_HEADERS.iter().any(|header| payload[..length].starts_with(*header)) => {
            stage_encrypted_payload(ad, &payload[..length]);
        }
        Ok((payload, length)) => {
            load_plain_payload(ad, boot_display, delay, liveness, &payload[..length]);
        }
        Err(error) => {
            log!("[SD-KSPT] Read failed: {}", error);
            show_rejection(boot_display, delay, "Read error", 2_000, ErrorSound::Silent);
        }
    }
}

fn read_selected_payload(
    ad: &AppData,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Result<([u8; MAX_IMPORT_BYTES], usize), &'static str> {
    let _ = &mut *i2c;
    sdcard::with_sd_card!(i2c, delay, |card| {
        let fat32 = sdcard::mount_fat32(card)?;
        let (entry, _, _) =
            sdcard::find_file_in_root(card, &fat32, &ad.storage.browser.selected_file)?;
        let mut payload = [0u8; MAX_IMPORT_BYTES];
        let length = sdcard::read_file(card, &fat32, &entry, &mut payload)?;
        Ok((payload, length))
    })
}

fn stage_encrypted_payload(ad: &mut AppData, payload: &[u8]) {
    ad.qr.outgoing.buffer[..payload.len()].copy_from_slice(payload);
    ad.qr.outgoing.length = payload.len();
    ad.storage.export_file.encrypted_operation = EncryptedFileOperation::Import {
        kind: EncryptedPayloadKind::Transaction,
        back_state: crate::runtime::navigation::continuation!(SdKsptFileList),
    };
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdKsptEncryptPass));
}

fn load_plain_payload(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    payload: &[u8],
) {
    ad.qr.outgoing.buffer[..payload.len()].copy_from_slice(payload);
    ad.qr.outgoing.length = payload.len();
    ad.qr.outgoing.frame = 0;
    ad.qr.outgoing.frame_count = 0;
    ad.qr.presentation.large = false;
    ad.signing.transaction.signatures_present = 0;
    ad.signing.transaction.signatures_required = 0;
    log!("[SD-KSPT] Loaded {} bytes from SD", payload.len());

    if payload.starts_with(b"multi_hd45(") || payload.starts_with(b"multi_hd(") {
        load_descriptor(ad, boot_display, delay, liveness, payload);
    } else if payload.starts_with(b"kaspa:") || payload.starts_with(b"kaspatest:") {
        load_multisig_address(ad, boot_display, delay, payload);
    } else if payload.starts_with(kassigner_protocol::wire::pskt_envelope::PSKT_MAGIC) {
        crate::runtime::interactions::tx::load_standard_transaction_with_checkpoint(payload, ad, liveness);
    } else {
        crate::runtime::interactions::tx::load_compact_transaction_with_checkpoint(payload, ad, liveness);
    }
}

fn load_descriptor(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    payload: &[u8],
) {
    liveness();
    let Some(descriptor) = parse_descriptor(payload) else {
        show_rejection(boot_display, delay, "Bad descriptor", 2_000, ErrorSound::Silent);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdKsptFileList));
        return;
    };

    crate::runtime::interactions::multisig_config::install_descriptor(ad, &descriptor, false);
    liveness();
    show_success(boot_display, delay, "Descriptor loaded!", 1_000);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigDescriptor));
}

fn load_multisig_address(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    payload: &[u8],
) {
    if payload.len() > ad.export.kpub_data.len() {
        show_rejection(boot_display, delay, "Address too long", 2_000, ErrorSound::Silent);
        return;
    }
    ad.export.kpub_data[..payload.len()].copy_from_slice(payload);
    ad.export.kpub_len = payload.len();
    ad.signing.multisig.creating.active = false;
    show_success(boot_display, delay, "Address loaded!", 1_000);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigShowAddress));
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_import_transaction_payload(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    payload: &[u8],
) {
    if ENCRYPTED_HEADERS.iter().any(|header| payload.starts_with(*header)) {
        stage_encrypted_payload(ad, payload);
    } else if payload.starts_with(b"multi_hd45(") || payload.starts_with(b"multi_hd(")
        || payload.starts_with(b"kaspa:") || payload.starts_with(b"kaspatest:")
    {
        load_plain_payload(ad, boot_display, delay, &mut || {}, payload);
    } else if payload.starts_with(kassigner_protocol::wire::pskt_envelope::PSKT_MAGIC) {
        crate::runtime::interactions::tx::workflow_load_standard_transaction(payload, ad);
    } else {
        crate::runtime::interactions::tx::workflow_load_compact_transaction(payload, ad);
    }
}
