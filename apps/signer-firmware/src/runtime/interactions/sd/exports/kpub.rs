use crate::runtime::interactions::feedback::{show_rejection, show_success, ErrorSound};
// SD controller workflow: kpub.
use super::super::{
    AppData,
    display,
    EncryptionPayload,
    EncryptionPromptWorkflow,
    PromptDestination,
    FilenameWorkflow,
    run_encryption_prompt,
    run_sd_file_list_context, FileListWorkflow,
    parse_descriptor,
    run_filename_workflow,
    sdcard,
};
use super::super::common::context::{SdFileListContext, SdIoContext};
use crate::runtime::{data::TextFileKind, input::AppState};

pub(crate) fn handle_sd_kpub_file_list(context: SdFileListContext<'_, '_, '_>) -> bool {
    run_sd_file_list_context(
        context,
        FileListWorkflow {
            allow_delete: true,
            current_state: AppState::SdKpubFileList,
            back_state: crate::runtime::navigation::continuation!(SdImportMenu),
        },
        load_selected_text,
    )
}

fn load_selected_text(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
    let _ = &mut *i2c;
    boot_display.draw_loading_screen(import_label(ad.storage.browser.text_import_kind));
    let Ok(mut buffer) = crate::services::memory::zeroed_bytes(1024) else {
        show_rejection(boot_display, delay, "Not enough memory", 2000, ErrorSound::Silent);
        return;
    };
    match read_selected_file(ad, i2c, delay, &mut buffer) {
        Ok(length) => handle_import_payload(ad, boot_display, delay, liveness, &buffer[..length]),
        Err(error) => {
            log!("[SD-TXT] Read failed: {}", error);
            show_rejection(boot_display, delay, "SD read error", 2000, ErrorSound::Silent);
        }
    }
}

fn import_label(kind: Option<TextFileKind>) -> &'static str {
    match kind {
        Some(TextFileKind::Kpub) => "Reading kpub...",
        Some(TextFileKind::MultisigAddress) => "Reading address...",
        Some(TextFileKind::MultisigDescriptor) => "Reading descriptor...",
        None => "Reading file...",
    }
}

fn read_selected_file(
    ad: &AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    let _ = &mut *i2c;
    sdcard::with_sd_card!(i2c, delay, |card| {
        let fat32 = sdcard::mount_fat32(card)?;
        let (entry, _, _) = sdcard::find_file_in_root(
            card,
            &fat32,
            &ad.storage.browser.selected_file,
        )?;
        sdcard::read_file(card, &fat32, &entry, buffer)
    })
}

fn handle_import_payload(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    payload: &[u8],
) {
    match ad.storage.browser.text_import_kind {
        Some(TextFileKind::Kpub) => load_kpub(ad, boot_display, delay, payload),
        Some(TextFileKind::MultisigAddress) => {
            load_multisig_address(ad, boot_display, delay, payload)
        }
        Some(TextFileKind::MultisigDescriptor) => {
            load_descriptor(ad, boot_display, delay, liveness, payload)
        }
        None => show_rejection(
            boot_display,
            delay,
            "Unsupported text import",
            2000,
            ErrorSound::Silent,
        ),
    }
}

fn is_encrypted(payload: &[u8]) -> bool {
    payload.starts_with(b"KAS\x04") || payload.starts_with(b"KAS\x03")
}

fn stage_encrypted_import(ad: &mut AppData, payload: &[u8], kind: TextFileKind) {
    if payload.len() > ad.qr.outgoing.buffer.len() {
        return;
    }
    ad.qr.outgoing.buffer[..payload.len()].copy_from_slice(payload);
    ad.qr.outgoing.length = payload.len();
    ad.storage.export_file.encrypted_operation =
        crate::runtime::data::EncryptedFileOperation::Import {
            kind: crate::runtime::data::EncryptedPayloadKind::Text(kind),
            back_state: crate::runtime::navigation::continuation!(SdKpubFileList),
        };
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdKsptEncryptPass));
}

fn load_kpub(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    payload: &[u8],
) {
    if is_encrypted(payload) {
        stage_encrypted_import(ad, payload, TextFileKind::Kpub);
        return;
    }
    let mut canonical = [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN];
    let Ok(length) = offline_signer::derivation::xpub::normalize_kpub_text(payload, &mut canonical)
    else {
        show_rejection(boot_display, delay, "Not a valid kpub", 2000, ErrorSound::Silent);
        return;
    };
    ad.export.kpub_data[..length].copy_from_slice(&canonical[..length]);
    ad.export.kpub_len = length;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub));
}

fn load_multisig_address(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    payload: &[u8],
) {
    if is_encrypted(payload) {
        stage_encrypted_import(ad, payload, TextFileKind::MultisigAddress);
        return;
    }
    if !(payload.starts_with(b"kaspa:") || payload.starts_with(b"kaspatest:")) {
        show_rejection(boot_display, delay, "Not a valid address", 2000, ErrorSound::Silent);
        return;
    }
    let maximum = offline_signer::derivation::xpub::KPUB_MAX_LEN
        .min(ad.qr.outgoing.buffer.len())
        .min(ad.export.kpub_data.len());
    if payload.len() > maximum {
        show_rejection(boot_display, delay, "Address too long", 2000, ErrorSound::Silent);
        return;
    }
    ad.export.kpub_data[..payload.len()].copy_from_slice(payload);
    ad.export.kpub_len = payload.len();
    ad.signing.multisig.creating.active = false;
    ad.qr.outgoing.buffer[..payload.len()].copy_from_slice(payload);
    ad.qr.outgoing.length = payload.len();
    ad.qr.outgoing.frame = 0;
    ad.qr.outgoing.frame_count = 0;
    ad.qr.presentation.large = false;
    show_success(boot_display, delay, "Address loaded!", 1_000);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigShowAddress));
}

fn load_descriptor(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    payload: &[u8],
) {
    if is_encrypted(payload) {
        stage_encrypted_import(ad, payload, TextFileKind::MultisigDescriptor);
        return;
    }
    if payload.is_empty() || payload.len() > 640 {
        show_rejection(boot_display, delay, "Invalid descriptor", 2000, ErrorSound::Silent);
        return;
    }
    log!("[SD-DESC] Loaded: {}", core::str::from_utf8(payload).unwrap_or("?"));
    let Some(descriptor) = parse_descriptor(payload) else {
        show_rejection(boot_display, delay, "Bad descriptor format", 2000, ErrorSound::Silent);
        return;
    };
    crate::runtime::interactions::multisig_config::install_descriptor_and_resolve(ad, &descriptor, false, liveness);
    show_success(boot_display, delay, "Descriptor loaded!", 1_000);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigDescriptor));
}

pub(crate) fn handle_sd_kpub_filename(ctx: SdIoContext<'_, '_, '_>) -> bool {
    run_filename_workflow(
        ctx,
        FilenameWorkflow {
            extension: *b"TXT",
            back_state: crate::runtime::navigation::continuation!(WatchOnlyMenu),
            filename_state: crate::runtime::input::AppState::SdKpubFilename,
            next_state: crate::runtime::navigation::continuation!(SdKpubEncryptAsk),
            redraw_if_exists: true,
            redraw_if_available: true,
        },
    )
}

pub(crate) fn handle_sd_kpub_encrypt_ask(ctx: SdIoContext<'_, '_, '_>) -> bool {
    run_encryption_prompt(
        ctx,
        EncryptionPromptWorkflow {
            back_state: crate::runtime::navigation::continuation!(WatchOnlyMenu),
            payload: EncryptionPayload::KpubExport { kind: TextFileKind::Kpub },
            password_back_state: crate::runtime::navigation::continuation!(SdKpubEncryptAsk),
            encrypted_success_state: crate::runtime::navigation::continuation!(ExportChoice),
            plain_destination: PromptDestination::Route(crate::runtime::navigation::continuation!(WatchOnlyMenu)),
            progress_message: "Saving kpub...",
            success_message: "kpub saved!",
        },
    )
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_import_text_payload(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    kind: TextFileKind,
    payload: &[u8],
) {
    ad.storage.browser.text_import_kind = Some(kind);
    handle_import_payload(ad, boot_display, delay, &mut || {}, payload);
}
