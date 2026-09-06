//! Shared optional-encryption workflows for SD exports.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound, show_success};
use super::super::{AppData, SdIoContext, display, sound, write_file_to_sd};
use crate::{
    runtime::{
        data::{EncryptedFileOperation, EncryptedPayloadKind, TextFileKind},
        navigation::ContinuationRoute,
    },
};

pub(super) enum EncryptionPromptAction {
    Back,
    Encrypt,
    Plain,
    None,
}

#[derive(Clone, Copy)]
pub(crate) enum EncryptionPayload {
    KpubExport { kind: TextFileKind },
    Outgoing { kind: TextFileKind },
    Transaction,
}

#[derive(Clone, Copy)]
pub(crate) enum PromptDestination {
    Route(ContinuationRoute),
    MainMenu,
}

pub(crate) struct EncryptionPromptWorkflow {
    pub back_state: ContinuationRoute,
    pub password_back_state: ContinuationRoute,
    pub encrypted_success_state: ContinuationRoute,
    pub payload: EncryptionPayload,
    pub plain_destination: PromptDestination,
    pub progress_message: &'static str,
    pub success_message: &'static str,
}

fn encryption_prompt_action(x: u16, y: u16, is_back: bool) -> EncryptionPromptAction {
    if is_back {
        EncryptionPromptAction::Back
    } else if (30..=155).contains(&x) && (140..=185).contains(&y) {
        EncryptionPromptAction::Encrypt
    } else if (165..=290).contains(&x) && (140..=185).contains(&y) {
        EncryptionPromptAction::Plain
    } else {
        EncryptionPromptAction::None
    }
}

fn stage_encrypted_export(ad: &mut AppData, workflow: &EncryptionPromptWorkflow) {
    let kind = match workflow.payload {
        EncryptionPayload::KpubExport { kind } => {
            let length = ad.export.kpub_len;
            ad.qr.outgoing.buffer[..length].copy_from_slice(&ad.export.kpub_data[..length]);
            ad.qr.outgoing.length = length;
            EncryptedPayloadKind::Text(kind)
        }
        EncryptionPayload::Outgoing { kind } => EncryptedPayloadKind::Text(kind),
        EncryptionPayload::Transaction => EncryptedPayloadKind::Transaction,
    };
    ad.storage.export_file.encrypted_operation = EncryptedFileOperation::Export {
        kind,
        filename: ad.storage.export_file.filename,
        back_state: workflow.password_back_state,
        success_state: workflow.encrypted_success_state,
    };
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdKsptEncryptPass));
}

fn plain_payload(ad: &AppData, payload: EncryptionPayload) -> &[u8] {
    match payload {
        EncryptionPayload::KpubExport { .. } => &ad.export.kpub_data[..ad.export.kpub_len],
        EncryptionPayload::Outgoing { .. } | EncryptionPayload::Transaction => {
            &ad.qr.outgoing.buffer[..ad.qr.outgoing.length]
        }
    }
}

fn navigate(ad: &mut AppData, destination: PromptDestination) {
    match destination {
        PromptDestination::Route(route) => {
            let _ = crate::runtime::effects::continue_to(ad, route);
        }
        PromptDestination::MainMenu => crate::runtime::effects::home(ad),
    }
}

pub(crate) fn run_encryption_prompt(
    ctx: SdIoContext<'_, '_, '_>,
    workflow: EncryptionPromptWorkflow,
) -> bool {
    let SdIoContext {
        ad,
        boot_display,
        delay,
        i2c,
        x,
        y,
        is_back,
        ..
    } = ctx;
    match encryption_prompt_action(x, y, is_back) {
        EncryptionPromptAction::Back => {
            let _ = crate::runtime::effects::continue_to(ad, workflow.back_state);
        }
        EncryptionPromptAction::Encrypt => stage_encrypted_export(ad, &workflow),
        EncryptionPromptAction::Plain => {
            if matches!(workflow.payload, EncryptionPayload::Transaction) {
                sound::stop_ticking();
            }
            write_plain_with_feedback(
                boot_display,
                delay,
                i2c,
                &ad.storage.export_file.filename,
                plain_payload(ad, workflow.payload),
                workflow.progress_message,
                workflow.success_message,
            );
            navigate(ad, workflow.plain_destination);
        }
        EncryptionPromptAction::None => return false,
    }
    true
}

pub(crate) fn write_plain_with_feedback(
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    filename: &[u8; 11],
    data: &[u8],
    progress_message: &str,
    success_message: &str,
) -> bool {
    boot_display.draw_saving_screen(progress_message);
    match write_file_to_sd(i2c, delay, filename, data) {
        Ok(()) => {
            show_success(boot_display, delay, success_message, 1500);
            true
        }
        Err(error) => {
            log!("[SD-EXPORT] Write failed: {}", error);
            show_rejection(boot_display, delay, "SD write failed", 2000, ErrorSound::Beep);
            false
        }
    }
}
