//! Password controller for explicit encrypted-file import and export operations.

use super::super::super::SdIoContext;
use crate::{
    runtime::interactions::{
        feedback::{show_rejection, ErrorSound},
        keyboard::{handle_passphrase_keyboard, KeyboardAction},
    },
    runtime::data::EncryptedFileOperation,
};

use super::{
    load::load_encrypted_payload,
    navigation::navigate_from_password,
    save::save_encrypted_payload,
};

pub(crate) fn handle_sd_kspt_encrypt_pass(ctx: SdIoContext<'_, '_, '_>) -> bool {
    let SdIoContext {
        ad,
        boot_display,
        delay,
        liveness,
        i2c,
        x,
        y,
        is_back,
        ..
    } = ctx;
    let operation = ad.storage.export_file.encrypted_operation;

    if is_back {
        navigate_from_password(ad, operation);
        return true;
    }

    match handle_passphrase_keyboard(&mut ad.wallet.seeds.pp_input, boot_display, x, y) {
        KeyboardAction::Submitted => {
            match operation {
                EncryptedFileOperation::Export { .. } => {
                    save_encrypted_payload(ad, boot_display, delay, i2c, operation);
                }
                EncryptedFileOperation::Import { .. } => {
                    load_encrypted_payload(ad, boot_display, delay, liveness, operation);
                }
                EncryptedFileOperation::None => {
                    show_rejection(
                        boot_display,
                        delay,
                        "No encrypted operation",
                        2_000,
                        ErrorSound::Silent,
                    );
                    ad.wallet.seeds.pp_input.reset();
                }
            }
            true
        }
        KeyboardAction::Edited | KeyboardAction::None => false,
    }
}
