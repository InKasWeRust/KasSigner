//! Decrypt and route the payload selected by an explicit import operation.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use super::{content, crypto, navigation::finish_operation};
use super::super::super::{AppData, display};
use crate::runtime::data::EncryptedFileOperation;

pub(super) fn load_encrypted_payload(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    operation: EncryptedFileOperation,
) {
    let EncryptedFileOperation::Import { kind, back_state } = operation else {
        return;
    };

    boot_display.draw_loading_screen("Decrypting...");
    let passphrase_length = ad.wallet.seeds.pp_input.len;
    let mut passphrase = [0u8; 64];
    passphrase[..passphrase_length]
        .copy_from_slice(&ad.wallet.seeds.pp_input.buf[..passphrase_length]);
    let Ok(mut plaintext) = crate::services::memory::zeroed_bytes(1_024) else {
        show_rejection(boot_display, delay, "Not enough memory", 2_000, ErrorSound::Beep);
        finish_operation(ad, back_state);
        return;
    };

    match crypto::decrypt_envelope(
        ad,
        boot_display,
        &passphrase[..passphrase_length],
        &mut plaintext,
    ) {
        Ok(length) => {
            ad.storage.export_file.encrypted_operation = EncryptedFileOperation::None;
            ad.wallet.seeds.pp_input.reset();
            content::route(ad, boot_display, delay, liveness, kind, back_state, &plaintext[..length]);
        }
        Err(crypto::DecryptError::Authentication) => {
            show_rejection(boot_display, delay, "Wrong password", 2_000, ErrorSound::Beep);
            ad.qr.outgoing.length = 0;
            finish_operation(ad, back_state);
        }
        Err(crypto::DecryptError::InvalidEnvelope) => {
            show_rejection(boot_display, delay, "Invalid file", 2_000, ErrorSound::Silent);
            ad.qr.outgoing.length = 0;
            finish_operation(ad, back_state);
        }
    }

    shared_signer::bytes::zeroize_bytes(&mut plaintext);
    shared_signer::bytes::zeroize_bytes(&mut passphrase);
}
