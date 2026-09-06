//! Encrypt and save the payload selected by an explicit export operation.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound, show_success};
use super::super::super::{
    AppData, display, generate_trng_nonce, sdcard, sound, write_file_to_sd,
};
use super::navigation::finish_operation;
use crate::runtime::data::EncryptedFileOperation;

pub(super) fn save_encrypted_payload(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    operation: EncryptedFileOperation,
) {
    let EncryptedFileOperation::Export {
        filename,
        success_state,
        ..
    } = operation
    else {
        return;
    };

    boot_display.draw_saving_screen("Encrypting...");
    let passphrase = &ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len];
    let nonce = match generate_trng_nonce() {
        Ok(nonce) => nonce,
        Err(message) => {
            show_rejection(boot_display, delay, message, 2_000, ErrorSound::Beep);
            finish_operation(ad, success_state);
            return;
        }
    };
    let mut salt = [0u8; offline_signer::crypto::password_kdf::SALT_SIZE];
    if crate::services::entropy::fill(&mut salt).is_err() {
        show_rejection(boot_display, delay, "RNG health failed", 2_000, ErrorSound::Beep);
        finish_operation(ad, success_state);
        return;
    }
    let data_len = ad.qr.outgoing.length;
    let Ok(mut encrypted) = crate::services::memory::zeroed_bytes(1_024) else {
        show_rejection(boot_display, delay, "Not enough memory", 2_000, ErrorSound::Beep);
        finish_operation(ad, success_state);
        return;
    };
    boot_display.update_progress_bar(10);
    let encryption_result = super::crypto::seal_envelope(
        &ad.qr.outgoing.buffer[..data_len], passphrase, &salt, &nonce, &mut encrypted,
    );
    shared_signer::bytes::zeroize_bytes(&mut salt);
    let encrypted_size = encryption_result.as_ref().copied().unwrap_or_default();

    match encryption_result {
        Ok(encrypted_size) => {
            boot_display.update_progress_bar(70);
            boot_display.draw_saving_screen("Writing to SD...");
            let result = write_file_to_sd(i2c, delay, &filename, &encrypted[..encrypted_size]);
            sound::stop_ticking();
            match result {
                Ok(()) => {
                    boot_display.update_progress_bar(100);
                    let mut display_name = [0u8; 13];
                    let display_length = sdcard::format_83_display(&filename, &mut display_name);
                    let name = core::str::from_utf8(&display_name[..display_length]).unwrap_or("?");
                    log!("[SD-ENCRYPT] Encrypted {} bytes as {}", data_len, name);
                    show_success(boot_display, delay, "Saved!", 1_500);
                }
                Err(error) => {
                    log!("[SD-ENCRYPT] Write failed: {}", error);
                    show_rejection(boot_display, delay, "SD write failed", 2_000, ErrorSound::Beep);
                }
            }
        }
        Err(_) => {
            sound::stop_ticking();
            show_rejection(boot_display, delay, "Encryption failed", 2_000, ErrorSound::Beep);
        }
    }

    shared_signer::bytes::zeroize_bytes(&mut encrypted[..encrypted_size]);
    finish_operation(ad, success_state);
}
