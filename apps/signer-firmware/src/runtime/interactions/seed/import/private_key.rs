//! Manual raw-private-key import.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::{hw::display, runtime::data::AppData};
use crate::services::audio as sound;
use crate::services::raw_key::{decode_and_install, decode_and_install_transient, RawKeyImportError};

fn import_input(ad: &mut AppData) -> Result<usize, RawKeyImportError> {
    let length = ad.wallet.keys.hex_input_len as usize;
    let mut encoded = [0u8; 64];
    encoded[..length].copy_from_slice(&ad.wallet.keys.hex_input[..length]);
    let result = if ad.wallet.seeds.pending_add_wallet_is_restore() {
        decode_and_install_transient(ad, &encoded[..length])
    } else {
        decode_and_install(ad, &encoded[..length])
    };
    shared_signer::bytes::zeroize_bytes(&mut encoded);
    if result.is_ok() {
        shared_signer::bytes::zeroize_bytes(&mut ad.wallet.keys.hex_input);
        ad.wallet.keys.hex_input_len = 0;
    }
    result
}

fn complete_import_navigation(ad: &mut AppData, slot_index: usize) -> Result<(), &'static str> {
    if ad.wallet.seeds.pending_add_wallet_is_restore() {
        let reserved = usize::from(ad.wallet.seeds.pending_add_wallet_slot);
        if slot_index != reserved {
            ad.wallet.seeds.seed_mgr.delete(slot_index);
            let _ = crate::services::wallet_session::restore_persistent_active_wallet(ad);
            return Err("Wallet creation failed");
        }
        ad.wallet.seeds.mark_pending_add_wallet_installed();
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(
            ad,
            crate::runtime::navigation::route!(WalletNameEntry { purpose: 3 }),
        );
    } else if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
        ad.storage.persistence.recovery_words_acknowledged = true;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageFinalizeChoice));
    } else {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu));
    }
    Ok(())
}

fn rejection_message(error: RawKeyImportError) -> &'static str {
    match error {
        RawKeyImportError::InvalidLength | RawKeyImportError::InvalidHex => "Invalid hex characters",
        RawKeyImportError::InvalidKey => "Invalid key (not on curve)",
        RawKeyImportError::AlreadyExists => "Wallet already exists",
        RawKeyImportError::SlotsFull => crate::services::wallet_session::SLOTS_FULL_MESSAGE,
    }
}

fn finish_import(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    match import_input(ad) {
        Ok(slot_index) => {
            log!("[IMPORT-KEY] Raw key stored in slot {}", slot_index);
            if crate::runtime::interactions::feedback::physical_presentation_enabled() {
                boot_display.draw_saving_screen("Key imported!");
                sound::success();
                crate::services::timing::pause(delay, 1500);
            }
            if let Err(message) = complete_import_navigation(ad, slot_index) {
                show_rejection(boot_display, delay, message, 2_000, ErrorSound::Silent);
            }
        }
        Err(error) => {
            show_rejection(
                boot_display,
                delay,
                rejection_message(error),
                2000,
                ErrorSound::Silent,
            );
        }
    }
    true
}

fn apply_back(ad: &mut AppData) -> bool {
    shared_signer::bytes::zeroize_bytes(&mut ad.wallet.keys.hex_input);
    ad.wallet.keys.hex_input_len = 0;
    if !crate::runtime::effects::back(ad) {
        let fallback = if ad.wallet.seeds.pending_add_wallet_is_restore()
            || ad.storage.persistence.device_storage_intent.is_seed_onboarding()
        {
            crate::runtime::navigation::route!(AdvancedRestoreMenu)
        } else {
            crate::runtime::navigation::route!(ImportMenu)
        };
        let _ = crate::runtime::effects::route(ad, fallback);
    }
    true
}

fn write_character(ad: &mut AppData, character: u8) {
    let normalized = if (b'A'..=b'F').contains(&character) {
        character + 32
    } else {
        character
    };
    if ad.wallet.keys.hex_input_len < 64 {
        ad.wallet.keys.hex_input[ad.wallet.keys.hex_input_len as usize] = normalized;
        ad.wallet.keys.hex_input_len += 1;
    }
}

fn backspace(ad: &mut AppData) {
    ad.wallet.keys.hex_input_len = ad.wallet.keys.hex_input_len.saturating_sub(1);
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        return apply_back(ad);
    }

    use crate::ui::keyboard::{hit_test, KeyAction, KeyboardMode};
    match hit_test(x, y, KeyboardMode::Hex, 0) {
        KeyAction::Char(character) => {
            write_character(ad, character);
            if crate::runtime::interactions::feedback::physical_presentation_enabled() {
                boot_display.update_import_privkey_input(
                    &ad.wallet.keys.hex_input,
                    ad.wallet.keys.hex_input_len,
                );
            }
        }
        KeyAction::Backspace => {
            backspace(ad);
            if crate::runtime::interactions::feedback::physical_presentation_enabled() {
                boot_display.update_import_privkey_input(
                    &ad.wallet.keys.hex_input,
                    ad.wallet.keys.hex_input_len,
                );
            }
        }
        KeyAction::Ok => {
            if ad.wallet.keys.hex_input_len == 64 {
                return finish_import(ad, boot_display, delay);
            }
        }
        _ => {}
    }
    false
}
