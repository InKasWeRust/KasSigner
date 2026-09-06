//! Raw private-key import from SD.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::services::raw_key::{decode_and_install, RawKeyImportError};

pub(super) fn import(
    ad: &mut crate::runtime::data::AppData,
    payload: &[u8],
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    match decode_and_install(ad, payload.get(..64).unwrap_or(payload)) {
        Ok(slot_index) => {
            log!("[SD-IMPORT] Plain hex key imported to slot {}", slot_index);
            boot_display.draw_saving_screen("Key imported!");
            crate::services::audio::success();
            crate::services::timing::pause(delay, 1500);
        }
        Err(error) => {
            show_rejection(boot_display, delay, error_message(error), 2000, ErrorSound::Silent);
        }
    }
}

fn error_message(error: RawKeyImportError) -> &'static str {
    match error {
        RawKeyImportError::InvalidLength | RawKeyImportError::InvalidHex => "Not a valid key file",
        RawKeyImportError::InvalidKey => "Invalid key",
        RawKeyImportError::AlreadyExists => "Wallet already exists",
        RawKeyImportError::SlotsFull => crate::services::wallet_session::SLOTS_FULL_MESSAGE,
    }
}
