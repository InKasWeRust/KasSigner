//! Plain extended-private-key import from SD.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};

pub(super) fn import(
    ad: &mut crate::runtime::data::AppData,
    payload: &[u8],
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    let imported = match offline_signer::derivation::xpub::import_xprv_with_metadata(payload) {
        Ok(imported) => imported,
        Err(_) => {
            show_rejection(boot_display, delay, "Invalid xprv", 2_000, ErrorSound::Silent);
            return;
        }
    };

    boot_display.draw_loading_screen("Importing xprv...");
    let result = crate::services::wallet_session::install_account_xprv(ad, imported);
    match result {
        Ok(slot_index) => {
            log!("[SD-IMPORT] Plain xprv imported to slot {}", slot_index);
            boot_display.draw_saving_screen("XPrv imported!");
            crate::services::timing::pause(delay, 2_000);
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList));
        }
        Err(message) => {
            show_rejection(boot_display, delay, message, 2_000, ErrorSound::Silent);
        }
    }
}
