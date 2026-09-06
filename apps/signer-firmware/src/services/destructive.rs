//! Domain/hardware effects for destructive operations.
//!
//! Runtime owns confirmation UI, feedback, sound, and navigation. This service
//! performs only the destructive state/storage mutation after runtime has
//! completed the hold-to-confirm policy.

use crate::{runtime::data::AppData, services::storage_device as sdcard};

pub(crate) fn delete_seed(ad: &mut AppData) -> bool {
    let index = usize::from(ad.wallet.seeds.pending_delete_slot);
    let mut deleted = false;
    if index < ad.wallet.seeds.seed_mgr.slots.len()
        && ad.wallet.seeds.seed_mgr.slot_visible(index)
    {
        let was_active = ad.wallet.seeds.seed_mgr.active == index as u8;
        ad.wallet.seeds.seed_mgr.delete(index);
        if was_active {
            crate::services::wallet_session::clear_active_wallet(ad);
        }
        deleted = true;
    }
    ad.wallet.seeds.pending_delete_slot = 0xFF;
    deleted
}


pub(crate) fn delete_sd_file(
    ad: &mut AppData,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> bool {
    let result = sdcard::with_sd_card!(i2c, delay, |card| {
        let fat32 = sdcard::mount_fat32(card)?;
        sdcard::delete_file(card, &fat32, &ad.storage.browser.selected_file)
    });
    match result {
        Ok(()) => {
            log_deleted_file(ad);
            remove_selected_file(ad);
            true
        }
        Err(error) => {
            log!("[SD-DELETE] Failed: {}", error);
            false
        }
    }
}

fn log_deleted_file(ad: &AppData) {
    let mut display_name = [0u8; 13];
    let length = sdcard::format_83_display(&ad.storage.browser.selected_file, &mut display_name);
    let name = core::str::from_utf8(&display_name[..length]).unwrap_or("?");
    log!("[SD-DELETE] Deleted {}", name);
}

fn remove_selected_file(ad: &mut AppData) {
    if let Some(index) = ad.storage.browser.file_list[..usize::from(ad.storage.browser.file_count)]
        .iter()
        .position(|entry| *entry == ad.storage.browser.selected_file)
    {
        for destination in index..7 {
            ad.storage.browser.file_list[destination] = ad.storage.browser.file_list[destination + 1];
        }
        ad.storage.browser.file_list[7] = [b' '; 11];
        ad.storage.browser.file_count = ad.storage.browser.file_count.saturating_sub(1);
    }
    if ad.storage.browser.file_scroll > 0
        && ad.storage.browser.file_scroll >= ad.storage.browser.file_count
    {
        ad.storage.browser.file_scroll = ad.storage.browser.file_count.saturating_sub(4);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FormatSdOutcome { Complete, Failed }

pub(crate) fn format_sd(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) -> FormatSdOutcome {
    if sdcard::card_is_known_locked() {
        match sdcard::force_erase_locked_card(i2c, delay, liveness) {
            Ok(true) | Ok(false) => {}
            Err(error) => {
                log!("[SD-FORMAT] locked-card force erase failed: {}", error);
                return FormatSdOutcome::Failed;
            },
        }
    }
    if sdcard::format_fat32(i2c, delay, liveness) {
        FormatSdOutcome::Complete
    } else {
        FormatSdOutcome::Failed
    }
}

