use super::{AppData, BootDisplay};
use crate::runtime::input::AppState;

pub(super) fn redraw(ad: &AppData, display: &mut BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::SdFileList | AppState::SdWalletBackupFileList => {
            let (fingerprints, count) = seed_fingerprints(ad);
            display.draw_sd_file_list_ex(
                &ad.storage.browser.file_list,
                ad.storage.browser.file_count,
                ad.storage.browser.file_scroll,
                &fingerprints,
                count,
            );
        }
        AppState::SdKsptFileList | AppState::SdKpubFileList => {
            display.draw_sd_file_list_ex(
                &ad.storage.browser.file_list,
                ad.storage.browser.file_count,
                ad.storage.browser.file_scroll,
                &[[0; 4]; 4],
                0,
            );
        }
        AppState::SdImportMenu => {
            let title = if ad.navigation.history.peek() == Some(AppState::SeedsMenu) {
                "RECOVERY"
            } else {
                "IMPORT FROM SD"
            };
            display.update_menu_content(title, &ad.navigation.sd_import_menu);
        }
        _ => return false,
    }
    true
}

fn seed_fingerprints(ad: &AppData) -> ([[u8; 4]; 4], u8) {
    let mut fingerprints = [[0u8; 4]; 4];
    let mut count = 0u8;
    for (slot_index, slot) in ad.wallet.seeds.seed_mgr.slots.iter().enumerate() {
        if count as usize == fingerprints.len() { break; }
        if !ad.wallet.seeds.seed_mgr.slot_visible(slot_index) { continue; }
        if slot.is_empty() { continue; }
        fingerprints[count as usize] = slot.fingerprint;
        count += 1;
    }
    (fingerprints, count)
}
