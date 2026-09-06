use crate::hw::{display, touch};
use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::runtime::data::AppData;
use crate::runtime::input::AppState;

use super::common::{prepare_signing_addresses, require_seed, selected_item};


pub(super) fn handle_pure(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    page_up: &touch::TouchZone,
    page_down: &touch::TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if ad.navigation.app.state != AppState::SingleSigMenu {
        return None;
    }
    if is_back {
        ad.navigation.single_sig_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu));
        return Some(true);
    }
    use crate::runtime::interactions::menu_selection::{handle_paged_menu_touch, PagedMenuAction};
    if matches!(
        handle_paged_menu_touch(
            &mut ad.navigation.single_sig_menu, list_zones, page_up, page_down, x, y,
        ),
        PagedMenuAction::PageChanged
    ) {
        return Some(true);
    }
    let Some(item) = selected_item(&ad.navigation.single_sig_menu, list_zones, x, y) else {
        return Some(false);
    };
    dispatch_pure_item(ad, item)
}

fn dispatch_pure_item(ad: &mut AppData, item: u8) -> Option<bool> {
    match item {
        // Address derivation may need a progress surface, so leave it to the
        // narrow hardware fallback.
        0 => None,
        1 if ad.wallet.seeds.seed_loaded => {
            ad.wallet.seeds.pp_input.reset();
            ad.signing.message.payload_len = 0;
            let _ = crate::runtime::effects::menu_select(ad, 1);
            Some(true)
        }
        2 if mnemonic_seed_loaded(ad) => {
            ad.signing.covenant.reset();
            let _ = crate::runtime::effects::menu_select(ad, 2);
            Some(true)
        }
        3 if ad.wallet.seeds.seed_loaded => {
            ad.wallet.seeds.pp_input.reset();
            ad.signing.commit_reveal.plaintext_len = 0;
            ad.signing.commit_reveal.ciphertext.clear();
            ad.signing.commit_reveal.hash = [0u8; 32];
            let _ = crate::runtime::effects::menu_select(ad, 3);
            Some(true)
        }
        4 if ad.wallet.seeds.seed_loaded => {
            ad.signing.commit_reveal.ciphertext.clear();
            ad.signing.commit_reveal.plaintext_len = 0;
            let _ = crate::runtime::effects::menu_select(ad, 4);
            Some(true)
        }
        // Missing-seed and non-mnemonic covenant errors retain the feedback
        // fallback instead of borrowing display/delay for every menu tap.
        1..=4 => None,
        _ => Some(false),
    }
}

fn mnemonic_seed_loaded(ad: &AppData) -> bool {
    ad.wallet.seeds.seed_loaded
        && ad.wallet.seeds.seed_mgr.active_slot().map(|slot| slot.is_mnemonic()).unwrap_or(false)
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.navigation.single_sig_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu));
        return true;
    }
    let Some(item) = selected_item(&ad.navigation.single_sig_menu, list_zones, x, y) else {
        return false;
    };
    match item {
        0 => {
            match prepare_signing_addresses(ad, boot_display, liveness) {
                Ok(()) => { let _ = crate::runtime::effects::menu_select(ad, 0); },
                Err(message) => {
                    show_rejection(
                        boot_display,
                        delay,
                        message,
                        1500,
                        ErrorSound::Beep,
                    );
                }
            }
        }
        1 if require_seed(ad, boot_display, delay) => {
            ad.wallet.seeds.pp_input.reset();
            ad.signing.message.payload_len = 0;
            let _ = crate::runtime::effects::menu_select(ad, 1);
        }
        2 if require_seed(ad, boot_display, delay) => {
            let mnemonic_loaded = ad.wallet.seeds.seed_mgr.active_slot()
                .map(|slot| slot.is_mnemonic())
                .unwrap_or(false);
            if mnemonic_loaded {
                ad.signing.covenant.reset();
                let _ = crate::runtime::effects::menu_select(ad, 2);
            } else {
                show_rejection(
                    boot_display,
                    delay,
                    "Covenant signing requires mnemonic",
                    1800,
                    ErrorSound::Beep,
                );
            }
        }
        3 if require_seed(ad, boot_display, delay) => {
            ad.wallet.seeds.pp_input.reset();
            ad.signing.commit_reveal.plaintext_len = 0;
            ad.signing.commit_reveal.ciphertext.clear();
            ad.signing.commit_reveal.hash = [0u8; 32];
            let _ = crate::runtime::effects::menu_select(ad, 3);
        }
        4 if require_seed(ad, boot_display, delay) => {
            ad.signing.commit_reveal.ciphertext.clear();
            ad.signing.commit_reveal.plaintext_len = 0;
            let _ = crate::runtime::effects::menu_select(ad, 4);
        }
        _ => {}
    }
    true
}
