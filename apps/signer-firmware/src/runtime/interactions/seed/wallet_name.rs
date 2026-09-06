//! Wallet-name entry for new wallets and Wallet Details edits.

use super::{AppData, display};
use crate::runtime::interactions::{feedback::{show_rejection, ErrorSound}, keyboard::{handle_passphrase_keyboard, KeyboardAction}};
use crate::runtime::input::AppState;
use crate::wallet::seed_manager::WALLET_NAME_MAX;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let AppState::WalletNameEntry { purpose } = ad.navigation.app.state else { return None; };
    if is_back {
        handle_back(ad, purpose);
        return Some(true);
    }

    match handle_passphrase_keyboard(&mut ad.wallet.seeds.pp_input, boot_display, x, y) {
        KeyboardAction::None => Some(false),
        KeyboardAction::Edited => {
            if ad.wallet.seeds.pp_input.len > WALLET_NAME_MAX {
                ad.wallet.seeds.pp_input.backspace();
                boot_display.draw_keyboard_screen(&ad.wallet.seeds.pp_input);
            }
            Some(false)
        }
        KeyboardAction::Submitted => handle_submitted(ad, boot_display, delay, purpose),
    }
}

fn handle_back(ad: &mut AppData, purpose: u8) {
    ad.wallet.seeds.pp_input.reset();
    if purpose != 2 { ad.wallet.seeds.clear_pending_wallet_name(); }
    if purpose == 3 {
        if ad.wallet.seeds.pending_add_wallet_has_installed_source() {
            // Raw-key/XPrv sources are already installed in a transient slot.
            // Cancelling the name step must remove that RAM-only slot before
            // returning to the Add Wallet decision.
            ad.wallet.seeds.clear_pending_add_wallet();
            let _ = crate::services::wallet_session::restore_persistent_active_wallet(ad);
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AddWalletChoice));
        } else {
            // Mnemonic restores deliberately order passphrase before name.
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
        }
        return;
    }
    let route = match purpose {
        0 => crate::runtime::navigation::route!(StorageModeChoice),
        1 => crate::runtime::navigation::route!(AddWalletChoice),
        _ => crate::runtime::navigation::route!(WalletDetails),
    };
    crate::runtime::effects::route(ad, route);
}

fn handle_submitted(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    purpose: u8,
) -> Option<bool> {
    let len = ad.wallet.seeds.pp_input.len.min(WALLET_NAME_MAX);
    if len == 0 {
        show_rejection(boot_display, delay, "Enter a wallet name", 1_200, ErrorSound::Silent);
        return Some(true);
    }
    let mut name = [0u8; WALLET_NAME_MAX];
    name[..len].copy_from_slice(&ad.wallet.seeds.pp_input.buf[..len]);
    ad.wallet.seeds.pp_input.reset();
    match purpose {
        0 => create_first_wallet(ad, &name[..len]),
        1 => create_additional_wallet(ad, &name[..len]),
        3 => name_imported_wallet(ad, &name[..len]),
        _ => rename_active_wallet(ad, boot_display, delay, &name[..len]),
    }
    Some(true)
}

fn create_first_wallet(ad: &mut AppData, name: &[u8]) {
    if ad.wallet.seeds.stage_wallet_name(name) {
        crate::runtime::effects::route(
            ad,
            crate::runtime::navigation::route!(StorageSeedWordCountChoice { action: 0 }),
        );
    }
}

fn create_additional_wallet(ad: &mut AppData, name: &[u8]) {
    if ad.wallet.seeds.stage_wallet_name(name) {
        let _ = crate::runtime::navigation::begin_add_wallet(ad, 0);
    }
}


fn name_imported_wallet(ad: &mut AppData, name: &[u8]) {
    if ad.wallet.seeds.stage_wallet_name(name) {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageFinalizeChoice));
    }
}

fn rename_active_wallet(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    name: &[u8],
) {
    let active = usize::from(ad.wallet.seeds.seed_mgr.active);
    if !ad.wallet.seeds.seed_mgr.set_slot_name(active, name) {
        show_rejection(boot_display, delay, "Wallet name unavailable", 1_200, ErrorSound::Silent);
    }
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WalletDetails));
}
