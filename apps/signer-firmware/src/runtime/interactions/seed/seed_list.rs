// Seed-list controller facade.

mod list;

use super::{AppData, display};

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
    liveness: &mut dyn FnMut(),
) -> Option<bool> {
    if !matches!(
        ad.navigation.app.state,
        crate::runtime::input::AppState::SeedList
    ) {
        return None;
    }
    Some(list::handle(ad, boot_display, delay, x, y, is_back, liveness))
}


pub(super) fn handle_add_wallet_choice(
    ad: &mut AppData, x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    use crate::runtime::input::AppState;
    use crate::ui::screens::device::persistence::{BUTTON_X, FRESH_BUTTON_Y, SAVE_BUTTON_Y};
    if ad.navigation.app.state != AppState::AddWalletChoice { return None; }
    if is_back {
        ad.wallet.seeds.clear_pending_add_wallet();
        return_after_add_wallet(ad);
        return Some(true);
    }
    if !BUTTON_X.contains(&x) { return Some(false); }
    if FRESH_BUTTON_Y.contains(&y) {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WalletNameEntry { purpose: 1 }));
        return Some(true);
    }
    if SAVE_BUTTON_Y.contains(&y) {
        return Some(crate::runtime::navigation::begin_add_wallet(ad, 2));
    }
    Some(false)
}

pub(super) fn return_after_add_wallet(ad: &mut AppData) {
    let pending_multisig_key = ad.wallet.seeds.multisig_wallet_return();
    let multisig_key = pending_multisig_key.filter(|key_idx| {
        !ad.signing.multisig.creating.active
            && *key_idx < ad.signing.multisig.creating.n
            && ad.signing.multisig.creating.slot_empty(*key_idx as usize)
    });
    if pending_multisig_key.is_some() && multisig_key.is_none() {
        ad.wallet.seeds.clear_multisig_wallet_return();
    }

    // Add Wallet reuses the hardened onboarding credential screens. Preserve
    // their narrow, audited transition policy by returning through WALLETS
    // first; from that Seeds-owned state we can safely resume Multisig. Keep
    // the continuation token until the Multisig route itself commits so an
    // unexpected navigation rejection cannot silently lose the pending key.
    if !matches!(
        ad.navigation.app.state,
        crate::runtime::input::AppState::SeedList
    ) && !crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList))
    {
        return;
    }
    if let Some(key_idx) = multisig_key {
        ad.signing.multisig.scroll = 0;
        if crate::runtime::effects::route(
            ad,
            crate::runtime::navigation::route!(MultisigPickSeed { key_idx }),
        ) {
            ad.wallet.seeds.clear_multisig_wallet_return();
        }
    }
}
