use crate::{
    runtime::interactions::feedback::{show_rejection, ErrorSound},
    hw::display,
    runtime::data::AppData,
    services::audio as sound,
    wallet::seed_manager,
};

const PAGE_SIZE: usize = 3;
const START_Y: u16 = 46;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
    liveness: &mut dyn FnMut(),
) -> bool {
    if is_back {
        ad.wallet.seeds.seed_list_scroll = 0;
        // WALLETS is a required-selection surface whenever inventory exists but
        // no wallet has successfully completed activation. Do not allow direct
        // handlers/workflow probes to bypass the central navigation guard.
        if ad.wallet.seeds.seed_mgr.active_slot().is_none() { return true; }
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu));
        return true;
    }
    let (loaded, loaded_count) = loaded_slots(ad);
    let can_add = ad.wallet.seeds.seed_mgr.find_free().is_some();
    let total = loaded_count + usize::from(can_add);
    let scroll = usize::from(ad.wallet.seeds.seed_list_scroll);
    if handle_paging(ad, x, y, scroll, total) { return true; }
    if !(40..280).contains(&x) || !(START_Y..184).contains(&y) { return false; }
    let row = usize::from((y - START_Y) / 46);
    if row >= PAGE_SIZE { return false; }
    let item = scroll + row;
    if can_add && item == 0 {
        ad.wallet.seeds.clear_multisig_wallet_return();
        crate::log!("   SeedList add wallet transition BEGIN");
        liveness();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AddWalletChoice));
        liveness();
        crate::log!("   SeedList add wallet transition DONE");
        return true;
    }
    let wallet_index = item.saturating_sub(usize::from(can_add));
    if wallet_index >= loaded_count { return false; }
    activate(ad, boot_display, delay, loaded[wallet_index]);
    true
}

fn loaded_slots(ad: &AppData) -> ([usize; 16], usize) {
    let mut indices = [0usize; 16];
    let mut count = 0;
    for slot in 0..seed_manager::MAX_SLOTS {
        if ad.wallet.seeds.seed_mgr.slot_visible(slot) {
            indices[count] = slot;
            count += 1;
        }
    }
    (indices, count)
}

fn handle_paging(ad: &mut AppData, x: u16, y: u16, scroll: usize, total: usize) -> bool {
    if y < 42 { return false; }
    if x < 40 && scroll > 0 {
        ad.wallet.seeds.seed_list_scroll = ad.wallet.seeds.seed_list_scroll.saturating_sub(PAGE_SIZE as u8);
        return true;
    }
    if x >= 280 && scroll + PAGE_SIZE < total {
        ad.wallet.seeds.seed_list_scroll = ad.wallet.seeds.seed_list_scroll.saturating_add(PAGE_SIZE as u8);
        return true;
    }
    false
}

fn activate(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>, delay: &mut esp_hal::delay::Delay, slot: usize) {
    if ad.wallet.seeds.seed_mgr.active == slot as u8 {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu));
        return;
    }
    let protection = ad.wallet.seeds.seed_mgr.slots[slot].protection;
    let challenge = match protection {
        crate::wallet::seed_manager::WalletProtection::Pin => Some(crate::services::persistent_wallet::CredentialKind::Pin),
        crate::wallet::seed_manager::WalletProtection::Password => Some(crate::services::persistent_wallet::CredentialKind::Password),
        crate::wallet::seed_manager::WalletProtection::DeviceOnly => None,
    };
    if let Some(kind) = challenge {
        if !ad.runtime.begin_wallet_activation_reauth(slot) {
            show_rejection(boot_display, delay, "Authentication already pending", 1_200, ErrorSound::Beep);
            return;
        }
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::interactions::persistence::enter_storage_unlock(ad, kind);
        return;
    }
    match crate::services::wallet_session::activate_slot(ad, slot) {
        Ok(()) => {
            sound::success();
            let route = if ad.runtime.home_reached {
                crate::runtime::navigation::route!(SeedsMenu)
            } else {
                crate::runtime::navigation::route!(MainMenu)
            };
            crate::runtime::effects::route(ad, route);
        }
        Err(error) => show_rejection(boot_display, delay, error.message(), 1_500, ErrorSound::Beep),
    }
}
