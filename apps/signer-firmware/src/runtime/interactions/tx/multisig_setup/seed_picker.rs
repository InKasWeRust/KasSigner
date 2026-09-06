use crate::{
    runtime::interactions::feedback::{show_rejection, ErrorSound},
    runtime::data::AppData,
    hw::display::BootDisplay,
    ui::display::{draw_lato_hint, measure_hint, COLOR_TEXT_DIM},
    wallet::seed_manager::MAX_SLOTS,
};

const VISIBLE_ROWS: u8 = 3;
const ROW_TOP: u16 = 46;
const ROW_HEIGHT: u16 = 46;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    key_idx: u8,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.wallet.seeds.clear_multisig_wallet_return();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigAddKey { key_idx }));
        return true;
    }

    let loaded = loaded_wallet_slots(ad);
    let loaded_count = loaded_wallet_count(ad);
    let can_add = ad.wallet.seeds.seed_mgr.find_free().is_some();
    let visible_total = loaded_count + usize::from(can_add);
    if x < 35 && (46..=184).contains(&y) {
        return scroll_up(ad);
    }
    if x > 285 && (46..=184).contains(&y) {
        return scroll_down(ad, visible_total);
    }

    let Some(list_idx) = tapped_list_index(ad.signing.multisig.scroll, x, y) else {
        return false;
    };
    if list_idx >= visible_total {
        return false;
    }
    if can_add && list_idx == 0 {
        return begin_add_wallet(ad, key_idx);
    }

    let wallet_idx = list_idx.saturating_sub(usize::from(can_add));
    if wallet_idx >= loaded_count {
        return false;
    }
    let real_slot = loaded[wallet_idx] as u8;

    // Multisig wallet selection intentionally has no destructive touch zone.
    // The whole wallet row selects that wallet; deletion is available only
    // from the normal Wallet Details/management flow.
    if let Err(message) = activate_seed_if_needed(ad, boot_display, liveness, real_slot) {
        show_rejection(
            boot_display,
            delay,
            message,
            1500,
            ErrorSound::Beep,
        );
        return true;
    }
    if !store_cosigner_and_advance(ad, liveness, key_idx) {
        show_rejection(boot_display, delay, "Duplicate cosigner", 1500, ErrorSound::Beep);
    }
    true
}

pub(super) fn has_wallet_choice(ad: &AppData) -> bool {
    ad.wallet.seeds.seed_mgr.find_free().is_some() || loaded_wallet_count(ad) > 0
}

fn begin_add_wallet(ad: &mut AppData, key_idx: u8) -> bool {
    if key_idx >= ad.signing.multisig.creating.n
        || !ad.signing.multisig.creating.slot_empty(key_idx as usize)
        || ad.wallet.seeds.seed_mgr.find_free().is_none()
    {
        return false;
    }
    ad.wallet.seeds.stage_multisig_wallet_return(key_idx);
    ad.wallet.seeds.seed_list_scroll = 0;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AddWalletChoice));
    true
}

fn loaded_wallet_count(ad: &AppData) -> usize {
    ad.wallet
        .seeds
        .seed_mgr
        .slots
        .iter()
        .enumerate()
        .filter(|(index, _)| ad.wallet.seeds.seed_mgr.slot_visible(*index))
        .count()
}

fn loaded_wallet_slots(ad: &AppData) -> [usize; 16] {
    let mut loaded = [0usize; 16];
    let mut count = 0usize;
    for index in 0..MAX_SLOTS {
        if ad.wallet.seeds.seed_mgr.slot_visible(index) {
            loaded[count] = index;
            count += 1;
        }
    }
    loaded
}

fn scroll_up(ad: &mut AppData) -> bool {
    if ad.signing.multisig.scroll < VISIBLE_ROWS {
        return false;
    }
    ad.signing.multisig.scroll -= VISIBLE_ROWS;
    true
}

fn scroll_down(ad: &mut AppData, visible_total: usize) -> bool {
    if usize::from(ad.signing.multisig.scroll) + usize::from(VISIBLE_ROWS) >= visible_total {
        return false;
    }
    ad.signing.multisig.scroll += VISIBLE_ROWS;
    true
}

fn tapped_list_index(scroll: u8, x: u16, y: u16) -> Option<usize> {
    if !(40..=280).contains(&x) {
        return None;
    }
    for visible in 0..VISIBLE_ROWS {
        let row_y = ROW_TOP + u16::from(visible) * ROW_HEIGHT;
        if (row_y..row_y + ROW_HEIGHT).contains(&y) {
            return Some(scroll as usize + visible as usize);
        }
    }
    None
}

fn activate_seed_if_needed(
    ad: &mut AppData,
    boot_display: &mut BootDisplay<'_>,
    liveness: &mut dyn FnMut(),
    real_slot: u8,
) -> Result<(), &'static str> {
    let already_active = ad.wallet.seeds.seed_mgr.active == real_slot
        && ad.wallet.addresses.pubkeys_cached;
    if already_active {
        return Ok(());
    }

    let slot = &ad.wallet.seeds.seed_mgr.slots[real_slot as usize];
    if slot.is_raw_key() {
        return Err("Raw keys cannot be multisig cosigners");
    }
    if ad.signing.multisig.creating.v45 && slot.is_account_key() {
        return Err("xprv slot has no 45' cosigner key");
    }
    if crate::runtime::interactions::feedback::physical_presentation_enabled() {
        boot_display.draw_saving_screen("Deriving addresses...");
        boot_display.update_progress_bar(50);
        let hint_width = measure_hint("Deriving...");
        draw_lato_hint(
            &mut boot_display.display,
            "Deriving...",
            (320 - hint_width) / 2,
            170,
            COLOR_TEXT_DIM,
        );
    }
    crate::services::wallet_session::activate_slot_with_cache(ad, real_slot as usize, liveness)
    .map_err(|error| error.message())
}

fn store_cosigner_and_advance(ad: &mut AppData, liveness: &mut dyn FnMut(), key_idx: u8) -> bool {
    if key_idx >= ad.signing.multisig.creating.n { return false; }
    let active = usize::from(ad.wallet.seeds.seed_mgr.active);
    let Some(slot) = ad.wallet.seeds.seed_mgr.slots.get(active) else { return false; };
    if !slot.is_mnemonic() { return false; }
    let Ok(mut seed) = crate::services::wallet_keys::derive_slot_seed_with_checkpoint(slot, liveness) else { return false; };
    let parts = offline_signer::derivation::xpub::derive_multisig_account_parts(&seed.bytes, 0);
    crate::runtime::signing::zeroize_seed(&mut seed.bytes);
    let Ok(parts) = parts else { return false; };
    if !ad.signing.multisig.creating.set_cosigner(key_idx as usize, &parts) { return false; }
    advance_after_cosigner(ad, key_idx + 1, liveness);
    true
}

pub(crate) fn finish_cosigner_collection(ad: &mut AppData, checkpoint: &mut (impl FnMut() + ?Sized)) {
    ad.wallet.seeds.clear_multisig_wallet_return();
    ad.signing.multisig.creating.sort_cosigners();
    let _ = resolve_loaded_cosigner_index(ad, checkpoint);
    ad.signing.multisig.creating.build_script();
    ad.signing.multisig.creating.active = true;
    if let Some(slot) = ad.signing.multisig.store.find_free() {
        ad.signing.multisig.store.configs[slot] = ad.signing.multisig.creating.clone();
    }
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigShowAddress));
}

pub(crate) fn advance_after_cosigner(
    ad: &mut AppData,
    next: u8,
    checkpoint: &mut (impl FnMut() + ?Sized),
) {
    if next < ad.signing.multisig.creating.n {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigAddKey { key_idx: next }));
    } else {
        finish_cosigner_collection(ad, checkpoint);
    }
}

pub(crate) fn resolve_loaded_cosigner_index(
    ad: &mut AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> bool {
    let mut best: Option<u8> = None;
    for (slot_index, slot) in ad.wallet.seeds.seed_mgr.slots.iter().enumerate() {
        if !ad.wallet.seeds.seed_mgr.slot_visible(slot_index) { continue; }
        if !slot.is_mnemonic() { continue; }
        let Ok(mut seed) = crate::services::wallet_keys::derive_slot_seed_with_checkpoint(slot, checkpoint) else { continue; };
        checkpoint();
        let parts = offline_signer::derivation::xpub::derive_multisig_account_parts(&seed.bytes, 0);
        checkpoint();
        crate::runtime::signing::zeroize_seed(&mut seed.bytes);
        let Ok(parts) = parts else { continue; };
        let mut candidate = ad.signing.multisig.creating.clone();
        if candidate.resolve_cosigner_index(&parts) {
            best = Some(best.map_or(candidate.cosigner_index, |old| old.min(candidate.cosigner_index)));
        }
    }
    if let Some(index) = best {
        ad.signing.multisig.creating.cosigner_index = index;
        true
    } else { false }
}

