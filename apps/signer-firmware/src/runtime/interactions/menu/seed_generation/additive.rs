//! Optional additive entropy choices layered on mandatory checked device entropy.

use crate::{
    runtime::data::AppData,
    ui::screens::device::persistence::{
        ADD_DICE_BUTTON_Y, ADD_TOUCH_BUTTON_Y, BUTTON_X, DICE_100_BUTTON_Y,
        DICE_200_BUTTON_Y, DICE_25_BUTTON_Y, DICE_50_BUTTON_Y, NO_DICE_BUTTON_Y,
        NO_TOUCH_BUTTON_Y,
    },
    wallet::mnemonic,
};

pub(super) fn handle_dice_choice(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    if is_back {
        restart_generation(ad);
        return true;
    }
    if !BUTTON_X.contains(&x) { return false; }
    if NO_DICE_BUTTON_Y.contains(&y) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedTouchChoice));
    } else if ADD_DICE_BUTTON_Y.contains(&y) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedDiceCountChoice));
    } else {
        return false;
    }
    true
}

pub(super) fn handle_dice_count(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedDiceChoice));
        return true;
    }
    if !BUTTON_X.contains(&x) { return false; }
    let target = if DICE_25_BUTTON_Y.contains(&y) { 25 }
        else if DICE_50_BUTTON_Y.contains(&y) { 50 }
        else if DICE_100_BUTTON_Y.contains(&y) { 100 }
        else if DICE_200_BUTTON_Y.contains(&y) { 200 }
        else { return false; };
    if !ad.wallet.seeds.pending_seed_entropy_valid
        || !ad.wallet.seeds.dice_collector.configure_target(target)
    {
        restart_generation(ad);
        return true;
    }
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(DiceRoll));
    true
}

pub(super) fn handle_touch_choice(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    if is_back {
        restart_generation(ad);
        return true;
    }
    if !BUTTON_X.contains(&x) { return false; }
    if NO_TOUCH_BUTTON_Y.contains(&y) {
        if !super::finalize_staged_entropy(ad) {
            restart_generation(ad);
        }
    } else if ADD_TOUCH_BUTTON_Y.contains(&y) {
        if !ad.wallet.seeds.pending_seed_entropy_valid {
            restart_generation(ad);
        } else {
            ad.wallet.seeds.touch_collector.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(TouchEntropy));
        }
    } else {
        return false;
    }
    true
}

pub(crate) fn mix_dice_into_staged(ad: &mut AppData, dice: &mut mnemonic::DiceCollector) -> bool {
    if !ad.wallet.seeds.pending_seed_entropy_valid || !dice.is_complete() { return false; }
    let mixed = crate::services::entropy::mix_additive_dice(
        &mut ad.wallet.seeds.pending_seed_entropy,
        &dice.rolls[..dice.count],
    );
    dice.zeroize();
    if !mixed {
        ad.wallet.seeds.clear_pending_seed_entropy();
        return false;
    }
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedTouchChoice));
    true
}

fn restart_generation(ad: &mut AppData) {
    ad.wallet.seeds.touch_collector.reset();
    ad.wallet.seeds.dice_collector.zeroize();
    ad.wallet.seeds.clear_pending_seed_entropy();
    let route = if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
        crate::runtime::navigation::route!(StorageSeedWordCountChoice { action: 0 })
    } else {
        crate::runtime::navigation::route!(ChooseWordCount { action: 0 })
    };
    crate::runtime::effects::route(ad, route);
}
