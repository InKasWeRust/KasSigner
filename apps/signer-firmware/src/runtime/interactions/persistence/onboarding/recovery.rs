//! Recovery-word acknowledgement stage.

use super::{
    ACK_BUTTON_X, ACK_BUTTON_Y, AppData, BootDisplay, DeviceStorageIntent, ErrorSound,
    TouchInput, cancel_seed_onboarding, show_rejection,
};

fn onboarding_mnemonic_ready(ad: &AppData) -> bool {
    ad.wallet.seeds.seed_loaded
        && ad.wallet.seeds.seed_mgr.active_slot()
            .and_then(|slot| slot.mnemonic_word_count())
            .is_some()
}

pub(super) fn handle_recovery_acknowledgement(
    input: TouchInput, ad: &mut AppData, display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    let intent = ad.storage.persistence.device_storage_intent;
    if input.is_back {
        ad.storage.persistence.recovery_words_acknowledged = false;
        if ad.wallet.seeds.has_pending_add_wallet() {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedBackup {
                word_idx: ad.wallet.seeds.word_count.saturating_sub(1),
            }));
            return Some(true);
        }
        let route = recovery_ack_back_route(ad, intent);
        crate::runtime::effects::route(ad, route);
        return Some(true);
    }
    if !ACK_BUTTON_X.contains(&input.x) || !ACK_BUTTON_Y.contains(&input.y) { return None; }

    if ad.wallet.seeds.has_pending_add_wallet() {
        let valid_staged = matches!(ad.wallet.seeds.word_count, 12 | 24)
            && crate::wallet::mnemonic::validate(
                &ad.wallet.seeds.mnemonic_indices,
                ad.wallet.seeds.word_count,
            );
        if !valid_staged {
            ad.wallet.seeds.clear_pending_add_wallet();
            show_rejection(display, delay, "Recovery words unavailable", 1700, ErrorSound::Silent);
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList));
            return Some(true);
        }
        ad.storage.persistence.recovery_words_acknowledged = true;
        ad.wallet.seeds.clear_pending_wallet_protection();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageProtectionChoice));
        return Some(true);
    }

    if intent.is_seed_onboarding() && !onboarding_mnemonic_ready(ad) {
        // A direct/corrupted state transition must never let an empty or
        // non-mnemonic wallet satisfy the recovery acknowledgement gate.
        ad.storage.persistence.recovery_words_acknowledged = false;
        show_rejection(display, delay, "Set up recovery words first", 1700, ErrorSound::Silent);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedSourceChoice));
        return Some(true);
    }

    ad.storage.persistence.recovery_words_acknowledged = true;
    complete_recovery_ack(ad, intent);
    Some(true)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_recovery_acknowledgement(
    input: TouchInput,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    handle_recovery_acknowledgement(input, ad, display, delay)
}

fn recovery_ack_back_route(ad: &mut AppData, intent: DeviceStorageIntent) -> crate::runtime::navigation::UiRoute {
    if intent.is_seed_onboarding() && ad.storage.persistence.onboarding_imported_mnemonic {
        cancel_seed_onboarding(ad);
        ad.storage.persistence.device_storage_intent = intent;
        ad.storage.persistence.onboarding_imported_mnemonic = true;
        return crate::runtime::navigation::route!(StorageSeedSourceChoice);
    }
    if intent.is_seed_onboarding() && onboarding_mnemonic_ready(ad) {
        return crate::runtime::navigation::route!(SeedBackup {
            word_idx: ad.wallet.seeds.word_count.saturating_sub(1),
        });
    }
    if intent == DeviceStorageIntent::EnableSd {
        ad.storage.persistence.device_storage_intent = DeviceStorageIntent::None;
        return crate::runtime::navigation::route!(AdvancedFeatures);
    }
    cancel_seed_onboarding(ad);
    crate::runtime::navigation::route!(StorageModeChoice)
}

fn complete_recovery_ack(ad: &mut AppData, intent: DeviceStorageIntent) {
    match intent {
        DeviceStorageIntent::StartFresh | DeviceStorageIntent::CreateInternal => {
            ad.storage.persistence.device_storage_intent = DeviceStorageIntent::StartFresh;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageFinalizeChoice));
        }
        DeviceStorageIntent::EnableSd => {
            ad.storage.persistence.device_storage_intent = DeviceStorageIntent::None;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedSdStorageWarning));
        }
        DeviceStorageIntent::None => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(StorageModeChoice),
            );
        }
    }
}

