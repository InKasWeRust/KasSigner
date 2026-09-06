//! Final persistence/protection choice stage.

use super::{
    cancel_seed_onboarding, AppData, BootDisplay, BUTTON_X, DeviceStorageIntent, ErrorSound,
    FRESH_BUTTON_Y, NO_PROTECT_BUTTON_Y, PROTECT_BUTTON_Y, PersistentWallet, SAVE_BUTTON_Y,
    TouchInput, show_rejection,
};

pub(super) fn handle_finalize_choice(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    if input.is_back {
        let route = finalize_back_route(ad);
        crate::runtime::effects::route(ad, route);
        return Some(true);
    }
    if !BUTTON_X.contains(&input.x) { return None; }
    if FRESH_BUTTON_Y.contains(&input.y) {
        if !persistence.device_key_available() {
            show_rejection(display, delay, "Device key not provisioned", 1800, ErrorSound::Silent);
            return Some(true);
        }
        if staged_onboarding_mnemonic(ad)
            && !crate::runtime::interactions::seed::commit_staged_onboarding_import(ad, display, delay)
        {
            return Some(true);
        }
        enter_secure_storage_credential_setup(ad);
        return Some(true);
    }
    if SAVE_BUTTON_Y.contains(&input.y) {
        if ad.wallet.seeds.pending_add_wallet_is_restore() {
            let _ = crate::runtime::interactions::seed::commit_staged_session_wallet(
                ad, display, delay,
            );
        } else {
            if staged_onboarding_mnemonic(ad)
                && !crate::runtime::interactions::seed::commit_staged_onboarding_import(ad, display, delay)
            {
                return Some(true);
            }
            complete_session_only(ad, persistence);
        }
        return Some(true);
    }
    None
}


fn staged_onboarding_mnemonic(ad: &AppData) -> bool {
    !ad.wallet.seeds.has_pending_add_wallet()
        && ad.storage.persistence.device_storage_intent.is_seed_onboarding()
        && ad.storage.persistence.onboarding_imported_mnemonic
        && matches!(ad.wallet.seeds.word_count, 12 | 24)
}

fn finalize_back_route(ad: &mut AppData) -> crate::runtime::navigation::UiRoute {
    if ad.storage.persistence.device_storage_intent.is_seed_onboarding()
        && ad.wallet.seeds.active_source == crate::wallet::seed_manager::WalletSource::RawPrivateKey
    {
        let intent = ad.storage.persistence.device_storage_intent;
        cancel_seed_onboarding(ad);
        ad.storage.persistence.device_storage_intent = intent;
        ad.storage.persistence.onboarding_imported_mnemonic = true;
        ad.navigation.production.advanced_restore_menu.reset();
        return crate::runtime::navigation::route!(AdvancedRestoreMenu);
    }
    if ad.wallet.seeds.pending_add_wallet_is_restore() || staged_onboarding_mnemonic(ad) {
        return crate::runtime::navigation::route!(WalletNameEntry { purpose: 3 });
    }
    crate::runtime::navigation::route!(StorageRecoveryAcknowledgement)
}

fn enter_secure_storage_credential_setup(ad: &mut AppData) {
    ad.storage.persistence.device_storage_intent = DeviceStorageIntent::CreateInternal;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageProtectionChoice));
}

pub(super) fn handle_protection_choice(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    if input.is_back {
        let route = if ad.wallet.seeds.has_pending_add_wallet() {
            if ad.wallet.seeds.pending_add_wallet_is_restore() {
                crate::runtime::navigation::route!(StorageFinalizeChoice)
            } else {
                crate::runtime::navigation::route!(StorageRecoveryAcknowledgement)
            }
        } else {
            crate::runtime::navigation::route!(StorageFinalizeChoice)
        };
        crate::runtime::effects::route(ad, route);
        return Some(true);
    }
    if !BUTTON_X.contains(&input.x) { return None; }
    if PROTECT_BUTTON_Y.contains(&input.y) {
        super::super::enter_credential_type_choice(ad);
        return Some(true);
    }
    if NO_PROTECT_BUTTON_Y.contains(&input.y) {
        if ad.wallet.seeds.has_pending_add_wallet() {
            ad.wallet.seeds.pending_wallet_protection = crate::wallet::seed_manager::WalletProtection::DeviceOnly;
            ad.wallet.seeds.mark_pending_wallet_activation_ready();
            let _ = crate::runtime::interactions::seed::commit_staged_add_wallet(
                ad, persistence, display, delay,
            );
            return Some(true);
        }
        let acknowledged = ad.storage.persistence.recovery_words_acknowledged;
        let mut progress = |_percent: u8| {};
        match persistence.save_device_only(&ad.wallet.seeds.seed_mgr, acknowledged, &mut progress) {
            Ok(()) => {
                persistence.refresh_security_mirror(ad);
                ad.storage.persistence.device_storage_intent = DeviceStorageIntent::CreateInternal;
                super::super::complete_start_fresh(ad);
            }
            Err(error) => show_rejection(display, delay, error.message(), 1800, ErrorSound::Silent),
        }
        return Some(true);
    }
    None
}

fn complete_session_only(
    ad: &mut AppData,
    persistence: &PersistentWallet<'_>,
) {
    ad.storage.persistence.device_storage_intent = DeviceStorageIntent::StartFresh;
    // One-time wallets must not expose or inherit any device-persistent
    // preference controls from a previously saved wallet. Keep ordinary
    // brightness/volume session controls, but force every persistent option
    // back to volatile defaults and refresh the security availability mirror.
    ad.settings.use_session_only_defaults();
    persistence.refresh_security_mirror(ad);
    super::super::complete_start_fresh(ad);
}

#[cfg(feature = "workflow-test-auto")]
fn complete_workflow_session_only(ad: &mut AppData) {
    ad.storage.persistence.device_storage_intent = DeviceStorageIntent::StartFresh;
    ad.settings.use_session_only_defaults();
    ad.storage.persistence.advanced.saved_wallet = false;
    ad.storage.persistence.advanced.outer_device_only = false;
    ad.storage.persistence.advanced.availability =
        crate::runtime::data::AdvancedAvailability::Unavailable;
    ad.storage.persistence.advanced.credential_kind = None;
    super::super::complete_start_fresh(ad);
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_protection_choice(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input.is_back {
        let route = if ad.wallet.seeds.has_pending_add_wallet() {
            if ad.wallet.seeds.pending_add_wallet_is_restore() {
                crate::runtime::navigation::route!(StorageFinalizeChoice)
            } else {
                crate::runtime::navigation::route!(StorageRecoveryAcknowledgement)
            }
        } else {
            crate::runtime::navigation::route!(StorageFinalizeChoice)
        };
        crate::runtime::effects::route(ad, route);
        return Some(true);
    }
    if !BUTTON_X.contains(&input.x) { return None; }
    if PROTECT_BUTTON_Y.contains(&input.y) {
        // This is the exact production protected-wallet navigation edge.  The
        // alternative device-only branch performs persistent FLASH/HMAC work
        // and remains owned by persistence HIL.
        super::super::enter_credential_type_choice(ad);
        return Some(true);
    }
    None
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_finalize_choice(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input.is_back {
        let route = finalize_back_route(ad);
        crate::runtime::effects::route(ad, route);
        return Some(true);
    }
    if !BUTTON_X.contains(&input.x) { return None; }
    if FRESH_BUTTON_Y.contains(&input.y) {
        // Device-key availability is intentionally a persistence/HIL concern.
        // Exercise the exact post-preflight production transition only.
        if staged_onboarding_mnemonic(ad)
            && !crate::runtime::interactions::seed::workflow_commit_staged_onboarding_import(ad)
        {
            return Some(true);
        }
        enter_secure_storage_credential_setup(ad);
        return Some(true);
    }
    if SAVE_BUTTON_Y.contains(&input.y) {
        if ad.wallet.seeds.pending_add_wallet_is_restore() {
            ad.wallet.seeds.clear_pending_add_wallet();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList));
        } else {
            if staged_onboarding_mnemonic(ad)
                && !crate::runtime::interactions::seed::workflow_commit_staged_onboarding_import(ad)
            {
                return Some(true);
            }
            complete_workflow_session_only(ad);
        }
        return Some(true);
    }
    None
}
