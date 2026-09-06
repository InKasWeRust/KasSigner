//! Wallet persistence controller facade.

use crate::{
    hw::display::BootDisplay,
    runtime::data::AppData,
    services::persistent_wallet::{CredentialKind, PersistentWallet, StartupDisposition},
};
use super::TouchInput;

mod credential;
mod onboarding;


#[inline(never)]
pub(crate) fn apply_startup_navigation(ad: &mut AppData, disposition: StartupDisposition) {
    match disposition {
        StartupDisposition::ChoiceRequired => enter_storage_choice(ad),
        StartupDisposition::Ready => {
            if crate::services::wallet_session::require_startup_wallet_selection(ad) {
                enter_required_wallet_selection(ad);
            } else {
                let _ = crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MainMenu));
            }
        },
        StartupDisposition::UnlockRequired(kind) => enter_storage_unlock(ad, kind),
        StartupDisposition::SdFailure => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSdFailure));
        }
    }
}


/// Enter the mandatory WALLETS resolver through policy-valid Seeds ownership.
/// This avoids a forbidden Main -> SeedList jump at boot while leaving no
/// intermediate screen visible to the user. Back/Home remain suppressed until
/// an active wallet exists.
pub(crate) fn enter_required_wallet_selection(ad: &mut AppData) {
    ad.wallet.seeds.seed_list_scroll = 0;
    let entered_seeds = crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu));
    if entered_seeds {
        let _ = crate::runtime::effects::replace(ad, crate::runtime::navigation::route!(SeedList));
    }
}

pub(crate) fn enter_storage_choice(ad: &mut AppData) {
    ad.wallet.seeds.pp_input.reset();
    ad.storage.persistence.device_storage_intent = crate::runtime::data::DeviceStorageIntent::None;
    ad.storage.persistence.recovery_words_acknowledged = false;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageModeChoice));
}

pub(crate) fn enter_seed_source_choice(
    ad: &mut AppData,
    intent: crate::runtime::data::DeviceStorageIntent,
) {
    ad.wallet.seeds.seed_mgr.zeroize_all();
    crate::services::wallet_session::clear_active_wallet(ad);
    shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
    ad.wallet.seeds.clear_pending_seed_entropy();
    ad.wallet.seeds.dice_collector.zeroize();
    ad.wallet.seeds.word_count = 0;
    ad.wallet.seeds.pp_input.reset();
    ad.wallet.seeds.word_input.reset();
    ad.storage.persistence.device_storage_intent = intent;
    ad.storage.persistence.recovery_words_acknowledged = false;
    ad.storage.persistence.onboarding_imported_mnemonic = false;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedSourceChoice));
}

pub(crate) fn retry_seed_source_choice(ad: &mut AppData) {
    let intent = ad.storage.persistence.device_storage_intent;
    enter_seed_source_choice(ad, intent);
}

pub(crate) fn complete_start_fresh(ad: &mut AppData) {
    let _ = crate::runtime::effects::complete_onboarding(ad);
}

pub(crate) fn enter_credential_type_choice(ad: &mut AppData) {
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageCredentialType));
}

pub(crate) fn enter_storage_unlock(ad: &mut AppData, kind: CredentialKind) {
    ad.wallet.seeds.pp_input.reset();
    match kind {
        CredentialKind::Pin => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageUnlockPin));
        }
        CredentialKind::Password => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageUnlockPassword));
        }
    };
}

pub(crate) fn cancel_seed_onboarding(ad: &mut AppData) {
    onboarding::cancel_seed_onboarding(ad);
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_mode_choice(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    onboarding::workflow_handle_mode_choice(input, ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_seed_source_choice(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    onboarding::workflow_handle_seed_source_choice(input, ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_advanced_restore(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    onboarding::workflow_handle_advanced_restore(input, ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_restore_12_detected(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    onboarding::workflow_handle_restore_12_detected(input, ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_recovery_acknowledgement(
    input: TouchInput,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    onboarding::workflow_handle_recovery_acknowledgement(input, ad, display, delay)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_finalize_choice(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    onboarding::workflow_handle_finalize_choice(input, ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_protection_choice(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    onboarding::workflow_handle_protection_choice(input, ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_credential_type(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    credential::workflow_handle_credential_type(input, ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_setup_back(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    credential::workflow_handle_setup_back(input, ad)
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
pub(crate) fn workflow_handle_unlock_touch(
    input: TouchInput,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
) -> Option<bool> {
    credential::workflow_handle_unlock_touch(input, ad, display)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_unlock_back_guard(state: crate::runtime::input::AppState) -> bool {
    credential::workflow_unlock_back_guard(state)
}


#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_unlock_backoff_probe(ad: &mut AppData) -> bool {
    crate::runtime::event_loop::operation_engine::workflow_backoff_probe(ad)
}

pub(crate) fn handle(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    if let Some(result) = onboarding::handle(input, ad, persistence, display, delay) {
        return Some(result);
    }
    credential::handle(input, ad, display)
}
