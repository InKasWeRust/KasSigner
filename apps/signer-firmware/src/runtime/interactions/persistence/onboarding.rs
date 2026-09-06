//! Wallet onboarding and terminal storage-policy selection.

use crate::{
    hw::display::BootDisplay,
    runtime::{data::{AppData, DeviceStorageIntent}, input::AppState},
    services::persistent_wallet::PersistentWallet,
    ui::screens::device::persistence::{
        ACK_BUTTON_X, ACK_BUTTON_Y, BUTTON_X, FRESH_BUTTON_Y, RESTORE_ROW_Y, SAVE_BUTTON_Y,
        PROTECT_BUTTON_Y, NO_PROTECT_BUTTON_Y,
    },
};
use super::super::{TouchInput, feedback::{ErrorSound, show_rejection}};

mod finalize;
mod recovery;

use finalize::{handle_finalize_choice, handle_protection_choice};
use recovery::handle_recovery_acknowledgement;
#[cfg(feature = "workflow-test-auto")]
pub(crate) use finalize::{workflow_handle_finalize_choice, workflow_handle_protection_choice};
#[cfg(feature = "workflow-test-auto")]
pub(crate) use recovery::workflow_handle_recovery_acknowledgement;

pub(super) fn handle(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::StorageModeChoice => handle_mode_choice(input, ad, persistence, display, delay),
        AppState::StorageSeedSourceChoice => handle_seed_source_choice(input, ad),
        AppState::AdvancedRestoreMenu => handle_advanced_restore(input, ad),
        AppState::RestoreWord12Detected => handle_restore_12_detected(input, ad),
        AppState::StorageRecoveryAcknowledgement => handle_recovery_acknowledgement(input, ad, display, delay),
        AppState::StorageFinalizeChoice => handle_finalize_choice(input, ad, persistence, display, delay),
        AppState::StorageProtectionChoice => handle_protection_choice(input, ad, persistence, display, delay),
        AppState::StorageSdFailure => Some(false),
        _ => None,
    }
}

fn begin_empty_wallet_setup(
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
) -> Result<(), &'static str> {
    persistence.select_fresh(&ad.wallet.seeds.seed_mgr).map_err(|error| error.message())?;
    ad.storage.persistence.device_storage_intent = DeviceStorageIntent::StartFresh;
    ad.storage.persistence.recovery_words_acknowledged = false;
    Ok(())
}

fn handle_mode_choice(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    if !BUTTON_X.contains(&input.x) { return None; }
    let create = FRESH_BUTTON_Y.contains(&input.y);
    let restore = SAVE_BUTTON_Y.contains(&input.y);
    if !create && !restore { return None; }
    if let Err(message) = begin_empty_wallet_setup(ad, persistence) {
        show_rejection(display, delay, message, 1500, ErrorSound::Beep);
        return Some(true);
    }
    apply_mode_choice(ad, create);
    Some(true)
}

fn apply_mode_choice(ad: &mut AppData, create: bool) {
    reset_pending_recovery(ad);
    if create {
        ad.storage.persistence.onboarding_imported_mnemonic = false;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WalletNameEntry { purpose: 0 }));
    } else {
        ad.storage.persistence.onboarding_imported_mnemonic = true;
        ad.navigation.production.restore_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedSourceChoice));
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_mode_choice(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if !BUTTON_X.contains(&input.x) { return None; }
    let create = FRESH_BUTTON_Y.contains(&input.y);
    let restore = SAVE_BUTTON_Y.contains(&input.y);
    if !create && !restore { return None; }

    // The connected workflow image intentionally owns no persistent FLASH/HMAC.
    // Reproduce only the volatile post-select_fresh state here; persistent erase,
    // mode journal writes, and device-key checks remain dedicated persistence HIL.
    ad.wallet.seeds.seed_mgr.zeroize_all();
    crate::services::wallet_session::clear_active_wallet(ad);
    ad.storage.persistence.device_storage_intent = DeviceStorageIntent::StartFresh;
    apply_mode_choice(ad, create);
    Some(true)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_seed_source_choice(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    handle_seed_source_choice(input, ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_advanced_restore(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    handle_advanced_restore(input, ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_restore_12_detected(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    handle_restore_12_detected(input, ad)
}

fn reset_pending_recovery(ad: &mut AppData) {
    shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
    ad.wallet.seeds.clear_pending_seed_entropy();
    ad.wallet.seeds.clear_pending_wallet_name();
    ad.wallet.seeds.dice_collector.zeroize();
    ad.wallet.seeds.word_count = 0;
    ad.wallet.seeds.pp_input.reset();
    ad.wallet.seeds.word_input.reset();
    ad.storage.persistence.recovery_words_acknowledged = false;
}

fn menu_row(y: u16) -> Option<usize> {
    RESTORE_ROW_Y.iter().position(|range| range.contains(&y))
}

fn handle_seed_source_choice(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input.is_back {
        if ad.wallet.seeds.pending_add_wallet_is_restore() {
            reset_pending_recovery(ad);
            ad.wallet.seeds.clear_pending_add_wallet();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AddWalletChoice));
        } else {
            cancel_seed_onboarding(ad);
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageModeChoice));
        }
        return Some(true);
    }
    if !(44..=276).contains(&input.x) { return None; }
    let item = menu_row(input.y)?;
    reset_pending_recovery(ad);
    if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
        ad.storage.persistence.onboarding_imported_mnemonic = true;
    }
    match item {
        0 => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(RestoreWord { word_idx: 0 }),
            );
        }
        1 => {
            
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ScanQR));
        },
        2 => {
            
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdWalletBackupFileList));
        },
        3 => {
            ad.navigation.production.advanced_restore_menu.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedRestoreMenu));
        }
        _ => return None,
    }
    Some(true)
}

fn handle_advanced_restore(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input.is_back {
        ad.navigation.production.restore_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedSourceChoice));
        return Some(true);
    }
    if !(44..=276).contains(&input.x) { return None; }
    let item = menu_row(input.y)?;
    match item {
        0 | 1 => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ScanQR));
        }
        2 => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(StegoImportPick),
            );
        }
        3 => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(ImportPrivKey),
            );
        }
        _ => return None,
    }
    Some(true)
}

fn handle_restore_12_detected(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input.is_back {
        ad.wallet.seeds.word_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(RestoreWord { word_idx: 11 }));
        return Some(true);
    }
    if !BUTTON_X.contains(&input.x) { return None; }
    if (76..=111).contains(&input.y) {
        ad.wallet.seeds.word_count = 12;
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
        return Some(true);
    }
    if (130..=165).contains(&input.y) {
        ad.wallet.seeds.word_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(RestoreWord { word_idx: 12 }));
        return Some(true);
    }
    None
}

pub(super) fn cancel_seed_onboarding(ad: &mut AppData) {
    ad.wallet.seeds.seed_mgr.zeroize_all();
    crate::services::wallet_session::clear_active_wallet(ad);
    shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
    ad.wallet.seeds.clear_pending_seed_entropy();
    ad.wallet.seeds.clear_pending_wallet_name();
    ad.wallet.seeds.dice_collector.zeroize();
    ad.wallet.seeds.word_count = 0;
    ad.wallet.seeds.pp_input.reset();
    ad.wallet.seeds.word_input.reset();
    ad.storage.persistence.device_storage_intent = DeviceStorageIntent::None;
    ad.storage.persistence.recovery_words_acknowledged = false;
    ad.storage.persistence.onboarding_imported_mnemonic = false;
}
