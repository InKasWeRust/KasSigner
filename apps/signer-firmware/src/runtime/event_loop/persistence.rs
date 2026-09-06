//! Persist wallet and irreversible signing-policy state after each iteration.

use crate::runtime::input::AppState;

pub(crate) const fn sync_deferred_for_state(state: AppState) -> bool {
    if matches!(state, AppState::StorageUnlockPin | AppState::StorageUnlockPassword) {
        return true;
    }
    #[cfg(feature = "provisioning-ui")]
    if matches!(state, AppState::PopItPrompt | AppState::PopItExplain | AppState::PopItConfirm) {
        return true;
    }
    false
}

#[cfg(not(feature = "workflow-test-auto"))]
macro_rules! sync {
    ($ad:ident, $persistent_wallet:ident, $boot_display:ident, $delay:ident, $i2c:ident) => {
        if $ad.storage.persistence.pending_rtc_floor_unix != 0 {
            let floor = $ad.storage.persistence.pending_rtc_floor_unix;
            if let Err(error) = $persistent_wallet.record_rtc_floor(
                floor,
                &$ad.wallet.seeds.seed_mgr,
                &mut $i2c,
                &mut $delay,
            ) {
                log!("Advanced signing policy floor save failed: {:?}", error);
                let initial_counts = $ad.signing.anti_klepto.initial_sig_counts;
                $crate::runtime::signing::rollback_added_signatures($ad, &initial_counts);
                $ad.storage.persistence.pending_rtc_floor_unix = 0;
                $ad.qr.outgoing.length = 0;
                $ad.signing.anti_klepto.reset();
                $crate::runtime::presentation::show_error_spec(
                    $ad, $crate::runtime::presentation::POLICY_SAVE,
                );
                continue;
            }
            $ad.storage.persistence.pending_rtc_floor_unix = 0;
            $persistent_wallet.refresh_security_mirror($ad);
        }

        if !$crate::runtime::event_loop::persistence::sync_deferred_for_state($ad.navigation.app.state) {
            match $persistent_wallet.sync_if_needed(
                &$ad.wallet.seeds.seed_mgr, &mut $i2c, &mut $delay,
            ) {
                Ok(true) => log!("Encrypted wallet state saved"),
                Ok(false) => {}
                Err(error) => {
                    log!("Encrypted wallet save failed: {:?}", error);
                    if $persistent_wallet.is_sd_mode() {
                        $crate::services::device_wipe::zeroize_volatile($ad);
                        $crate::runtime::effects::route($ad, $crate::runtime::navigation::route!(StorageSdFailure));
                    } else {
                        $persistent_wallet.require_choice(&$ad.wallet.seeds.seed_mgr);
                        $crate::runtime::interactions::persistence::enter_storage_choice($ad);
                    }
                    $crate::runtime::presentation::show_error_spec(
                        $ad, $crate::runtime::presentation::STORAGE_SYNC,
                    );
                }
            }
        }
    };
}

#[cfg(not(feature = "workflow-test-auto"))]
pub(crate) use sync;
