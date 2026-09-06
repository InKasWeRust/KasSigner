//! Credential operation terminal-state and retry handling.

use super::task::credential_kind;

use crate::{
    hw::display::BootDisplay,
    runtime::data::{AppData, OperationKind},
    runtime::navigation::ContinuationRoute,
    services::persistent_wallet::{CredentialKind, PersistError, PersistentWallet},
};

pub(super) fn finish(
    ad: &mut AppData,
    operation: OperationKind,
    error: PersistError,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    persistence: &mut PersistentWallet<'_>,
) {
    finish_result(ad, operation, Err(error), display, delay, persistence);
}

pub(super) fn finish_result(
    ad: &mut AppData,
    operation: OperationKind,
    result: Result<(), PersistError>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    persistence: &mut PersistentWallet<'_>,
) {
    let Some((kind, unlock)) = credential_kind(operation) else { return; };
    if !crate::runtime::presentation::execution_done(ad, operation, result.is_ok()) { return; }
    if unlock {
        commit_unlock_result(ad, kind, operation, result, display, delay, persistence);
    } else {
        match result {
            Ok(()) => commit_save_success(ad, persistence, kind, operation, display, delay),
            Err(error) => commit_save_error(ad, kind, operation, error),
        }
    }
}
fn commit_save_success(
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    kind: CredentialKind,
    operation: OperationKind,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    if ad.wallet.seeds.has_pending_add_wallet() {
        let committed = crate::runtime::interactions::seed::commit_staged_add_wallet(
            ad, persistence, display, delay,
        );
        if committed {
            let _ = crate::runtime::presentation::credential_result_committed(
                ad, operation, "success wallet-create",
            );
            crate::runtime::presentation::finish_success(ad);
        } else if crate::runtime::presentation::credential_result_committed(
            ad, operation, "wallet-create-failed",
        ) {
            crate::runtime::presentation::clear_operation(ad);
        }
        return;
    }
    if let Some(slot) = ad.runtime.pending_wallet_protection_update() {
        if !ad.wallet.seeds.pending_wallet_activation_ready() {
            commit_save_error(ad, kind, operation, PersistError::InvalidWallet);
            return;
        }
        let protection = ad.wallet.seeds.pending_wallet_protection;
        let salt = ad.wallet.seeds.pending_wallet_activation_salt;
        let verifier = ad.wallet.seeds.pending_wallet_activation_verifier;
        let active = usize::from(ad.wallet.seeds.seed_mgr.active);
        if active != slot
            || protection == crate::wallet::seed_manager::WalletProtection::DeviceOnly
            || !ad.wallet.seeds.seed_mgr.set_slot_protection(slot, protection)
        {
            commit_save_error(ad, kind, operation, PersistError::InvalidWallet);
            return;
        }
        if let Err(error) =
            persistence.stage_wallet_activation_record(slot, protection, salt, verifier)
        {
            let _ = ad.wallet.seeds.seed_mgr.set_slot_protection(
                slot,
                crate::wallet::seed_manager::WalletProtection::DeviceOnly,
            );
            let _ = persistence.clear_wallet_activation_record(slot);
            commit_save_error(ad, kind, operation, error);
            return;
        }
        let _ = ad.runtime.take_pending_wallet_protection_update();
        ad.wallet.seeds.clear_pending_wallet_protection();
        shared_signer::bytes::zeroize_bytes(&mut ad.storage.persistence.confirmation_digest);
        ad.storage.persistence.confirmation_pending = false;
        ad.storage.persistence.kind = None;
        ad.wallet.seeds.pp_input.reset();
        persistence.refresh_security_mirror(ad);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WalletDetails));
        if crate::runtime::presentation::credential_result_committed(
            ad,
            operation,
            "success wallet-protection-update",
        ) {
            crate::runtime::presentation::finish_success(ad);
        }
        return;
    }
    persistence.refresh_security_mirror(ad);
    if crate::runtime::effects::complete_onboarding(ad) {
        if !crate::runtime::presentation::credential_result_committed(
            ad, operation, "success MainMenu",
        ) { return; }
        crate::runtime::presentation::finish_success(ad);
        return;
    }
    if crate::runtime::presentation::credential_result_committed(
        ad, operation, "navigation-recovery",
    ) {
        crate::runtime::presentation::clear_operation(ad);
    }
}

fn commit_save_error(
    ad: &mut AppData,
    kind: CredentialKind,
    operation: OperationKind,
    error: PersistError,
) {
    prepare_save_retry(ad, kind);
    crate::log!("Persistent wallet save failed: {:?}", error);
    if crate::runtime::presentation::credential_result_committed(
        ad, operation, "recoverable-error",
    ) {
        crate::runtime::presentation::fail_recoverable(ad, error.message(), persist_code(error), 0);
    }
}

fn commit_unlock_result(
    ad: &mut AppData,
    kind: CredentialKind,
    operation: OperationKind,
    result: Result<(), PersistError>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    persistence: &mut PersistentWallet<'_>,
) {
    match result {
        Ok(()) => commit_unlock_success(ad, operation, persistence),
        Err(PersistError::DuressTriggered) => {
            display.draw_recoverable_error_screen(
                "Incorrect credential or damaged wallet", "AUTH-01", false,
            );
            let _ = crate::runtime::presentation::credential_result_committed(
                ad, operation, "duress-reset",
            );
            crate::services::timing::pause(delay, 1800);
            esp_hal::system::software_reset();
        }
        Err(PersistError::DeviceWipeFailed) => {
            if crate::runtime::presentation::credential_result_committed(
                ad, operation, "fatal-error",
            ) {
                crate::runtime::presentation::fail_fatal(ad, "Secure device wipe failed", "SEC-WIPE-01");
            }
        }
        Err(error) => commit_unlock_error(ad, kind, operation, error),
    }
}

fn commit_unlock_success(
    ad: &mut AppData,
    operation: OperationKind,
    persistence: &mut PersistentWallet<'_>,
) {
    persistence.refresh_security_mirror(ad);
    if let Err(error) = persistence.load_display_preferences(ad) {
        crate::log!("   SETTINGS preference reload after unlock failed: {:?}", error);
    }
    if commit_pending_wallet_activation(ad, operation, persistence) {
        return;
    }
    if let Some(return_to) = ad.runtime.take_pin_reauth_return() {
        if commit_reauth_success(ad, operation, return_to) {
            return;
        }
    } else if commit_default_unlock_route(ad, operation) {
        return;
    }
    if crate::runtime::presentation::credential_result_committed(
        ad, operation, "navigation-recovery",
    ) {
        crate::runtime::presentation::clear_operation(ad);
    }
}

fn commit_pending_wallet_activation(
    ad: &mut AppData,
    operation: OperationKind,
    persistence: &mut PersistentWallet<'_>,
) -> bool {
    let Some(slot) = ad.runtime.take_pending_wallet_activation() else { return false; };
    reset_unlock_feedback(ad);
    if let Err(error) = crate::services::wallet_session::activate_slot(ad, slot) {
        crate::log!("   authenticated wallet activation failed: {:?}", error);
        return false;
    }
    persistence.refresh_security_mirror(ad);
    let startup_activation = !ad.runtime.home_reached;
    let route = if startup_activation {
        crate::runtime::navigation::route!(MainMenu)
    } else {
        crate::runtime::navigation::route!(SeedsMenu)
    };
    let marker = if startup_activation {
        "success startup-wallet-home"
    } else {
        "success wallet-switch"
    };
    let _ = crate::runtime::effects::route(ad, route);
    if crate::runtime::presentation::credential_result_committed(ad, operation, marker) {
        crate::runtime::presentation::finish_success(ad);
    }
    true
}

fn commit_reauth_success(
    ad: &mut AppData,
    operation: OperationKind,
    return_to: ContinuationRoute,
) -> bool {
    reset_unlock_feedback(ad);
    if !crate::runtime::effects::authenticated_resume(ad, return_to) {
        return false;
    }
    if !crate::runtime::presentation::credential_result_committed(
        ad, operation, "success dim-reauth",
    ) {
        return true;
    }
    crate::runtime::presentation::finish_success(ad);
    true
}

fn commit_default_unlock_route(ad: &mut AppData, operation: OperationKind) -> bool {
    ad.storage.persistence.reset();
    let requires_wallet = crate::services::wallet_session::require_startup_wallet_selection(ad);
    let route = if requires_wallet {
        crate::runtime::navigation::route!(SeedList)
    } else {
        crate::runtime::navigation::route!(MainMenu)
    };
    if !crate::runtime::effects::route(ad, route) {
        return false;
    }
    let marker = if requires_wallet { "success SeedList" } else { "success MainMenu" };
    if crate::runtime::presentation::credential_result_committed(ad, operation, marker) {
        crate::runtime::presentation::finish_success(ad);
    }
    true
}

fn reset_unlock_feedback(ad: &mut AppData) {
    ad.storage.persistence.unlock_feedback = crate::runtime::data::UnlockFeedback::None;
    ad.storage.persistence.unlock_failures = 0;
    ad.storage.persistence.unlock_retry_after_ms = 0;
}

fn commit_unlock_error(
    ad: &mut AppData,
    kind: CredentialKind,
    operation: OperationKind,
    error: PersistError,
) {
    let retry_ms = record_unlock_failure(ad);
    if is_credential_rejection(error) {
        crate::log!("Persistent wallet unlock failed: Authentication");
        commit_authentication_retry(ad, kind, operation, retry_ms);
        return;
    }
    crate::log!("Persistent wallet unlock failed: {:?}", error);

    let result = match kind {
        CredentialKind::Pin => "recoverable-error pin",
        CredentialKind::Password => "recoverable-error password",
    };
    if crate::runtime::presentation::credential_result_committed(ad, operation, result) {
        crate::runtime::presentation::fail_recoverable(
            ad, error.message(), persist_code(error), retry_ms,
        );
    }
}

fn commit_authentication_retry(
    ad: &mut AppData,
    kind: CredentialKind,
    operation: OperationKind,
    retry_ms: u32,
) {
    ad.wallet.seeds.pp_input.reset();
    ad.storage.persistence.unlock_feedback = match kind {
        CredentialKind::Pin => crate::runtime::data::UnlockFeedback::WrongPin,
        CredentialKind::Password => crate::runtime::data::UnlockFeedback::WrongPassword,
    };
    ad.storage.persistence.unlock_retry_after_ms = now_millis().saturating_add(u64::from(retry_ms));
    let result = match kind {
        CredentialKind::Pin => "invalid-pin retry",
        CredentialKind::Password => "invalid-password retry",
    };
    let _ = crate::runtime::presentation::credential_result_committed(ad, operation, result);
    crate::runtime::presentation::clear_operation(ad);
    crate::runtime::effects::redraw(ad);
    crate::services::audio::error();
    crate::log!("KASSIGNER_PIN_FLOW: AUTH RETRY {:?} delay={}ms", kind, retry_ms);
}

const fn is_credential_rejection(error: PersistError) -> bool {
    matches!(
        error,
        PersistError::Authentication
            | PersistError::CredentialRequired
            | PersistError::PinTooShort
            | PersistError::PinTooLong
            | PersistError::PinNotNumeric
            | PersistError::PasswordTooShort
            | PersistError::PasswordTooLong
            | PersistError::PasswordNeedsLetter
            | PersistError::PasswordNeedsDigit
    )
}

fn prepare_save_retry(ad: &mut AppData, kind: CredentialKind) {
    shared_signer::bytes::zeroize_bytes(&mut ad.storage.persistence.confirmation_digest);
    ad.storage.persistence.confirmation_pending = false;
    ad.storage.persistence.kind = Some(kind);
}

fn record_unlock_failure(ad: &mut AppData) -> u32 {
    ad.storage.persistence.unlock_failures = ad.storage.persistence.unlock_failures.saturating_add(1);
    crate::services::credential_policy::retry_delay_millis(ad.storage.persistence.unlock_failures)
}

fn now_millis() -> u64 {
    esp_hal::time::Instant::now().duration_since_epoch().as_millis()
}

const fn persist_code(error: PersistError) -> &'static str {
    match error {
        PersistError::Authentication => "AUTH-01",
        PersistError::Flash | PersistError::SdStorageWrite => "STORE-IO-01",
        PersistError::DeviceKeyMissing => "STORE-KEY-01",
        PersistError::Entropy => "ENTROPY-01",
        PersistError::Crypto => "CRYPTO-01",
        PersistError::InvalidWallet | PersistError::SdStorageCorrupt => "STORE-DATA-01",
        PersistError::PolicyIntegrity | PersistError::InvalidSecurityPolicy => "POLICY-01",
        PersistError::SdStorageUnavailable => "STORE-SD-01",
        _ => "STORE-01",
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_backoff_probe(ad: &mut AppData) -> bool {
    let saved = ad.storage.persistence.unlock_failures;
    ad.storage.persistence.unlock_failures = 0;
    let first = record_unlock_failure(ad);
    let second = record_unlock_failure(ad);
    ad.storage.persistence.unlock_failures = saved;
    second > first
}
