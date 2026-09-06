//! Credential creation and authenticated wallet unlock.

use crate::{
    hw::display::BootDisplay,
    runtime::{data::{AppData, DeviceStorageIntent}, input::AppState},
    services::persistent_wallet::CredentialKind,
    ui::{
        keyboard::{KeyAction, KeyboardMode, hit_test},
        screens::device::persistence::{BUTTON_X, PASSWORD_BUTTON_Y, PIN_BUTTON_Y, PinPadAction, pin_pad_action},
    },
};
use crate::services::credential_policy::{confirmation_digest, confirmation_matches, validate};
use super::super::TouchInput;

pub(super) fn handle(
    input: TouchInput,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::StorageCredentialType => handle_credential_type(input, ad),
        AppState::StoragePinEntry => handle_setup_entry(input, ad, CredentialKind::Pin, false, display),
        AppState::StoragePinConfirm => handle_setup_entry(input, ad, CredentialKind::Pin, true, display),
        AppState::StoragePasswordEntry => handle_setup_entry(input, ad, CredentialKind::Password, false, display),
        AppState::StoragePasswordConfirm => handle_setup_entry(input, ad, CredentialKind::Password, true, display),
        AppState::StorageUnlockPin => handle_unlock(input, ad, CredentialKind::Pin, display),
        AppState::StorageUnlockPassword => handle_unlock(input, ad, CredentialKind::Password, display),
        _ => None,
    }
}

fn handle_credential_type(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input.is_back {
        if ad.runtime.pending_wallet_protection_update().is_some() {
            ad.runtime.cancel_pending_wallet_protection_update();
            ad.wallet.seeds.clear_pending_wallet_protection();
            ad.wallet.seeds.pp_input.reset();
            shared_signer::bytes::zeroize_bytes(&mut ad.storage.persistence.confirmation_digest);
            ad.storage.persistence.confirmation_pending = false;
            ad.storage.persistence.kind = None;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WalletDetails));
            return Some(true);
        }
        let intent = ad.storage.persistence.device_storage_intent;
        let recovery_ack = ad.storage.persistence.recovery_words_acknowledged;
        ad.storage.persistence.reset();
        ad.storage.persistence.device_storage_intent = intent;
        ad.storage.persistence.recovery_words_acknowledged = recovery_ack;
        let route = if ad.wallet.seeds.has_pending_add_wallet() || intent == DeviceStorageIntent::CreateInternal {
            crate::runtime::navigation::route!(StorageProtectionChoice)
        } else {
            crate::runtime::navigation::route!(StorageModeChoice)
        };
        crate::runtime::effects::route(ad, route);
        return Some(true);
    }
    if !BUTTON_X.contains(&input.x) { return None; }
    let kind = if PIN_BUTTON_Y.contains(&input.y) {
        CredentialKind::Pin
    } else if PASSWORD_BUTTON_Y.contains(&input.y) {
        CredentialKind::Password
    } else {
        return None;
    };
    let recovery_ack = ad.storage.persistence.recovery_words_acknowledged;
    let intent = ad.storage.persistence.device_storage_intent;
    ad.storage.persistence.reset();
    ad.storage.persistence.device_storage_intent = intent;
    ad.storage.persistence.recovery_words_acknowledged = recovery_ack;
    ad.storage.persistence.kind = Some(kind);
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, entry_route(kind));
    Some(true)
}
#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_credential_type(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    handle_credential_type(input, ad)
}

fn handle_setup_entry(
    input: TouchInput,
    ad: &mut AppData,
    kind: CredentialKind,
    confirming: bool,
    display: &mut BootDisplay<'_>,
) -> Option<bool> {
    if input.is_back {
        return setup_back(ad, kind, confirming);
    }

    match edit_secret(input, ad, kind, display) {
        // Credential screens own every tap. A miss is a consumed no-op and must
        // never fall through into broader navigation/effect routers.
        SecretAction::None => Some(false),
        SecretAction::Edited => Some(false),
        SecretAction::Submitted => {
            let secret = &ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len];
            if let Err(error) = validate(kind, secret) {
                let persist_error = crate::services::persistent_wallet::PersistError::from(error);
                crate::runtime::presentation::show_recoverable_error(
                    ad, persist_error.message(), "CRED-VALID-01", 0,
                );
                return Some(true);
            }
            let digest = confirmation_digest(kind, secret);
            if !confirming {
                ad.storage.persistence.confirmation_digest = digest;
                ad.storage.persistence.confirmation_pending = true;
                ad.wallet.seeds.pp_input.reset();
                crate::runtime::effects::route(ad, confirm_state(kind));
                return Some(true);
            }
            if !ad.storage.persistence.confirmation_pending
                || !confirmation_matches(&ad.storage.persistence.confirmation_digest, &digest)
            {
                reset_confirmation_for_retry(ad, kind);
                crate::runtime::presentation::show_recoverable_error_to(
                    ad, entry_state(kind), "Credentials do not match", "CRED-MATCH-01", 0,
                );
                return Some(true);
            }
            // Stage 6 gives credential persistence a dedicated fail-closed
            // ordering machine. A failed save returns to a clean first-entry
            // screen rather than the now-empty confirmation screen.
            let queued = crate::runtime::presentation::start_credential_operation(
                ad, operation_kind(kind, false), entry_state(kind),
            );
            if !queued {
                crate::runtime::presentation::show_recoverable_error(ad, "Another operation is active", "UI-BUSY-01", 0);
            }
            Some(true)
        }
    }
}

fn setup_back(ad: &mut AppData, kind: CredentialKind, confirming: bool) -> Option<bool> {
    ad.wallet.seeds.pp_input.reset();
    let recovery_ack = ad.storage.persistence.recovery_words_acknowledged;
    let intent = ad.storage.persistence.device_storage_intent;
    ad.storage.persistence.reset();
    ad.storage.persistence.device_storage_intent = intent;
    ad.storage.persistence.recovery_words_acknowledged = recovery_ack;
    if confirming {
        ad.storage.persistence.kind = Some(kind);
        crate::runtime::effects::route(ad, entry_route(kind));
    } else {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageCredentialType));
    }
    Some(true)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_handle_setup_back(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if !input.is_back { return None; }
    match ad.navigation.app.state {
        AppState::StoragePinEntry => setup_back(ad, CredentialKind::Pin, false),
        AppState::StoragePinConfirm => setup_back(ad, CredentialKind::Pin, true),
        AppState::StoragePasswordEntry => setup_back(ad, CredentialKind::Password, false),
        AppState::StoragePasswordConfirm => setup_back(ad, CredentialKind::Password, true),
        _ => None,
    }
}

fn handle_unlock(
    input: TouchInput,
    ad: &mut AppData,
    kind: CredentialKind,
    display: &mut BootDisplay<'_>,
) -> Option<bool> {
    // Unlock cannot be bypassed with Back/Home. Successful authenticated
    // decryption is the only route to wallet state.
    if let Some(blocked) = unlock_navigation_guard(input) { return Some(blocked); }
    match edit_secret(input, ad, kind, display) {
        // Unlock owns the complete touch surface, including misses.
        SecretAction::None => Some(false),
        SecretAction::Edited => Some(kind == CredentialKind::Pin),
        SecretAction::Submitted => {
            if !unlock_retry_ready(ad) {
                crate::log!("KASSIGNER_PIN_FLOW: retry backoff active");
                return Some(false);
            }
            ad.storage.persistence.unlock_feedback = crate::runtime::data::UnlockFeedback::None;
            ad.storage.persistence.unlock_retry_after_ms = 0;
            // OperationState recovery owns an AppState target; dim-lock resume is
            // carried separately as an opaque ContinuationRoute and consumed only
            // after authenticated unlock succeeds. Do not mix those route types.
            let queued = crate::runtime::presentation::start_credential_operation(
                ad, operation_kind(kind, true), unlock_state(kind),
            );
            if !queued {
                crate::runtime::presentation::show_recoverable_error(ad, "Another operation is active", "UI-BUSY-01", 0);
            }
            Some(true)
        }
    }
}

fn unlock_retry_ready(ad: &AppData) -> bool {
    ad.storage.persistence.unlock_retry_after_ms == 0
        || esp_hal::time::Instant::now().duration_since_epoch().as_millis()
            >= ad.storage.persistence.unlock_retry_after_ms
}

fn operation_kind(kind: CredentialKind, unlock: bool) -> crate::runtime::data::OperationKind {
    match (kind, unlock) {
        (CredentialKind::Pin, false) => crate::runtime::data::OperationKind::SaveWalletPin,
        (CredentialKind::Password, false) => crate::runtime::data::OperationKind::SaveWalletPassword,
        (CredentialKind::Pin, true) => crate::runtime::data::OperationKind::UnlockWalletPin,
        (CredentialKind::Password, true) => crate::runtime::data::OperationKind::UnlockWalletPassword,
    }
}


fn unlock_navigation_guard(input: TouchInput) -> Option<bool> {
    input.is_back.then_some(false)
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
pub(crate) fn workflow_handle_unlock_touch(
    input: TouchInput,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::StorageUnlockPin => handle_unlock(input, ad, CredentialKind::Pin, display),
        AppState::StorageUnlockPassword => handle_unlock(input, ad, CredentialKind::Password, display),
        _ => None,
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_unlock_back_guard(state: AppState) -> bool {
    matches!(state, AppState::StorageUnlockPin | AppState::StorageUnlockPassword)
        && unlock_navigation_guard(TouchInput::new(20, 20, true)) == Some(false)
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretAction { None, Edited, Submitted }

fn edit_secret(
    input: TouchInput,
    ad: &mut AppData,
    kind: CredentialKind,
    display: &mut BootDisplay<'_>,
) -> SecretAction {
    if kind == CredentialKind::Pin {
        return edit_pin_secret(input, ad, display);
    }
    edit_password_secret(input, ad, display)
}

fn edit_pin_secret(input: TouchInput, ad: &mut AppData, display: &mut BootDisplay<'_>) -> SecretAction {
    let action = match pin_pad_action(input.x, input.y) {
        Some(action) => action,
        None => return SecretAction::None,
    };
    let reveal = setup_entry_is_visible(ad.navigation.app.state);
    if !matches!(action, PinPadAction::Submit) { crate::services::audio::click(); }
    let pp = &mut ad.wallet.seeds.pp_input;
    match action {
        PinPadAction::Digit(digit) if pp.len < 12 => pp.push_char(digit),
        PinPadAction::Digit(_) => return SecretAction::None,
        PinPadAction::Backspace => pp.backspace(),
        PinPadAction::Submit => return SecretAction::Submitted,
    }
    if reveal {
        display.update_storage_pin_value(pp, true);
    }
    SecretAction::Edited
}

fn edit_password_secret(
    input: TouchInput,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
) -> SecretAction {
    let action = hit_test(input.x, input.y, KeyboardMode::Full, ad.wallet.seeds.pp_input.page);
    if !matches!(action, KeyAction::None | KeyAction::Ok) { crate::services::audio::click(); }
    let pp = &mut ad.wallet.seeds.pp_input;
    match action {
        KeyAction::Char(character) => pp.push_char(character),
        KeyAction::Backspace => pp.backspace(),
        KeyAction::Page => pp.next_page(),
        KeyAction::Space => pp.push_char(b' '),
        KeyAction::CursorLeft => pp.cursor_left(),
        KeyAction::CursorRight => pp.cursor_right(),
        KeyAction::Ok => return SecretAction::Submitted,
        KeyAction::None => return SecretAction::None,
    }
    display.draw_storage_secret_entry(
        pp,
        secret_title(ad.navigation.app.state),
        false,
        setup_entry_is_visible(ad.navigation.app.state),
    );
    SecretAction::Edited
}

const fn setup_entry_is_visible(state: AppState) -> bool {
    matches!(
        state,
        AppState::StoragePinEntry
            | AppState::StoragePinConfirm
            | AppState::StoragePasswordEntry
            | AppState::StoragePasswordConfirm
    )
}

fn entry_state(kind: CredentialKind) -> AppState {
    match kind {
        CredentialKind::Pin => AppState::StoragePinEntry,
        CredentialKind::Password => AppState::StoragePasswordEntry,
    }
}

fn unlock_state(kind: CredentialKind) -> AppState {
    match kind {
        CredentialKind::Pin => AppState::StorageUnlockPin,
        CredentialKind::Password => AppState::StorageUnlockPassword,
    }
}

fn reset_confirmation_for_retry(ad: &mut AppData, kind: CredentialKind) {
    shared_signer::bytes::zeroize_bytes(&mut ad.storage.persistence.confirmation_digest);
    ad.storage.persistence.confirmation_pending = false;
    ad.storage.persistence.kind = Some(kind);
    ad.wallet.seeds.pp_input.reset();
}

fn entry_route(kind: CredentialKind) -> crate::runtime::navigation::UiRoute {
    match kind {
        CredentialKind::Pin => crate::runtime::navigation::route!(StoragePinEntry),
        CredentialKind::Password => crate::runtime::navigation::route!(StoragePasswordEntry),
    }
}

fn confirm_state(kind: CredentialKind) -> crate::runtime::navigation::UiRoute {
    match kind {
        CredentialKind::Pin => crate::runtime::navigation::route!(StoragePinConfirm),
        CredentialKind::Password => crate::runtime::navigation::route!(StoragePasswordConfirm),
    }
}

const fn secret_title(state: AppState) -> &'static str {
    match state {
        AppState::StoragePinEntry => "CREATE PIN",
        AppState::StoragePinConfirm => "CONFIRM PIN",
        AppState::StoragePasswordEntry => "CREATE PASSWORD",
        AppState::StoragePasswordConfirm => "CONFIRM PASSWORD",
        AppState::StorageUnlockPin => "UNLOCK PIN",
        AppState::StorageUnlockPassword => "UNLOCK PASSWORD",
        _ => "CREDENTIAL",
    }
}
