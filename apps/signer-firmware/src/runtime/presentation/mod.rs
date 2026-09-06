//! Stage-3 presentation controller. Navigation owns stable screen routes;
//! this module owns transient operation and modal presentation state.

mod errors;
pub(crate) use errors::{
    ErrorSpec, ANTI_KLEPTO, COVENANT,
    OP_CONNECT_TIMEOUT, OP_CREDENTIAL_TIMEOUT, OP_MULTISIG_TIMEOUT, OP_SIGN_TIMEOUT,
    POLICY_SAVE, PRIVATE_SWAP, QR_FRAME, SIGN_ENTROPY, SIGN_FINALIZE, SIGN_INPUT, SIGN_KEY,
    SIGN_POLICY, SIGN_REVIEW, TX_IMPORT, TX_OWNERSHIP,
};
#[cfg(all(
    not(feature = "hardware-tests"),
    any(
        not(feature = "workflow-test-auto"),
        all(feature = "m5stack", feature = "workflow-runtime-auto")
    )
))]
pub(crate) use errors::{CAMERA_CAPTURE, CAMERA_MEMORY};
#[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]
pub(crate) use errors::NAVIGATION;
#[cfg(all(
    feature = "m5stack",
    not(feature = "hardware-tests"),
    any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto")
))]
pub(crate) use errors::CAMERA_UNAVAILABLE;
#[cfg(all(feature = "m5stack", not(feature = "hardware-tests")))]
pub(crate) use errors::{ADDRESS_DERIVE, ADDRESS_TIMEOUT};
#[cfg(all(not(feature = "hardware-tests"), not(feature = "workflow-test-auto")))]
pub(crate) use errors::{SD_WRITE, STORAGE_SYNC};

use esp_hal::time::Instant;
use crate::runtime::{data::{AppData, ModalState, OperationKind, OperationPhase}, input::AppState};

pub(crate) fn start_operation(ad: &mut AppData, kind: OperationKind) -> bool {
    let stable = ad.navigation.committed_state;
    if ad.presentation.modal != ModalState::None {
        crate::log!("   UI operation {:?} rejected: modal active", kind);
        return false;
    }
    if !ad.presentation.operation.start(kind, stable, now_millis()) {
        crate::log!(
            "   UI operation {:?} rejected: active={:?} phase={:?}",
            kind,
            ad.presentation.operation.kind(),
            ad.presentation.operation.phase(),
        );
        return false;
    }
    ad.runtime.needs_redraw = true;
    crate::log!("   UI operation queued {:?} on {:?}", kind, stable);
    true
}

/// Queue one credential operation with an explicit stable recovery target.
/// Credential ordering is part of the same `OperationState` lifecycle used by
/// every other long-running operation; there is no parallel credential machine.
pub(crate) fn start_credential_operation(
    ad: &mut AppData,
    kind: OperationKind,
    return_to: AppState,
) -> bool {
    if !kind.is_credential() || ad.presentation.modal != ModalState::None { return false; }
    crate::log!("KASSIGNER_PIN_FLOW: PIN SUBMIT {}", kind.credential_marker());
    if !ad.presentation.operation.start_credential(kind, return_to) { return false; }
    crate::log!("KASSIGNER_PIN_FLOW: LOADING COMMITTED {}", kind.credential_marker());
    ad.runtime.needs_redraw = true;
    crate::log!("   UI credential operation queued {:?} return {:?}", kind, return_to);
    true
}


pub(crate) fn previous_stable_screen(ad: &AppData) -> AppState {
    ad.navigation.history.peek().unwrap_or(ad.navigation.committed_state)
}

pub(crate) fn show_error_spec(ad: &mut AppData, error: ErrorSpec) {
    show_recoverable_error(ad, error.message, error.code, 0);
}

pub(crate) fn show_error_spec_to(ad: &mut AppData, return_to: AppState, error: ErrorSpec) {
    show_recoverable_error_to(ad, return_to, error.message, error.code, 0);
}

pub(crate) fn show_error_spec_previous(ad: &mut AppData, error: ErrorSpec) {
    let return_to = previous_stable_screen(ad);
    show_error_spec_to(ad, return_to, error);
}


pub(crate) fn operation_active(ad: &AppData, kind: OperationKind) -> bool {
    ad.presentation.operation.kind() == Some(kind) && ad.presentation.operation.is_active()
}

pub(crate) fn operation_kind(ad: &AppData) -> Option<OperationKind> {
    ad.presentation.operation.kind()
}

pub(crate) fn operation_phase(ad: &AppData) -> OperationPhase {
    ad.presentation.operation.phase()
}

pub(crate) fn operation_cursor(ad: &AppData) -> usize {
    ad.presentation.operation.cursor()
}


pub(crate) fn mark_operation_presented(ad: &mut AppData) {
    let Some(kind) = ad.presentation.operation.kind() else { return; };
    if !ad.presentation.operation.mark_presented(now_millis()) {
        operation_order_violation(ad, "loading-render");
        return;
    }
    if kind.is_credential() {
        crate::log!("KASSIGNER_PIN_FLOW: LOADING RENDERED {}", kind.credential_marker());
    }
}

/// Advance one presented operation into execution. Every long-running driver,
/// including credentials, enters through this same boundary.
pub(crate) fn take_ready_operation(ad: &mut AppData) -> Option<OperationKind> {
    let kind = ad.presentation.operation.take_ready()?;
    if kind.is_credential() {
        crate::log!("KASSIGNER_PIN_FLOW: KDF BEGIN {}", kind.credential_marker());
    }
    Some(kind)
}

/// Record the result of the execution body before committing a terminal UI
/// result. This validates that the operation is still the owner of execution.
pub(crate) fn execution_done(ad: &mut AppData, kind: OperationKind, ok: bool) -> bool {
    if !ad.presentation.operation.execution_result_ready(kind) {
        operation_order_violation(ad, "execution-done");
        return false;
    }
    if kind.is_credential() {
        crate::log!("KASSIGNER_PIN_FLOW: KDF DONE {} ok={}", kind.credential_marker(), ok);
    }
    true
}

/// Emit terminal credential evidence while the unified operation lifecycle is
/// still owned by `kind`. Call this immediately before clearing the operation.
pub(crate) fn credential_result_committed(
    ad: &mut AppData,
    kind: OperationKind,
    result: &'static str,
) -> bool {
    if ad.presentation.operation.kind() != Some(kind) || !ad.presentation.operation.is_active() {
        operation_order_violation(ad, "result-commit");
        return false;
    }
    crate::log!(
        "KASSIGNER_PIN_FLOW: RESULT COMMITTED {} {}",
        kind.credential_marker(),
        result,
    );
    true
}


pub(crate) fn set_progress(ad: &mut AppData, progress: u8) {
    ad.presentation.operation.set_progress(progress, now_millis());
}

pub(crate) fn timed_out_operation(ad: &AppData) -> Option<OperationKind> {
    if ad.presentation.operation.timed_out(now_millis()) {
        ad.presentation.operation.kind()
    } else {
        None
    }
}

pub(crate) const fn timeout_error(kind: OperationKind) -> Option<ErrorSpec> {
    match kind {
        OperationKind::ConnectKasSee => Some(OP_CONNECT_TIMEOUT),
        OperationKind::DeriveMultisigKpub => Some(OP_MULTISIG_TIMEOUT),
        OperationKind::SignTransaction => Some(OP_SIGN_TIMEOUT),
        OperationKind::SaveWalletPin
        | OperationKind::SaveWalletPassword
        | OperationKind::UnlockWalletPin
        | OperationKind::UnlockWalletPassword => Some(OP_CREDENTIAL_TIMEOUT),
    }
}

pub(crate) fn set_cursor(ad: &mut AppData, cursor: usize) {
    ad.presentation.operation.set_cursor(cursor);
}

pub(crate) fn finish_success(ad: &mut AppData) {
    ad.presentation.operation.mark_success();
    ad.presentation.operation.clear();
}

/// Clear transient operation presentation after the owning subsystem has
/// canceled its in-flight work. This is intentionally separate from
/// `finish_success`: abandonment must not be recorded as success.
pub(crate) fn clear_operation(ad: &mut AppData) {
    ad.presentation.operation.clear();
}

pub(crate) fn fail_recoverable_spec(ad: &mut AppData, error: ErrorSpec) {
    fail_recoverable(ad, error.message, error.code, 0);
}

pub(crate) fn fail_recoverable(
    ad: &mut AppData,
    message: &'static str,
    code: &'static str,
    retry_delay_ms: u32,
) {
    let return_to = ad.presentation.operation.return_to();
    ad.presentation.operation.mark_recoverable_error();
    ad.presentation.operation.clear();
    install_recoverable_error(ad, return_to, message, code, retry_delay_ms);
}

pub(crate) fn show_recoverable_error(
    ad: &mut AppData,
    message: &'static str,
    code: &'static str,
    retry_delay_ms: u32,
) {
    let return_to = ad.navigation.committed_state;
    install_recoverable_error(ad, return_to, message, code, retry_delay_ms);
}

/// Show an ordinary recoverable failure and return to an explicitly validated
/// stable screen when the user presses OK. The target must be the current
/// committed screen or a screen already present in bounded navigation history.
pub(crate) fn show_recoverable_error_to(
    ad: &mut AppData,
    return_to: AppState,
    message: &'static str,
    code: &'static str,
    retry_delay_ms: u32,
) {
    install_recoverable_error(ad, return_to, message, code, retry_delay_ms);
}

fn install_recoverable_error(
    ad: &mut AppData,
    return_to: AppState,
    message: &'static str,
    code: &'static str,
    retry_delay_ms: u32,
) {
    ad.presentation.modal = ModalState::RecoverableError {
        message,
        code,
        return_to,
        dismiss_after_ms: now_millis().saturating_add(u64::from(retry_delay_ms)),
    };
    ad.runtime.needs_redraw = true;
    crate::services::audio::error();
    crate::log!("   UI recoverable error {}: {}", code, message);
}

pub(crate) fn fail_fatal(ad: &mut AppData, message: &'static str, code: &'static str) {
    ad.presentation.operation.mark_fatal_error();
    ad.presentation.operation.clear();
    ad.presentation.modal = ModalState::FatalError { message, code };
    ad.runtime.needs_redraw = true;
    crate::services::audio::error();
    crate::log!("   UI fatal error {}: {}", code, message);
}

/// Clear an ordinary recoverable presentation when an internal workflow
/// deliberately abandons the current screen and commits Home. Fatal errors
/// remain sticky and can never be hidden by navigation recovery.
pub(crate) fn clear_recoverable_modal(ad: &mut AppData) {
    if matches!(ad.presentation.modal, ModalState::RecoverableError { .. }) {
        ad.presentation.modal = ModalState::None;
    }
}

pub(crate) fn blocks_input(ad: &AppData) -> bool { ad.presentation.blocks_input() }

/// Consume a tap while a stage-3 modal/operation owns presentation. Recoverable
/// errors dismiss only through the explicit OK button and never invent a new
/// navigation destination: the stable screen remained committed underneath.
pub(crate) fn handle_tap(ad: &mut AppData, x: u16, y: u16) -> bool {
    match ad.presentation.modal {
        ModalState::RecoverableError { return_to, dismiss_after_ms, .. } => {
            if crate::ui::layout::ERROR_OK_ZONE.contains(x, y) && now_millis() >= dismiss_after_ms {
                if !crate::runtime::navigation::return_from_error(ad, return_to) {
                    crate::log!("   UI modal stable-screen recovery rejected: {:?}", return_to);
                    return true;
                }
                ad.presentation.modal = ModalState::None;
                ad.runtime.needs_redraw = true;
                crate::services::audio::click();
            }
            true
        }
        ModalState::FatalError { .. } => true,
        ModalState::None if ad.presentation.operation.is_active() => true,
        ModalState::None => false,
    }
}

pub(crate) fn filter_action(
    ad: &mut AppData,
    action: crate::hw::touch::TouchAction,
) -> crate::hw::touch::TouchAction {
    match action {
        crate::hw::touch::TouchAction::Tap { x, y } if handle_tap(ad, x, y) => {
            crate::hw::touch::TouchAction::None
        }
        _ if blocks_input(ad) => crate::hw::touch::TouchAction::None,
        other => other,
    }
}

fn operation_order_violation(ad: &mut AppData, boundary: &'static str) {
    let kind = ad.presentation.operation.kind();
    ad.presentation.operation.clear();
    ad.presentation.modal = ModalState::FatalError {
        message: "Operation lifecycle ordering failure. Restart required.",
        code: "OP-ORDER-01",
    };
    ad.runtime.needs_redraw = true;
    crate::services::audio::error();
    crate::log!("   Operation lifecycle ordering violation {} kind={:?}", boundary, kind);
}

fn now_millis() -> u64 {
    Instant::now().duration_since_epoch().as_millis()
}

