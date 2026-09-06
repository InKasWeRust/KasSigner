use crate::{
    hw::display::BootDisplay,
    runtime::data::{AppData, ModalState, OperationKind, OperationPhase},
};

/// Draw stage-3 transient presentation before the stable AppState screen.
/// Returns true when a modal/operation owns the whole frame.
pub(super) fn redraw(ad: &mut AppData, display: &mut BootDisplay<'_>) -> bool {
    match ad.presentation.modal {
        ModalState::RecoverableError { message, code, return_to, dismiss_after_ms } => {
            let ready = esp_hal::time::Instant::now().duration_since_epoch().as_millis() >= dismiss_after_ms;
            if crate::runtime::input::is_scan_state(ad.navigation.committed_state) {
                let action = if return_to == crate::runtime::input::AppState::MainMenu {
                    "HOME"
                } else {
                    "BACK"
                };
                display.draw_recoverable_error_screen_with_action(message, code, ready, action);
            } else {
                display.draw_recoverable_error_screen(message, code, ready);
            }
            return true;
        }
        ModalState::FatalError { message, code } => {
            display.draw_fatal_error_screen(message, code);
            return true;
        }
        ModalState::None => {}
    }

    let Some(kind) = ad.presentation.operation.kind() else { return false; };
    if !ad.presentation.operation.is_active() { return false; }
    match kind {
        OperationKind::SaveWalletPin | OperationKind::SaveWalletPassword => {
            display.draw_saving_screen("Securing wallet...");
        }
        OperationKind::UnlockWalletPin | OperationKind::UnlockWalletPassword => {
            display.draw_wait_screen("Unlocking wallet...");
        }
        OperationKind::ConnectKasSee => {
            display.draw_loading_screen("Deriving account key...");
        }
        OperationKind::DeriveMultisigKpub => {
            display.draw_loading_screen("Deriving multisig kpub...");
        }
        OperationKind::SignTransaction => {
            display.draw_signing_screen(ad.presentation.operation.cursor(), ad.navigation.app.total_inputs);
        }
    }
    if let OperationPhase::Progress(progress) = ad.presentation.operation.phase() {
        display.update_progress_bar(progress);
    }
    if ad.presentation.operation.phase() == OperationPhase::Queued {
        crate::runtime::presentation::mark_operation_presented(ad);
    }
    true
}
