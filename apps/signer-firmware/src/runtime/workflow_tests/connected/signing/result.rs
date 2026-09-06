use core::sync::atomic::{AtomicU8, Ordering};
use crate::runtime::{data::{ModalState, OperationPhase}, input::AppState};
use super::SigningContext;

static FAILURE_STAGE: AtomicU8 = AtomicU8::new(0);

pub(super) fn sign_and_present(ctx: &mut SigningContext<'_, '_, '_>, expected_magic: &[u8; 4]) -> bool {
    FAILURE_STAGE.store(1, Ordering::Relaxed);
    if crate::runtime::presentation::operation_phase(ctx.ad) != OperationPhase::Queued
        || !ctx.activate_signing_operation()
        || crate::runtime::presentation::operation_phase(ctx.ad) != OperationPhase::Running
        || !crate::runtime::signing::workflow_signing_step(ctx.ad)
        || ctx.ad.navigation.app.state != AppState::ConfirmTx
        || crate::runtime::presentation::operation_cursor(ctx.ad) != 1
        || crate::runtime::presentation::operation_phase(ctx.ad) != OperationPhase::Progress(50)
    {
        return false;
    }

    // This redraw is the production failure path that originally retried the
    // one-shot Presented transition after input 1. Progress must remain owned
    // by the running operation and must never become OP-ORDER-01.
    ctx.redraw();
    if crate::runtime::presentation::operation_phase(ctx.ad) != OperationPhase::Progress(50)
        || ctx.ad.presentation.modal != ModalState::None
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX LIFECYCLE PROGRESS-REDRAW 1/2 PASS");

    FAILURE_STAGE.store(2, Ordering::Relaxed);
    if !crate::runtime::signing::workflow_signing_step(ctx.ad)
        || ctx.ad.navigation.app.state != AppState::ShowQR
        || ctx.ad.qr.outgoing.length == 0
        || ctx.ad.signing.transaction.active.inputs[0].sig_count == 0
        || ctx.ad.signing.transaction.active.inputs[1].sig_count == 0
        || ctx.ad.qr.outgoing.buffer.get(..4) != Some(&expected_magic[..])
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX CRYPTO/SERIALIZE 2/2 INPUTS PASS");
    ctx.redraw();
    FAILURE_STAGE.store(3, Ordering::Relaxed);
    crate::runtime::qr_presentation::prepare_navigation(ctx.ad);
    if ctx.ad.navigation.app.state == AppState::ShowQrModeChoice {
        FAILURE_STAGE.store(4, Ordering::Relaxed);
        if !manual_multiframe(ctx) { return false; }
    } else if ctx.ad.navigation.app.state == AppState::ShowQR {
        FAILURE_STAGE.store(5, Ordering::Relaxed);
        if ctx.menu_touch(160, 120, false) != Some(true) { return false; }
    } else {
        return false;
    }
    FAILURE_STAGE.store(6, Ordering::Relaxed);
    let ok = close_popup(ctx);
    if ok { FAILURE_STAGE.store(0, Ordering::Relaxed); }
    ok
}

pub(super) fn replay_failure_stage() {
    const NAMES: [&str; 6] = [
        "SIGN-INPUT-1", "SIGN-INPUT-2-SERIALIZE", "QR-PREPARE",
        "QR-MANUAL-FRAMES", "QR-SINGLE-FRAME", "QR-POPUP-BACK",
    ];
    let stage = FAILURE_STAGE.load(Ordering::Relaxed);
    if let Some(name) = stage.checked_sub(1).and_then(|index| NAMES.get(usize::from(index))) {
        log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED STANDARD-PSKT STAGE {}", name);
    }
}

fn manual_multiframe(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    let frames = ctx.ad.qr.outgoing.frame_count;
    if frames <= 1 || ctx.sd_touch(220, 160, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::ShowQR
        || !ctx.ad.qr.outgoing.manual_frames
    {
        return false;
    }
    ctx.redraw_step();
    for expected in 1..frames {
        if ctx.menu_touch(160, 120, false) != Some(true) || ctx.ad.qr.outgoing.frame != expected {
            return false;
        }
    }
    if ctx.menu_touch(160, 120, false) != Some(true) || ctx.ad.navigation.app.state != AppState::ShowQrPopup {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX SIGNED-QR MANUAL FRAMES PASS {}", frames);
    true
}

fn close_popup(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if ctx.ad.navigation.app.state != AppState::ShowQrPopup { return false; }
    if ctx.sd_touch(220, 160, false) != Some(true) || ctx.ad.navigation.app.state != AppState::ShowQR {
        return false;
    }
    if !reopen_manual_popup(ctx) { return false; }
    if ctx.sd_touch(20, 20, true) != Some(true) || ctx.ad.navigation.app.state != AppState::ShowQrModeChoice {
        return false;
    }
    if ctx.sd_touch(20, 20, true) != Some(true) || !super::super::root::home_ok(ctx.ad) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX SIGNED-QR POPUP/BACK PASS");
    true
}

fn reopen_manual_popup(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    // "Back to QR" restarts manual presentation at frame 0. Walk the
    // remaining frames again before expecting the popup; a single tap is only
    // sufficient for a single-frame payload.
    if ctx.ad.qr.outgoing.manual_frames
        && ctx.ad.qr.outgoing.frame_count > 1
        && !replay_manual_frames(ctx)
    {
        return false;
    }
    ctx.menu_touch(160, 120, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::ShowQrPopup
}

fn replay_manual_frames(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    let frames = ctx.ad.qr.outgoing.frame_count;
    for expected in 1..frames {
        if ctx.menu_touch(160, 120, false) != Some(true)
            || ctx.ad.qr.outgoing.frame != expected
            || ctx.ad.navigation.app.state != AppState::ShowQR
        {
            return false;
        }
    }
    true
}
