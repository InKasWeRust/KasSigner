use alloc::vec;
use crate::runtime::{data::AntiKleptoPhase, input::AppState};
use super::{fixture, review, SigningContext};

const HOST_SECRET: [u8; 32] = [0x33; 32];

pub(super) fn exercise(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: ANTI-KLEPTO TRANCHE BEGIN");
    let mut summary = super::super::probe_status::ProbeSummary::new("ANTI-KLEPTO");

    summary.begin("TRANSACTION-BINDING");
    let binding_ok = transaction_binding_reject(ctx);
    summary.record("TRANSACTION-BINDING", binding_ok);
    recover(ctx, binding_ok);

    summary.begin("SESSION-REJECT");
    let session_ok = reveal_session_reject(ctx);
    summary.record("SESSION-REJECT", session_ok);
    recover(ctx, session_ok);

    summary.begin("SECRET-REJECT");
    let secret_ok = reveal_secret_reject(ctx);
    summary.record("SECRET-REJECT", secret_ok);
    recover(ctx, secret_ok);

    summary.begin("SUCCESS");
    let success_ok = successful_round_trip(ctx);
    summary.record("SUCCESS", success_ok);

    summary.begin("REPLAY");
    let replay_ok = if success_ok {
        replay_reject(ctx)
    } else {
        log!("KASSIGNER_WORKFLOW_TESTS: ANTI-KLEPTO PROBE REPLAY SKIPPED; SUCCESS PREREQUISITE FAILED");
        false
    };
    summary.record("REPLAY", replay_ok);

    summary.begin("FINISH-HOME");
    let finish_ok = finish(ctx);
    summary.record("FINISH-HOME", finish_ok);
    summary.finish(6)
}

fn recover(ctx: &mut SigningContext<'_, '_, '_>, probe_ok: bool) {
    if probe_ok {
        return;
    }
    let _ = super::super::reset_tranche_to_home(ctx.ad);
    let _ = super::fixture::install_wallet(ctx.ad);
}

fn request_wire(ctx: &SigningContext<'_, '_, '_>, host_secret: &[u8; 32]) -> Option<alloc::vec::Vec<u8>> {
    let tx = fixture::wire(ctx.ad, fixture::WireFormat::CompactKspt)?;
    let mut output = vec![0u8; tx.len().saturating_add(192)];
    let len = shared_signer::anti_klepto::encode_request(host_secret, &tx, &mut output).ok()?;
    output.truncate(len);
    Some(output)
}

fn begin(ctx: &mut SigningContext<'_, '_, '_>) -> Option<[u8; shared_signer::anti_klepto::SESSION_ID_LEN]> {
    let session = scan_request(ctx)?;
    sign_to_commitment(ctx, &session).then_some(session)
}

fn scan_request(ctx: &mut SigningContext<'_, '_, '_>) -> Option<[u8; shared_signer::anti_klepto::SESSION_ID_LEN]> {
    if !super::super::root::home_ok(ctx.ad) { return None; }
    let scan = crate::ui::layout::HOME_GRID_ZONES[1];
    if !crate::runtime::interactions::menu::handle_connected_root_probe(
        ctx.ad, scan.x + scan.w / 2, scan.y + scan.h / 2,
    ) || ctx.ad.navigation.app.state != AppState::ScanQR { return None; }
    let request = request_wire(ctx, &HOST_SECRET)?;
    let session = shared_signer::anti_klepto::parse_request(&request).ok()?.session_id;
    crate::runtime::interactions::camera_loop::workflow_process_anti_klepto_payload(
        &request, ctx.ad,
    );
    (ctx.ad.signing.anti_klepto.phase == AntiKleptoPhase::Reviewing
        && ctx.ad.navigation.app.state == AppState::ConfirmTx)
        .then_some(session)
}

fn sign_to_commitment(
    ctx: &mut SigningContext<'_, '_, '_>,
    session: &[u8; shared_signer::anti_klepto::SESSION_ID_LEN],
) -> bool {
    if !review::confirm(ctx) || !ctx.activate_signing_operation() { return false; }
    if !crate::runtime::signing::workflow_signing_step(ctx.ad)
        || !crate::runtime::signing::workflow_signing_step(ctx.ad)
        || ctx.ad.signing.anti_klepto.phase != AntiKleptoPhase::AwaitingReveal
        || ctx.ad.navigation.app.state != AppState::ShowQR
    { return false; }
    let Ok(commitment) = shared_signer::anti_klepto::parse_commitment(
        &ctx.ad.qr.outgoing.buffer[..ctx.ad.qr.outgoing.length],
    ) else { return false; };
    let ok = commitment.len() == 2 && commitment.session_id == *session;
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: ANTI-KLEPTO COMMITMENT 2/2 PASS"); }
    ok
}

fn enter_reveal_scan(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if ctx.menu_touch(160, 120, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::AntiKleptoRevealGuide
        || ctx.ad.signing.anti_klepto.phase != AntiKleptoPhase::AwaitingReveal
    {
        return false;
    }
    let ok = crate::ui::layout::ERROR_OK_ZONE;
    ctx.tx_touch(ok.x + ok.w / 2, ok.y + ok.h / 2, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::ScanQR
        && ctx.ad.signing.anti_klepto.phase == AntiKleptoPhase::AwaitingReveal
}

fn reveal_wire(session: &[u8; shared_signer::anti_klepto::SESSION_ID_LEN], secret: &[u8; 32]) -> Option<alloc::vec::Vec<u8>> {
    let mut output = vec![0u8; 96];
    let len = shared_signer::anti_klepto::encode_reveal(session, secret, &mut output).ok()?;
    output.truncate(len);
    Some(output)
}

fn process_reveal(ctx: &mut SigningContext<'_, '_, '_>, session: &[u8; shared_signer::anti_klepto::SESSION_ID_LEN], secret: &[u8; 32]) -> bool {
    let Some(reveal) = reveal_wire(session, secret) else { return false; };
    crate::runtime::interactions::camera_loop::workflow_process_anti_klepto_payload(
        &reveal, ctx.ad,
    );
    true
}

fn transaction_binding_reject(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if !super::super::root::home_ok(ctx.ad) { return false; }
    let scan = crate::ui::layout::HOME_GRID_ZONES[1];
    if !crate::runtime::interactions::menu::handle_connected_root_probe(
        ctx.ad,
        scan.x + scan.w / 2,
        scan.y + scan.h / 2,
    ) || ctx.ad.navigation.app.state != AppState::ScanQR
    {
        return false;
    }
    let Some(mut request) = request_wire(ctx, &HOST_SECRET) else { return false; };
    let Some(last) = request.last_mut() else { return false; };
    *last ^= 0x01;
    crate::runtime::interactions::camera_loop::workflow_process_anti_klepto_payload(&request, ctx.ad);
    let ok = ctx.ad.navigation.app.state == AppState::Rejected
        && ctx.dismiss_scan_rejection_to_home();
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: ANTI-KLEPTO TRANSACTION-BINDING REJECT PASS"); }
    ok
}

fn reveal_session_reject(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    let Some(mut session) = begin(ctx) else { return false; };
    if !enter_reveal_scan(ctx) { return false; }
    session[0] ^= 0x80;
    if !process_reveal(ctx, &session, &HOST_SECRET) { return false; }
    let rolled_back = (0..2).all(|index| ctx.ad.signing.transaction.active.inputs[index].sig_count == 0);
    let ok = ctx.ad.navigation.app.state == AppState::Rejected && rolled_back
        && ctx.dismiss_scan_rejection_to_home();
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: ANTI-KLEPTO SESSION-MISMATCH/ROLLBACK PASS"); }
    ok
}

fn reveal_secret_reject(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    let Some(session) = begin(ctx) else { return false; };
    if !enter_reveal_scan(ctx) { return false; }
    let wrong = [0x44u8; 32];
    if !process_reveal(ctx, &session, &wrong) { return false; }
    let ok = ctx.ad.navigation.app.state == AppState::Rejected
        && ctx.dismiss_scan_rejection_to_home();
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: ANTI-KLEPTO HOST-SECRET REJECT PASS"); }
    ok
}

fn successful_round_trip(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    let Some(session) = begin(ctx) else { return false; };
    if !enter_reveal_scan(ctx) || !process_reveal(ctx, &session, &HOST_SECRET) { return false; }
    if ctx.ad.navigation.app.state != AppState::ShowQrModeChoice
        || ctx.ad.signing.anti_klepto.phase != AntiKleptoPhase::FinalResponse
        || ctx.ad.qr.outgoing.frame_count <= 1
    { return false; }
    // Anti-klepto already fixes the peer/protocol. The only remaining choice is
    // final QR presentation mode; choose Auto Cycle for the workflow probe.
    if ctx.sd_touch(80, 160, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::ShowQR
        || ctx.ad.qr.outgoing.manual_frames
    { return false; }
    let Ok(signed) = shared_signer::anti_klepto::parse_signed(
        &ctx.ad.qr.outgoing.buffer[..ctx.ad.qr.outgoing.length],
    ) else { return false; };
    let ok = signed.session_id == session && signed.proof_count() == 2
        && signed.transaction.starts_with(b"KSPT");
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: ANTI-KLEPTO REVEAL/SIGNED 2/2 PASS"); }
    ok
}

fn replay_reject(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    let session = ctx.ad.signing.anti_klepto.session_id;
    if ctx.menu_touch(160, 120, false) != Some(true) || !super::super::root::home_ok(ctx.ad) { return false; }
    let scan = crate::ui::layout::HOME_GRID_ZONES[1];
    if !crate::runtime::interactions::menu::handle_connected_root_probe(ctx.ad, scan.x + scan.w / 2, scan.y + scan.h / 2) { return false; }
    if !process_reveal(ctx, &session, &HOST_SECRET) { return false; }
    let ok = ctx.ad.navigation.app.state == AppState::Rejected
        && ctx.dismiss_scan_rejection_to_home();
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: ANTI-KLEPTO REPLAY REJECT PASS"); }
    ok
}

fn finish(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if !super::super::root::home_ok(ctx.ad) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: ANTI-KLEPTO RTC/PERSISTENT FLOOR DEFERRED TO SECURITY HIL");
    log!("KASSIGNER_WORKFLOW_TESTS: ANTI-KLEPTO TRANCHE PASS");
    true
}
