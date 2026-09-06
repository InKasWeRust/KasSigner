use crate::{
    runtime::interactions::{TouchInput, tx::TxTouchContext},
    runtime::input::AppState,
    services::signing_policy::EnforcementError,
};
use signer_firmware_core::advanced_policy::{SigningPolicy, SigningWindow};
use super::SecurityContext;

const NOW_UNIX: u64 = 1_830_499_200; // 2028-01-03 08:00 UTC, Monday.

pub(super) fn exercise(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    let boundaries_ok = pure_policy_boundaries(ctx);
    let signing_ok = signing_deny_allow(ctx);
    boundaries_ok && signing_ok
}

fn pure_policy_boundaries(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    let policy = ctx.ad.storage.persistence.advanced.policy;
    let before = NOW_UNIX + 30 * 60;
    let allowed = NOW_UNIX + 90 * 60;
    let end = NOW_UNIX + 2 * 60 * 60;
    if crate::services::signing_policy::workflow_authorize_transaction_time(policy, true, before)
        != Err(EnforcementError::BeforeNotBefore)
        || crate::services::signing_policy::workflow_authorize_transaction_time(policy, true, allowed)
            != Ok(Some(allowed))
        || crate::services::signing_policy::workflow_authorize_transaction_time(policy, true, end)
            != Err(EnforcementError::OutsideWeeklyWindow)
        || crate::services::signing_policy::workflow_authorize_transaction_time(policy, false, allowed)
            != Err(EnforcementError::Integrity)
    { return false; }
    let mut rollback = policy;
    rollback.rtc_floor_unix = allowed;
    if crate::services::signing_policy::workflow_authorize_transaction_time(
        rollback, true, allowed - 1,
    ) != Err(EnforcementError::ClockRollback) { return false; }
    let mut invalid = SigningPolicy::disabled();
    invalid.weekly_enabled = true;
    invalid.weekly_count = 1;
    invalid.windows[0] = SigningWindow { weekday: 7, start_minute: 1, end_minute: 2 };
    if crate::services::signing_policy::workflow_authorize_transaction_time(invalid, true, allowed)
        != Err(EnforcementError::InvalidPolicy)
    { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY SIGNING POLICY INTEGRITY/ROLLBACK/LOCK/WINDOW BOUNDARIES PASS");
    true
}

fn signing_deny_allow(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    let policy = ctx.ad.storage.persistence.advanced.policy;
    if !prepare_confirmed_transaction(ctx) { return false; }
    let before_counts = offline_signer::transaction::kspt::initial_signature_counts(
        &ctx.ad.signing.transaction.active,
    );
    if crate::runtime::signing::workflow_signing_step_with_policy(
        ctx.ad, policy, true, NOW_UNIX + 30 * 60,
    ) || ctx.ad.navigation.app.state != AppState::Rejected { return false; }
    let after_counts = offline_signer::transaction::kspt::initial_signature_counts(
        &ctx.ad.signing.transaction.active,
    );
    if before_counts != after_counts { return false; }
    crate::runtime::effects::home(ctx.ad);
    if !prepare_confirmed_transaction(ctx) { return false; }
    let initial = offline_signer::transaction::kspt::initial_signature_counts(&ctx.ad.signing.transaction.active);
    if !crate::runtime::signing::workflow_signing_step_with_policy(
        ctx.ad, policy, true, NOW_UNIX + 90 * 60,
    ) || ctx.ad.navigation.app.state != AppState::ConfirmTx
        || crate::runtime::presentation::operation_cursor(ctx.ad) != 1 { return false; }
    let signed = offline_signer::transaction::kspt::initial_signature_counts(&ctx.ad.signing.transaction.active);
    if initial == signed { return false; }
    crate::runtime::effects::home(ctx.ad);
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY SIGNING POLICY ACTUAL SIGN DENY/ALLOW PASS");
    true
}

fn prepare_confirmed_transaction(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    crate::runtime::effects::home(ctx.ad);
    let Some(wire) = super::super::signing::fixture::wire(
        ctx.ad,
        super::super::signing::fixture::WireFormat::CompactKspt,
    ) else { return false; };
    let scan = crate::ui::layout::HOME_GRID_ZONES[1];
    if !crate::runtime::interactions::menu::handle_connected_root_probe(
        ctx.ad, scan.x + scan.w / 2, scan.y + scan.h / 2,
    ) { return false; }
    crate::runtime::interactions::camera_loop::workflow_process_transaction_payload(
        &wire, false, ctx.ad,
    );
    if ctx.ad.navigation.app.state != AppState::ConfirmTx { return false; }
    tx_touch(ctx, 60, 208) == Some(true)
        && ctx.ad.navigation.app.state == AppState::ConfirmTx
        && crate::runtime::presentation::operation_active(
            ctx.ad, crate::runtime::data::OperationKind::SignTransaction,
        )
        && crate::runtime::presentation::operation_cursor(ctx.ad) == 0
        && ctx.ad.navigation.app.review_authorized
        && crate::runtime::signing::workflow_activate_signing_operation(ctx.ad)
}

fn tx_touch(ctx: &mut SecurityContext<'_, '_, '_>, x: u16, y: u16) -> Option<bool> {
    crate::runtime::interactions::tx::handle_tx_touch(TxTouchContext {
        ad: ctx.ad,
        boot_display: ctx.display,
        delay: ctx.delay,
        liveness: &mut || {},
        i2c: ctx.i2c,
        sd_card_type: ctx.sd,
        list_zones: &ctx.list,
        input: TouchInput::new(x, y, false),
    })
}
