//! Destructive wallet-delete workflow coverage.

use crate::{
    runtime::{interactions::TouchInput, input::AppState},
    hw::touch::TouchState,
};
use signer_firmware_core::input::touch::{TouchEventType, TouchPoint};

use super::WalletContext;

pub(super) fn exercise(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    super::mark_failure_stage(6);
    if !delete_release_cancel(ctx) { return false; }
    super::mark_failure_stage(7);
    delete_commit(ctx)
}

fn delete_release_cancel(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    if !open_delete_for_active(ctx) || !begin_delete_hold(ctx) { return false; }
    if !service_destructive(ctx, TouchState::NoTouch)
        || !service_destructive(ctx, touch_at(230, 205))
        || ctx.ad.runtime.destructive.started_at_ms == 0
        || !service_destructive(ctx, TouchState::NoTouch)
    {
        return false;
    }
    if ctx.ad.navigation.app.state != AppState::SeedList
        || ctx.ad.wallet.seeds.seed_mgr.slots[1].is_empty()
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE RELEASE CANCEL OK");
    ctx.seed_list_touch(20, 20, true) == Some(true) && ctx.return_wallet_menu()
}

fn delete_commit(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE COMMIT OPEN BEGIN");
    if !open_delete_for_active(ctx) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE COMMIT OPEN OK");
    if !begin_delete_hold(ctx) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE COMMIT HOLD ARMED");
    if !service_destructive(ctx, TouchState::NoTouch) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE COMMIT RELEASE OK");
    if !service_destructive(ctx, touch_at(230, 205))
        || ctx.ad.runtime.destructive.started_at_ms == 0
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE COMMIT HOLD STARTED");
    if !crate::runtime::destructive::workflow_fast_forward_active_hold(ctx.ad) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE COMMIT FAST FORWARD OK");
    if !service_destructive(ctx, touch_at(230, 205)) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE COMMIT SERVICE OK");
    if ctx.ad.navigation.app.state != AppState::SeedList
        || !ctx.ad.wallet.seeds.seed_mgr.slots[1].is_empty()
        || ctx.ad.wallet.seeds.seed_mgr.active_slot().is_some()
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE ACTIVE LEAVES NO ACTIVE WALLET OK");
    super::mark_failure_stage(8);
    // The current workflow deliberately leaves WALLETS unresolved after deleting the active
    // wallet. Back/Home must stay trapped until a surviving wallet is selected.
    if ctx.seed_list_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SeedList
        || ctx.ad.wallet.seeds.seed_mgr.active_slot().is_some()
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE REQUIRED-SELECTION BACK GUARD OK");
    // Slot 1 is gone: Add Wallet is row 0 and surviving slot 0 is row 1.
    if ctx.seed_list_touch(160, 112, false) != Some(true)
        || ctx.ad.wallet.seeds.seed_mgr.active != 0
        || !ctx.return_wallet_menu()
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE SURVIVOR REACTIVATION OK");
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DELETE COMMIT OK");
    true
}

fn open_delete_for_active(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    if !ctx.open_wallet_item(2, AppState::WalletDetails) { return false; }
    crate::runtime::interactions::menu::primary::workflow_wallet_details_delete(ctx.ad)
        && ctx.ad.navigation.app.state == AppState::ConfirmDeleteSeed
        && ctx.ad.wallet.seeds.pending_delete_slot == ctx.ad.wallet.seeds.seed_mgr.active
}

fn begin_delete_hold(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    crate::runtime::interactions::seed::handle_seed_touch(
        ctx.ad, ctx.display, ctx.delay, &mut || {}, TouchInput::new(230, 205, false),
    ) == Some(false)
        && ctx.ad.runtime.destructive.action == crate::runtime::destructive::DestructiveAction::DeleteSeed
}

fn service_destructive(ctx: &mut WalletContext<'_, '_, '_>, touch: TouchState) -> bool {
    let mut feed = || {};
    crate::runtime::destructive::workflow_service_step(
        touch, &mut *ctx.ad, &mut *ctx.display, &mut *ctx.delay, &mut *ctx.i2c, &mut feed,
    )
}

fn touch_at(x: u16, y: u16) -> TouchState {
    TouchState::One(TouchPoint { x, y, event: TouchEventType::Contact })
}
