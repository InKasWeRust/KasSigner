use crate::runtime::input::AppState;
use super::SigningContext;

pub(super) fn open_review(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if ctx.ad.navigation.app.state != AppState::ConfirmTx { return false; }
    ctx.tx_touch(160, 208, false) == Some(true)
        && ctx.ad.navigation.app.state == (AppState::ReviewTx { page: 0 })
}

pub(super) fn inspect_all_inputs(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if ctx.ad.navigation.app.state != (AppState::ReviewTx { page: 0 }) { return false; }
    if ctx.tx_touch(58, 210, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::InspectUtxoSummary { return false; }
    ctx.redraw_step();
    let expected = [
        AppState::InspectUtxo { index: 0, address_page: false },
        AppState::InspectUtxo { index: 0, address_page: true },
        AppState::InspectUtxo { index: 1, address_page: false },
        AppState::InspectUtxo { index: 1, address_page: true },
        AppState::ReviewTx { page: 0 },
    ];
    for state in expected {
        if ctx.tx_touch(160, 220, false) != Some(true) || ctx.ad.navigation.app.state != state {
            return false;
        }
        ctx.redraw();
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX UTXO INSPECTION 2/2 PASS");
    true
}

pub(super) fn advance_review_to_confirm(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if ctx.ad.navigation.app.state != (AppState::ReviewTx { page: 0 }) { return false; }
    for expected in [AppState::ReviewTx { page: 1 }, AppState::ReviewTx { page: 2 }, AppState::ConfirmTx] {
        if ctx.tx_touch(260, 210, false) != Some(true) || ctx.ad.navigation.app.state != expected {
            return false;
        }
        ctx.redraw_step();
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX REVIEW PAGES 3/3 PASS");
    true
}

pub(super) fn review_back(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    ctx.tx_touch(20, 20, true) == Some(true) && ctx.ad.navigation.app.state == AppState::ConfirmTx
}

pub(super) fn confirm_back(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    ctx.tx_touch(20, 20, true) == Some(true) && super::super::root::home_ok(ctx.ad)
}

pub(super) fn reject(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    ctx.tx_touch(260, 208, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::Rejected
        && ctx.dismiss_confirm_rejection_to_home()
}

pub(super) fn confirm(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    ctx.tx_touch(60, 208, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::ConfirmTx
        && crate::runtime::presentation::operation_active(
            ctx.ad, crate::runtime::data::OperationKind::SignTransaction,
        )
        && crate::runtime::presentation::operation_cursor(ctx.ad) == 0
        && ctx.ad.navigation.app.review_authorized
}
