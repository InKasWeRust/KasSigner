//! Transaction-review route events owned by the stage-2 navigation authority.

use crate::runtime::{data::AppData, input::{AppState, Menu, CONFIRM_MENU_ITEMS}};

use super::{dispatch, kernel, reconcile, route, UiEvent};

pub(crate) fn start_review(ad: &mut AppData, num_outputs: u8, num_inputs: usize) {
    ad.navigation.app.review_pages = 1 + num_outputs;
    ad.navigation.app.total_inputs = num_inputs;
    ad.navigation.app.review_authorized = false;
    ad.navigation.app.menu = Menu::from_items(CONFIRM_MENU_ITEMS);
    let _ = dispatch(ad, UiEvent::Route(route!(ConfirmTx)));
}

pub(crate) fn advance_review(ad: &mut AppData) -> bool {
    let AppState::ReviewTx { page } = ad.navigation.app.state else { return false; };
    let next = page.saturating_add(1);
    if next < ad.navigation.app.review_pages {
        let _ = dispatch(ad, UiEvent::Route(route!(ReviewTx { page: next })));
    } else {
        ad.navigation.app.menu = Menu::from_items(CONFIRM_MENU_ITEMS);
        let _ = dispatch(ad, UiEvent::Route(route!(ConfirmTx)));
    }
    true
}

pub(crate) fn advance_inspection(ad: &mut AppData) -> bool {
    match ad.navigation.app.state {
        AppState::InspectUtxoSummary => begin_inspection(ad),
        AppState::InspectUtxo { index, address_page: false } => {
            let _ = dispatch(ad, UiEvent::Route(route!(InspectUtxo { index: index, address_page: true })));
        }
        AppState::InspectUtxo { index, address_page: true } => advance_input(ad, index),
        _ => return false,
    }
    true
}

fn begin_inspection(ad: &mut AppData) {
    if ad.navigation.app.total_inputs == 0 {
        let _ = dispatch(ad, UiEvent::Route(route!(ReviewTx { page: 0 })));
    } else {
        let _ = dispatch(ad, UiEvent::Route(route!(InspectUtxo { index: 0, address_page: false })));
    }
}

fn advance_input(ad: &mut AppData, index: usize) {
    if index + 1 < ad.navigation.app.total_inputs {
        let _ = dispatch(ad, UiEvent::Route(route!(InspectUtxo { index: index + 1, address_page: false })));
    } else {
        let _ = dispatch(ad, UiEvent::Route(route!(ReviewTx { page: 0 })));
    }
}

pub(crate) fn confirm_transaction(ad: &mut AppData, cursor: u8) -> bool {
    if !matches!(cursor, 0 | 1 | 2) || !signing_route_ready(ad, AppState::ConfirmTx) { return false; }
    ad.navigation.app.menu.cursor = cursor;
    match cursor {
        0 => authorize_signing(ad),
        1 => reject_signing(ad),
        2 => { let _ = dispatch(ad, UiEvent::Route(route!(ReviewTx { page: 0 }))); },
        _ => {}
    }
    true
}

fn authorize_signing(ad: &mut AppData) {
    ad.navigation.app.review_authorized = true;
    let _ = dispatch(ad, UiEvent::MenuSelect(0));
}

fn reject_signing(ad: &mut AppData) {
    ad.navigation.app.review_authorized = false;
    let _ = dispatch(ad, UiEvent::Route(route!(Rejected)));
}

pub(crate) fn advance_signing(ad: &mut AppData) -> bool {
    if !crate::runtime::presentation::operation_active(
        ad, crate::runtime::data::OperationKind::SignTransaction,
    ) || !signing_route_ready(ad, AppState::ConfirmTx) {
        return false;
    }
    let input_idx = crate::runtime::presentation::operation_cursor(ad);
    let next = input_idx + 1;
    if next >= ad.navigation.app.total_inputs {
        ad.navigation.app.review_authorized = false;
        crate::runtime::presentation::finish_success(ad);
        ad.qr.presentation.large = false;
        ad.qr.presentation.mode = 0;
        ad.qr.presentation.via_density = false;
        ad.qr.outgoing.frame = 0;
        ad.qr.outgoing.frame_count = 0;
        ad.qr.outgoing.manual_frames = false;
        let _ = dispatch(ad, UiEvent::Route(route!(ShowQR)));
    } else {
        crate::runtime::presentation::set_cursor(ad, next);
        ad.runtime.needs_redraw = true;
    }
    true
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn reject_active_signing(ad: &mut AppData) -> bool {
    if !crate::runtime::presentation::operation_active(
        ad, crate::runtime::data::OperationKind::SignTransaction,
    ) || !signing_route_ready(ad, AppState::ConfirmTx) {
        return false;
    }
    ad.navigation.app.review_authorized = false;
    crate::runtime::presentation::clear_operation(ad);
    dispatch(ad, UiEvent::Route(route!(Rejected)))
}

fn signing_route_ready(ad: &mut AppData, expected: AppState) -> bool {
    if !reconcile(ad) { return false; }
    if ad.navigation.committed_state == expected && ad.navigation.app.state == expected {
        return true;
    }
    kernel::force_recover(ad, expected);
    false
}
