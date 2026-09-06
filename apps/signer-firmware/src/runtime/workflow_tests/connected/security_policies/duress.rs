use crate::{runtime::input::AppState, services::persistent_wallet::PersistError};
use super::SecurityContext;

const CANCEL_X: u16 = 82;
const CONTINUE_X: u16 = 238;
const WARNING_Y: u16 = 212;

fn duress_y() -> u16 {
    let range = &crate::ui::screens::device::advanced_security::DURESS_Y;
    (*range.start() + *range.end()) / 2
}

fn back_xy() -> (u16, u16) { crate::ui::layout::zone_center(crate::ui::layout::BACK_ZONE) }

pub(super) fn exercise(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    let cancel_ok = cancel_warning(ctx);
    let invalid_ok = invalid_and_mismatch(ctx);
    let persistence_ok = persistence_error(ctx);
    let activate_ok = activate(ctx);
    cancel_ok && invalid_ok && persistence_ok && activate_ok
}

fn open_entry(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    ctx.open_card(duress_y()) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedDuressWarning
        && ctx.advanced_touch(CONTINUE_X, WARNING_Y, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedDuressEntry
}

fn cancel_warning(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if ctx.open_card(duress_y()) != Some(true)
        || ctx.ad.navigation.app.state != AppState::AdvancedDuressWarning
        || ctx.advanced_touch(CANCEL_X, WARNING_Y, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::AdvancedFeatures
    { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY DURESS WARNING CANCEL PASS");
    true
}

fn invalid_and_mismatch(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_entry(ctx) { return false; }
    ctx.set_text(b"123");
    if crate::runtime::interactions::settings::advanced::workflow::submit_duress(ctx.ad, false, Ok(())).is_ok()
        || ctx.ad.navigation.app.state != AppState::AdvancedDuressEntry
    { return false; }
    ctx.set_text(b"246810");
    if crate::runtime::interactions::settings::advanced::workflow::submit_duress(ctx.ad, false, Ok(())).is_err()
        || ctx.ad.navigation.app.state != AppState::AdvancedDuressConfirm
    { return false; }
    ctx.set_text(b"246811");
    if crate::runtime::interactions::settings::advanced::workflow::submit_duress(ctx.ad, true, Ok(())).is_ok()
        || ctx.ad.navigation.app.state != AppState::AdvancedDuressEntry
        || ctx.ad.wallet.seeds.pp_input.len != 0
    { return false; }
    if ctx.advanced_touch(back_xy().0, back_xy().1, true) != Some(true) || ctx.ad.navigation.app.state != AppState::AdvancedFeatures {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY DURESS INVALID/MISMATCH REJECT PASS");
    true
}

fn persistence_error(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_entry(ctx) { return false; }
    ctx.set_text(b"246810");
    if crate::runtime::interactions::settings::advanced::workflow::submit_duress(ctx.ad, false, Ok(())).is_err() { return false; }
    ctx.set_text(b"246810");
    let result = crate::runtime::interactions::settings::advanced::workflow::submit_duress(
        ctx.ad, true, Err(PersistError::DuressMatchesUnlockCredential),
    );
    if result.is_ok() || ctx.ad.navigation.app.state != AppState::AdvancedDuressEntry { return false; }
    if ctx.advanced_touch(back_xy().0, back_xy().1, true) != Some(true) || ctx.ad.navigation.app.state != AppState::AdvancedFeatures {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY DURESS PERSISTENCE ERROR PASS");
    true
}

fn activate(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_entry(ctx) { return false; }
    ctx.set_text(b"246810");
    if crate::runtime::interactions::settings::advanced::workflow::submit_duress(ctx.ad, false, Ok(())).is_err() { return false; }
    ctx.set_text(b"246810");
    if crate::runtime::interactions::settings::advanced::workflow::submit_duress(ctx.ad, true, Ok(())).is_err()
        || ctx.ad.navigation.app.state != AppState::AdvancedFeatures
        || !ctx.ad.storage.persistence.advanced.duress.is_enabled()
    { return false; }
    if ctx.open_card(duress_y()) != Some(true) || ctx.ad.navigation.app.state != AppState::AdvancedFeatures { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY DURESS CONFIRM/READ-ONLY PASS");
    true
}
