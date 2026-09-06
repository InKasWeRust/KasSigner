use crate::{runtime::input::AppState, services::persistent_wallet::PersistError};
use super::SecurityContext;

const CANCEL_X: u16 = 82;
const CONTINUE_X: u16 = 238;
const WARNING_Y: u16 = 212;
pub(super) const NOW_UNIX: u64 = 1_830_499_200; // 2028-01-03 08:00 UTC, Monday.

pub(super) fn exercise(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    let rtc_ok = rtc(ctx);
    let no_sign_ok = no_sign_before(ctx);
    let weekly_ok = weekly(ctx);
    rtc_ok && no_sign_ok && weekly_ok
}

fn rtc(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_rtc(ctx) { return false; }
    if ctx.advanced_touch(20, 20, true) != Some(true) || ctx.ad.navigation.app.state != AppState::AdvancedFeatures { return false; }
    if !open_rtc(ctx) { return false; }
    ctx.set_text(b"202813010800");
    if crate::runtime::interactions::settings::advanced::workflow::submit_rtc(ctx.ad).is_ok() { return false; }
    crate::runtime::interactions::settings::advanced::workflow::rtc_low_voltage(ctx.ad);
    if ctx.ad.storage.persistence.advanced.rtc_verification.is_verified() { return false; }
    ctx.set_text(b"202801030800");
    let verified = crate::runtime::interactions::settings::advanced::workflow::submit_rtc(ctx.ad) == Ok(NOW_UNIX)
        && ctx.ad.navigation.app.state == AppState::AdvancedFeatures
        && ctx.ad.storage.persistence.advanced.rtc_verification.is_verified();
    if verified { log!("KASSIGNER_WORKFLOW_TESTS: SECURITY RTC INVALID/LOW-VOLTAGE/VERIFY PASS"); }
    verified
}

fn open_rtc(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    ctx.open_card(207) == Some(true) && ctx.ad.navigation.app.state == AppState::AdvancedRtcEntry
}

fn no_sign_before(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    no_sign_cancel(ctx)
        && no_sign_input_boundaries(ctx)
        && no_sign_persistence_error(ctx)
        && no_sign_activate_readonly(ctx)
}

fn no_sign_cancel(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    ctx.open_card(93) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedTimeLockWarning
        && ctx.advanced_touch(CANCEL_X, WARNING_Y, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedFeatures
}

fn open_time_lock_entry(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    ctx.open_card(93) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedTimeLockWarning
        && ctx.advanced_touch(CONTINUE_X, WARNING_Y, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedTimeLockEntry
}

fn no_sign_input_boundaries(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_time_lock_entry(ctx) { return false; }
    ctx.set_text(b"bad");
    if crate::runtime::interactions::settings::advanced::workflow::submit_time_lock(ctx.ad, NOW_UNIX).is_ok() { return false; }
    ctx.set_text(b"202801030800");
    if crate::runtime::interactions::settings::advanced::workflow::submit_time_lock(ctx.ad, NOW_UNIX).is_ok() { return false; }
    if !stage_future(ctx) { return false; }
    ctx.advanced_touch(CANCEL_X, WARNING_Y, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedFeatures
}

fn no_sign_persistence_error(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_time_lock_entry(ctx) || !stage_future(ctx) { return false; }
    let rejected = crate::runtime::interactions::settings::advanced::workflow::confirm_time_lock(
        ctx.ad, NOW_UNIX, Err(PersistError::PolicyIntegrity),
    ).is_err() && ctx.ad.navigation.app.state == AppState::AdvancedTimeLockConfirm;
    rejected && ctx.advanced_touch(CANCEL_X, WARNING_Y, false) == Some(true)
}

fn no_sign_activate_readonly(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_time_lock_entry(ctx) || !stage_future(ctx) { return false; }
    if crate::runtime::interactions::settings::advanced::workflow::confirm_time_lock(ctx.ad, NOW_UNIX, Ok(())).is_err() { return false; }
    let active = ctx.ad.navigation.app.state == AppState::AdvancedFeatures
        && ctx.ad.storage.persistence.advanced.policy.not_before_unix == 1_830_502_800;
    let readonly = ctx.open_card(93) == Some(true) && ctx.ad.navigation.app.state == AppState::AdvancedFeatures;
    let rtc_locked = ctx.open_card(207) == Some(true) && ctx.ad.navigation.app.state == AppState::AdvancedFeatures;
    let ok = active && readonly && rtc_locked;
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: SECURITY NO-SIGN-BEFORE INVALID/CANCEL/PERSIST/READ-ONLY PASS"); }
    ok
}

fn stage_future(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    ctx.set_text(b"202801030900");
    crate::runtime::interactions::settings::advanced::workflow::submit_time_lock(ctx.ad, NOW_UNIX).is_ok()
        && ctx.ad.navigation.app.state == AppState::AdvancedTimeLockConfirm
}

fn weekly(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    weekly_invalid(ctx) && weekly_cancel(ctx) && weekly_persistence_error(ctx) && weekly_activate(ctx)
}

fn open_weekly_entry(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    ctx.open_card(131) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedWeeklyWarning
        && ctx.advanced_touch(CONTINUE_X, WARNING_Y, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedWeeklyEntry
}

fn weekly_invalid(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_weekly_entry(ctx) { return false; }
    ctx.set_text(b"MON 09:00-10:00;MON 09:30-10:30");
    let rejected = crate::runtime::interactions::settings::advanced::workflow::submit_weekly(ctx.ad).is_err();
    if rejected { ctx.advanced_touch(20, 20, true) == Some(true) } else { false }
}

fn weekly_cancel(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_weekly_entry(ctx) || !stage_weekly(ctx) { return false; }
    ctx.advanced_touch(CANCEL_X, WARNING_Y, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedFeatures
}

fn weekly_persistence_error(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_weekly_entry(ctx) || !stage_weekly(ctx) { return false; }
    let rejected = crate::runtime::interactions::settings::advanced::workflow::confirm_weekly(
        ctx.ad, NOW_UNIX, Err(PersistError::PolicyIntegrity),
    ).is_err() && ctx.ad.navigation.app.state == AppState::AdvancedWeeklyConfirm;
    rejected && ctx.advanced_touch(CANCEL_X, WARNING_Y, false) == Some(true)
}

fn weekly_activate(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !open_weekly_entry(ctx) || !stage_weekly(ctx) { return false; }
    if crate::runtime::interactions::settings::advanced::workflow::confirm_weekly(ctx.ad, NOW_UNIX, Ok(())).is_err() { return false; }
    let active = ctx.ad.navigation.app.state == AppState::AdvancedFeatures
        && ctx.ad.storage.persistence.advanced.policy.weekly_enabled
        && ctx.ad.storage.persistence.advanced.policy.weekly_count == 2;
    let readonly = ctx.open_card(131) == Some(true) && ctx.ad.navigation.app.state == AppState::AdvancedFeatures;
    let ok = active && readonly;
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: SECURITY WEEKLY INVALID/CANCEL/PERSIST/READ-ONLY PASS"); }
    ok
}

fn stage_weekly(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    ctx.set_text(b"MON 09:00-10:00;TUE 12:00-13:00");
    crate::runtime::interactions::settings::advanced::workflow::submit_weekly(ctx.ad).is_ok()
        && ctx.ad.navigation.app.state == AppState::AdvancedWeeklyConfirm
}
