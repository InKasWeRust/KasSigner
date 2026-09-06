use crate::{
    runtime::input::AppState,
    ui::screens::device::pop_it::{
        CONTINUE_WITHOUT_BUTTON_Y, EXPLAIN_BUTTON_X, NO_BUTTON_X, OWNER_PROMPT_BUTTON_X,
        OWNER_SETUP_BUTTON_Y, PROMPT_BUTTON_Y, YES_BUTTON_X,
    },
};
use super::SecurityContext;

fn center(range: &core::ops::RangeInclusive<u16>) -> u16 {
    (*range.start() + *range.end()) / 2
}

fn prompt_y() -> u16 { center(&PROMPT_BUTTON_Y) }

pub(super) fn exercise(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    let owner_warning_ok = owner_warning(ctx);
    let explain_ok = explain_and_no(ctx);
    let failures_ok = phrase_and_failures(ctx);
    let success_ok = simulated_success(ctx);
    owner_warning_ok && explain_ok && failures_ok && success_ok
}

fn owner_warning(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    enter(ctx);
    ctx.ad.pop_it.owner_authority_enrolled = false;
    let x = center(&OWNER_PROMPT_BUTTON_X);
    let setup_y = center(&OWNER_SETUP_BUTTON_Y);
    if crate::runtime::interactions::settings::advanced::workflow::pop_it_prompt(
        crate::runtime::interactions::TouchInput::new(x, setup_y, false), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::OwnerFirmwareMenu {
        return false;
    }
    enter(ctx);
    ctx.ad.pop_it.owner_authority_enrolled = false;
    let continue_y = center(&CONTINUE_WITHOUT_BUTTON_Y);
    if crate::runtime::interactions::settings::advanced::workflow::pop_it_prompt(
        crate::runtime::interactions::TouchInput::new(x, continue_y, false), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::PopItConfirm {
        return false;
    }
    if ctx.advanced_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::AdvancedMenu
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY POP-IT OWNER WARNING PASS");
    true
}

fn enter(ctx: &mut SecurityContext<'_, '_, '_>) {
    crate::runtime::interactions::settings::advanced::workflow::enter_pop_it(ctx.ad);
}

fn explain_and_no(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    enter(ctx);
    if ctx.ad.navigation.app.state != AppState::PopItPrompt
        || ctx.advanced_touch(center(&EXPLAIN_BUTTON_X), prompt_y(), false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::PopItExplain
        || ctx.advanced_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::PopItPrompt
    { return false; }
    if crate::runtime::interactions::settings::advanced::workflow::pop_it_prompt(
        crate::runtime::interactions::TouchInput::new(center(&NO_BUTTON_X), prompt_y(), false), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::AdvancedMenu { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY POP-IT EXPLAIN/NO PASS");
    true
}

fn phrase_and_failures(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    for accepted in [b"popit".as_slice(), b"POP IT".as_slice(), b"pop-it!".as_slice()] {
        if !crate::runtime::interactions::settings::advanced::workflow::pop_it_phrase_valid(accepted) { return false; }
    }
    if crate::runtime::interactions::settings::advanced::workflow::pop_it_phrase_valid(b"burn it") { return false; }
    enter(ctx);
    if crate::runtime::interactions::settings::advanced::workflow::pop_it_prompt(
        crate::runtime::interactions::TouchInput::new(center(&YES_BUTTON_X), prompt_y(), false), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::PopItConfirm { return false; }
    if crate::runtime::interactions::settings::advanced::workflow::pop_it_confirmation(
        ctx.ad, b"wrong", true, true,
    ).is_ok() || ctx.ad.pop_it.error.is_none() { return false; }
    if crate::runtime::interactions::settings::advanced::workflow::pop_it_confirmation(
        ctx.ad, b"pop it", false, true,
    ).is_ok() { return false; }
    if crate::runtime::interactions::settings::advanced::workflow::pop_it_confirmation(
        ctx.ad, b"pop it", true, false,
    ).is_ok() { return false; }
    if ctx.advanced_touch(20, 20, true) != Some(true) || ctx.ad.navigation.app.state != AppState::AdvancedMenu {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY POP-IT PHRASE/PREFLIGHT/ARM-FAIL PASS");
    true
}

fn simulated_success(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    enter(ctx);
    if crate::runtime::interactions::settings::advanced::workflow::pop_it_prompt(
        crate::runtime::interactions::TouchInput::new(center(&YES_BUTTON_X), prompt_y(), false), ctx.ad,
    ) != Some(true) { return false; }
    if crate::runtime::interactions::settings::advanced::workflow::pop_it_confirmation(
        ctx.ad, b"pop-it!", true, true,
    ).is_err() || ctx.ad.navigation.app.state != AppState::AdvancedMenu || ctx.ad.pop_it.error.is_some() {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY POP-IT SAFE SIMULATED SUCCESS PASS");
    true
}
