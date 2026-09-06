use core::sync::atomic::{AtomicU16, Ordering};
use crate::{
    runtime::interactions::TouchInput,
    hw::{display::BootDisplay, sdcard::SdCardType},
    runtime::{data::AppData, input::AppState},
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

mod creation;
mod credentials;
#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
pub(super) use credentials::persistent_pin_round_trip;
mod restore;


pub(super) static FAILURE_MASK: AtomicU16 = AtomicU16::new(0);
pub(super) struct OnboardingContext<'ctx, 'display, 'hal> {
    pub(super) ad: &'ctx mut AppData,
    pub(super) display: &'ctx mut BootDisplay<'display>,
    pub(super) i2c: &'ctx mut I2c<'hal, Blocking>,
    pub(super) sd: &'ctx Option<SdCardType>,
    pub(super) delay: &'ctx mut Delay,
}

impl OnboardingContext<'_, '_, '_> {
    pub(super) fn redraw(&mut self) {
        super::redraw_step(self.ad, self.display, self.i2c, self.sd);
    }

    pub(super) fn redraw_step(&mut self) {
        self.redraw();
        super::show_step(self.delay);
    }

    pub(super) fn seed_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::seed::handle_seed_touch(
            self.ad,
            self.display,
            self.delay,
            &mut || {},
            TouchInput::new(x, y, is_back),
        )
    }

    pub(super) fn additive_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        use AppState::*;
        let handled = match self.ad.navigation.app.state {
            StorageSeedDiceChoice => crate::runtime::interactions::menu::seed_generation::workflow_dice_choice(
                self.ad, x, y, is_back,
            ),
            StorageSeedDiceCountChoice => crate::runtime::interactions::menu::seed_generation::workflow_dice_count(
                self.ad, x, y, is_back,
            ),
            StorageSeedTouchChoice => crate::runtime::interactions::menu::seed_generation::workflow_touch_choice(
                self.ad, x, y, is_back,
            ),
            TouchEntropy => crate::runtime::interactions::menu::seed_generation::workflow_touch_back(
                self.ad, is_back,
            ),
            _ => return None,
        };
        Some(handled)
    }

    pub(super) fn dice_touch(&mut self, x: u16, y: u16, is_back: bool) -> bool {
        crate::runtime::interactions::menu::seed_tools::handle_onboarding_dice(
            self.ad, self.display, x, y, is_back,
        )
    }
}

pub(super) fn reset_to_storage_choice(ad: &mut AppData) -> bool {
    // This is scenario isolation, not a user Home action.  Use the connected
    // reset so a prior wallet/onboarding probe cannot make production Home
    // guards poison the next independent onboarding case.
    if crate::runtime::navigation::is_onboarding(ad)
        && !crate::runtime::navigation::workflow_cleanup_onboarding_to_home(ad)
    {
        return false;
    }
    if !super::reset_tranche_to_home(ad) {
        return false;
    }
    crate::runtime::interactions::persistence::enter_storage_choice(ad);
    ad.navigation.app.state == AppState::StorageModeChoice
        && crate::runtime::navigation::reconcile(ad)
}

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    FAILURE_MASK.store(0, Ordering::Relaxed);
    if !super::root::home_ok(ad) {
        return false;
    }
    let mut ctx = OnboardingContext { ad, display, i2c, sd, delay };
    log!("KASSIGNER_WORKFLOW_TESTS: ONBOARDING/CREATE TRANCHE BEGIN");
    let mut summary = super::probe_status::ProbeSummary::new("ONBOARDING");

    summary.begin("WELCOME");
    let welcome_ok = welcome_restore_back(&mut ctx);
    summary.record("WELCOME", welcome_ok);

    summary.begin("CREATE-12");
    let create_12_ok = reset_to_storage_choice(ctx.ad)
        && creation::create_12_session_only(&mut ctx);
    summary.record("CREATE-12", create_12_ok);

    summary.begin("CREATE-24");
    let create_24_ok = creation::create_24_passphrase(&mut ctx);
    summary.record("CREATE-24", create_24_ok);

    summary.begin("CREDENTIAL-ROUTES");
    let credentials_ok = if create_24_ok {
        credentials::secure_storage_routes(&mut ctx)
    } else {
        log!("KASSIGNER_WORKFLOW_TESTS: ONBOARDING PROBE CREDENTIAL-ROUTES SKIPPED; CREATE-24 PREREQUISITE FAILED");
        false
    };
    summary.record("CREDENTIAL-ROUTES", credentials_ok);

    summary.begin("FINISH-SESSION");
    let finish_ok = if credentials_ok {
        finish_session_only(&mut ctx)
    } else {
        log!("KASSIGNER_WORKFLOW_TESTS: ONBOARDING PROBE FINISH-SESSION SKIPPED; CREDENTIAL PREREQUISITE FAILED");
        false
    };
    summary.record("FINISH-SESSION", finish_ok);

    summary.begin("RESTORE-IMPORT");
    let restore_ok = restore::exercise(ctx.ad, ctx.display, ctx.i2c, ctx.sd, ctx.delay);
    summary.record("RESTORE-IMPORT", restore_ok);
    let mut failure_mask = 0u16;
    if !welcome_ok { failure_mask |= 1u16 << 0; }
    if !create_12_ok { failure_mask |= 1u16 << 1; }
    if !create_24_ok { failure_mask |= 1u16 << 2; }
    if !credentials_ok { failure_mask |= 1u16 << 3; }
    if !finish_ok { failure_mask |= 1u16 << 4; }
    if !restore_ok { failure_mask |= 1u16 << 5; }
    FAILURE_MASK.store(failure_mask, Ordering::Relaxed);
    summary.finish(6)
}

fn welcome_restore_back(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if !reset_to_storage_choice(ctx.ad) {
        return false;
    }
    ctx.redraw_step();

    if crate::runtime::interactions::persistence::workflow_handle_mode_choice(
        TouchInput::new(310, 100, false), ctx.ad,
    ).is_some() || ctx.ad.navigation.app.state != AppState::StorageModeChoice {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_mode_choice(
        TouchInput::new(160, 142, false), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::StorageSeedSourceChoice {
        return false;
    }
    ctx.redraw_step();
    if crate::runtime::interactions::persistence::workflow_handle_seed_source_choice(
        TouchInput::new(20, 20, true), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::StorageModeChoice {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ONBOARDING WELCOME CREATE/RESTORE/NOOP OK");
    true
}

fn finish_session_only(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if ctx.ad.navigation.app.state != AppState::StorageFinalizeChoice {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_finalize_choice(
        TouchInput::new(160, 142, false), ctx.ad,
    ) != Some(true) || !super::root::home_ok(ctx.ad) {
        return false;
    }
    ctx.redraw_step();
    log!("KASSIGNER_WORKFLOW_TESTS: ONBOARDING SESSION-ONLY COMPLETE OK");
    log!("KASSIGNER_WORKFLOW_TESTS: ONBOARDING/CREATE TRANCHE PASS");
    true
}
