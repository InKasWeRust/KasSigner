use crate::{
    runtime::interactions::{TouchInput, sd::SdTouchContext, stego::StegoTouchContext},
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::input::AppState,
};

use super::OnboardingContext;
use super::super::backup::WorkflowBackupDevice;

mod qr;
mod raw_key;
mod routes;
mod words;

pub(super) const BUTTON_X: u16 = 160;
pub(super) const RESTORE_ROWS: [u16; 4] = [66, 112, 158, 204];

pub(super) struct RestoreIo<'ctx, 'display, 'hal> {
    pub(super) base: OnboardingContext<'ctx, 'display, 'hal>,
    pub(super) list: [TouchZone; 4],
    pub(super) up: TouchZone,
    pub(super) down: TouchZone,
    backup_device: WorkflowBackupDevice,
}

impl RestoreIo<'_, '_, '_> {
    pub(super) fn redraw_step(&mut self) {
        self.base.redraw_step();
    }

    pub(super) fn source_touch(&mut self, item: usize) -> Option<bool> {
        crate::runtime::interactions::persistence::workflow_handle_seed_source_choice(
            TouchInput::new(BUTTON_X, RESTORE_ROWS[item], false),
            self.base.ad,
        )
    }

    pub(super) fn source_back(&mut self) -> Option<bool> {
        crate::runtime::interactions::persistence::workflow_handle_seed_source_choice(
            TouchInput::new(20, 20, true),
            self.base.ad,
        )
    }

    pub(super) fn advanced_touch(&mut self, item: usize) -> Option<bool> {
        crate::runtime::interactions::persistence::workflow_handle_advanced_restore(
            TouchInput::new(BUTTON_X, RESTORE_ROWS[item], false),
            self.base.ad,
        )
    }

    pub(super) fn advanced_back(&mut self) -> Option<bool> {
        crate::runtime::interactions::persistence::workflow_handle_advanced_restore(
            TouchInput::new(20, 20, true),
            self.base.ad,
        )
    }

    pub(super) fn detected_touch(&mut self, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::persistence::workflow_handle_restore_12_detected(
            TouchInput::new(BUTTON_X, y, is_back),
            self.base.ad,
        )
    }

    pub(super) fn sd_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::sd::handle_sd_touch(SdTouchContext {
            ad: &mut *self.base.ad,
            boot_display: &mut *self.base.display,
            delay: &mut *self.base.delay,
            liveness: &mut || {}, i2c: &mut *self.base.i2c,
            sd_card_type: self.base.sd,
            backup_device: &mut self.backup_device,
            list_zones: &self.list,
            page_up_zone: &self.up,
            page_down_zone: &self.down,
            input: TouchInput::new(x, y, is_back),
        })
    }

    pub(super) fn stego_back(&mut self) -> Option<bool> {
        crate::runtime::interactions::stego::handle_stego_touch(StegoTouchContext {
            ad: &mut *self.base.ad,
            boot_display: &mut *self.base.display,
            delay: &mut *self.base.delay,
            liveness: &mut || {},
            i2c: &mut *self.base.i2c,
            sd_card_type: self.base.sd,
            backup_device: &mut self.backup_device,
            list_zones: &self.list,
            page_up_zone: &self.up,
            page_down_zone: &self.down,
            input: TouchInput::new(20, 20, true),
        })
    }
}

pub(super) fn exercise(
    ad: &mut crate::runtime::data::AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    // Each restore subprobe enters the authoritative storage-choice state on
    // its own so a prior create/restore failure cannot suppress later restore
    // cases in the same connected hardware run.
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let base = OnboardingContext { ad, display, i2c, sd, delay };
    let mut ctx = RestoreIo { base, list, up, down, backup_device: WorkflowBackupDevice };
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE/IMPORT TRANCHE BEGIN");
    let mut summary = super::super::probe_status::ProbeSummary::new("RESTORE/IMPORT");

    summary.begin("MENU-ROUTES");
    summary.record("MENU-ROUTES", routes::menu_routes(&mut ctx));
    summary.begin("WORDS-12");
    summary.record("WORDS-12", words::restore_12(&mut ctx));
    summary.begin("WORDS-24");
    summary.record("WORDS-24", words::restore_24(&mut ctx));
    summary.begin("INVALID-24");
    summary.record("INVALID-24", words::reject_invalid_24(&mut ctx));
    summary.begin("STANDARD-SEEDQR");
    summary.record("STANDARD-SEEDQR", qr::standard_seedqr(&mut ctx));
    summary.begin("COMPACT-SEEDQR");
    summary.record("COMPACT-SEEDQR", qr::compact_seedqr(&mut ctx));
    summary.begin("RAW-KEY");
    summary.record("RAW-KEY", raw_key::restore(&mut ctx));
    summary.begin("SD-EMPTY-BACK");
    summary.record("SD-EMPTY-BACK", routes::sd_empty_back(&mut ctx));
    summary.begin("FINISH-HOME");
    summary.record("FINISH-HOME", finish_home(&mut ctx));
    summary.finish(9)
}

pub(super) fn begin_restore(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if !super::reset_to_storage_choice(ctx.base.ad) {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_mode_choice(
        TouchInput::new(BUTTON_X, 142, false),
        ctx.base.ad,
    ) != Some(true) || ctx.base.ad.navigation.app.state != AppState::StorageSeedSourceChoice {
        return false;
    }
    ctx.redraw_step();
    true
}

pub(super) fn choose_no_passphrase(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    ctx.base.seed_touch(BUTTON_X, 143, false) == Some(true)
        && ctx.base.ad.navigation.app.state == AppState::StorageFinalizeChoice
}

pub(super) fn finish_restored_session(ctx: &mut RestoreIo<'_, '_, '_>, word_count: u8) -> bool {
    if ctx.base.ad.wallet.seeds.seed_loaded
        || ctx.base.ad.navigation.app.state != AppState::StorageFinalizeChoice
    {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_finalize_choice(
        TouchInput::new(BUTTON_X, 142, false),
        ctx.base.ad,
    ) != Some(true) {
        return false;
    }
    ctx.base.ad.wallet.seeds.seed_loaded
        && ctx.base.ad.wallet.seeds.active_source.mnemonic_word_count() == Some(word_count)
        && super::super::root::home_ok(ctx.base.ad)
}

fn finish_home(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if !crate::runtime::navigation::workflow_cleanup_onboarding_to_home(ctx.base.ad)
        || !super::super::root::home_ok(ctx.base.ad)
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE/IMPORT TRANCHE PASS");
    true
}
