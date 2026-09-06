use crate::{
    runtime::interactions::{stego::StegoTouchContext, TouchInput},
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::{data::AppData, input::AppState},
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

mod entry;
mod export;
mod media;
mod restore;

const NO_SD: Option<SdCardType> = None;

pub(super) struct StegoContext<'ctx, 'display, 'hal> {
    pub(super) ad: &'ctx mut AppData,
    pub(super) display: &'ctx mut BootDisplay<'display>,
    pub(super) i2c: &'ctx mut I2c<'hal, Blocking>,
    pub(super) sd: &'ctx Option<SdCardType>,
    pub(super) delay: &'ctx mut Delay,
    pub(super) list: [TouchZone; 4],
    pub(super) up: TouchZone,
    pub(super) down: TouchZone,
    pub(super) workflow_sd: Option<SdCardType>,
    pub(super) backup_device: super::backup::WorkflowBackupDevice,
}

impl StegoContext<'_, '_, '_> {
    pub(super) fn touch(&mut self, x: u16, y: u16, is_back: bool, media_present: bool) -> Option<bool> {
        let sd_card_type = if media_present { &self.workflow_sd } else { &NO_SD };
        crate::runtime::interactions::stego::handle_stego_touch(StegoTouchContext {
            ad: self.ad,
            boot_display: self.display,
            delay: self.delay,
            liveness: &mut || {},
            i2c: self.i2c,
            sd_card_type,
            backup_device: &mut self.backup_device,
            list_zones: &self.list,
            page_up_zone: &self.up,
            page_down_zone: &self.down,
            input: TouchInput::new(x, y, is_back),
        })
    }

    pub(super) fn set_text(&mut self, value: &[u8]) {
        self.ad.wallet.seeds.pp_input.reset();
        let length = value.len().min(self.ad.wallet.seeds.pp_input.buf.len());
        self.ad.wallet.seeds.pp_input.buf[..length].copy_from_slice(&value[..length]);
        self.ad.wallet.seeds.pp_input.len = length;
        self.ad.wallet.seeds.pp_input.cursor = length;
    }

    pub(super) fn redraw_step(&mut self) {
        super::redraw_step(self.ad, self.display, self.i2c, self.sd);
        super::show_step(self.delay);
    }

    pub(super) fn home(&mut self) -> bool {
        crate::runtime::effects::home(self.ad);
        super::root::home_ok(self.ad)
    }

    /// Enter steganographic backup through the same Wallet -> Backup ->
    /// Advanced Backup route used by production. Connected E2E may substitute
    /// deterministic media bytes, but it must not manufacture Stego ownership
    /// by jumping directly from Home.
    pub(super) fn enter_export_mode(&mut self) -> bool {
        if !super::backup::enter_advanced_backup(self.ad) {
            return false;
        }
        crate::runtime::interactions::menu::primary::workflow_backup_recovery_select(self.ad, 2)
            && self.ad.navigation.app.state == AppState::StegoModeSelect
            && crate::runtime::navigation::reconcile(self.ad)
    }

    /// Enter first-wallet stego restore through the authoritative onboarding
    /// restore hierarchy. This keeps Onboarding ownership intact for every
    /// import screen and catches production transition-policy drift.
    pub(super) fn enter_onboarding_import_picker(&mut self) -> bool {
        if !super::root::home_ok(self.ad) {
            if !crate::runtime::navigation::workflow_cleanup_onboarding_to_home(self.ad) {
                crate::runtime::effects::home(self.ad);
                if !super::root::home_ok(self.ad) {
                    return false;
                }
            }
        }
        crate::runtime::interactions::persistence::enter_storage_choice(self.ad);
        if self.ad.navigation.app.state != AppState::StorageModeChoice
            || crate::runtime::interactions::persistence::workflow_handle_mode_choice(
                TouchInput::new(160, 142, false),
                self.ad,
            ) != Some(true)
            || self.ad.navigation.app.state != AppState::StorageSeedSourceChoice
            || crate::runtime::interactions::persistence::workflow_handle_seed_source_choice(
                TouchInput::new(160, 204, false),
                self.ad,
            ) != Some(true)
            || self.ad.navigation.app.state != AppState::AdvancedRestoreMenu
            || crate::runtime::interactions::persistence::workflow_handle_advanced_restore(
                TouchInput::new(160, 158, false),
                self.ad,
            ) != Some(true)
            || self.ad.navigation.app.state != AppState::StegoImportPick
        {
            return false;
        }
        crate::runtime::navigation::reconcile(self.ad)
    }

    pub(super) fn enter_onboarding_import_descriptor(&mut self) -> bool {
        if !self.enter_onboarding_import_picker() {
            return false;
        }
        self.ad.stego.import.jpeg_count = 1;
        self.ad.stego.import.jpeg_selected = 0;
        let zone = self.list[0];
        self.touch(zone.x + zone.w / 2, zone.y + zone.h / 2, false, true) == Some(true)
            && self.ad.navigation.app.state == AppState::StegoImportDescChoice
            && crate::runtime::navigation::reconcile(self.ad)
    }
}

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ad) {
        return false;
    }
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let mut ctx = StegoContext {
        ad,
        display,
        i2c,
        sd,
        delay,
        list,
        up,
        down,
        workflow_sd: Some(SdCardType::SdV2Hc),
        backup_device: super::backup::WorkflowBackupDevice,
    };
    log!("KASSIGNER_WORKFLOW_TESTS: STEGANOGRAPHY TRANCHE BEGIN");
    let mut summary = super::probe_status::ProbeSummary::new("STEGO");

    summary.begin("ENTRY");
    let entry_ok = entry::exercise(&mut ctx);
    summary.record("ENTRY", entry_ok);
    recover(&mut ctx, entry_ok);

    summary.begin("EXPORT");
    let export_ok = export::exercise(&mut ctx);
    summary.record("EXPORT", export_ok);
    recover(&mut ctx, export_ok);

    summary.begin("MEDIA");
    let artifacts = media::exercise(&mut ctx);
    let media_ok = artifacts.is_some();
    summary.record("MEDIA", media_ok);
    recover(&mut ctx, media_ok);

    summary.begin("RESTORE");
    let restore_ok = match artifacts {
        Some(artifacts) => restore::exercise(&mut ctx, artifacts),
        None => {
            log!("KASSIGNER_WORKFLOW_TESTS: STEGO PROBE RESTORE SKIPPED; MEDIA PREREQUISITE FAILED");
            false
        }
    };
    summary.record("RESTORE", restore_ok);

    summary.begin("FINISH-HOME");
    let finish_ok = finish(&mut ctx);
    summary.record("FINISH-HOME", finish_ok);
    summary.finish(5)
}

fn recover(ctx: &mut StegoContext<'_, '_, '_>, probe_ok: bool) {
    if probe_ok {
        return;
    }
    crate::runtime::effects::home(ctx.ad);
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad) {
        log!("KASSIGNER_WORKFLOW_TESTS: STEGO PROBE RECOVERY FIXTURE FAILED");
    }
}

fn finish(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if !ctx.home() {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: STEGO PHYSICAL SD/JPEG MEDIA HIL DEFERRED TO PERIPHERAL TRANCHE");
    log!("KASSIGNER_WORKFLOW_TESTS: STEGANOGRAPHY TRANCHE PASS");
    true
}
