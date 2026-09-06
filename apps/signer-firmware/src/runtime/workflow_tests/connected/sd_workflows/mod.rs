use core::sync::atomic::{AtomicU16, Ordering};
use crate::{
    runtime::interactions::{TouchInput, sd::SdTouchContext},
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::{data::AppData, input::{AppState}},
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

mod browser;
mod imports;
mod encrypted;


pub(super) static FAILURE_MASK: AtomicU16 = AtomicU16::new(0);
pub(super) struct SdWorkflowContext<'ctx, 'display, 'hal> {
    pub(super) ad: &'ctx mut AppData,
    pub(super) display: &'ctx mut BootDisplay<'display>,
    pub(super) i2c: &'ctx mut I2c<'hal, Blocking>,
    pub(super) sd: &'ctx Option<SdCardType>,
    pub(super) delay: &'ctx mut Delay,
    pub(super) list: [TouchZone; 4],
    pub(super) up: TouchZone,
    pub(super) down: TouchZone,
    pub(super) backup_device: super::backup::WorkflowBackupDevice,
}

impl SdWorkflowContext<'_, '_, '_> {
    pub(super) fn sd_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::sd::handle_sd_touch(SdTouchContext {
            ad: &mut *self.ad,
            boot_display: &mut *self.display,
            delay: &mut *self.delay,
            liveness: &mut || {},
            i2c: &mut *self.i2c,
            sd_card_type: self.sd,
            backup_device: &mut self.backup_device,
            list_zones: &self.list,
            page_up_zone: &self.up,
            page_down_zone: &self.down,
            input: TouchInput::new(x, y, is_back),
        })
    }

    pub(super) fn set_password(&mut self, password: &[u8]) {
        self.ad.wallet.seeds.pp_input.reset();
        let length = password.len().min(self.ad.wallet.seeds.pp_input.buf.len());
        self.ad.wallet.seeds.pp_input.buf[..length].copy_from_slice(&password[..length]);
        self.ad.wallet.seeds.pp_input.len = length;
        self.ad.wallet.seeds.pp_input.cursor = length;
    }

    pub(super) fn home(&mut self) -> bool {
        super::reset_tranche_to_home(self.ad)
    }

    /// Enter the SD import hierarchy through the same production Wallet ->
    /// Backup -> Advanced Backup route a user must take. Normal controller E2E
    /// may inject file bytes, but it must not manufacture Storage ownership by
    /// jumping directly from Home to an SD screen.
    pub(super) fn enter_import_menu(&mut self) -> bool {
        if !super::backup::enter_advanced_backup(self.ad) {
            return false;
        }
        crate::runtime::interactions::menu::primary::workflow_backup_recovery_select(self.ad, 3)
            && self.ad.navigation.app.state == AppState::SdImportMenu
            && crate::runtime::navigation::reconcile(self.ad)
    }

    pub(super) fn enter_import_list(&mut self, state: AppState) -> bool {
        if !matches!(
            state,
            AppState::SdFileList | AppState::SdKsptFileList | AppState::SdKpubFileList
        ) || !self.enter_import_menu()
        {
            return false;
        }
        match state {
            AppState::SdFileList => crate::runtime::effects::route(self.ad, crate::runtime::navigation::route!(SdFileList)),
            AppState::SdKsptFileList => crate::runtime::effects::route(self.ad, crate::runtime::navigation::route!(SdKsptFileList)),
            AppState::SdKpubFileList => crate::runtime::effects::route(self.ad, crate::runtime::navigation::route!(SdKpubFileList)),
            _ => false,
        };
        self.ad.navigation.app.state == state && crate::runtime::navigation::reconcile(self.ad)
    }
}

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    FAILURE_MASK.store(0, Ordering::Relaxed);
    if !super::root::home_ok(ad) || !super::signing::fixture::install_wallet(ad) {
        return false;
    }
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let mut ctx = SdWorkflowContext {
        ad, display, i2c, sd, delay, list, up, down,
        backup_device: super::backup::WorkflowBackupDevice,
    };
    log!("KASSIGNER_WORKFLOW_TESTS: SD WORKFLOWS TRANCHE BEGIN");
    let mut summary = super::probe_status::ProbeSummary::new("SD-WORKFLOWS");

    summary.begin("BROWSER");
    let browser_ok = prepare_probe(&mut ctx) && browser::exercise(&mut ctx);
    summary.record("BROWSER", browser_ok);

    summary.begin("IMPORTS");
    let imports_ok = prepare_probe(&mut ctx) && imports::exercise(&mut ctx);
    summary.record("IMPORTS", imports_ok);

    summary.begin("ENCRYPTED");
    let encrypted_ok = prepare_probe(&mut ctx) && encrypted::exercise(&mut ctx);
    summary.record("ENCRYPTED", encrypted_ok);

    summary.begin("FINISH-HOME");
    let finish_ok = finish(&mut ctx);
    summary.record("FINISH-HOME", finish_ok);
    let mut failure_mask = 0u16;
    if !browser_ok { failure_mask |= 1u16 << 0; }
    if !imports_ok { failure_mask |= 1u16 << 1; }
    if !encrypted_ok { failure_mask |= 1u16 << 2; }
    if !finish_ok { failure_mask |= 1u16 << 3; }
    FAILURE_MASK.store(failure_mask, Ordering::Relaxed);
    summary.finish(4)
}

pub(super) fn replay_import_failure_detail() {
    if FAILURE_MASK.load(Ordering::Relaxed) & (1u16 << 1) != 0 {
        imports::replay_failure_stage();
    }
}

fn prepare_probe(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    if !ctx.home() || crate::runtime::presentation::operation_kind(ctx.ad).is_some() {
        log!("KASSIGNER_WORKFLOW_TESTS: SD-WORKFLOWS PROBE HOME/CANCEL RESET FAIL");
        return false;
    }
    ctx.ad.signing.zeroize_sensitive();
    ctx.ad.qr.clear_sensitive();
    super::signing::fixture::install_wallet(ctx.ad)
}

fn finish(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    if !ctx.home() { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SD WORKFLOWS TRANCHE PASS");
    true
}
