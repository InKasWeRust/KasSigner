use core::sync::atomic::{AtomicU8, AtomicU16, Ordering};
use crate::{
    runtime::interactions::{sd::SdTouchContext, tx::TxTouchContext},
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::{data::AppData, input::AppState},
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

pub(super) mod fixture;
mod result;
mod review;
mod anti_klepto;


pub(super) static FAILURE_MASK: AtomicU16 = AtomicU16::new(0);
static STANDARD_FAILURE_STAGE: AtomicU8 = AtomicU8::new(0);
struct SigningContext<'ctx, 'display, 'hal> {
    ad: &'ctx mut AppData,
    display: &'ctx mut BootDisplay<'display>,
    i2c: &'ctx mut I2c<'hal, Blocking>,
    sd: &'ctx Option<SdCardType>,
    delay: &'ctx mut Delay,
    list: [TouchZone; 4],
    up: TouchZone,
    down: TouchZone,
    backup_device: super::backup::WorkflowBackupDevice,
}

impl SigningContext<'_, '_, '_> {
    fn redraw(&mut self) { super::redraw_step(self.ad, self.display, self.i2c, self.sd); }
    fn redraw_step(&mut self) { self.redraw(); super::show_step(self.delay); }
    fn activate_signing_operation(&mut self) -> bool {
        #[cfg(feature = "workflow-runtime-auto")]
        if crate::runtime::presentation::operation_phase(self.ad)
            == crate::runtime::data::OperationPhase::Queued
        {
            self.redraw();
        }
        crate::runtime::signing::workflow_activate_signing_operation(self.ad)
    }
    fn tx_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        let input = crate::runtime::touch_dispatch::workflow_touch_input(x, y, is_back)?;
        crate::runtime::interactions::tx::handle_tx_touch(TxTouchContext {
            ad: &mut *self.ad, boot_display: &mut *self.display, delay: &mut *self.delay,
            liveness: &mut || {}, i2c: &mut *self.i2c, sd_card_type: self.sd, list_zones: &self.list,
            input,
        })
    }
    fn menu_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::menu::handle_navigation_touch(
            self.ad, &crate::ui::layout::HOME_GRID_ZONES, &self.list, &self.up, &self.down,
            crate::runtime::touch_dispatch::workflow_touch_input(x, y, is_back)?,
        )
    }
    fn sd_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::sd::handle_sd_touch(SdTouchContext {
            ad: &mut *self.ad, boot_display: &mut *self.display, delay: &mut *self.delay,
            liveness: &mut || {}, i2c: &mut *self.i2c, sd_card_type: self.sd, backup_device: &mut self.backup_device,
            list_zones: &self.list, page_up_zone: &self.up, page_down_zone: &self.down,
            input: crate::runtime::touch_dispatch::workflow_touch_input(x, y, is_back)?,
        })
    }

    fn dismiss_rejected_to(&mut self, expected: AppState) -> bool {
        let (x, y) = crate::ui::layout::zone_center(crate::ui::layout::ERROR_OK_ZONE);
        self.menu_touch(x, y, false) == Some(true) && self.ad.navigation.app.state == expected
    }

    fn dismiss_scan_rejection_to_home(&mut self) -> bool {
        if !self.dismiss_rejected_to(AppState::ScanQR) { return false; }
        crate::runtime::interactions::camera_loop::route_camera_back(self.ad);
        super::root::home_ok(self.ad)
    }

    fn dismiss_confirm_rejection_to_home(&mut self) -> bool {
        if !self.dismiss_rejected_to(AppState::ConfirmTx) { return false; }
        self.tx_touch(20, 20, true) == Some(true) && super::root::home_ok(self.ad)
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
    if !super::root::home_ok(ad) || !fixture::install_wallet(ad) {
        return false;
    }
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let mut ctx = SigningContext { ad, display, i2c, sd, delay, list, up, down, backup_device: super::backup::WorkflowBackupDevice };
    log!("KASSIGNER_WORKFLOW_TESTS: SIGNING/REVIEW TRANCHE BEGIN");
    let mut summary = super::probe_status::ProbeSummary::new("SIGNING/REVIEW");

    summary.begin("INVALID-KSPT");
    let invalid_ok = prepare_probe(&mut ctx) && invalid_compact(&mut ctx);
    summary.record("INVALID-KSPT", invalid_ok);

    summary.begin("COMPACT-REVIEW");
    let review_ok = prepare_probe(&mut ctx) && compact_review_paths(&mut ctx);
    summary.record("COMPACT-REVIEW", review_ok);

    summary.begin("COMPACT-SIGN");
    let compact_ok = prepare_probe(&mut ctx) && compact_sign(&mut ctx);
    summary.record("COMPACT-SIGN", compact_ok);

    summary.begin("STANDARD-PSKT");
    let standard_ok = prepare_probe(&mut ctx) && standard_pskt_sign(&mut ctx);
    summary.record("STANDARD-PSKT", standard_ok);

    summary.begin("ANTI-KLEPTO");
    let anti_klepto_ok = prepare_probe(&mut ctx) && anti_klepto::exercise(&mut ctx);
    summary.record("ANTI-KLEPTO", anti_klepto_ok);

    summary.begin("FINISH-HOME");
    let finish_ok = finish(&mut ctx);
    summary.record("FINISH-HOME", finish_ok);
    let mut failure_mask = 0u16;
    if !invalid_ok { failure_mask |= 1u16 << 0; }
    if !review_ok { failure_mask |= 1u16 << 1; }
    if !compact_ok { failure_mask |= 1u16 << 2; }
    if !standard_ok { failure_mask |= 1u16 << 3; }
    if !anti_klepto_ok { failure_mask |= 1u16 << 4; }
    if !finish_ok { failure_mask |= 1u16 << 5; }
    FAILURE_MASK.store(failure_mask, Ordering::Relaxed);
    summary.finish(6)
}



pub(super) fn replay_standard_failure_detail() {
    if FAILURE_MASK.load(Ordering::Relaxed) & (1u16 << 3) == 0 { return; }
    const NAMES: [&str; 3] = ["FIXTURE", "PROCESS-REVIEW", "CONFIRM"];
    let stage = STANDARD_FAILURE_STAGE.load(Ordering::Relaxed);
    if let Some(name) = stage.checked_sub(1).and_then(|index| NAMES.get(usize::from(index))) {
        log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED STANDARD-PSKT STAGE {}", name);
        if *name == "PROCESS-REVIEW" {
            crate::runtime::interactions::tx::workflow_replay_standard_pskt_failure_reason();
        }
    } else {
        result::replay_failure_stage();
    }
}

fn prepare_probe(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if !super::reset_tranche_to_home(ctx.ad)
        || crate::runtime::presentation::operation_kind(ctx.ad).is_some()
    {
        log!("KASSIGNER_WORKFLOW_TESTS: SIGNING PROBE HOME/CANCEL RESET FAIL");
        return false;
    }
    ctx.ad.signing.zeroize_sensitive();
    ctx.ad.qr.clear_sensitive();
    fixture::install_wallet(ctx.ad)
}

fn begin_scan(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if !super::root::home_ok(ctx.ad) { return false; }
    let scan = crate::ui::layout::HOME_GRID_ZONES[1];
    crate::runtime::interactions::menu::handle_connected_root_probe(ctx.ad, scan.x + scan.w / 2, scan.y + scan.h / 2)
        && ctx.ad.navigation.app.state == AppState::ScanQR
}

fn process(ctx: &mut SigningContext<'_, '_, '_>, wire: &[u8], standard_pskt: bool) -> bool {
    if !begin_scan(ctx) { return false; }
    crate::runtime::interactions::camera_loop::workflow_process_transaction_payload(
        wire, standard_pskt, ctx.ad,
    );
    ctx.redraw_step();
    let ok = ctx.ad.navigation.app.state == AppState::ConfirmTx
        && ctx.ad.navigation.app.total_inputs == 2
        && ctx.ad.navigation.app.review_pages == 3;
    if !ok {
        log!(
            "KASSIGNER_WORKFLOW_TESTS: TX PROCESS-REVIEW FAIL standard={} state={:?} total_inputs={} review_pages={}",
            standard_pskt,
            ctx.ad.navigation.app.state,
            ctx.ad.navigation.app.total_inputs,
            ctx.ad.navigation.app.review_pages,
        );
        if standard_pskt {
            crate::runtime::interactions::tx::workflow_mark_standard_pskt_review_state_failure();
        }
    }
    ok
}

fn invalid_compact(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if !begin_scan(ctx) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX INVALID KSPT PROCESS BEGIN");
    crate::runtime::interactions::camera_loop::workflow_process_transaction_payload(
        b"KSPT\x04\x00", false, ctx.ad,
    );
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX INVALID KSPT PROCESS RETURNED");
    let rejected = ctx.ad.navigation.app.state == AppState::Rejected;
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX INVALID KSPT DISMISS BEGIN");
    let home = ctx.dismiss_scan_rejection_to_home();
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX INVALID KSPT DISMISS RETURNED");
    if rejected && home { log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX INVALID KSPT REJECT PASS"); }
    rejected && home
}

fn compact_review_paths(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    let Some(wire) = fixture::wire(ctx.ad, fixture::WireFormat::CompactKspt) else { return false; };
    if !process(ctx, &wire, false)
        || !review::open_review(ctx)
        || !review::inspect_all_inputs(ctx)
        || !review::review_back(ctx)
        || !review::confirm_back(ctx)
    { return false; }
    if !process(ctx, &wire, false) || !review::open_review(ctx) || !review::advance_review_to_confirm(ctx) || !review::confirm_back(ctx) { return false; }
    if !process(ctx, &wire, false) || !review::reject(ctx) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX REVIEW BACK/CONFIRM-BACK/REJECT PASS");
    true
}

fn compact_sign(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    let Some(wire) = fixture::wire(ctx.ad, fixture::WireFormat::CompactKspt) else { return false; };
    if !process(ctx, &wire, false) || !review::confirm(ctx) { return false; }
    ctx.ad.navigation.app.review_authorized = false;
    if !ctx.activate_signing_operation()
        || crate::runtime::signing::workflow_signing_step(ctx.ad)
        || ctx.ad.navigation.app.state != AppState::Rejected
        || !ctx.dismiss_confirm_rejection_to_home()
    { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX REVIEW-AUTHORIZATION REJECT PASS");
    if !process(ctx, &wire, false) || !review::confirm(ctx) { return false; }
    result::sign_and_present(ctx, b"KSPT")
}

fn standard_pskt_sign(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    STANDARD_FAILURE_STAGE.store(1, Ordering::Relaxed);
    let Some(wire) = fixture::wire(ctx.ad, fixture::WireFormat::StandardPskt) else { return false; };
    STANDARD_FAILURE_STAGE.store(2, Ordering::Relaxed);
    if !process(ctx, &wire, true) { return false; }
    STANDARD_FAILURE_STAGE.store(3, Ordering::Relaxed);
    if !review::confirm(ctx) { return false; }
    STANDARD_FAILURE_STAGE.store(4, Ordering::Relaxed);
    let ok = result::sign_and_present(ctx, b"PSKT");
    if ok {
        STANDARD_FAILURE_STAGE.store(0, Ordering::Relaxed);
        log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX STANDARD PSKT PARSE/SIGN PASS");
    }
    ok
}

fn finish(ctx: &mut SigningContext<'_, '_, '_>) -> bool {
    if !super::root::home_ok(ctx.ad) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SIGN TX RTC/PERSISTENT POLICY ENFORCEMENT DEFERRED TO SECURITY HIL");
    log!("KASSIGNER_WORKFLOW_TESTS: SIGNING/REVIEW TRANCHE PASS");
    true
}
