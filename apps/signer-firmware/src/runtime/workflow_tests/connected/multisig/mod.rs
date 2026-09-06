use crate::{
    runtime::interactions::{TouchInput, tx::TxTouchContext},
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::{data::AppData, input::AppState},
};
use core::sync::atomic::{AtomicU8, Ordering};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

mod configuration;
mod cosigners;
mod output;
mod signing;

const PROBE_ENTER_CONFIG: u8 = 1 << 0;
const PROBE_COSIGNERS: u8 = 1 << 1;
const PROBE_OUTPUT: u8 = 1 << 2;
const PROBE_SIGNING: u8 = 1 << 3;
const PROBE_FINISH_HOME: u8 = 1 << 4;
static FAILED_PROBES: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy)]
pub(super) struct FailureSnapshot {
    failed_probes: u8,
    output_stage: u8,
    signing_stage: u8,
}

fn record_probe(
    summary: &mut super::probe_status::ProbeSummary,
    bit: u8,
    name: &'static str,
    result: bool,
) {
    if !result {
        FAILED_PROBES.fetch_or(bit, Ordering::Relaxed);
    }
    summary.record(name, result);
}

pub(super) fn snapshot_failures() -> FailureSnapshot {
    FailureSnapshot {
        failed_probes: FAILED_PROBES.load(Ordering::Relaxed),
        output_stage: output::failure_stage(),
        signing_stage: signing::failure_stage(),
    }
}

pub(super) fn replay_snapshot(snapshot: FailureSnapshot) {
    log!(
        "KASSIGNER_WORKFLOW_TESTS: CONNECTED MULTISIG FAILURE SNAPSHOT probes=0x{:02x} output_stage={} signing_stage={}",
        snapshot.failed_probes,
        snapshot.output_stage,
        snapshot.signing_stage,
    );
    for (bit, name) in [
        (PROBE_ENTER_CONFIG, "ENTER-CONFIG"),
        (PROBE_COSIGNERS, "COSIGNERS"),
        (PROBE_OUTPUT, "OUTPUT"),
        (PROBE_SIGNING, "SIGNING"),
        (PROBE_FINISH_HOME, "FINISH-HOME"),
    ] {
        if snapshot.failed_probes & bit != 0 {
            log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED MULTISIG PROBE {}", name);
        }
    }
    if snapshot.failed_probes & PROBE_OUTPUT != 0 {
        output::replay_failure_stage(snapshot.output_stage);
    }
    if snapshot.failed_probes & PROBE_SIGNING != 0 {
        signing::replay_failure_stage(snapshot.signing_stage);
    }
}

pub(super) fn replay_failures() {
    let snapshot = snapshot_failures();
    log!(
        "KASSIGNER_WORKFLOW_TESTS: CONNECTED MULTISIG FAILURE SNAPSHOT probes=0x{:02x} output_stage={} signing_stage={}",
        snapshot.failed_probes,
        snapshot.output_stage,
        snapshot.signing_stage,
    );
    for (bit, name) in [
        (PROBE_ENTER_CONFIG, "ENTER-CONFIG"),
        (PROBE_COSIGNERS, "COSIGNERS"),
        (PROBE_OUTPUT, "OUTPUT"),
        (PROBE_SIGNING, "SIGNING"),
        (PROBE_FINISH_HOME, "FINISH-HOME"),
    ] {
        if snapshot.failed_probes & bit != 0 {
            log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED MULTISIG PROBE {}", name);
        }
    }
    if snapshot.failed_probes & PROBE_OUTPUT != 0 {
        output::replay_failure();
    }
    if snapshot.failed_probes & PROBE_SIGNING != 0 {
        signing::replay_failure();
    }
}

pub(super) struct MultisigContext<'ctx, 'display, 'hal> {
    pub(super) ad: &'ctx mut AppData,
    pub(super) display: &'ctx mut BootDisplay<'display>,
    pub(super) i2c: &'ctx mut I2c<'hal, Blocking>,
    pub(super) sd: &'ctx Option<SdCardType>,
    pub(super) delay: &'ctx mut Delay,
    pub(super) grid: [TouchZone; 4],
    pub(super) list: [TouchZone; 4],
    pub(super) up: TouchZone,
    pub(super) down: TouchZone,
}

impl MultisigContext<'_, '_, '_> {
    pub(super) fn redraw_step(&mut self) {
        super::redraw_step(self.ad, self.display, self.i2c, self.sd);
        super::show_step(self.delay);
    }

    pub(super) fn tx_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::tx::handle_tx_touch(TxTouchContext {
            ad: self.ad,
            boot_display: self.display,
            delay: self.delay,
            liveness: &mut || {}, i2c: self.i2c,
            sd_card_type: self.sd,
            list_zones: &self.list,
            input: TouchInput::new(x, y, is_back),
        })
    }

    pub(super) fn menu_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::menu::handle_navigation_touch(
            self.ad, &self.grid, &self.list, &self.up, &self.down, TouchInput::new(x, y, is_back),
        )
    }

    pub(super) fn seed_navigation_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::seed::handle_navigation_touch(
            self.ad, TouchInput::new(x, y, is_back),
        )
    }

    pub(super) fn signing_feedback_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::menu::handle_signing_feedback_touch(
            self.ad, self.display, self.delay, &mut || {}, &self.list, TouchInput::new(x, y, is_back),
        )
    }

    pub(super) fn export_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::export::handle_export_touch(crate::runtime::interactions::export::ExportTouchContext {
            ad: self.ad,
            boot_display: self.display,
            delay: self.delay,
            liveness: &mut || {}, i2c: self.i2c,
            sd_card_type: self.sd,
            list_zones: &self.list,
            page_up_zone: &self.up,
            page_down_zone: &self.down,
            input: TouchInput::new(x, y, is_back),
        })
    }
}

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    FAILED_PROBES.store(0, Ordering::Relaxed);
    if !crate::services::wallet_session::install_workflow_multisig_mnemonic_inventory(ad) {
        FAILED_PROBES.store(PROBE_ENTER_CONFIG, Ordering::Relaxed);
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG FIXTURE FAIL");
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG MNEMONIC FIXTURE READY 5");
    let (grid, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let mut ctx = MultisigContext {
        ad,
        display,
        i2c,
        sd,
        delay,
        grid,
        list,
        up,
        down,
    };
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG TRANCHE BEGIN");
    let mut summary = super::probe_status::ProbeSummary::new("MULTISIG");

    summary.begin("ENTER-CONFIG");
    let configuration_ok = enter_multisig_menu(&mut ctx) && configuration::exercise(&mut ctx);
    record_probe(&mut summary, PROBE_ENTER_CONFIG, "ENTER-CONFIG", configuration_ok);

    summary.begin("COSIGNERS");
    let cosigners_ok = if configuration_ok {
        cosigners::exercise(&mut ctx)
    } else {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG PROBE COSIGNERS SKIPPED; CONFIG PREREQUISITE FAILED");
        false
    };
    record_probe(&mut summary, PROBE_COSIGNERS, "COSIGNERS", cosigners_ok);

    summary.begin("OUTPUT");
    let output_ok = if cosigners_ok {
        output::exercise(&mut ctx)
    } else {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG PROBE OUTPUT SKIPPED; COSIGNER PREREQUISITE FAILED");
        false
    };
    record_probe(&mut summary, PROBE_OUTPUT, "OUTPUT", output_ok);

    summary.begin("SIGNING");
    // Signing owns a fresh deterministic fixture and production Scan QR entry,
    // so attempt it even when the independent descriptor/output probe failed.
    // The earlier failure remains recorded and still fails the tranche.
    let signing_ok = signing::exercise(&mut ctx);
    record_probe(&mut summary, PROBE_SIGNING, "SIGNING", signing_ok);

    summary.begin("FINISH-HOME");
    let finish_ok = finish_home(&mut ctx);
    record_probe(&mut summary, PROBE_FINISH_HOME, "FINISH-HOME", finish_ok);
    summary.finish(5)
}

fn enter_multisig_menu(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    crate::runtime::effects::home(ctx.ad);
    if !crate::runtime::interactions::menu::handle_root_touch(ctx.ad, 82, 188)
        || ctx.ad.navigation.app.state != AppState::SeedsMenu
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG ENTER CONFIG WALLET ROUTE OK");
    if !crate::runtime::interactions::menu::primary::workflow_wallet_select(ctx.ad, 4)
        || ctx.ad.navigation.app.state != AppState::MultisigMenu
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG ENTER CONFIG MENU ROUTE OK");
    ctx.redraw_step();
    true
}

fn finish_home(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    crate::runtime::effects::home(ctx.ad);
    let ok = super::root::home_ok(ctx.ad);
    if ok {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG PHYSICAL QR/SD HIL DEFERRED TO PERIPHERAL TRANCHE");
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG TRANCHE PASS");
    }
    ok
}
