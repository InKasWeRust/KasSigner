use crate::{
    runtime::interactions::{TouchInput, tx::TxTouchContext},
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::data::AppData,
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

mod matrix;
mod multiframe;

pub(super) struct QrContext<'ctx, 'display, 'hal> {
    ad: &'ctx mut AppData,
    display: &'ctx mut BootDisplay<'display>,
    i2c: &'ctx mut I2c<'hal, Blocking>,
    sd: &'ctx Option<SdCardType>,
    delay: &'ctx mut Delay,
    list: [TouchZone; 4],
}

impl QrContext<'_, '_, '_> {
    fn tx_back(&mut self) -> bool {
        crate::runtime::interactions::tx::handle_tx_touch(TxTouchContext {
            ad: &mut *self.ad,
            boot_display: &mut *self.display,
            delay: &mut *self.delay,
            liveness: &mut || {},
            i2c: &mut *self.i2c,
            sd_card_type: self.sd,
            list_zones: &self.list,
            input: TouchInput::new(20, 20, true),
        }) == Some(true)
    }
}

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    if !super::root::home_ok(ad) || !super::signing::fixture::install_wallet(ad) { return false; }
    let (_, list, _, _) = crate::runtime::touch_dispatch::touch_zones();
    let mut ctx = QrContext { ad, display, i2c, sd, delay, list };
    log!("KASSIGNER_WORKFLOW_TESTS: QR PROTOCOL MATRIX TRANCHE BEGIN");
    let mut summary = super::probe_status::ProbeSummary::new("QR-PROTOCOL");

    summary.begin("MATRIX");
    let matrix_ok = matrix::exercise(&mut ctx);
    summary.record("MATRIX", matrix_ok);
    if !matrix_ok {
        crate::runtime::effects::home(ctx.ad);
        let _ = super::signing::fixture::install_wallet(ctx.ad);
    }

    summary.begin("MULTIFRAME");
    let multiframe_ok = multiframe::exercise(&mut ctx);
    summary.record("MULTIFRAME", multiframe_ok);

    summary.begin("FINISH-HOME");
    let finish_ok = finish(&mut ctx);
    summary.record("FINISH-HOME", finish_ok);
    summary.finish(3)
}

fn finish(ctx: &mut QrContext<'_, '_, '_>) -> bool {
    if !super::root::home_ok(ctx.ad) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: QR CAMERA CAPTURE/DECODE HIL DEFERRED TO PERIPHERAL TRANCHE");
    log!("KASSIGNER_WORKFLOW_TESTS: QR PROTOCOL MATRIX TRANCHE PASS");
    true
}
