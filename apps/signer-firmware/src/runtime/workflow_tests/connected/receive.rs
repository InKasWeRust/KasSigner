use crate::{
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::{data::AppData, input::AppState},
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

struct ReceiveContext<'ctx, 'display, 'hal> {
    ad: &'ctx mut AppData,
    display: &'ctx mut BootDisplay<'display>,
    i2c: &'ctx mut I2c<'hal, Blocking>,
    sd: &'ctx Option<SdCardType>,
    delay: &'ctx mut Delay,
    list: [TouchZone; 4],
    up: TouchZone,
    down: TouchZone,
}

impl ReceiveContext<'_, '_, '_> {
    fn touch(&mut self, x: u16, y: u16) -> bool {
        let input = crate::runtime::touch_dispatch::physical_touch_input(x, y);
        crate::runtime::interactions::export::handle_export_touch(
            crate::runtime::interactions::export::ExportTouchContext {
                ad: &mut *self.ad,
                boot_display: &mut *self.display,
                delay: &mut *self.delay,
                liveness: &mut || {},
                i2c: &mut *self.i2c,
                sd_card_type: self.sd,
                list_zones: &self.list,
                page_up_zone: &self.up,
                page_down_zone: &self.down,
                input,
            },
        )
        .unwrap_or(false)
    }

    fn redraw(&mut self) {
        super::redraw_step(
            &mut *self.ad,
            &mut *self.display,
            &mut *self.i2c,
            self.sd,
        );
    }

    fn show_step(&mut self) {
        super::show_step(&mut *self.delay);
    }
}

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let mut ctx = ReceiveContext {
        ad,
        display,
        i2c,
        sd,
        delay,
        list,
        up,
        down,
    };
    log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE CONTROLS BEGIN");

    // workflow-runtime-auto deliberately disables the old public-key fixture.
    // Install a deterministic mnemonic test wallet and run the real production
    // derivation so Receive exercises genuine address data instead of a fake
    // cache. The later runtime-GUI tranche separately proves the cooperative
    // Core1 address-cache driver under the physical watchdog.
    if !super::signing::fixture::install_wallet(ctx.ad) {
        log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE REAL DERIVATION FAILED");
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE REAL DERIVATION READY");
    if !open_receive(ctx.ad) {
        log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE ROUTE FAILED");
        return false;
    }

    qr_round_trip(&mut ctx)
        && chain_toggle(&mut ctx)
        && index_step_boundaries(&mut ctx)
        && custom_index(&mut ctx)
        && return_home(&mut ctx)
}

fn open_receive(ad: &mut AppData) -> bool {
    crate::runtime::effects::home(ad);
    let zone = crate::ui::layout::HOME_GRID_ZONES[2];
    crate::runtime::interactions::menu::handle_connected_root_probe(
        ad,
        zone.x + zone.w / 2,
        zone.y + zone.h / 2,
    )
        && ad.navigation.app.state == AppState::SeedsMenu
        && crate::runtime::navigation::reconcile(ad)
        && crate::runtime::interactions::menu::primary::workflow_wallet_select(ad, 0)
        && ad.navigation.app.state == AppState::ShowAddress
        && crate::runtime::navigation::reconcile(ad)
}

fn qr_round_trip(ctx: &mut ReceiveContext<'_, '_, '_>) -> bool {
    let (qr_x, qr_y) = crate::ui::layout::zone_center(crate::ui::layout::ADDRESS_QR_ZONE);
    if !ctx.touch(qr_x, qr_y)
        || ctx.ad.navigation.app.state != AppState::ShowAddressQR
        || !crate::runtime::navigation::reconcile(ctx.ad)
    {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    let (back_x, back_y) = crate::ui::layout::zone_center(crate::ui::layout::BACK_ZONE);
    if !ctx.touch(back_x, back_y)
        || ctx.ad.navigation.app.state != AppState::ShowAddress
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE QR OPEN/CLOSE OK");
    true
}

fn chain_toggle(ctx: &mut ReceiveContext<'_, '_, '_>) -> bool {
    if ctx.ad.wallet.addresses.view_is_change {
        return false;
    }
    let (x, y) = crate::ui::layout::zone_center(crate::ui::layout::ADDRESS_CHAIN_ZONE);
    if !ctx.touch(x, y)
        || !ctx.ad.wallet.addresses.view_is_change
        || ctx.ad.wallet.addresses.current_addr_index != 0
    {
        return false;
    }
    if !ctx.touch(x, y) || ctx.ad.wallet.addresses.view_is_change {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE CHAIN TOGGLE OK");
    true
}

fn index_step_boundaries(ctx: &mut ReceiveContext<'_, '_, '_>) -> bool {
    let (prev_x, prev_y) = crate::ui::layout::zone_center(crate::ui::layout::ADDRESS_PREV_ZONE);
    if ctx.touch(prev_x, prev_y) {
        return false;
    }
    if ctx.ad.wallet.addresses.current_addr_index != 0 {
        return false;
    }
    let (next_x, next_y) = crate::ui::layout::zone_center(crate::ui::layout::ADDRESS_NEXT_ZONE);
    if !ctx.touch(next_x, next_y)
        || ctx.ad.wallet.addresses.current_addr_index != 1
    {
        return false;
    }
    if !ctx.touch(prev_x, prev_y)
        || ctx.ad.wallet.addresses.current_addr_index != 0
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE INDEX STEP/BOUNDARY OK");
    true
}

fn custom_index(ctx: &mut ReceiveContext<'_, '_, '_>) -> bool {
    let (index_x, index_y) = crate::ui::layout::zone_center(crate::ui::layout::ADDRESS_INDEX_ZONE);
    if !ctx.touch(index_x, index_y)
        || ctx.ad.navigation.app.state != AppState::AddrIndexPicker
    {
        return false;
    }
    enter_repeated_digit(ctx);
    if ctx.ad.wallet.addresses.input_len != 5 {
        return false;
    }
    clear_index(ctx);
    submit_index_three(ctx)
}

fn enter_repeated_digit(ctx: &mut ReceiveContext<'_, '_, '_>) {
    for _ in 0..6 {
        let _ = ctx.touch(75, 90);
    }
}

fn clear_index(ctx: &mut ReceiveContext<'_, '_, '_>) {
    let _ = ctx.touch(75, 190);
}

fn submit_index_three(ctx: &mut ReceiveContext<'_, '_, '_>) -> bool {
    if ctx.ad.wallet.addresses.input_len != 0 {
        return false;
    }
    let _ = ctx.touch(230, 90);
    if !ctx.touch(230, 190)
        || ctx.ad.navigation.app.state != AppState::ShowAddress
        || ctx.ad.wallet.addresses.current_addr_index != 3
    {
        return false;
    }
    let (qr_x, qr_y) = crate::ui::layout::zone_center(crate::ui::layout::ADDRESS_QR_ZONE);
    let (back_x, back_y) = crate::ui::layout::zone_center(crate::ui::layout::BACK_ZONE);
    if !ctx.touch(qr_x, qr_y)
        || ctx.ad.navigation.app.state != AppState::ShowAddressQR
        || ctx.ad.wallet.addresses.current_addr_index != 3
        || !ctx.touch(back_x, back_y)
        || ctx.ad.navigation.app.state != AppState::ShowAddress
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE CUSTOM INDEX OK");
    log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE CUSTOM INDEX/QR JOURNEY OK");
    true
}

fn return_home(ctx: &mut ReceiveContext<'_, '_, '_>) -> bool {
    let (x, y) = crate::ui::layout::zone_center(crate::ui::layout::BACK_ZONE);
    if !ctx.touch(x, y)
        || ctx.ad.navigation.app.state != AppState::SeedsMenu
        || !crate::runtime::navigation::reconcile(ctx.ad)
    {
        return false;
    }
    let input = crate::runtime::touch_dispatch::physical_touch_input(x, y);
    if crate::runtime::interactions::menu::handle_navigation_touch(
        ctx.ad,
        &crate::ui::layout::HOME_GRID_ZONES,
        &ctx.list,
        &ctx.up,
        &ctx.down,
        input,
    ) != Some(true)
        || !super::root::home_ok(ctx.ad)
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE CONTROLS PASS");
    true
}
