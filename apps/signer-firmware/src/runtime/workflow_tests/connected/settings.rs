use crate::{
    runtime::interactions::TouchInput,
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::{data::AppData, input::AppState},
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

struct SettingsContext<'ctx, 'display, 'hal> {
    ad: &'ctx mut AppData,
    display: &'ctx mut BootDisplay<'display>,
    i2c: &'ctx mut I2c<'hal, Blocking>,
    sd: &'ctx Option<SdCardType>,
    delay: &'ctx mut Delay,
    list: [TouchZone; 4],
    up: TouchZone,
    down: TouchZone,
}

impl SettingsContext<'_, '_, '_> {
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

    fn select(&mut self, x: u16, y: u16) -> bool {
        crate::runtime::interactions::settings::handle_settings_menu_navigation(
            &mut *self.ad,
            &self.list,
            &self.up,
            &self.down,
            TouchInput::new(x, y, false),
        ) == Some(true)
    }

    fn page(&mut self, upward: bool) -> bool {
        let zone = if upward { self.up } else { self.down };
        self.select(zone.x + zone.w / 2, zone.y + zone.h / 2)
    }

    fn open(&mut self, item: usize, expected: AppState) -> bool {
        self.ad.navigation.settings_menu.reset();
        if item >= 4 && !self.page(false) {
            return false;
        }
        let zone = self.list[item % 4];
        if !self.select(zone.x + zone.w / 2, zone.y + zone.h / 2) {
            return false;
        }
        self.ad.navigation.app.state == expected && crate::runtime::navigation::reconcile(self.ad)
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
    let mut ctx = SettingsContext {
        ad,
        display,
        i2c,
        sd,
        delay,
        list,
        up,
        down,
    };
    log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS EXHAUSTIVE ROOT BEGIN");

    if ctx.select(320, 235) {
        return false;
    }
    if ctx.ad.navigation.app.state != AppState::SettingsMenu {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS OUTSIDE-ITEM NOOP OK");

    if !display_settings(&mut ctx) {
        return false;
    }
    #[cfg(feature = "m5stack")]
    if !audio_settings(&mut ctx) || !global_audio_control(&mut ctx) {
        return false;
    }
    #[cfg(feature = "waveshare")]
    if !camera_settings(&mut ctx) {
        return false;
    }
    if !remaining_routes(&mut ctx) { return false; }

    let back = TouchInput::new(20, 20, true);
    if crate::runtime::interactions::settings::handle_settings_menu_navigation(
        &mut *ctx.ad,
        &ctx.list,
        &ctx.up,
        &ctx.down,
        back,
    ) != Some(true)
        || !super::root::home_ok(ctx.ad)
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS ROOT ITEMS PASS 6/6");
    true
}

fn remaining_routes(ctx: &mut SettingsContext<'_, '_, '_>) -> bool {
    if !simple_item(ctx, 2, AppState::AdvancedFeatures, back_security)
        || !simple_item(ctx, 3, AppState::SdCardSettings, back_storage)
    {
        return false;
    }
    if !ctx.page(false) || ctx.ad.navigation.settings_menu.scroll != 4
        || !ctx.page(true) || ctx.ad.navigation.settings_menu.scroll != 0
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS PAGING BOUNDARIES OK");
    advanced_menu_flow(ctx)
        && simple_item(ctx, 5, AppState::About, back_about)
}

fn advanced_menu_flow(ctx: &mut SettingsContext<'_, '_, '_>) -> bool {
    if !ctx.open(4, AppState::AdvancedMenu) {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    if !crate::runtime::interactions::menu::primary::workflow_advanced_select(ctx.ad, 1)
        || ctx.ad.navigation.app.state != AppState::FactoryResetWarning
    {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    if crate::runtime::interactions::settings::handle_advanced_navigation(
        ctx.ad,
        TouchInput::new(240, 210, false),
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::FactoryResetConfirm
    {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    if crate::runtime::interactions::settings::handle_advanced_navigation(
        ctx.ad,
        TouchInput::new(80, 210, false),
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::AdvancedMenu
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: FACTORY RESET WARN/CONFIRM/CANCEL OK");
    owner_firmware_flow(ctx) && back_advanced(ctx.ad)
}

fn owner_firmware_flow(ctx: &mut SettingsContext<'_, '_, '_>) -> bool {
    if !crate::runtime::interactions::menu::primary::workflow_advanced_select(ctx.ad, 2)
        || ctx.ad.navigation.app.state != AppState::OwnerFirmwareMenu
    {
        return false;
    }
    ctx.redraw();
    ctx.show_step();

    if !crate::runtime::interactions::menu::primary::workflow_owner_firmware_select(ctx.ad, 0)
        || ctx.ad.navigation.app.state != AppState::OwnerKeyWarning
    {
        return false;
    }
    ctx.redraw();
    if crate::runtime::interactions::settings::handle_advanced_navigation(
        ctx.ad,
        TouchInput::new(240, 210, false),
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::OwnerKeyConfirm
    {
        return false;
    }
    ctx.redraw();
    if crate::runtime::interactions::settings::handle_advanced_navigation(
        ctx.ad,
        TouchInput::new(20, 20, true),
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::OwnerFirmwareMenu
    {
        return false;
    }

    if !crate::runtime::interactions::menu::primary::workflow_owner_firmware_select(ctx.ad, 1)
        || ctx.ad.navigation.app.state != AppState::OwnerInstallWarning
    {
        return false;
    }
    ctx.redraw();
    if crate::runtime::interactions::settings::handle_advanced_navigation(
        ctx.ad,
        TouchInput::new(240, 210, false),
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::OwnerInstallConfirm
    {
        return false;
    }
    ctx.redraw();
    if crate::runtime::interactions::settings::handle_advanced_navigation(
        ctx.ad,
        TouchInput::new(20, 20, true),
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::OwnerFirmwareMenu
        || !crate::runtime::interactions::menu::primary::workflow_owner_firmware_back(ctx.ad)
        || ctx.ad.navigation.app.state != AppState::AdvancedMenu
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS OWNER FIRMWARE WARN/CONFIRM/BACK PASS");
    true
}

#[cfg(feature = "waveshare")]
fn display_settings(ctx: &mut SettingsContext<'_, '_, '_>) -> bool {
    if !ctx.open(0, AppState::DisplaySettings) {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    let result = crate::runtime::interactions::settings::handle_settings_touch(
        crate::runtime::interactions::settings::SettingsTouchContext {
            ad: &mut *ctx.ad,
            boot_display: &mut *ctx.display,
            delay: &mut *ctx.delay,
            i2c: &mut *ctx.i2c,
            sd_card_type: ctx.sd,
            input: TouchInput::new(20, 20, true),
        },
    );
    let ok = result == Some(true) && ctx.ad.navigation.app.state == AppState::SettingsMenu;
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS DISPLAY ROUTE/BACK OK"); }
    ok
}

#[cfg(feature = "waveshare")]
fn camera_settings(ctx: &mut SettingsContext<'_, '_, '_>) -> bool {
    if !ctx.open(1, AppState::CameraSettings) {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    let result = crate::runtime::interactions::settings::handle_settings_touch(
        crate::runtime::interactions::settings::SettingsTouchContext {
            ad: &mut *ctx.ad,
            boot_display: &mut *ctx.display,
            delay: &mut *ctx.delay,
            i2c: &mut *ctx.i2c,
            sd_card_type: ctx.sd,
            input: TouchInput::new(20, 20, true),
        },
    );
    let ok = result == Some(true) && ctx.ad.navigation.app.state == AppState::SettingsMenu;
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS CAMERA ROUTE/BACK OK"); }
    ok
}

#[cfg(feature = "m5stack")]
fn display_settings(ctx: &mut SettingsContext<'_, '_, '_>) -> bool {
    if !ctx.open(0, AppState::DisplaySettings) {
        return false;
    }
    ctx.redraw();
    ctx.show_step();

    ctx.ad.settings.brightness = 0;
    if crate::runtime::interactions::settings::handle_display_settings_navigation(
        &mut *ctx.ad,
        TouchInput::new(40, 95, false),
    ) != Some(false)
        || ctx.ad.settings.brightness != 0
    {
        return false;
    }
    ctx.ad.settings.brightness = 255;
    if crate::runtime::interactions::settings::handle_display_settings_navigation(
        &mut *ctx.ad,
        TouchInput::new(280, 95, false),
    ) != Some(false)
        || ctx.ad.settings.brightness != 255
    {
        return false;
    }
    if crate::runtime::interactions::settings::handle_display_settings_navigation(
        &mut *ctx.ad,
        TouchInput::new(160, 95, false),
    ) != Some(true)
        || ctx.ad.settings.brightness != 127
    {
        return false;
    }
    let mut applied = 0;
    crate::runtime::power_state::apply_requested_brightness(&mut *ctx.ad, &mut *ctx.i2c, &mut applied);
    if applied != 127 {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS DISPLAY BOUNDARIES/HIL OK");
    crate::runtime::interactions::settings::handle_display_settings_navigation(
        &mut *ctx.ad,
        TouchInput::new(20, 20, true),
    ) == Some(true)
        && ctx.ad.navigation.app.state == AppState::SettingsMenu
}

#[cfg(feature = "m5stack")]
fn audio_settings(ctx: &mut SettingsContext<'_, '_, '_>) -> bool {
    if !ctx.open(1, AppState::AudioSettings) {
        return false;
    }
    ctx.redraw();
    ctx.show_step();

    ctx.ad.settings.set_volume(0);
    if crate::runtime::interactions::settings::handle_audio_settings_navigation(
        &mut *ctx.ad,
        TouchInput::new(40, 95, false),
    ) != Some(false)
        || ctx.ad.settings.volume != 0
    {
        return false;
    }
    ctx.ad.settings.set_volume(255);
    if crate::runtime::interactions::settings::handle_audio_settings_navigation(
        &mut *ctx.ad,
        TouchInput::new(280, 95, false),
    ) != Some(false)
        || ctx.ad.settings.volume != 255
    {
        return false;
    }
    if crate::runtime::interactions::settings::handle_audio_settings_navigation(
        &mut *ctx.ad,
        TouchInput::new(160, 95, false),
    ) != Some(true)
        || ctx.ad.settings.volume != 127
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS AUDIO BOUNDARIES OK");
    crate::runtime::interactions::settings::handle_audio_settings_navigation(
        &mut *ctx.ad,
        TouchInput::new(20, 20, true),
    ) == Some(true)
        && ctx.ad.navigation.app.state == AppState::SettingsMenu
}

#[cfg(feature = "m5stack")]
fn global_audio_control(ctx: &mut SettingsContext<'_, '_, '_>) -> bool {
    if ctx.ad.navigation.app.state != AppState::SettingsMenu {
        return false;
    }
    ctx.ad.settings.set_volume(127);
    let before = ctx.ad.settings.audio_muted();
    if crate::ui::layout::audio_toggle_zone(ctx.ad.navigation.app.state)
        .is_some_and(|zone| zone.contains(95, 24))
        || ctx.ad.settings.audio_muted() != before
    {
        return false;
    }
    if !crate::ui::layout::audio_toggle_zone(ctx.ad.navigation.app.state)
        .is_some_and(|zone| zone.contains(70, 24))
    {
        return false;
    }
    let muted_volume = crate::runtime::event_loop::audio::toggle_global_mute(ctx.ad);
    if !ctx.ad.settings.audio_muted() || muted_volume != 0 {
        return false;
    }
    let restored_volume = crate::runtime::event_loop::audio::toggle_global_mute(ctx.ad);
    if ctx.ad.settings.audio_muted() || restored_volume == 0 {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: GLOBAL AUDIO TOGGLE/NEARBY-NOOP OK");
    true
}

fn simple_item(
    ctx: &mut SettingsContext<'_, '_, '_>,
    item: usize,
    expected: AppState,
    back: fn(&mut AppData) -> bool,
) -> bool {
    if !ctx.open(item, expected) {
        return false;
    }
    ctx.redraw();
    log!(
        "KASSIGNER_WORKFLOW_TESTS: SETTINGS ITEM {} SCREEN {:?}",
        item,
        expected
    );
    ctx.show_step();
    back(&mut *ctx.ad)
        && ctx.ad.navigation.app.state == AppState::SettingsMenu
        && crate::runtime::navigation::reconcile(ctx.ad)
}

fn back_security(ad: &mut AppData) -> bool {
    crate::runtime::interactions::settings::handle_advanced_navigation(ad, TouchInput::new(20, 20, true))
        == Some(true)
}

fn back_storage(ad: &mut AppData) -> bool {
    crate::runtime::interactions::settings::handle_sd_settings_navigation(ad, TouchInput::new(20, 20, true))
        == Some(true)
}

fn back_advanced(ad: &mut AppData) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS ADVANCED BACK BEGIN");
    if ad.navigation.app.state != AppState::AdvancedMenu {
        return false;
    }
    let handled = crate::runtime::navigation::handle_back(ad);
    let ok = handled
        && ad.navigation.app.state == AppState::SettingsMenu
        && crate::runtime::navigation::reconcile(ad);
    if ok {
        log!("KASSIGNER_WORKFLOW_TESTS: SETTINGS ADVANCED BACK OK");
    }
    ok
}

fn back_about(ad: &mut AppData) -> bool {
    crate::runtime::interactions::settings::handle_about_navigation(ad, TouchInput::new(20, 20, true))
        == Some(true)
}
