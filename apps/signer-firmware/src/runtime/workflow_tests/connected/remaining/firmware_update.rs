//! Connected firmware-update USB-guidance coverage.

use crate::runtime::{data::AppData, input::AppState, interactions::TouchInput};

pub(super) fn exercise(ad: &mut AppData) -> bool {
    if !enter_firmware_update(ad)
        || ad.navigation.app.state != AppState::FirmwareUpdateReady
        || ad.navigation.owner != crate::runtime::navigation::NavigationOwner::Settings
    { return false; }
    let back = TouchInput { x: 0, y: 0, is_back: true };
    if crate::runtime::interactions::settings::handle_advanced_navigation(ad, back) != Some(true)
        || ad.navigation.app.state != AppState::AdvancedMenu
    { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: FIRMWARE UPDATE USB GUIDANCE PASS");
    true
}

fn enter_firmware_update(ad: &mut AppData) -> bool {
    crate::runtime::effects::home(ad);
    let settings = crate::ui::layout::HOME_GRID_ZONES[3];
    if !crate::runtime::interactions::menu::handle_connected_root_probe(
        ad, settings.x + settings.w / 2, settings.y + settings.h / 2,
    ) || ad.navigation.app.state != AppState::SettingsMenu
    {
        return false;
    }

    // The Settings menu has six entries; page to rows 4-5 exactly as the
    // production UI does before selecting absolute item 4 (Advanced).
    let (_, list, _up, down) = crate::runtime::touch_dispatch::touch_zones();
    ad.navigation.settings_menu.reset();
    if crate::runtime::interactions::settings::handle_settings_menu_navigation(
        ad, &list, &_up, &down,
        TouchInput::new(down.x + 20, down.y + 20, false),
    ) != Some(true) || ad.navigation.settings_menu.scroll != 4
    {
        return false;
    }
    let advanced = list[0];
    if crate::runtime::interactions::settings::handle_settings_menu_navigation(
        ad, &list, &_up, &down,
        TouchInput::new(advanced.x + advanced.w / 2, advanced.y + advanced.h / 2, false),
    ) != Some(true) || ad.navigation.app.state != AppState::AdvancedMenu
    {
        return false;
    }

    crate::runtime::interactions::menu::primary::workflow_advanced_select(ad, 0)
        && ad.navigation.app.state == AppState::FirmwareUpdateReady
        && crate::runtime::navigation::reconcile(ad)
}
