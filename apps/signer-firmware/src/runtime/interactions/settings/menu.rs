//! Production Settings root controller.

use super::{touch, AppData};
use crate::runtime::interactions::menu_selection::{handle_paged_menu_touch, PagedMenuAction};

pub(super) fn handle_settings_menu(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.navigation.settings_menu.reset();
        crate::runtime::effects::home(ad);
        return true;
    }
    match handle_paged_menu_touch(&mut ad.navigation.settings_menu, list_zones, page_up_zone, page_down_zone, x, y) {
        PagedMenuAction::PageChanged => true,
        PagedMenuAction::Selected(item) => { open_setting(ad, usize::from(item)); true }
        PagedMenuAction::None => false,
    }
}

fn open_setting(ad: &mut AppData, item: usize) {
    #[cfg(feature = "m5stack")]
    open_m5stack_setting(ad, item);
    #[cfg(feature = "waveshare")]
    open_waveshare_setting(ad, item);
    #[cfg(feature = "qemu")]
    open_qemu_setting(ad, item);
}

#[cfg(feature = "m5stack")]
fn open_m5stack_setting(ad: &mut AppData, item: usize) {
    match item {
        2 => { open_security(ad); return; }
        4 => ad.navigation.production.advanced_menu =
            crate::runtime::input::Menu::from_items(crate::runtime::navigation::production::advanced_items()),
        #[cfg(feature = "developer-ui")]
        6 => {
            // Developer UI is intentionally outside the consumer production graph.
            ad.navigation.production.developer_menu.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(DeveloperMenu));
            return;
        }
        _ => {}
    }
    let Ok(index) = u8::try_from(item) else { return; };
    let _ = crate::runtime::effects::menu_select(ad, index);
}

#[cfg(feature = "waveshare")]
fn open_waveshare_setting(ad: &mut AppData, item: usize) {
    match item {
        0 => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(DisplaySettings),
            );
        }
        1 => open_waveshare_camera(ad),
        2 => open_security(ad),
        3 => {  crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdCardSettings)); }
        4 => { ad.navigation.production.advanced_menu = crate::runtime::input::Menu::from_items(crate::runtime::navigation::production::advanced_items()); crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedMenu)); }
        5 => {  crate::runtime::effects::route(ad, crate::runtime::navigation::route!(About)); }
        #[cfg(feature = "developer-ui")]
        6 => { ad.navigation.production.developer_menu.reset(); crate::runtime::effects::route(ad, crate::runtime::navigation::route!(DeveloperMenu)); }
        _ => {}
    }
}

#[cfg(feature = "waveshare")]
fn open_waveshare_camera(ad: &mut AppData) {
    ad.camera.cam_tune_active = true;
    ad.camera.cam_tune_dirty = true;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CameraSettings));
}

#[cfg(feature = "qemu")]
fn open_qemu_setting(ad: &mut AppData, item: usize) {
    match item {
        0 => open_security(ad),
        1 => { ad.navigation.production.advanced_menu = crate::runtime::input::Menu::from_items(crate::runtime::navigation::production::advanced_items()); crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedMenu)); }
        2 => {  crate::runtime::effects::route(ad, crate::runtime::navigation::route!(About)); }
        _ => {}
    }
}

fn open_security(ad: &mut AppData) {
    
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedFeatures));
}
