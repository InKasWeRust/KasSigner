use super::address;
use crate::{
    runtime::interactions::{
        feedback::{show_rejection, ErrorSound},
        menu_selection::{handle_paged_menu_touch, PagedMenuAction},
    },
    hw::{display, touch::TouchZone},
    runtime::data::AppData,
};


/// Hardware-free Seed Tools routing. Returns `None` only for selections that
/// intentionally require display/delay work (Address derivation or rejection).
pub(super) fn handle_pure(
    ad: &mut AppData,
    list_zones: &[TouchZone; 4],
    page_up_zone: &TouchZone,
    page_down_zone: &TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if is_back {
        ad.navigation.seed_tools_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu));
        return Some(true);
    }
    match handle_paged_menu_touch(
        &mut ad.navigation.seed_tools_menu,
        list_zones,
        page_up_zone,
        page_down_zone,
        x,
        y,
    ) {
        PagedMenuAction::PageChanged => Some(true),
        PagedMenuAction::Selected(item) => match item {
            0 => { crate::runtime::effects::menu_select(ad, 0); Some(true) }
            1 => { crate::runtime::effects::menu_select(ad, 1); Some(true) }
            2 => { crate::runtime::effects::menu_select(ad, 2); Some(true) }
            3 => { crate::runtime::effects::menu_select(ad, 3); Some(true) }
            5 if ad.wallet.seeds.seed_loaded => {
                crate::runtime::effects::menu_select(ad, 5);
                Some(true)
            }
            6 => {
                crate::runtime::effects::menu_select(ad, 6);
                Some(true)
            }
            // Address derivation and the no-seed BIP85 rejection retain the
            // narrow display/delay fallback.
            4 | 5 => None,
            _ => Some(false),
        },
        PagedMenuAction::None => Some(false),
    }
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    list_zones: &[TouchZone; 4],
    page_up_zone: &TouchZone,
    page_down_zone: &TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.navigation.seed_tools_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu));
        return true;
    }
    match handle_paged_menu_touch(
        &mut ad.navigation.seed_tools_menu,
        list_zones,
        page_up_zone,
        page_down_zone,
        x,
        y,
    ) {
        PagedMenuAction::PageChanged => true,
        PagedMenuAction::Selected(item) => {
            dispatch_item(ad, boot_display, delay, liveness, item);
            true
        }
        PagedMenuAction::None => false,
    }
}

fn dispatch_item(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    item: u8,
) {
    match item {
        0 => { let _ = crate::runtime::effects::menu_select(ad, 0); }
        1 => { let _ = crate::runtime::effects::menu_select(ad, 1); }
        2 => { let _ = crate::runtime::effects::menu_select(ad, 2); }
        3 => { let _ = crate::runtime::effects::menu_select(ad, 3); }
        4 => address::open(ad, boot_display, delay, liveness),
        5 => {
            if ad.wallet.seeds.seed_loaded {
                let _ = crate::runtime::effects::menu_select(ad, 5);
            } else {
                show_rejection(boot_display, delay, "Load a seed first", 1_500, ErrorSound::Silent);
            }
        }
        6 => { let _ = crate::runtime::effects::menu_select(ad, 6); }
        _ => {}
    }
}
