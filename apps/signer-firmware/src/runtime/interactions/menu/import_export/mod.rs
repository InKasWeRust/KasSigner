//! Import/export menu composition.

use super::{display, touch, AppData};
use crate::runtime::input::AppState;

type Delay = esp_hal::delay::Delay;
type I2c<'a> = esp_hal::i2c::master::I2c<'a, esp_hal::Blocking>;

mod filename;
pub(super) mod menu;
mod scanning;


/// Route import/export choices that only mutate navigation/application state.
pub(super) fn handle_pure(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    menu::handle_pure(ad, list_zones, x, y, is_back)
}


pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut Delay,
    i2c: &mut I2c<'_>,
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::CovBackupName => Some(filename::handle(
            ad,
            boot_display,
            x,
            y,
            is_back,
        )),
        AppState::ImportExportChoice => Some(menu::handle_choice(
            ad,
            boot_display,
            delay,
            x,
            y,
            is_back,
        )),
        AppState::ImportMenu => Some(menu::handle_import_menu(
            ad,
            boot_display,
            delay,
            i2c,
            list_zones,
            x,
            y,
            is_back,
        )),
        _ => None,
    }
}
