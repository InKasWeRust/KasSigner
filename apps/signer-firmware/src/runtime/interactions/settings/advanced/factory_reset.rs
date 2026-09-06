//! Explicit factory-reset warning and irreversible reset boundary.

use crate::{
    hw::display::BootDisplay,
    runtime::{data::AppData, interactions::TouchInput},
    services::persistent_wallet::PersistentWallet,
};
use crate::ui::screens::device::advanced_security::{
    WARNING_BUTTON_Y, WARNING_CANCEL_X, WARNING_ENABLE_X,
};

pub(super) fn handle_warning(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input.is_back
        || (WARNING_BUTTON_Y.contains(&input.y) && WARNING_CANCEL_X.contains(&input.x))
    {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedMenu));
        return Some(true);
    }
    if WARNING_BUTTON_Y.contains(&input.y) && WARNING_ENABLE_X.contains(&input.x) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(FactoryResetConfirm));
        return Some(true);
    }
    None
}

pub(super) fn execute_confirmed_reset(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    if input.is_back
        || (WARNING_BUTTON_Y.contains(&input.y) && WARNING_CANCEL_X.contains(&input.x))
    {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedMenu));
        return Some(true);
    }
    if !WARNING_BUTTON_Y.contains(&input.y) || !WARNING_ENABLE_X.contains(&input.x) { return None; }
    display.draw_loading_screen("Erasing user data...");
    match persistence.factory_reset(ad, i2c, delay) {
        Ok(()) => {
            crate::log!("   Factory reset complete; rebooting");
            crate::services::timing::pause(delay, 250);
            esp_hal::system::software_reset();
        }
        Err(error) => {
            crate::log!("   Factory reset failed: {:?}", error);
            crate::runtime::interactions::feedback::show_rejection(
                display, delay, error.message(), 2200,
                crate::runtime::interactions::feedback::ErrorSound::Beep,
            );
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedMenu));
        }
    }
    Some(true)
}
