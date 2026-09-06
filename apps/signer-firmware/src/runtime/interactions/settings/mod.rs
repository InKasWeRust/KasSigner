// KasSigner — Air-gapped offline signing device for Kaspa
// Settings controller façade; subsystem handlers live in focused modules.

use crate::{
    runtime::interactions::TouchInput,
    hw::display as hw_display,
    services::storage_device,
    hw::touch,
    runtime::data::AppData,
};

mod menu;
mod display;
mod scalar;
pub(crate) mod advanced;
#[cfg(feature = "m5stack")]
mod audio;
mod storage;
#[cfg(feature = "waveshare")]
mod camera;

use menu::handle_settings_menu;
use display::handle_display_settings;
#[cfg(feature = "m5stack")]
use audio::handle_audio_settings;
use storage::handle_sd_card_settings;
#[cfg(feature = "waveshare")]
use camera::handle_camera_settings;

pub struct SettingsTouchContext<'ctx, 'display, 'hal> {
    pub ad: &'ctx mut AppData,
    pub boot_display: &'ctx mut hw_display::BootDisplay<'display>,
    pub delay: &'ctx mut esp_hal::delay::Delay,
    pub i2c: &'ctx mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    pub sd_card_type: &'ctx Option<storage_device::SdCardType>,
    pub input: TouchInput,
}

/// Route the Settings root menu without borrowing board hardware. The menu
/// itself is pure navigation; only its destination screens may need devices.
pub fn handle_settings_menu_navigation(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    input: TouchInput,
) -> Option<bool> {
    if ad.navigation.app.state != crate::runtime::input::AppState::SettingsMenu {
        return None;
    }
    Some(handle_settings_menu(
        ad, list_zones, page_up_zone, page_down_zone,
        input.x, input.y, input.is_back,
    ))
}


#[cfg(feature = "m5stack")]
/// Route Display Settings without borrowing display/I2C/SD/camera resources.
pub fn handle_display_settings_navigation(ad: &mut AppData, input: TouchInput) -> Option<bool> {
    if ad.navigation.app.state != crate::runtime::input::AppState::DisplaySettings { return None; }
    Some(handle_display_settings(ad, input.x, input.y, input.is_back))
}

#[cfg(feature = "m5stack")]
/// Route Audio Settings without borrowing board hardware. Volume changes are
/// pure AppData/atomic state changes; the shared frame stage redraws the screen.
pub fn handle_audio_settings_navigation(
    ad: &mut AppData,
    input: TouchInput,
) -> Option<bool> {
    if ad.navigation.app.state != crate::runtime::input::AppState::AudioSettings {
        return None;
    }
    Some(handle_audio_settings(ad, input.x, input.y, input.is_back))
}

/// Route About without borrowing board hardware.
pub fn handle_about_navigation(ad: &mut AppData, input: TouchInput) -> Option<bool> {
    if ad.navigation.app.state != crate::runtime::input::AppState::About { return None; }
    let _ = input;
    crate::runtime::effects::back(ad);
    Some(true)
}


/// Pure Advanced navigation/editing pre-dispatch.
pub fn handle_advanced_navigation(ad: &mut AppData, input: TouchInput) -> Option<bool> {
    advanced::handle_pure(input, ad)
}

/// Back from SD-card settings never needs the SD/display/I2C hardware path.
pub fn handle_sd_settings_navigation(ad: &mut AppData, input: TouchInput) -> Option<bool> {
    match ad.navigation.app.state {
        crate::runtime::input::AppState::SdCardSettings if input.is_back => {
            crate::runtime::effects::back(ad);
            Some(true)
        }
        crate::runtime::input::AppState::SdCardUnlockPassword if input.is_back => {
            ad.wallet.seeds.pp_input.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdCardSettings));
            Some(true)
        }
        _ => None,
    }
}

/// Handle settings screens that genuinely own board hardware.
#[inline(never)]
pub fn handle_settings_touch(context: SettingsTouchContext<'_, '_, '_>) -> Option<bool> {
    let SettingsTouchContext {
        ad,
        boot_display,
        delay,
        i2c,
        sd_card_type,
        input,
    } = context;
    let TouchInput { x, y, is_back } = input;
    let needs_redraw = match ad.navigation.app.state {
        #[cfg(feature = "waveshare")]
        crate::runtime::input::AppState::DisplaySettings => {
            handle_display_settings(ad, boot_display, i2c, x, y, is_back)
        }
        crate::runtime::input::AppState::SdCardSettings => handle_sd_card_settings(
            ad, boot_display, delay, i2c, sd_card_type, x, y, is_back,
        ),
        crate::runtime::input::AppState::SdCardUnlockPassword => storage::handle_unlock_password(
            ad, boot_display, delay, i2c, x, y, is_back,
        ),
        #[cfg(feature = "waveshare")]
        crate::runtime::input::AppState::CameraSettings => {
            handle_camera_settings(ad, boot_display, x, y, is_back)
        }
        _ => return None,
    };
    Some(needs_redraw)
}
