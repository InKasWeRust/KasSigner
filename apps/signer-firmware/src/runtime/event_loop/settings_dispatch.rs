//! Hardware-free Settings tap dispatch.

use crate::{controllers::TouchInput, hw::touch::TouchZone, runtime::data::AppData};

pub(crate) fn handle(
    ad: &mut AppData,
    list_zones: &[TouchZone; 4],
    page_up_zone: &TouchZone,
    page_down_zone: &TouchZone,
    x: u16,
    y: u16,
) -> Option<bool> {
    let input = TouchInput::new(x, y, crate::ui::layout::is_back_tap(x, y));
    match ad.navigation.app.state {
        crate::runtime::input::AppState::SettingsMenu => {
            #[cfg(feature = "m5stack")]
            crate::log!("   TOUCH CoreS3 SettingsMenu pure dispatch BEGIN ({}, {})", x, y);
            let result = crate::runtime::interactions::settings::handle_settings_menu_navigation(
                ad, list_zones, page_up_zone, page_down_zone, input,
            );
            #[cfg(feature = "m5stack")]
            if let Some(redraw) = result {
                crate::log!("   TOUCH CoreS3 SettingsMenu pure dispatch DONE redraw={}", redraw);
            }
            result
        }
        #[cfg(feature = "m5stack")]
        crate::runtime::input::AppState::DisplaySettings => {
            crate::log!("   TOUCH CoreS3 DisplaySettings pure dispatch BEGIN ({}, {})", x, y);
            let result = crate::runtime::interactions::settings::handle_display_settings_navigation(ad, input);
            if let Some(redraw) = result {
                crate::log!("   TOUCH CoreS3 DisplaySettings pure dispatch DONE redraw={} brightness={}", redraw, ad.settings.brightness);
            }
            result
        }
        #[cfg(feature = "m5stack")]
        crate::runtime::input::AppState::AudioSettings => {
            crate::log!("   TOUCH CoreS3 AudioSettings pure dispatch BEGIN ({}, {})", x, y);
            let result = crate::runtime::interactions::settings::handle_audio_settings_navigation(ad, input);
            if let Some(redraw) = result {
                crate::log!("   TOUCH CoreS3 AudioSettings pure dispatch DONE redraw={} volume={}", redraw, ad.settings.volume);
            }
            result
        }
        crate::runtime::input::AppState::SdCardSettings | crate::runtime::input::AppState::SdCardUnlockPassword => {
            crate::runtime::interactions::settings::handle_sd_settings_navigation(ad, input)
        }
        state if crate::runtime::interactions::settings::advanced::is_advanced_state(state) => {
            crate::runtime::interactions::settings::handle_advanced_navigation(ad, input)
        }
        crate::runtime::input::AppState::About => {
            crate::runtime::interactions::settings::handle_about_navigation(ad, input)
        }
        _ => None,
    }
}
pub(crate) fn persist_device_preferences(
    ad: &mut AppData,
    persistence: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
) {
    if !ad.settings.device_preferences_dirty() { return; }
    match persistence.save_display_preferences(ad) {
        Ok(()) => ad.settings.clear_device_preferences_dirty(),
        Err(error) => crate::log!("   SETTINGS preference save failed: {:?}", error),
    }
}

#[cfg(feature = "waveshare")]
pub(crate) fn handle_display_drag(
    ad: &mut AppData,
    display: &mut crate::hw::display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    x: u16, y: u16,
) -> bool {
    let _ = &mut *i2c;
    if ad.navigation.app.state != crate::runtime::input::AppState::DisplaySettings
        || !(70..=250).contains(&x) || !(60..=130).contains(&y) { return false; }
    let value = ((x as u32 - 70) * 255 / 180).min(255) as u8;
    if value == ad.settings.brightness { return false; }
    ad.settings.brightness = value;
    crate::hw::pmu::set_brightness!(i2c, value);
    display.update_brightness_bar(value);
    true
}
