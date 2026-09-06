// KasSigner — Air-gapped offline signing device for Kaspa
// Focused settings controller component.
use super::AppData;
use crate::ui::screens::device::{DISPLAY_DIM_ROW_Y, DISPLAY_PIN_ROW_Y};

fn persistent_controls(ad: &AppData) -> bool {
    ad.storage.persistence.advanced.saved_wallet
}

fn pin_lock_available(ad: &AppData) -> bool {
    persistent_controls(ad)
        && ad.storage.persistence.advanced.credential_kind
            == Some(crate::services::persistent_wallet::CredentialKind::Pin)
}

#[cfg(feature = "m5stack")]
pub(super) fn handle_display_settings(
    ad: &mut AppData,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SettingsMenu));
        return true;
    }
    if persistent_controls(ad) {
        let pin_available = pin_lock_available(ad);
        let changed = ad.settings.apply_persistent_display_tap(
            DISPLAY_DIM_ROW_Y.contains(&y),
            DISPLAY_PIN_ROW_Y.contains(&y),
            x < 160,
            pin_available,
        );
        if changed { return true; }
    }
    let Some(value) = super::scalar::update(ad.settings.brightness, x, y) else {
        return false;
    };
    if value == ad.settings.brightness { return false; }
    ad.settings.brightness = value;
    true
}

#[cfg(feature = "waveshare")]
pub(super) fn handle_display_settings(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SettingsMenu));
        return true;
    }
    if persistent_controls(ad) {
        let pin_available = pin_lock_available(ad);
        let changed = ad.settings.apply_persistent_display_tap(
            DISPLAY_DIM_ROW_Y.contains(&y),
            DISPLAY_PIN_ROW_Y.contains(&y),
            x < 160,
            pin_available,
        );
        if changed { return true; }
    }
    let Some(value) = super::scalar::update(ad.settings.brightness, x, y) else {
        return false;
    };
    if value == ad.settings.brightness { return false; }
    ad.settings.brightness = value;
    crate::services::power::set_brightness(i2c, value);
    boot_display.update_brightness_bar(value);
    false
}
