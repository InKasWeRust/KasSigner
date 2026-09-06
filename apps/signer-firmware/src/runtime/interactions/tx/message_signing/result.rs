use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::{
    hw::display,
    runtime::data::AppData,
};

use super::export;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    has_sd_card: bool,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SigningTool);
        return true;
    }
    if (155..=191).contains(&y) && (20..=150).contains(&x) {
        if has_sd_card {
            export::begin_sd_export(ad, i2c, delay);
        } else {
            show_rejection(boot_display, delay, "No SD card", 1500, ErrorSound::Beep);
        }
        return true;
    }
    if (155..=191).contains(&y) && (170..=300).contains(&x) {
        let mut qr_data = [0u8; 96];
        qr_data[..64].copy_from_slice(&ad.signing.message.signature);
        qr_data[64..].copy_from_slice(&ad.signing.message.hash);
        boot_display.draw_qr_fullscreen(&qr_data);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgResultQr));
    }
    false
}

pub(super) fn close_qr(ad: &mut AppData) -> bool {
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgResult));
    true
}
