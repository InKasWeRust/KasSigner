use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::{
    hw::display,
    runtime::data::AppData,
    services::audio as sound,
};

use super::service;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgChoice));
        return true;
    }
    if !(185..=225).contains(&y) || !(100..=220).contains(&x) {
        return false;
    }

    boot_display.draw_loading_screen("Signing...");
    boot_display.update_progress_bar(20);
    crate::services::timing::pause(delay, 50);
    ad.signing.message.hash = service::message_digest(ad);
    boot_display.update_progress_bar(70);

    match service::sign_reviewed_message(ad, liveness) {
        Ok(signature) => {
            ad.signing.message.signature = signature;
            boot_display.update_progress_bar(100);
            sound::success();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgResult));
        }
        Err(()) => {
            show_rejection(boot_display, delay, "Signing failed", 2000, ErrorSound::Beep);
        }
    }
    true
}
