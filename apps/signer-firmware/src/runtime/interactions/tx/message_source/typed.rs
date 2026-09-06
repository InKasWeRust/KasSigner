use super::super::{AppData, display};
use crate::{
    runtime::interactions::{feedback::{show_rejection, ErrorSound}, keyboard::{handle_passphrase_keyboard, KeyboardAction}},
};

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgChoice));
        return true;
    }

    match handle_passphrase_keyboard(&mut ad.wallet.seeds.pp_input, boot_display, x, y) {
        KeyboardAction::Submitted => {
            if store_message(ad).is_err() {
                show_rejection(boot_display, delay, "Message required", 1_200, ErrorSound::Beep);
            }
        }
        KeyboardAction::Edited => {}
        KeyboardAction::None => return false,
    }
    true
}

fn store_message(ad: &mut AppData) -> Result<(), ()> {
    let message = ad.wallet.seeds.pp_input.as_str();
    if message.is_empty() { return Err(()); }
    let length = message.len().min(ad.signing.message.payload.len());
    ad.signing.message.payload.fill(0);
    ad.signing.message.payload[..length].copy_from_slice(&message.as_bytes()[..length]);
    ad.signing.message.payload_len = length;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgPreview));
    Ok(())
}
