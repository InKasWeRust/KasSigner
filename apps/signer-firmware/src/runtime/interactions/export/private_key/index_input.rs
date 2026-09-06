use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::{
    hw::display,
    runtime::data::AppData,
};

use super::derivation;
use crate::runtime::interactions::export::index_keypad::{self, IndexKey};

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
        reset_input(ad);
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::KeyExport);
        return true;
    }
    let Some(key) = index_keypad::hit(x, y) else {
        return false;
    };
    match key {
        IndexKey::Digit(digit) => append_digit(ad, boot_display, b'0' + digit),
        IndexKey::Clear => {
            reset_input(ad);
            if crate::runtime::interactions::feedback::physical_presentation_enabled() {
                boot_display.update_addr_index_input("");
            }
        }
        IndexKey::Submit => submit(ad, boot_display, delay, liveness),
    }
    true
}

fn append_digit(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>, digit: u8) {
    if ad.wallet.addresses.input_len < 5 {
        ad.wallet.addresses.input_buf[ad.wallet.addresses.input_len as usize] = digit;
        ad.wallet.addresses.input_len += 1;
    }
    let input = core::str::from_utf8(
        &ad.wallet.addresses.input_buf[..ad.wallet.addresses.input_len as usize],
    )
    .unwrap_or("");
    if crate::runtime::interactions::feedback::physical_presentation_enabled() {
        boot_display.update_addr_index_input(input);
    }
}

fn submit(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) {
    let Some(address_index) = parse_index(ad) else {
        show_rejection(boot_display, delay, "Index is too large", 2000, ErrorSound::Silent);
        return;
    };
    if crate::runtime::interactions::feedback::physical_presentation_enabled() {
        boot_display.draw_saving_screen("Deriving key...");
    }
    match derivation::derive_hex(ad, address_index, liveness) {
        Ok(encoded) => {
            ad.export.export_key_hex = encoded;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportPrivKey));
        }
        Err(message) => {
            show_rejection(boot_display, delay, message, 2000, ErrorSound::Silent);
        }
    }
}

fn parse_index(ad: &mut AppData) -> Option<u16> {
    if ad.wallet.addresses.input_len == 0 {
        return None;
    }
    let result = ad.wallet.addresses.input_buf[..ad.wallet.addresses.input_len as usize]
        .iter()
        .try_fold(0u16, |value, digit| {
            value.checked_mul(10)?.checked_add(u16::from(digit.checked_sub(b'0')?))
        });
    reset_input(ad);
    result
}

fn reset_input(ad: &mut AppData) {
    ad.wallet.addresses.input_len = 0;
}
