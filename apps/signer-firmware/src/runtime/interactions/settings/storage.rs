// KasSigner — Air-gapped offline signing device for Kaspa
// Focused SD-card settings facade.
mod format;
mod test;

use super::AppData;
use crate::{
    hw::display as hw_display,
    services::storage_device as sdcard,
    runtime::interactions::feedback::{show_rejection, show_success, ErrorSound},
    ui::keyboard::{hit_test, KeyAction, KeyboardMode},
};

const LEFT_ACTION_X: core::ops::RangeInclusive<u16> = 10..=155;
const RIGHT_ACTION_X: core::ops::RangeInclusive<u16> = 165..=310;
const NORMAL_ACTION_Y: core::ops::RangeInclusive<u16> = 100..=139;
const LOCKED_ACTION_Y: core::ops::RangeInclusive<u16> = 110..=154;

pub(super) fn handle_sd_card_settings(
    ad: &mut AppData,
    boot_display: &mut hw_display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<sdcard::SdCardType>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SettingsMenu));
        return true;
    }
    if sd_card_type.is_none() { return false; }
    if sdcard::card_is_known_locked() {
        return handle_locked_card(ad, x, y);
    }
    if LEFT_ACTION_X.contains(&x) && NORMAL_ACTION_Y.contains(&y) {
        format::begin(ad);
        return false;
    }
    if RIGHT_ACTION_X.contains(&x) && NORMAL_ACTION_Y.contains(&y) {
        test::run(boot_display, delay, i2c);
        return true;
    }
    false
}

fn handle_locked_card(ad: &mut AppData, x: u16, y: u16) -> bool {
    if !LOCKED_ACTION_Y.contains(&y) { return false; }
    if LEFT_ACTION_X.contains(&x) {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdCardUnlockPassword));
        return true;
    }
    if RIGHT_ACTION_X.contains(&x) {
        format::begin(ad);
    }
    false
}

pub(super) fn handle_unlock_password(
    ad: &mut AppData,
    display: &mut hw_display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdCardSettings));
        return true;
    }
    match edit_password(ad, x, y) {
        UnlockEdit::Edited => true,
        UnlockEdit::None => false,
        UnlockEdit::Submitted => submit_unlock(ad, display, delay, i2c),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnlockEdit { None, Edited, Submitted }

fn edit_password(ad: &mut AppData, x: u16, y: u16) -> UnlockEdit {
    let action = hit_test(x, y, KeyboardMode::Full, ad.wallet.seeds.pp_input.page);
    let input = &mut ad.wallet.seeds.pp_input;
    match action {
        KeyAction::Char(c) if input.len < 16 => input.push_char(c),
        KeyAction::Space if input.len < 16 => input.push_char(b' '),
        KeyAction::Backspace => input.backspace(),
        KeyAction::Page => input.next_page(),
        KeyAction::CursorLeft => input.cursor_left(),
        KeyAction::CursorRight => input.cursor_right(),
        KeyAction::Ok => return UnlockEdit::Submitted,
        _ => return UnlockEdit::None,
    }
    UnlockEdit::Edited
}

fn submit_unlock(
    ad: &mut AppData,
    display: &mut hw_display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> bool {
    let len = ad.wallet.seeds.pp_input.len.min(16);
    if len == 0 {
        show_rejection(display, delay, "Enter the SD password", 1_500, ErrorSound::Beep);
        return true;
    }
    let mut password = [0u8; 16];
    password[..len].copy_from_slice(&ad.wallet.seeds.pp_input.buf[..len]);
    ad.wallet.seeds.pp_input.reset();
    display.draw_sdcard_unlocking();
    let result = sdcard::unlock_locked_card(i2c, delay, &password[..len]);
    shared_signer::bytes::zeroize_bytes(&mut password);
    show_unlock_result(display, delay, result);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdCardSettings));
    true
}

fn show_unlock_result(
    display: &mut hw_display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    result: Result<(), &'static str>,
) {
    match result {
        Ok(()) => show_success(display, delay, "SD card unlocked", 1_800),
        Err(error) => show_rejection(display, delay, error, 1_800, ErrorSound::Beep),
    }
}
