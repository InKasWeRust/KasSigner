use crate::{
    runtime::interactions::{
        feedback::{show_rejection, ErrorSound},
        TouchInput,
    },
    hw::display::BootDisplay,
    runtime::data::AppData,
    services::persistent_wallet::PersistentWallet,
    ui::screens::device::advanced_security::{
        WARNING_BUTTON_Y, WARNING_CANCEL_X, WARNING_ENABLE_X,
    },
};
use signer_firmware_core::advanced_policy::{parse_utc_yyyymmddhhmm, parse_weekly_windows};

use super::clock::{read_now_unix, RtcReadError};

use super::input::{edit, return_to_advanced, EditAction};

pub(super) fn handle_time_lock_entry(
    input: TouchInput,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    if input.is_back {
        return return_to_advanced(ad);
    }
    match edit(input, ad, true) {
        EditAction::None => None,
        EditAction::Edited => Some(true),
        EditAction::Submitted => {
            let parsed = parse_utc_yyyymmddhhmm(
                &ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len],
            )
            .and_then(|value| value.to_unix_seconds());
            match (parsed, read_now_unix(i2c)) {
                (Ok(target), Ok(current)) if target > current => {
                    ad.storage.persistence.advanced.pending_not_before_unix = target;
                    ad.wallet.seeds.pp_input.reset();
                    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedTimeLockConfirm));
                }
                (Ok(_), Ok(_)) => show_rejection(
                    display,
                    delay,
                    "Lock date must be in the future",
                    1800,
                    ErrorSound::Beep,
                ),
                (Err(_), _) => show_rejection(
                    display,
                    delay,
                    "Use valid UTC YYYYMMDDHHMM",
                    1800,
                    ErrorSound::Beep,
                ),
                (_, Err(error)) => handle_rtc_read_error(error, ad, display, delay),
            }
            Some(true)
        }
    }
}

pub(super) fn handle_time_lock_confirm(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    if cancelled(input) {
        return return_to_advanced(ad);
    }
    if !confirmed(input) {
        return None;
    }
    let now = match read_now_unix(i2c) {
        Ok(value) => value,
        Err(error) => {
            handle_rtc_read_error(error, ad, display, delay);
            return Some(true);
        }
    };
    let result = persistence.enable_not_before(
        ad.storage.persistence.advanced.pending_not_before_unix,
        now,
        &ad.wallet.seeds.seed_mgr,
        i2c,
        delay,
    );
    finish_activation(result, ad, persistence, display, delay)
}

pub(super) fn handle_weekly_entry(
    input: TouchInput,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    if input.is_back {
        return return_to_advanced(ad);
    }
    match edit(input, ad, false) {
        EditAction::None => None,
        EditAction::Edited => Some(true),
        EditAction::Submitted => {
            let parsed = parse_weekly_windows(
                &ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len],
            );
            match (parsed, read_now_unix(i2c)) {
                (Ok((windows, count)), Ok(_)) => {
                    ad.storage.persistence.advanced.pending_windows = windows;
                    ad.storage.persistence.advanced.pending_weekly_count = count;
                    ad.wallet.seeds.pp_input.reset();
                    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedWeeklyConfirm));
                }
                (Err(_), _) => show_rejection(
                    display,
                    delay,
                    "Use DAY HH:MM-HH:MM; max 4",
                    1900,
                    ErrorSound::Beep,
                ),
                (_, Err(error)) => handle_rtc_read_error(error, ad, display, delay),
            }
            Some(true)
        }
    }
}

pub(super) fn handle_weekly_confirm(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    if cancelled(input) {
        return return_to_advanced(ad);
    }
    if !confirmed(input) {
        return None;
    }
    let now = match read_now_unix(i2c) {
        Ok(value) => value,
        Err(error) => {
            handle_rtc_read_error(error, ad, display, delay);
            return Some(true);
        }
    };
    let result = persistence.enable_weekly_windows(
        ad.storage.persistence.advanced.pending_windows,
        ad.storage.persistence.advanced.pending_weekly_count,
        now,
        &ad.wallet.seeds.seed_mgr,
        i2c,
        delay,
    );
    finish_activation(result, ad, persistence, display, delay)
}

fn handle_rtc_read_error(
    error: RtcReadError,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    if error == RtcReadError::LowVoltage {
        ad.storage.persistence.advanced.rtc_verification =
            crate::runtime::data::RtcVerification::Unverified;
        ad.storage.persistence.advanced.clear_pending();
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedRtcEntry));
        crate::log!("   RTC low-voltage flag: verification cleared; routing to RTC setup");
        return;
    }
    show_rejection(display, delay, error.message(), 1800, ErrorSound::Beep);
}

fn finish_activation(
    result: Result<(), crate::services::persistent_wallet::PersistError>,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    match result {
        Ok(()) => {
            persistence.refresh_security_mirror(ad);
            return_to_advanced(ad)
        }
        Err(error) => {
            show_rejection(display, delay, error.message(), 2000, ErrorSound::Beep);
            Some(true)
        }
    }
}

fn cancelled(input: TouchInput) -> bool {
    input.is_back || (WARNING_BUTTON_Y.contains(&input.y) && WARNING_CANCEL_X.contains(&input.x))
}

fn confirmed(input: TouchInput) -> bool {
    WARNING_BUTTON_Y.contains(&input.y) && WARNING_ENABLE_X.contains(&input.x)
}
