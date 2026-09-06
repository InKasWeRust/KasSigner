//! Hardware RTC setup and validated UTC reads for permanent time policies.

use crate::{
    runtime::interactions::{
        feedback::{show_rejection, ErrorSound},
        TouchInput,
    },
    hw::display::BootDisplay,
    runtime::{
        data::{AppData, RtcVerification},
    },
    services::secure_time,
};
use signer_firmware_core::advanced_policy::parse_utc_yyyymmddhhmm;

use super::input::{edit, EditAction};

pub(super) fn handle_rtc_entry(
    input: TouchInput,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    if input.is_back {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedFeatures));
        return Some(true);
    }
    match edit(input, ad, true) {
        EditAction::None => None,
        EditAction::Edited => Some(true),
        EditAction::Submitted => {
            let raw = &ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len];
            let result = parse_utc_yyyymmddhhmm(raw)
                .map_err(|_| "Use valid UTC YYYYMMDDHHMM")
                .and_then(|value| {
                    secure_time::set_utc(i2c, value).map_err(|_| "Hardware RTC set failed")
                });
            ad.wallet.seeds.pp_input.reset();
            match result {
                Ok(()) => {
                    ad.storage.persistence.advanced.rtc_verification = RtcVerification::Verified;
                    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedFeatures));
                }
                Err(message) => {
                    show_rejection(display, delay, message, 1800, ErrorSound::Beep)
                }
            }
            Some(true)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RtcReadError {
    LowVoltage,
    Io,
    Invalid,
}

impl RtcReadError {
    pub(super) const fn message(self) -> &'static str {
        match self {
            Self::LowVoltage => "RTC lost power; set UTC again",
            Self::Io => "Hardware RTC read failed",
            Self::Invalid => "Hardware RTC contains invalid UTC time",
        }
    }
}

pub(super) fn read_now_unix(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Result<u64, RtcReadError> {
    let value = secure_time::read_utc(i2c).map_err(|error| match error {
        secure_time::SecureTimeError::LowVoltage => RtcReadError::LowVoltage,
        secure_time::SecureTimeError::Io => RtcReadError::Io,
        secure_time::SecureTimeError::Invalid => RtcReadError::Invalid,
    })?;
    value.to_unix_seconds().map_err(|_| RtcReadError::Invalid)
}
