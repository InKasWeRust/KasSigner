//! Board-aware trusted-time facade for irreversible transaction-signing policy.

use esp_hal::i2c::master::I2c;
use signer_firmware_core::advanced_policy::UtcDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureTimeError {
    #[cfg(feature = "waveshare")]
    Unsupported,
    #[cfg(feature = "m5stack")]
    Io,
    #[cfg(feature = "m5stack")]
    LowVoltage,
    #[cfg(feature = "m5stack")]
    Invalid,
}

#[cfg(feature = "m5stack")]
pub fn read_utc(i2c: &mut I2c<'_, esp_hal::Blocking>) -> Result<UtcDateTime, SecureTimeError> {
    crate::hw::rtc::read_utc(i2c).map_err(map_m5_error)
}

#[cfg(feature = "m5stack")]
pub fn set_utc(i2c: &mut I2c<'_, esp_hal::Blocking>, value: UtcDateTime) -> Result<(), SecureTimeError> {
    crate::hw::rtc::set_utc(i2c, value).map_err(map_m5_error)
}

#[cfg(feature = "m5stack")]
fn map_m5_error(error: crate::hw::rtc::RtcError) -> SecureTimeError {
    use crate::hw::rtc::RtcError;
    match error {
        RtcError::Io => SecureTimeError::Io,
        RtcError::LowVoltage => SecureTimeError::LowVoltage,
        RtcError::Invalid => SecureTimeError::Invalid,
    }
}

#[cfg(feature = "waveshare")]
pub fn read_utc(_: &mut I2c<'_, esp_hal::Blocking>) -> Result<UtcDateTime, SecureTimeError> {
    Err(SecureTimeError::Unsupported)
}

