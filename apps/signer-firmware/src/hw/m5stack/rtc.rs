//! BM8563 hardware RTC adapter for M5Stack CoreS3/CoreS3 Lite.

use esp_hal::i2c::master::I2c;
use signer_firmware_core::{
    advanced_policy::UtcDateTime,
    time::bm8563::{self as rtc, Bm8563Error},
};

const ADDRESS: u8 = 0x51;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RtcError { Io, LowVoltage, Invalid }

pub(crate) fn read_utc(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
) -> Result<UtcDateTime, RtcError> {
    let mut raw = [0u8; 7];
    i2c.write_read(ADDRESS, &[rtc::BM8563_SECONDS_REGISTER], &mut raw)
        .map_err(|_| RtcError::Io)?;
    rtc::decode_bm8563(&raw).map_err(map_codec_error)
}

pub(crate) fn set_utc(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    value: UtcDateTime,
) -> Result<(), RtcError> {
    let encoded = rtc::encode_bm8563(value).map_err(map_codec_error)?;
    i2c.write(ADDRESS, &encoded.time).map_err(|_| RtcError::Io)?;
    i2c.write(ADDRESS, &encoded.date).map_err(|_| RtcError::Io)
}

const fn map_codec_error(error: Bm8563Error) -> RtcError {
    match error {
        Bm8563Error::LowVoltage => RtcError::LowVoltage,
        Bm8563Error::Invalid => RtcError::Invalid,
    }
}
