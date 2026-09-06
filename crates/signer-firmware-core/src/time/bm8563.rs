//! Host-testable BM8563 RTC register codec.

use crate::advanced_policy::UtcDateTime;

pub const BM8563_SECONDS_REGISTER: u8 = 0x02;
pub const BM8563_DAYS_REGISTER: u8 = 0x05;
const LOW_VOLTAGE_FLAG: u8 = 0x80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bm8563Error {
    LowVoltage,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bm8563Write {
    pub time: [u8; 4],
    pub date: [u8; 5],
}

pub fn decode_bm8563(raw: &[u8; 7]) -> Result<UtcDateTime, Bm8563Error> {
    if raw[0] & LOW_VOLTAGE_FLAG != 0 {
        return Err(Bm8563Error::LowVoltage);
    }
    let value = UtcDateTime::new(
        2000u16 + u16::from(decode_bcd(raw[6])?),
        decode_bcd(raw[5] & 0x1F)?,
        decode_bcd(raw[3] & 0x3F)?,
        decode_bcd(raw[2] & 0x3F)?,
        decode_bcd(raw[1] & 0x7F)?,
        decode_bcd(raw[0] & 0x7F)?,
    );
    value.validate().map_err(|_| Bm8563Error::Invalid)?;
    Ok(value)
}

pub fn encode_bm8563(value: UtcDateTime) -> Result<Bm8563Write, Bm8563Error> {
    // UtcDateTime::validate() already enforces the shared 2000..=2099
    // policy. Rechecking the same range here was unreachable on success and
    // created a permanently uncovered branch in the host-production codec.
    value.validate().map_err(|_| Bm8563Error::Invalid)?;
    let weekday = value.weekday_monday0().map_err(|_| Bm8563Error::Invalid)?;
    Ok(Bm8563Write {
        time: [
            BM8563_SECONDS_REGISTER,
            encode_bcd(value.second),
            encode_bcd(value.minute),
            encode_bcd(value.hour),
        ],
        date: [
            BM8563_DAYS_REGISTER,
            encode_bcd(value.day),
            weekday,
            encode_bcd(value.month),
            encode_bcd((value.year - 2000) as u8),
        ],
    })
}

fn decode_bcd(value: u8) -> Result<u8, Bm8563Error> {
    let high = value >> 4;
    let low = value & 0x0F;
    if high > 9 || low > 9 {
        Err(Bm8563Error::Invalid)
    } else {
        Ok(high * 10 + low)
    }
}

const fn encode_bcd(value: u8) -> u8 {
    ((value / 10) << 4) | (value % 10)
}
