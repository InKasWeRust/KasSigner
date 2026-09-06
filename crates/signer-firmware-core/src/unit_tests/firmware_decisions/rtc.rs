use crate::{
    advanced_policy::UtcDateTime,
    time::bm8563::{
        decode_bm8563, encode_bm8563, Bm8563Error, BM8563_DAYS_REGISTER, BM8563_SECONDS_REGISTER,
    },
};

#[test]
fn bm8563_codec_round_trips_utc_registers() {
    let value = UtcDateTime::new(2026, 8, 10, 8, 10, 30);
    let encoded = encode_bm8563(value).expect("encode RTC");
    assert_eq!(encoded.time, [BM8563_SECONDS_REGISTER, 0x30, 0x10, 0x08]);
    assert_eq!(encoded.date, [BM8563_DAYS_REGISTER, 0x10, 0, 0x08, 0x26]);
    let raw = [0x30, 0x10, 0x08, 0x10, 0, 0x08, 0x26];
    assert_eq!(decode_bm8563(&raw), Ok(value));
}

#[test]
fn bm8563_codec_fails_closed_on_low_voltage_and_invalid_bcd() {
    assert_eq!(
        decode_bm8563(&[0x80, 0, 0, 1, 0, 1, 0]),
        Err(Bm8563Error::LowVoltage),
    );
    assert_eq!(
        decode_bm8563(&[0x6a, 0, 0, 1, 0, 1, 0]),
        Err(Bm8563Error::Invalid),
    );
    assert_eq!(
        encode_bm8563(UtcDateTime::new(1999, 12, 31, 23, 59, 59)),
        Err(Bm8563Error::Invalid),
    );
}
