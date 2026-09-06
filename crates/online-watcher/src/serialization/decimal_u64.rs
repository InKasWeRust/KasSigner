//! Lossless JSON representation for consensus `u64` values at browser boundaries.
//!
//! New payloads use canonical decimal strings because JavaScript `Number` cannot
//! represent every `u64`. Legacy JSON integers remain accepted only inside the
//! JavaScript safe-integer range; larger numeric literals are rejected rather
//! than silently accepting a value that may already have been rounded by JS.

use serde::{Deserialize, Deserializer, Serializer};

const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DecimalU64 {
        Text(String),
        Integer(u64),
    }

    match DecimalU64::deserialize(deserializer)? {
        DecimalU64::Text(text) => parse_canonical_decimal(&text).map_err(serde::de::Error::custom),
        DecimalU64::Integer(value) if value <= JS_MAX_SAFE_INTEGER => Ok(value),
        DecimalU64::Integer(_) => Err(serde::de::Error::custom(
            "unsafe JSON integer above JavaScript Number.MAX_SAFE_INTEGER; use a decimal string",
        )),
    }
}

fn parse_canonical_decimal(text: &str) -> Result<u64, &'static str> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("expected an unsigned decimal string");
    }
    if text.len() > 1 && text.as_bytes()[0] == b'0' {
        return Err("decimal string must be canonical (no leading zeroes)");
    }
    text.parse::<u64>()
        .map_err(|_| "decimal string exceeds u64")
}
