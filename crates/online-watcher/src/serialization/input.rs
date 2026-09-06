//! Browser-neutral parsing helpers for externally supplied textual values.
//!
//! These helpers intentionally return `String` errors and contain no WASM/browser
//! types so domain and transaction-planning code can validate the same inputs as
//! the JavaScript boundary without depending on `wasm_api`.

use serde::de::DeserializeOwned;

pub(crate) fn parse_json<T: DeserializeOwned>(
    value: &str,
    error_prefix: &str,
) -> Result<T, String> {
    serde_json::from_str(value).map_err(|error| format!("{error_prefix}: {error}"))
}

pub(crate) fn parse_named_json<T: DeserializeOwned>(
    value: &str,
    request_name: &str,
) -> Result<T, String> {
    parse_json(value, &format!("Bad {request_name} JSON"))
}

pub(crate) fn parse_u64(value: &str, field_name: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|error| format!("Invalid {field_name}: {error}"))
}

pub(crate) fn decode_hex_32(
    value: &str,
    invalid_prefix: &str,
    wrong_length: &str,
) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("{invalid_prefix}: {error}"))?;
    if bytes.len() != 32 {
        return Err(wrong_length.to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn decode_pubkey32(value: &str) -> Result<[u8; 32], String> {
    decode_hex_32(value, "Bad hex", "Pubkey must be 32 bytes")
}

pub(crate) fn decode_named_32(value: &str, name: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("Bad {name} hex: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!("{name} must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
