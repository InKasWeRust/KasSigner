use crate::WalletData;
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::JsValue;

#[cfg(target_arch = "wasm32")]
pub(crate) fn js_error(message: impl AsRef<str>) -> JsValue {
    JsValue::from_str(message.as_ref())
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn js_error(message: impl AsRef<str>) -> JsValue {
    let _ = message.as_ref();
    JsValue::NULL
}

pub(crate) fn parse_utxo_indices(value: &str) -> Result<Vec<usize>, JsValue> {
    value
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| {
            item.trim()
                .parse::<usize>()
                .map_err(|error| js_error(format!("Invalid UTXO index: {error}")))
        })
        .collect()
}

pub(crate) fn parse_wallet_string(
    wallet_json: &str,
    error_prefix: &str,
) -> Result<WalletData, String> {
    crate::serialization::input::parse_json(wallet_json, error_prefix)
}

pub(crate) fn parse_wallet(wallet_json: &str, error_prefix: &str) -> Result<WalletData, JsValue> {
    parse_wallet_string(wallet_json, error_prefix).map_err(js_error)
}

pub(crate) fn parse_request_string<T: DeserializeOwned>(
    request_json: &str,
    request_name: &str,
) -> Result<T, String> {
    crate::serialization::input::parse_named_json(request_json, request_name)
}

pub(crate) fn parse_request<T: DeserializeOwned>(
    request_json: &str,
    request_name: &str,
) -> Result<T, JsValue> {
    parse_request_string(request_json, request_name).map_err(js_error)
}

pub(crate) fn parse_u64_field_string(value: &str, field_name: &str) -> Result<u64, String> {
    crate::serialization::input::parse_u64(value, field_name)
}

pub(crate) fn parse_u64_field(value: &str, field_name: &str) -> Result<u64, JsValue> {
    parse_u64_field_string(value, field_name).map_err(js_error)
}

pub(crate) fn serialize_json_string<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

pub(crate) fn serialize_json<T: Serialize>(value: &T) -> Result<String, JsValue> {
    serialize_json_string(value).map_err(js_error)
}

pub(crate) fn network_to_prefix(network: &str) -> &'static str {
    crate::account::address::network_prefix(network)
}

#[cfg(test)]
pub(crate) fn decode_pubkey32(hex_str: &str) -> Result<[u8; 32], String> {
    crate::serialization::input::decode_pubkey32(hex_str)
}

#[cfg(test)]
pub(crate) fn hex_to_pubkey32(hex_str: &str) -> Result<[u8; 32], JsValue> {
    decode_pubkey32(hex_str).map_err(js_error)
}

#[cfg(test)]
pub(crate) fn decode_named_32(hex_str: &str, name: &str) -> Result<[u8; 32], String> {
    crate::serialization::input::decode_named_32(hex_str, name)
}
