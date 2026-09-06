use crate::wasm_api::utilities::common::js_error;
use wasm_bindgen::prelude::*;

/// Build the plaintext covenant payload blob: [version:1][type:1][params...]
/// version = 0x01, type = covenant type byte. Caller provides params as hex.
/// Returns hex of the assembled plaintext (ready for AES-GCM encryption in JS).
#[wasm_bindgen]
pub fn build_covenant_payload(covenant_type: u8, params_hex: &str) -> Result<String, JsValue> {
    let params =
        hex::decode(params_hex).map_err(|error| js_error(format!("Bad params hex: {error}")))?;
    let mut blob = Vec::with_capacity(2 + params.len());
    blob.push(0x01);
    blob.push(covenant_type);
    blob.extend_from_slice(&params);
    Ok(hex::encode(&blob))
}

/// Parse a decrypted covenant payload blob: [version:1][type:1][params...]
/// Returns JSON: { "version": 1, "covenant_type": N, "params_hex": "..." }
#[wasm_bindgen]
pub fn parse_covenant_payload(plaintext_hex: &str) -> Result<String, JsValue> {
    let blob = hex::decode(plaintext_hex)
        .map_err(|error| js_error(format!("Bad plaintext hex: {error}")))?;
    if blob.len() < 2 {
        return Err(js_error("Payload too short"));
    }
    let result = serde_json::json!({
        "version": blob[0],
        "covenant_type": blob[1],
        "params_hex": hex::encode(&blob[2..]),
    });
    serde_json::to_string(&result).map_err(|error| js_error(error.to_string()))
}
