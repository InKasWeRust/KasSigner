use crate::account::address;
use crate::wasm_api::utilities::common::{js_error, network_to_prefix};
use wasm_bindgen::prelude::*;

/// Encode a 32-byte x-only pubkey (hex) as a Kaspa P2PK address
/// Optional network parameter (defaults to mainnet)
#[wasm_bindgen]
pub fn encode_p2pk_address(pubkey_hex: &str, network: Option<String>) -> Result<String, JsValue> {
    let bytes =
        hex::decode(pubkey_hex).map_err(|error| js_error(format!("Invalid hex: {error}")))?;
    if bytes.len() != 32 {
        return Err(js_error("Pubkey must be 32 bytes"));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes);
    let prefix = network_to_prefix(network.as_deref().unwrap_or("mainnet"));
    Ok(address::encode_p2pk_address(&public_key, prefix))
}

/// Encode a 32-byte script hash (hex) as a Kaspa P2SH address
#[wasm_bindgen]
pub fn encode_p2sh_address(
    script_hash_hex: &str,
    network: Option<String>,
) -> Result<String, JsValue> {
    let bytes =
        hex::decode(script_hash_hex).map_err(|error| js_error(format!("Invalid hex: {error}")))?;
    if bytes.len() != 32 {
        return Err(js_error("Script hash must be 32 bytes"));
    }
    let mut script_hash = [0u8; 32];
    script_hash.copy_from_slice(&bytes);
    let prefix = network_to_prefix(network.as_deref().unwrap_or("mainnet"));
    Ok(address::encode_p2sh_address(&script_hash, prefix))
}

/// Decode a Kaspa address → JSON { version, payload_hex }
#[wasm_bindgen]
pub fn decode_address(addr: &str) -> Result<String, JsValue> {
    let (version, payload) = address::decode_address(addr).map_err(js_error)?;
    let result = serde_json::json!({
        "version": version,
        "payload": hex::encode(payload),
    });
    serde_json::to_string(&result).map_err(|error| js_error(error.to_string()))
}
