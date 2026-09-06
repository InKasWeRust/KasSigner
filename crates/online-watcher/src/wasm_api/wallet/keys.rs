use crate::account::bip32::decode_kpub_text;
use wasm_bindgen::prelude::*;

/// Derive the 32-byte AES-256 key used for encrypting covenant payloads.
#[wasm_bindgen]
pub fn derive_covenant_payload_key(kpub_text: &str) -> Result<String, JsValue> {
    let payload = decode_kpub_text(kpub_text).map_err(|error| wasm_error!(&error))?;
    let mut input = Vec::with_capacity(32 + 21);
    input.extend_from_slice(&payload[13..45]);
    input.extend_from_slice(b"covenant-payload-key");
    let hash = blake2b_simd::Params::new().hash_length(32).hash(&input);
    Ok(hex::encode(hash.as_bytes()))
}

/// Extract the account-level x-only public key from canonical `kpub1:` text.
#[wasm_bindgen]
pub fn parse_kpub(kpub_text: &str) -> Result<String, JsValue> {
    let payload = decode_kpub_text(kpub_text).map_err(|error| wasm_error!(&error))?;
    let key = &payload[45..78];
    if !matches!(key[0], 0x02 | 0x03) {
        return Err(wasm_error!(
            "Account key has an invalid compressed-key prefix"
        ));
    }
    let result = serde_json::json!({
        "account_pubkey": hex::encode(&key[1..]),
    });
    serde_json::to_string(&result).map_err(|error| wasm_error!(&error.to_string()))
}
