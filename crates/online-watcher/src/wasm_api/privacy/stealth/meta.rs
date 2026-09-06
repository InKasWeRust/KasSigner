use crate::wasm_api::utilities::common::js_error;
use crate::wasm_api::utilities::common::network_to_prefix;
use crate::{account::bip32, privacy::stealth};
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
// ─── Stealth Addresses ───

/// Derive a stealth meta-address from a kpub string.
/// Returns JSON: { scan_pubkey: "hex", spend_pubkey: "hex", meta_address: "hex128" }
#[wasm_bindgen]
pub fn stealth_meta_from_kpub(kpub_str: &str) -> Result<String, JsValue> {
    let xpub = bip32::ExtPubKey::from_kpub(kpub_str).map_err(js_error)?;
    let meta = stealth::derive_stealth_meta(&xpub).map_err(js_error)?;
    let encoded = stealth::encode_stealth_meta(&meta);
    let scan_x = hex::encode(stealth::x_only_pub(&meta.scan_pubkey));
    let spend_x = hex::encode(stealth::x_only_pub(&meta.spend_pubkey));
    let result = serde_json::json!({
        "scan_pubkey": scan_x,
        "spend_pubkey": spend_x,
        "meta_address": encoded,
    });
    serde_json::to_string(&result).map_err(|e| js_error(e.to_string()))
}

/// Generate a stealth payment: derive one-time address + ephemeral R.
/// `meta_hex` is the 128-char stealth meta-address.
/// `entropy_hex` is 64 hex chars (32 bytes) of randomness from window.crypto.
/// `network` is "mainnet" or "testnet-12" etc.
/// Returns JSON: { address, ephemeral_r, stealth_index }
#[wasm_bindgen]
pub fn stealth_generate_payment(
    meta_hex: &str,
    entropy_hex: &str,
    network: &str,
) -> Result<String, JsValue> {
    let meta = stealth::decode_stealth_meta(meta_hex).map_err(js_error)?;

    let entropy_bytes =
        hex::decode(entropy_hex).map_err(|e| js_error(format!("Bad entropy hex: {}", e)))?;
    if entropy_bytes.len() != 32 {
        return Err(js_error("Entropy must be 32 bytes"));
    }
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&entropy_bytes);

    let payment = stealth::generate_stealth_payment(&meta, &entropy).map_err(js_error)?;

    let prefix = network_to_prefix(network);
    let address = crate::account::address::encode_p2pk_address(&payment.one_time_pubkey, prefix);

    let result = serde_json::json!({
        "address": address,
        "ephemeral_r": hex::encode(payment.ephemeral_pubkey),
        "stealth_index": payment.stealth_index,
    });
    serde_json::to_string(&result).map_err(|e| js_error(e.to_string()))
}

/// Get the well-known stealth announcement address for a network.
#[wasm_bindgen]
pub fn stealth_announcement_address(network: &str) -> String {
    let prefix = network_to_prefix(network);
    stealth::announcement_address(prefix)
}
