use crate::wasm_api::utilities::common::{js_error, serialize_json};
use crate::{network, privacy::stealth};
use wasm_bindgen::prelude::*;

/// Query node for current fee rates → return JSON
#[wasm_bindgen]
pub async fn get_fee_estimate(ws_url: &str) -> Result<String, JsValue> {
    let estimate = network::queries::fees::get(ws_url)
        .await
        .map_err(js_error)?;
    serialize_json(&estimate)
}

/// Fetch UTXOs for a single address (for multisig balance check) → JSON array
#[wasm_bindgen]
pub async fn fetch_utxos_for_address_js(address: &str, ws_url: &str) -> Result<String, JsValue> {
    let utxos = network::queries::utxos::fetch_for_address(ws_url, address)
        .await
        .map_err(js_error)?;
    serialize_json(&utxos)
}

/// Get the current virtual DAA score from the node.
#[wasm_bindgen]
pub async fn get_virtual_daa_score(ws_url: &str) -> Result<String, JsValue> {
    let daa = network::queries::chain::virtual_daa_score(ws_url)
        .await
        .map_err(js_error)?;
    Ok(daa.to_string())
}

/// Build a NotifyVirtualChainChanged subscribe request (raw bytes).
#[wasm_bindgen]
pub fn build_vcc_subscribe_request(request_id: u64) -> Result<Vec<u8>, JsValue> {
    network::codec::requests::subscription::block_added(request_id)
        .map_err(|error| js_error(error.to_string()))
}

/// Build a NotifyUtxosChanged subscribe request.
#[wasm_bindgen]
pub fn build_utxo_subscribe_request(
    covenant_address: &str,
    request_id: u64,
) -> Result<Vec<u8>, JsValue> {
    network::codec::requests::subscription::utxos_changed(covenant_address, request_id)
        .map_err(|error| js_error(error.to_string()))
}

/// Search a specific block (by hash hex) for a TX that spent the given outpoint.
/// Returns hex-encoded preimage if found, empty string if not.
#[wasm_bindgen]
pub async fn find_preimage_in_block(
    block_hash_hex: &str,
    outpoint_txid_hex: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let (block_hash, transaction_id) =
        decode_preimage_query(block_hash_hex, outpoint_txid_hex).map_err(js_error)?;
    let raw = network::queries::blocks::get_raw(ws_url, &block_hash)
        .await
        .map_err(js_error)?;
    Ok(find_preimage_in_raw_block(&raw, &transaction_id))
}

pub(crate) fn decode_preimage_query(
    block_hash_hex: &str,
    outpoint_txid_hex: &str,
) -> Result<([u8; 32], [u8; 32]), String> {
    let block_hash = decode_hash32(block_hash_hex, "block hash")?;
    let transaction_id = decode_hash32(outpoint_txid_hex, "txid")?;
    Ok((block_hash, transaction_id))
}

fn decode_hash32(value: &str, name: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("Invalid {name}: {error}"))?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| "Hash and txid must be 32 bytes".to_string())
}

pub(crate) fn find_preimage_in_raw_block(raw: &[u8], transaction_id: &[u8; 32]) -> String {
    stealth::scanner::scan_raw_for_preimage(raw, transaction_id)
        .map(hex::encode)
        .unwrap_or_default()
}
