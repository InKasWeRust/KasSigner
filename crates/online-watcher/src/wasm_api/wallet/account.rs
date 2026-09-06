use crate::wasm_api::utilities::common::{
    js_error, network_to_prefix, parse_wallet, serialize_json,
};
use crate::{account::bip32, WatchWallet};
use wasm_bindgen::prelude::*;

/// Import canonical `kpub1:` text and derive receive/change addresses.
#[wasm_bindgen]
pub fn import_kpub(kpub_str: &str, network: &str) -> Result<String, JsValue> {
    let prefix = network_to_prefix(network);
    let result = WatchWallet::new()
        .import_account(kpub_str, prefix)
        .map_err(js_error)?;
    serialize_json(&result)
}

/// Import the 78-byte payload from the compact binary QR envelope.
#[wasm_bindgen]
pub fn import_kpub_raw(raw_payload: &[u8], network: &str) -> Result<String, JsValue> {
    let prefix = network_to_prefix(network);
    let result = WatchWallet::new()
        .import_raw_account(raw_payload, prefix)
        .map_err(js_error)?;
    serialize_json(&result)
}

/// Derive additional receive/change addresses beyond the current set.
#[wasm_bindgen]
pub fn extend_addresses(
    wallet_json: &str,
    extra_receive: u32,
    extra_change: u32,
    network: &str,
) -> Result<String, JsValue> {
    let wallet = parse_wallet(wallet_json, "Invalid wallet")?;
    let prefix = network_to_prefix(network);
    let result =
        bip32::extend_addresses(&wallet, extra_receive, extra_change, prefix).map_err(js_error)?;
    serialize_json(&result)
}

/// Connect to node via Borsh wRPC, fetch UTXOs, return JSON balance.
#[wasm_bindgen]
pub async fn fetch_balance(wallet_json: &str, ws_url: &str) -> Result<String, JsValue> {
    let wallet = parse_wallet(wallet_json, "Invalid wallet")?;
    let balance = WatchWallet::new()
        .synchronize_balance(&wallet, ws_url)
        .await
        .map_err(js_error)?;
    serialize_json(&balance)
}

/// Fetch all UTXOs as JSON array
#[wasm_bindgen]
pub async fn fetch_utxos(wallet_json: &str, ws_url: &str) -> Result<String, JsValue> {
    let wallet = parse_wallet(wallet_json, "Invalid wallet")?;
    let utxos = WatchWallet::new()
        .synchronize_utxos(&wallet, ws_url)
        .await
        .map_err(js_error)?;
    serialize_json(&utxos)
}

/// Fetch the complete UTXO set for manual coin control using bounded address batches.
#[wasm_bindgen]
pub async fn fetch_utxos_complete(wallet_json: &str, ws_url: &str) -> Result<String, JsValue> {
    let wallet = parse_wallet(wallet_json, "Invalid wallet")?;
    let utxos = WatchWallet::new()
        .synchronize_utxos_complete(&wallet, ws_url)
        .await
        .map_err(js_error)?;
    serialize_json(&utxos)
}
