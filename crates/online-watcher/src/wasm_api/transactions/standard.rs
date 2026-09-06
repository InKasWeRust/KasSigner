use super::explicit_utxos::parse_explicit_utxos;
use crate::wasm_api::utilities::common::{js_error, parse_utxo_indices, parse_wallet};
use crate::WatchWallet;
use wasm_bindgen::prelude::*;

async fn create_send(
    wallet_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    ws_url: &str,
    wallet_error_prefix: &str,
) -> Result<String, JsValue> {
    let wallet = parse_wallet(wallet_json, wallet_error_prefix)?;
    WatchWallet::new()
        .build_transaction(&wallet, dest_address, amount_sompi, fee_sompi, ws_url)
        .await
        .map_err(js_error)
}

async fn create_consolidation(
    wallet_json: &str,
    fee_sompi: u64,
    ws_url: &str,
    wallet_error_prefix: &str,
) -> Result<String, JsValue> {
    let wallet = parse_wallet(wallet_json, wallet_error_prefix)?;
    WatchWallet::new()
        .build_consolidation(&wallet, fee_sompi, ws_url)
        .await
        .map_err(js_error)
}

struct SelectedSendRequest<'a> {
    wallet_json: &'a str,
    destination: &'a str,
    amount_sompi: u64,
    fee_sompi: u64,
    utxo_indices_csv: &'a str,
    ws_url: &'a str,
    wallet_error_prefix: &'a str,
}

async fn create_selected_send(request: SelectedSendRequest<'_>) -> Result<String, JsValue> {
    let wallet = parse_wallet(request.wallet_json, request.wallet_error_prefix)?;
    let indices = parse_utxo_indices(request.utxo_indices_csv)?;
    WatchWallet::new()
        .build_selected_transaction(
            &wallet,
            request.destination,
            request.amount_sompi,
            request.fee_sompi,
            &indices,
            request.ws_url,
        )
        .await
        .map_err(js_error)
}

/// Create an unsigned single-signature PSKB. Routes through the PSKT review
/// screen on the JS side (same flow as multisig PSKB).
#[wasm_bindgen]
pub async fn create_send_pskb(
    wallet_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    create_send(
        wallet_json,
        dest_address,
        amount_sompi,
        fee_sompi,
        ws_url,
        "Bad wallet",
    )
    .await
}

/// Create an unsigned PSKB with automatic largest-first selection capped by
/// the user-visible Advanced UTXO limit. The requested value is additionally
/// bounded by the public KasSigner signer-capability contract.
#[wasm_bindgen]
pub async fn create_send_pskb_limited(
    wallet_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    max_inputs: u32,
    ws_url: &str,
) -> Result<String, JsValue> {
    let (wallet, max_inputs) = parse_limited_send_request(wallet_json, max_inputs)?;
    crate::transaction_builder::create_send_limited(
        &wallet,
        dest_address,
        amount_sompi,
        fee_sompi,
        max_inputs,
        ws_url,
    )
    .await
    .map_err(js_error)
}

fn parse_limited_send_request(
    wallet_json: &str,
    max_inputs: u32,
) -> Result<(crate::account::bip32::WalletData, usize), JsValue> {
    if max_inputs == 0 {
        return Err(js_error("UTXO selection limit must be at least 1"));
    }
    let signer_limit = u32::from(kassigner_protocol::SIGNER_CAPABILITIES.max_inputs);
    if max_inputs > signer_limit {
        return Err(js_error(format!(
            "UTXO selection limit exceeds KasSigner capability ({signer_limit})"
        )));
    }
    parse_wallet(wallet_json, "Bad wallet").map(|wallet| (wallet, max_inputs as usize))
}

/// Consolidate all UTXOs into one via PSKB format.
#[wasm_bindgen]
pub async fn create_consolidate_pskb(
    wallet_json: &str,
    fee_sompi: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    create_consolidation(wallet_json, fee_sompi, ws_url, "Bad wallet").await
}

/// Create unsigned PSKB with specific UTXO indices.
#[wasm_bindgen]
pub async fn create_send_pskb_selected(
    wallet_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    utxo_csv: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    create_selected_send(SelectedSendRequest {
        wallet_json,
        destination: dest_address,
        amount_sompi,
        fee_sompi,
        utxo_indices_csv: utxo_csv,
        ws_url,
        wallet_error_prefix: "Bad wallet",
    })
    .await
}

/// Create unsigned PSKB with explicit UTXO data (no re-fetch, no stale indices).
/// utxos_json: JSON array of {tx_id, index, amount, script_public_key, block_daa_score} objects.
#[wasm_bindgen]
pub async fn create_send_pskb_with_utxos(
    wallet_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    utxos_json: &str,
) -> Result<String, JsValue> {
    let wallet = parse_wallet(wallet_json, "Bad wallet")?;
    let utxos = parse_explicit_utxos(utxos_json)?;
    WatchWallet::new()
        .build_pskb_with_utxos(&wallet, dest_address, amount_sompi, fee_sompi, utxos)
        .map_err(js_error)
}

#[cfg(test)]
mod unit_tests;
