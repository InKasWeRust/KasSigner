//! Thin WASM adapters for Merkle whitelist contracts and spends.

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn merkle_root_from_addresses(addresses_json: &str) -> Result<String, JsValue> {
    let result = crate::contracts::merkle::application::root_from_addresses(addresses_json)
        .map_err(|error| wasm_error!(&error))?;
    crate::infrastructure::log_info("[KasSee] Merkle whitelist root prepared");
    Ok(result)
}

#[wasm_bindgen]
pub fn merkle_proof_for_address(
    addresses_json: &str,
    target_address: &str,
) -> Result<String, JsValue> {
    crate::contracts::merkle::application::proof_for_address(addresses_json, target_address)
        .map_err(|error| wasm_error!(&error))
}

#[wasm_bindgen]
pub fn covenant_merkle_whitelist(
    owner_pubkey_hex: &str,
    merkle_root_hex: &str,
    depth: u8,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    crate::contracts::merkle::application::build_whitelist_json(
        owner_pubkey_hex,
        merkle_root_hex,
        depth,
        locktime_daa,
        network,
    )
    .map_err(|error| wasm_error!(&error))
}

#[wasm_bindgen]
pub async fn create_merkle_whitelist_spend(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    proof_json: &str,
    send_amount: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    crate::transaction_builder::zk::merkle::build_remote(
        covenant_address,
        dest_address,
        redeem_script_hex,
        proof_json,
        send_amount,
        fee,
        ws_url,
    )
    .await
    .map_err(|error| wasm_error!(&error))
}

#[cfg(test)]
pub(super) use crate::transaction_builder::zk::merkle::*;

#[cfg(test)]
mod unit_tests;
