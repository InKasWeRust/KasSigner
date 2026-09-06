//! Thin WASM adapters for commit-reveal contracts and spends.

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn covenant_commit_reveal(
    owner_pubkey_hex: &str,
    committed_hash_hex: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    build_commit_reveal_json(owner_pubkey_hex, committed_hash_hex, locktime_daa, network)
        .map_err(|error| wasm_error!(&error))
}

pub(super) fn build_commit_reveal_json(
    owner_pubkey_hex: &str,
    committed_hash_hex: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, String> {
    crate::contracts::commit_reveal::application::build_json(
        owner_pubkey_hex,
        committed_hash_hex,
        locktime_daa,
        network,
    )
}

#[cfg(test)]
pub(super) use crate::transaction_builder::zk::commit_reveal::parse as parse_commit_reveal_spend;

#[wasm_bindgen]
pub async fn create_commit_reveal_spend(request_json: &str) -> Result<String, JsValue> {
    crate::transaction_builder::zk::commit_reveal::build(request_json)
        .await
        .map_err(|error| wasm_error!(&error))
}

#[cfg(test)]
mod unit_tests;
