//! Thin WASM adapters for crowdfunding proof/covenant services.

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn zk_crowdfund_setup() -> Result<String, JsValue> {
    crate::contracts::zk::crowdfund::setup_json().map_err(|error| wasm_error!(&error))
}

#[wasm_bindgen]
pub fn zk_crowdfund_prove(
    proving_key_hex: &str,
    verifying_key_hex: &str,
    amounts_json: &str,
) -> Result<String, JsValue> {
    build_proof_json(proving_key_hex, verifying_key_hex, amounts_json)
        .map_err(|error| wasm_error!(&error))
}

#[wasm_bindgen]
pub fn crowdfund_campaign_id(
    organizer_address: &str,
    goal_sompi: u64,
    locktime_daa: u64,
    verifying_key_hex: &str,
) -> Result<String, JsValue> {
    compute_campaign_id_hex(
        organizer_address,
        goal_sompi,
        locktime_daa,
        verifying_key_hex,
    )
    .map_err(|error| wasm_error!(&error))
}

#[wasm_bindgen]
pub fn covenant_crowdfund(
    contributor_pubkey_hex: &str,
    organizer_address: &str,
    goal_sompi: u64,
    locktime_daa: u64,
    verifying_key_hex: &str,
    network: &str,
) -> Result<String, JsValue> {
    build_crowdfund_address_json(
        contributor_pubkey_hex,
        organizer_address,
        goal_sompi,
        locktime_daa,
        verifying_key_hex,
        network,
    )
    .map_err(|error| wasm_error!(&error))
}

pub(in crate::wasm_api::contracts::zk) fn build_proof_json(
    proving_key_hex: &str,
    verifying_key_hex: &str,
    amounts_json: &str,
) -> Result<String, String> {
    crate::contracts::zk::crowdfund::build_proof_json(
        proving_key_hex,
        verifying_key_hex,
        amounts_json,
    )
}

pub(in crate::wasm_api::contracts::zk) fn compute_campaign_id_hex(
    organizer_address: &str,
    goal_sompi: u64,
    locktime_daa: u64,
    verifying_key_hex: &str,
) -> Result<String, String> {
    crate::contracts::zk::crowdfund::compute_campaign_id_hex(
        organizer_address,
        goal_sompi,
        locktime_daa,
        verifying_key_hex,
    )
}

pub(in crate::wasm_api::contracts::zk) fn build_crowdfund_address_json(
    contributor_pubkey_hex: &str,
    organizer_address: &str,
    goal_sompi: u64,
    locktime_daa: u64,
    verifying_key_hex: &str,
    network: &str,
) -> Result<String, String> {
    crate::contracts::zk::crowdfund::build_address_json(
        contributor_pubkey_hex,
        organizer_address,
        goal_sompi,
        locktime_daa,
        verifying_key_hex,
        network,
    )
}

#[cfg(test)]
use crate::contracts::zk::crowdfund::{
    decode_hex_bounded, encode_setup_json, MAX_CROWDFUND_PK_BYTES, MAX_CROWDFUND_VK_BYTES,
};

#[cfg(test)]
mod unit_tests;
