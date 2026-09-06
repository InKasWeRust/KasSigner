//! Thin Oracle-v1 covenant WASM boundary.

use super::{wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn covenant_oracle_v1(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    oracle_pubkey_hex: &str,
    oracle_covenant_key_id_hex: &str,
    release_statement: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    build_oracle_v1_json(
        owner_pubkey_hex,
        beneficiary_pubkey_hex,
        oracle_pubkey_hex,
        oracle_covenant_key_id_hex,
        release_statement,
        locktime_daa,
        network,
    )
    .map_err(|error| wasm_error!(&error))
}

pub(crate) fn build_oracle_v1_json(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    oracle_pubkey_hex: &str,
    oracle_covenant_key_id_hex: &str,
    release_statement: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, String> {
    crate::contracts::covenant::oracle_v1::build_json(
        owner_pubkey_hex,
        beneficiary_pubkey_hex,
        oracle_pubkey_hex,
        oracle_covenant_key_id_hex,
        release_statement,
        locktime_daa,
        network,
    )
}

#[wasm_bindgen]
pub fn verify_oracle_v1_attestation(
    oracle_pubkey_hex: &str,
    oracle_signature_hex: &str,
    message_commitment_hex: &str,
) -> Result<bool, JsValue> {
    crate::contracts::covenant::oracle_v1::verify_attestation(
        oracle_pubkey_hex,
        oracle_signature_hex,
        message_commitment_hex,
    )
    .map_err(|error| wasm_error!(&error))
}

// Positional arguments are part of the stable wasm-bindgen API.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub async fn create_covenant_oracle_v1_claim(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    oracle_pubkey_hex: &str,
    oracle_signature_hex: &str,
    message_commitment_hex: &str,
    fee: u64,
    websocket_url: &str,
) -> Result<String, JsValue> {
    let (prepared, wire) = crate::transaction_builder::covenant::oracle_v1::build_claim(
        crate::transaction_builder::covenant::oracle_v1::OracleClaimRequest {
            covenant_address,
            destination_address,
            redeem_script_hex,
            oracle_pubkey_hex,
            oracle_signature_hex,
            message_commitment_hex,
            fee,
            websocket_url,
        },
    )
    .await
    .map_err(|error| wasm_error!(&error))?;
    super::logging::log_prepared_sweep("Oracle-v1 claim PSKB", &prepared, fee, &wire);
    Ok(wire)
}

#[cfg(test)]
use crate::contracts::covenant::oracle_v1::{checked_redeem_and_attestation, decode_attestation};

#[cfg(test)]
mod unit_tests;
