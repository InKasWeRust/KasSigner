use super::{wasm_bindgen, JsValue};
/// Create a PayJoin covenant address.
///
/// Two branches:
///   - Owner refund after locktime (IF)
///   - Beneficiary claims only in a multi-input TX with mixed addresses (ELSE)
///
/// Returns JSON: { address, redeem_script_hex, locktime_daa }
#[wasm_bindgen]
pub fn covenant_payjoin(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    locktime_daa: u64,
    min_inputs: u64,
    min_outputs: u64,
    network: &str,
) -> Result<String, JsValue> {
    crate::contracts::covenant::construction::payjoin::build_json(
        owner_pubkey_hex,
        beneficiary_pubkey_hex,
        locktime_daa,
        min_inputs,
        min_outputs,
        network,
    )
    .map_err(|error| wasm_error!(&error))
}

/// Create a PSKB for a PayJoin covenant claim (beneficiary spend).
///
/// The transaction mixes at least one caller-owned input with the covenant
/// inputs so the covenant can verify that distinct script owners participate.
#[wasm_bindgen]
pub async fn create_covenant_payjoin_claim(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    extra_utxo_address: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    claim::create(
        covenant_address,
        dest_address,
        redeem_script_hex,
        extra_utxo_address,
        fee,
        ws_url,
    )
    .await
}

mod claim;

#[cfg(test)]
mod unit_tests;
