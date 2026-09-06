use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
/// Build a time-locked escrow covenant P2SH address.
/// alice_pubkey_hex / bob_pubkey_hex: 32-byte x-only pubkeys (hex)
/// alice_addr / bob_addr: destination addresses for each party
/// locktime_daa: DAA score after which funds auto-refund to Alice
/// Returns JSON: { "address", "redeem_script_hex", "locktime_daa" }
#[wasm_bindgen]
pub fn covenant_timelocked_escrow(
    alice_pubkey_hex: &str,
    bob_pubkey_hex: &str,
    alice_addr: &str,
    bob_addr: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    build_timelocked_escrow_json(
        alice_pubkey_hex,
        bob_pubkey_hex,
        alice_addr,
        bob_addr,
        locktime_daa,
        network,
    )
    .map_err(|error| wasm_error!(&error))
}

pub(crate) fn build_timelocked_escrow_json(
    alice_pubkey_hex: &str,
    bob_pubkey_hex: &str,
    alice_addr: &str,
    bob_addr: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, String> {
    crate::contracts::covenant::construction::escrow::build_timelocked_json(
        alice_pubkey_hex,
        bob_pubkey_hex,
        alice_addr,
        bob_addr,
        locktime_daa,
        network,
    )
}

/// Create a PSKB for a timeout refund on a time-locked escrow.
#[wasm_bindgen]
pub async fn create_covenant_timeout_refund(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let (prepared, wire) =
        crate::transaction_builder::covenant::sweeps::timelocked::build_timeout_refund(
            covenant_address,
            dest_address,
            redeem_script_hex,
            locktime_daa,
            fee,
            ws_url,
        )
        .await
        .map_err(|error| wasm_error!(&error))?;
    super::super::logging::log_prepared_sweep_with_detail(
        "Timeout-refund PSKB",
        &prepared,
        fee,
        &wire,
        ("locktime", locktime_daa),
    );
    Ok(wire)
}

#[wasm_bindgen]
pub async fn create_covenant_beneficiary_spend(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let (prepared, wire, displayed_locktime) =
        crate::transaction_builder::covenant::sweeps::timelocked::build_beneficiary_automatic(
            covenant_address,
            dest_address,
            redeem_script_hex,
            locktime_daa,
            fee,
            ws_url,
        )
        .await
        .map_err(|error| wasm_error!(&error))?;
    super::super::logging::log_prepared_sweep_with_detail(
        "Beneficiary-spend PSKB",
        &prepared,
        fee,
        &wire,
        ("locktime", displayed_locktime),
    );
    Ok(wire)
}

#[wasm_bindgen]
pub fn create_covenant_beneficiary_spend_selected(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    utxos_json: &str,
    fee: u64,
) -> Result<String, JsValue> {
    let (prepared, wire, displayed_locktime) =
        crate::transaction_builder::covenant::sweeps::timelocked::build_beneficiary_selected(
            covenant_address,
            dest_address,
            redeem_script_hex,
            locktime_daa,
            utxos_json,
            fee,
        )
        .map_err(|error| wasm_error!(&error))?;
    super::super::logging::log_prepared_sweep_with_detail(
        "Beneficiary-spend (selected) PSKB",
        &prepared,
        fee,
        &wire,
        ("locktime", displayed_locktime),
    );
    Ok(wire)
}

#[cfg(test)]
pub(crate) use crate::transaction_builder::covenant::sweeps::timelocked::{
    timeout_refund_spec, BeneficiarySweepPlan,
};

#[cfg(test)]
mod unit_tests;
