//! Thin WASM adapter for owner-path covenant spends.

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[cfg(test)]
pub(super) use crate::transaction_builder::covenant::sweeps::owner::OwnerSpendPlan;

fn log_result(
    label: &str,
    prepared: &crate::transaction_builder::pskb::PreparedSweep,
    fee: u64,
    wire: &str,
    lock_time: u64,
) {
    super::super::logging::log_prepared_sweep_with_detail(
        label,
        prepared,
        fee,
        wire,
        ("locktime", lock_time),
    );
}

#[wasm_bindgen]
pub async fn create_covenant_owner_spend(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    fee: u64,
    ws_url: &str,
    covenant_branch: &str,
) -> Result<String, JsValue> {
    let (prepared, wire, lock_time) =
        crate::transaction_builder::covenant::sweeps::owner::build_automatic(
            covenant_address,
            dest_address,
            redeem_script_hex,
            fee,
            ws_url,
            covenant_branch,
        )
        .await
        .map_err(|error| wasm_error!(&error))?;
    log_result(
        "Covenant owner-spend PSKB",
        &prepared,
        fee,
        &wire,
        lock_time,
    );
    Ok(wire)
}

#[wasm_bindgen]
pub fn create_covenant_owner_spend_selected(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    utxos_json: &str,
    fee: u64,
    covenant_branch: &str,
) -> Result<String, JsValue> {
    let (prepared, wire, lock_time) =
        crate::transaction_builder::covenant::sweeps::owner::build_selected(
            covenant_address,
            dest_address,
            redeem_script_hex,
            utxos_json,
            fee,
            covenant_branch,
        )
        .map_err(|error| wasm_error!(&error))?;
    log_result(
        "Covenant owner-spend-selected PSKB",
        &prepared,
        fee,
        &wire,
        lock_time,
    );
    Ok(wire)
}

#[cfg(test)]
mod unit_tests;
