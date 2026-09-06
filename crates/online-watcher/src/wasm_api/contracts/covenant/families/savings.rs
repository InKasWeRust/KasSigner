use super::{wasm_bindgen, JsValue};
/// Build a time-locked SAVINGS covenant P2SH address.
/// wallet1_pubkey_hex / wallet2_pubkey_hex: 32-byte x-only pubkeys (hex).
///   wallet2 is the key-loss recovery key (1-of-2, not multisig). Pass the
///   same value as wallet1 if you do not want a separate recovery key.
/// locktime_daa: DAA score; funds are frozen for everyone until this score,
///   after which either wallet can sweep with a single signature.
/// Returns JSON: { "address", "redeem_script_hex", "locktime_daa" }
#[wasm_bindgen]
pub fn covenant_timelocked_savings(
    wallet1_pubkey_hex: &str,
    wallet2_pubkey_hex: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    build_timelocked_savings_json(
        wallet1_pubkey_hex,
        wallet2_pubkey_hex,
        locktime_daa,
        network,
    )
    .map_err(|error| wasm_error!(&error))
}

pub(crate) fn build_timelocked_savings_json(
    wallet1_pubkey_hex: &str,
    wallet2_pubkey_hex: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, String> {
    crate::contracts::covenant::construction::savings::build_json(
        wallet1_pubkey_hex,
        wallet2_pubkey_hex,
        locktime_daa,
        network,
    )
}

/// Create a PSKB to claim a time-locked savings covenant.
#[wasm_bindgen]
pub async fn create_covenant_timelocked_savings_claim(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let (prepared, wire) = crate::transaction_builder::covenant::sweeps::savings::build_automatic(
        covenant_address,
        dest_address,
        redeem_script_hex,
        locktime_daa,
        fee,
        ws_url,
    )
    .await
    .map_err(|error| wasm_error!(&error))?;
    super::logging::log_prepared_sweep_with_detail(
        "Savings-claim PSKB",
        &prepared,
        fee,
        &wire,
        ("locktime", locktime_daa),
    );
    Ok(wire)
}

/// Create a PSKB from a caller-selected savings UTXO subset.
#[wasm_bindgen]
pub fn create_covenant_timelocked_savings_claim_selected(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    utxos_json: &str,
    fee: u64,
) -> Result<String, JsValue> {
    let (prepared, wire) = crate::transaction_builder::covenant::sweeps::savings::build_selected(
        covenant_address,
        dest_address,
        redeem_script_hex,
        locktime_daa,
        utxos_json,
        fee,
    )
    .map_err(|error| wasm_error!(&error))?;
    super::logging::log_prepared_sweep_with_detail(
        "Savings-claim (selected) PSKB",
        &prepared,
        fee,
        &wire,
        ("locktime", locktime_daa),
    );
    Ok(wire)
}

#[cfg(test)]
pub(crate) use crate::transaction_builder::covenant::sweeps::savings::SavingsClaimPlan;

#[cfg(test)]
mod unit_tests;
