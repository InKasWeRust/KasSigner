#[cfg(any(test, target_arch = "wasm32"))]
use super::super::super::global_thread::{create_topup, TopupApiRequest};
use super::super::super::global_thread::{
    create_withdrawal, GlobalThreadFamily, WithdrawalRequest,
};
use crate::wasm_api::utilities::common::js_error;
#[cfg(any(test, target_arch = "wasm32"))]
use crate::wasm_api::utilities::common::parse_request_string;
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

async fn create_global_allowance_withdraw_core(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    selected_utxos_json: &str,
) -> Result<String, String> {
    create_withdrawal(
        WithdrawalRequest {
            family: GlobalThreadFamily::Allowance,
            covenant_address,
            destination_address: dest_address,
            redeem_script_hex,
            covenant_id_hex,
            withdrawal: withdraw_sompi,
            fee,
            selected_utxos_json,
        },
        "Global allowance",
    )
    .await
}

/// Create a PSKB for a BENEFICIARY withdrawal from a GLOBAL ALLOWANCE thread.
///
/// The thread is a single tagged UTXO. A normal withdrawal continues the thread
/// with one tagged output; a close takes the whole balance with no continuation.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn create_global_allowance_withdraw(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    selected_utxos_json: &str,
) -> Result<String, JsValue> {
    create_global_allowance_withdraw_core(
        covenant_address,
        dest_address,
        redeem_script_hex,
        covenant_id_hex,
        withdraw_sompi,
        fee,
        selected_utxos_json,
    )
    .await
    .map_err(js_error)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn create_global_allowance_withdraw(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    selected_utxos_json: &str,
) -> Result<String, String> {
    create_global_allowance_withdraw_core(
        covenant_address,
        dest_address,
        redeem_script_hex,
        covenant_id_hex,
        withdraw_sompi,
        fee,
        selected_utxos_json,
    )
    .await
}

#[cfg(any(test, target_arch = "wasm32"))]
async fn create_global_allowance_topup_core(request_json: &str) -> Result<String, String> {
    let request: TopupApiRequest = parse_request_string(request_json, "allowance top-up request")?;
    create_topup(
        request.request(GlobalThreadFamily::Allowance)?,
        "Global allowance",
    )
    .await
}

/// Create a PSKB that TOPS UP the GLOBAL ALLOWANCE thread (OWNER adds funds).
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn create_global_allowance_topup(request_json: &str) -> Result<String, JsValue> {
    create_global_allowance_topup_core(request_json)
        .await
        .map_err(js_error)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub async fn create_global_allowance_topup(request_json: &str) -> Result<String, String> {
    create_global_allowance_topup_core(request_json).await
}

/// Build a GLOBAL single-thread ALLOWANCE covenant P2SH address.
///
/// Per-spend cap applied to the whole thread balance (one tagged covenant_id
/// UTXO), withdrawn by the BENEFICIARY with a cooldown between withdrawals and
/// an optional vesting start date. The OWNER keeps a free reclaim/close path.
/// Genesis is created with `create_covenant_pskb_with_payload(tag_genesis=true)`
/// (full-spend, no change). Continued by `create_global_allowance_withdraw`
/// (beneficiary) and `create_global_allowance_topup` (owner).
///
/// Returns JSON: { address, redeem_script_hex, max_withdraw_sompi,
/// cooldown_daa, start_daa, salt, type }
#[wasm_bindgen]
pub fn covenant_global_allowance(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    max_withdraw_sompi: u64,
    cooldown_daa: u64,
    start_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    crate::contracts::covenant::construction::allowance::build_global_json(
        owner_pubkey_hex,
        beneficiary_pubkey_hex,
        max_withdraw_sompi,
        cooldown_daa,
        start_daa,
        network,
    )
    .map_err(js_error)
}
