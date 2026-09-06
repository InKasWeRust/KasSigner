#[cfg(any(test, target_arch = "wasm32"))]
use super::super::super::global_thread::{create_topup, TopupApiRequest};
use super::super::super::global_thread::{
    create_withdrawal, GlobalThreadFamily, WithdrawalRequest,
};
use crate::wasm_api::utilities::common::js_error;
#[cfg(any(test, target_arch = "wasm32"))]
use crate::wasm_api::utilities::common::parse_request_string;
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

async fn create_global_spending_limit_withdraw_core(
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
            family: GlobalThreadFamily::SpendingLimit,
            covenant_address,
            destination_address: dest_address,
            redeem_script_hex,
            covenant_id_hex,
            withdrawal: withdraw_sompi,
            fee,
            selected_utxos_json,
        },
        "Global spending-limit",
    )
    .await
}

/// Create a PSKB for a GLOBAL spending-limit withdrawal (single covenant_id thread).
///
/// A normal withdrawal emits one tagged continuation plus the destination output;
/// a close emits only the destination output when the full balance fits the cap.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn create_global_spending_limit_withdraw(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    selected_utxos_json: &str,
) -> Result<String, JsValue> {
    create_global_spending_limit_withdraw_core(
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
pub async fn create_global_spending_limit_withdraw(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    selected_utxos_json: &str,
) -> Result<String, String> {
    create_global_spending_limit_withdraw_core(
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
async fn create_global_spending_limit_topup_core(request_json: &str) -> Result<String, String> {
    let request: TopupApiRequest =
        parse_request_string(request_json, "spending-limit top-up request")?;
    create_topup(
        request.request(GlobalThreadFamily::SpendingLimit)?,
        "Global spending-limit",
    )
    .await
}

/// Create a PSKB that TOPS UP / consolidates the GLOBAL spending-limit thread.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn create_global_spending_limit_topup(request_json: &str) -> Result<String, JsValue> {
    create_global_spending_limit_topup_core(request_json)
        .await
        .map_err(js_error)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub async fn create_global_spending_limit_topup(request_json: &str) -> Result<String, String> {
    create_global_spending_limit_topup_core(request_json).await
}

/// Build a GLOBAL spending-limit covenant P2SH address (covenant_id single-thread).
///
/// Same per-spend cap + cooldown as `covenant_spending_limit`, but the whole
/// balance lives in ONE covenant_id-tagged UTXO (the thread), so the cap is
/// global instead of per-UTXO. Fund it as a covenant genesis via
/// `create_covenant_pskb` (passing this address), which tags the first UTXO
/// with the covenant_id that identifies the thread. Spend it later with
/// `create_global_spending_limit_withdraw`, which continues the single thread.
///
/// Returns JSON: { address, redeem_script_hex, max_withdraw_sompi, cooldown_daa, salt }
#[wasm_bindgen]
pub fn covenant_global_spending_limit(
    owner_pubkey_hex: &str,
    max_withdraw_sompi: u64,
    cooldown_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    crate::contracts::covenant::construction::spending_limit::build_global_json(
        owner_pubkey_hex,
        max_withdraw_sompi,
        cooldown_daa,
        network,
    )
    .map_err(js_error)
}
