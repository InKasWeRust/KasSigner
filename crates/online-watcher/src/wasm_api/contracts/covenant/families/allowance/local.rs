use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[cfg(test)]
pub(crate) use crate::transaction_builder::covenant::allowance::build_allowance_withdrawal;
use crate::transaction_builder::covenant::allowance::AllowanceWithdrawal;

/// Beneficiary signs the allowance covenant's ELSE branch.
#[wasm_bindgen]
pub async fn create_covenant_allowance_withdraw(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let withdrawal = crate::transaction_builder::covenant::allowance::build_remote(
        covenant_address,
        dest_address,
        redeem_script_hex,
        withdraw_sompi,
        fee,
        ws_url,
    )
    .await;
    finalize_withdrawal_result(withdrawal, withdraw_sompi, fee)
}

pub(in crate::wasm_api::contracts::covenant::families) fn finalize_withdrawal_result(
    withdrawal: Result<AllowanceWithdrawal, String>,
    withdraw_sompi: u64,
    fee: u64,
) -> Result<String, JsValue> {
    let withdrawal = withdrawal.map_err(|error| wasm_error!(&error))?;
    log_withdrawal(&withdrawal, withdraw_sompi, fee);
    Ok(withdrawal.wire)
}

pub(in crate::wasm_api::contracts::covenant::families) fn log_withdrawal(
    withdrawal: &AllowanceWithdrawal,
    withdraw_sompi: u64,
    fee: u64,
) {
    crate::infrastructure::log_info(format!(
        "[KasSee] Allowance-withdraw PSKB: {} inputs, total_in={}, withdraw={}, return={}, fee={}, csv_seq={}, wire {} chars",
        withdrawal.input_count,
        withdrawal.total_balance,
        withdraw_sompi,
        withdrawal.return_amount,
        fee,
        withdrawal.sequence,
        withdrawal.wire.len()
    ));
}

/// Build an allowance covenant P2SH address.
#[wasm_bindgen]
pub fn covenant_allowance(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    max_withdraw_sompi: u64,
    min_sequence: u64,
    start_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    crate::contracts::covenant::construction::allowance::build_local_json(
        owner_pubkey_hex,
        beneficiary_pubkey_hex,
        max_withdraw_sompi,
        min_sequence,
        start_daa,
        network,
    )
    .map_err(|error| wasm_error!(&error))
}
