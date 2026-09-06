//! Thin WASM boundary for shipping-escrow withdrawals.

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[cfg(test)]
pub(super) use crate::transaction_builder::covenant::shipping::withdraw::build_withdrawal;

#[wasm_bindgen]
pub async fn create_covenant_borrower_withdraw(
    borrower_wallet_json: &str,
    covenant_address: &str,
    redeem_script_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let summary = crate::transaction_builder::covenant::shipping::withdraw::create_remote(
        borrower_wallet_json,
        covenant_address,
        redeem_script_hex,
        withdraw_sompi,
        fee,
        ws_url,
    )
    .await
    .map_err(|error| wasm_error!(&error))?;
    log_summary(&summary, fee);
    Ok(summary.wire)
}

pub(super) fn log_summary(
    summary: &crate::transaction_builder::covenant::shipping::withdraw::WithdrawalSummary,
    fee: u64,
) {
    crate::infrastructure::log_info(format!(
        "[KasSee] Covenant borrower-withdraw PSKB: 1 covenant + {} funding inputs, return={}, withdraw={}, fee={}, wire {} chars",
        summary.funding_count,
        summary.covenant_return,
        summary.borrower_receive,
        fee,
        summary.wire.len()
    ));
}
