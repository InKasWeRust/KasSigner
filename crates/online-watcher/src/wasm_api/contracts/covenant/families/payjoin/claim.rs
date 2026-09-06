//! Thin WASM boundary for PayJoin claim planning.

use wasm_bindgen::prelude::JsValue;

#[cfg(test)]
use crate::transaction_builder::covenant::payjoin::PayjoinClaim;
#[cfg(test)]
pub(crate) use crate::transaction_builder::covenant::payjoin::{
    build_claim, fetch_covenant_utxos, fetch_smallest_mixing_utxo,
};

pub(super) async fn create(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    mixing_address: &str,
    requested_fee: u64,
    websocket_url: &str,
) -> Result<String, JsValue> {
    let claim = crate::transaction_builder::covenant::payjoin::create(
        covenant_address,
        destination_address,
        redeem_script_hex,
        mixing_address,
        requested_fee,
        websocket_url,
    )
    .await
    .map_err(|error| wasm_error!(&error))?;
    log_summary(&claim);
    Ok(claim.wire)
}

fn log_summary(claim: &crate::transaction_builder::covenant::payjoin::PayjoinClaim) {
    crate::infrastructure::log_info(format!(
        "[KasSee] PayJoin claim PSKB: {} inputs ({}cov + 1own), total {}, send {}, change {}, fee {}",
        claim.input_count,
        claim.covenant_input_count,
        claim.total,
        claim.send,
        claim.change,
        claim.fee,
    ));
}

#[cfg(test)]
pub(super) fn log_claim(claim: &PayjoinClaim) {
    log_summary(claim);
}
