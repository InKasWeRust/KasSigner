//! Thin WASM adapters for crowdfunding sweep application services.

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[wasm_bindgen]
pub async fn inspect_crowdfund_contributions(
    contributions_json: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    crate::transaction_builder::zk::crowdfund::inspect_crowdfund_contributions_string(
        contributions_json,
        ws_url,
    )
    .await
    .map_err(|error| wasm_error!(&error))
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_crowdfund_sweep(
    contributions_json: &str,
    organizer_address: &str,
    goal_sompi: u64,
    locktime_daa: u64,
    verifying_key_hex: &str,
    proof_hex: &str,
    public_input_hex: &str,
    requested_fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    crate::transaction_builder::zk::crowdfund::create_crowdfund_sweep_string(
        contributions_json,
        organizer_address,
        goal_sompi,
        locktime_daa,
        verifying_key_hex,
        proof_hex,
        public_input_hex,
        requested_fee,
        ws_url,
    )
    .await
    .map_err(|error| wasm_error!(&error))
}

#[cfg(test)]
pub(in crate::wasm_api::contracts::zk) use crate::transaction_builder::zk::crowdfund::{
    prepare_crowdfund_sweep, ContributionRef, CrowdfundSweepRequest,
};
