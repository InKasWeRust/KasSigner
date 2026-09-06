//! Browser-neutral PSKB sweep application services.
//!
//! These routines may acquire network state and apply transaction policy, but do
//! not depend on browser binding types. Browser adapters translate errors.

use super::{
    encode_prepared_sweep, prepare_sweep_from_utxos, PreparedSweep, PskbGlobalPlan,
    SweepInputPolicy,
};
use crate::network;

pub(crate) async fn prepare_sweep(
    websocket_url: &str,
    source_address: &str,
    destination_address: &str,
    fee: u64,
    empty_error: &str,
    low_balance_error: &str,
) -> Result<PreparedSweep, String> {
    let utxos = network::queries::utxos::fetch_for_address(websocket_url, source_address).await?;
    prepare_sweep_from_utxos(
        utxos,
        source_address,
        destination_address,
        fee,
        empty_error,
        low_balance_error,
    )
}

pub(crate) fn encode(
    prepared: &PreparedSweep,
    global: PskbGlobalPlan,
    input_policy: &SweepInputPolicy,
) -> Result<String, String> {
    encode_prepared_sweep(prepared, global, input_policy)
}

pub(crate) struct CovenantSweepRequest<'a> {
    pub(crate) websocket_url: &'a str,
    pub(crate) covenant_address: &'a str,
    pub(crate) destination_address: &'a str,
    pub(crate) fee: u64,
    pub(crate) redeem_script: &'a [u8],
    pub(crate) branch: &'a str,
    pub(crate) proprietaries: serde_json::Value,
    pub(crate) signature_op_count: u8,
    pub(crate) transaction_payload: Option<Vec<u8>>,
    pub(crate) empty_error: &'a str,
    pub(crate) low_balance_error: &'a str,
}

pub(crate) async fn build_covenant_sweep(
    request: CovenantSweepRequest<'_>,
) -> Result<(PreparedSweep, String), String> {
    let prepared = prepare_sweep(
        request.websocket_url,
        request.covenant_address,
        request.destination_address,
        request.fee,
        request.empty_error,
        request.low_balance_error,
    )
    .await?;
    let mut global = PskbGlobalPlan::standard().with_branch(request.branch);
    global.transaction_payload = request.transaction_payload;
    let mut policy = SweepInputPolicy::covenant(request.redeem_script, 0, request.proprietaries);
    policy.sig_op_count = request.signature_op_count;
    let wire = encode(&prepared, global, &policy)?;
    Ok((prepared, wire))
}

#[cfg(test)]
mod unit_tests;
