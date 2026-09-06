//! Oracle-v1 claim transaction planning.

use crate::transaction_builder::pskb::{
    encode_prepared_sweep, prepare_sweep_from_utxos, PreparedSweep, PskbGlobalPlan,
    SweepInputPolicy,
};

pub(crate) struct OracleClaimRequest<'a> {
    pub covenant_address: &'a str,
    pub destination_address: &'a str,
    pub redeem_script_hex: &'a str,
    pub oracle_pubkey_hex: &'a str,
    pub oracle_signature_hex: &'a str,
    pub message_commitment_hex: &'a str,
    pub fee: u64,
    pub websocket_url: &'a str,
}

pub(crate) async fn build_claim(
    request: OracleClaimRequest<'_>,
) -> Result<(PreparedSweep, String), String> {
    let redeem = crate::contracts::covenant::oracle_v1::checked_redeem_and_attestation(
        request.redeem_script_hex,
        request.oracle_pubkey_hex,
        request.oracle_signature_hex,
        request.message_commitment_hex,
    )?;
    let utxos = crate::network::queries::utxos::fetch_for_address(
        request.websocket_url,
        request.covenant_address,
    )
    .await?;
    let prepared = prepare_sweep_from_utxos(
        utxos,
        request.covenant_address,
        request.destination_address,
        request.fee,
        "No UTXOs at oracle covenant address",
        "Oracle covenant balance too low to cover fee",
    )?;
    let global = PskbGlobalPlan::standard().with_branch("oracle-v1-claim");
    let mut policy = SweepInputPolicy::covenant(
        &redeem,
        0,
        serde_json::json!({
            "oracleV1Claim": true,
            "oracleV1Signature": request.oracle_signature_hex,
        }),
    );
    policy.sig_op_count = crate::contracts::covenant::script::ORACLE_V1_SIG_OP_COUNT;
    let wire = encode_prepared_sweep(&prepared, global, &policy)?;
    Ok((prepared, wire))
}
