//! Private-swap claim transaction planning.

use crate::transaction_builder::pskb::{
    encode_prepared_sweep, prepare_selected_sweep, PreparedSweep, PskbGlobalPlan, SweepInputPolicy,
};

pub(crate) fn prepare_claim(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    selected_utxo_json: &str,
    fee: u64,
) -> Result<(PreparedSweep, Vec<u8>), String> {
    let redeem = hex::decode(redeem_script_hex).map_err(|error| format!("Bad redeem: {error}"))?;
    let prepared = prepare_selected_sweep(
        selected_utxo_json,
        covenant_address,
        destination_address,
        fee,
        "Private Swap funding UTXO missing",
        "Private Swap balance too low",
    )?;
    if prepared.utxos.len() != 1 {
        return Err("Private Swap claim requires exactly one funding UTXO".to_string());
    }
    Ok((prepared, redeem))
}

pub(crate) fn build_claim(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    selected_utxo_json: &str,
    fee: u64,
) -> Result<String, String> {
    let (prepared, redeem) = prepare_claim(
        covenant_address,
        destination_address,
        redeem_script_hex,
        selected_utxo_json,
        fee,
    )?;
    let global = PskbGlobalPlan::standard().with_branch("beneficiary");
    let mut policy =
        SweepInputPolicy::covenant(&redeem, 0, serde_json::json!({"privateSwapClaim": true}));
    policy.sig_op_count = 1;
    encode_prepared_sweep(&prepared, global, &policy)
}

pub(crate) fn insert_completed_signature_hex(
    pskb_hex: &str,
    claim_pubkey_x: &[u8; 32],
    signature: &[u8; 64],
) -> Result<String, String> {
    let (format, mut root) = crate::protocol::pskt::wire::decode_root(pskb_hex)?;
    let partial_signatures = partial_signatures(&mut root, format)?;
    let mut full_public_key = String::from("02");
    full_public_key.push_str(&hex::encode(claim_pubkey_x));
    partial_signatures.insert(
        full_public_key,
        serde_json::json!({"schnorr": hex::encode(signature), "sighashType": 1}),
    );
    crate::protocol::pskt::wire::encode_root(format, &root)
}

fn partial_signatures(
    root: &mut serde_json::Value,
    format: crate::protocol::pskt::PsktFormat,
) -> Result<&mut serde_json::Map<String, serde_json::Value>, String> {
    use serde_json::Value;
    let pskt = crate::protocol::pskt::wire::pskt_from_root_mut(root, format)?;
    let inputs = pskt
        .get_mut("inputs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "Private Swap PSKB inputs missing".to_string())?;
    if inputs.len() != 1 {
        return Err("Private Swap claim must have exactly one input".to_string());
    }
    let input = inputs[0]
        .as_object_mut()
        .ok_or_else(|| "Private Swap input invalid".to_string())?;
    let signatures = input
        .get_mut("partialSigs")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "Private Swap partialSigs missing".to_string())?;
    if !signatures.is_empty() {
        return Err("Private Swap claim already has a signature".to_string());
    }
    Ok(signatures)
}

#[cfg(test)]
mod unit_tests;
