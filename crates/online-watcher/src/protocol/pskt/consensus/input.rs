// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::{Map, Value};

use crate::protocol::pskt::exact_json::parse_exact_u64;
use crate::protocol::pskt::review::parse_spk_hex;
use crate::protocol::pskt::scripts::{build_signature_script, ScriptBuildOptions};

pub(crate) fn build_consensus_input(
    inp: &Value,
    force_beneficiary: bool,
    force_time_path: bool,
    escrow_branch: &Option<String>,
    ship_branch: &Option<String>,
) -> Result<crate::protocol::transaction::consensus::ConsensusInput, String> {
    let obj = inp.as_object().ok_or_else(|| "not object".to_string())?;
    let spk_script = input_script_public_key(obj)?;
    let (prev_tx_id, prev_index) = input_outpoint(obj)?;
    let sequence = input_sequence(obj)?;
    let sig_op_count = input_sig_op_count(obj)?;
    let redeem = input_redeem_script(obj)?;
    let partial_map = input_partial_signatures(obj);
    let sig_script = build_signature_script(
        obj,
        &spk_script,
        &redeem,
        &partial_map,
        ScriptBuildOptions {
            force_beneficiary,
            force_time_path,
            escrow_branch,
            ship_branch,
        },
    )?;

    Ok(crate::protocol::transaction::consensus::ConsensusInput {
        prev_tx_id,
        prev_index,
        sig_script,
        sequence,
        sig_op_count,
    })
}

fn input_script_public_key(obj: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let utxo = obj
        .get("utxoEntry")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let script_public_key = utxo
        .get("scriptPublicKey")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    parse_spk_hex(script_public_key).map(|(_, script)| script)
}

fn input_outpoint(obj: &Map<String, Value>) -> Result<([u8; 32], u32), String> {
    let outpoint = obj
        .get("previousOutpoint")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let transaction_id = outpoint
        .get("transactionId")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing transactionId".to_string())?;
    let prev_tx_id = decode_transaction_id(transaction_id)?;
    let prev_index = outpoint
        .get("index")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing index".to_string())?;
    let prev_index = u32::try_from(prev_index).map_err(|_| "index exceeds u32".to_string())?;
    Ok((prev_tx_id, prev_index))
}

fn decode_transaction_id(transaction_id: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(transaction_id).map_err(|error| format!("bad tx_id hex: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "tx_id not 32 bytes".to_string())
}

fn input_sequence(obj: &Map<String, Value>) -> Result<u64, String> {
    match obj.get("sequence") {
        None | Some(Value::Null) => Ok(0),
        Some(value) => parse_exact_u64(value, "sequence"),
    }
}

fn input_sig_op_count(obj: &Map<String, Value>) -> Result<u8, String> {
    match obj.get("sigOpCount").and_then(Value::as_u64) {
        Some(value) => u8::try_from(value).map_err(|_| "sigOpCount exceeds u8".to_string()),
        None => Ok(1),
    }
}

fn input_redeem_script(obj: &Map<String, Value>) -> Result<Option<Vec<u8>>, String> {
    match obj.get("redeemScript") {
        Some(Value::String(value)) => hex::decode(value)
            .map(Some)
            .map_err(|error| format!("redeem hex: {error}")),
        _ => Ok(None),
    }
}

fn input_partial_signatures(obj: &Map<String, Value>) -> Map<String, Value> {
    obj.get("partialSigs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}
