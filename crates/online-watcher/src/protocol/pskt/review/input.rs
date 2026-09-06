// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::{Map, Value};

use super::classification::classify_input_script;
use super::{find_pubkey_position_in_redeem, parse_spk_hex};
use crate::protocol::pskt::exact_json::parse_exact_u64;
use crate::protocol::pskt::{InputSummary, PartialSigInfo};

pub(crate) fn parse_input_summary(inp: &Value) -> Result<InputSummary, String> {
    let obj = inp
        .as_object()
        .ok_or_else(|| "input not object".to_string())?;
    let (amount_sompi, spk_script) = summary_utxo(obj)?;
    let (prev_tx_id, prev_index) = summary_outpoint(obj)?;
    let (redeem_script_hex, redeem_bytes) = summary_redeem_script(obj)?;
    let (script_kind, multisig_m, multisig_n) =
        classify_input_script(&spk_script, redeem_bytes.as_deref());
    let (sigs_present, partial_sigs) =
        parse_partial_sigs_map(obj.get("partialSigs"), redeem_bytes.as_deref())?;

    Ok(InputSummary {
        prev_tx_id,
        prev_index,
        amount_sompi,
        amount_kas: amount_sompi as f64 / 1e8,
        script_kind,
        script_hex: hex::encode(&spk_script),
        redeem_script_hex,
        multisig_m,
        multisig_n,
        sigs_present,
        partial_sigs,
    })
}

fn summary_utxo(obj: &Map<String, Value>) -> Result<(u64, Vec<u8>), String> {
    let utxo = obj
        .get("utxoEntry")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let amount_sompi = parse_exact_u64(
        utxo.get("amount")
            .ok_or_else(|| "missing amount".to_string())?,
        "amount",
    )?;
    let spk_full = utxo
        .get("scriptPublicKey")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    parse_spk_hex(spk_full).map(|(_, script)| (amount_sompi, script))
}

fn summary_outpoint(obj: &Map<String, Value>) -> Result<(String, u32), String> {
    let outpoint = obj
        .get("previousOutpoint")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let transaction_id = outpoint
        .get("transactionId")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing transactionId".to_string())?
        .to_string();
    let index = outpoint
        .get("index")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing index".to_string())?;
    let index = u32::try_from(index).map_err(|_| "index exceeds u32".to_string())?;
    Ok((transaction_id, index))
}

fn summary_redeem_script(
    obj: &Map<String, Value>,
) -> Result<(Option<String>, Option<Vec<u8>>), String> {
    let redeem_script_hex = obj
        .get("redeemScript")
        .and_then(Value::as_str)
        .map(str::to_string);
    let redeem_bytes = redeem_script_hex
        .as_deref()
        .map(hex::decode)
        .transpose()
        .map_err(|error| format!("bad redeemScript: {error}"))?;
    Ok((redeem_script_hex, redeem_bytes))
}

fn parse_partial_sigs_map(
    v: Option<&Value>,
    redeem: Option<&[u8]>,
) -> Result<(u8, Vec<PartialSigInfo>), String> {
    let Some(value) = v else {
        return Ok((0, vec![]));
    };
    let map = value
        .as_object()
        .ok_or_else(|| "partialSigs not object".to_string())?;
    let sigs = map
        .iter()
        .map(|(pubkey, signature)| parse_partial_sig_entry(pubkey, signature, redeem))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((sigs.len().min(u8::MAX as usize) as u8, sigs))
}

fn parse_partial_sig_entry(
    pubkey_hex: &str,
    signature: &Value,
    redeem: Option<&[u8]>,
) -> Result<PartialSigInfo, String> {
    validate_partial_pubkey(pubkey_hex)?;
    validate_partial_signature(signature)?;
    let position = redeem.and_then(|script| find_pubkey_position_in_redeem(script, pubkey_hex));
    Ok(PartialSigInfo {
        pubkey_hex: pubkey_hex.to_string(),
        position,
    })
}

fn validate_partial_pubkey(pubkey_hex: &str) -> Result<(), String> {
    if pubkey_hex.len() == 66 {
        Ok(())
    } else {
        Err(format!("bad pubkey length: {}", pubkey_hex.len()))
    }
}

fn validate_partial_signature(signature: &Value) -> Result<(), String> {
    let object = signature
        .as_object()
        .ok_or_else(|| "sig value not object".to_string())?;
    let schnorr = object
        .get("schnorr")
        .and_then(Value::as_str)
        .ok_or_else(|| "schnorr sig missing (ECDSA not supported)".to_string())?;
    if schnorr.len() == 128 {
        Ok(())
    } else {
        Err(format!("bad schnorr sig length: {}", schnorr.len()))
    }
}
