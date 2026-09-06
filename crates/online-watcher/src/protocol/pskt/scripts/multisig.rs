// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use super::first_schnorr_signature;

use super::push_redeem_script;
use crate::protocol::pskt::review::{find_pubkey_position_in_redeem, parse_multisig_redeem};

pub(crate) fn build_p2sh_single_path_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    // Extract the first (and only) signature from partialSigs
    let (_, sig_bytes) = first_schnorr_signature(
        partial_map,
        "no partial signature".to_string(),
        "partial sig missing schnorr variant".to_string(),
        None,
        "sig hex",
    )?;

    let mut script = Vec::with_capacity(1 + sig_bytes.len() + 3 + redeem.len());
    // Push signature
    script.push(sig_bytes.len() as u8);
    script.extend_from_slice(&sig_bytes);
    // Push redeem script
    push_redeem_script(&mut script, redeem)?;
    Ok(script)
}

pub(crate) fn build_p2sh_multisig_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (m, _n) = parse_multisig_redeem(redeem)
        .ok_or_else(|| "redeem not a valid M-of-N multisig".to_string())?;
    let mut signatures = collect_multisig_signatures(redeem, partial_map)?;
    signatures.sort_by_key(|entry| entry.0);
    require_multisig_threshold(signatures.len(), m)?;
    emit_multisig_witness(redeem, &signatures, m)
}

fn collect_multisig_signatures(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<(u8, Vec<u8>)>, String> {
    let mut signatures = Vec::with_capacity(partial_map.len());
    for (pubkey, value) in partial_map {
        if let Some(entry) = parse_multisig_signature(redeem, pubkey, value)? {
            signatures.push(entry);
        }
    }
    Ok(signatures)
}

fn parse_multisig_signature(
    redeem: &[u8],
    pubkey: &str,
    value: &Value,
) -> Result<Option<(u8, Vec<u8>)>, String> {
    if pubkey.len() != 66 {
        return Ok(None);
    }
    let signature_hex = value
        .get("schnorr")
        .and_then(Value::as_str)
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if signature_hex.len() != 128 {
        return Err(format!("bad sig length: {}", signature_hex.len()));
    }
    let position = find_pubkey_position_in_redeem(redeem, pubkey)
        .ok_or_else(|| format!("pubkey not in redeem: {pubkey}"))?;
    let mut signature = hex::decode(signature_hex).map_err(|error| format!("sig hex: {error}"))?;
    signature.push(0x01);
    Ok(Some((position, signature)))
}

fn require_multisig_threshold(signature_count: usize, m: u8) -> Result<(), String> {
    if signature_count >= usize::from(m) {
        Ok(())
    } else {
        Err(format!("only {signature_count} sig(s), need {m}"))
    }
}

fn emit_multisig_witness(
    redeem: &[u8],
    signatures: &[(u8, Vec<u8>)],
    m: u8,
) -> Result<Vec<u8>, String> {
    let mut script = Vec::with_capacity(usize::from(m) * 66 + redeem.len() + 2);
    for (_, signature) in signatures.iter().take(usize::from(m)) {
        script.push(signature.len() as u8);
        script.extend_from_slice(signature);
    }
    push_redeem_script(&mut script, redeem)?;
    Ok(script)
}
