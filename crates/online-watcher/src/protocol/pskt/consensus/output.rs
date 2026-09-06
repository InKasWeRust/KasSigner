// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::{Map, Value};

use crate::protocol::pskt::exact_json::parse_exact_u64;
use crate::protocol::pskt::review::parse_spk_hex;

pub(crate) fn build_consensus_output(
    out: &Value,
) -> Result<crate::protocol::transaction::consensus::ConsensusOutput, String> {
    let obj = out.as_object().ok_or_else(|| "not object".to_string())?;
    let value = parse_output_amount(obj)?;
    let (spk_version, spk_script) = parse_output_script(obj)?;
    let covenant = parse_output_covenant(obj)?;
    Ok(crate::protocol::transaction::consensus::ConsensusOutput {
        value,
        spk_version,
        spk_script,
        covenant,
    })
}

fn parse_output_amount(obj: &Map<String, Value>) -> Result<u64, String> {
    parse_exact_u64(
        obj.get("amount")
            .ok_or_else(|| "missing amount".to_string())?,
        "amount",
    )
}

fn parse_output_script(obj: &Map<String, Value>) -> Result<(u16, Vec<u8>), String> {
    let script = obj
        .get("scriptPublicKey")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    parse_spk_hex(script)
}

fn parse_output_covenant(obj: &Map<String, Value>) -> Result<Option<(u16, [u8; 32])>, String> {
    let Some(binding) = obj.get("covenantBinding").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let binding = binding
        .as_object()
        .ok_or_else(|| "covenantBinding not object".to_string())?;
    let authorizing_input = parse_authorizing_input(binding)?;
    let covenant_id = parse_covenant_id(binding)?;
    Ok(Some((authorizing_input, covenant_id)))
}

fn parse_authorizing_input(binding: &Map<String, Value>) -> Result<u16, String> {
    let value = binding
        .get("authorizingInput")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing authorizingInput".to_string())?;
    u16::try_from(value).map_err(|_| "authorizingInput exceeds u16".to_string())
}

fn parse_covenant_id(binding: &Map<String, Value>) -> Result<[u8; 32], String> {
    let covenant_id = binding
        .get("covenantId")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing covenantId".to_string())?;
    let bytes = hex::decode(covenant_id).map_err(|error| format!("bad covenantId hex: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "covenantId must be 32 bytes".to_string())
}
