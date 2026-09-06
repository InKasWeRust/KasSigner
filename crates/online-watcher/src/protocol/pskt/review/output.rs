// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use super::classification::classify_output_script;
use super::parse_spk_hex;
use crate::protocol::pskt::exact_json::parse_exact_u64;
use crate::protocol::pskt::OutputSummary;

fn parse_derivation_hint(obj: &serde_json::Map<String, Value>) -> (Option<u8>, Option<u32>) {
    let Some(hint) = obj
        .get("proprietaries")
        .and_then(Value::as_object)
        .and_then(|props| props.get("kassignerDerivation"))
        .and_then(Value::as_object)
    else {
        return (None, None);
    };
    let branch = hint
        .get("branch")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok());
    let index = hint.get("index").and_then(|value| {
        value
            .as_str()
            .and_then(|text| text.parse::<u32>().ok())
            .or_else(|| value.as_u64().and_then(|number| u32::try_from(number).ok()))
    });
    match (branch, index) {
        (Some(branch), Some(index)) => (Some(branch), Some(index)),
        _ => (None, None),
    }
}

pub(crate) fn parse_output_summary(
    out: &Value,
    network_prefix: &str,
) -> Result<OutputSummary, String> {
    let obj = out
        .as_object()
        .ok_or_else(|| "output not object".to_string())?;
    let amount_sompi = parse_exact_u64(
        obj.get("amount")
            .ok_or_else(|| "missing amount".to_string())?,
        "amount",
    )?;
    let spk_full = obj
        .get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (_spk_version, spk_script) = parse_spk_hex(spk_full)?;
    let (kind, address) = classify_output_script(&spk_script, network_prefix);
    let (derivation_branch, derivation_index) = parse_derivation_hint(obj);

    Ok(OutputSummary {
        amount_sompi,
        amount_kas: amount_sompi as f64 / 1e8,
        script_kind: kind,
        script_hex: hex::encode(&spk_script),
        address,
        derivation_branch,
        derivation_index,
    })
}
