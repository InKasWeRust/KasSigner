// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::{Map, Value};

use super::{parse_input_summary, parse_output_summary};
use crate::protocol::pskt::wire::{decode_root_for_review, pskt_from_root_for_review};
use crate::protocol::pskt::{InputSummary, OutputSummary, PsktFormat, PsktSummary};

struct ParsedInputs {
    summaries: Vec<InputSummary>,
    total_sompi: u64,
    all_ready: bool,
}

struct ParsedOutputs {
    summaries: Vec<OutputSummary>,
    total_sompi: u64,
}

pub fn parse_summary(wire_hex: &str, network_prefix: &str) -> Result<PsktSummary, String> {
    let (format, root) = decode_root_for_review(wire_hex)?;
    let pskt = pskt_from_root_for_review(&root, format)?;
    parse_pskt_object(pskt, format, network_prefix)
}

fn parse_pskt_object(
    pskt: &Value,
    format: PsktFormat,
    network_prefix: &str,
) -> Result<PsktSummary, String> {
    let obj = pskt
        .as_object()
        .ok_or("PSKT is not an object".to_string())?;
    let tx_version = parse_tx_version(obj)?;
    let inputs = parse_inputs(obj)?;
    let outputs = parse_outputs(obj, network_prefix)?;
    let fee_sompi = inputs
        .total_sompi
        .checked_sub(outputs.total_sompi)
        .ok_or("PSKT outputs exceed inputs".to_string())?;

    Ok(PsktSummary {
        format: format_label(format),
        tx_version,
        input_count: inputs.summaries.len(),
        output_count: outputs.summaries.len(),
        inputs: inputs.summaries,
        outputs: outputs.summaries,
        total_in_sompi: inputs.total_sompi,
        total_out_sompi: outputs.total_sompi,
        fee_sompi,
        finalize_ready: inputs.all_ready,
    })
}

fn parse_tx_version(obj: &Map<String, Value>) -> Result<u16, String> {
    obj.get("global")
        .and_then(Value::as_object)
        .and_then(|global| global.get("txVersion"))
        .and_then(Value::as_u64)
        .ok_or("missing txVersion".to_string())
        .and_then(|version| {
            u16::try_from(version).map_err(|_| "txVersion exceeds supported range".to_string())
        })
}

fn parse_inputs(obj: &Map<String, Value>) -> Result<ParsedInputs, String> {
    let entries = obj
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or("missing inputs".to_string())?;
    let mut summaries = Vec::with_capacity(entries.len());
    let mut total_sompi = 0u64;
    let mut all_ready = true;
    for (index, input) in entries.iter().enumerate() {
        let summary =
            parse_input_summary(input).map_err(|error| format!("input[{index}]: {error}"))?;
        total_sompi = checked_total(total_sompi, summary.amount_sompi, "input")?;
        all_ready &= input_is_ready(input, &summary);
        summaries.push(summary);
    }
    Ok(ParsedInputs {
        summaries,
        total_sompi,
        all_ready,
    })
}

fn parse_outputs(obj: &Map<String, Value>, network_prefix: &str) -> Result<ParsedOutputs, String> {
    let entries = obj
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or("missing outputs".to_string())?;
    let mut summaries = Vec::with_capacity(entries.len());
    let mut total_sompi = 0u64;
    for (index, output) in entries.iter().enumerate() {
        let summary = parse_output_summary(output, network_prefix)
            .map_err(|error| format!("output[{index}]: {error}"))?;
        total_sompi = checked_total(total_sompi, summary.amount_sompi, "output")?;
        summaries.push(summary);
    }
    Ok(ParsedOutputs {
        summaries,
        total_sompi,
    })
}

fn checked_total(total: u64, amount: u64, kind: &str) -> Result<u64, String> {
    total.checked_add(amount).ok_or(format!(
        "PSKT {kind} total exceeds supported monetary range"
    ))
}

fn input_is_ready(input: &Value, summary: &InputSummary) -> bool {
    let minimum = input
        .get("minimumSignatures")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok());
    match (summary.multisig_m, minimum) {
        (Some(required), _) => summary.sigs_present >= required,
        (None, Some(0)) => true,
        (None, _) => summary.sigs_present >= 1,
    }
}

fn format_label(format: PsktFormat) -> String {
    match format {
        PsktFormat::Pskb => "pskb",
        PsktFormat::PsktSingle => "pskt",
        PsktFormat::Unknown => "unknown",
    }
    .into()
}
