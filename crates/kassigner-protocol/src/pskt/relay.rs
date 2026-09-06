use blake2b_simd::Params;
use serde_json::{Map, Value};

use crate::{wire::kspt, Network};

use super::{
    compact::{Input, Output, Signature, Transaction},
    relay_fields::{collect_signatures, parse_ms45, parse_multisig_redeem, InputFields},
    wire::{document, parse_derivation, parse_exact_u64, parse_spk},
};

pub(crate) fn encode_pskt(pskt_hex: &str, network: Network) -> Result<Vec<u8>, String> {
    let (format, root) = super::wire::decode(pskt_hex)?;
    let document = document(&root, format)?
        .as_object()
        .ok_or_else(|| "PSKT not object".to_string())?;
    let global = document
        .get("global")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing global".to_string())?;
    let inputs = document
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing inputs".to_string())?;
    let outputs = document
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing outputs".to_string())?;
    let transaction = build_transaction(global, inputs, outputs, network)?;
    kspt::encode_vec(&transaction).map_err(|error| error.to_string())
}

fn build_transaction(
    global: &Map<String, Value>,
    inputs: &[Value],
    outputs: &[Value],
    network: Network,
) -> Result<Transaction, String> {
    validate_counts(inputs, outputs)?;
    let mut transaction = build_base_transaction(global, inputs, outputs, network)?;
    apply_extensions(&mut transaction, inputs, outputs)?;
    transaction.flags = completion_flags(&transaction.inputs);
    Ok(transaction)
}

fn completion_flags(inputs: &[Input]) -> u8 {
    if !inputs.is_empty() && inputs.iter().all(input_is_complete) {
        kspt::FLAG_SIGNED_OR_COMPLETE
    } else {
        0
    }
}

fn input_is_complete(input: &Input) -> bool {
    match input.redeem.is_empty() {
        true => !input.signatures.is_empty(),
        false => parse_multisig_redeem(&input.redeem)
            .is_some_and(|(threshold, _)| input.signatures.len() >= usize::from(threshold)),
    }
}

fn validate_counts(inputs: &[Value], outputs: &[Value]) -> Result<(), String> {
    if inputs.len() > u32::MAX as usize {
        return Err("too many inputs".to_string());
    }
    if outputs.len() > u8::MAX as usize {
        return Err("too many outputs".to_string());
    }
    Ok(())
}

fn build_base_transaction(
    global: &Map<String, Value>,
    inputs: &[Value],
    outputs: &[Value],
    network: Network,
) -> Result<Transaction, String> {
    Ok(Transaction {
        flags: 0,
        version: tx_version(global)?,
        locktime: optional_exact(global, "fallbackLockTime")?,
        subnetwork: decode_subnetwork(global)?,
        gas: optional_exact(global, "gas")?,
        payload: decode_payload(global)?,
        network: network.kspt_code(),
        inputs: build_inputs(inputs)?,
        outputs: build_outputs(outputs)?,
        stealth: find_stealth(inputs),
    })
}

fn apply_extensions(
    transaction: &mut Transaction,
    inputs: &[Value],
    outputs: &[Value],
) -> Result<(), String> {
    apply_ms45(transaction, inputs, outputs);
    apply_derivations(transaction, inputs, outputs);
    apply_covenants(transaction, inputs, outputs)
}

fn tx_version(global: &Map<String, Value>) -> Result<u16, String> {
    let value = global
        .get("txVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing txVersion".to_string())?;
    u16::try_from(value).map_err(|_| "txVersion exceeds u16".to_string())
}

fn optional_exact(global: &Map<String, Value>, key: &str) -> Result<u64, String> {
    match global.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(value) => parse_exact_u64(value, key),
    }
}

fn decode_subnetwork(global: &Map<String, Value>) -> Result<[u8; 20], String> {
    match global.get("subnetworkId") {
        None | Some(Value::Null) => Ok([0u8; 20]),
        Some(Value::String(value)) => {
            let bytes = hex::decode(value).map_err(|error| format!("subnetworkId hex: {error}"))?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| "subnetworkId must be 20 bytes".to_string())
        }
        _ => Err("subnetworkId must be a hex string".to_string()),
    }
}

fn decode_payload(global: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let payload = global
        .get("txPayload")
        .and_then(Value::as_str)
        .map(hex::decode)
        .transpose()
        .map_err(|error| format!("txPayload hex: {error}"))?
        .unwrap_or_default();
    if payload.len() > u16::MAX as usize {
        return Err("transaction payload is too large".to_string());
    }
    Ok(payload)
}

fn build_inputs(values: &[Value]) -> Result<Vec<Input>, String> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            build_input(value).map_err(|error| format!("input[{index}]: {error}"))
        })
        .collect()
}

fn build_input(value: &Value) -> Result<Input, String> {
    let fields = InputFields::parse(value)?;
    let signatures = collect_signatures(&fields)?
        .into_iter()
        .map(|entry| Signature {
            position: entry.position,
            sighash: 0x01,
            bytes: entry.bytes,
        })
        .collect();
    Ok(Input {
        tx_id: fields.previous_tx_id,
        index: fields.previous_index,
        amount: fields.amount,
        sequence: fields.sequence,
        sig_op_count: fields.sig_op_count,
        script_version: fields.script_version,
        script: fields.script_public_key,
        signatures,
        redeem: fields.redeem_script.unwrap_or_default(),
        derivation: None,
        ms45: None,
    })
}

fn build_outputs(values: &[Value]) -> Result<Vec<Output>, String> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            build_output(value).map_err(|error| format!("output[{index}]: {error}"))
        })
        .collect()
}

fn build_output(value: &Value) -> Result<Output, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "output not object".to_string())?;
    let amount = parse_exact_u64(
        object
            .get("amount")
            .ok_or_else(|| "missing amount".to_string())?,
        "amount",
    )?;
    let spk = object
        .get("scriptPublicKey")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (script_version, script) = parse_spk(spk)?;
    if script.len() > kspt::MAX_SCRIPT_SIZE {
        return Err(format!(
            "script too long for compact KSPT ({})",
            script.len()
        ));
    }
    Ok(Output {
        amount,
        script_version,
        script,
        derivation: None,
        ms45: None,
        covenant: None,
    })
}

fn apply_derivations(transaction: &mut Transaction, inputs: &[Value], outputs: &[Value]) {
    for (position, value) in inputs.iter().enumerate() {
        if let Some(hint) = value.get("proprietaries").and_then(parse_derivation) {
            transaction.inputs[position].derivation = Some(hint);
        }
    }
    for (position, value) in outputs.iter().enumerate() {
        if let Some(hint) = value.get("proprietaries").and_then(parse_derivation) {
            transaction.outputs[position].derivation = Some(hint);
        }
    }
}

fn apply_ms45(transaction: &mut Transaction, inputs: &[Value], outputs: &[Value]) {
    for (position, value) in inputs.iter().enumerate() {
        transaction.inputs[position].ms45 = value.get("bip32Derivations").and_then(parse_ms45);
    }
    for (position, value) in outputs.iter().enumerate() {
        transaction.outputs[position].ms45 = value.get("bip32Derivations").and_then(parse_ms45);
    }
}

fn find_stealth(inputs: &[Value]) -> Option<[u8; 32]> {
    inputs.iter().find_map(|input| {
        let value = input.get("proprietaries")?.get("stealthTweak")?.as_str()?;
        let bytes = hex::decode(value).ok()?;
        bytes.as_slice().try_into().ok()
    })
}

fn apply_covenants(
    transaction: &mut Transaction,
    inputs: &[Value],
    outputs: &[Value],
) -> Result<(), String> {
    apply_explicit_covenants(transaction, outputs)?;
    if transaction
        .outputs
        .first()
        .is_some_and(|output| output.covenant.is_some())
    {
        return Ok(());
    }
    let persistent = inputs.iter().any(|input| {
        input
            .get("proprietaries")
            .and_then(|value| value.get("persistentVault"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    });
    if !persistent {
        return Ok(());
    }
    let Some((tx_id, prev_index)) = first_outpoint(inputs) else {
        return Ok(());
    };
    let Some(output) = transaction.outputs.first() else {
        return Ok(());
    };
    let id = covenant_id(
        &tx_id,
        prev_index,
        0,
        output.amount,
        output.script_version,
        &output.script,
    );
    transaction.outputs[0].covenant = Some((0, id));
    Ok(())
}

fn apply_explicit_covenants(
    transaction: &mut Transaction,
    outputs: &[Value],
) -> Result<(), String> {
    for (position, value) in outputs.iter().enumerate() {
        let Some(binding) = value
            .get("covenantBinding")
            .filter(|value| !value.is_null())
            .and_then(Value::as_object)
        else {
            continue;
        };
        let authorizing = binding
            .get("authorizingInput")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                format!("output[{position}] covenant binding is missing authorizingInput")
            })?;
        let authorizing = u16::try_from(authorizing)
            .map_err(|_| format!("output[{position}] covenant authorizing input exceeds u16"))?;
        if usize::from(authorizing) >= transaction.inputs.len() {
            return Err(format!(
                "output[{position}] covenant authorizing input is out of range"
            ));
        }
        let text = binding
            .get("covenantId")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("output[{position}] covenant binding is missing covenantId"))?;
        let bytes =
            hex::decode(text).map_err(|_| format!("output[{position}] covenant id is not hex"))?;
        let id = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("output[{position}] covenant id must be 32 bytes"))?;
        transaction.outputs[position].covenant = Some((authorizing, id));
    }
    Ok(())
}

pub(crate) fn first_outpoint(inputs: &[Value]) -> Option<([u8; 32], u32)> {
    let outpoint = inputs.first()?.get("previousOutpoint")?.as_object()?;
    let bytes = hex::decode(outpoint.get("transactionId")?.as_str()?).ok()?;
    let id = bytes.as_slice().try_into().ok()?;
    let index = outpoint
        .get("index")?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())?;
    Some((id, index))
}

fn covenant_id(
    prev_tx_id: &[u8; 32],
    prev_index: u32,
    output_index: u32,
    value: u64,
    version: u16,
    script: &[u8],
) -> [u8; 32] {
    let hash = Params::new()
        .hash_length(32)
        .key(b"CovenantID")
        .to_state()
        .update(prev_tx_id)
        .update(&prev_index.to_le_bytes())
        .update(&1u64.to_le_bytes())
        .update(&output_index.to_le_bytes())
        .update(&value.to_le_bytes())
        .update(&version.to_le_bytes())
        .update(&(script.len() as u64).to_le_bytes())
        .update(script)
        .finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(hash.as_bytes());
    output
}
