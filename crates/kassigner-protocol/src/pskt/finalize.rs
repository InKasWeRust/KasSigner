use serde_json::{json, Map, Value};

use super::{relay_fields::parse_multisig_redeem, wire};

pub(crate) fn finalize_json(pskt_hex: &str) -> Result<String, String> {
    let (format, root) = wire::decode(pskt_hex)?;
    let document = wire::document(&root, format)?
        .as_object()
        .ok_or_else(|| "PSKT not object".to_string())?;
    finalize_document(document)
}

fn finalize_document(document: &Map<String, Value>) -> Result<String, String> {
    let global = object_field(document, "global")?;
    let inputs = array_field(document, "inputs")?;
    let outputs = array_field(document, "outputs")?;
    let input_json = finalize_inputs(inputs)?;
    let output_json = finalize_outputs(outputs)?;
    let fields = finalize_global(global)?;
    serde_json::to_string(&json!({
        "version": fields.tx_version,
        "inputEncoding": "budgeted",
        "inputs": input_json,
        "outputs": output_json,
        "lockTime": fields.locktime.to_string(),
        "subnetworkId": hex::encode(fields.subnetwork),
        "gas": fields.gas.to_string(),
        "payload": hex::encode(fields.payload),
    }))
    .map_err(|error| format!("Final transaction JSON failed: {error}"))
}

struct GlobalFields {
    tx_version: u16,
    locktime: u64,
    subnetwork: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
}

fn finalize_global(global: &Map<String, Value>) -> Result<GlobalFields, String> {
    let tx_version = global
        .get("txVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing txVersion".to_string())?;
    Ok(GlobalFields {
        tx_version: u16::try_from(tx_version).map_err(|_| "txVersion exceeds u16".to_string())?,
        locktime: optional_exact(global, "fallbackLockTime")?,
        subnetwork: optional_fixed_hex::<20>(global, "subnetworkId")?.unwrap_or([0u8; 20]),
        gas: optional_exact(global, "gas")?,
        payload: optional_hex(global, "txPayload")?,
    })
}

fn object_field<'a>(
    document: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, String> {
    document
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing {key}"))
}

fn array_field<'a>(document: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>, String> {
    document
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing {key}"))
}

fn finalize_inputs(inputs: &[Value]) -> Result<Vec<Value>, String> {
    inputs
        .iter()
        .enumerate()
        .map(|(index, value)| {
            finalize_input(value).map_err(|error| format!("input[{index}]: {error}"))
        })
        .collect()
}

fn finalize_outputs(outputs: &[Value]) -> Result<Vec<Value>, String> {
    outputs
        .iter()
        .enumerate()
        .map(|(index, value)| {
            finalize_output(value).map_err(|error| format!("output[{index}]: {error}"))
        })
        .collect()
}

fn finalize_input(value: &Value) -> Result<Value, String> {
    let input = value.as_object().ok_or_else(|| "not object".to_string())?;
    reject_specialized_covenant(input)?;
    let (transaction_id, previous_index) = finalize_outpoint(input)?;
    let sequence = finalize_sequence(input)?;
    let sig_op_count = finalize_sig_op_count(input)?;
    let spk_script = finalize_input_script(input)?;
    let partials = input_partials(input)?;
    let signature_script = build_signature_script(input, &spk_script, partials)?;
    Ok(json!({
        "previousOutpoint": { "transactionId": transaction_id, "index": previous_index },
        "signatureScript": hex::encode(signature_script),
        "sequence": sequence.to_string(),
        "sigOpCount": sig_op_count,
    }))
}

fn finalize_outpoint(input: &Map<String, Value>) -> Result<(&str, u32), String> {
    let outpoint = input
        .get("previousOutpoint")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let transaction_id = outpoint
        .get("transactionId")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing transactionId".to_string())?;
    if hex::decode(transaction_id)
        .map_err(|error| format!("bad tx_id hex: {error}"))?
        .len()
        != 32
    {
        return Err("tx_id not 32 bytes".to_string());
    }
    let previous_index = outpoint
        .get("index")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing index".to_string())?;
    Ok((
        transaction_id,
        u32::try_from(previous_index).map_err(|_| "index exceeds u32".to_string())?,
    ))
}

fn finalize_sequence(input: &Map<String, Value>) -> Result<u64, String> {
    match input.get("sequence") {
        None | Some(Value::Null) => Ok(0),
        Some(value) => wire::parse_exact_u64(value, "sequence"),
    }
}

fn finalize_sig_op_count(input: &Map<String, Value>) -> Result<u8, String> {
    input
        .get("sigOpCount")
        .and_then(Value::as_u64)
        .map_or(Ok(1), |value| {
            u8::try_from(value).map_err(|_| "sigOpCount exceeds u8".to_string())
        })
}

fn finalize_input_script(input: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let script_public_key = input
        .get("utxoEntry")
        .and_then(Value::as_object)
        .and_then(|utxo| utxo.get("scriptPublicKey"))
        .and_then(Value::as_str)
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    wire::parse_spk(script_public_key).map(|(_, script)| script)
}

fn input_partials(input: &Map<String, Value>) -> Result<&Map<String, Value>, String> {
    input
        .get("partialSigs")
        .and_then(Value::as_object)
        .ok_or_else(|| "signed input has no partialSigs".to_string())
}

fn reject_specialized_covenant(input: &Map<String, Value>) -> Result<(), String> {
    let has_covenant_metadata = input
        .get("proprietaries")
        .and_then(Value::as_object)
        .is_some_and(|values| {
            values.keys().any(|key| {
                matches!(
                    key.as_str(),
                    "risc0OracleMb"
                        | "oracleMbHeartbeat"
                        | "oracleMbPassthrough"
                        | "oracleMbConsumer"
                        | "persistentVault"
                        | "escrowBranch"
                        | "shipBranch"
                )
            })
        });
    if has_covenant_metadata {
        Err("generic KasSigner SDK finalization does not own covenant execution policy; finalize the merged PSKT with the host wallet's covenant finalizer".to_string())
    } else {
        Ok(())
    }
}

fn build_signature_script(
    input: &Map<String, Value>,
    spk_script: &[u8],
    partials: &Map<String, Value>,
) -> Result<Vec<u8>, String> {
    if !is_p2sh(spk_script) {
        return p2pk_script(partials);
    }
    let redeem_hex = input
        .get("redeemScript")
        .and_then(Value::as_str)
        .ok_or_else(|| "P2SH input without redeem script cannot be finalized".to_string())?;
    let redeem = hex::decode(redeem_hex).map_err(|error| format!("redeem hex: {error}"))?;
    if parse_multisig_redeem(&redeem).is_none() {
        return Err("generic KasSigner SDK finalization supports standard P2PK and standard M-of-N P2SH; host wallet must finalize specialized redeem scripts".to_string());
    }
    multisig_script(&redeem, partials)
}

fn p2pk_script(partials: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let signature = first_signature(partials)?;
    let mut script = Vec::with_capacity(66);
    script.push(65);
    script.extend_from_slice(&signature);
    script.push(0x01);
    Ok(script)
}

fn multisig_script(redeem: &[u8], partials: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let (threshold, _) = parse_multisig_redeem(redeem)
        .ok_or_else(|| "redeem not a valid M-of-N multisig".to_string())?;
    let mut signatures = partials
        .iter()
        .filter_map(|(public_key, value)| {
            let position = super::relay_fields::find_pubkey_position(redeem, public_key)?;
            Some(parse_signature(value).map(|signature| (position, signature)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    signatures.sort_by_key(|entry| entry.0);
    if signatures.len() < usize::from(threshold) {
        return Err(format!(
            "only {} sig(s), need {threshold}",
            signatures.len()
        ));
    }
    let mut script = Vec::new();
    for (_, signature) in signatures.iter().take(usize::from(threshold)) {
        script.push(65);
        script.extend_from_slice(signature);
        script.push(0x01);
    }
    push_data(&mut script, redeem)?;
    Ok(script)
}

fn first_signature(partials: &Map<String, Value>) -> Result<[u8; 64], String> {
    let value = partials
        .values()
        .next()
        .ok_or_else(|| "signed input has no signature".to_string())?;
    parse_signature(value)
}

fn parse_signature(value: &Value) -> Result<[u8; 64], String> {
    let text = value
        .get("schnorr")
        .and_then(Value::as_str)
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    let bytes = hex::decode(text).map_err(|error| format!("signature hex: {error}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Schnorr signature must be 64 bytes".to_string())
}

fn push_data(script: &mut Vec<u8>, data: &[u8]) -> Result<(), String> {
    match data.len() {
        0..=75 => script.push(data.len() as u8),
        76..=255 => {
            script.extend_from_slice(&[0x4c, data.len() as u8]);
        }
        256..=65535 => {
            script.push(0x4d);
            script.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        _ => return Err("redeem script too large".to_string()),
    }
    script.extend_from_slice(data);
    Ok(())
}

fn finalize_output(value: &Value) -> Result<Value, String> {
    let output = value.as_object().ok_or_else(|| "not object".to_string())?;
    let amount = wire::parse_exact_u64(
        output
            .get("amount")
            .ok_or_else(|| "missing amount".to_string())?,
        "amount",
    )?;
    let spk = output
        .get("scriptPublicKey")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (version, script) = wire::parse_spk(spk)?;
    let covenant = parse_covenant(output)?;
    Ok(json!({
        "amount": amount.to_string(),
        "scriptPublicKey": { "version": version, "script": hex::encode(script) },
        "covenant": covenant,
    }))
}

fn parse_covenant(output: &Map<String, Value>) -> Result<Value, String> {
    let Some(binding) = output
        .get("covenantBinding")
        .filter(|value| !value.is_null())
    else {
        return Ok(Value::Null);
    };
    let binding = binding
        .as_object()
        .ok_or_else(|| "covenantBinding not object".to_string())?;
    let authorizing = binding
        .get("authorizingInput")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing authorizingInput".to_string())?;
    let authorizing =
        u16::try_from(authorizing).map_err(|_| "authorizingInput exceeds u16".to_string())?;
    let id = binding
        .get("covenantId")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing covenantId".to_string())?;
    let bytes = hex::decode(id).map_err(|error| format!("bad covenantId hex: {error}"))?;
    if bytes.len() != 32 {
        return Err("covenantId must be 32 bytes".to_string());
    }
    Ok(json!({ "authorizingInput": authorizing, "id": id }))
}

fn optional_exact(global: &Map<String, Value>, key: &str) -> Result<u64, String> {
    match global.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(value) => wire::parse_exact_u64(value, key),
    }
}

fn optional_hex(global: &Map<String, Value>, key: &str) -> Result<Vec<u8>, String> {
    match global.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(value)) => {
            hex::decode(value).map_err(|error| format!("{key} hex: {error}"))
        }
        _ => Err(format!("{key} must be a hex string")),
    }
}

fn optional_fixed_hex<const N: usize>(
    global: &Map<String, Value>,
    key: &str,
) -> Result<Option<[u8; N]>, String> {
    let Some(Value::String(value)) = global.get(key) else {
        return match global.get(key) {
            None | Some(Value::Null) => Ok(None),
            _ => Err(format!("{key} must be a hex string")),
        };
    };
    let bytes = hex::decode(value).map_err(|error| format!("{key} hex: {error}"))?;
    bytes
        .as_slice()
        .try_into()
        .map(Some)
        .map_err(|_| format!("{key} must be {N} bytes"))
}

fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 35 && script[0] == 0xaa && script[1] == 0x20 && script[34] == 0x87
}
