use serde_json::{Map, Value};

use super::wire::{parse_exact_u64, parse_spk};

pub(crate) struct InputFields {
    pub previous_tx_id: [u8; 32],
    pub previous_index: u32,
    pub amount: u64,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub script_version: u16,
    pub script_public_key: Vec<u8>,
    pub redeem_script: Option<Vec<u8>>,
    pub partial_signatures: Map<String, Value>,
}

impl InputFields {
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "input not object".to_string())?;
        let (amount, script_version, script_public_key) = parse_utxo_fields(object)?;
        let (previous_tx_id, previous_index) = parse_outpoint(object)?;
        let sequence = parse_sequence(object)?;
        let sig_op_count = parse_sig_op_count(object)?;
        let redeem_script = parse_redeem_script(object)?;
        let partial_signatures = object
            .get("partialSigs")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        Ok(Self {
            previous_tx_id,
            previous_index,
            amount,
            sequence,
            sig_op_count,
            script_version,
            script_public_key,
            redeem_script,
            partial_signatures,
        })
    }
}

fn parse_utxo_fields(object: &Map<String, Value>) -> Result<(u64, u16, Vec<u8>), String> {
    let utxo = object
        .get("utxoEntry")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let amount = parse_exact_u64(
        utxo.get("amount")
            .ok_or_else(|| "missing amount".to_string())?,
        "amount",
    )?;
    let spk = utxo
        .get("scriptPublicKey")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (script_version, script_public_key) = parse_spk(spk)?;
    if script_public_key.len() > 512 {
        return Err(format!(
            "spk too long for compact KSPT ({})",
            script_public_key.len()
        ));
    }
    Ok((amount, script_version, script_public_key))
}

fn parse_sequence(object: &Map<String, Value>) -> Result<u64, String> {
    object
        .get("sequence")
        .map_or(Ok(0), |value| parse_exact_u64(value, "sequence"))
}

fn parse_sig_op_count(object: &Map<String, Value>) -> Result<u8, String> {
    match object.get("sigOpCount").and_then(Value::as_u64) {
        Some(value) => u8::try_from(value).map_err(|_| "sigOpCount exceeds u8".to_string()),
        None => Ok(1),
    }
}

fn parse_redeem_script(object: &Map<String, Value>) -> Result<Option<Vec<u8>>, String> {
    object
        .get("redeemScript")
        .and_then(Value::as_str)
        .map(|value| hex::decode(value).map_err(|error| format!("redeem hex: {error}")))
        .transpose()
}

fn parse_outpoint(object: &Map<String, Value>) -> Result<([u8; 32], u32), String> {
    let outpoint = object
        .get("previousOutpoint")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let transaction_id = outpoint
        .get("transactionId")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing transactionId".to_string())?;
    let bytes = hex::decode(transaction_id).map_err(|error| format!("bad tx_id hex: {error}"))?;
    let previous_tx_id = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "tx_id not 32 bytes".to_string())?;
    let index = outpoint
        .get("index")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing index".to_string())?;
    let previous_index = u32::try_from(index).map_err(|_| "index exceeds u32".to_string())?;
    Ok((previous_tx_id, previous_index))
}

pub(crate) struct Signature {
    pub position: u8,
    pub bytes: [u8; 64],
}

pub(crate) fn collect_signatures(fields: &InputFields) -> Result<Vec<Signature>, String> {
    if fields.partial_signatures.is_empty() {
        return Ok(Vec::new());
    }
    match fields.redeem_script.as_deref() {
        Some(redeem) if parse_multisig_redeem(redeem).is_some() => {
            let mut signatures = Vec::with_capacity(fields.partial_signatures.len());
            for (public_key, value) in &fields.partial_signatures {
                let position = find_pubkey_position(redeem, public_key).ok_or_else(|| {
                    format!("partial-signature pubkey is not in redeem script: {public_key}")
                })?;
                signatures.push(Signature {
                    position,
                    bytes: decode_signature(value)?,
                });
            }
            signatures.sort_by_key(|entry| entry.position);
            Ok(signatures)
        }
        Some(_) => Ok(Vec::new()),
        None => {
            let (_, value) = fields
                .partial_signatures
                .iter()
                .next()
                .expect("non-empty map");
            Ok(vec![Signature {
                position: 0,
                bytes: decode_signature(value)?,
            }])
        }
    }
}

fn decode_signature(value: &Value) -> Result<[u8; 64], String> {
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

pub(crate) fn parse_multisig_redeem(script: &[u8]) -> Option<(u8, u8)> {
    let threshold = script.first().copied().and_then(decode_small_int)?;
    let declared = multisig_declared_count(script)?;
    let count = multisig_key_count(script)?;
    (script.last() == Some(&0xae) && declared == count && threshold <= declared)
        .then_some((threshold, declared))
}

fn multisig_declared_count(script: &[u8]) -> Option<u8> {
    let position = script.len().checked_sub(2)?;
    script.get(position).copied().and_then(decode_small_int)
}

fn multisig_key_count(script: &[u8]) -> Option<u8> {
    let end = script.len().checked_sub(2)?;
    let region = script.get(1..end)?;
    if !region.len().is_multiple_of(33) || !region.chunks_exact(33).all(|chunk| chunk[0] == 0x20) {
        return None;
    }
    u8::try_from(region.len() / 33).ok()
}

fn decode_small_int(opcode: u8) -> Option<u8> {
    (0x51..=0x60).contains(&opcode).then_some(opcode - 0x50)
}

pub(crate) fn find_pubkey_position(redeem: &[u8], public_key_hex: &str) -> Option<u8> {
    if public_key_hex.len() != 66 {
        return None;
    }
    let xonly = hex::decode(&public_key_hex[2..]).ok()?;
    let mut position = 1usize;
    let mut index = 0u8;
    while position + 33 < redeem.len() {
        if redeem[position] != 0x20 {
            return None;
        }
        if redeem.get(position + 1..position + 33)? == xonly.as_slice() {
            return Some(index);
        }
        position += 33;
        index = index.saturating_add(1);
    }
    None
}

pub(crate) fn parse_ms45(value: &Value) -> Option<(u32, u32, u32)> {
    let map = value.as_object()?;
    map.values().find_map(|entry| {
        let path = entry.get("derivationPath")?.as_str()?;
        let tail = path.strip_prefix("m/45'/111111'/0'/")?;
        let mut parts = tail.split('/');
        let cosigner = parse_soft(parts.next()?)?;
        let chain = parse_soft(parts.next()?)?;
        let index = parse_soft(parts.next()?)?;
        (chain <= 1 && parts.next().is_none()).then_some((cosigner, chain, index))
    })
}

fn parse_soft(value: &str) -> Option<u32> {
    if value.ends_with('\'') {
        return None;
    }
    let parsed = value.parse::<u32>().ok()?;
    (parsed < 0x8000_0000).then_some(parsed)
}
