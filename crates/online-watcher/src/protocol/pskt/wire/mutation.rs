// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use super::{decode_root, detect_format_hex, encode_root, first_pskt_from_pskb_mut};
use crate::protocol::pskt::PsktFormat;

/// Set `global.txPayload` on the first PSKT in an existing PSKB wire.
#[cfg(test)]
pub fn inject_tx_payload(wire_hex: &str, payload: &[u8]) -> Result<String, String> {
    if detect_format_hex(wire_hex) != PsktFormat::Pskb {
        return Err("inject_tx_payload: not a PSKB wire".into());
    }
    let (format, mut root) = decode_root(wire_hex)?;
    let pskt = first_pskt_from_pskb_mut(&mut root)?;
    let global = pskt
        .get_mut("global")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "missing global".to_string())?;
    global.insert("txPayload".to_string(), Value::String(hex::encode(payload)));
    encode_root(format, &root)
}

/// Stamp a transaction lane and payload into an existing PSKB wire.
pub fn set_tx_lane(
    wire_hex: &str,
    subnetwork_id_hex: &str,
    gas: u64,
    tx_version: u16,
    payload: &[u8],
) -> Result<String, String> {
    if detect_format_hex(wire_hex) != PsktFormat::Pskb {
        return Err("set_tx_lane: not a PSKB wire".into());
    }
    let subnetwork_id = hex::decode(subnetwork_id_hex)
        .map_err(|e| format!("set_tx_lane: subnetwork hex: {}", e))?;
    if subnetwork_id.len() != 20 {
        return Err(format!(
            "set_tx_lane: subnetwork_id must be 20 bytes, got {}",
            subnetwork_id.len()
        ));
    }
    let (format, mut root) = decode_root(wire_hex)?;
    let pskt = first_pskt_from_pskb_mut(&mut root)?;
    let global = pskt
        .get_mut("global")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "missing global".to_string())?;
    global.insert(
        "subnetworkId".to_string(),
        Value::String(hex::encode(subnetwork_id)),
    );
    global.insert("gas".to_string(), Value::from(gas));
    global.insert("txVersion".to_string(), Value::from(tx_version));
    global.insert("txPayload".to_string(), Value::String(hex::encode(payload)));
    encode_root(format, &root)
}
