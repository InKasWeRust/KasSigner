// KasSee Web — PSKT (Partially Signed Kaspa Transaction) support
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// pskt.rs — Kaspa-standard PSKT / PSKB wire-format support for KasSee.
//
// Mirrors the on-wire format produced by `kaspa-wallet-pskt` and by
// KasSigner's own `bootloader/src/wallet/std_pskt.rs`. This is Lane B
// of the migration roadmap: hand-rolled, zero-new-deps, byte-compatible
// with the device. When full interop with Keystone / KasWare is
// required, Lane A (importing `kaspa-wasm` PSKT bindings) takes over.
//
// ═══════════════════════════════════════════════════════════════════
// Roles covered
// ═══════════════════════════════════════════════════════════════════
//
// KasSee operates as:
//   - Finalizer  — when ≥M sigs present, assemble sig_scripts.
//   - Extractor  — emit a broadcast-ready transaction.
//
// (Creator / Constructor still go through `kspt.rs` for now; that
//  work is the next KasSee PSKT chapter after this circle closes.)
//
// ═══════════════════════════════════════════════════════════════════
// Wire format (what the device emits after signing)
// ═══════════════════════════════════════════════════════════════════
//
// 4-byte magic `PSKB` or `PSKT` + lowercase hex of compact UTF-8 JSON.
// For `PSKB` the JSON body is a single-element array wrapping one
// PSKT object. For `PSKT` the body is the PSKT object directly.
//
// PSKT object shape (exact field names, camelCase):
//
//   {
//     "global": {
//       "version": 0,
//       "txVersion": N,
//       "fallbackLockTime": null,
//       "inputsModifiable": bool,
//       "outputsModifiable": bool,
//       "inputCount": N,
//       "outputCount": N,
//       "xpubs": {},
//       "id": null,
//       "proprietaries": {}
//     },
//     "inputs": [
//       {
//         "utxoEntry": {
//           "amount": N,
//           "scriptPublicKey": "<4hex version BE><script hex>",
//           "blockDaaScore": N,
//           "isCoinbase": bool
//         },
//         "previousOutpoint": {
//           "transactionId": "<64 hex>",
//           "index": N
//         },
//         "sequence": N,
//         "minTime": null,
//         "partialSigs": {
//           "<66 hex pubkey>": {"schnorr":"<128 hex sig>"},
//           ...
//         },
//         "sighashType": 1,
//         "redeemScript": null | "<hex>",
//         "sigOpCount": N,
//         "bip32Derivations": {...},
//         "finalScriptSig": null,
//         "proprietaries": {}
//       }
//     ],
//     "outputs": [
//       {
//         "amount": N,
//         "scriptPublicKey": "<hex>",
//         "redeemScript": null,
//         "bip32Derivations": {},
//         "proprietaries": {}
//       }
//     ]
//   }
//
// Verified byte-compatible against rusty-kaspa's `kaspa-wallet-pskt`
// on 20 Apr 2026 via desktop harness.

//! PSKT / PSKB wire-format engine: encode and decode of partially-signed
//! bundles, consensus-input construction, and the finalize / merge / relay paths.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ═══════════════════════════════════════════════════════════════════
// Envelope detection
// ═══════════════════════════════════════════════════════════════════

/// Magic prefix for PSKB (bundle of PSKTs) wire payloads.
/// Kept `pub const` as documentation for the wire format; detection
/// itself compares the hex-ASCII form to avoid a decode step.
// Kept: retained for future use; not currently wired.
#[allow(dead_code)]
pub const PSKB_MAGIC: &[u8; 4] = b"PSKB";
/// Magic prefix for single-PSKT wire payloads.
// Kept: retained for future use; not currently wired.
#[allow(dead_code)]
pub const PSKT_MAGIC: &[u8; 4] = b"PSKT";

/// Detected wire format for a given hex payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PsktFormat {
    /// `PSKB` magic — body is `[<PSKT>]`.
    Pskb,
    /// `PSKT` magic — body is `<PSKT>` directly.
    PsktSingle,
    /// Not a PSKT-shaped payload.
    Unknown,
}

/// Cheap pre-check: given a hex string (whatever the QR decoder returned),
/// inspect the first 8 hex chars and report the magic.
/// Returns `Unknown` for KSPT or anything else — existing paths keep
/// working; only real PSKT/PSKB routes through this module.
pub fn detect_format_hex(hex_str: &str) -> PsktFormat {
    if hex_str.len() < 8 {
        return PsktFormat::Unknown;
    }
    // Match case-insensitively on the hex of "PSKB" / "PSKT"
    //   "PSKB" -> 50534b42
    //   "PSKT" -> 50534b54
    let head = hex_str[..8].to_ascii_lowercase();
    match head.as_str() {
        "50534b42" => PsktFormat::Pskb,
        "50534b54" => PsktFormat::PsktSingle,
        _ => PsktFormat::Unknown,
    }
}

/// Set `global.txPayload` on an existing single-entry PSKB wire and re-emit
/// the wire. Used to attach a transaction payload (e.g. the stealth ephemeral
/// R) to a plain send PSKB built by `create_send_pskb`, without duplicating
/// coin-selection/change logic.
///
/// The payload is committed by the firmware sighash (`payload_hash`) and by
/// consensus (`finalize_and_broadcast` reads `txPayload`), so the device signs
/// over it and the broadcast tx carries it. Wire framing matches the rest of
/// the PSKB family: `hex( b"PSKB" + ascii(hex(json)) )`.
pub fn inject_tx_payload(wire_hex: &str, payload: &[u8]) -> Result<String, String> {
    if detect_format_hex(wire_hex) != PsktFormat::Pskb {
        return Err("inject_tx_payload: not a PSKB wire".into());
    }
    let wire = hex::decode(wire_hex).map_err(|e| format!("outer hex: {}", e))?;
    if wire.len() < 4 || &wire[..4] != b"PSKB" {
        return Err("inject_tx_payload: missing PSKB magic".into());
    }
    let json_bytes = hex::decode(&wire[4..]).map_err(|e| format!("inner hex: {}", e))?;
    let mut root: Value =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("JSON parse: {}", e))?;

    {
        let arr = root
            .as_array_mut()
            .ok_or_else(|| "PSKB not array".to_string())?;
        let pskt = arr.get_mut(0).ok_or_else(|| "empty PSKB".to_string())?;
        let global = pskt
            .get_mut("global")
            .and_then(|v| v.as_object_mut())
            .ok_or_else(|| "missing global".to_string())?;
        global.insert("txPayload".to_string(), Value::String(hex::encode(payload)));
    }

    let new_json = serde_json::to_vec(&root).map_err(|e| e.to_string())?;
    let mut out: Vec<u8> = Vec::with_capacity(4 + new_json.len() * 2);
    out.extend_from_slice(b"PSKB");
    out.extend_from_slice(hex::encode(&new_json).as_bytes());
    Ok(hex::encode(&out))
}

/// Like `inject_tx_payload`, but also stamps the lane `subnetwork_id`, `gas`,
/// and `tx_version` into the PSKB global, so the device signs a v1 lane tx and
/// both `relay_pskb_as_kspt_v2_hex` (device KSPT) and `finalize_and_broadcast`
/// (consensus tx) emit it on that lane. `subnetwork_id_hex` is 20 bytes hex
/// (e.g. "4b53544c" + 16 zero bytes for the KSTL seq-commit lane). Standard
/// sends never call this, so their global stays native/0 and behaviour is
/// unchanged.
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
    let sub = hex::decode(subnetwork_id_hex)
        .map_err(|e| format!("set_tx_lane: subnetwork hex: {}", e))?;
    if sub.len() != 20 {
        return Err(format!(
            "set_tx_lane: subnetwork_id must be 20 bytes, got {}",
            sub.len()
        ));
    }
    let wire = hex::decode(wire_hex).map_err(|e| format!("outer hex: {}", e))?;
    if wire.len() < 4 || &wire[..4] != b"PSKB" {
        return Err("set_tx_lane: missing PSKB magic".into());
    }
    let json_bytes = hex::decode(&wire[4..]).map_err(|e| format!("inner hex: {}", e))?;
    let mut root: Value =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("JSON parse: {}", e))?;

    {
        let arr = root
            .as_array_mut()
            .ok_or_else(|| "PSKB not array".to_string())?;
        let pskt = arr.get_mut(0).ok_or_else(|| "empty PSKB".to_string())?;
        let global = pskt
            .get_mut("global")
            .and_then(|v| v.as_object_mut())
            .ok_or_else(|| "missing global".to_string())?;
        global.insert("subnetworkId".to_string(), Value::String(hex::encode(&sub)));
        global.insert("gas".to_string(), Value::from(gas));
        global.insert("txVersion".to_string(), Value::from(tx_version));
        global.insert("txPayload".to_string(), Value::String(hex::encode(payload)));
    }

    let new_json = serde_json::to_vec(&root).map_err(|e| e.to_string())?;
    let mut out: Vec<u8> = Vec::with_capacity(4 + new_json.len() * 2);
    out.extend_from_slice(b"PSKB");
    out.extend_from_slice(hex::encode(&new_json).as_bytes());
    Ok(hex::encode(&out))
}

// ═══════════════════════════════════════════════════════════════════
// Parsed summary — what the JS review screen consumes
// ═══════════════════════════════════════════════════════════════════

/// One partial signature present on an input.
#[derive(Clone, Serialize, Deserialize)]
pub struct PartialSigInfo {
    pub pubkey_hex: String,
    /// Position in the redeem script (0-indexed across pubkeys), if
    /// pubkey matched a redeem-script entry. `None` for non-multisig
    /// inputs or if the pubkey wasn't found in the script.
    pub position: Option<u8>,
}

/// One input, as digestible by the review UI.
#[derive(Clone, Serialize, Deserialize)]
pub struct InputSummary {
    pub prev_tx_id: String,
    pub prev_index: u32,
    pub amount_sompi: u64,
    pub amount_kas: f64,
    pub script_kind: String, // "p2pk", "p2sh", "p2sh-multisig", "unknown"
    pub script_hex: String,  // full scriptPublicKey (hex, without version prefix)
    pub redeem_script_hex: Option<String>,
    /// For multisig redeem scripts: M in M-of-N. `None` if not multisig.
    pub multisig_m: Option<u8>,
    /// For multisig: N (total pubkeys in redeem script).
    pub multisig_n: Option<u8>,
    pub sigs_present: u8,
    pub partial_sigs: Vec<PartialSigInfo>,
}

/// One output.
#[derive(Clone, Serialize, Deserialize)]
pub struct OutputSummary {
    pub amount_sompi: u64,
    pub amount_kas: f64,
    pub script_kind: String,
    pub script_hex: String,
    /// Decoded Kaspa address when the script is a recognized P2PK/P2SH
    /// form — saves the JS side from reimplementing address encoding.
    pub address: Option<String>,
}

/// Everything the UI needs to render a PSKB review screen.
#[derive(Clone, Serialize, Deserialize)]
pub struct PsktSummary {
    pub format: String, // "pskb" or "pskt"
    pub tx_version: u16,
    pub input_count: usize,
    pub output_count: usize,
    pub inputs: Vec<InputSummary>,
    pub outputs: Vec<OutputSummary>,
    pub total_in_sompi: u64,
    pub total_out_sompi: u64,
    pub fee_sompi: u64,
    /// True when every multisig input has at least M sigs present.
    /// (For non-multisig inputs, "ready" means ≥1 sig present.)
    pub finalize_ready: bool,
}

// ═══════════════════════════════════════════════════════════════════
// Parse: wire bytes → PsktSummary
// ═══════════════════════════════════════════════════════════════════

/// Parse a hex-encoded PSKB or PSKT payload into a review summary.
pub fn parse_summary(wire_hex: &str, network_prefix: &str) -> Result<PsktSummary, String> {
    let format = detect_format_hex(wire_hex);
    if format == PsktFormat::Unknown {
        return Err("Not a PSKT/PSKB payload".into());
    }

    let wire = hex::decode(wire_hex).map_err(|e| format!("Bad outer hex: {}", e))?;
    if wire.len() < 4 {
        return Err("Payload too short".into());
    }
    let body_hex = &wire[4..];
    let json_bytes = hex::decode(body_hex).map_err(|e| format!("Bad inner hex: {}", e))?;

    // Parse JSON. For PSKB the body is an array; for PSKT it's an object.
    let root: Value =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("JSON parse: {}", e))?;
    let pskt_obj = match format {
        PsktFormat::Pskb => {
            let arr = root
                .as_array()
                .ok_or_else(|| "PSKB body is not an array".to_string())?;
            if arr.len() != 1 {
                return Err(format!("PSKB must wrap exactly 1 PSKT, got {}", arr.len()));
            }
            arr[0].clone()
        }
        PsktFormat::PsktSingle => root,
        PsktFormat::Unknown => unreachable!(),
    };

    parse_pskt_object(&pskt_obj, format, network_prefix)
}

fn parse_pskt_object(
    pskt: &Value,
    format: PsktFormat,
    network_prefix: &str,
) -> Result<PsktSummary, String> {
    let obj = pskt
        .as_object()
        .ok_or_else(|| "PSKT is not an object".to_string())?;

    // ─── global ───
    let global = obj
        .get("global")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing global".to_string())?;
    let tx_version = global
        .get("txVersion")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing txVersion".to_string())? as u16;

    // ─── inputs ───
    let inputs_arr = obj
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing inputs".to_string())?;
    let mut inputs = Vec::with_capacity(inputs_arr.len());
    let mut total_in_sompi: u64 = 0;
    let mut all_ready = true;

    for (i, inp) in inputs_arr.iter().enumerate() {
        let summary = parse_input_summary(inp).map_err(|e| format!("input[{}]: {}", i, e))?;
        total_in_sompi = total_in_sompi.saturating_add(summary.amount_sompi);

        // Readiness check
        let min_sigs = inp
            .get("minimumSignatures")
            .and_then(|v| v.as_u64())
            .map(|v| v as u8);
        let ready_here = match (summary.multisig_m, min_sigs, summary.sigs_present) {
            // Multisig: need M sigs
            (Some(m), _, present) => present >= m,
            // Explicit minimumSignatures: 0 (covenant borrower path)
            (None, Some(0), _) => true,
            // Default: need at least 1 sig
            (None, _, present) => present >= 1,
        };
        if !ready_here {
            all_ready = false;
        }
        inputs.push(summary);
    }

    // ─── outputs ───
    let outputs_arr = obj
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing outputs".to_string())?;
    let mut outputs = Vec::with_capacity(outputs_arr.len());
    let mut total_out_sompi: u64 = 0;

    for (i, out) in outputs_arr.iter().enumerate() {
        let summary = parse_output_summary(out, network_prefix)
            .map_err(|e| format!("output[{}]: {}", i, e))?;
        total_out_sompi = total_out_sompi.saturating_add(summary.amount_sompi);
        outputs.push(summary);
    }

    let fee_sompi = total_in_sompi.saturating_sub(total_out_sompi);

    Ok(PsktSummary {
        format: match format {
            PsktFormat::Pskb => "pskb".into(),
            PsktFormat::PsktSingle => "pskt".into(),
            PsktFormat::Unknown => "unknown".into(),
        },
        tx_version,
        input_count: inputs.len(),
        output_count: outputs.len(),
        inputs,
        outputs,
        total_in_sompi,
        total_out_sompi,
        fee_sompi,
        finalize_ready: all_ready,
    })
}

fn parse_input_summary(inp: &Value) -> Result<InputSummary, String> {
    let obj = inp
        .as_object()
        .ok_or_else(|| "input not object".to_string())?;

    // utxoEntry
    let utxo = obj
        .get("utxoEntry")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let amount_sompi = utxo
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = utxo
        .get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (_spk_version, spk_script) = parse_spk_hex(spk_full)?;

    // previousOutpoint
    let op = obj
        .get("previousOutpoint")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let prev_tx_id = op
        .get("transactionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing transactionId".to_string())?
        .to_string();
    let prev_index = op
        .get("index")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing index".to_string())? as u32;

    // redeemScript
    let redeem_script_hex: Option<String> = match obj.get("redeemScript") {
        Some(v) if v.is_null() => None,
        Some(v) => v.as_str().map(|s| s.to_string()),
        None => None,
    };
    let redeem_bytes: Option<Vec<u8>> = match &redeem_script_hex {
        Some(h) => Some(hex::decode(h).map_err(|e| format!("bad redeemScript: {}", e))?),
        None => None,
    };

    // Classify script
    let (script_kind, multisig_m, multisig_n) =
        classify_input_script(&spk_script, redeem_bytes.as_deref());

    // partialSigs
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

fn parse_output_summary(out: &Value, network_prefix: &str) -> Result<OutputSummary, String> {
    let obj = out
        .as_object()
        .ok_or_else(|| "output not object".to_string())?;
    let amount_sompi = obj
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = obj
        .get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (_spk_version, spk_script) = parse_spk_hex(spk_full)?;
    let (kind, address) = classify_output_script(&spk_script, network_prefix);

    Ok(OutputSummary {
        amount_sompi,
        amount_kas: amount_sompi as f64 / 1e8,
        script_kind: kind,
        script_hex: hex::encode(&spk_script),
        address,
    })
}

/// `scriptPublicKey` is flat hex: first 4 hex chars (2 bytes BE) = version,
/// remainder is the script. Returns (version, script_bytes).
fn parse_spk_hex(s: &str) -> Result<(u16, Vec<u8>), String> {
    if s.len() < 4 {
        return Err(format!("scriptPublicKey too short: {}", s.len()));
    }
    // Version: 2 bytes BE = 4 hex chars.
    let ver_hex = &s[..4];
    let script_hex = &s[4..];
    let v0 = u8::from_str_radix(&ver_hex[..2], 16).map_err(|e| format!("bad version hi: {}", e))?;
    let v1 =
        u8::from_str_radix(&ver_hex[2..4], 16).map_err(|e| format!("bad version lo: {}", e))?;
    let version = ((v0 as u16) << 8) | (v1 as u16);
    let script = hex::decode(script_hex).map_err(|e| format!("bad script hex: {}", e))?;
    Ok((version, script))
}

fn classify_input_script(spk: &[u8], redeem: Option<&[u8]>) -> (String, Option<u8>, Option<u8>) {
    // P2SH: OP_BLAKE2B(0xAA) OP_DATA_32(0x20) <32> OP_EQUAL(0x87)
    let is_p2sh = spk.len() == 35 && spk[0] == 0xAA && spk[1] == 0x20 && spk[34] == 0x87;
    if is_p2sh {
        if let Some(rs) = redeem {
            if let Some((m, n)) = parse_multisig_redeem(rs) {
                return ("p2sh-multisig".into(), Some(m), Some(n));
            }
            // Covenant scripts start with OP_IF (0x63)
            if !rs.is_empty() && rs[0] == 0x63 {
                return ("p2sh-covenant".into(), None, None);
            }
        }
        return ("p2sh".into(), None, None);
    }
    // P2PK: OP_DATA_32(0x20) <32> OP_CHECKSIG(0xAC)
    let is_p2pk = spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xAC;
    if is_p2pk {
        return ("p2pk".into(), None, None);
    }
    ("unknown".into(), None, None)
}

fn classify_output_script(spk: &[u8], network_prefix: &str) -> (String, Option<String>) {
    // P2SH
    if spk.len() == 35 && spk[0] == 0xAA && spk[1] == 0x20 && spk[34] == 0x87 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&spk[2..34]);
        return (
            "p2sh".into(),
            Some(crate::address::encode_p2sh_address(&hash, network_prefix)),
        );
    }
    // P2PK
    if spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xAC {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&spk[1..33]);
        return (
            "p2pk".into(),
            Some(crate::address::encode_p2pk_address(&pk, network_prefix)),
        );
    }
    ("unknown".into(), None)
}

/// Parse a redeem script: OP_M OP_DATA_32 <pk1> ... OP_N OP_CHECKMULTISIG
/// Returns (M, N) if the shape matches.
/// Each pubkey is 32-bytes (x-only, OP_DATA_32 = 0x20). Matches the
/// KasSigner-native multisig redeem-script format from kspt.rs line 456.
fn parse_multisig_redeem(rs: &[u8]) -> Option<(u8, u8)> {
    if rs.len() < 4 {
        return None;
    }
    if rs[rs.len() - 1] != 0xAE {
        return None;
    } // OP_CHECKMULTISIG
    let op_m = rs[0];
    if !(0x51..=0x60).contains(&op_m) {
        return None;
    }
    let m = op_m - 0x50;

    // Walk pubkeys
    let mut pos = 1usize;
    let mut n: u8 = 0;
    while pos < rs.len() - 2 {
        if rs[pos] != 0x20 {
            return None;
        } // OP_DATA_32
        pos += 1;
        if pos + 32 > rs.len() {
            return None;
        }
        pos += 32;
        n = n.saturating_add(1);
    }
    // pos now should point at OP_N; next is OP_CHECKMULTISIG.
    if pos + 2 != rs.len() {
        return None;
    }
    let op_n = rs[pos];
    if !(0x51..=0x60).contains(&op_n) {
        return None;
    }
    let n_from_op = op_n - 0x50;
    if n != n_from_op {
        return None;
    }
    if m == 0 || m > n {
        return None;
    }

    Some((m, n))
}

fn parse_partial_sigs_map(
    v: Option<&Value>,
    redeem: Option<&[u8]>,
) -> Result<(u8, Vec<PartialSigInfo>), String> {
    let map = match v {
        Some(Value::Object(m)) => m,
        Some(_) => return Err("partialSigs not object".into()),
        None => return Ok((0, vec![])),
    };

    let mut sigs = Vec::with_capacity(map.len());
    for (pk_hex, sig_val) in map.iter() {
        if pk_hex.len() != 66 {
            return Err(format!("bad pubkey length: {}", pk_hex.len()));
        }
        // Validate variant is schnorr (lowercase), and that sig hex is 128 chars.
        let obj = sig_val
            .as_object()
            .ok_or_else(|| "sig value not object".to_string())?;
        let sig_hex = obj
            .get("schnorr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "schnorr sig missing (ECDSA not supported)".to_string())?;
        if sig_hex.len() != 128 {
            return Err(format!("bad schnorr sig length: {}", sig_hex.len()));
        }

        // Position: scan redeem pubkeys (32-byte x-only). Device emits
        // the 33-byte SEC1-compressed pubkey here, so strip the 02/03
        // prefix to get the x-only key that lives in the redeem script.
        let position = match redeem {
            Some(rs) => find_pubkey_position_in_redeem(rs, pk_hex),
            None => None,
        };

        sigs.push(PartialSigInfo {
            pubkey_hex: pk_hex.clone(),
            position,
        });
    }

    let count = sigs.len().min(u8::MAX as usize) as u8;
    Ok((count, sigs))
}

/// Given a redeem script and a 33-byte compressed pubkey (66 hex),
/// return its 0-indexed position among the N pubkeys if present.
fn find_pubkey_position_in_redeem(rs: &[u8], pk_hex_66: &str) -> Option<u8> {
    if pk_hex_66.len() != 66 {
        return None;
    }
    // Strip SEC1 prefix (02/03) to get the 32-byte x-only key.
    let xonly_hex = &pk_hex_66[2..];
    let xonly = match hex::decode(xonly_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return None,
    };
    // Walk redeem: OP_M, then repeated [OP_DATA_32, <32>].
    let mut pos = 1usize;
    let mut idx: u8 = 0;
    while pos + 33 < rs.len() {
        if rs[pos] != 0x20 {
            return None;
        }
        if &rs[pos + 1..pos + 33] == xonly.as_slice() {
            return Some(idx);
        }
        pos += 33;
        idx = idx.saturating_add(1);
    }
    None
}

// ═══════════════════════════════════════════════════════════════════
// Finalize — PSKT → signed KSPT v2 hex
// ═══════════════════════════════════════════════════════════════════
//
// The existing `rpc::broadcast_signed` already consumes a **signed
// KSPT v2** binary (rpc.rs lines 494-583) and assembles a
// broadcast-ready Borsh `RpcTransaction`. That code path is
// mainnet-validated with real 2-of-3 multisig ceremonies. We reuse
// it verbatim: this finalizer emits KSPT v2 signed so no new
// broadcast code is needed.
//
// KSPT v2 signed layout (from bootloader/src/wallet/pskt.rs + rpc.rs):
//
//   Header:
//     "KSPT" | 0x02 (version) | 0x01 (flags: signed)
//   Global:
//     tx_version(2) | num_in(1) | num_out(1)
//     locktime(8) | subnetwork_id(20) | gas(8)
//     payload_len(2) | payload(payload_len)
//   Per input:
//     prev_tx_id(32) prev_index(4) amount(8) sequence(8) sig_op(1)
//     spk_version(2) spk_len(1) spk_bytes
//     sig_count(1)
//     [ pubkey_pos(1) sighash_type(1) sig(64) ] × sig_count
//     redeem_script_len(1) redeem_script_bytes
//   Per output:
//     value(8) spk_version(2) spk_len(1) spk_bytes
//
// For P2SH multisig: rpc.rs reads redeem_script_len + redeem_script
// per input, parses M from the first byte (OP_1..OP_16), sorts sigs
// by pubkey_pos, and assembles the final sig_script exactly as the
// existing multisig path does. We hand it the same shape.
//
// For P2PK: emit `redeem_script_len = 0` and a single
// `(pubkey_pos=0, sighash, sig)` triple. rpc.rs P2PK fallback at
// lines 565-582 takes sig[0] and emits the P2PK sig_script.

/// Finalize a fully-signed PSKT into a signed KSPT v2 hex blob the
/// existing `broadcast_signed` RPC path can consume directly.
///
/// Fails if any multisig input lacks the required M signatures or if
/// any P2PK input has zero sigs.
pub fn finalize_to_kspt_hex(wire_hex: &str) -> Result<String, String> {
    let format = detect_format_hex(wire_hex);
    if format == PsktFormat::Unknown {
        return Err("Not a PSKT/PSKB payload".into());
    }
    let wire = hex::decode(wire_hex).map_err(|e| format!("outer hex: {}", e))?;
    if wire.len() < 4 {
        return Err("payload too short".into());
    }
    let json_bytes = hex::decode(&wire[4..]).map_err(|e| format!("inner hex: {}", e))?;
    let root: Value =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("JSON parse: {}", e))?;
    let pskt = match format {
        PsktFormat::Pskb => {
            let arr = root
                .as_array()
                .ok_or_else(|| "PSKB not array".to_string())?;
            if arr.len() != 1 {
                return Err(format!("PSKB must have 1 entry, got {}", arr.len()));
            }
            arr[0].clone()
        }
        PsktFormat::PsktSingle => root,
        PsktFormat::Unknown => unreachable!(),
    };
    let obj = pskt
        .as_object()
        .ok_or_else(|| "PSKT not object".to_string())?;

    // ─── Global ───
    let global = obj
        .get("global")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing global".to_string())?;
    let tx_version = global
        .get("txVersion")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing txVersion".to_string())? as u16;

    // ─── Input / output arrays ───
    let inputs = obj
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing inputs".to_string())?;
    let outputs = obj
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing outputs".to_string())?;
    if inputs.len() > 255 {
        return Err("too many inputs".into());
    }
    if outputs.len() > 255 {
        return Err("too many outputs".into());
    }

    // ─── Build KSPT v3 signed buffer ───
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    buf.extend_from_slice(b"KSPT");
    buf.push(0x03); // version = v3 (u16 redeem_len)
    buf.push(0x01); // flags   = signed
    buf.extend_from_slice(&tx_version.to_le_bytes());
    buf.push(inputs.len() as u8);
    buf.push(outputs.len() as u8);
    // locktime + subnetwork_id + gas + payload_len (standard tx: all zero / empty)
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&[0u8; 20]);
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    for (i, inp) in inputs.iter().enumerate() {
        encode_input_kspt_v2(&mut buf, inp).map_err(|e| format!("input[{}]: {}", i, e))?;
    }
    for (i, out) in outputs.iter().enumerate() {
        encode_output_kspt(&mut buf, out).map_err(|e| format!("output[{}]: {}", i, e))?;
    }

    Ok(hex::encode(&buf))
}

/// Encode one input in KSPT v2 signed layout. See the module header
/// comment for the exact byte layout.
#[allow(clippy::unnecessary_unwrap)]
fn encode_input_kspt_v2(buf: &mut Vec<u8>, inp: &Value) -> Result<(), String> {
    let obj = inp.as_object().ok_or_else(|| "not object".to_string())?;

    // utxoEntry
    let utxo = obj
        .get("utxoEntry")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let amount = utxo
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = utxo
        .get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (spk_version, spk_script) = parse_spk_hex(spk_full)?;
    if spk_script.len() > 512 {
        return Err(format!(
            "spk too long for KSPT v2 ({} > 512)",
            spk_script.len()
        ));
    }

    // outpoint
    let op = obj
        .get("previousOutpoint")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let prev_tx_id_hex = op
        .get("transactionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing transactionId".to_string())?;
    let prev_tx_id = hex::decode(prev_tx_id_hex).map_err(|e| format!("bad tx_id hex: {}", e))?;
    if prev_tx_id.len() != 32 {
        return Err("tx_id not 32 bytes".into());
    }
    let prev_index = op
        .get("index")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing index".to_string())? as u32;

    let sequence = obj.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0);
    let sig_op_count = obj.get("sigOpCount").and_then(|v| v.as_u64()).unwrap_or(1) as u8;

    // redeemScript
    let redeem: Option<Vec<u8>> = match obj.get("redeemScript") {
        Some(v) if v.is_null() => None,
        Some(Value::String(s)) => Some(hex::decode(s).map_err(|e| format!("redeem hex: {}", e))?),
        _ => None,
    };

    // partialSigs
    let partial_map = obj
        .get("partialSigs")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    // Build v2 sig records: (pubkey_pos, sighash_type, 64-byte sig).
    //
    // Two branches:
    //   - P2SH-multisig: pubkey_pos is the index of the signer's x-only
    //     pubkey in the redeem script. rpc.rs sorts by this field and
    //     takes the first M sigs. We must provide ≥M valid entries.
    //   - P2PK or P2SH-non-multisig: emit one entry with pubkey_pos=0.
    let is_p2sh = spk_script.len() == 35
        && spk_script[0] == 0xAA
        && spk_script[1] == 0x20
        && spk_script[34] == 0x87;

    let mut sig_records: Vec<(u8, Vec<u8>)> = Vec::new();

    if is_p2sh && redeem.is_some() {
        let rs = redeem.as_ref().unwrap();
        if rs.first() == Some(&0x63) {
            // Covenant script — position 0 = IF (owner), 1 = ELSE (beneficiary)
            let (_pk_hex, sig_val) = partial_map
                .iter()
                .next()
                .ok_or_else(|| "covenant input has no signature".to_string())?;
            let sig_hex = sig_val
                .get("schnorr")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
            if sig_hex.len() != 128 {
                return Err(format!("bad sig length: {}", sig_hex.len()));
            }
            let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;

            // Determine branch: match signing pubkey against IF and ELSE pubkeys
            let pk_hex = _pk_hex.clone();
            let xonly_hex = if pk_hex.len() == 66 {
                &pk_hex[2..]
            } else {
                &pk_hex[..]
            };

            let owner_hex = if rs.len() >= 34 && rs[1] == 0x20 {
                Some(hex::encode(&rs[2..34]))
            } else {
                None
            };

            let pos = if owner_hex.as_deref() == Some(xonly_hex) {
                0u8 // IF branch (owner)
            } else {
                1u8 // ELSE branch (beneficiary)
            };

            sig_records.push((pos, sig_bytes));
        } else {
            let (required_m, _n) = parse_multisig_redeem(rs)
                .ok_or_else(|| "redeem is not a valid M-of-N multisig".to_string())?;

            for (pk_hex, sig_val) in partial_map.iter() {
                if pk_hex.len() != 66 {
                    continue;
                }
                let sig_hex = sig_val
                    .get("schnorr")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        "partial sig missing schnorr variant (ECDSA unsupported)".to_string()
                    })?;
                if sig_hex.len() != 128 {
                    return Err(format!("bad sig length: {}", sig_hex.len()));
                }
                let pos = find_pubkey_position_in_redeem(rs, pk_hex)
                    .ok_or_else(|| format!("pubkey not in redeem: {}", pk_hex))?;
                let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
                sig_records.push((pos, sig_bytes));
            }
            sig_records.sort_by_key(|t| t.0);

            if sig_records.len() < required_m as usize {
                return Err(format!(
                    "multisig not ready: {} sig(s) present, need {}",
                    sig_records.len(),
                    required_m,
                ));
            }
        }
    } else {
        // P2PK (or unknown non-multisig): need at least 1 sig.
        let (_pk_hex, sig_val) = partial_map
            .iter()
            .next()
            .ok_or_else(|| "input has no signature".to_string())?;
        let sig_hex = sig_val
            .get("schnorr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "partial sig missing schnorr variant (ECDSA unsupported)".to_string())?;
        if sig_hex.len() != 128 {
            return Err(format!("bad sig length: {}", sig_hex.len()));
        }
        let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
        sig_records.push((0u8, sig_bytes));
    }
    if sig_records.len() > 255 {
        return Err("too many sigs".into());
    }

    // ─── Write bytes ───
    buf.extend_from_slice(&prev_tx_id);
    buf.extend_from_slice(&prev_index.to_le_bytes());
    buf.extend_from_slice(&amount.to_le_bytes());
    buf.extend_from_slice(&sequence.to_le_bytes());
    buf.push(sig_op_count);
    buf.extend_from_slice(&spk_version.to_le_bytes());
    push_spk_len(buf, spk_script.len());
    buf.extend_from_slice(&spk_script);

    // sig_count + records (pubkey_pos + sighash_type + 64-byte sig)
    buf.push(sig_records.len() as u8);
    for (pos, sig) in &sig_records {
        buf.push(*pos);
        buf.push(0x01); // SIGHASH_ALL
        if sig.len() != 64 {
            return Err("sig must be 64 bytes".into());
        }
        buf.extend_from_slice(sig);
    }

    // redeem_script_len (u16 LE for v3) + redeem_script_bytes
    match redeem {
        Some(rs) => {
            if rs.len() > 1024 {
                return Err(format!("redeem too long for KSPT v3 ({} > 1024)", rs.len()));
            }
            buf.extend_from_slice(&(rs.len() as u16).to_le_bytes());
            buf.extend_from_slice(&rs);
        }
        None => {
            buf.extend_from_slice(&0u16.to_le_bytes());
        }
    }

    Ok(())
}

/// SPK length, extended encoding: len <= 254 -> 1 byte; len >= 255 -> 0xFF + u16 LE.
/// Backward compatible (small SPKs encode identically). Firmware read_spk_len mirrors this.
fn push_spk_len(buf: &mut Vec<u8>, len: usize) {
    if len <= 254 {
        buf.push(len as u8);
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(len as u16).to_le_bytes());
    }
}

fn encode_output_kspt(buf: &mut Vec<u8>, out: &Value) -> Result<(), String> {
    let obj = out.as_object().ok_or_else(|| "not object".to_string())?;
    let value = obj
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = obj
        .get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (spk_version, spk_script) = parse_spk_hex(spk_full)?;
    if spk_script.len() > 512 {
        return Err(format!("output spk too long ({} > 512)", spk_script.len()));
    }

    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(&spk_version.to_le_bytes());
    push_spk_len(buf, spk_script.len());
    buf.extend_from_slice(&spk_script);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// KSPT v2 relay (partial-sig transport to KasSigner)
// ═══════════════════════════════════════════════════════════════════
//
// Same wire layout as `finalize_to_kspt_hex`, with two relaxations:
//
//   1. Header `flags` byte = 0x00 (partial) instead of 0x01 (fully
//      signed). The device's `parse_signed_pskt_v2` already accepts
//      both values (bootloader/src/wallet/pskt.rs line 1076 discards
//      the flag byte after reading it).
//
//   2. The multisig sig-count gate is removed: relay may carry 0..=N
//      sigs per input. Finalize requires ≥M; relay does not.
//
// Everything else — global header, input layout, output layout,
// redeem-script carriage, pubkey-position sort — is byte-identical
// to `finalize_to_kspt_hex`. This is intentional: the device reads
// the same bytes either way.
//
// `finalize_to_kspt_hex` is the mainnet-verified path that produced
// tx `407d9489...`. Not one byte of it is touched by relay. The only
// shared code path is the header/global-emission prelude, which is
// duplicated here rather than refactored into a shared helper — any
// future refactor happens after relay is hardware-tested.

/// Re-emit a PSKB/PSKT as a KSPT v2 "partial" blob suitable for
/// relay to KasSigner over QR. Does NOT require M sigs to be present.
pub fn relay_pskb_as_kspt_v2_hex(wire_hex: &str) -> Result<String, String> {
    let format = detect_format_hex(wire_hex);
    if format == PsktFormat::Unknown {
        return Err("Not a PSKT/PSKB payload".into());
    }
    let wire = hex::decode(wire_hex).map_err(|e| format!("outer hex: {}", e))?;
    if wire.len() < 4 {
        return Err("payload too short".into());
    }
    let json_bytes = hex::decode(&wire[4..]).map_err(|e| format!("inner hex: {}", e))?;
    let root: Value =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("JSON parse: {}", e))?;
    let pskt = match format {
        PsktFormat::Pskb => {
            let arr = root
                .as_array()
                .ok_or_else(|| "PSKB not array".to_string())?;
            if arr.len() != 1 {
                return Err(format!("PSKB must have 1 entry, got {}", arr.len()));
            }
            arr[0].clone()
        }
        PsktFormat::PsktSingle => root,
        PsktFormat::Unknown => unreachable!(),
    };
    let obj = pskt
        .as_object()
        .ok_or_else(|| "PSKT not object".to_string())?;

    // ─── Global ───
    let global = obj
        .get("global")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing global".to_string())?;
    let tx_version = global
        .get("txVersion")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing txVersion".to_string())? as u16;

    // ─── Input / output arrays ───
    let inputs = obj
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing inputs".to_string())?;
    let outputs = obj
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing outputs".to_string())?;
    if inputs.len() > 255 {
        return Err("too many inputs".into());
    }
    if outputs.len() > 255 {
        return Err("too many outputs".into());
    }

    let locktime = global
        .get("fallbackLockTime")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // ─── Build KSPT v3 partial buffer ───
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    buf.extend_from_slice(b"KSPT");
    buf.push(0x03); // version = v3 (u16 redeem_len)
    buf.push(0x00); // flags   = partial (RELAY)
    buf.extend_from_slice(&tx_version.to_le_bytes());
    buf.push(inputs.len() as u8);
    buf.push(outputs.len() as u8);
    buf.extend_from_slice(&locktime.to_le_bytes()); // locktime from global
                                                    // subnetwork_id + gas from the PSKB global (default native/0 for standard
                                                    // sends; KSTL lane sends set them via set_tx_lane).
    let subnet_b = global
        .get("subnetworkId")
        .and_then(|v| v.as_str())
        .and_then(|h| hex::decode(h).ok())
        .unwrap_or_default();
    let mut subnet20 = [0u8; 20];
    if subnet_b.len() == 20 {
        subnet20.copy_from_slice(&subnet_b);
    }
    buf.extend_from_slice(&subnet20); // subnetwork_id
    let lane_gas = global.get("gas").and_then(|v| v.as_u64()).unwrap_or(0);
    buf.extend_from_slice(&lane_gas.to_le_bytes()); // gas

    // TX payload from PSKB global (for sighash computation on device)
    let payload_hex = global
        .get("txPayload")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let payload_bytes = hex::decode(payload_hex).unwrap_or_default();
    buf.extend_from_slice(&(payload_bytes.len() as u16).to_le_bytes());
    if !payload_bytes.is_empty() {
        buf.extend_from_slice(&payload_bytes);
    }

    for (i, inp) in inputs.iter().enumerate() {
        encode_input_kspt_v2_relay(&mut buf, inp).map_err(|e| format!("input[{}]: {}", i, e))?;
    }
    for (i, out) in outputs.iter().enumerate() {
        encode_output_kspt(&mut buf, out).map_err(|e| format!("output[{}]: {}", i, e))?;
    }

    // Stealth tweak trailer: if any input has proprietaries.stealthTweak,
    // append 0x53 ('S') + 32-byte tweak. Backwards compatible.
    for inp in inputs.iter() {
        if let Some(tweak_hex) = inp
            .as_object()
            .and_then(|o| o.get("proprietaries"))
            .and_then(|v| v.as_object())
            .and_then(|p| p.get("stealthTweak"))
            .and_then(|v| v.as_str())
        {
            if let Ok(tweak_bytes) = hex::decode(tweak_hex) {
                if tweak_bytes.len() == 32 {
                    buf.push(0x53); // stealth marker 'S'
                    buf.extend_from_slice(&tweak_bytes);
                    web_sys::console::log_1(
                        &"[KasSee] KSPT v2 relay: stealth tweak appended"
                            .to_string()
                            .into(),
                    );
                    break;
                }
            }
        }
    }

    // Covenant trailer: if any input has proprietaries.persistentVault = true,
    // compute the genesis covenant_id and append 0x43 ('C') + out_idx(u8) +
    // auth_input(u16 LE) + covenant_id(32) for the continuation output.
    let is_persistent_vault = inputs.iter().any(|inp| {
        inp.get("proprietaries")
            .and_then(|p| p.get("persistentVault"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    });
    let out0_has_explicit_binding = outputs
        .first()
        .and_then(|o| o.get("covenantBinding"))
        .map(|cb| !cb.is_null())
        .unwrap_or(false);
    if is_persistent_vault
        && !inputs.is_empty()
        && !outputs.is_empty()
        && !out0_has_explicit_binding
    {
        // Extract input[0] outpoint for covenant_id computation
        if let Some(inp0) = inputs[0].as_object() {
            if let Some(op) = inp0.get("previousOutpoint").and_then(|v| v.as_object()) {
                let prev_tx_hex = op
                    .get("transactionId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let prev_index = op.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                if let Ok(prev_tx_vec) = hex::decode(prev_tx_hex) {
                    if prev_tx_vec.len() == 32 {
                        let mut prev_tx_id = [0u8; 32];
                        prev_tx_id.copy_from_slice(&prev_tx_vec);
                        // Get continuation output[0] data
                        if let Some(out0) = outputs[0].as_object() {
                            let out_val = out0.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                            let out_spk_full = out0
                                .get("scriptPublicKey")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            if let Ok((spk_ver, spk_script)) = parse_spk_hex(out_spk_full) {
                                let covenant_id = compute_genesis_covenant_id(
                                    &prev_tx_id,
                                    prev_index,
                                    0u32,
                                    out_val,
                                    spk_ver,
                                    &spk_script,
                                );
                                buf.push(0x43); // covenant marker 'C'
                                buf.push(0u8); // output index 0
                                buf.extend_from_slice(&0u16.to_le_bytes()); // auth_input = 0
                                buf.extend_from_slice(&covenant_id);
                                web_sys::console::log_1(
                                    &format!(
                                        "[KasSee] KSPT v2 relay: covenant trailer appended, id={}",
                                        hex::encode(covenant_id)
                                    )
                                    .into(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Covenant trailer for outputs with explicit covenantBinding field.
    // Covers any covenant PSKB (not just persistentVault).
    for (i, out) in outputs.iter().enumerate() {
        if let Some(cb) = out.get("covenantBinding") {
            if !cb.is_null() {
                if let Some(cb_obj) = cb.as_object() {
                    let auth_input = cb_obj
                        .get("authorizingInput")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u16;
                    let cov_id_hex = cb_obj
                        .get("covenantId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if let Ok(cov_id_vec) = hex::decode(cov_id_hex) {
                        if cov_id_vec.len() == 32 {
                            buf.push(0x43);
                            buf.push(i as u8);
                            buf.extend_from_slice(&auth_input.to_le_bytes());
                            buf.extend_from_slice(&cov_id_vec);
                            web_sys::console::log_1(
                                &format!(
                                    "[KasSee] KSPT relay: covenant trailer out[{}] id={}",
                                    i, cov_id_hex
                                )
                                .into(),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(hex::encode(&buf))
}

/// Encode one input in KSPT v2 layout for RELAY: carries 0..=N sigs,
/// no M-of-N gate. Byte-for-byte identical to `encode_input_kspt_v2`
/// except that empty `partialSigs` is allowed.
#[allow(clippy::unnecessary_unwrap)]
fn encode_input_kspt_v2_relay(buf: &mut Vec<u8>, inp: &Value) -> Result<(), String> {
    let obj = inp.as_object().ok_or_else(|| "not object".to_string())?;

    // utxoEntry
    let utxo = obj
        .get("utxoEntry")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let amount = utxo
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = utxo
        .get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (spk_version, spk_script) = parse_spk_hex(spk_full)?;
    if spk_script.len() > 512 {
        return Err(format!(
            "spk too long for KSPT v2 ({} > 512)",
            spk_script.len()
        ));
    }

    // outpoint
    let op = obj
        .get("previousOutpoint")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let prev_tx_id_hex = op
        .get("transactionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing transactionId".to_string())?;
    let prev_tx_id = hex::decode(prev_tx_id_hex).map_err(|e| format!("bad tx_id hex: {}", e))?;
    if prev_tx_id.len() != 32 {
        return Err("tx_id not 32 bytes".into());
    }
    let prev_index = op
        .get("index")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing index".to_string())? as u32;

    let sequence = obj.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0);
    let sig_op_count = obj.get("sigOpCount").and_then(|v| v.as_u64()).unwrap_or(1) as u8;

    // redeemScript
    let redeem: Option<Vec<u8>> = match obj.get("redeemScript") {
        Some(v) if v.is_null() => None,
        Some(Value::String(s)) => Some(hex::decode(s).map_err(|e| format!("redeem hex: {}", e))?),
        _ => None,
    };

    // partialSigs (may be empty in relay mode)
    let partial_map = obj
        .get("partialSigs")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let is_p2sh = spk_script.len() == 35
        && spk_script[0] == 0xAA
        && spk_script[1] == 0x20
        && spk_script[34] == 0x87;

    let mut sig_records: Vec<(u8, Vec<u8>)> = Vec::new();

    if is_p2sh && redeem.is_some() {
        let rs = redeem.as_ref().unwrap();
        // Try multisig parse — if it succeeds, map partial sigs to positions.
        // If it fails (e.g. covenant script), carry the redeem script but skip
        // positional sig mapping — the device handles signing internally.
        if let Some((_m, _n)) = parse_multisig_redeem(rs) {
            for (pk_hex, sig_val) in partial_map.iter() {
                if pk_hex.len() != 66 {
                    continue;
                }
                let sig_hex = sig_val
                    .get("schnorr")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        "partial sig missing schnorr variant (ECDSA unsupported)".to_string()
                    })?;
                if sig_hex.len() != 128 {
                    return Err(format!("bad sig length: {}", sig_hex.len()));
                }
                let pos = find_pubkey_position_in_redeem(rs, pk_hex)
                    .ok_or_else(|| format!("pubkey not in redeem: {}", pk_hex))?;
                let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
                sig_records.push((pos, sig_bytes));
            }
            sig_records.sort_by_key(|t| t.0);
        }
        // else: covenant P2SH — no positional sigs to map, device will sign
    } else {
        // P2PK (or non-multisig P2SH): carry the one sig if present,
        // otherwise emit an empty sig list. Relay must not reject inputs
        // that have not been signed yet.
        if let Some((_pk_hex, sig_val)) = partial_map.iter().next() {
            let sig_hex = sig_val
                .get("schnorr")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    "partial sig missing schnorr variant (ECDSA unsupported)".to_string()
                })?;
            if sig_hex.len() != 128 {
                return Err(format!("bad sig length: {}", sig_hex.len()));
            }
            let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
            sig_records.push((0u8, sig_bytes));
        }
    }
    if sig_records.len() > 255 {
        return Err("too many sigs".into());
    }

    // ─── Write bytes (layout identical to encode_input_kspt_v2) ───
    buf.extend_from_slice(&prev_tx_id);
    buf.extend_from_slice(&prev_index.to_le_bytes());
    buf.extend_from_slice(&amount.to_le_bytes());
    buf.extend_from_slice(&sequence.to_le_bytes());
    buf.push(sig_op_count);
    buf.extend_from_slice(&spk_version.to_le_bytes());
    push_spk_len(buf, spk_script.len());
    buf.extend_from_slice(&spk_script);

    buf.push(sig_records.len() as u8);
    for (pos, sig) in &sig_records {
        buf.push(*pos);
        buf.push(0x01); // SIGHASH_ALL
        if sig.len() != 64 {
            return Err("sig must be 64 bytes".into());
        }
        buf.extend_from_slice(sig);
    }

    match redeem {
        Some(rs) => {
            if rs.len() > 1024 {
                return Err(format!("redeem too long for KSPT v3 ({} > 1024)", rs.len()));
            }
            buf.extend_from_slice(&(rs.len() as u16).to_le_bytes());
            buf.extend_from_slice(&rs);
        }
        None => {
            buf.extend_from_slice(&0u16.to_le_bytes());
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// PSKT-native finalize + broadcast (no KSPT intermediate)
// ═══════════════════════════════════════════════════════════════════
//
// This is the replacement for `finalize_to_kspt_hex` + `broadcast_signed`.
// It walks the PSKB JSON once, assembles a consensus `sig_script` per
// input (with partial sigs + redeem script for P2SH multisig, or just
// the Schnorr sig push for P2PK), and hands the result to
// `rpc::submit_consensus_tx` which Borsh-serializes it directly onto
// the wire.
//
// Nothing in this path speaks KSPT. No intermediate binary format at
// all. PSKB JSON → consensus Transaction fields → Borsh.

/// Finalize a fully-signed PSKT/PSKB and submit to a Kaspa node,
/// bypassing the legacy KSPT broadcast path entirely.
///
/// Returns the submitted transaction ID on success.
pub async fn finalize_and_broadcast(wire_hex: &str, ws_url: &str) -> Result<String, String> {
    let format = detect_format_hex(wire_hex);
    if format == PsktFormat::Unknown {
        return Err("Not a PSKT/PSKB payload".into());
    }
    let wire = hex::decode(wire_hex).map_err(|e| format!("outer hex: {}", e))?;
    if wire.len() < 4 {
        return Err("payload too short".into());
    }
    let json_bytes = hex::decode(&wire[4..]).map_err(|e| format!("inner hex: {}", e))?;
    let root: Value =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("JSON parse: {}", e))?;
    let pskt = match format {
        PsktFormat::Pskb => {
            let arr = root
                .as_array()
                .ok_or_else(|| "PSKB not array".to_string())?;
            if arr.len() != 1 {
                return Err(format!("PSKB must have 1 entry, got {}", arr.len()));
            }
            arr[0].clone()
        }
        PsktFormat::PsktSingle => root,
        PsktFormat::Unknown => unreachable!(),
    };
    let obj = pskt
        .as_object()
        .ok_or_else(|| "PSKT not object".to_string())?;

    // ─── Global ───
    let global = obj
        .get("global")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing global".to_string())?;
    let tx_version = global
        .get("txVersion")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing txVersion".to_string())? as u16;
    let locktime = global
        .get("fallbackLockTime")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let force_beneficiary = global
        .get("covenantBranch")
        .and_then(|v| v.as_str())
        .map(|s| s == "beneficiary")
        .unwrap_or(false);
    let explicit_time_path = global
        .get("covenantBranch")
        .and_then(|v| v.as_str())
        .map(|s| s == "owner-time")
        .unwrap_or(false);
    let oracle_heartbeat = global
        .get("covenantBranch")
        .and_then(|v| v.as_str())
        .map(|s| s == "oracle-heartbeat")
        .unwrap_or(false);
    // Auto-detect: if TX has locktime > 0, the time path is available.
    // The finalize will use it for nested IF scripts when amount path would fail.
    let force_time_path = explicit_time_path || locktime > 0;

    // Check for escrow branch selector in global proprietaries
    let escrow_branch: Option<String> = global
        .get("proprietaries")
        .and_then(|v| v.as_object())
        .and_then(|p| p.get("escrowBranch"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Check for shipment-escrow branch selector in global proprietaries.
    // The ship-escrow redeem body also starts with OP_TX_INPUT_INDEX (0xb9),
    // so this explicit selector disambiguates it from a plain state machine.
    let ship_branch: Option<String> = global
        .get("proprietaries")
        .and_then(|v| v.as_object())
        .and_then(|p| p.get("shipBranch"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // ─── Walk inputs, assemble consensus inputs ───
    let inputs_json = obj
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing inputs".to_string())?;
    let mut consensus_inputs: Vec<crate::rpc::ConsensusInput> =
        Vec::with_capacity(inputs_json.len());

    for (i, inp) in inputs_json.iter().enumerate() {
        let ci = build_consensus_input(
            inp,
            force_beneficiary,
            force_time_path,
            &escrow_branch,
            &ship_branch,
            oracle_heartbeat,
        )
        .map_err(|e| format!("input[{}]: {}", i, e))?;
        consensus_inputs.push(ci);
    }

    // ─── Walk outputs ───
    let outputs_json = obj
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing outputs".to_string())?;
    let mut consensus_outputs: Vec<crate::rpc::ConsensusOutput> =
        Vec::with_capacity(outputs_json.len());

    for (i, out) in outputs_json.iter().enumerate() {
        let co = build_consensus_output(out).map_err(|e| format!("output[{}]: {}", i, e))?;
        consensus_outputs.push(co);
    }

    // Subnetwork + gas from the PSKB global (default native/0 for standard
    // sends; KSTL lane sends set them via set_tx_lane). Locktime from
    // global.fallbackLockTime (nonzero for time-locked covenants).
    let subnetwork_id = {
        let h = global
            .get("subnetworkId")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let b = hex::decode(h).unwrap_or_default();
        let mut s = [0u8; 20];
        if b.len() == 20 {
            s.copy_from_slice(&b);
        }
        s
    };
    let lane_gas = global.get("gas").and_then(|v| v.as_u64()).unwrap_or(0);
    let tx_payload: Vec<u8> = global
        .get("txPayload")
        .and_then(|v| v.as_str())
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .unwrap_or_default();

    // ─── Persistent Vault: compute genesis covenant binding ───
    let is_persistent_vault = inputs_json.iter().any(|inp| {
        inp.get("proprietaries")
            .and_then(|p| p.get("persistentVault"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    });

    // Auto-derive a genesis covenant binding ONLY when the output does not
    // already carry an explicit one. The rollup advance sets the binding itself
    // (genesis-derived on the first spend, threaded on continuation); overriding
    // it here would force every spend to look like a fresh genesis and make the
    // OP_AUTH_OUTPUT_COUNT == 1 continuation path unreachable.
    if is_persistent_vault
        && !consensus_inputs.is_empty()
        && !consensus_outputs.is_empty()
        && consensus_outputs[0].covenant.is_none()
    {
        let inp = &consensus_inputs[0];
        let cont = &consensus_outputs[0];
        let covenant_id = compute_genesis_covenant_id(
            &inp.prev_tx_id,
            inp.prev_index,
            0u32,
            cont.value,
            cont.spk_version,
            &cont.spk_script,
        );
        web_sys::console::log_1(
            &format!(
                "[KasSee] Persistent vault: genesis covenant_id = {}",
                hex::encode(covenant_id)
            )
            .into(),
        );
        consensus_outputs[0].covenant = Some((0u16, covenant_id));
    }

    web_sys::console::log_1(
        &format!(
            "[KasSee] PSKT-native broadcast: {} input(s), {} output(s), tx_version={}, locktime={}",
            consensus_inputs.len(),
            consensus_outputs.len(),
            tx_version,
            locktime,
        )
        .into(),
    );

    crate::rpc::submit_consensus_tx(
        ws_url,
        tx_version,
        &consensus_inputs,
        &consensus_outputs,
        locktime,
        &subnetwork_id,
        lane_gas, // gas (from PSKB global; 0 for native sends)
        &tx_payload,
    )
    .await
}

/// Build one consensus-layer `ConsensusInput` from a PSKT input object,
/// assembling the final `sig_script` directly from partial sigs + the
/// redeem script (for P2SH) or the single Schnorr sig (for P2PK).
#[allow(clippy::unnecessary_unwrap)]
fn build_consensus_input(
    inp: &Value,
    force_beneficiary: bool,
    force_time_path: bool,
    escrow_branch: &Option<String>,
    ship_branch: &Option<String>,
    oracle_heartbeat: bool,
) -> Result<crate::rpc::ConsensusInput, String> {
    let obj = inp.as_object().ok_or_else(|| "not object".to_string())?;

    // utxoEntry → scriptPublicKey (used for classification)
    let utxo = obj
        .get("utxoEntry")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let spk_full = utxo
        .get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (_spk_version, spk_script) = parse_spk_hex(spk_full)?;

    // Outpoint
    let op = obj
        .get("previousOutpoint")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let prev_tx_id_hex = op
        .get("transactionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing transactionId".to_string())?;
    let prev_tx_vec = hex::decode(prev_tx_id_hex).map_err(|e| format!("bad tx_id hex: {}", e))?;
    if prev_tx_vec.len() != 32 {
        return Err("tx_id not 32 bytes".into());
    }
    let mut prev_tx_id = [0u8; 32];
    prev_tx_id.copy_from_slice(&prev_tx_vec);
    let prev_index = op
        .get("index")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing index".to_string())? as u32;

    let sequence = obj.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0);
    let sig_op_count = obj.get("sigOpCount").and_then(|v| v.as_u64()).unwrap_or(1) as u8;

    // redeemScript
    let redeem: Option<Vec<u8>> = match obj.get("redeemScript") {
        Some(v) if v.is_null() => None,
        Some(Value::String(s)) => Some(hex::decode(s).map_err(|e| format!("redeem hex: {}", e))?),
        _ => None,
    };

    // partialSigs map
    let partial_map = obj
        .get("partialSigs")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    // Branch on script kind
    let is_p2sh = spk_script.len() == 35
        && spk_script[0] == 0xAA
        && spk_script[1] == 0x20
        && spk_script[34] == 0x87;

    let sig_script = if is_p2sh && redeem.is_some() {
        let rs = redeem.as_ref().unwrap();
        // Detect optional salt prefix: 0x08 <8 bytes> 0x75(OP_DROP) before the
        // covenant body. The body may begin with OP_IF (0x63, IF/ELSE covenants),
        // OP_TX_INPUT_INDEX (0xb9, amount-dispatch state machines), or
        // OP_DATA_32 (0x20, single-sig covenants like spending-limit/allowance).
        let (rs_body, salt_offset) = if rs.len() > 10
            && rs[0] == 0x08
            && rs[9] == 0x75
            && (rs.get(10) == Some(&0x63) || rs.get(10) == Some(&0xb9) || rs.get(10) == Some(&0x20))
        {
            (&rs[10..], 10usize)
        } else {
            (&rs[..], 0usize)
        };
        web_sys::console::log_1(&format!(
            "[KasSee] build_consensus_input: is_p2sh=true, redeem_len={}, first_byte=0x{:02x}, salt_offset={}, partial_keys={}",
            rs.len(), rs_body.first().copied().unwrap_or(0), salt_offset, partial_map.len()
        ).into());
        // Keyless Oracle (Model B) covenants are routed by explicit proprietary
        // flag, NOT by redeem shape. The ROLL / heartbeat / passthrough / consumer
        // redeems lead with price+daa data pushes (0x08 <price> 0x08 <daa> OP_IF...),
        // so the OP_IF first-byte heuristic below misses them and the M-of-N
        // multisig fallthrough rejects the redeem ("not a valid M-of-N multisig").
        // These spends carry no signature, so build the keyless witness here.
        let omb_publish = obj
            .get("proprietaries")
            .and_then(|v| v.as_object())
            .and_then(|p| p.get("risc0OracleMb"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let omb_heartbeat = obj
            .get("proprietaries")
            .and_then(|v| v.as_object())
            .and_then(|p| p.get("oracleMbHeartbeat"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let omb_passthrough = obj
            .get("proprietaries")
            .and_then(|v| v.as_object())
            .and_then(|p| p.get("oracleMbPassthrough"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let omb_consumer = obj
            .get("proprietaries")
            .and_then(|v| v.as_object())
            .and_then(|p| p.get("oracleMbConsumer"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if omb_publish {
            let seal = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("risc0Seal"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok())
                .ok_or_else(|| "oracle MB publish missing risc0Seal".to_string())?;
            let fields = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("risc0Fields"))
                .and_then(|v| v.as_object())
                .cloned()
                .ok_or_else(|| "oracle MB publish missing risc0Fields".to_string())?;
            web_sys::console::log_1(
                &format!(
                    "[KasSee] ORACLE_MB_PUBLISH (early route): keyless ROLL, seal_len={}",
                    seal.len()
                )
                .into(),
            );
            build_p2sh_oracle_mb_publish_sig_script(rs, &seal, &fields)?
        } else if omb_heartbeat {
            web_sys::console::log_1(
                &"[KasSee] ORACLE_MB_HEARTBEAT (early route): keyless redeem-only".into(),
            );
            build_p2sh_oracle_mb_heartbeat_sig_script(rs)?
        } else if omb_passthrough {
            web_sys::console::log_1(
                &"[KasSee] ORACLE_MB_PASSTHROUGH (early route): keyless OP_0 + redeem".into(),
            );
            build_p2sh_oracle_mb_passthrough_sig_script(rs)?
        } else if omb_consumer {
            web_sys::console::log_1(
                &"[KasSee] ORACLE_MB_CONSUMER (early route): keyless redeem-only".into(),
            );
            build_p2sh_oracle_mb_consumer_sig_script(rs)?
        } else if rs_body.first() == Some(&0x63) {
            // Covenant script (starts with OP_IF, possibly after salt+DROP).
            // Determine branch by matching the signing pubkey against
            // the IF-branch pubkey (owner) vs ELSE-branch pubkey (beneficiary).
            let owner_pk_hex = if rs_body.len() >= 34 && rs_body[1] == 0x20 {
                Some(hex::encode(&rs_body[2..34]))
            } else {
                None
            };

            // Find ELSE-branch pubkey(s): scan for pubkey pushes after OP_ELSE.
            // Patterns: OP_ELSE(0x67) + OP_DATA_32(0x20) (simple vault/escrow)
            //           OP_ELSE(0x67) + OP_IF(0x63) + OP_DATA_32(0x20) (nested escrow inner IF)
            let bene_pk_hex = {
                let mut found = None;
                for off in 34..rs_body.len().saturating_sub(33) {
                    if rs_body[off] == 0x67 {
                        // Check OP_ELSE + OP_DATA_32
                        if off + 34 <= rs_body.len() && rs_body[off + 1] == 0x20 {
                            found = Some(hex::encode(&rs_body[off + 2..off + 34]));
                            break;
                        }
                        // Check OP_ELSE + OP_IF + OP_DATA_32 (nested)
                        if off + 35 <= rs_body.len()
                            && rs_body[off + 1] == 0x63
                            && rs_body[off + 2] == 0x20
                        {
                            found = Some(hex::encode(&rs_body[off + 3..off + 35]));
                            break;
                        }
                    }
                }
                found
            };

            // Check which branch the signer's pubkey belongs to
            // For atomic swap: IF = counterparty (claim), ELSE = owner (refund)
            // Detect atomic swap: OP_IF PUSH_32 <pk:32> CHECKSIGVERIFY OP_BLAKE2B (0x63 0x20 <32> 0xad 0xaa)
            let is_atomic_swap = rs.len() >= 37
                && rs[0] == 0x63
                && rs[1] == 0x20
                && rs[34] == 0xad
                && rs[35] == 0xaa;

            let signer_is_owner = if is_atomic_swap {
                // In atomic swap, "owner" is in ELSE, not IF
                // Check if signer matches the ELSE branch pubkey
                if let Some(ref bpk) = bene_pk_hex {
                    partial_map
                        .keys()
                        .any(|k| k.len() == 66 && k[2..] == bpk[..])
                } else {
                    false
                }
            } else if force_beneficiary {
                false
            } else if let Some(ref opk) = owner_pk_hex {
                // partialSigs key is "02" + xonly (33-byte compressed hex)
                partial_map
                    .keys()
                    .any(|k| k.len() == 66 && k[2..] == opk[..])
            } else {
                false
            };

            let signer_is_beneficiary = if force_beneficiary {
                !partial_map.is_empty()
            } else if let Some(ref bpk) = bene_pk_hex {
                partial_map
                    .keys()
                    .any(|k| k.len() == 66 && k[2..] == bpk[..])
            } else {
                false
            };

            // Check minimumSignatures — if 0, this is a no-sig borrower path
            let min_sigs = obj
                .get("minimumSignatures")
                .and_then(|v| v.as_u64())
                .unwrap_or(1);

            web_sys::console::log_1(&format!(
                "[KasSee] finalize covenant input: min_sigs={}, signer_is_owner={}, signer_is_bene={}, partial_keys={}",
                min_sigs, signer_is_owner, signer_is_beneficiary, partial_map.len()
            ).into());

            // Check for atomic swap claim preimage in proprietaries
            let atomic_preimage: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("atomicPreimage"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());

            // Check for oracle claim data in proprietaries
            let oracle_sig: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("oracleSig"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());
            let oracle_msg_hash: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("oracleMsgHash"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());

            // Check for ZK proof data in proprietaries
            let zk_proof: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("zkProof"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());
            let zk_public_inputs: Option<Vec<Vec<u8>>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("zkPublicInputs"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .filter_map(|h| hex::decode(h).ok())
                        .collect()
                });
            let zk_vk: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("zkVk"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());

            // Check for commit-reveal split preimage parts in proprietaries
            let commit_part_a: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("commitPartA"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());
            let commit_part_b: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("commitPartB"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());
            // Legacy single preimage fallback
            let commit_preimage: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("commitPreimage"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());

            // Check for merkle whitelist proof in proprietaries
            let merkle_proof: Option<String> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("merkleProof"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let merkle_dest_spk: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("merkleDestSpk"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());

            // Check for RISC0 proof data in proprietaries
            let risc0_seal: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("risc0Seal"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());
            let risc0_fields: Option<serde_json::Map<String, Value>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("risc0Fields"))
                .and_then(|v| v.as_object())
                .cloned();
            let risc0_bridge: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("risc0Bridge"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let groth16_bridge: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("groth16Bridge"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            // Oracle (Model B) keyless spend selectors.
            let risc0_oracle_mb: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("risc0OracleMb"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let oracle_mb_passthrough: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("oracleMbPassthrough"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let oracle_mb_heartbeat: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("oracleMbHeartbeat"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let oracle_mb_consumer: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("oracleMbConsumer"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Check for KIP-21 bridge withdrawal SPK in proprietaries
            let bridge_withdrawal_spk: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("withdrawalSpk"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());

            // Phase 3 rollup-state covenant: explicit branch selectors. The
            // redeem reuses owner_pk in both IF (refund) and ELSE (advance), and
            // its body is data-heavy (32B root literal + VK), so the pubkey-scan
            // / atomic-swap heuristics below cannot route it. These flags do.
            // Dedicated keys (rollupProof/Prefix/Suffix) keep the advance off the
            // generic zkProof/zkPublicInputs/zkVk path, whose template pushes the
            // VK + inputs into the sig_script — here the VK is committed in the
            // redeem and the inputs are assembled on-stack.
            let rollup_state_advance: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("rollupStateAdvance"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let rollup_state_refund: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("rollupStateRefund"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let rollup_proof: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("rollupProof"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());
            let rollup_prefix: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("rollupPrefix"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());
            let rollup_suffix: Option<Vec<u8>> = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("rollupSuffix"))
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok());

            // Phase 4a deposit routing. The vault advance reuses the transfer
            // advance witness (rollupProof/Prefix/Suffix). The deposit-holding
            // credit is no-sig and supplies the vault template halves (reusing
            // rollupPrefix/rollupSuffix on that input). The deposit-holding
            // refund reuses the owner-refund (IF/CLTV) layout with the
            // depositor's key.
            let rollup_deposit_advance: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("rollupDepositAdvance"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            // Phase 4b unified op-typed advance (transfer | deposit | withdraw).
            // The vault input's witness is byte-identical to the transfer/deposit
            // advance (<proof><prefix><suffix><owner_sig> OP_FALSE <redeem>); the
            // op_type lives in the tx payload and the per-op I/O shape (transfer
            // 2-in/1-out, deposit 2-in/1-out, withdraw 2-in/2-out + L1 payout) is
            // built when the PSKB is assembled, not here. Distinct flag for logging.
            let rollup_unified_advance: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("rollupUnifiedAdvance"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let rollup_forced_exit: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("rollupForcedExit"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let deposit_holding_credit: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("depositHoldingCredit"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let deposit_holding_refund: bool = obj
                .get("proprietaries")
                .and_then(|v| v.as_object())
                .and_then(|p| p.get("depositHoldingRefund"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if deposit_holding_credit {
                // Phase 4a deposit-holding credit (no-sig ELSE). Checked before
                // the generic min_sigs==0 path: this no-sig input needs the
                // specific <vault_prefix> <vault_suffix> OP_FALSE <redeem>
                // witness, not the generic borrower script.
                let prefix = rollup_prefix
                    .as_ref()
                    .ok_or_else(|| "deposit-holding credit missing rollupPrefix".to_string())?;
                let suffix = rollup_suffix
                    .as_ref()
                    .ok_or_else(|| "deposit-holding credit missing rollupSuffix".to_string())?;
                web_sys::console::log_1(
                    &format!(
                        "[KasSee] DEPOSIT_HOLDING_CREDIT: prefix_len={}, suffix_len={}",
                        prefix.len(),
                        suffix.len()
                    )
                    .into(),
                );
                build_p2sh_deposit_holding_credit_sig_script(rs, prefix, suffix)?
            } else if min_sigs == 0 {
                // No-sig borrower path (additive, spending-limit, allowance)
                build_p2sh_covenant_nosig_script(rs)?
            } else if let Some(ref branch) = escrow_branch {
                // 2-of-3 escrow explicit branch routing
                build_p2sh_escrow_sig_script(rs, &partial_map, branch)?
            } else if rollup_state_advance {
                // Phase 3 rollup advance (ELSE):
                //   <proof> <prefix> <suffix> <owner_sig> OP_FALSE <redeem>
                let proof = rollup_proof
                    .as_ref()
                    .ok_or_else(|| "rollup advance missing rollupProof".to_string())?;
                let prefix = rollup_prefix
                    .as_ref()
                    .ok_or_else(|| "rollup advance missing rollupPrefix".to_string())?;
                let suffix = rollup_suffix
                    .as_ref()
                    .ok_or_else(|| "rollup advance missing rollupSuffix".to_string())?;
                web_sys::console::log_1(
                    &format!(
                        "[KasSee] ROLLUP_STATE_ADVANCE: proof_len={}, prefix_len={}, suffix_len={}",
                        proof.len(),
                        prefix.len(),
                        suffix.len()
                    )
                    .into(),
                );
                build_p2sh_rollup_advance_sig_script(rs, &partial_map, proof, prefix, suffix)?
            } else if rollup_deposit_advance {
                // Phase 4a deposit advance (vault, ELSE) — identical witness to
                // the transfer advance: <proof> <prefix> <suffix> <owner_sig> OP_FALSE <redeem>
                let proof = rollup_proof
                    .as_ref()
                    .ok_or_else(|| "deposit advance missing rollupProof".to_string())?;
                let prefix = rollup_prefix
                    .as_ref()
                    .ok_or_else(|| "deposit advance missing rollupPrefix".to_string())?;
                let suffix = rollup_suffix
                    .as_ref()
                    .ok_or_else(|| "deposit advance missing rollupSuffix".to_string())?;
                web_sys::console::log_1(
                    &format!(
                    "[KasSee] ROLLUP_DEPOSIT_ADVANCE: proof_len={}, prefix_len={}, suffix_len={}",
                    proof.len(), prefix.len(), suffix.len()
                )
                    .into(),
                );
                build_p2sh_rollup_advance_sig_script(rs, &partial_map, proof, prefix, suffix)?
            } else if rollup_unified_advance {
                // Phase 4b unified advance (vault, inner IF) — nested redeem, two
                // selectors; op_type is read from the payload and the script
                // self-branches on it:
                //   <proof> <prefix> <suffix> <owner_sig> OP_1 OP_0 <redeem>
                let proof = rollup_proof
                    .as_ref()
                    .ok_or_else(|| "unified advance missing rollupProof".to_string())?;
                let prefix = rollup_prefix
                    .as_ref()
                    .ok_or_else(|| "unified advance missing rollupPrefix".to_string())?;
                let suffix = rollup_suffix
                    .as_ref()
                    .ok_or_else(|| "unified advance missing rollupSuffix".to_string())?;
                web_sys::console::log_1(
                    &format!(
                    "[KasSee] ROLLUP_UNIFIED_ADVANCE: proof_len={}, prefix_len={}, suffix_len={}",
                    proof.len(), prefix.len(), suffix.len()
                )
                    .into(),
                );
                build_p2sh_rollup_unified_advance_sig_script(
                    rs,
                    &partial_map,
                    proof,
                    prefix,
                    suffix,
                )?
            } else if rollup_forced_exit {
                // Phase 4 forced exit (vault, inner ELSE) — NO operator sig. The
                // committed account owner signs; both selectors FALSE select the
                // forced-exit branch (which the redeem gates on a CSV timeout):
                //   <proof> <prefix> <suffix> <exiter_sig> OP_0 OP_0 <redeem>
                let proof = rollup_proof
                    .as_ref()
                    .ok_or_else(|| "forced exit missing rollupProof".to_string())?;
                let prefix = rollup_prefix
                    .as_ref()
                    .ok_or_else(|| "forced exit missing rollupPrefix".to_string())?;
                let suffix = rollup_suffix
                    .as_ref()
                    .ok_or_else(|| "forced exit missing rollupSuffix".to_string())?;
                web_sys::console::log_1(
                    &format!(
                        "[KasSee] ROLLUP_FORCED_EXIT: proof_len={}, prefix_len={}, suffix_len={}",
                        proof.len(),
                        prefix.len(),
                        suffix.len()
                    )
                    .into(),
                );
                build_p2sh_rollup_forced_exit_sig_script(rs, &partial_map, proof, prefix, suffix)?
            } else if rollup_state_refund {
                // Phase 3 owner refund (IF) after CLTV:
                //   <owner_sig> OP_1 <redeem>
                web_sys::console::log_1(
                    &"[KasSee] ROLLUP_STATE_REFUND: owner refund (IF/CLTV)".into(),
                );
                build_p2sh_rollup_refund_sig_script(rs, &partial_map)?
            } else if deposit_holding_refund {
                // Phase 4a depositor refund (IF) after CLTV — same layout as the
                // rollup refund, signed with the depositor's key:
                //   <depositor_sig> OP_1 <redeem>
                web_sys::console::log_1(
                    &"[KasSee] DEPOSIT_HOLDING_REFUND: depositor refund (IF/CLTV)".into(),
                );
                build_p2sh_rollup_refund_sig_script(rs, &partial_map)?
            } else if groth16_bridge {
                // Groth16-wrap bridge withdrawal: vk, public inputs, proof and
                // tag are all committed in the redeem, so the sig_script supplies
                // only the owner signature + ELSE selector:
                //   <owner_sig> OP_FALSE <redeem>
                web_sys::console::log_1(
                    &"[KasSee] GROTH16_BRIDGE_CLAIM: building owner-sig sig_script"
                        .to_string()
                        .into(),
                );
                build_p2sh_groth16_bridge_claim_sig_script(rs, &partial_map)?
            } else if oracle_heartbeat {
                // Oracle heartbeat beacon: <sig> OP_FALSE OP_FALSE <redeem>
                web_sys::console::log_1(
                    &"[KasSee] ORACLE_HEARTBEAT: building heartbeat sig_script"
                        .to_string()
                        .into(),
                );
                build_p2sh_oracle_heartbeat_sig_script(rs, &partial_map)?
            } else if oracle_mb_heartbeat {
                // Oracle (Model B) heartbeat roll: keyless self-recreate. The
                // sig_script is JUST the revealed redeem (no selector, no sig).
                web_sys::console::log_1(
                    &"[KasSee] ORACLE_MB_HEARTBEAT_ROLL: keyless redeem-only sig_script"
                        .to_string()
                        .into(),
                );
                build_p2sh_oracle_mb_heartbeat_sig_script(rs)?
            } else if oracle_mb_passthrough {
                // Oracle (Model B) passthrough read: keyless. OP_0 selects the
                // ELSE (PASSTHROUGH) branch; the oracle is recreated unchanged.
                web_sys::console::log_1(
                    &"[KasSee] ORACLE_MB_PASSTHROUGH: keyless OP_0 + redeem sig_script"
                        .to_string()
                        .into(),
                );
                build_p2sh_oracle_mb_passthrough_sig_script(rs)?
            } else if oracle_mb_consumer {
                // Oracle (Model B) test-consumer read-gated release: keyless.
                // sig_script is JUST the revealed redeem; the embedded read runs.
                web_sys::console::log_1(
                    &"[KasSee] ORACLE_MB_CONSUMER: keyless redeem-only sig_script"
                        .to_string()
                        .into(),
                );
                build_p2sh_oracle_mb_consumer_sig_script(rs)?
            } else if let (Some(ref o_sig), Some(ref o_hash)) = (&oracle_sig, &oracle_msg_hash) {
                // Oracle claim: <oracle_sig> <msg_hash> <bene_sig> OP_TRUE OP_FALSE <redeem>
                web_sys::console::log_1(
                    &format!(
                        "[KasSee] ORACLE_CLAIM: oracle_sig_len={}, msg_hash_len={}",
                        o_sig.len(),
                        o_hash.len()
                    )
                    .into(),
                );
                build_p2sh_oracle_claim_sig_script(rs, &partial_map, o_sig, o_hash)?
            } else if let (Some(ref proof), Some(ref inputs), Some(ref vk), Some(ref w_spk)) =
                (&zk_proof, &zk_public_inputs, &zk_vk, &bridge_withdrawal_spk)
            {
                // KIP-21 Bridge withdrawal:
                // <withdrawal_spk> <inputs> <n_inputs> <proof> <vk> <sig> OP_FALSE <redeem>
                web_sys::console::log_1(&format!(
                    "[KasSee] BRIDGE_WITHDRAWAL: proof_len={}, n_inputs={}, vk_len={}, w_spk_len={}",
                    proof.len(), inputs.len(), vk.len(), w_spk.len()
                ).into());
                build_p2sh_bridge_claim_sig_script(rs, &partial_map, proof, inputs, vk, w_spk)?
            } else if let (Some(ref proof), Some(ref inputs), Some(ref vk)) =
                (&zk_proof, &zk_public_inputs, &zk_vk)
            {
                // ZK proof claim: <inputs> <n_inputs> <proof> <vk> <sig> OP_FALSE <redeem>
                web_sys::console::log_1(
                    &format!(
                        "[KasSee] ZK_CLAIM: proof_len={}, n_inputs={}, vk_len={}",
                        proof.len(),
                        inputs.len(),
                        vk.len()
                    )
                    .into(),
                );
                build_p2sh_zk_claim_sig_script(rs, &partial_map, proof, inputs, vk)?
            } else if let (Some(ref seal), Some(ref fields)) = (&risc0_seal, &risc0_fields) {
                if risc0_bridge {
                    // RISC0 bridge withdrawal: journal/image_id/control_id/hashfn
                    // are committed in the redeem; sig_script supplies only the
                    // bottom four (claim, control_index, control_digests, seal).
                    web_sys::console::log_1(
                        &format!("[KasSee] RISC0_BRIDGE_CLAIM: seal_len={}", seal.len()).into(),
                    );
                    build_p2sh_risc0_bridge_claim_sig_script(rs, &partial_map, seal, fields)?
                } else if risc0_oracle_mb {
                    // Oracle (Model B) publish: keyless ROLL. image_id/control_id/
                    // set_root/hashfn are committed in the redeem; the sig_script
                    // supplies claim, control_index, control_digests, seal, the
                    // 48-byte journal, then OP_1 to select the ROLL (IF) branch.
                    web_sys::console::log_1(
                        &format!("[KasSee] RISC0_ORACLE_MB_PUBLISH: seal_len={}", seal.len())
                            .into(),
                    );
                    build_p2sh_oracle_mb_publish_sig_script(rs, seal, fields)?
                } else {
                    // RISC0 succinct proof claim
                    web_sys::console::log_1(
                        &format!("[KasSee] RISC0_CLAIM: seal_len={}", seal.len()).into(),
                    );
                    build_p2sh_risc0_claim_sig_script(rs, &partial_map, seal, fields)?
                }
            } else if let Some(ref preimage) = atomic_preimage {
                // Atomic swap claim: <sig> <preimage> OP_FALSE <redeem>
                web_sys::console::log_1(
                    &format!("[KasSee] ATOMIC_CLAIM: preimage_len={}", preimage.len()).into(),
                );
                build_p2sh_atomic_claim_sig_script(rs, &partial_map, preimage)?
            } else if let (Some(ref pa), Some(ref pb)) = (&commit_part_a, &commit_part_b) {
                // Commit-reveal split: <part_A> <part_B> <sig> OP_FALSE <redeem>
                // Script: CHECKSIGVERIFY CAT BLAKE2B <hash> EQUALVERIFY
                // Stack after CHECKSIGVERIFY: [part_A, part_B] -> CAT -> part_A||part_B
                web_sys::console::log_1(
                    &format!(
                        "[KasSee] COMMIT_REVEAL_SPLIT: part_a={} part_b={}",
                        pa.len(),
                        pb.len()
                    )
                    .into(),
                );
                build_p2sh_commit_reveal_split_sig_script(rs, &partial_map, pa, pb)?
            } else if let Some(ref preimage) = commit_preimage {
                // Legacy commit-reveal: <preimage> <sig> OP_FALSE <redeem>
                web_sys::console::log_1(
                    &format!("[KasSee] COMMIT_REVEAL: preimage_len={}", preimage.len()).into(),
                );
                build_p2sh_atomic_claim_sig_script(rs, &partial_map, preimage)?
            } else if let (Some(ref proof_str), Some(ref dest_spk)) =
                (&merkle_proof, &merkle_dest_spk)
            {
                // Merkle whitelist spend
                web_sys::console::log_1(
                    &format!("[KasSee] MERKLE_WHITELIST: dest_spk_len={}", dest_spk.len()).into(),
                );
                build_p2sh_merkle_claim_sig_script(rs, &partial_map, proof_str, dest_spk)?
            } else if signer_is_owner || (!signer_is_beneficiary && !partial_map.is_empty()) {
                // Owner spend — <sig> OP_TRUE <redeem>
                build_p2sh_covenant_sig_script(rs, &partial_map, force_time_path)?
            } else if signer_is_beneficiary {
                // Beneficiary/borrower spend — <sig> OP_FALSE <redeem>
                build_p2sh_covenant_borrower_sig_script(rs, &partial_map)?
            } else {
                // No sigs at all (legacy borrower path for additive/spending-limit)
                build_p2sh_covenant_nosig_script(rs)?
            }
        } else if rs.first() == Some(&0x20) && rs.len() >= 35 && rs[33] == 0xad {
            // Treasury script: PUSH_32 <pubkey> CHECKSIGVERIFY ...
            // Sig_script: <sig> <redeem>
            // The sig is in partialSigs, keyed by the owner pubkey
            if partial_map.is_empty() {
                return Err("Treasury input requires a signature".into());
            }
            build_p2sh_treasury_sig_script(rs, &partial_map)?
        } else if rs_body.first() == Some(&0xb9) {
            // Body starts with OP_TX_INPUT_INDEX (0xb9), possibly after a
            // salt+DROP prefix. Two covenant families share this prefix:
            //   - shipment-escrow: needs an explicit branch selector, and its
            //     timeout branches are sigless (CLTV enforced on locktime).
            //   - plain state machine: dispatches internally on input_amount,
            //     single sig, no selector.
            // The builder is passed the FULL redeem (rs, including any salt) so
            // the pushed redeem still hashes to the P2SH address.
            if let Some(ref branch) = ship_branch {
                web_sys::console::log_1(
                    &format!("[KasSee] finalize: ship-escrow branch '{}'", branch).into(),
                );
                build_p2sh_ship_escrow_sig_script(rs, &partial_map, branch)?
            } else {
                // Sig_script: <sig||sighash> <redeem>
                if partial_map.is_empty() {
                    return Err("State machine input requires a signature".into());
                }
                web_sys::console::log_1(&"[KasSee] finalize: state machine covenant (0xb9)".into());
                build_p2sh_state_machine_sig_script(rs, &partial_map)?
            }
        } else if rs_body.first() == Some(&0x20) && rs_body.len() > 34 && rs_body[33] == 0xad {
            // Single-path covenant: body is OP_DATA_32 <pk:32> OP_CHECKSIGVERIFY (0xad),
            // optionally behind a salt+DROP prefix. No branch selector.
            // Detect on rs_body (salt-stripped); push the full rs so the revealed
            // redeem still hashes to the P2SH address. Sig_script: <sig||sighash> <redeem>
            if partial_map.is_empty() {
                return Err("Single-path covenant input requires a signature".into());
            }
            web_sys::console::log_1(&"[KasSee] finalize: single-path covenant (0x20..0xad)".into());
            build_p2sh_single_path_sig_script(rs, &partial_map)?
        } else if rs.first() == Some(&0x00) {
            // Approach-1 KCC20 token conservation covenant: flat no-sig redeem that
            // starts with OP_0. sig_script is just push(redeem) — no OP_FALSE branch
            // selector (the body has no top-level IF/ELSE), matching the engine-validated
            // anyone-can-conserve spend (empty signature + push(redeem)).
            web_sys::console::log_1(
                &"[KasSee] finalize: KCC20 token conservation (no-sig P2SH)".into(),
            );
            build_p2sh_token_conservation_sig_script(rs)?
        } else {
            build_p2sh_multisig_sig_script(rs, &partial_map)?
        }
    } else if !is_p2sh {
        build_p2pk_sig_script(&partial_map)?
    } else {
        return Err("P2SH input without redeem script cannot be finalized".into());
    };

    Ok(crate::rpc::ConsensusInput {
        prev_tx_id,
        prev_index,
        sig_script,
        sequence,
        sig_op_count,
    })
}

fn build_consensus_output(out: &Value) -> Result<crate::rpc::ConsensusOutput, String> {
    let obj = out.as_object().ok_or_else(|| "not object".to_string())?;
    let value = obj
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = obj
        .get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (spk_version, spk_script) = parse_spk_hex(spk_full)?;

    // KIP-20 covenant binding (optional)
    let covenant = match obj.get("covenantBinding") {
        Some(cb) if !cb.is_null() => {
            let cb_obj = cb
                .as_object()
                .ok_or_else(|| "covenantBinding not object".to_string())?;
            let auth_input = cb_obj
                .get("authorizingInput")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "missing authorizingInput".to_string())?
                as u16;
            let cov_id_hex = cb_obj
                .get("covenantId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing covenantId".to_string())?;
            let cov_id_bytes =
                hex::decode(cov_id_hex).map_err(|e| format!("bad covenantId hex: {}", e))?;
            if cov_id_bytes.len() != 32 {
                return Err("covenantId must be 32 bytes".into());
            }
            let mut cov_id = [0u8; 32];
            cov_id.copy_from_slice(&cov_id_bytes);
            Some((auth_input, cov_id))
        }
        _ => None,
    };

    Ok(crate::rpc::ConsensusOutput {
        value,
        spk_version,
        spk_script,
        covenant,
    })
}

/// Compute a genesis covenant_id matching rusty-kaspa's `hashing::covenant_id::covenant_id`.
///
/// Blake2b-256 keyed with b"CovenantID":
///   - transaction_id (32 bytes)
///   - outpoint.index (u32 LE)
///   - auth_outputs.len() (u64 LE) — always 1 for persistent vault
///   - output_index (u32 LE)
///   - output.value (u64 LE)
///   - spk.version (u16 LE)
///   - spk.script.len() (u64 LE) + spk.script (raw bytes)
fn compute_genesis_covenant_id(
    prev_tx_id: &[u8; 32],
    prev_index: u32,
    output_index: u32,
    output_value: u64,
    spk_version: u16,
    spk_script: &[u8],
) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"CovenantID")
        .to_state()
        .update(prev_tx_id)
        .update(&prev_index.to_le_bytes())
        .update(&1u64.to_le_bytes())
        .update(&output_index.to_le_bytes())
        .update(&output_value.to_le_bytes())
        .update(&spk_version.to_le_bytes())
        .update(&(spk_script.len() as u64).to_le_bytes())
        .update(spk_script)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Assemble the final sig_script for a P2SH multisig input.
///
/// Consensus layout: `OP_0 <push sig1> <push sig2> … <push redeemScript>`
///
/// Each signature push carries (64-byte Schnorr sig || 1-byte SIGHASH_ALL).
/// Signatures are ordered by each signer's pubkey position in the
/// redeem script (ascending), and the first M are used. Final push is
/// the redeem script itself (OP_PUSHDATA1 prefix when >75 bytes).
///
/// This is the standard Kaspa CHECKMULTISIG unlocking pattern. The
/// dummy `OP_0` at the start is the Bitcoin-inherited off-by-one.
/// Build sig_script for a single-path covenant (no IF/ELSE).
/// Format: <sig||sighash> <redeem_script>
fn build_p2sh_single_path_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    // Extract the first (and only) signature from partialSigs
    let (_, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "no partial signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut script = Vec::with_capacity(1 + sig_bytes.len() + 3 + redeem.len());
    // Push signature
    script.push(sig_bytes.len() as u8);
    script.extend_from_slice(&sig_bytes);
    // Push redeem script
    push_redeem_script(&mut script, redeem)?;
    Ok(script)
}

fn build_p2sh_multisig_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (m, _n) = parse_multisig_redeem(redeem)
        .ok_or_else(|| "redeem not a valid M-of-N multisig".to_string())?;

    // (pubkey_pos, sig||sighash) per available partial sig
    let mut sigs: Vec<(u8, Vec<u8>)> = Vec::with_capacity(partial_map.len());
    for (pk_hex, sig_val) in partial_map.iter() {
        if pk_hex.len() != 66 {
            continue;
        }
        let sig_hex = sig_val
            .get("schnorr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
        if sig_hex.len() != 128 {
            return Err(format!("bad sig length: {}", sig_hex.len()));
        }
        let pos = find_pubkey_position_in_redeem(redeem, pk_hex)
            .ok_or_else(|| format!("pubkey not in redeem: {}", pk_hex))?;
        let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
        sig_bytes.push(0x01); // SIGHASH_ALL
        sigs.push((pos, sig_bytes));
    }
    sigs.sort_by_key(|t| t.0);

    if sigs.len() < m as usize {
        return Err(format!("only {} sig(s), need {}", sigs.len(), m));
    }

    let mut sig_script: Vec<u8> = Vec::with_capacity((m as usize) * 66 + redeem.len() + 2);

    // NOTE: unlike Bitcoin's OP_CHECKMULTISIG, Kaspa's OpCheckMultiSig
    // does NOT pop an extra dummy element. No leading OP_0. Verified
    // against crypto/txscript test vector at lib.rs:1000.

    // Push first M sigs in redeem-script pubkey order.
    for (_pos, sig) in sigs.iter().take(m as usize) {
        sig_script.push(sig.len() as u8); // 65
        sig_script.extend_from_slice(sig);
    }

    // Push redeem script (supports >255 bytes via OP_PUSHDATA2)
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

/// Assemble the final sig_script for a covenant P2SH input (owner spend).
/// Layout: `<push sig||sighash> OP_TRUE <push redeem_script>`
/// The OP_TRUE (0x51) selects the OP_IF branch where the owner's
/// signature is checked via OP_CHECKSIG.
fn build_p2sh_covenant_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    force_time_path: bool,
) -> Result<Vec<u8>, String> {
    // Get the single signature (owner or counterparty)
    let (pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Covenant input has no signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    // Salt-aware body view. A piggy/deposit redeem may carry an 8-byte salt
    // prefix (0x08 <salt> OP_DROP) before the covenant body, which shifts every
    // structural opcode by +10. All offset-based detection below runs against
    // `body`; the redeem PUSHED at the end stays the full script so its blake2b
    // still matches the committed P2SH. (Mirrors build_consensus_input.)
    let body: &[u8] = if redeem.len() > 10
        && redeem[0] == 0x08
        && redeem[9] == 0x75
        && (redeem.get(10) == Some(&0x63)
            || redeem.get(10) == Some(&0xb9)
            || redeem.get(10) == Some(&0x20))
    {
        &redeem[10..]
    } else {
        redeem
    };

    // Determine which branch the signer belongs to.
    // Covenant scripts: OP_IF <push32 alice_pk> ... OP_ELSE <push32 bob_pk> ...
    // Alice's pubkey is at body[2..34] (after OP_IF 0x63, OP_DATA_32 0x20).
    // If the signer's x-only pubkey matches Alice → OP_TRUE (OP_IF branch).
    // Otherwise → OP_FALSE (OP_ELSE branch, e.g. Bob in escrow).
    let use_if_branch = if body.len() >= 34 && body[0] == 0x63 && body[1] == 0x20 {
        // Extract signer's x-only pubkey (strip 02/03 prefix if 33 bytes)
        let signer_xonly: Vec<u8> = if pk_hex.len() == 66 {
            hex::decode(&pk_hex[2..]).unwrap_or_default()
        } else {
            hex::decode(pk_hex).unwrap_or_default()
        };
        let alice_pk = &body[2..34];
        signer_xonly == alice_pk
    } else {
        true // default to OP_IF for non-standard covenant layouts
    };

    let mut sig_script: Vec<u8> = Vec::with_capacity(sig_bytes.len() + redeem.len() + 10);

    // Check for nested IF after CHECKSIGVERIFY (Piggy Bank with conditions).
    // Script: OP_IF <pk> CHECKSIGVERIFY OP_IF ... OP_ELSE ... OP_ENDIF
    // After P2SH pops redeem, stack must be: [inner_selector, sig, outer_selector]
    // Outer IF pops outer_selector. CHECKSIGVERIFY pops sig + pubkey(from script).
    // Inner IF pops inner_selector.
    let has_nested_if = body.len() > 35
        && body[34] == 0xad  // OP_CHECKSIGVERIFY
        && body.get(35) == Some(&0x63); // OP_IF (inner)

    // Push branch selector and signature
    if use_if_branch {
        if has_nested_if {
            // Inner selector: TRUE = amount path, FALSE = time path
            if force_time_path {
                sig_script.push(0x00); // inner selector FALSE = time path (ELSE)
            } else {
                sig_script.push(0x51); // inner selector TRUE = amount path (IF)
            }
            sig_script.push(sig_bytes.len() as u8);
            sig_script.extend_from_slice(&sig_bytes);
            sig_script.push(0x51); // outer selector (TRUE = owner IF)
        } else {
            sig_script.push(sig_bytes.len() as u8);
            sig_script.extend_from_slice(&sig_bytes);
            sig_script.push(0x51); // OP_TRUE → OP_IF branch
        }
    } else {
        sig_script.push(sig_bytes.len() as u8);
        sig_script.extend_from_slice(&sig_bytes);
        sig_script.push(0x00); // OP_FALSE → OP_ELSE branch
    }

    // Push redeem script (supports >255 bytes via OP_PUSHDATA2)
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

/// Assemble the final sig_script for a covenant P2SH input (borrower spend).
/// Layout: `OP_FALSE <push redeem_script>`
/// The OP_FALSE (0x00) selects the OP_ELSE branch where introspection
/// opcodes enforce the additive condition — no signature needed.
fn build_p2sh_covenant_borrower_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    // Beneficiary/borrower spend: <sig||sighash> [branch_selectors] <redeem_script>
    // Simple 2-branch (vault): <sig> OP_FALSE <redeem>
    // Nested 3-branch (time-locked escrow, inner IF): <sig> OP_TRUE OP_FALSE <redeem>
    // Detect nesting by counting OP_ENDIF (0x68) bytes.

    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Beneficiary input has no signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    // Decide whether the spender must supply an INNER branch selector.
    //
    // Some covenants nest a spender-selected inner branch directly inside the
    // outer OP_ELSE (the time-locked escrow: outer ELSE -> inner OP_IF chooses
    // release-vs-refund). Those need <sig> OP_TRUE OP_FALSE <redeem>.
    //
    // Others have an inner OP_IF that is NOT spender-selected: the script itself
    // computes the condition and feeds OP_IF from the stack (e.g. the global
    // allowance, whose inner IF tests OP_COV_OUTPUT_COUNT == 1). Those have two
    // OP_ENDIFs but must NOT receive an inner selector, or the extra byte sits
    // between the signature and CHECKSIGVERIFY and the node rejects it as a
    // "malformed signature".
    //
    // The precise signal is a top-level OP_ELSE (0x67) immediately followed by
    // OP_IF (0x63): an inner branch the spender chooses. Walk opcodes (skipping
    // push data) so a 0x67/0x63 byte inside pushed data is never mistaken for an
    // opcode. Counting OP_ENDIF is too coarse and misclassifies stack-driven
    // inner IFs like the global allowance.
    let nested = {
        let mut found = false;
        let mut i = 0usize;
        while i < redeem.len() {
            let op = redeem[i];
            if op == 0x67 {
                // OP_ELSE: is the next opcode OP_IF?
                if redeem.get(i + 1) == Some(&0x63) {
                    found = true;
                    break;
                }
                i += 1;
            } else if (0x01..=0x4b).contains(&op) {
                i += 1 + op as usize;
            } else if op == 0x4c && i + 1 < redeem.len() {
                i += 2 + redeem[i + 1] as usize;
            } else if op == 0x4d && i + 2 < redeem.len() {
                let len = redeem[i + 1] as usize | ((redeem[i + 2] as usize) << 8);
                i += 3 + len;
            } else if op == 0x4e && i + 4 < redeem.len() {
                let len = redeem[i + 1] as usize
                    | ((redeem[i + 2] as usize) << 8)
                    | ((redeem[i + 3] as usize) << 16)
                    | ((redeem[i + 4] as usize) << 24);
                i += 5 + len;
            } else {
                i += 1;
            }
        }
        found
    };

    let mut sig_script: Vec<u8> = Vec::with_capacity(66 + 3 + redeem.len() + 3);

    // Push signature (65 bytes: 64-byte Schnorr + 1-byte sighash)
    sig_script.push(65u8);
    sig_script.extend_from_slice(&sig_bytes);

    if nested {
        // Nested: OP_TRUE (inner IF) then OP_FALSE (outer ELSE)
        sig_script.push(0x51); // OP_TRUE
    }
    // OP_FALSE to select outer ELSE branch
    sig_script.push(0x00);

    // Push redeem script (supports >255 bytes via OP_PUSHDATA2)
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

/// Assemble sig_script for a 2-of-3 escrow covenant.
///
/// Branch paths and sig_scripts:
///   buyer-release:        <sig> TRUE <redeem>
///   seller-refund:        <sig> TRUE FALSE <redeem>
///   arbiter-award-seller: <sig> TRUE TRUE FALSE FALSE <redeem>
///   arbiter-refund-buyer: <sig> FALSE TRUE FALSE FALSE <redeem>
fn build_p2sh_escrow_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    branch: &str,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Escrow input has no signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut ss: Vec<u8> = Vec::with_capacity(66 + 8 + redeem.len() + 4);

    match branch {
        "buyer-release" => {
            // <sig> TRUE <redeem>
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // TRUE (L1 IF)
        }
        "seller-refund" => {
            // <sig> TRUE FALSE <redeem>
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // TRUE (L2 IF)
            ss.push(0x00); // FALSE (L1 ELSE)
        }
        "arbiter-award-seller" => {
            // Stack needed (bottom to top): L4a_sel, <sig>, L3_sel, L2_sel, L1_sel
            // L4a IF selector goes BELOW sig (survives CHECKSIGVERIFY)
            ss.push(0x51); // TRUE (L4a IF = award bob/seller) - pushed first, deepest
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // TRUE (L3 IF = arbiter path)
            ss.push(0x00); // FALSE (L2 ELSE)
            ss.push(0x00); // FALSE (L1 ELSE)
        }
        "arbiter-refund-buyer" => {
            // Stack needed (bottom to top): L4a_sel, <sig>, L3_sel, L2_sel, L1_sel
            ss.push(0x00); // FALSE (L4a ELSE = refund alice/buyer) - pushed first, deepest
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // TRUE (L3 IF = arbiter path)
            ss.push(0x00); // FALSE (L2 ELSE)
            ss.push(0x00); // FALSE (L1 ELSE)
        }
        "buyer-dispute" => {
            // Stack needed (bottom to top): <sig>, L4b_sel, L3_sel, L2_sel, L1_sel
            // After 3 IF pops: <sig>, L4b_sel. OP_IF pops L4b. CHECKSIGVERIFY gets sig.
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // TRUE (L4b IF = buyer signs)
            ss.push(0x00); // FALSE (L3 ELSE = dispute path)
            ss.push(0x00); // FALSE (L2 ELSE)
            ss.push(0x00); // FALSE (L1 ELSE)
        }
        "seller-dispute" => {
            // Stack needed (bottom to top): <sig>, L4b_sel, L3_sel, L2_sel, L1_sel
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x00); // FALSE (L4b ELSE = seller signs)
            ss.push(0x00); // FALSE (L3 ELSE = dispute path)
            ss.push(0x00); // FALSE (L2 ELSE)
            ss.push(0x00); // FALSE (L1 ELSE)
        }
        _ => {
            return Err(format!("Unknown escrow branch: {}", branch));
        }
    }

    push_redeem_script(&mut ss, redeem)?;

    Ok(ss)
}

/// Assemble the unlock sig_script for the shipment-escrow covenant.
///
/// Selectors are pushed bottom-to-top (the signature, when present, sits
/// deepest so it survives the IF pops until its CHECKSIGVERIFY). Timeout
/// branches carry no signature; the consensus engine enforces the CLTV
/// deadline against the transaction locktime instead.
///
///   pickup            <sig_D>   TRUE              <redeem>
///   delivery          <sig_B>   TRUE TRUE         <redeem>
///   state0-arb-refund <sig_Arb> TRUE FALSE        <redeem>
///   state0-timeout              FALSE FALSE       <redeem>
///   state1-arb-award  <sig_Arb> TRUE FALSE TRUE   <redeem>
///   state1-timeout              FALSE FALSE TRUE  <redeem>
///   state1-arb-refund <sig_Arb> FALSE             <redeem>
///
/// (TRUE = 0x51, FALSE = 0x00.) Verified byte sequences for the standard
/// test params, e.g. delivery selector/sig prefix = 41<65B sig>5151.
fn build_p2sh_ship_escrow_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    branch: &str,
) -> Result<Vec<u8>, String> {
    // Timeout branches carry no signature; every other branch takes the
    // single sig present in partialSigs (the signer chose which key).
    let needs_sig = !matches!(branch, "state0-timeout" | "state1-timeout");
    let mut sig_bytes: Vec<u8> = Vec::new();
    if needs_sig {
        let (_pk_hex, sig_val) = partial_map
            .iter()
            .next()
            .ok_or_else(|| format!("ship-escrow branch '{}' requires a signature", branch))?;
        let sig_hex = sig_val
            .get("schnorr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
        if sig_hex.len() != 128 {
            return Err(format!("bad sig length: {}", sig_hex.len()));
        }
        sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
        sig_bytes.push(0x01); // SIGHASH_ALL
    }

    let mut ss: Vec<u8> = Vec::with_capacity(66 + 4 + redeem.len() + 4);

    match branch {
        "pickup" => {
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // L1 = pickup (deliverer)
        }
        "delivery" => {
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // L2 = buyer
            ss.push(0x51); // L1 = pay-workers
        }
        "state0-arb-refund" => {
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // L2 = arbiter
            ss.push(0x00); // L1 = refund
        }
        "state0-timeout" => {
            ss.push(0x00); // L2 = timeout
            ss.push(0x00); // L1 = refund
        }
        "state1-arb-award" => {
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // L3 = arbiter
            ss.push(0x00); // L2 = not buyer
            ss.push(0x51); // L1 = pay-workers
        }
        "state1-timeout" => {
            ss.push(0x00); // L3 = timeout
            ss.push(0x00); // L2 = not buyer
            ss.push(0x51); // L1 = pay-workers
        }
        "state1-arb-refund" => {
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x00); // L1 = refund (arbiter only)
        }
        _ => {
            return Err(format!("Unknown ship-escrow branch: {}", branch));
        }
    }

    push_redeem_script(&mut ss, redeem)?;
    Ok(ss)
}

/// Assemble sig_script for an atomic swap claim (ELSE branch with preimage).
/// Layout: `<push sig||sighash> <push preimage> OP_FALSE <push redeem_script>`
/// The preimage is hashed by OP_BLAKE2B in the script and compared to the expected hash.
fn build_p2sh_atomic_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    preimage: &[u8],
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Atomic claim input has no signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut sig_script: Vec<u8> = Vec::with_capacity(66 + preimage.len() + 3 + redeem.len() + 3);

    // Push preimage FIRST (goes deepest on stack — consumed by OP_BLAKE2B after CHECKSIGVERIFY)
    if preimage.len() <= 75 {
        sig_script.push(preimage.len() as u8);
    } else if preimage.len() <= 255 {
        sig_script.push(0x4C);
        sig_script.push(preimage.len() as u8);
    } else {
        return Err("preimage too large".into());
    }
    sig_script.extend_from_slice(preimage);

    // Push signature (65 bytes) — on top of preimage
    sig_script.push(65u8);
    sig_script.extend_from_slice(&sig_bytes);

    // OP_FALSE to select ELSE branch (claim)
    sig_script.push(0x00);

    // Push redeem script
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

/// Assemble sig_script for commit-reveal split (OP_CAT) covenant.
/// Layout: `<push part_A> <push part_B> <push sig> OP_FALSE <push redeem_script>`
///
/// Stack after sig_script push (bottom to top):
///   part_A | part_B | sig | OP_FALSE | redeem
///
/// Execution:
///   1. P2SH pops redeem, verifies hash
///   2. OP_FALSE selects ELSE branch
///   3. CHECKSIGVERIFY consumes sig
///   4. Stack: [part_A, part_B] with part_B on top
///   5. OP_CAT: pop part_B (x2), pop part_A (x1), push part_A||part_B
///   6. OP_BLAKE2B hashes the result
///   7. EQUALVERIFY checks against committed hash
fn build_p2sh_commit_reveal_split_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    part_a: &[u8],
    part_b: &[u8],
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Commit-reveal split input has no signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut ss: Vec<u8> =
        Vec::with_capacity(part_a.len() + part_b.len() + 66 + 3 + redeem.len() + 10);

    // Push part_A FIRST (goes deepest on stack)
    push_data_item(&mut ss, part_a)?;

    // Push part_B (above part_A on stack)
    push_data_item(&mut ss, part_b)?;

    // Push signature (65 bytes) — on top
    ss.push(65u8);
    ss.extend_from_slice(&sig_bytes);

    // OP_FALSE to select ELSE branch
    ss.push(0x00);

    // Push redeem script
    push_redeem_script(&mut ss, redeem)?;

    Ok(ss)
}

/// Helper: push variable-length data with appropriate OP_PUSHDATA prefix
fn push_data_item(ss: &mut Vec<u8>, data: &[u8]) -> Result<(), String> {
    let len = data.len();
    if len == 0 {
        ss.push(0x00); // OP_0 = empty
    } else if len <= 75 {
        ss.push(len as u8);
    } else if len <= 255 {
        ss.push(0x4C);
        ss.push(len as u8);
    } else if len <= 65535 {
        ss.push(0x4D);
        ss.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        return Err("data item too large".into());
    }
    ss.extend_from_slice(data);
    Ok(())
}

/// Assemble sig_script for an oracle covenant claim (ELSE-IF branch with oracle attestation).
/// Layout: `<push oracle_sig> <push msg_hash> <push bene_sig||sighash> OP_TRUE OP_FALSE <push redeem_script>`
///
/// Stack (bottom to top after sig_script push):
///   oracle_sig (deepest) | msg_hash | bene_sig||sighash | OP_TRUE | OP_FALSE | redeem
///
/// Execution:
///   1. P2SH pops & hashes redeem, verifies against SPK hash
///   2. OP_FALSE → selects outer ELSE branch
///   3. OP_TRUE → selects inner IF branch (beneficiary claim)
///   4. <bene_pk> CHECKSIGVERIFY: pops bene_sig, verifies against TX sighash
///   5. <oracle_pk> CHECKSIGFROMSTACK: pops [oracle_sig, msg_hash, oracle_pk],
///      verifies Schnorr signature of oracle_sig on msg_hash using oracle_pk
///   6. OP_VERIFY, OP_TRUE → clean stack
fn build_p2sh_oracle_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    oracle_sig: &[u8],
    msg_hash: &[u8],
) -> Result<Vec<u8>, String> {
    if oracle_sig.len() != 64 {
        return Err(format!(
            "oracle sig must be 64 bytes, got {}",
            oracle_sig.len()
        ));
    }
    if msg_hash.len() != 32 {
        return Err(format!("msg_hash must be 32 bytes, got {}", msg_hash.len()));
    }

    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Oracle claim input has no beneficiary signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad beneficiary sig length: {}", sig_hex.len()));
    }
    let mut bene_sig_bytes = hex::decode(sig_hex).map_err(|e| format!("bene sig hex: {}", e))?;
    bene_sig_bytes.push(0x01); // SIGHASH_ALL

    let mut sig_script: Vec<u8> =
        Vec::with_capacity(1 + 64 + 1 + 32 + 1 + 65 + 1 + 2 + redeem.len());

    // Push oracle signature (64 bytes) — goes deepest on stack
    sig_script.push(64u8);
    sig_script.extend_from_slice(oracle_sig);

    // Push message hash (32 bytes) — second on stack
    sig_script.push(32u8);
    sig_script.extend_from_slice(msg_hash);

    // Push beneficiary signature (65 bytes = 64 sig + 1 sighash) — third on stack
    sig_script.push(65u8);
    sig_script.extend_from_slice(&bene_sig_bytes);

    // OP_TRUE OP_FALSE: outer ELSE (FALSE), inner IF (TRUE) for beneficiary claim
    sig_script.push(0x51); // OP_TRUE — inner IF selector
    sig_script.push(0x00); // OP_FALSE — outer ELSE selector

    // Push redeem script
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

/// Assemble sig_script for an oracle heartbeat beacon (ELSE-ELSE branch).
/// Layout: `<push sig||sighash> OP_FALSE OP_FALSE <push redeem_script>`
///
/// The oracle signs with CHECKSIGVERIFY, output goes back to same P2SH.
/// Attestation data rides in the TX payload field (not in sig_script).
fn build_p2sh_oracle_heartbeat_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Oracle heartbeat input has no signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad oracle sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("oracle sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut sig_script: Vec<u8> = Vec::with_capacity(1 + 65 + 1 + 1 + 3 + redeem.len());

    // Push oracle signature (65 bytes = 64 sig + 1 sighash)
    sig_script.push(65u8);
    sig_script.extend_from_slice(&sig_bytes);

    // OP_FALSE OP_FALSE: outer ELSE, inner ELSE (heartbeat branch)
    sig_script.push(0x00); // inner ELSE
    sig_script.push(0x00); // outer ELSE

    // Push redeem script
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

/// Assemble sig_script for a ZK proof covenant claim (ELSE branch with Groth16 proof).
///
/// Layout (pushed into sig_script, bottom → top after execution):
///   <input_{n-1}> ... <input_0> <n_inputs> <proof> <sig||sighash> OP_FALSE <redeem>
///
/// Stack after sig_script push and before redeem execution:
///   input_{n-1} | ... | input_0 | n_inputs | proof | sig | OP_FALSE | redeem
///
/// Execution:
///   1. P2SH pops & hashes redeem, verifies against SPK hash
///   2. OP_FALSE → selects ELSE branch
///   3. <owner_pk> CHECKSIGVERIFY: pops sig, verifies against TX sighash
///   4. Script pushes VK and tag (embedded in redeem)
///   5. OpZkPrecompile: pops [tag, vk, proof, n_inputs, input_0..input_{n-1}]
///      and verifies the Groth16 proof
///   6. OP_VERIFY, OP_TRUE → clean stack
fn build_p2sh_zk_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    public_inputs: &[Vec<u8>],
    vk: &[u8],
) -> Result<Vec<u8>, String> {
    // Extract the owner signature from partialSigs
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "ZK claim input has no owner signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad owner sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("owner sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let n_inputs = public_inputs.len();

    let mut sig_script: Vec<u8> = Vec::with_capacity(1024);

    // Push public inputs in REVERSE order (deepest first)
    for input in public_inputs.iter().rev() {
        push_data_sigscript(&mut sig_script, input);
    }

    // Push n_inputs as integer
    push_int_sigscript(&mut sig_script, n_inputs as u64);

    // Push proof (128 bytes)
    push_data_sigscript(&mut sig_script, proof);

    // Push VK (296 bytes) — will be verified via BLAKE2B hash in redeem script
    push_data_sigscript(&mut sig_script, vk);

    // Push owner signature (65 bytes = 64 sig + 1 sighash)
    push_data_sigscript(&mut sig_script, &sig_bytes);

    // OP_FALSE to select ELSE branch
    sig_script.push(0x00);

    // Push redeem script
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

/// Build sig_script for KIP-21 bridge withdrawal.
///
/// Same as ZK claim but with withdrawal_spk pushed at the bottom of the stack.
/// After CHECKSIGVERIFY consumes sig and ZK_PRECOMPILE consumes proof items,
/// withdrawal_spk remains on the stack for the OP_TX_OUTPUT_SPK EQUALVERIFY check.
///
/// Stack layout (bottom -> top):
///   <withdrawal_spk> <inputs> <n_inputs> <proof> <vk> <sig||sighash> OP_FALSE <redeem>
fn build_p2sh_bridge_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    public_inputs: &[Vec<u8>],
    vk: &[u8],
    withdrawal_spk: &[u8],
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Bridge claim input has no owner signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad owner sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("owner sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let n_inputs = public_inputs.len();

    let mut sig_script: Vec<u8> = Vec::with_capacity(1024);

    // Push withdrawal SPK at the very bottom of the stack
    // This stays on the stack after ZK verification for the SPK check
    push_data_sigscript(&mut sig_script, withdrawal_spk);

    // Push public inputs in REVERSE order (deepest first)
    for input in public_inputs.iter().rev() {
        push_data_sigscript(&mut sig_script, input);
    }

    // Push n_inputs
    push_int_sigscript(&mut sig_script, n_inputs as u64);

    // Push proof (128 bytes)
    push_data_sigscript(&mut sig_script, proof);

    // Push VK
    push_data_sigscript(&mut sig_script, vk);

    // Push owner signature
    push_data_sigscript(&mut sig_script, &sig_bytes);

    // OP_FALSE to select ELSE branch
    sig_script.push(0x00);

    // Push redeem script
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

/// Push data with correct prefix for sig_script context.
fn push_data_sigscript(buf: &mut Vec<u8>, data: &[u8]) {
    if data.len() <= 75 {
        buf.push(data.len() as u8);
    } else if data.len() <= 255 {
        buf.push(0x4C); // OP_PUSHDATA1
        buf.push(data.len() as u8);
    } else if data.len() <= 65535 {
        buf.push(0x4D); // OP_PUSHDATA2
        buf.push((data.len() & 0xff) as u8);
        buf.push((data.len() >> 8) as u8);
    } else {
        buf.push(0x4E); // OP_PUSHDATA4
        buf.push((data.len() & 0xff) as u8);
        buf.push(((data.len() >> 8) & 0xff) as u8);
        buf.push(((data.len() >> 16) & 0xff) as u8);
        buf.push(((data.len() >> 24) & 0xff) as u8);
    }
    buf.extend_from_slice(data);
}

/// Push an integer in sig_script context (small integer encoding).
fn push_int_sigscript(buf: &mut Vec<u8>, value: u64) {
    if value == 0 {
        buf.push(0x00);
    } else if value <= 16 {
        buf.push(0x50 + value as u8);
    } else {
        let mut v = value;
        let mut bytes = Vec::new();
        while v > 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }
        if bytes.last().is_some_and(|b| b & 0x80 != 0) {
            bytes.push(0x00);
        }
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(&bytes);
    }
}

/// Push redeem script with correct OP_PUSHDATA prefix.
pub fn push_redeem_script(buf: &mut Vec<u8>, redeem: &[u8]) -> Result<(), String> {
    if redeem.len() <= 75 {
        buf.push(redeem.len() as u8);
    } else if redeem.len() <= 255 {
        buf.push(0x4C);
        buf.push(redeem.len() as u8);
    } else if redeem.len() <= 65535 {
        buf.push(0x4D); // OP_PUSHDATA2
        buf.push((redeem.len() & 0xff) as u8);
        buf.push((redeem.len() >> 8) as u8);
    } else {
        return Err("redeem script too large".into());
    }
    buf.extend_from_slice(redeem);
    Ok(())
}

/// Assemble sig_script for a RISC0 succinct proof covenant claim (ELSE branch).
///
/// Stack layout after sig_script push and CHECKSIGVERIFY (bottom → top):
///   claim | control_index | control_digests | seal | journal |
///   image_id | control_id | hashfn
///
/// Then script pushes tag (0x21) and calls OpZkPrecompile.
/// The opcode pops: hashfn, control_id, image_id, journal, seal,
///   control_digests, control_index, claim — then tag.
fn build_p2sh_risc0_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    seal: &[u8],
    fields: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    // Extract owner signature
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "RISC0 claim has no owner signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad owner sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("owner sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    // Extract RISC0 fields
    let decode_field = |name: &str| -> Result<Vec<u8>, String> {
        let hex_str = fields
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("missing risc0 field: {}", name))?;
        hex::decode(hex_str).map_err(|e| format!("bad hex for {}: {}", name, e))
    };

    let claim = decode_field("claim")?;
    let control_index = decode_field("controlIndex")?;
    let control_digests = decode_field("controlDigests")?;
    let journal = decode_field("journal")?;
    let image_id = decode_field("imageId")?;
    let control_id = decode_field("controlId")?;
    let hashfn = decode_field("hashfn")?;

    web_sys::console::log_1(&format!(
        "[KasSee] RISC0 sig_script: seal={}B, claim={}B, ctrl_id={}B, img_id={}B, journal={}B, ctrl_dig={}B, ctrl_idx={}B, hashfn={}B",
        seal.len(), claim.len(), control_id.len(), image_id.len(),
        journal.len(), control_digests.len(), control_index.len(), hashfn.len()
    ).into());
    web_sys::console::log_1(
        &format!(
            "[KasSee] RISC0 fields: claim={}, ctrl_idx={}, hashfn={}, img_id={}, ctrl_id={}",
            hex::encode(&claim[..4.min(claim.len())]),
            hex::encode(&control_index),
            hex::encode(&hashfn),
            hex::encode(&image_id[..4.min(image_id.len())]),
            hex::encode(&control_id[..4.min(control_id.len())]),
        )
        .into(),
    );

    let mut ss: Vec<u8> = Vec::with_capacity(seal.len() + 1024);

    // Push in order: claim deepest, hashfn on top (before sig)
    // Stack bottom → top: claim | ctrl_idx | ctrl_dig | seal | journal | img_id | ctrl_id | hashfn
    push_data_sigscript(&mut ss, &claim);
    push_data_sigscript(&mut ss, &control_index);
    push_data_sigscript(&mut ss, &control_digests);
    push_data_sigscript(&mut ss, seal);
    push_data_sigscript(&mut ss, &journal);
    push_data_sigscript(&mut ss, &image_id);
    push_data_sigscript(&mut ss, &control_id);
    push_data_sigscript(&mut ss, &hashfn);

    // Owner signature
    push_data_sigscript(&mut ss, &sig_bytes);

    // OP_FALSE to select ELSE branch
    ss.push(0x00);

    // Redeem script
    push_redeem_script(&mut ss, redeem)?;

    // Debug: log sig_script prefix and suffix
    let prefix = if ss.len() >= 20 {
        hex::encode(&ss[..20])
    } else {
        hex::encode(&ss)
    };
    let suffix_start = if ss.len() > 20 { ss.len() - 20 } else { 0 };
    let suffix = hex::encode(&ss[suffix_start..]);
    web_sys::console::log_1(
        &format!(
            "[KasSee] RISC0 sig_script: len={}, prefix={}, suffix={}",
            ss.len(),
            prefix,
            suffix
        )
        .into(),
    );

    Ok(ss)
}

/// No-signature covenant sig_script.
/// For simple 2-branch covenants (additive/spending-limit): OP_FALSE <redeem>
/// For nested 3-branch covenants (time-locked escrow): OP_FALSE OP_FALSE <redeem>
/// Detects nesting by counting OP_ENDIF (0x68) bytes in the redeem script.
/// Assemble sig_script for a treasury P2SH input.
/// Layout: `<push 65 sig||sighash> <push redeem_script>`
/// No branch selector — the script starts with CHECKSIGVERIFY, not IF.
fn build_p2sh_treasury_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    // Get the single signature
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Treasury input has no signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Treasury sig missing schnorr field".to_string())?;
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("bad treasury sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut sig_script: Vec<u8> = Vec::with_capacity(sig_bytes.len() + 2 + redeem.len() + 2);

    // Push signature (64 bytes sig + 1 byte sighash type = 65)
    sig_script.push(sig_bytes.len() as u8);
    sig_script.extend_from_slice(&sig_bytes);

    // Push redeem script
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

/// Sig_script for a state machine covenant.
/// Layout: <sig||sighash> <redeem>
/// No branch selector — the script internally dispatches based on
/// auth_output_count (genesis) or input_amount (state).
fn build_p2sh_state_machine_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "State machine input has no signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "State machine sig missing schnorr field".to_string())?;
    let mut sig_bytes =
        hex::decode(sig_hex).map_err(|e| format!("bad state machine sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut ss: Vec<u8> = Vec::with_capacity(sig_bytes.len() + 2 + redeem.len() + 3);

    // Push signature
    push_data_sigscript(&mut ss, &sig_bytes);

    // Push redeem script
    push_redeem_script(&mut ss, redeem)?;

    Ok(ss)
}

/// Assemble sig_script for a merkle whitelist vault claim (ELSE branch).
///
/// Sig_script layout (bottom → top):
///   <dest_spk_copy> <sibling_N-1> <dir_N-1> ... <sibling_0> <dir_0> <dest_spk> <sig>
///   OP_FALSE <redeem>
///
/// After CHECKSIGVERIFY eats sig, stack:
///   dest_spk_copy | sibling_N-1 | dir_N-1 | ... | sibling_0 | dir_0 | dest_spk
///
/// Script: BLAKE2B → leaf hash, then per-level SWAP/IF/CAT/BLAKE2B,
/// then EQUALVERIFY root, then verify output[0].spk == dest_spk_copy.
fn build_p2sh_merkle_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof_json: &str,
    dest_spk: &[u8],
) -> Result<Vec<u8>, String> {
    // Parse proof
    let proof: Vec<serde_json::Value> =
        serde_json::from_str(proof_json).map_err(|e| format!("Bad proof JSON: {}", e))?;

    // Get signature
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Merkle claim has no signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut ss: Vec<u8> = Vec::with_capacity(1024);

    // Push dest_spk copy (for output verification at end of script)
    push_data_sigscript(&mut ss, dest_spk);

    // Push proof items in reverse order (deepest level first on stack)
    // so they get consumed top-down during verification
    for item in proof.iter().rev() {
        let sibling_hex = item
            .get("sibling")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "proof item missing sibling".to_string())?;
        let direction =
            item.get("direction")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "proof item missing direction".to_string())? as u8;

        let sibling = hex::decode(sibling_hex).map_err(|e| format!("bad sibling hex: {}", e))?;

        push_data_sigscript(&mut ss, &sibling);
        // Push direction as a minimal integer
        if direction == 0 {
            ss.push(0x00); // OP_FALSE = 0
        } else {
            ss.push(0x51); // OP_TRUE = 1
        }
    }

    // Push dest_spk (the leaf — will be hashed by script)
    push_data_sigscript(&mut ss, dest_spk);

    // Push signature
    push_data_sigscript(&mut ss, &sig_bytes);

    // OP_FALSE to select ELSE branch
    ss.push(0x00);

    // Push redeem script
    push_redeem_script(&mut ss, redeem)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Merkle sig_script: {} bytes, proof_depth={}, dest_spk={}B",
            ss.len(),
            proof.len(),
            dest_spk.len()
        )
        .into(),
    );

    Ok(ss)
}

/// sig_script for the approach-1 KCC20 token conservation covenant: just push(redeem).
/// The body is flat (no top-level IF/ELSE), so no OP_FALSE branch selector is prepended;
/// it executes from an empty stack and leaves a single TRUE (CleanStack). Matches the
/// engine-validated spend (empty signature + push(redeem)).
fn build_p2sh_token_conservation_sig_script(redeem: &[u8]) -> Result<Vec<u8>, String> {
    let mut sig_script: Vec<u8> = Vec::with_capacity(redeem.len() + 4);
    push_redeem_script(&mut sig_script, redeem)?;
    Ok(sig_script)
}

fn build_p2sh_covenant_nosig_script(redeem: &[u8]) -> Result<Vec<u8>, String> {
    // Single OP_FALSE selects the ELSE branch for borrower/no-sig covenants.
    // Nested scripts (escrow) use different builders with explicit branch selectors.
    let false_count = 1;

    web_sys::console::log_1(
        &format!(
            "[KasSee] nosig_script: redeem_len={}, false_count={}",
            redeem.len(),
            false_count
        )
        .into(),
    );

    let mut sig_script: Vec<u8> = Vec::with_capacity(redeem.len() + 5 + false_count);

    // Push OP_FALSE(s) to select ELSE branch(es)
    sig_script.resize(sig_script.len() + false_count, 0x00u8);

    // Push redeem script
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

/// Assemble the final sig_script for a P2PK input.
/// Layout: `<push 65 sig||sighash>` — single 65-byte push.
fn build_p2pk_sig_script(partial_map: &serde_json::Map<String, Value>) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "P2PK input has no signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut sig_script = Vec::with_capacity(66);
    sig_script.push(65u8);
    sig_script.extend_from_slice(&sig_bytes);
    Ok(sig_script)
}

// ═══════════════════════════════════════════════════════════════════
// KSPT v2 merge (incoming relay — device → KasSee)
// ═══════════════════════════════════════════════════════════════════
//
// Inverse of `relay_pskb_as_kspt_v2_hex`. Takes a KSPT v2 blob
// returned by the device (either `flags=0x00` partial or `flags=0x01`
// fully-signed) together with the canonical PSKB KasSee holds, and
// writes each (pubkey_pos, sig) record into the PSKB input's
// `partialSigs` map at the slot keyed by the corresponding 33-byte
// compressed cosigner pubkey.
//
// Pubkey reconstruction: KSPT v2 wire format carries only a 1-byte
// `pubkey_pos`. The cosigner's 32-byte x-only key lives in the
// redeem script at that position. The 33-byte SEC1 form is recovered
// as `02 || xonly` — this is the Kaspa Schnorr multisig convention
// (BIP340 "lift_x" with even-Y assumption), matching the device's
// own `lift_x` in bootloader/src/wallet/schnorr.rs line 307.
//
// Merge semantics:
//   - Pubkeys already in `partialSigs` are LEFT ALONE (no clobber).
//     An earlier signer's sig cannot be overwritten by a later relay.
//   - New pubkeys are INSERTED.
//   - The canonical PSKB remains the source of truth; this function
//     returns a new hex blob with the merged sigs. The caller keeps
//     the result as the new canonical PSKB.
//   - Wallet convention (KIP): cosigner ordering in the redeem script
//     is lexicographic-by-x-only. This merge preserves that because
//     the redeem script is copied through unchanged; we only add map
//     entries to `partialSigs`.
//
// Idempotent: merging the same KSPT v2 twice is a no-op on the
// second call.

/// Merge the partial signatures from a device-returned KSPT v2 blob
/// into the canonical PSKB and return the resulting PSKB wire hex.
/// Helper: merge a single P2PK sig from a KSPT v2 record into a PSKB
/// input that has no redeem script. Extracts the x-only pubkey from the
/// PSKB's `utxoEntry.scriptPublicKey` instead of a redeem script.
fn merge_v2_p2pk_sig(
    inp: &mut serde_json::Map<String, Value>,
    rec: &KsptSigRecord,
    input_idx: usize,
) -> Result<(), String> {
    // Read the pubkey from utxoEntry.scriptPublicKey (P2PK: 0x20 <32> 0xAC)
    let utxo = inp
        .get("utxoEntry")
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("input[{}] missing utxoEntry", input_idx))?;
    let spk_full = utxo
        .get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("input[{}] missing scriptPublicKey", input_idx))?;
    // spk_full is "0000" + hex(script). Skip 4 hex chars (version).
    if spk_full.len() < 4 + 68 {
        return Err(format!(
            "input[{}] scriptPublicKey too short for P2PK",
            input_idx
        ));
    }
    let script_hex = &spk_full[4..];
    let script =
        hex::decode(script_hex).map_err(|e| format!("input[{}] spk hex: {}", input_idx, e))?;
    if script.len() != 34 || script[0] != 0x20 || script[33] != 0xAC {
        return Err(format!("input[{}] spk is not P2PK", input_idx));
    }
    let pk_hex = format!("02{}", hex::encode(&script[1..33]));

    if !matches!(inp.get("partialSigs"), Some(Value::Object(_))) {
        inp.insert("partialSigs".to_string(), Value::Object(Default::default()));
    }
    let partial_map = inp
        .get_mut("partialSigs")
        .and_then(|v| v.as_object_mut())
        .expect("just inserted/verified");

    if !partial_map.contains_key(&pk_hex) {
        let sig_hex = hex::encode(rec.sig);
        let mut sig_obj = serde_json::Map::new();
        sig_obj.insert("schnorr".to_string(), Value::String(sig_hex));
        partial_map.insert(pk_hex, Value::Object(sig_obj));
    }
    Ok(())
}

///
/// Accepts both `flags = 0x00` (relay partial) and `flags = 0x01`
/// (fully signed) KSPT v2 blobs — both are treated identically as
/// "read out the sigs present". The flag byte is advisory; the real
/// test for "ready to finalize" is still `partialSigs.len() >= M`.
pub fn merge_signed_kspt_v2_into_pskb(
    signed_kspt_hex: &str,
    pskb_wire_hex: &str,
) -> Result<String, String> {
    // ── 1. Parse KSPT bytes — detect v1 vs v2 ──
    let kspt = hex::decode(signed_kspt_hex).map_err(|e| format!("KSPT hex: {}", e))?;
    if kspt.len() < 5 {
        return Err("KSPT blob too short".into());
    }
    let kspt_version = kspt[4];

    // ── 2. Parse PSKB envelope ──
    let format = detect_format_hex(pskb_wire_hex);
    if format == PsktFormat::Unknown {
        return Err("Not a PSKT/PSKB payload".into());
    }
    let wire = hex::decode(pskb_wire_hex).map_err(|e| format!("outer hex: {}", e))?;
    if wire.len() < 4 {
        return Err("payload too short".into());
    }
    let magic = wire[0..4].to_vec();
    let json_bytes = hex::decode(&wire[4..]).map_err(|e| format!("inner hex: {}", e))?;
    let mut root: Value =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("JSON parse: {}", e))?;

    // ── 3. Locate the inputs array (PSKB wraps in a 1-element array) ──
    let inputs_mut: &mut Vec<Value> = match format {
        PsktFormat::Pskb => {
            let arr = root
                .as_array_mut()
                .ok_or_else(|| "PSKB not array".to_string())?;
            if arr.len() != 1 {
                return Err(format!("PSKB must have 1 entry, got {}", arr.len()));
            }
            let pskt = arr[0]
                .as_object_mut()
                .ok_or_else(|| "PSKB entry not object".to_string())?;
            pskt.get_mut("inputs")
                .and_then(|v| v.as_array_mut())
                .ok_or_else(|| "missing inputs".to_string())?
        }
        PsktFormat::PsktSingle => {
            let pskt = root
                .as_object_mut()
                .ok_or_else(|| "PSKT not object".to_string())?;
            pskt.get_mut("inputs")
                .and_then(|v| v.as_array_mut())
                .ok_or_else(|| "missing inputs".to_string())?
        }
        PsktFormat::Unknown => unreachable!(),
    };

    // ── 4. Branch on KSPT version ──
    if kspt_version == 0x02 || kspt_version == 0x03 {
        // ── v2/v3: multisig path (pubkey_pos + redeem script) ──
        let per_input = parse_kspt_v2_partials(&kspt)?;

        if inputs_mut.len() != per_input.len() {
            return Err(format!(
                "input count mismatch: PSKB has {}, KSPT v2 has {}",
                inputs_mut.len(),
                per_input.len()
            ));
        }

        for (i, sigs_at_input) in per_input.iter().enumerate() {
            web_sys::console::log_1(
                &format!(
                    "[KasSee] merge input[{}]: {} sigs in KSPT v2",
                    i,
                    sigs_at_input.len()
                )
                .into(),
            );
            if sigs_at_input.is_empty() {
                continue;
            }

            let inp = inputs_mut[i]
                .as_object_mut()
                .ok_or_else(|| format!("input[{}] not object", i))?;

            let redeem_hex = match inp.get("redeemScript") {
                Some(Value::String(s)) => s.clone(),
                _ => {
                    // P2PK input in a v2 blob — extract pubkey from spk.
                    // This happens when the device emits v2 for a mixed or
                    // single-sig tx. Fall through to P2PK merge below.
                    merge_v2_p2pk_sig(inp, &sigs_at_input[0], i)?;
                    continue;
                }
            };
            let redeem =
                hex::decode(&redeem_hex).map_err(|e| format!("input[{}] redeem hex: {}", i, e))?;

            if !matches!(inp.get("partialSigs"), Some(Value::Object(_))) {
                inp.insert("partialSigs".to_string(), Value::Object(Default::default()));
            }
            let partial_map = inp
                .get_mut("partialSigs")
                .and_then(|v| v.as_object_mut())
                .expect("just inserted/verified");

            for rec in sigs_at_input {
                let xonly = xonly_at_position(&redeem, rec.pubkey_pos).ok_or_else(|| {
                    format!(
                        "input[{}] pubkey_pos {} out of range for redeem",
                        i, rec.pubkey_pos
                    )
                })?;
                let pk_hex = format!("02{}", hex::encode(xonly));

                if partial_map.contains_key(&pk_hex) {
                    continue;
                }

                let sig_hex = hex::encode(rec.sig);
                let mut sig_obj = serde_json::Map::new();
                sig_obj.insert("schnorr".to_string(), Value::String(sig_hex));
                partial_map.insert(pk_hex, Value::Object(sig_obj));
            }
        }
    } else if kspt_version == 0x01 {
        // ── v1: single-sig P2PK path ──
        // The device signed a KSPT v1 unsigned payload and returned v1
        // signed. Per input: sig(64) + spk(script with embedded pubkey).
        // P2PK script: 0x20 <32-byte xonly> 0xAC → compressed = 02 || xonly.
        let v1_records = parse_kspt_v1_signed(&kspt)?;

        if inputs_mut.len() != v1_records.len() {
            return Err(format!(
                "input count mismatch: PSKB has {}, KSPT v1 has {}",
                inputs_mut.len(),
                v1_records.len()
            ));
        }

        for (i, rec) in v1_records.iter().enumerate() {
            // Skip unsigned inputs (sig is all zeros)
            if rec.sig == [0u8; 64] {
                continue;
            }

            let inp = inputs_mut[i]
                .as_object_mut()
                .ok_or_else(|| format!("input[{}] not object", i))?;

            // Extract x-only pubkey from P2PK script
            let spk = &rec.spk;
            if spk.len() != 34 || spk[0] != 0x20 || spk[33] != 0xAC {
                return Err(format!(
                    "input[{}] KSPT v1 spk is not P2PK (len={}, expected 34)",
                    i,
                    spk.len()
                ));
            }
            let pk_hex = format!("02{}", hex::encode(&spk[1..33]));

            if !matches!(inp.get("partialSigs"), Some(Value::Object(_))) {
                inp.insert("partialSigs".to_string(), Value::Object(Default::default()));
            }
            let partial_map = inp
                .get_mut("partialSigs")
                .and_then(|v| v.as_object_mut())
                .expect("just inserted/verified");

            if !partial_map.contains_key(&pk_hex) {
                let sig_hex = hex::encode(rec.sig);
                let mut sig_obj = serde_json::Map::new();
                sig_obj.insert("schnorr".to_string(), Value::String(sig_hex));
                partial_map.insert(pk_hex, Value::Object(sig_obj));
            }
        }
    } else {
        return Err(format!("unsupported KSPT version: 0x{:02x}", kspt_version));
    }

    // ── 5. Re-serialize PSKB with the same wrapping format ──
    //
    // The outer wire we decoded was `hex::decode(pskb_wire_hex)` →
    // 4 raw magic bytes + hex-ASCII of JSON. Re-encode accordingly:
    // build `magic || hex_ascii(json)` as bytes, then hex it.
    let new_json = serde_json::to_vec(&root).map_err(|e| format!("re-serialize: {}", e))?;
    let mut wire_bytes: Vec<u8> = Vec::with_capacity(4 + new_json.len() * 2);
    wire_bytes.extend_from_slice(&magic);
    wire_bytes.extend_from_slice(hex::encode(&new_json).as_bytes());
    Ok(hex::encode(&wire_bytes))
}

/// One sig record as parsed from a KSPT v2 input section.
struct KsptSigRecord {
    pubkey_pos: u8,
    // Kept: retained for future use; not currently wired.
    #[allow(dead_code)]
    sighash_type: u8,
    sig: [u8; 64],
}

/// Parse a KSPT v2 byte blob and return, for each input, the list of
/// `(pubkey_pos, sighash_type, sig)` records present. Does not
/// validate sigs; that's the device/consensus job.
///
/// Layout (from bootloader/src/wallet/pskt.rs `serialize_signed_pskt_v2`
/// and the matching emitter here in `encode_input_kspt_v2`):
///
///   Header:  "KSPT"(4) | version=0x02(1) | flags(1)
///   Global:  tx_version(2 LE) | num_in(1) | num_out(1)
///            locktime(8 LE) | subnetwork_id(20) | gas(8 LE)
///            payload_len(2 LE) | payload(payload_len)
///   Per input:
///            prev_tx_id(32) | prev_index(4 LE) | amount(8 LE)
///            sequence(8 LE) | sig_op_count(1)
///            spk_version(2 LE) | spk_len(1) | spk_bytes
///            sig_count(1)
///            [ pubkey_pos(1) | sighash(1) | sig(64) ] × sig_count
///            redeem_script_len(1) | redeem_script_bytes
///   Per output:
///            value(8 LE) | spk_version(2 LE) | spk_len(1) | spk_bytes
fn parse_kspt_v2_partials(data: &[u8]) -> Result<Vec<Vec<KsptSigRecord>>, String> {
    let mut r = KsptReader::new(data);
    // Header
    let magic = r.bytes(4)?;
    if magic != b"KSPT" {
        return Err("not a KSPT blob".into());
    }
    let version = r.u8()?;
    if version != 0x02 && version != 0x03 {
        return Err(format!("unsupported KSPT version: 0x{:02x}", version));
    }
    let _flags = r.u8()?; // 0x00 partial, 0x01 fully signed — treat same
                          // Global
    let _tx_version = r.u16_le()?;
    let num_in = r.u8()? as usize;
    let num_out = r.u8()? as usize;
    let _locktime = r.u64_le()?;
    let _subnetwork_id = r.bytes(20)?.to_vec();
    let _gas = r.u64_le()?;
    let payload_len = r.u16_le()? as usize;
    if payload_len > 0 {
        let _ = r.bytes(payload_len)?;
    }

    let mut out: Vec<Vec<KsptSigRecord>> = Vec::with_capacity(num_in);
    for _ in 0..num_in {
        // Per-input header
        let _prev_tx_id = r.bytes(32)?.to_vec();
        let _prev_index = r.u32_le()?;
        let _amount = r.u64_le()?;
        let _sequence = r.u64_le()?;
        let _sig_op = r.u8()?;
        let _spk_version = r.u16_le()?;
        let spk_len = {
            let b0 = r.u8()?;
            if b0 == 0xFF {
                r.u16_le()? as usize
            } else {
                b0 as usize
            }
        };
        let _spk = r.bytes(spk_len)?;

        // Sig records
        let sig_count = r.u8()? as usize;
        let mut sigs: Vec<KsptSigRecord> = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            let pos = r.u8()?;
            let sighash = r.u8()?;
            let sig_bytes = r.bytes(64)?;
            let mut sig = [0u8; 64];
            sig.copy_from_slice(sig_bytes);
            sigs.push(KsptSigRecord {
                pubkey_pos: pos,
                sighash_type: sighash,
                sig,
            });
        }

        // Redeem script (may be empty for P2PK). v3: u16 LE len, v2: u8 len.
        let rs_len = if version == 0x03 {
            r.u16_le()? as usize
        } else {
            r.u8()? as usize
        };
        if rs_len > 0 {
            let _ = r.bytes(rs_len)?;
        }
        out.push(sigs);
    }

    // Outputs — read to validate length, no data needed for merge
    for _ in 0..num_out {
        let _value = r.u64_le()?;
        let _spk_version = r.u16_le()?;
        let spk_len = {
            let b0 = r.u8()?;
            if b0 == 0xFF {
                r.u16_le()? as usize
            } else {
                b0 as usize
            }
        };
        let _ = r.bytes(spk_len)?;
    }

    // Trailing bytes are tolerated by some encoders; don't fail on them.
    Ok(out)
}

/// Per-input record from a KSPT v1 signed blob: the 64-byte Schnorr
/// signature and the scriptPublicKey bytes (used to extract the x-only
/// pubkey for P2PK inputs).
struct KsptV1SigRecord {
    sig: [u8; 64],
    spk: Vec<u8>,
}

/// Parse a KSPT v1 signed blob (`version=0x01, flags=0x01`) and return
/// per-input signature + scriptPublicKey. Used by the merge function to
/// handle the case where a single-sig P2PK transaction comes back from
/// KasSigner in v1 format after compact relay.
///
/// Layout (from bootloader/src/wallet/pskt.rs `serialize_signed_pskt`):
///   Header: "KSPT"(4) | version=0x01(1) | flags=0x01(1)
///   Global: tx_version(2) num_in(1) num_out(1)
///           locktime(8) subnetwork_id(20) gas(8)
///           payload_len(2) payload(payload_len)
///   Per input:
///           prev_tx_id(32) prev_index(4) amount(8) sequence(8) sig_op(1)
///           spk_version(2) spk_len(1) spk_bytes
///           sig_len(1)
///           if sig_len>0: signature(64) sighash_type(1)
///   Per output:
///           value(8) spk_version(2) spk_len(1) spk_bytes
fn parse_kspt_v1_signed(data: &[u8]) -> Result<Vec<KsptV1SigRecord>, String> {
    let mut r = KsptReader::new(data);
    let magic = r.bytes(4)?;
    if magic != b"KSPT" {
        return Err("not a KSPT blob".into());
    }
    let version = r.u8()?;
    if version != 0x01 {
        return Err(format!("expected KSPT v1, got 0x{:02x}", version));
    }
    let flags = r.u8()?;
    let has_covenant_data = (flags & 0x04) != 0;
    let _tx_version = r.u16_le()?;
    let num_in = r.u8()? as usize;
    let num_out = r.u8()? as usize;
    let _locktime = r.u64_le()?;
    let _subnetwork_id = r.bytes(20)?;
    let _gas = r.u64_le()?;
    let payload_len = r.u16_le()? as usize;
    if payload_len > 0 {
        let _ = r.bytes(payload_len)?;
    }

    let mut out: Vec<KsptV1SigRecord> = Vec::with_capacity(num_in);
    for _ in 0..num_in {
        let _prev_tx_id = r.bytes(32)?;
        let _prev_index = r.u32_le()?;
        let _amount = r.u64_le()?;
        let _sequence = r.u64_le()?;
        let _sig_op = r.u8()?;
        let _spk_version = r.u16_le()?;
        let spk_len = {
            let b0 = r.u8()?;
            if b0 == 0xFF {
                r.u16_le()? as usize
            } else {
                b0 as usize
            }
        };
        let spk = r.bytes(spk_len)?.to_vec();

        let sig_len = r.u8()? as usize;
        let mut sig = [0u8; 64];
        if sig_len > 0 {
            let sig_bytes = r.bytes(64)?;
            sig.copy_from_slice(sig_bytes);
            let _sighash = r.u8()?;
        }
        out.push(KsptV1SigRecord { sig, spk });
    }

    for _ in 0..num_out {
        let _value = r.u64_le()?;
        let _spk_version = r.u16_le()?;
        let spk_len = {
            let b0 = r.u8()?;
            if b0 == 0xFF {
                r.u16_le()? as usize
            } else {
                b0 as usize
            }
        };
        let _ = r.bytes(spk_len)?;

        // Skip covenant binding data if flag 0x04 is set
        if has_covenant_data {
            let has_cov = r.u8()?;
            if has_cov == 1 {
                let _auth_input = r.u16_le()?;
                let _ = r.bytes(32)?;
            }
        }
    }

    Ok(out)
}

/// Return the 32-byte x-only pubkey at the given 0-indexed slot in a
/// redeem script. Mirrors `find_pubkey_position_in_redeem` but in the
/// opposite direction.
fn xonly_at_position(rs: &[u8], position: u8) -> Option<[u8; 32]> {
    if rs.len() < 4 {
        return None;
    }

    // Check for standard M-of-N multisig first:
    // OP_M (0x51..0x60) [0x20 <32B>]xN OP_N (0x51..0x60) OP_CHECKMULTISIG (0xAE)
    if rs[rs.len() - 1] == 0xAE {
        let m_byte = rs[0];
        let n_byte = rs[rs.len() - 2];
        if (0x51..=0x60).contains(&m_byte) && (0x51..=0x60).contains(&n_byte) {
            let n = (n_byte - 0x50) as usize;
            let expected_len = 1 + n * 33 + 1 + 1;
            if rs.len() == expected_len && (position as usize) < n {
                let off = 1 + (position as usize) * 33 + 1; // skip OP_M + pos*(0x20+pk) + 0x20
                let mut out = [0u8; 32];
                out.copy_from_slice(&rs[off..off + 32]);
                return Some(out);
            }
        }
    }

    // Generic scanner for covenant scripts: find all 0x20 <32 bytes> patterns
    // followed by CHECKSIG (0xac) or CHECKSIGVERIFY (0xad) within 2 bytes.
    // Opcode-aware: honor each push's declared length so a 0x20 byte inside
    // push DATA (an 8-byte salt, a 4-byte amount) is never misread as
    // OP_DATA_32. A naive scan skips the first real pubkey when the salt
    // contains 0x20 (~3% of salts), which mislabels every position.
    let mut idx: u8 = 0;
    let mut off = 0usize;
    while off < rs.len() {
        let op = rs[off];
        if op == 0x20 && off + 33 <= rs.len() {
            let after = off + 33;
            let has_checksig = (after < rs.len() && (rs[after] == 0xac || rs[after] == 0xad))
                || (after + 1 < rs.len() && (rs[after + 1] == 0xac || rs[after + 1] == 0xad));
            if has_checksig {
                if idx == position {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&rs[off + 1..off + 33]);
                    return Some(out);
                }
                idx = idx.saturating_add(1);
            }
            off += 33;
        } else if (0x01..=0x4b).contains(&op) {
            off += 1 + op as usize;
        } else if op == 0x4c {
            off += if off + 1 < rs.len() {
                2 + rs[off + 1] as usize
            } else {
                1
            };
        } else if op == 0x4d {
            off += if off + 2 < rs.len() {
                3 + (rs[off + 1] as usize | ((rs[off + 2] as usize) << 8))
            } else {
                1
            };
        } else if op == 0x4e {
            off += if off + 4 < rs.len() {
                5 + (rs[off + 1] as usize
                    | ((rs[off + 2] as usize) << 8)
                    | ((rs[off + 3] as usize) << 16)
                    | ((rs[off + 4] as usize) << 24))
            } else {
                1
            };
        } else {
            off += 1;
        }
    }
    None
}

/// Minimal byte reader for parse_kspt_v2_partials. Keeps the parser
/// itself readable — every field-read is a one-line call.
struct KsptReader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> KsptReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.buf.len() {
            return Err(format!(
                "KSPT truncated: want {} bytes at pos {}, only {} remain",
                n,
                self.pos,
                self.buf.len() - self.pos
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.bytes(1)?[0])
    }
    fn u16_le(&mut self) -> Result<u16, String> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32_le(&mut self) -> Result<u32, String> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64_le(&mut self) -> Result<u64, String> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
}

/// Assemble the RISC0 ZK-bridge withdrawal sig_script.
/// The bridge redeem COMMITS journal/image_id/control_id/hashfn, so only the
/// bottom four fields + owner sig + ELSE selector are supplied here:
///   <claim> <control_index> <control_digests> <seal> <owner_sig> OP_FALSE <redeem>
/// Matches the toc5-verified tier6 layout byte-for-byte.
fn build_p2sh_risc0_bridge_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    seal: &[u8],
    fields: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "RISC0 bridge claim has no owner signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad owner sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("owner sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let decode_field = |name: &str| -> Result<Vec<u8>, String> {
        let hex_str = fields
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("missing risc0 field: {}", name))?;
        hex::decode(hex_str).map_err(|e| format!("bad hex for {}: {}", name, e))
    };

    let claim = decode_field("claim")?;
    let control_index = decode_field("controlIndex")?;
    let control_digests = decode_field("controlDigests")?;

    let mut ss: Vec<u8> = Vec::with_capacity(seal.len() + 512);
    push_data_sigscript(&mut ss, &claim);
    push_data_sigscript(&mut ss, &control_index);
    push_data_sigscript(&mut ss, &control_digests);
    push_data_sigscript(&mut ss, seal);
    push_data_sigscript(&mut ss, &sig_bytes);
    ss.push(0x00); // OP_FALSE -> ELSE
    push_redeem_script(&mut ss, redeem)?;
    Ok(ss)
}

/// Assemble the keyless sig_script for an Oracle (Model B) PUBLISH (ROLL).
/// Bottom -> top: claim, control_index, control_digests, seal, journal(48),
/// OP_1 (selects the IF/ROLL branch), redeem. No signature: the oracle advances
/// purely on the committed-guest succinct proof over the committed signer set.
fn build_p2sh_oracle_mb_publish_sig_script(
    redeem: &[u8],
    seal: &[u8],
    fields: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let decode_field = |name: &str| -> Result<Vec<u8>, String> {
        let hex_str = fields
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("missing risc0 field: {}", name))?;
        hex::decode(hex_str).map_err(|e| format!("bad hex for {}: {}", name, e))
    };
    let claim = decode_field("claim")?;
    let control_index = decode_field("controlIndex")?;
    let control_digests = decode_field("controlDigests")?;
    let journal = decode_field("journal")?;
    if journal.len() != 48 {
        return Err(format!(
            "oracle journal must be 48 bytes, got {}",
            journal.len()
        ));
    }
    let mut j = [0u8; 48];
    j.copy_from_slice(&journal);
    Ok(crate::kspt::build_oracle_mb_publish_sig_script(
        redeem,
        &claim,
        &control_index,
        &control_digests,
        seal,
        &j,
    ))
}

/// Keyless Oracle (Model B) PASSTHROUGH read sig_script: OP_0 (ELSE) + redeem.
fn build_p2sh_oracle_mb_passthrough_sig_script(redeem: &[u8]) -> Result<Vec<u8>, String> {
    Ok(crate::kspt::build_oracle_mb_passthrough_sig_script(redeem))
}

/// Keyless Oracle (Model B) HEARTBEAT roll sig_script: JUST the revealed redeem.
fn build_p2sh_oracle_mb_heartbeat_sig_script(redeem: &[u8]) -> Result<Vec<u8>, String> {
    Ok(crate::kspt::build_oracle_mb_heartbeat_sig_script(redeem))
}

/// Keyless Oracle (Model B) test-consumer sig_script: JUST the revealed redeem.
fn build_p2sh_oracle_mb_consumer_sig_script(redeem: &[u8]) -> Result<Vec<u8>, String> {
    Ok(crate::kspt::build_oracle_mb_consumer_sig_script(redeem))
}

/// Assemble the Groth16-wrap bridge withdrawal sig_script (KIP-21 Step 1).
/// The redeem COMMITS vk/public-inputs/proof/tag, so the only spender-supplied
/// items are the owner signature and the ELSE selector:
///   <owner_sig> OP_FALSE <redeem>
fn build_p2sh_groth16_bridge_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "Groth16 bridge claim has no owner signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad owner sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("owner sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut ss: Vec<u8> = Vec::with_capacity(redeem.len() + 128);
    push_data_sigscript(&mut ss, &sig_bytes);
    ss.push(0x00); // OP_FALSE -> ELSE
    push_redeem_script(&mut ss, redeem)?;
    Ok(ss)
}

/// Phase 3 rollup-advance (ELSE) sig_script. The covenant commits the VK and
/// reads new_root from the tx payload; the spender supplies the proof and the
/// (prefix, suffix) template halves so the script can rebuild this-state and
/// next-state redeem hashes on-stack without embedding the root twice.
///   sig_script (bottom -> top): <proof> <prefix> <suffix> <owner_sig> OP_FALSE <redeem>
/// Byte-equivalent to kspt::build_rollup_advance_sig_script (validated against
/// rollup_sim.py); only the sig gains a trailing SIGHASH_ALL byte here.
fn build_p2sh_rollup_advance_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "rollup advance has no owner signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad owner sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("owner sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut ss: Vec<u8> =
        Vec::with_capacity(redeem.len() + proof.len() + prefix.len() + suffix.len() + 160);
    push_data_sigscript(&mut ss, proof);
    push_data_sigscript(&mut ss, prefix);
    push_data_sigscript(&mut ss, suffix);
    push_data_sigscript(&mut ss, &sig_bytes);
    ss.push(0x00); // OP_FALSE -> selects ELSE (advance)
    push_redeem_script(&mut ss, redeem)?;
    Ok(ss)
}

/// Phase 4b unified advance (nested redeem). Two selectors:
///   <proof> <prefix> <suffix> <owner_sig> OP_1 OP_0 <redeem>
/// selector2 TRUE = inner IF (advance), selector1 FALSE = outer ELSE (not reclaim).
/// Byte-equivalent to kspt::build_rollup_unified_advance_sig_script.
fn build_p2sh_rollup_unified_advance_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "unified advance has no owner signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad owner sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("owner sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut ss: Vec<u8> =
        Vec::with_capacity(redeem.len() + proof.len() + prefix.len() + suffix.len() + 160);
    push_data_sigscript(&mut ss, proof);
    push_data_sigscript(&mut ss, prefix);
    push_data_sigscript(&mut ss, suffix);
    push_data_sigscript(&mut ss, &sig_bytes);
    ss.push(0x51); // OP_1 -> selector2 TRUE  (inner IF advance)
    ss.push(0x00); // OP_0 -> selector1 FALSE (outer ELSE)
    push_redeem_script(&mut ss, redeem)?;
    Ok(ss)
}

/// Phase 4 forced exit (no operator sig). The committed account owner signs the
/// vault input; both selectors FALSE select the forced-exit (inner ELSE) branch:
///   <proof> <prefix> <suffix> <exiter_sig> OP_0 OP_0 <redeem>
/// Byte-equivalent to kspt::build_rollup_forced_exit_sig_script.
fn build_p2sh_rollup_forced_exit_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "forced exit has no account-owner signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad exiter sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("exiter sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut ss: Vec<u8> =
        Vec::with_capacity(redeem.len() + proof.len() + prefix.len() + suffix.len() + 160);
    push_data_sigscript(&mut ss, proof);
    push_data_sigscript(&mut ss, prefix);
    push_data_sigscript(&mut ss, suffix);
    push_data_sigscript(&mut ss, &sig_bytes);
    ss.push(0x00); // OP_0 -> selector2 FALSE (inner ELSE forced exit)
    ss.push(0x00); // OP_0 -> selector1 FALSE (outer ELSE)
    push_redeem_script(&mut ss, redeem)?;
    Ok(ss)
}

/// Phase 3 owner-refund (IF) sig_script, after the CLTV locktime:
///   sig_script (bottom -> top): <owner_sig> OP_1 <redeem>
fn build_p2sh_rollup_refund_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map
        .iter()
        .next()
        .ok_or_else(|| "rollup refund has no owner signature".to_string())?;
    let sig_hex = sig_val
        .get("schnorr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad owner sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex).map_err(|e| format!("owner sig hex: {}", e))?;
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut ss: Vec<u8> = Vec::with_capacity(redeem.len() + 96);
    push_data_sigscript(&mut ss, &sig_bytes);
    ss.push(0x51); // OP_1 -> selects IF (refund)
    push_redeem_script(&mut ss, redeem)?;
    Ok(ss)
}

/// Phase 4a deposit-holding credit (no-sig ELSE). The operator folds the
/// depositor's locked UTXO into the vault by supplying the vault template
/// halves; the covenant hash-checks them and rebuilds the vault address.
/// No signature is involved on this path.
///   <vault_prefix> <vault_suffix> OP_FALSE <redeem>
/// Mirrors kspt.rs::build_deposit_holding_credit_sig_script.
fn build_p2sh_deposit_holding_credit_sig_script(
    redeem: &[u8],
    vault_prefix: &[u8],
    vault_suffix: &[u8],
) -> Result<Vec<u8>, String> {
    let mut ss: Vec<u8> =
        Vec::with_capacity(redeem.len() + vault_prefix.len() + vault_suffix.len() + 16);
    push_data_sigscript(&mut ss, vault_prefix);
    push_data_sigscript(&mut ss, vault_suffix);
    ss.push(0x00); // OP_FALSE -> selects ELSE (credit)
    push_redeem_script(&mut ss, redeem)?;
    Ok(ss)
}
