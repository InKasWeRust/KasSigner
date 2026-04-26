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

use serde::{Serialize, Deserialize};
use serde_json::Value;

// ═══════════════════════════════════════════════════════════════════
// Envelope detection
// ═══════════════════════════════════════════════════════════════════

/// Magic prefix for PSKB (bundle of PSKTs) wire payloads.
/// Kept `pub const` as documentation for the wire format; detection
/// itself compares the hex-ASCII form to avoid a decode step.
#[allow(dead_code)]
pub const PSKB_MAGIC: &[u8; 4] = b"PSKB";
/// Magic prefix for single-PSKT wire payloads.
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
    if hex_str.len() < 8 { return PsktFormat::Unknown; }
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
    pub script_kind: String,     // "p2pk", "p2sh", "p2sh-multisig", "unknown"
    pub script_hex: String,      // full scriptPublicKey (hex, without version prefix)
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
    pub format: String,              // "pskb" or "pskt"
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

    let wire = hex::decode(wire_hex)
        .map_err(|e| format!("Bad outer hex: {}", e))?;
    if wire.len() < 4 {
        return Err("Payload too short".into());
    }
    let body_hex = &wire[4..];
    let json_bytes = hex::decode(body_hex)
        .map_err(|e| format!("Bad inner hex: {}", e))?;

    // Parse JSON. For PSKB the body is an array; for PSKT it's an object.
    let root: Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("JSON parse: {}", e))?;
    let pskt_obj = match format {
        PsktFormat::Pskb => {
            let arr = root.as_array()
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
    let obj = pskt.as_object().ok_or_else(|| "PSKT is not an object".to_string())?;

    // ─── global ───
    let global = obj.get("global")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing global".to_string())?;
    let tx_version = global.get("txVersion")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing txVersion".to_string())? as u16;

    // ─── inputs ───
    let inputs_arr = obj.get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing inputs".to_string())?;
    let mut inputs = Vec::with_capacity(inputs_arr.len());
    let mut total_in_sompi: u64 = 0;
    let mut all_ready = true;

    for (i, inp) in inputs_arr.iter().enumerate() {
        let summary = parse_input_summary(inp)
            .map_err(|e| format!("input[{}]: {}", i, e))?;
        total_in_sompi = total_in_sompi.saturating_add(summary.amount_sompi);

        // Readiness check
        let ready_here = match (summary.multisig_m, summary.sigs_present) {
            (Some(m), present) => present >= m,
            (None, present) => present >= 1,
        };
        if !ready_here { all_ready = false; }
        inputs.push(summary);
    }

    // ─── outputs ───
    let outputs_arr = obj.get("outputs")
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
    let obj = inp.as_object().ok_or_else(|| "input not object".to_string())?;

    // utxoEntry
    let utxo = obj.get("utxoEntry")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let amount_sompi = utxo.get("amount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = utxo.get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (_spk_version, spk_script) = parse_spk_hex(spk_full)?;

    // previousOutpoint
    let op = obj.get("previousOutpoint")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let prev_tx_id = op.get("transactionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing transactionId".to_string())?.to_string();
    let prev_index = op.get("index")
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
    let (sigs_present, partial_sigs) = parse_partial_sigs_map(
        obj.get("partialSigs"),
        redeem_bytes.as_deref(),
    )?;

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
    let obj = out.as_object().ok_or_else(|| "output not object".to_string())?;
    let amount_sompi = obj.get("amount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = obj.get("scriptPublicKey")
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
    let v1 = u8::from_str_radix(&ver_hex[2..4], 16).map_err(|e| format!("bad version lo: {}", e))?;
    let version = ((v0 as u16) << 8) | (v1 as u16);
    let script = hex::decode(script_hex).map_err(|e| format!("bad script hex: {}", e))?;
    Ok((version, script))
}

fn classify_input_script(
    spk: &[u8],
    redeem: Option<&[u8]>,
) -> (String, Option<u8>, Option<u8>) {
    // P2SH: OP_BLAKE2B(0xAA) OP_DATA_32(0x20) <32> OP_EQUAL(0x87)
    let is_p2sh = spk.len() == 35 && spk[0] == 0xAA && spk[1] == 0x20 && spk[34] == 0x87;
    if is_p2sh {
        if let Some(rs) = redeem {
            if let Some((m, n)) = parse_multisig_redeem(rs) {
                return ("p2sh-multisig".into(), Some(m), Some(n));
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
        return ("p2sh".into(), Some(crate::address::encode_p2sh_address(&hash, network_prefix)));
    }
    // P2PK
    if spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xAC {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&spk[1..33]);
        return ("p2pk".into(), Some(crate::address::encode_p2pk_address(&pk, network_prefix)));
    }
    ("unknown".into(), None)
}

/// Parse a redeem script: OP_M OP_DATA_32 <pk1> ... OP_N OP_CHECKMULTISIG
/// Returns (M, N) if the shape matches.
/// Each pubkey is 32-bytes (x-only, OP_DATA_32 = 0x20). Matches the
/// KasSigner-native multisig redeem-script format from kspt.rs line 456.
fn parse_multisig_redeem(rs: &[u8]) -> Option<(u8, u8)> {
    if rs.len() < 4 { return None; }
    if rs[rs.len() - 1] != 0xAE { return None; } // OP_CHECKMULTISIG
    let op_m = rs[0];
    if !(0x51..=0x60).contains(&op_m) { return None; }
    let m = op_m - 0x50;

    // Walk pubkeys
    let mut pos = 1usize;
    let mut n: u8 = 0;
    while pos < rs.len() - 2 {
        if rs[pos] != 0x20 { return None; } // OP_DATA_32
        pos += 1;
        if pos + 32 > rs.len() { return None; }
        pos += 32;
        n = n.saturating_add(1);
    }
    // pos now should point at OP_N; next is OP_CHECKMULTISIG.
    if pos + 2 != rs.len() { return None; }
    let op_n = rs[pos];
    if !(0x51..=0x60).contains(&op_n) { return None; }
    let n_from_op = op_n - 0x50;
    if n != n_from_op { return None; }
    if m == 0 || m > n { return None; }

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
        let obj = sig_val.as_object().ok_or_else(|| "sig value not object".to_string())?;
        let sig_hex = obj.get("schnorr")
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
    if pk_hex_66.len() != 66 { return None; }
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
        if rs[pos] != 0x20 { return None; }
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
    if wire.len() < 4 { return Err("payload too short".into()); }
    let json_bytes = hex::decode(&wire[4..]).map_err(|e| format!("inner hex: {}", e))?;
    let root: Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("JSON parse: {}", e))?;
    let pskt = match format {
        PsktFormat::Pskb => {
            let arr = root.as_array().ok_or_else(|| "PSKB not array".to_string())?;
            if arr.len() != 1 { return Err(format!("PSKB must have 1 entry, got {}", arr.len())); }
            arr[0].clone()
        }
        PsktFormat::PsktSingle => root,
        PsktFormat::Unknown => unreachable!(),
    };
    let obj = pskt.as_object().ok_or_else(|| "PSKT not object".to_string())?;

    // ─── Global ───
    let global = obj.get("global").and_then(|v| v.as_object())
        .ok_or_else(|| "missing global".to_string())?;
    let tx_version = global.get("txVersion").and_then(|v| v.as_u64())
        .ok_or_else(|| "missing txVersion".to_string())? as u16;

    // ─── Input / output arrays ───
    let inputs = obj.get("inputs").and_then(|v| v.as_array())
        .ok_or_else(|| "missing inputs".to_string())?;
    let outputs = obj.get("outputs").and_then(|v| v.as_array())
        .ok_or_else(|| "missing outputs".to_string())?;
    if inputs.len() > 255 { return Err("too many inputs".into()); }
    if outputs.len() > 255 { return Err("too many outputs".into()); }

    // ─── Build KSPT v2 signed buffer ───
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    buf.extend_from_slice(b"KSPT");
    buf.push(0x02); // version = v2
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
        encode_input_kspt_v2(&mut buf, inp)
            .map_err(|e| format!("input[{}]: {}", i, e))?;
    }
    for (i, out) in outputs.iter().enumerate() {
        encode_output_kspt(&mut buf, out)
            .map_err(|e| format!("output[{}]: {}", i, e))?;
    }

    Ok(hex::encode(&buf))
}

/// Encode one input in KSPT v2 signed layout. See the module header
/// comment for the exact byte layout.
fn encode_input_kspt_v2(buf: &mut Vec<u8>, inp: &Value) -> Result<(), String> {
    let obj = inp.as_object().ok_or_else(|| "not object".to_string())?;

    // utxoEntry
    let utxo = obj.get("utxoEntry").and_then(|v| v.as_object())
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let amount = utxo.get("amount").and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = utxo.get("scriptPublicKey").and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (spk_version, spk_script) = parse_spk_hex(spk_full)?;
    if spk_script.len() > 255 {
        return Err(format!("spk too long for KSPT v2 ({} > 255)", spk_script.len()));
    }

    // outpoint
    let op = obj.get("previousOutpoint").and_then(|v| v.as_object())
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let prev_tx_id_hex = op.get("transactionId").and_then(|v| v.as_str())
        .ok_or_else(|| "missing transactionId".to_string())?;
    let prev_tx_id = hex::decode(prev_tx_id_hex)
        .map_err(|e| format!("bad tx_id hex: {}", e))?;
    if prev_tx_id.len() != 32 { return Err("tx_id not 32 bytes".into()); }
    let prev_index = op.get("index").and_then(|v| v.as_u64())
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
    let partial_map = obj.get("partialSigs")
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
        && spk_script[0] == 0xAA && spk_script[1] == 0x20 && spk_script[34] == 0x87;

    let mut sig_records: Vec<(u8, Vec<u8>)> = Vec::new();

    if is_p2sh && redeem.is_some() {
        let rs = redeem.as_ref().unwrap();
        let (required_m, _n) = parse_multisig_redeem(rs)
            .ok_or_else(|| "redeem is not a valid M-of-N multisig".to_string())?;

        for (pk_hex, sig_val) in partial_map.iter() {
            if pk_hex.len() != 66 { continue; }
            let sig_hex = sig_val.get("schnorr").and_then(|v| v.as_str())
                .ok_or_else(|| "partial sig missing schnorr variant (ECDSA unsupported)".to_string())?;
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
                sig_records.len(), required_m,
            ));
        }
    } else {
        // P2PK (or unknown non-multisig): need at least 1 sig.
        let (_pk_hex, sig_val) = partial_map.iter().next()
            .ok_or_else(|| "input has no signature".to_string())?;
        let sig_hex = sig_val.get("schnorr").and_then(|v| v.as_str())
            .ok_or_else(|| "partial sig missing schnorr variant (ECDSA unsupported)".to_string())?;
        if sig_hex.len() != 128 {
            return Err(format!("bad sig length: {}", sig_hex.len()));
        }
        let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
        sig_records.push((0u8, sig_bytes));
    }
    if sig_records.len() > 255 { return Err("too many sigs".into()); }

    // ─── Write bytes ───
    buf.extend_from_slice(&prev_tx_id);
    buf.extend_from_slice(&prev_index.to_le_bytes());
    buf.extend_from_slice(&amount.to_le_bytes());
    buf.extend_from_slice(&sequence.to_le_bytes());
    buf.push(sig_op_count);
    buf.extend_from_slice(&spk_version.to_le_bytes());
    buf.push(spk_script.len() as u8);
    buf.extend_from_slice(&spk_script);

    // sig_count + records (pubkey_pos + sighash_type + 64-byte sig)
    buf.push(sig_records.len() as u8);
    for (pos, sig) in &sig_records {
        buf.push(*pos);
        buf.push(0x01); // SIGHASH_ALL
        if sig.len() != 64 { return Err("sig must be 64 bytes".into()); }
        buf.extend_from_slice(sig);
    }

    // redeem_script_len + redeem_script_bytes
    match redeem {
        Some(rs) => {
            if rs.len() > 255 {
                return Err(format!("redeem too long for KSPT v2 ({} > 255)", rs.len()));
            }
            buf.push(rs.len() as u8);
            buf.extend_from_slice(&rs);
        }
        None => {
            buf.push(0);
        }
    }

    Ok(())
}

fn encode_output_kspt(buf: &mut Vec<u8>, out: &Value) -> Result<(), String> {
    let obj = out.as_object().ok_or_else(|| "not object".to_string())?;
    let value = obj.get("amount").and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = obj.get("scriptPublicKey").and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (spk_version, spk_script) = parse_spk_hex(spk_full)?;
    if spk_script.len() > 255 {
        return Err(format!("output spk too long ({} > 255)", spk_script.len()));
    }

    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(&spk_version.to_le_bytes());
    buf.push(spk_script.len() as u8);
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
    if wire.len() < 4 { return Err("payload too short".into()); }
    let json_bytes = hex::decode(&wire[4..]).map_err(|e| format!("inner hex: {}", e))?;
    let root: Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("JSON parse: {}", e))?;
    let pskt = match format {
        PsktFormat::Pskb => {
            let arr = root.as_array().ok_or_else(|| "PSKB not array".to_string())?;
            if arr.len() != 1 { return Err(format!("PSKB must have 1 entry, got {}", arr.len())); }
            arr[0].clone()
        }
        PsktFormat::PsktSingle => root,
        PsktFormat::Unknown => unreachable!(),
    };
    let obj = pskt.as_object().ok_or_else(|| "PSKT not object".to_string())?;

    // ─── Global ───
    let global = obj.get("global").and_then(|v| v.as_object())
        .ok_or_else(|| "missing global".to_string())?;
    let tx_version = global.get("txVersion").and_then(|v| v.as_u64())
        .ok_or_else(|| "missing txVersion".to_string())? as u16;

    // ─── Input / output arrays ───
    let inputs = obj.get("inputs").and_then(|v| v.as_array())
        .ok_or_else(|| "missing inputs".to_string())?;
    let outputs = obj.get("outputs").and_then(|v| v.as_array())
        .ok_or_else(|| "missing outputs".to_string())?;
    if inputs.len() > 255 { return Err("too many inputs".into()); }
    if outputs.len() > 255 { return Err("too many outputs".into()); }

    // ─── Build KSPT v2 partial buffer ───
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    buf.extend_from_slice(b"KSPT");
    buf.push(0x02); // version = v2
    buf.push(0x00); // flags   = partial (RELAY)
    buf.extend_from_slice(&tx_version.to_le_bytes());
    buf.push(inputs.len() as u8);
    buf.push(outputs.len() as u8);
    buf.extend_from_slice(&0u64.to_le_bytes());           // locktime
    buf.extend_from_slice(&[0u8; 20]);                    // subnetwork_id
    buf.extend_from_slice(&0u64.to_le_bytes());           // gas
    buf.extend_from_slice(&0u16.to_le_bytes());           // payload_len

    for (i, inp) in inputs.iter().enumerate() {
        encode_input_kspt_v2_relay(&mut buf, inp)
            .map_err(|e| format!("input[{}]: {}", i, e))?;
    }
    for (i, out) in outputs.iter().enumerate() {
        encode_output_kspt(&mut buf, out)
            .map_err(|e| format!("output[{}]: {}", i, e))?;
    }

    Ok(hex::encode(&buf))
}

/// Encode one input in KSPT v2 layout for RELAY: carries 0..=N sigs,
/// no M-of-N gate. Byte-for-byte identical to `encode_input_kspt_v2`
/// except that empty `partialSigs` is allowed.
fn encode_input_kspt_v2_relay(buf: &mut Vec<u8>, inp: &Value) -> Result<(), String> {
    let obj = inp.as_object().ok_or_else(|| "not object".to_string())?;

    // utxoEntry
    let utxo = obj.get("utxoEntry").and_then(|v| v.as_object())
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let amount = utxo.get("amount").and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = utxo.get("scriptPublicKey").and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (spk_version, spk_script) = parse_spk_hex(spk_full)?;
    if spk_script.len() > 255 {
        return Err(format!("spk too long for KSPT v2 ({} > 255)", spk_script.len()));
    }

    // outpoint
    let op = obj.get("previousOutpoint").and_then(|v| v.as_object())
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let prev_tx_id_hex = op.get("transactionId").and_then(|v| v.as_str())
        .ok_or_else(|| "missing transactionId".to_string())?;
    let prev_tx_id = hex::decode(prev_tx_id_hex)
        .map_err(|e| format!("bad tx_id hex: {}", e))?;
    if prev_tx_id.len() != 32 { return Err("tx_id not 32 bytes".into()); }
    let prev_index = op.get("index").and_then(|v| v.as_u64())
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
    let partial_map = obj.get("partialSigs")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let is_p2sh = spk_script.len() == 35
        && spk_script[0] == 0xAA && spk_script[1] == 0x20 && spk_script[34] == 0x87;

    let mut sig_records: Vec<(u8, Vec<u8>)> = Vec::new();

    if is_p2sh && redeem.is_some() {
        let rs = redeem.as_ref().unwrap();
        // Parse redeem to validate it's well-formed; M is not checked for relay.
        let _ = parse_multisig_redeem(rs)
            .ok_or_else(|| "redeem is not a valid M-of-N multisig".to_string())?;

        for (pk_hex, sig_val) in partial_map.iter() {
            if pk_hex.len() != 66 { continue; }
            let sig_hex = sig_val.get("schnorr").and_then(|v| v.as_str())
                .ok_or_else(|| "partial sig missing schnorr variant (ECDSA unsupported)".to_string())?;
            if sig_hex.len() != 128 {
                return Err(format!("bad sig length: {}", sig_hex.len()));
            }
            let pos = find_pubkey_position_in_redeem(rs, pk_hex)
                .ok_or_else(|| format!("pubkey not in redeem: {}", pk_hex))?;
            let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
            sig_records.push((pos, sig_bytes));
        }
        sig_records.sort_by_key(|t| t.0);
        // No `sig_records.len() < required_m` gate — relay allows 0..=N.
    } else {
        // P2PK (or non-multisig P2SH): carry the one sig if present,
        // otherwise emit an empty sig list. Relay must not reject inputs
        // that have not been signed yet.
        if let Some((_pk_hex, sig_val)) = partial_map.iter().next() {
            let sig_hex = sig_val.get("schnorr").and_then(|v| v.as_str())
                .ok_or_else(|| "partial sig missing schnorr variant (ECDSA unsupported)".to_string())?;
            if sig_hex.len() != 128 {
                return Err(format!("bad sig length: {}", sig_hex.len()));
            }
            let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {}", e))?;
            sig_records.push((0u8, sig_bytes));
        }
    }
    if sig_records.len() > 255 { return Err("too many sigs".into()); }

    // ─── Write bytes (layout identical to encode_input_kspt_v2) ───
    buf.extend_from_slice(&prev_tx_id);
    buf.extend_from_slice(&prev_index.to_le_bytes());
    buf.extend_from_slice(&amount.to_le_bytes());
    buf.extend_from_slice(&sequence.to_le_bytes());
    buf.push(sig_op_count);
    buf.extend_from_slice(&spk_version.to_le_bytes());
    buf.push(spk_script.len() as u8);
    buf.extend_from_slice(&spk_script);

    buf.push(sig_records.len() as u8);
    for (pos, sig) in &sig_records {
        buf.push(*pos);
        buf.push(0x01); // SIGHASH_ALL
        if sig.len() != 64 { return Err("sig must be 64 bytes".into()); }
        buf.extend_from_slice(sig);
    }

    match redeem {
        Some(rs) => {
            if rs.len() > 255 {
                return Err(format!("redeem too long for KSPT v2 ({} > 255)", rs.len()));
            }
            buf.push(rs.len() as u8);
            buf.extend_from_slice(&rs);
        }
        None => {
            buf.push(0);
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
pub async fn finalize_and_broadcast(
    wire_hex: &str,
    ws_url: &str,
) -> Result<String, String> {
    let format = detect_format_hex(wire_hex);
    if format == PsktFormat::Unknown {
        return Err("Not a PSKT/PSKB payload".into());
    }
    let wire = hex::decode(wire_hex).map_err(|e| format!("outer hex: {}", e))?;
    if wire.len() < 4 { return Err("payload too short".into()); }
    let json_bytes = hex::decode(&wire[4..]).map_err(|e| format!("inner hex: {}", e))?;
    let root: Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("JSON parse: {}", e))?;
    let pskt = match format {
        PsktFormat::Pskb => {
            let arr = root.as_array().ok_or_else(|| "PSKB not array".to_string())?;
            if arr.len() != 1 {
                return Err(format!("PSKB must have 1 entry, got {}", arr.len()));
            }
            arr[0].clone()
        }
        PsktFormat::PsktSingle => root,
        PsktFormat::Unknown => unreachable!(),
    };
    let obj = pskt.as_object().ok_or_else(|| "PSKT not object".to_string())?;

    // ─── Global ───
    let global = obj.get("global").and_then(|v| v.as_object())
        .ok_or_else(|| "missing global".to_string())?;
    let tx_version = global.get("txVersion").and_then(|v| v.as_u64())
        .ok_or_else(|| "missing txVersion".to_string())? as u16;

    // ─── Walk inputs, assemble consensus inputs ───
    let inputs_json = obj.get("inputs").and_then(|v| v.as_array())
        .ok_or_else(|| "missing inputs".to_string())?;
    let mut consensus_inputs: Vec<crate::rpc::ConsensusInput> =
        Vec::with_capacity(inputs_json.len());

    for (i, inp) in inputs_json.iter().enumerate() {
        let ci = build_consensus_input(inp)
            .map_err(|e| format!("input[{}]: {}", i, e))?;
        consensus_inputs.push(ci);
    }

    // ─── Walk outputs ───
    let outputs_json = obj.get("outputs").and_then(|v| v.as_array())
        .ok_or_else(|| "missing outputs".to_string())?;
    let mut consensus_outputs: Vec<crate::rpc::ConsensusOutput> =
        Vec::with_capacity(outputs_json.len());

    for (i, out) in outputs_json.iter().enumerate() {
        let co = build_consensus_output(out)
            .map_err(|e| format!("output[{}]: {}", i, e))?;
        consensus_outputs.push(co);
    }

    // Standard tx: zero locktime, zero subnetwork, zero gas, empty payload.
    let subnetwork_id = [0u8; 20];
    let tx_payload: Vec<u8> = Vec::new();

    web_sys::console::log_1(&format!(
        "[KasSee] PSKT-native broadcast: {} input(s), {} output(s), tx_version={}",
        consensus_inputs.len(), consensus_outputs.len(), tx_version,
    ).into());

    crate::rpc::submit_consensus_tx(
        ws_url,
        tx_version,
        &consensus_inputs,
        &consensus_outputs,
        0,              // locktime
        &subnetwork_id,
        0,              // gas
        &tx_payload,
    ).await
}

/// Build one consensus-layer `ConsensusInput` from a PSKT input object,
/// assembling the final `sig_script` directly from partial sigs + the
/// redeem script (for P2SH) or the single Schnorr sig (for P2PK).
fn build_consensus_input(inp: &Value) -> Result<crate::rpc::ConsensusInput, String> {
    let obj = inp.as_object().ok_or_else(|| "not object".to_string())?;

    // utxoEntry → scriptPublicKey (used for classification)
    let utxo = obj.get("utxoEntry").and_then(|v| v.as_object())
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let spk_full = utxo.get("scriptPublicKey").and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (_spk_version, spk_script) = parse_spk_hex(spk_full)?;

    // Outpoint
    let op = obj.get("previousOutpoint").and_then(|v| v.as_object())
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let prev_tx_id_hex = op.get("transactionId").and_then(|v| v.as_str())
        .ok_or_else(|| "missing transactionId".to_string())?;
    let prev_tx_vec = hex::decode(prev_tx_id_hex)
        .map_err(|e| format!("bad tx_id hex: {}", e))?;
    if prev_tx_vec.len() != 32 { return Err("tx_id not 32 bytes".into()); }
    let mut prev_tx_id = [0u8; 32];
    prev_tx_id.copy_from_slice(&prev_tx_vec);
    let prev_index = op.get("index").and_then(|v| v.as_u64())
        .ok_or_else(|| "missing index".to_string())? as u32;

    let sequence = obj.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0);
    let sig_op_count = obj.get("sigOpCount").and_then(|v| v.as_u64())
        .unwrap_or(1) as u8;

    // redeemScript
    let redeem: Option<Vec<u8>> = match obj.get("redeemScript") {
        Some(v) if v.is_null() => None,
        Some(Value::String(s)) => Some(hex::decode(s)
            .map_err(|e| format!("redeem hex: {}", e))?),
        _ => None,
    };

    // partialSigs map
    let partial_map = obj.get("partialSigs")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    // Branch on script kind
    let is_p2sh = spk_script.len() == 35
        && spk_script[0] == 0xAA && spk_script[1] == 0x20 && spk_script[34] == 0x87;

    let sig_script = if is_p2sh && redeem.is_some() {
        let rs = redeem.as_ref().unwrap();
        build_p2sh_multisig_sig_script(rs, &partial_map)?
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
    let value = obj.get("amount").and_then(|v| v.as_u64())
        .ok_or_else(|| "missing amount".to_string())?;
    let spk_full = obj.get("scriptPublicKey").and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (spk_version, spk_script) = parse_spk_hex(spk_full)?;
    Ok(crate::rpc::ConsensusOutput { value, spk_version, spk_script })
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
fn build_p2sh_multisig_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (m, _n) = parse_multisig_redeem(redeem)
        .ok_or_else(|| "redeem not a valid M-of-N multisig".to_string())?;

    // (pubkey_pos, sig||sighash) per available partial sig
    let mut sigs: Vec<(u8, Vec<u8>)> = Vec::with_capacity(partial_map.len());
    for (pk_hex, sig_val) in partial_map.iter() {
        if pk_hex.len() != 66 { continue; }
        let sig_hex = sig_val.get("schnorr").and_then(|v| v.as_str())
            .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
        if sig_hex.len() != 128 {
            return Err(format!("bad sig length: {}", sig_hex.len()));
        }
        let pos = find_pubkey_position_in_redeem(redeem, pk_hex)
            .ok_or_else(|| format!("pubkey not in redeem: {}", pk_hex))?;
        let mut sig_bytes = hex::decode(sig_hex)
            .map_err(|e| format!("sig hex: {}", e))?;
        sig_bytes.push(0x01); // SIGHASH_ALL
        sigs.push((pos, sig_bytes));
    }
    sigs.sort_by_key(|t| t.0);

    if sigs.len() < m as usize {
        return Err(format!("only {} sig(s), need {}", sigs.len(), m));
    }

    let mut sig_script: Vec<u8> =
        Vec::with_capacity((m as usize) * 66 + redeem.len() + 2);

    // NOTE: unlike Bitcoin's OP_CHECKMULTISIG, Kaspa's OpCheckMultiSig
    // does NOT pop an extra dummy element. No leading OP_0. Verified
    // against crypto/txscript test vector at lib.rs:1000.

    // Push first M sigs in redeem-script pubkey order.
    for (_pos, sig) in sigs.iter().take(m as usize) {
        sig_script.push(sig.len() as u8); // 65
        sig_script.extend_from_slice(sig);
    }

    // Push redeem script (OP_PUSHDATA1 for >75 bytes).
    if redeem.len() <= 75 {
        sig_script.push(redeem.len() as u8);
    } else if redeem.len() <= 255 {
        sig_script.push(0x4C); // OP_PUSHDATA1
        sig_script.push(redeem.len() as u8);
    } else {
        return Err("redeem script too large for OP_PUSHDATA1".into());
    }
    sig_script.extend_from_slice(redeem);

    Ok(sig_script)
}

/// Assemble the final sig_script for a P2PK input.
/// Layout: `<push 65 sig||sighash>` — single 65-byte push.
fn build_p2pk_sig_script(
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_val) = partial_map.iter().next()
        .ok_or_else(|| "P2PK input has no signature".to_string())?;
    let sig_hex = sig_val.get("schnorr").and_then(|v| v.as_str())
        .ok_or_else(|| "partial sig missing schnorr variant".to_string())?;
    if sig_hex.len() != 128 {
        return Err(format!("bad sig length: {}", sig_hex.len()));
    }
    let mut sig_bytes = hex::decode(sig_hex)
        .map_err(|e| format!("sig hex: {}", e))?;
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
    let utxo = inp.get("utxoEntry")
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("input[{}] missing utxoEntry", input_idx))?;
    let spk_full = utxo.get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("input[{}] missing scriptPublicKey", input_idx))?;
    // spk_full is "0000" + hex(script). Skip 4 hex chars (version).
    if spk_full.len() < 4 + 68 {
        return Err(format!("input[{}] scriptPublicKey too short for P2PK", input_idx));
    }
    let script_hex = &spk_full[4..];
    let script = hex::decode(script_hex)
        .map_err(|e| format!("input[{}] spk hex: {}", input_idx, e))?;
    if script.len() != 34 || script[0] != 0x20 || script[33] != 0xAC {
        return Err(format!("input[{}] spk is not P2PK", input_idx));
    }
    let pk_hex = format!("02{}", hex::encode(&script[1..33]));

    if !matches!(inp.get("partialSigs"), Some(Value::Object(_))) {
        inp.insert("partialSigs".to_string(), Value::Object(Default::default()));
    }
    let partial_map = inp.get_mut("partialSigs")
        .and_then(|v| v.as_object_mut())
        .expect("just inserted/verified");

    if !partial_map.contains_key(&pk_hex) {
        let sig_hex = hex::encode(&rec.sig);
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
    let kspt = hex::decode(signed_kspt_hex)
        .map_err(|e| format!("KSPT hex: {}", e))?;
    if kspt.len() < 5 {
        return Err("KSPT blob too short".into());
    }
    let kspt_version = kspt[4];

    // ── 2. Parse PSKB envelope ──
    let format = detect_format_hex(pskb_wire_hex);
    if format == PsktFormat::Unknown {
        return Err("Not a PSKT/PSKB payload".into());
    }
    let wire = hex::decode(pskb_wire_hex)
        .map_err(|e| format!("outer hex: {}", e))?;
    if wire.len() < 4 { return Err("payload too short".into()); }
    let magic = wire[0..4].to_vec();
    let json_bytes = hex::decode(&wire[4..])
        .map_err(|e| format!("inner hex: {}", e))?;
    let mut root: Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("JSON parse: {}", e))?;

    // ── 3. Locate the inputs array (PSKB wraps in a 1-element array) ──
    let inputs_mut: &mut Vec<Value> = match format {
        PsktFormat::Pskb => {
            let arr = root.as_array_mut()
                .ok_or_else(|| "PSKB not array".to_string())?;
            if arr.len() != 1 {
                return Err(format!("PSKB must have 1 entry, got {}", arr.len()));
            }
            let pskt = arr[0].as_object_mut()
                .ok_or_else(|| "PSKB entry not object".to_string())?;
            pskt.get_mut("inputs")
                .and_then(|v| v.as_array_mut())
                .ok_or_else(|| "missing inputs".to_string())?
        }
        PsktFormat::PsktSingle => {
            let pskt = root.as_object_mut()
                .ok_or_else(|| "PSKT not object".to_string())?;
            pskt.get_mut("inputs")
                .and_then(|v| v.as_array_mut())
                .ok_or_else(|| "missing inputs".to_string())?
        }
        PsktFormat::Unknown => unreachable!(),
    };

    // ── 4. Branch on KSPT version ──
    if kspt_version == 0x02 {
        // ── v2: multisig path (pubkey_pos + redeem script) ──
        let per_input = parse_kspt_v2_partials(&kspt)?;

        if inputs_mut.len() != per_input.len() {
            return Err(format!(
                "input count mismatch: PSKB has {}, KSPT v2 has {}",
                inputs_mut.len(), per_input.len()
            ));
        }

        for (i, sigs_at_input) in per_input.iter().enumerate() {
            if sigs_at_input.is_empty() { continue; }

            let inp = inputs_mut[i].as_object_mut()
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
            let redeem = hex::decode(&redeem_hex)
                .map_err(|e| format!("input[{}] redeem hex: {}", i, e))?;

            if !matches!(inp.get("partialSigs"), Some(Value::Object(_))) {
                inp.insert("partialSigs".to_string(), Value::Object(Default::default()));
            }
            let partial_map = inp.get_mut("partialSigs")
                .and_then(|v| v.as_object_mut())
                .expect("just inserted/verified");

            for rec in sigs_at_input {
                let xonly = xonly_at_position(&redeem, rec.pubkey_pos)
                    .ok_or_else(|| format!(
                        "input[{}] pubkey_pos {} out of range for redeem",
                        i, rec.pubkey_pos
                    ))?;
                let pk_hex = format!("02{}", hex::encode(xonly));

                if partial_map.contains_key(&pk_hex) {
                    continue;
                }

                let sig_hex = hex::encode(&rec.sig);
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
                inputs_mut.len(), v1_records.len()
            ));
        }

        for (i, rec) in v1_records.iter().enumerate() {
            // Skip unsigned inputs (sig is all zeros)
            if rec.sig == [0u8; 64] { continue; }

            let inp = inputs_mut[i].as_object_mut()
                .ok_or_else(|| format!("input[{}] not object", i))?;

            // Extract x-only pubkey from P2PK script
            let spk = &rec.spk;
            if spk.len() != 34 || spk[0] != 0x20 || spk[33] != 0xAC {
                return Err(format!(
                    "input[{}] KSPT v1 spk is not P2PK (len={}, expected 34)",
                    i, spk.len()
                ));
            }
            let pk_hex = format!("02{}", hex::encode(&spk[1..33]));

            if !matches!(inp.get("partialSigs"), Some(Value::Object(_))) {
                inp.insert("partialSigs".to_string(), Value::Object(Default::default()));
            }
            let partial_map = inp.get_mut("partialSigs")
                .and_then(|v| v.as_object_mut())
                .expect("just inserted/verified");

            if !partial_map.contains_key(&pk_hex) {
                let sig_hex = hex::encode(&rec.sig);
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
    let new_json = serde_json::to_vec(&root)
        .map_err(|e| format!("re-serialize: {}", e))?;
    let mut wire_bytes: Vec<u8> = Vec::with_capacity(4 + new_json.len() * 2);
    wire_bytes.extend_from_slice(&magic);
    wire_bytes.extend_from_slice(hex::encode(&new_json).as_bytes());
    Ok(hex::encode(&wire_bytes))
}

/// One sig record as parsed from a KSPT v2 input section.
struct KsptSigRecord {
    pubkey_pos: u8,
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
    if version != 0x02 {
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
        let spk_len = r.u8()? as usize;
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

        // Redeem script (may be empty for P2PK)
        let rs_len = r.u8()? as usize;
        if rs_len > 0 {
            let _ = r.bytes(rs_len)?;
        }
        out.push(sigs);
    }

    // Outputs — read to validate length, no data needed for merge
    for _ in 0..num_out {
        let _value = r.u64_le()?;
        let _spk_version = r.u16_le()?;
        let spk_len = r.u8()? as usize;
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
    let _flags = r.u8()?;
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
        let spk_len = r.u8()? as usize;
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
        let spk_len = r.u8()? as usize;
        let _ = r.bytes(spk_len)?;
    }

    Ok(out)
}

/// Return the 32-byte x-only pubkey at the given 0-indexed slot in a
/// redeem script. Mirrors `find_pubkey_position_in_redeem` but in the
/// opposite direction.
fn xonly_at_position(rs: &[u8], position: u8) -> Option<[u8; 32]> {
    if rs.len() < 4 { return None; }
    let mut pos = 1usize; // skip OP_M
    let mut idx: u8 = 0;
    while pos + 33 <= rs.len() {
        if rs[pos] != 0x20 { return None; } // OP_DATA_32
        if idx == position {
            let mut out = [0u8; 32];
            out.copy_from_slice(&rs[pos + 1..pos + 33]);
            return Some(out);
        }
        pos += 33;
        idx = idx.saturating_add(1);
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
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.buf.len() {
            return Err(format!(
                "KSPT truncated: want {} bytes at pos {}, only {} remain",
                n, self.pos, self.buf.len() - self.pos
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> { Ok(self.bytes(1)?[0]) }
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

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_pskb() {
        // "PSKB" = 0x50 0x53 0x4B 0x42 → "50534b42"
        assert_eq!(detect_format_hex("50534b42deadbeef"), PsktFormat::Pskb);
        assert_eq!(detect_format_hex("50534B42DEADBEEF"), PsktFormat::Pskb); // case-insensitive
    }

    #[test]
    fn detect_pskt() {
        // "PSKT" = 0x50 0x53 0x4B 0x54 → "50534b54"
        assert_eq!(detect_format_hex("50534b54aa"), PsktFormat::PsktSingle);
    }

    #[test]
    fn detect_kspt_is_unknown() {
        // "KSPT" = 0x4B 0x53 0x50 0x54 → "4b535054"
        assert_eq!(detect_format_hex("4b535054000001"), PsktFormat::Unknown);
    }

    #[test]
    fn detect_short_is_unknown() {
        assert_eq!(detect_format_hex("505"), PsktFormat::Unknown);
    }

    #[test]
    fn parse_multisig_redeem_2of3() {
        // OP_2 [OP_DATA_32 <32>]×3 OP_3 OP_CHECKMULTISIG
        let mut rs = vec![0x52]; // OP_2
        for _ in 0..3 {
            rs.push(0x20);
            rs.extend_from_slice(&[0u8; 32]);
        }
        rs.push(0x53); // OP_3
        rs.push(0xAE); // OP_CHECKMULTISIG
        assert_eq!(parse_multisig_redeem(&rs), Some((2, 3)));
    }

    #[test]
    fn parse_multisig_redeem_rejects_truncated() {
        let rs = vec![0x52, 0x20, 0x01, 0x02]; // too short
        assert_eq!(parse_multisig_redeem(&rs), None);
    }

    #[test]
    fn find_position_finds_pubkey() {
        // Build a redeem with a known pubkey at position 1
        let pk1 = [0x11u8; 32];
        let pk2 = [0x22u8; 32];
        let pk3 = [0x33u8; 32];
        let mut rs = vec![0x52]; // OP_2
        rs.push(0x20); rs.extend_from_slice(&pk1);
        rs.push(0x20); rs.extend_from_slice(&pk2);
        rs.push(0x20); rs.extend_from_slice(&pk3);
        rs.push(0x53); // OP_3
        rs.push(0xAE);

        // Compressed form: prefix 02 + xonly
        let pk_hex = format!("02{}", hex::encode(pk2));
        assert_eq!(find_pubkey_position_in_redeem(&rs, &pk_hex), Some(1));
    }
}
