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
