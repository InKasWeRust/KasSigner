// KasSee Web — Watch-only companion wallet for KasSigner
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// lib.rs — WASM entry point. Exports wallet operations to JavaScript.
// All Kaspa logic runs in the browser. No server, no backend.

//! # KasSee Web
//!
//! Watch-only companion wallet for KasSigner, compiled to WebAssembly. This crate
//! is the `wasm-bindgen` boundary: every `pub fn` here and in the `*_api` modules
//! is a JS-callable export. Signing never happens here — KasSee builds *unsigned*
//! transactions (KSPT binary or PSKB bundles), the air-gapped KasSigner signs them,
//! and KasSee broadcasts the result.
//!
//! ## Module map
//! - `kspt` — core KSPT/PSKB transaction construction and the shared script
//!   primitives (opcode table, push helpers); the covenant redeem-script builders
//!   live in its `kspt_*` submodules (oracle-mb, KIP-10, merkle, vault,
//!   state-machine, commit-reveal, crowdfund) and are re-exported as `kspt::build_*`.
//! - `pskt` — PSKT/PSKB wire-format engine (encode/decode, finalize, relay).
//! - `*_api` — JS export surfaces grouped by feature: `adaptor_api`, `stealth_api`,
//!   `oracle_mb_api`, `vault_api`, `covenant_api`, `zk_api`.
//! - `address`, `bip32`, `qr`, `rpc`, `stealth`, `adaptor`, `zkproof` — supporting
//!   primitives (addresses, key derivation, animated QR, node RPC, stealth crypto,
//!   adaptor signatures, Groth16 proofs).
//!
//! ## Flow
//! ```ignore
//! // 1. scan the kpub QR from KasSigner -> derive watch-only wallet state
//! // 2. build an unsigned tx (KSPT/PSKB) with the create_* / covenant_* exports
//! // 3. show it as a QR for KasSigner to sign; scan the signed result back
//! // 4. broadcast with the rpc broadcast export
//! ```

#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::type_complexity)]
mod adaptor;
mod adaptor_api;
mod address;
mod bip32;
mod covenant_api;
mod kspt;
mod oracle_mb_api;
mod pskt;
mod qr;
mod rpc;
mod stealth;
mod stealth_api;
mod vault_api;
mod zk_api;
mod zkproof;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ─── Network → prefix mapping ───

pub(crate) fn network_to_prefix(network: &str) -> &'static str {
    match network {
        "testnet-10" | "testnet-11" | "testnet-12" => "kaspatest",
        "simnet" => "kaspasim",
        "devnet" => "kaspadev",
        _ => "kaspa", // mainnet and anything else
    }
}

pub(crate) fn hex_to_pubkey32(hex_str: &str) -> Result<[u8; 32], JsValue> {
    let bytes = hex::decode(hex_str).map_err(|e| JsValue::from_str(&format!("Bad hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("Pubkey must be 32 bytes"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes);
    Ok(pk)
}

// ─── kpub import ───

/// Import a kpub string + network → derive 20 receive + 20 change addresses → return JSON
#[wasm_bindgen]
pub fn import_kpub(kpub_str: &str, network: &str) -> Result<String, JsValue> {
    let prefix = network_to_prefix(network);
    let result = bip32::import_kpub(kpub_str, prefix).map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Import a V1-raw compact kpub (78 raw payload bytes — the header
/// byte 0x01 should already be stripped by the JS side). Same output
/// as `import_kpub` — the raw payload is re-encoded to a standard
/// base58check kpub internally so all downstream paths (storage, UI,
/// RPC) are unchanged.
#[wasm_bindgen]
pub fn import_kpub_raw(raw_payload: &[u8], network: &str) -> Result<String, JsValue> {
    let prefix = network_to_prefix(network);
    let result = bip32::import_kpub_raw(raw_payload, prefix).map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Derive additional receive/change addresses beyond the current set.
#[wasm_bindgen]
pub fn extend_addresses(
    wallet_json: &str,
    extra_receive: u32,
    extra_change: u32,
    network: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    let prefix = network_to_prefix(network);
    let result = bip32::extend_addresses(&wallet, extra_receive, extra_change, prefix)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Balance ───

/// Connect to node via Borsh wRPC, fetch UTXOs, return JSON balance.
#[wasm_bindgen]
pub async fn fetch_balance(wallet_json: &str, ws_url: &str) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    let balance = rpc::fetch_balance(ws_url, &wallet)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&balance).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Fetch all UTXOs as JSON array
#[wasm_bindgen]
pub async fn fetch_utxos(wallet_json: &str, ws_url: &str) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    let utxos = rpc::fetch_all_utxos(ws_url, &wallet)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&utxos).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Fee estimation ───

/// Query node for current fee rates → return JSON
#[wasm_bindgen]
pub async fn get_fee_estimate(ws_url: &str) -> Result<String, JsValue> {
    let estimate = rpc::get_fee_estimate(ws_url)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&estimate).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Send (create unsigned KSPT) ───

/// Build unsigned KSPT from wallet, destination, amount, fee → return hex
#[wasm_bindgen]
pub async fn create_send_kspt(
    wallet_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    kspt::create_send_kspt(&wallet, dest_address, amount_sompi, fee_sompi, ws_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Consolidate all UTXOs into one
#[wasm_bindgen]
pub async fn create_consolidate_kspt(
    wallet_json: &str,
    fee_sompi: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    kspt::create_consolidate_kspt(&wallet, fee_sompi, ws_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Create unsigned KSPT with specific UTXO indices (comma-separated)
#[wasm_bindgen]
pub async fn create_send_kspt_selected(
    wallet_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    utxo_indices_csv: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    let indices: Vec<usize> = utxo_indices_csv
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().parse::<usize>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid index: {}", e)))?;
    kspt::create_send_kspt_selected(
        &wallet,
        dest_address,
        amount_sompi,
        fee_sompi,
        &indices,
        ws_url,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))
}

/// Create compound KSPT with multiple recipients
/// recipients_json: [{"address":"kaspa:...","amount_sompi":"150000000"}, ...]
#[wasm_bindgen]
pub async fn create_compound_kspt(
    wallet_json: &str,
    recipients_json: &str,
    fee_sompi: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    kspt::create_compound_kspt(&wallet, recipients_json, fee_sompi, ws_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Create unsigned multisig spend KSPT
/// descriptor: "multi(2,pk1hex,...)" or "multi_hd(2,xpub130hex,...)"
/// addr_index: HD derivation index (0 for legacy multi(...) descriptors)
/// source_address: the P2SH multisig address holding the funds
/// change_address: where change goes (typically same P2SH address)
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_multisig_kspt(
    descriptor: &str,
    source_address: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    change_address: &str,
    ws_url: &str,
    addr_index: u32,
) -> Result<String, JsValue> {
    kspt::create_multisig_kspt(
        descriptor,
        source_address,
        dest_address,
        amount_sompi,
        fee_sompi,
        change_address,
        ws_url,
        addr_index,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))
}

/// Build an unsigned multisig PSKB — Path 2. Same semantics as
/// `create_multisig_kspt` but emits a Kaspa-standard PSKB wire blob
/// instead of legacy KSPT v1 binary.
///
/// The output goes directly to `openPsktReview` on the JS side,
/// landing the user on the Review PSKB screen with 0/M sigs where
/// they can pick Relay → (Any wallet | KasSigner compact).
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_multisig_pskb(
    descriptor: &str,
    source_address: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    change_address: &str,
    ws_url: &str,
    addr_index: u32,
) -> Result<String, JsValue> {
    kspt::create_multisig_pskb(
        descriptor,
        source_address,
        dest_address,
        amount_sompi,
        fee_sompi,
        change_address,
        ws_url,
        addr_index,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))
}

/// Same as `create_multisig_pskb` but with explicit UTXO indices
/// instead of greedy auto-selection.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_multisig_pskb_selected(
    descriptor: &str,
    source_address: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    change_address: &str,
    ws_url: &str,
    addr_index: u32,
    utxo_csv: &str,
) -> Result<String, JsValue> {
    let indices: Vec<usize> = utxo_csv
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    kspt::create_multisig_pskb_selected(
        descriptor,
        source_address,
        dest_address,
        amount_sompi,
        fee_sompi,
        change_address,
        ws_url,
        addr_index,
        &indices,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))
}

/// Fetch UTXOs for a single address (for multisig balance check) → JSON array
#[wasm_bindgen]
pub async fn fetch_utxos_for_address_js(address: &str, ws_url: &str) -> Result<String, JsValue> {
    let utxos = rpc::fetch_utxos_for_address(ws_url, address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&utxos).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Single-sig PSKB (standard PSKT wire format for P2PK) ───

/// Create unsigned single-sig PSKB — same as `create_send_kspt` but
/// emits a standard PSKB wire blob. Routes through the PSKT review
/// screen on the JS side (same flow as multisig PSKB).
#[wasm_bindgen]
pub async fn create_send_pskb(
    wallet_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet: {}", e)))?;
    kspt::create_send_pskb(&wallet, dest_address, amount_sompi, fee_sompi, ws_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Consolidate all UTXOs into one via PSKB format.
#[wasm_bindgen]
pub async fn create_consolidate_pskb(
    wallet_json: &str,
    fee_sompi: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet: {}", e)))?;
    kspt::create_consolidate_pskb(&wallet, fee_sompi, ws_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Create unsigned PSKB with specific UTXO indices.
#[wasm_bindgen]
pub async fn create_send_pskb_selected(
    wallet_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    utxo_csv: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet: {}", e)))?;
    let indices: Vec<usize> = utxo_csv
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    kspt::create_send_pskb_selected(
        &wallet,
        dest_address,
        amount_sompi,
        fee_sompi,
        &indices,
        ws_url,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))
}

/// Create unsigned PSKB with explicit UTXO data (no re-fetch, no stale indices).
/// utxos_json: JSON array of {tx_id, index, amount, script_public_key, block_daa_score} objects.
#[wasm_bindgen]
pub async fn create_send_pskb_with_utxos(
    wallet_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    utxos_json: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet: {}", e)))?;
    let utxos: Vec<rpc::UtxoEntry> = serde_json::from_str::<Vec<serde_json::Value>>(utxos_json)
        .map_err(|e| JsValue::from_str(&format!("Bad UTXOs JSON: {}", e)))?
        .iter()
        .map(|v| {
            // script_public_key can be a JSON array of bytes [0,32,...] or a hex string
            let spk_bytes = if let Some(arr) = v["script_public_key"].as_array() {
                arr.iter()
                    .filter_map(|b| b.as_u64().map(|n| n as u8))
                    .collect()
            } else if let Some(hex_str) = v["script_public_key"].as_str() {
                hex::decode(hex_str).unwrap_or_default()
            } else {
                Vec::new()
            };
            rpc::UtxoEntry {
                tx_id: v["tx_id"].as_str().unwrap_or("").to_string(),
                index: v["index"].as_u64().unwrap_or(0) as u32,
                amount: v["amount"].as_u64().unwrap_or(0),
                script_public_key: spk_bytes,
                block_daa_score: v["block_daa_score"].as_u64().unwrap_or(0),
                covenant_id: None,
            }
        })
        .collect();
    kspt::create_send_pskb_with_utxos(
        &wallet,
        dest_address,
        amount_sompi,
        fee_sompi,
        utxos,
        ws_url,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))
}

/// Create compound unsigned PSKB: multiple recipients.
#[wasm_bindgen]
pub async fn create_compound_pskb(
    wallet_json: &str,
    recipients_json: &str,
    fee_sompi: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet: {}", e)))?;
    kspt::create_compound_pskb(&wallet, recipients_json, fee_sompi, ws_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

// ─── Broadcast ───

/// Broadcast a signed KSPT hex to the network → return TX ID
#[wasm_bindgen]
pub async fn broadcast_signed(signed_hex: &str, ws_url: &str) -> Result<String, JsValue> {
    rpc::broadcast_signed(ws_url, signed_hex)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

// ─── QR frames ───

/// Generate QR frames (SVG strings) for a KSPT hex → return JSON array
#[wasm_bindgen]
pub fn generate_qr_frames(kspt_hex: &str) -> Result<String, JsValue> {
    let frames = qr::generate_frames(kspt_hex).map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&frames).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate a single QR code SVG from a plain UTF-8 string.
/// No framing, no hex encoding. Used for swap invites and data exchange.
#[wasm_bindgen]
pub fn generate_qr_svg_text(text: &str) -> Result<String, JsValue> {
    qr::generate_svg_from_text(text).map_err(|e| JsValue::from_str(&e))
}

/// Search mempool for a TX that spent a specific UTXO and extract
/// the preimage from its sig_script. Used by the atomic swap watcher.
///
/// Returns hex-encoded preimage if found, empty string if not found.
#[wasm_bindgen]
pub async fn find_preimage_for_utxo(
    outpoint_txid_hex: &str,
    covenant_address: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    rpc::find_preimage_for_outpoint(ws_url, outpoint_txid_hex, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Feed a scanned QR frame (hex). Returns complete KSPT hex when done, or empty string.
#[wasm_bindgen]
pub fn decode_qr_frame(frame_hex: &str) -> Result<String, JsValue> {
    qr::decode_frame(frame_hex)
        .map(|opt| opt.unwrap_or_default())
        .map_err(|e| JsValue::from_str(&e))
}

/// Reset multi-frame decoder state
#[wasm_bindgen]
pub fn reset_qr_decoder() {
    qr::reset_decoder();
}

/// Get decoder scan progress as JSON
#[wasm_bindgen]
pub fn decoder_progress() -> String {
    qr::decoder_progress()
}

/// Version string
#[wasm_bindgen]
pub fn version() -> String {
    "KasSee Web".into()
}

// ─── PSKT / PSKB support (Kaspa-standard wire format) ───

/// Inspect a hex payload (output of the multi-frame QR decoder) and
/// return the detected format as a short string: "pskb", "pskt", or
/// "unknown". JS uses this to route a decoded payload to either the
/// PSKT review screen (this module) or the legacy KSPT flow.
#[wasm_bindgen]
pub fn pskt_detect(wire_hex: &str) -> String {
    match pskt::detect_format_hex(wire_hex) {
        pskt::PsktFormat::Pskb => "pskb".into(),
        pskt::PsktFormat::PsktSingle => "pskt".into(),
        pskt::PsktFormat::Unknown => "unknown".into(),
    }
}

/// Parse a PSKT/PSKB payload into a review summary (JSON string).
///
/// `network` is one of "mainnet", "testnet-10/11/12", "simnet",
/// "devnet" — used to format decoded output addresses for display.
#[wasm_bindgen]
pub fn pskt_summary(wire_hex: &str, network: &str) -> Result<String, JsValue> {
    let prefix = network_to_prefix(network);
    let summary = pskt::parse_summary(wire_hex, prefix).map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&summary).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Finalize a fully-signed PSKT/PSKB into a signed KSPT v2 hex blob
/// that the existing `broadcast_signed` RPC path can consume directly.
///
/// Fails if any multisig input lacks the required M signatures.
#[wasm_bindgen]
pub fn pskt_finalize_to_kspt(wire_hex: &str) -> Result<String, JsValue> {
    pskt::finalize_to_kspt_hex(wire_hex).map_err(|e| JsValue::from_str(&e))
}

/// Re-emit a PSKB/PSKT as a KSPT v2 "partial" hex blob for relay to
/// KasSigner over QR. Does NOT require M sigs — accepts 0..=N partial
/// sigs per input. Flags byte = 0x00 (partial).
///
/// The mainnet-verified `pskt_finalize_to_kspt` path is not touched:
/// this is a sibling function that shares no mutable state with it.
#[wasm_bindgen]
pub fn pskt_relay_to_kspt_v2(wire_hex: &str) -> Result<String, JsValue> {
    pskt::relay_pskb_as_kspt_v2_hex(wire_hex).map_err(|e| JsValue::from_str(&e))
}

/// Inverse of `pskt_relay_to_kspt_v2`: merge the partial sigs from a
/// device-returned KSPT v2 blob into the canonical PSKB and return
/// the updated PSKB wire hex. Idempotent — existing sigs are not
/// clobbered.
///
/// Accepts `flags = 0x00` (partial) and `flags = 0x01` (fully signed)
/// equally. Caller must still check whether the merged PSKB has ≥M
/// sigs before finalizing/broadcasting.
#[wasm_bindgen]
pub fn pskt_merge_signed_kspt_v2(
    signed_kspt_hex: &str,
    pskb_wire_hex: &str,
) -> Result<String, JsValue> {
    pskt::merge_signed_kspt_v2_into_pskb(signed_kspt_hex, pskb_wire_hex)
        .map_err(|e| JsValue::from_str(&e))
}

/// PSKT-native finalize + broadcast. Walks the PSKB JSON once,
/// assembles a consensus Transaction directly (sig_scripts per input,
/// with partial sigs + redeem script for P2SH multisig), and submits
/// via Borsh wRPC. No KSPT intermediate format, no shim — PSKB JSON
/// in, Kaspa consensus transaction out, TX ID returned on acceptance.
#[wasm_bindgen]
pub async fn pskt_finalize_and_broadcast(wire_hex: &str, ws_url: &str) -> Result<String, JsValue> {
    pskt::finalize_and_broadcast(wire_hex, ws_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

// ─── Address utilities ───

/// Encode a 32-byte x-only pubkey (hex) as a Kaspa P2PK address
/// Optional network parameter (defaults to mainnet)
#[wasm_bindgen]
pub fn encode_p2pk_address(pubkey_hex: &str, network: Option<String>) -> Result<String, JsValue> {
    let bytes =
        hex::decode(pubkey_hex).map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("Pubkey must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let prefix = network_to_prefix(network.as_deref().unwrap_or("mainnet"));
    Ok(address::encode_p2pk_address(&arr, prefix))
}

/// Encode a 32-byte script hash (hex) as a Kaspa P2SH address
#[wasm_bindgen]
pub fn encode_p2sh_address(
    script_hash_hex: &str,
    network: Option<String>,
) -> Result<String, JsValue> {
    let bytes = hex::decode(script_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("Script hash must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let prefix = network_to_prefix(network.as_deref().unwrap_or("mainnet"));
    Ok(address::encode_p2sh_address(&arr, prefix))
}

/// Decode a Kaspa address → JSON { version, payload_hex }
#[wasm_bindgen]
pub fn decode_address(addr: &str) -> Result<String, JsValue> {
    let (version, payload) = address::decode_address(addr).map_err(|e| JsValue::from_str(&e))?;
    let result = serde_json::json!({
        "version": version,
        "payload": hex::encode(payload),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Compute unkeyed Blake2b-256 hash of the input bytes (hex in, hex out).
/// Used for atomic swap expected hash computation from preimage.
#[wasm_bindgen]
pub fn blake2b_hash(input_hex: &str) -> Result<String, JsValue> {
    let input =
        hex::decode(input_hex).map_err(|e| JsValue::from_str(&format!("bad hex: {}", e)))?;
    let hash = blake2b_simd::Params::new().hash_length(32).hash(&input);
    Ok(hex::encode(hash.as_bytes()))
}

/// Compute SHA-256 hash of the input bytes (hex in, hex out).
/// Used for cross-chain atomic swap expected hash computation.
#[wasm_bindgen]
pub fn sha256_hash(input_hex: &str) -> Result<String, JsValue> {
    let input =
        hex::decode(input_hex).map_err(|e| JsValue::from_str(&format!("bad hex: {}", e)))?;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&input);
    Ok(hex::encode(hash))
}

/// Derive the 32-byte AES-256 key used for encrypting covenant payloads.
/// Key = blake2b(chain_code || "covenant-payload-key"), where chain_code
/// is the 32-byte BIP32 chain code extracted from the kpub (bytes 13..45).
/// This key is deterministic from the seed (chain_code is derived from seed
/// via BIP32), so recovery only requires the seed -> kpub -> this key.
#[wasm_bindgen]
pub fn derive_covenant_payload_key(kpub_str: &str) -> Result<String, JsValue> {
    if !kpub_str.starts_with("kpub") && !kpub_str.starts_with("ktub") {
        return Err(JsValue::from_str("Not a kpub/ktub"));
    }
    let decoded = bs58::decode(kpub_str)
        .into_vec()
        .map_err(|e| JsValue::from_str(&format!("Base58 decode error: {}", e)))?;
    if decoded.len() < 78 {
        return Err(JsValue::from_str(&format!(
            "kpub too short: {} bytes",
            decoded.len()
        )));
    }
    let chain_code = &decoded[13..45]; // 32-byte BIP32 chain code
    let mut input = Vec::with_capacity(32 + 21);
    input.extend_from_slice(chain_code);
    input.extend_from_slice(b"covenant-payload-key");
    let hash = blake2b_simd::Params::new().hash_length(32).hash(&input);
    Ok(hex::encode(hash.as_bytes()))
}

/// Build the plaintext covenant payload blob: [version:1][type:1][params...]
/// version = 0x01, type = covenant type byte. Caller provides params as hex.
/// Returns hex of the assembled plaintext (ready for AES-GCM encryption in JS).
#[wasm_bindgen]
pub fn build_covenant_payload(covenant_type: u8, params_hex: &str) -> Result<String, JsValue> {
    let params = hex::decode(params_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad params hex: {}", e)))?;
    let mut blob = Vec::with_capacity(2 + params.len());
    blob.push(0x01); // version
    blob.push(covenant_type);
    blob.extend_from_slice(&params);
    Ok(hex::encode(&blob))
}

/// Parse a decrypted covenant payload blob: [version:1][type:1][params...]
/// Returns JSON: { "version": 1, "covenant_type": N, "params_hex": "..." }
#[wasm_bindgen]
pub fn parse_covenant_payload(plaintext_hex: &str) -> Result<String, JsValue> {
    let blob = hex::decode(plaintext_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad plaintext hex: {}", e)))?;
    if blob.len() < 2 {
        return Err(JsValue::from_str("Payload too short"));
    }
    let version = blob[0];
    let cov_type = blob[1];
    let params_hex = hex::encode(&blob[2..]);
    let result = serde_json::json!({
        "version": version,
        "covenant_type": cov_type,
        "params_hex": params_hex,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Parse a kpub (extended public key) and extract the account-level xonly pubkey.
/// Returns JSON: { "account_pubkey": "64-char hex xonly" }
#[wasm_bindgen]
pub fn parse_kpub(kpub_str: &str) -> Result<String, JsValue> {
    if !kpub_str.starts_with("kpub") {
        return Err(JsValue::from_str("Not a kpub"));
    }
    // Base58 decode the full string
    let decoded = bs58::decode(kpub_str)
        .into_vec()
        .map_err(|e| JsValue::from_str(&format!("Base58 decode error: {}", e)))?;
    // BIP32 extended key: 4(version) + 1(depth) + 4(parent_fp) + 4(child_num) + 32(chaincode) + 33(key) + 4(checksum) = 82 bytes
    if decoded.len() < 78 {
        return Err(JsValue::from_str(&format!(
            "kpub too short: {} bytes",
            decoded.len()
        )));
    }
    // The compressed pubkey is at bytes 45..78
    let key = &decoded[45..78];
    if key[0] != 0x02 && key[0] != 0x03 {
        return Err(JsValue::from_str(&format!(
            "Invalid pubkey prefix: 0x{:02x}",
            key[0]
        )));
    }
    let xonly = hex::encode(&key[1..]);
    let result = serde_json::json!({
        "account_pubkey": xonly,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── ZK Proof Covenant (Groth16 via OP_ZK_PRECOMPILE) ───

// ================================================================
// KasFreeze: Timed Auto-Release
// ================================================================

// ================================================================
// KasFreeze Beacon: decentralized UTXO relay
// ================================================================

/// Same as `create_covenant_pskb` but includes a TX payload.
/// Used for crowdfund campaign deposits where the VK is embedded in the payload.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_covenant_pskb_with_payload(
    wallet_json: &str,
    covenant_address: &str,
    send_amount: u64,
    fee: u64,
    change_address: &str,
    payload_hex: &str,
    utxo_indices_csv: &str,
    ws_url: &str,
    tag_genesis: bool,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet JSON: {}", e)))?;

    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let change_spk =
        address::address_to_script_pubkey(change_address).map_err(|e| JsValue::from_str(&e))?;
    let payload = hex::decode(payload_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad payload hex: {}", e)))?;

    let mut utxos = rpc::fetch_all_utxos(ws_url, &wallet)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    // Sort to match JS-side UTXO picker order (amount desc, then txid asc + index asc)
    utxos.sort_by(|a, b| {
        b.amount
            .cmp(&a.amount)
            .then_with(|| a.tx_id.cmp(&b.tx_id))
            .then_with(|| a.index.cmp(&b.index))
    });

    let manual_indices: Vec<usize> = utxo_indices_csv
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    // Deposit-fee floor from the ACTUAL input count (single source of truth). JS estimates
    // the fee with selectedUtxoIndices.length, which is 0 on auto-select and so underpays
    // the node's compute-mass floor. The builder knows the real count, so it recomputes the
    // fee here and bumps the passed-in value up to it. Mirrors the JS covDepositFee formula;
    // a genesis spends plain wallet inputs, so there is no revealed redeem to price.
    let payload_len = payload.len() as u64;
    let deposit_fee = |n_inputs: u64| -> u64 {
        const FEE_RATE: u64 = 100; // sompi per gram (node relay rate)
        let per_p2pk = n_inputs * (45 + 66 + 4); // outpoint+seq + 66B schnorr sig push
        let cov_out_bytes = 35 + if tag_genesis { 32 } else { 0 }; // P2SH spk (+ covenant_id field)
        let change_out_bytes = 43u64; // P2PK change output
        let est_tx_bytes = 46 + per_p2pk + cov_out_bytes + change_out_bytes + payload_len + 10;
        let sig_op_mass = n_inputs * 1000; // sig_op_count = 1 per input
        let spk_mass = (35 + 34) * 10; // covenant P2SH spk + change P2PK spk
        let compute_mass = est_tx_bytes + sig_op_mass + spk_mass;
        ((compute_mass * FEE_RATE * 115) / 100).max(100_000) // * 1.15 margin, degenerate backstop
    };

    let mut fee = fee;
    let mut target = send_amount + fee;
    let mut selected = Vec::new();
    let mut total = 0u64;

    if !manual_indices.is_empty() {
        // Manual UTXO selection: use exactly the picked UTXOs.
        for &idx in &manual_indices {
            if idx >= utxos.len() {
                return Err(JsValue::from_str(&format!(
                    "UTXO index {} out of range (have {})",
                    idx,
                    utxos.len()
                )));
            }
            selected.push(utxos[idx].clone());
            total += utxos[idx].amount;
        }
        // Bump the fee to the floor for the count actually picked.
        fee = fee.max(deposit_fee(selected.len() as u64));
        target = send_amount + fee;
    } else {
        // Auto-select greedy, recomputing the fee as the count grows so the selection
        // always covers send_amount plus the fee for the inputs actually chosen.
        for u in &utxos {
            selected.push(u.clone());
            total += u.amount;
            fee = fee.max(deposit_fee(selected.len() as u64));
            target = send_amount + fee;
            if total >= target {
                break;
            }
        }
    }

    // Auto-adjust send_amount if manual selection covers fee but not full amount+fee
    let mut adjusted_send = send_amount;
    if total < target && total > fee && !manual_indices.is_empty() {
        adjusted_send = total - fee;
        target = total;
        web_sys::console::log_1(
            &format!(
                "[KasSee] Auto-adjusted send: {} -> {} (fee {})",
                send_amount, adjusted_send, fee
            )
            .into(),
        );
    }

    if total < target {
        return Err(JsValue::from_str(&format!(
            "Insufficient funds: {} < {}",
            total, target
        )));
    }

    // Covenant_id-bound genesis (global spending limit). Two funding modes:
    //   - send_amount == 0: fund the whole selection into the single thread with no
    //     change. This is the "fund everything" default.
    //   - send_amount  > 0: honor the requested principal and emit change back to the
    //     wallet, exactly like a normal covenant deposit. The thread is still a single
    //     tagged output[0]; the change is plain wallet money, never a second thread, so
    //     the per-spend cap still governs the whole thread.
    if tag_genesis && send_amount == 0 && total > fee {
        adjusted_send = total - fee;
    }

    // KIP-9 / v2.0.1: a covenant_id-tagged genesis output is plurality 2, so it must
    // clear the storage-mass floor. Mirror the withdraw/topup continuation floor.
    const MIN_GENESIS_SOMPI: u64 = 10_000_000; // 0.1 KAS
    if tag_genesis && adjusted_send < MIN_GENESIS_SOMPI {
        return Err(JsValue::from_str(&format!(
            "Genesis funding {} sompi ({:.4} KAS) is too small for a covenant thread. \
             Fund at least 0.1 KAS so the tagged output clears the storage-mass floor.",
            adjusted_send,
            adjusted_send as f64 / 1e8
        )));
    }

    let change = total - adjusted_send - fee;

    // For a covenant_id-bound genesis (e.g. global spending limit), tag output[0]
    // with G = covenant_id(funding_input[0].outpoint, [output[0]]). The thread then
    // carries G on-chain, so the continuation can reuse it (true continuation) and
    // the node serves it back on the UTXO. authorizing_input = 0 (the funding input).
    let genesis_binding: Option<(u16, [u8; 32])> = if tag_genesis {
        let fund_txid = hex::decode(&selected[0].tx_id)
            .map_err(|e| JsValue::from_str(&format!("Bad funding txid: {}", e)))?;
        if fund_txid.len() != 32 {
            return Err(JsValue::from_str("funding txid not 32 bytes"));
        }
        let mut t = [0u8; 32];
        t.copy_from_slice(&fund_txid);
        let g = kspt::compute_covenant_id(
            &t,
            selected[0].index,
            &[(0u32, adjusted_send, 0u16, covenant_spk.as_slice())],
        );
        web_sys::console::log_1(
            &format!(
                "[KasSee] Tagged genesis: covenant_id (G) = {}",
                hex::encode(g)
            )
            .into(),
        );
        Some((0u16, g))
    } else {
        None
    };

    let mut outputs = vec![kspt::PskbOutput {
        amount: adjusted_send,
        script: covenant_spk,
        covenant: genesis_binding, // Some((0, G)) tags the genesis; None = plain (tx_version=0)
    }];
    if change > 0 {
        outputs.push(kspt::PskbOutput {
            amount: change,
            script: change_spk,
            covenant: None,
        });
    }

    let pskb_hex = kspt::serialize_pskb_with_covenants_and_payload(&selected, &outputs, &payload)
        .map_err(|e| JsValue::from_str(&e))?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Covenant PSKB (payload): {} chars, {} inputs, {} outputs, payload {} bytes",
            pskb_hex.len(),
            selected.len(),
            outputs.len(),
            payload.len()
        )
        .into(),
    );

    Ok(pskb_hex)
}

// ================================================================
// KasFreeze Beacon Path C: Pure UTXO WASM exports
// ================================================================

/// Get the current virtual DAA score from the node.
#[wasm_bindgen]
pub async fn get_virtual_daa_score(ws_url: &str) -> Result<String, JsValue> {
    let daa = rpc::get_virtual_daa_score(ws_url)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    Ok(daa.to_string())
}

/// Build a NotifyVirtualChainChanged subscribe request (raw bytes).
#[wasm_bindgen]
pub fn build_vcc_subscribe_request(request_id: u64) -> Result<Vec<u8>, JsValue> {
    let mut payload = Vec::new();
    // Scope: u16(version=1) + u32(variant=0 for BlockAdded) + bw_bytes(empty inner scope)
    rpc::bw_u16_pub(&mut payload, 1).map_err(|e| JsValue::from_str(&e.to_string()))?;
    rpc::bw_u32_pub(&mut payload, 0).map_err(|e| JsValue::from_str(&e.to_string()))?; // BlockAdded = variant 0
                                                                                      // Empty inner scope: bw_bytes of just a version u16
    let mut inner = Vec::new();
    rpc::bw_u16_pub(&mut inner, 1).map_err(|e| JsValue::from_str(&e.to_string()))?;
    rpc::bw_bytes_pub(&mut payload, &inner).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let request = rpc::build_request_pub(request_id, 3, &payload);
    Ok(request)
}

/// Build a NotifyUtxosChanged subscribe request.
#[wasm_bindgen]
pub fn build_utxo_subscribe_request(
    covenant_address: &str,
    request_id: u64,
) -> Result<Vec<u8>, JsValue> {
    let mut payload = Vec::new();
    // Scope: u16(version=1) + Borsh_enum(Scope::UtxosChanged = u32(4))
    // + serialize!(UtxosChangedScope) = bw_bytes(u16(1) + Vec<Address>)
    rpc::bw_u16_pub(&mut payload, 1).map_err(|e| JsValue::from_str(&e.to_string()))?;
    rpc::bw_u32_pub(&mut payload, 4).map_err(|e| JsValue::from_str(&e.to_string()))?; // Scope variant 4 = UtxosChanged
                                                                                      // Inner scope: bw_bytes wraps (u16(1) + Vec<Address>)
    let mut inner = Vec::new();
    rpc::bw_u16_pub(&mut inner, 1).map_err(|e| JsValue::from_str(&e.to_string()))?;
    rpc::bw_u32_pub(&mut inner, 1).map_err(|e| JsValue::from_str(&e.to_string()))?; // 1 address
    rpc::borsh_write_address_pub(&mut inner, covenant_address)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    rpc::bw_bytes_pub(&mut payload, &inner).map_err(|e| JsValue::from_str(&e.to_string()))?;
    // Op 3 = Subscribe
    let request = rpc::build_request_pub(request_id, 3, &payload);
    Ok(request)
}

/// Search a specific block (by hash hex) for a TX that spent the given outpoint.
/// Returns hex-encoded preimage if found, empty string if not.
#[wasm_bindgen]
pub async fn find_preimage_in_block(
    block_hash_hex: &str,
    outpoint_txid_hex: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let txid_bytes = hex::decode(outpoint_txid_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid txid: {}", e)))?;
    let hash_bytes = hex::decode(block_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid block hash: {}", e)))?;
    if hash_bytes.len() != 32 || txid_bytes.len() != 32 {
        return Err(JsValue::from_str("Hash and txid must be 32 bytes"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);
    let raw = rpc::get_block_raw(ws_url, &hash)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if let Some(preimage) = rpc::scan_raw_for_preimage_pub(&raw, &txid_bytes) {
        Ok(hex::encode(&preimage))
    } else {
        Ok(String::new())
    }
}

/// Test function: GetSink + GetBlock(sink, include_transactions=true).
/// Call from browser console: await test_getblock("ws://localhost:17210")
/// Returns a summary string. If the node crashes, you'll know GetBlock is the culprit.
#[wasm_bindgen]
pub async fn test_getblock(ws_url: &str) -> Result<String, JsValue> {
    use rpc::{get_block_raw, get_sink_hash};

    let sink = get_sink_hash(ws_url)
        .await
        .map_err(|e| JsValue::from_str(&format!("GetSink failed: {}", e)))?;
    let sink_hex = hex::encode(sink);

    let raw = get_block_raw(ws_url, &sink)
        .await
        .map_err(|e| JsValue::from_str(&format!("GetBlock failed: {}", e)))?;

    Ok(format!(
        "OK. Sink: {}. Block: {} bytes.",
        sink_hex,
        raw.len()
    ))
}

// ─── State Machine Covenant (Supply Chain) ───

// ─── RISC0 Succinct ZK Covenant ───

// ================================================================
// KIP-21 ZK Bridge PoC (Groth16 over BN254)
// ================================================================

/// Helper: decode hex to [u8; 32].
pub(crate) fn hex_to_32(hex_str: &str, name: &str) -> Result<[u8; 32], JsValue> {
    let bytes =
        hex::decode(hex_str).map_err(|e| JsValue::from_str(&format!("Bad {} hex: {}", name, e)))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "{} must be 32 bytes, got {}",
            name,
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ================================================================
// KIP-21 ZK Rollup State Transition (Groth16 over BN254)
// ================================================================

/// Helper: serialize a BN254 field element.
// Kept: Groth16 field serializer, ZK infrastructure.
#[allow(dead_code)]
fn ark_serialize_field(f: &ark_bn254::Fr) -> Result<Vec<u8>, JsValue> {
    use ark_serialize::CanonicalSerialize;
    let mut buf = Vec::new();
    f.serialize_compressed(&mut buf)
        .map_err(|e| JsValue::from_str(&format!("Serialize failed: {}", e)))?;
    Ok(buf)
}

// ================================================================
// KIP-21 Persistent Rollup Covenant
// ================================================================

// ================================================================
// Covenant PSKB: air-gap signed covenant TX via KasSigner
// ================================================================

/// Build a PSKB for a covenant genesis TX (wallet -> covenant P2SH).
///
/// The PSKB includes covenant binding data so KasSigner computes the
/// correct sighash for TX version 1. After KasSigner signs, KasSee
/// extracts the signature and broadcasts with output v2 + covenant binding.
///
/// Returns: PSKB hex string for QR display
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_covenant_pskb(
    wallet_json: &str,
    covenant_address: &str,
    send_amount: u64,
    fee: u64,
    change_address: &str,
    _covenant_id_hex: &str, // ignored, computed from selected UTXO
    utxo_indices_csv: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet JSON: {}", e)))?;

    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let change_spk =
        address::address_to_script_pubkey(change_address).map_err(|e| JsValue::from_str(&e))?;

    // Fetch UTXOs
    let mut utxos = rpc::fetch_all_utxos(ws_url, &wallet)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    // Sort to match JS-side UTXO picker order
    utxos.sort_by(|a, b| {
        b.amount
            .cmp(&a.amount)
            .then_with(|| a.tx_id.cmp(&b.tx_id))
            .then_with(|| a.index.cmp(&b.index))
    });

    let manual_indices: Vec<usize> = utxo_indices_csv
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    // Deposit-fee floor from the ACTUAL input count (single source of truth), same as
    // create_covenant_pskb_with_payload. JS estimates the fee with a guessed input count
    // (selectedUtxoIndices.length, which is 0 on auto-select, or a hardcoded value), which
    // can underpay the node's compute-mass floor. The builder knows the real count, so it
    // recomputes the fee here and bumps the passed-in value up to it. This builder carries
    // no payload and always tags output[0] with the covenant_id.
    let deposit_fee = |n_inputs: u64| -> u64 {
        const FEE_RATE: u64 = 100; // sompi per gram (node relay rate)
        let per_p2pk = n_inputs * (45 + 66 + 4); // outpoint+seq + 66B schnorr sig push
        let cov_out_bytes = 35 + 32; // P2SH spk + covenant_id field (always tagged)
        let change_out_bytes = 43u64; // P2PK change output
        let est_tx_bytes = 46 + per_p2pk + cov_out_bytes + change_out_bytes + 10;
        let sig_op_mass = n_inputs * 1000; // sig_op_count = 1 per input
        let spk_mass = (35 + 34) * 10; // covenant P2SH spk + change P2PK spk
        let compute_mass = est_tx_bytes + sig_op_mass + spk_mass;
        ((compute_mass * FEE_RATE * 115) / 100).max(100_000) // * 1.15 margin, degenerate backstop
    };

    let mut fee = fee;
    let mut target = send_amount + fee;
    let mut selected = Vec::new();
    let mut total = 0u64;

    if !manual_indices.is_empty() {
        for &idx in &manual_indices {
            if idx >= utxos.len() {
                return Err(JsValue::from_str(&format!(
                    "UTXO index {} out of range (have {})",
                    idx,
                    utxos.len()
                )));
            }
            selected.push(utxos[idx].clone());
            total += utxos[idx].amount;
        }
        // Bump the fee to the floor for the count actually picked.
        fee = fee.max(deposit_fee(selected.len() as u64));
        target = send_amount + fee;
    } else {
        // Auto-select greedy, recomputing the fee as the count grows so the selection
        // always covers send_amount plus the fee for the inputs actually chosen.
        for u in &utxos {
            selected.push(u.clone());
            total += u.amount;
            fee = fee.max(deposit_fee(selected.len() as u64));
            target = send_amount + fee;
            if total >= target {
                break;
            }
        }
    }

    // Auto-adjust send_amount if manual selection covers fee but not full amount+fee
    let mut adjusted_send = send_amount;
    if total < target && total > fee && !manual_indices.is_empty() {
        adjusted_send = total - fee;
        target = total;
        web_sys::console::log_1(
            &format!(
                "[KasSee] Auto-adjusted send: {} -> {} (fee {})",
                send_amount, adjusted_send, fee
            )
            .into(),
        );
    }

    if total < target {
        return Err(JsValue::from_str(&format!(
            "Insufficient funds: {} < {}",
            total, target
        )));
    }

    // Compute covenant_id from the first selected UTXO's outpoint + output[0]
    let txid_bytes: [u8; 32] = hex::decode(&selected[0].tx_id)
        .map_err(|e| JsValue::from_str(&format!("Bad txid: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("txid not 32 bytes"))?;

    let auth_outputs = vec![(0u32, adjusted_send, 0u16, covenant_spk.as_slice())];
    let covenant_id = kspt::compute_covenant_id(&txid_bytes, selected[0].index, &auth_outputs);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Covenant PSKB: computed cov_id={} from utxo {}:{}",
            hex::encode(covenant_id),
            &selected[0].tx_id[..16],
            selected[0].index
        )
        .into(),
    );

    let change = total - adjusted_send - fee;

    let mut outputs = vec![kspt::PskbOutput {
        amount: adjusted_send,
        script: covenant_spk,
        covenant: Some((0u16, covenant_id)),
    }];
    if change > 0 {
        outputs.push(kspt::PskbOutput {
            amount: change,
            script: change_spk,
            covenant: None,
        });
    }

    let pskb_hex = kspt::serialize_pskb_with_covenants(&selected, &outputs)
        .map_err(|e| JsValue::from_str(&e))?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Covenant PSKB: {} chars, {} inputs, {} outputs, cov_id={}",
            pskb_hex.len(),
            selected.len(),
            outputs.len(),
            hex::encode(covenant_id)
        )
        .into(),
    );

    Ok(pskb_hex)
}
