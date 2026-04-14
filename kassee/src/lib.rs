// KasSee Web — Watch-only companion wallet for KasSigner
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// lib.rs — WASM entry point. Exports wallet operations to JavaScript.
// All Kaspa logic runs in the browser. No server, no backend.

#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::type_complexity)]
mod bip32;
mod address;
mod kspt;
mod qr;
mod rpc;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ─── Network → prefix mapping ───

fn network_to_prefix(network: &str) -> &'static str {
    match network {
        "testnet-10" | "testnet-11" | "testnet-12" => "kaspatest",
        "simnet" => "kaspasim",
        "devnet" => "kaspadev",
        _ => "kaspa", // mainnet and anything else
    }
}

// ─── kpub import ───

/// Import a kpub string + network → derive 20 receive + 5 change addresses → return JSON
#[wasm_bindgen]
pub fn import_kpub(kpub_str: &str, network: &str) -> Result<String, JsValue> {
    let prefix = network_to_prefix(network);
    let result = bip32::import_kpub(kpub_str, prefix)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Balance ───

/// Connect to node via Borsh wRPC, fetch UTXOs, return JSON balance.
#[wasm_bindgen]
pub async fn fetch_balance(wallet_json: &str, ws_url: &str) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    let balance = rpc::fetch_balance(ws_url, &wallet).await
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&balance)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Fetch all UTXOs as JSON array
#[wasm_bindgen]
pub async fn fetch_utxos(wallet_json: &str, ws_url: &str) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    let utxos = rpc::fetch_all_utxos(ws_url, &wallet).await
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&utxos)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Fee estimation ───

/// Query node for current fee rates → return JSON
#[wasm_bindgen]
pub async fn get_fee_estimate(ws_url: &str) -> Result<String, JsValue> {
    let estimate = rpc::get_fee_estimate(ws_url).await
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&estimate)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Send (create unsigned KSPT) ───

/// Build unsigned KSPT from wallet, destination, amount, fee → return hex
#[wasm_bindgen]
pub async fn create_send_kspt(
    wallet_json: &str,
    dest_address: &str,
    amount_kas: f64,
    fee_sompi: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    kspt::create_send_kspt(&wallet, dest_address, amount_kas, fee_sompi, ws_url).await
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
    kspt::create_consolidate_kspt(&wallet, fee_sompi, ws_url).await
        .map_err(|e| JsValue::from_str(&e))
}

/// Create unsigned KSPT with specific UTXO indices (comma-separated)
#[wasm_bindgen]
pub async fn create_send_kspt_selected(
    wallet_json: &str,
    dest_address: &str,
    amount_kas: f64,
    fee_sompi: u64,
    utxo_indices_csv: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    let indices: Vec<usize> = utxo_indices_csv.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().parse::<usize>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid index: {}", e)))?;
    kspt::create_send_kspt_selected(&wallet, dest_address, amount_kas, fee_sompi, &indices, ws_url).await
        .map_err(|e| JsValue::from_str(&e))
}

/// Create compound KSPT with multiple recipients
/// recipients_json: [{"address":"kaspa:...","amount_kas":1.5}, ...]
#[wasm_bindgen]
pub async fn create_compound_kspt(
    wallet_json: &str,
    recipients_json: &str,
    fee_sompi: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    kspt::create_compound_kspt(&wallet, recipients_json, fee_sompi, ws_url).await
        .map_err(|e| JsValue::from_str(&e))
}

/// Create unsigned multisig spend KSPT
/// descriptor: "multi(2,pk1hex,pk2hex,pk3hex)"
/// source_address: the P2SH multisig address holding the funds
/// change_address: where change goes (typically same P2SH address)
#[wasm_bindgen]
pub async fn create_multisig_kspt(
    descriptor: &str,
    source_address: &str,
    dest_address: &str,
    amount_kas: f64,
    fee_sompi: u64,
    change_address: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    kspt::create_multisig_kspt(descriptor, source_address, dest_address, amount_kas, fee_sompi, change_address, ws_url).await
        .map_err(|e| JsValue::from_str(&e))
}

/// Fetch UTXOs for a single address (for multisig balance check) → JSON array
#[wasm_bindgen]
pub async fn fetch_utxos_for_address_js(address: &str, ws_url: &str) -> Result<String, JsValue> {
    let utxos = rpc::fetch_utxos_for_address(ws_url, address).await
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&utxos)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Broadcast ───

/// Broadcast a signed KSPT hex to the network → return TX ID
#[wasm_bindgen]
pub async fn broadcast_signed(signed_hex: &str, ws_url: &str) -> Result<String, JsValue> {
    rpc::broadcast_signed(ws_url, signed_hex).await
        .map_err(|e| JsValue::from_str(&e))
}

// ─── QR frames ───

/// Generate QR frames (SVG strings) for a KSPT hex → return JSON array
#[wasm_bindgen]
pub fn generate_qr_frames(kspt_hex: &str) -> Result<String, JsValue> {
    let frames = qr::generate_frames(kspt_hex)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&frames)
        .map_err(|e| JsValue::from_str(&e.to_string()))
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

// ─── Address utilities ───

/// Encode a 32-byte x-only pubkey (hex) as a Kaspa P2PK address
/// Optional network parameter (defaults to mainnet)
#[wasm_bindgen]
pub fn encode_p2pk_address(pubkey_hex: &str, network: Option<String>) -> Result<String, JsValue> {
    let bytes = hex::decode(pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))?;
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
pub fn encode_p2sh_address(script_hash_hex: &str, network: Option<String>) -> Result<String, JsValue> {
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
    let (version, payload) = address::decode_address(addr)
        .map_err(|e| JsValue::from_str(&e))?;
    let result = serde_json::json!({
        "version": version,
        "payload": hex::encode(payload),
    });
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
