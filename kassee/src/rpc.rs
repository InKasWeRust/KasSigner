// KasSee Web — Kaspa wRPC Borsh client
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// Borsh wRPC protocol over browser WebSocket.
// Request:  Option<u64>(id) + u8(op) + Vec<u8>(Serializable payload)
// Response: Option<u64>(id) + u8(kind:0=Ok,1=Err) + Option<u8>(op) + payload

//! Node communication over Kaspa wRPC (Borsh) and REST: UTXO and DAG queries,
//! transaction broadcast, and subscription-request builders.

use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{MessageEvent, WebSocket};

use std::cell::RefCell;
use std::io::{Cursor, Write};
use std::rc::Rc;

use crate::bip32::WalletData;

const OP_GET_UTXOS_BY_ADDRESSES: u8 = 135;
const OP_SUBMIT_TRANSACTION: u8 = 125;
const OP_GET_FEE_ESTIMATE: u8 = 147;
const OP_GET_BLOCK_DAG_INFO: u8 = 131;
const OP_GET_SINK: u8 = 120;
const OP_GET_BLOCK: u8 = 126;

// ─── Public types ───

#[derive(Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub tx_id: String,
    pub index: u32,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub block_daa_score: u64,
    /// On-chain covenant id (hex) for covenant-tagged UTXOs, None otherwise.
    /// Exposed so a continuation can bind to the thread's actual id.
    #[serde(default)]
    pub covenant_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct BalanceInfo {
    pub total_sompi: u64,
    pub total_kas: f64,
    pub utxo_count: usize,
    pub funded_addresses: usize,
    pub funded_receive_indices: Vec<usize>,
    pub funded_change_indices: Vec<usize>,
}

// ─── Borsh write helpers ───

fn bw_u8(w: &mut impl Write, v: u8) -> std::io::Result<()> {
    w.write_all(&[v])
}
fn bw_u16(w: &mut impl Write, v: u16) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn bw_u32(w: &mut impl Write, v: u32) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn bw_u64(w: &mut impl Write, v: u64) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn bw_bytes(w: &mut impl Write, data: &[u8]) -> std::io::Result<()> {
    bw_u32(w, data.len() as u32)?;
    w.write_all(data)
}
fn bw_option_u64(w: &mut impl Write, val: u64) -> std::io::Result<()> {
    bw_u8(w, 1)?;
    bw_u64(w, val)
}

// ─── Borsh read helpers ───

fn br_u8(r: &mut Cursor<&[u8]>) -> Result<u8, String> {
    u8::deserialize_reader(r).map_err(|e| format!("u8: {}", e))
}
fn br_u16(r: &mut Cursor<&[u8]>) -> Result<u16, String> {
    u16::deserialize_reader(r).map_err(|e| format!("u16: {}", e))
}
fn br_u32(r: &mut Cursor<&[u8]>) -> Result<u32, String> {
    u32::deserialize_reader(r).map_err(|e| format!("u32: {}", e))
}
fn br_u64(r: &mut Cursor<&[u8]>) -> Result<u64, String> {
    u64::deserialize_reader(r).map_err(|e| format!("u64: {}", e))
}
fn br_bool(r: &mut Cursor<&[u8]>) -> Result<bool, String> {
    bool::deserialize_reader(r).map_err(|e| format!("bool: {}", e))
}
fn br_bytes(r: &mut Cursor<&[u8]>) -> Result<Vec<u8>, String> {
    Vec::<u8>::deserialize_reader(r).map_err(|e| format!("bytes: {}", e))
}
fn br_f64(r: &mut Cursor<&[u8]>) -> Result<f64, String> {
    f64::deserialize_reader(r).map_err(|e| format!("f64: {}", e))
}

// ─── Build wRPC request ───

fn build_request(id: u64, op: u8, inner_payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + inner_payload.len());
    bw_option_u64(&mut buf, id).unwrap();
    bw_u8(&mut buf, op).unwrap();
    bw_bytes(&mut buf, inner_payload).unwrap();
    buf
}

// Public wrappers for lib.rs access
pub fn build_request_pub(id: u64, op: u8, inner_payload: &[u8]) -> Vec<u8> {
    build_request(id, op, inner_payload)
}
// Kept: retained for future use; not currently wired.
#[allow(dead_code)]
pub fn bw_u8_pub(w: &mut impl Write, v: u8) -> std::io::Result<()> {
    bw_u8(w, v)
}
pub fn bw_u16_pub(w: &mut impl Write, v: u16) -> std::io::Result<()> {
    bw_u16(w, v)
}
pub fn bw_u32_pub(w: &mut impl Write, v: u32) -> std::io::Result<()> {
    bw_u32(w, v)
}
pub fn bw_bytes_pub(w: &mut impl Write, data: &[u8]) -> std::io::Result<()> {
    bw_bytes(w, data)
}
pub fn borsh_write_address_pub(w: &mut impl Write, addr_str: &str) -> std::io::Result<()> {
    borsh_write_address(w, addr_str)
}

// ─── Kaspa Address Borsh serialization ───

fn borsh_write_address(w: &mut impl Write, addr_str: &str) -> std::io::Result<()> {
    let (version, payload) = crate::address::decode_address(addr_str)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let prefix_byte: u8 = if addr_str.starts_with("kaspatest:") {
        1
    } else if addr_str.starts_with("kaspasim:") {
        2
    } else if addr_str.starts_with("kaspadev:") {
        3
    } else {
        0
    };
    bw_u8(w, prefix_byte)?;
    bw_u8(w, version)?;
    bw_u32(w, payload.len() as u32)?;
    w.write_all(&payload)?;
    Ok(())
}

// ─── GetUtxosByAddresses request payload ───

fn build_get_utxos_payload(addresses: &[String]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    bw_u16(&mut buf, 1).map_err(|e| format!("borsh version: {}", e))?;
    bw_u32(&mut buf, addresses.len() as u32).map_err(|e| format!("borsh len: {}", e))?;
    for addr in addresses {
        borsh_write_address(&mut buf, addr)
            .map_err(|e| format!("Invalid address '{}': {}", addr, e))?;
    }
    Ok(buf)
}

// ─── Parse response header ───

struct RpcResponse {
    kind: u8,
    payload: Vec<u8>,
}

fn parse_response(data: &[u8]) -> Result<RpcResponse, String> {
    if data.len() < 4 {
        return Err(format!("Response too short: {} bytes", data.len()));
    }

    let mut r = Cursor::new(data);

    // Option<u64> id
    let tag = br_u8(&mut r)?;
    if tag == 1 {
        let _ = br_u64(&mut r)?;
    }

    // u8 kind: 0=Success, 1=Error
    let kind = br_u8(&mut r)?;

    // Option<u8> op
    let pos = r.position() as usize;
    let remaining = &data[pos..];
    let payload_start = if !remaining.is_empty() && remaining[0] == 0 {
        1
    } else if remaining.len() >= 2 && remaining[0] == 1 {
        2
    } else {
        0
    };

    Ok(RpcResponse {
        kind,
        payload: remaining[payload_start..].to_vec(),
    })
}

// ─── Parse UTXO response payload ───

fn parse_utxo_payload(data: &[u8]) -> Result<Vec<UtxoEntry>, String> {
    if data.len() < 6 {
        return Ok(Vec::new());
    }

    let mut r = Cursor::new(data);

    // Result tag: 0x01 = success in Kaspa encoding, 0xff = notification (skip)
    let result_tag = br_u8(&mut r)?;
    if result_tag == 255 {
        r = Cursor::new(data);
    }

    // Outer Serializable Vec<u8> wrapper
    let outer = br_bytes(&mut r)?;
    let mut r = Cursor::new(outer.as_slice());

    let _version = br_u16(&mut r)?;
    let entries_blob = br_bytes(&mut r)?;

    if entries_blob.is_empty() {
        return Ok(Vec::new());
    }

    let mut er = Cursor::new(entries_blob.as_slice());
    let count = br_u32(&mut er)?;

    let mut entries = Vec::new();
    for i in 0..count {
        // Each entry is Vec<u8> wrapped (serialize! per element)
        let entry_blob = br_bytes(&mut er)?;
        let mut r2 = Cursor::new(entry_blob.as_slice());

        let _ev = br_u8(&mut r2)?; // entry version

        // Option<Address>
        let has_addr = br_u8(&mut r2)?;
        if has_addr == 1 {
            let _prefix = br_u8(&mut r2)?;
            let _ver = br_u8(&mut r2)?;
            let _payload = br_bytes(&mut r2)?;
        }

        // Outpoint (Vec<u8> wrapped, starts with version byte)
        let op_blob = br_bytes(&mut r2)?;
        if op_blob.len() < 37 {
            return Err(format!("Entry {}: outpoint {} bytes", i, op_blob.len()));
        }
        let tx_id_bytes = &op_blob[1..33]; // skip version byte
        let index = u32::from_le_bytes([op_blob[33], op_blob[34], op_blob[35], op_blob[36]]);

        // UtxoEntry (Vec<u8> wrapped, starts with version byte)
        let ue_blob = br_bytes(&mut r2)?;
        let mut ur = Cursor::new(ue_blob.as_slice());
        let ue_ver = br_u8(&mut ur)?;
        let amount = br_u64(&mut ur)?;
        let _spk_ver = br_u16(&mut ur)?;
        let spk_script = br_bytes(&mut ur)?;
        let block_daa_score = br_u64(&mut ur)?;
        let _is_coinbase = br_bool(&mut ur)?;
        // Version > 1: Option<Hash> covenant_id. Expose it (hex) so spends can bind
        // a continuation to the thread's real on-chain id; the node rejects a
        // continuation whose id != the authorizing input's covenant_id.
        let mut covenant_id_hex: Option<String> = None;
        if ue_ver > 1 {
            let has_cov = br_u8(&mut ur)?;
            if has_cov == 1 {
                let mut cov_id = [0u8; 32];
                std::io::Read::read_exact(&mut ur, &mut cov_id)
                    .map_err(|e| format!("Entry {}: covenant_id read: {}", i, e))?;
                covenant_id_hex = Some(hex::encode(cov_id));
            }
        }

        entries.push(UtxoEntry {
            tx_id: hex::encode(tx_id_bytes),
            index,
            amount,
            script_public_key: spk_script,
            block_daa_score,
            covenant_id: covenant_id_hex,
        });
    }

    Ok(entries)
}

// ─── WebSocket RPC call ───

async fn ws_rpc_call(ws_url: &str, op: u8, payload: &[u8]) -> Result<Vec<u8>, String> {
    let ws = WebSocket::new(ws_url).map_err(|e| format!("WS create: {:?}", e))?;
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

    let id: u64 = (js_sys::Math::random() * 1_000_000.0) as u64;
    let request = build_request(id, op, payload);

    let result: Rc<RefCell<Option<Result<Vec<u8>, String>>>> = Rc::new(RefCell::new(None));

    let promise = {
        let result = result.clone();
        let request = request.clone();

        js_sys::Promise::new(&mut |resolve, _reject| {
            let res = result.clone();
            let req = request.clone();
            let ws2 = ws.clone();

            let on_open = Closure::once(move |_: JsValue| {
                let arr = js_sys::Uint8Array::from(&req[..]);
                ws2.send_with_array_buffer(&arr.buffer()).ok();
            });

            let res2 = res.clone();
            let resolve2 = resolve.clone();
            let on_message = Closure::once(move |event: MessageEvent| {
                if let Ok(buf) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                    let arr = js_sys::Uint8Array::new(&buf);
                    let mut data = vec![0u8; arr.length() as usize];
                    arr.copy_to(&mut data);

                    match parse_response(&data) {
                        Ok(resp) => {
                            if resp.kind == 0x00 {
                                *res2.borrow_mut() = Some(Ok(resp.payload));
                            } else {
                                // Extract error text from Borsh payload
                                // RPC errors are typically: version(u16) + Serializable(String)
                                // Try to extract a readable string
                                let payload = &resp.payload;
                                let err_text = if payload.len() > 6 {
                                    // Skip version(2) + outer len(4), try to read inner string
                                    let inner_start = 6usize;
                                    if inner_start + 4 <= payload.len() {
                                        let slen = u32::from_le_bytes([
                                            payload[inner_start],
                                            payload.get(inner_start + 1).copied().unwrap_or(0),
                                            payload.get(inner_start + 2).copied().unwrap_or(0),
                                            payload.get(inner_start + 3).copied().unwrap_or(0),
                                        ])
                                            as usize;
                                        let str_start = inner_start + 4;
                                        if str_start + slen <= payload.len() {
                                            String::from_utf8_lossy(
                                                &payload[str_start..str_start + slen],
                                            )
                                            .to_string()
                                        } else {
                                            String::from_utf8_lossy(payload).to_string()
                                        }
                                    } else {
                                        String::from_utf8_lossy(payload).to_string()
                                    }
                                } else {
                                    String::from_utf8_lossy(payload).to_string()
                                };
                                // Also log raw hex for debugging
                                let hex_preview: String = payload
                                    .iter()
                                    .take(200)
                                    .map(|b| format!("{:02x}", b))
                                    .collect();
                                web_sys::console::log_1(
                                    &format!(
                                        "[KasSee] RPC error kind={}: text='{}' raw_hex={}",
                                        resp.kind, err_text, hex_preview
                                    )
                                    .into(),
                                );
                                *res2.borrow_mut() = Some(Err(format!(
                                    "RPC error kind={}: {}",
                                    resp.kind, err_text
                                )));
                            }
                        }
                        Err(e) => {
                            *res2.borrow_mut() = Some(Err(format!("Parse: {}", e)));
                        }
                    }
                    resolve2.call0(&JsValue::NULL).ok();
                }
            });

            let res3 = res.clone();
            let resolve3 = resolve.clone();
            let on_error = Closure::once(move |_: JsValue| {
                *res3.borrow_mut() = Some(Err("WebSocket error".into()));
                resolve3.call0(&JsValue::NULL).ok();
            });

            ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
            ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
            ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
            on_open.forget();
            on_message.forget();
            on_error.forget();

            // 15-second timeout: if no response arrives, resolve with timeout error
            let res4 = res.clone();
            let resolve4 = resolve.clone();
            let timeout_cb = Closure::once(move || {
                let mut guard = res4.borrow_mut();
                if guard.is_none() {
                    *guard = Some(Err("WebSocket timeout (15s)".into()));
                    resolve4.call0(&JsValue::NULL).ok();
                }
            });
            // Get setTimeout from the global object (CSP-safe, no eval)
            let global = js_sys::global();
            if let Ok(st) = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout")) {
                if let Ok(set_timeout) = st.dyn_into::<js_sys::Function>() {
                    let _ = set_timeout.call2(
                        &JsValue::NULL,
                        timeout_cb.as_ref(),
                        &JsValue::from(15_000),
                    );
                }
            }
            timeout_cb.forget();
        })
    };

    JsFuture::from(promise)
        .await
        .map_err(|_| "Promise failed".to_string())?;
    ws.close().ok();

    let response = result.borrow_mut().take();
    response.unwrap_or_else(|| Err("No response".into()))
}

// ─── Public API: UTXO fetch ───

pub async fn fetch_all_utxos(ws_url: &str, wallet: &WalletData) -> Result<Vec<UtxoEntry>, String> {
    let all_addresses: Vec<String> = wallet
        .receive_addresses
        .iter()
        .chain(wallet.change_addresses.iter())
        .cloned()
        .collect();

    let payload = build_get_utxos_payload(&all_addresses)?;
    let response = ws_rpc_call(ws_url, OP_GET_UTXOS_BY_ADDRESSES, &payload).await?;
    parse_utxo_payload(&response)
}

/// Fetch UTXOs for a single address (used for multisig P2SH)
pub async fn fetch_utxos_for_address(
    ws_url: &str,
    address: &str,
) -> Result<Vec<UtxoEntry>, String> {
    let addresses = vec![address.to_string()];
    let payload = build_get_utxos_payload(&addresses)?;
    let response = ws_rpc_call(ws_url, OP_GET_UTXOS_BY_ADDRESSES, &payload).await?;
    parse_utxo_payload(&response)
}

pub async fn fetch_balance(ws_url: &str, wallet: &WalletData) -> Result<BalanceInfo, String> {
    let utxos = fetch_all_utxos(ws_url, wallet).await?;
    let total_sompi: u64 = utxos.iter().map(|u| u.amount).sum();

    let funded_addresses = {
        let mut seen = std::collections::HashSet::new();
        for u in &utxos {
            seen.insert(&u.script_public_key);
        }
        seen.len()
    };

    let funded_scripts: std::collections::HashSet<Vec<u8>> =
        utxos.iter().map(|u| u.script_public_key.clone()).collect();

    let funded_receive_indices: Vec<usize> = wallet
        .receive_addresses
        .iter()
        .enumerate()
        .filter_map(|(i, addr)| {
            crate::address::address_to_script_pubkey(addr)
                .ok()
                .filter(|spk| funded_scripts.contains(spk))
                .map(|_| i)
        })
        .collect();

    let funded_change_indices: Vec<usize> = wallet
        .change_addresses
        .iter()
        .enumerate()
        .filter_map(|(i, addr)| {
            crate::address::address_to_script_pubkey(addr)
                .ok()
                .filter(|spk| funded_scripts.contains(spk))
                .map(|_| i)
        })
        .collect();

    Ok(BalanceInfo {
        total_sompi,
        total_kas: total_sompi as f64 / 100_000_000.0,
        utxo_count: utxos.len(),
        funded_addresses,
        funded_receive_indices,
        funded_change_indices,
    })
}

// ─── Public API: Fee estimation ───

#[derive(Serialize, Deserialize)]
pub struct FeeEstimate {
    pub priority_sompi_per_gram: f64,
    pub normal_sompi_per_gram: f64,
    pub low_sompi_per_gram: f64,
    pub priority_seconds: f64,
    pub normal_seconds: f64,
    pub low_seconds: f64,
    pub suggested_fee: u64,
}

pub async fn get_fee_estimate(ws_url: &str) -> Result<FeeEstimate, String> {
    // Request: just version u16 = 1
    let mut payload = Vec::new();
    bw_u16(&mut payload, 1).unwrap();

    let response = ws_rpc_call(ws_url, OP_GET_FEE_ESTIMATE, &payload).await?;

    if response.len() < 6 {
        return Ok(FeeEstimate {
            priority_sompi_per_gram: 1.0,
            normal_sompi_per_gram: 1.0,
            low_sompi_per_gram: 1.0,
            priority_seconds: 1.0,
            normal_seconds: 30.0,
            low_seconds: 1800.0,
            suggested_fee: 10000,
        });
    }

    // Parse: result_tag(1) + Vec<u8> outer + version(u16) + serialize!(RpcFeeEstimate)
    let mut r = Cursor::new(response.as_slice());
    let result_tag = br_u8(&mut r)?;
    if result_tag == 255 {
        r = Cursor::new(response.as_slice());
    }

    // Outer Serializable wrapper
    let outer = br_bytes(&mut r)?;
    let mut r = Cursor::new(outer.as_slice());
    let _resp_version = br_u16(&mut r)?;

    // serialize!(RpcFeeEstimate) = Vec<u8> wrapper
    let estimate_blob = br_bytes(&mut r)?;
    let mut r = Cursor::new(estimate_blob.as_slice());
    let _est_version = br_u16(&mut r)?;

    // priority_bucket: f64 feerate + f64 estimated_seconds (BorshSerialize = direct)
    let priority_feerate = br_f64(&mut r)?;
    let priority_seconds = br_f64(&mut r)?;

    // normal_buckets: Vec<RpcFeerateBucket> = u32 count + each (f64 + f64)
    let normal_count = br_u32(&mut r)?;
    let mut normal_feerate = 1.0f64;
    let mut normal_seconds = 30.0f64;
    for i in 0..normal_count {
        let fr = br_f64(&mut r)?;
        let es = br_f64(&mut r)?;
        if i == 0 {
            normal_feerate = fr;
            normal_seconds = es;
        }
    }

    // low_buckets
    let low_count = br_u32(&mut r)?;
    let mut low_feerate = 1.0f64;
    let mut low_seconds = 1800.0f64;
    for i in 0..low_count {
        let fr = br_f64(&mut r)?;
        let es = br_f64(&mut r)?;
        if i == 0 {
            low_feerate = fr;
            low_seconds = es;
        }
    }

    // Typical 1-in 2-out P2PK tx: ~2300 grams compute mass
    // Post-Crescendo minimum: 10000 sompi
    let suggested = (normal_feerate * 2300.0).max(10000.0) as u64;

    Ok(FeeEstimate {
        priority_sompi_per_gram: priority_feerate,
        normal_sompi_per_gram: normal_feerate,
        low_sompi_per_gram: low_feerate,
        priority_seconds,
        normal_seconds,
        low_seconds,
        suggested_fee: suggested,
    })
}

// ─── Public API: Broadcast signed KSPT ───

// Checked byte readers for manual wire parsing. Every read validates
// bounds and returns Err instead of panicking; a panic in WASM aborts
// the whole module. Use these instead of raw `bytes[pos..pos + n]`
// indexing anywhere the input is user- or wire-controlled.
fn rd_take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = pos
        .checked_add(n)
        .filter(|&e| e <= b.len())
        .ok_or_else(|| format!("KSPT truncated at byte {}", *pos))?;
    let s = &b[*pos..end];
    *pos = end;
    Ok(s)
}

fn rd_u8(b: &[u8], pos: &mut usize) -> Result<u8, String> {
    Ok(rd_take(b, pos, 1)?[0])
}

fn rd_u16(b: &[u8], pos: &mut usize) -> Result<u16, String> {
    let s = rd_take(b, pos, 2)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(b: &[u8], pos: &mut usize) -> Result<u32, String> {
    let s = rd_take(b, pos, 4)?;
    Ok(u32::from_le_bytes(
        s.try_into().expect("rd_take returned 4 bytes"),
    ))
}

fn rd_u64(b: &[u8], pos: &mut usize) -> Result<u64, String> {
    let s = rd_take(b, pos, 8)?;
    Ok(u64::from_le_bytes(
        s.try_into().expect("rd_take returned 8 bytes"),
    ))
}

pub async fn broadcast_signed(ws_url: &str, signed_hex: &str) -> Result<String, String> {
    let bytes = hex::decode(signed_hex).map_err(|e| format!("Invalid hex: {}", e))?;

    if bytes.len() < 6 || &bytes[0..4] != b"KSPT" {
        return Err("Not a KSPT (missing header)".into());
    }
    let version = bytes[4];
    let flags = bytes[5];

    if version == 0x01 && flags != 0x01 {
        return Err(format!("Not signed (flags={:#x}, expected 0x01)", flags));
    }
    if version == 0x02 && flags == 0x00 {
        return Err("Partially signed KSPT — needs more signatures".into());
    }

    // Parse signed KSPT binary
    let mut pos: usize = 6;

    // Bounds guard: fixed global header after the 6-byte magic is
    // tx_version(2) + num_inputs(1) + num_outputs(1) + locktime(8)
    // + subnetwork_id(20) + gas(8) + payload_len(2) = 42 bytes.
    // Without this, a truncated hex panics on slice indexing below,
    // which aborts the whole WASM module.
    if bytes.len() < pos + 42 {
        return Err("KSPT truncated at header".into());
    }

    // Global (every read below is bounds-checked by the rd_* helpers;
    // the up-front guard stays for a clearer error on obvious truncation)
    let tx_version = rd_u16(&bytes, &mut pos)?;
    let num_inputs = rd_u8(&bytes, &mut pos)? as usize;
    let num_outputs = rd_u8(&bytes, &mut pos)? as usize;
    let locktime = rd_u64(&bytes, &mut pos)?;
    let subnetwork_id: Vec<u8> = rd_take(&bytes, &mut pos, 20)?.to_vec();
    let gas = rd_u64(&bytes, &mut pos)?;
    let payload_len = rd_u16(&bytes, &mut pos)? as usize;
    let tx_payload: Vec<u8> = rd_take(&bytes, &mut pos, payload_len)
        .map_err(|_| "KSPT truncated at payload".to_string())?
        .to_vec();

    // Parse inputs with signatures
    struct TxInput {
        prev_tx_id: [u8; 32],
        prev_index: u32,
        sig_script: Vec<u8>,
        sequence: u64,
        sig_op_count: u8,
    }

    let mut inputs = Vec::new();
    for _i in 0..num_inputs {
        // Fixed per-input fields: prev_tx_id(32) + prev_index(4) + amount(8)
        // + sequence(8) + sig_op_count(1) + spk_version(2) + spk_len(1) = 56.
        if pos + 56 > bytes.len() {
            return Err("KSPT truncated at input".into());
        }
        let mut prev_tx_id = [0u8; 32];
        prev_tx_id.copy_from_slice(rd_take(&bytes, &mut pos, 32)?);
        let prev_index = rd_u32(&bytes, &mut pos)?;
        let _amount = rd_u64(&bytes, &mut pos)?;
        let sequence = rd_u64(&bytes, &mut pos)?;
        let sig_op_count = rd_u8(&bytes, &mut pos)?;
        let _spk_version = rd_u16(&bytes, &mut pos)?;
        let spk_len = rd_u8(&bytes, &mut pos)? as usize;
        let spk_script = rd_take(&bytes, &mut pos, spk_len)
            .map_err(|_| "KSPT truncated at spk".to_string())?
            .to_vec();

        let mut sig_script = Vec::new();

        if version == 0x01 {
            // v1: sig_len(1) + sig(sig_len) + sighash_type(1)
            let sig_len =
                rd_u8(&bytes, &mut pos).map_err(|_| "KSPT truncated at sig".to_string())? as usize;
            if sig_len > 0 {
                let sig_bytes = rd_take(&bytes, &mut pos, sig_len)
                    .map_err(|_| "KSPT truncated at sig data".to_string())?
                    .to_vec();
                let sighash_type = rd_u8(&bytes, &mut pos)
                    .map_err(|_| "KSPT truncated at sig data".to_string())?;
                sig_script.push((sig_len + 1) as u8);
                sig_script.extend_from_slice(&sig_bytes);
                sig_script.push(sighash_type);
            }
        } else {
            // v2: sig_count(1) + [pubkey_pos(1) + sighash_type(1) + sig(64)] × sig_count + redeem_script
            let sig_count = rd_u8(&bytes, &mut pos)
                .map_err(|_| "KSPT truncated at v2 sig".to_string())?
                as usize;
            if sig_count == 0 {
                return Err("Input has no signatures".into());
            }

            // Detect script type
            let is_p2sh = spk_len == 35
                && spk_script[0] == 0xAA   // OP_BLAKE2B
                && spk_script[1] == 0x20   // OP_DATA_32
                && spk_script[34] == 0x87; // OP_EQUAL
            let is_multisig = !is_p2sh && spk_len >= 37
                && spk_script[spk_len - 1] == 0xAE // OP_CHECKMULTISIG
                && spk_script[0] >= 0x51 && spk_script[0] <= 0x55;

            if is_multisig || is_p2sh {
                // Collect sigs sorted by pubkey position
                let mut sigs: Vec<(u8, Vec<u8>)> = Vec::new();
                for _s in 0..sig_count {
                    let pubkey_pos = rd_u8(&bytes, &mut pos)
                        .map_err(|_| "KSPT truncated at multisig sig".to_string())?;
                    let sighash_type = rd_u8(&bytes, &mut pos)
                        .map_err(|_| "KSPT truncated at multisig sig".to_string())?;
                    let sig_bytes = rd_take(&bytes, &mut pos, 64)
                        .map_err(|_| "KSPT truncated at multisig sig".to_string())?;
                    let mut sig_data = Vec::with_capacity(65);
                    sig_data.extend_from_slice(sig_bytes);
                    sig_data.push(sighash_type);
                    sigs.push((pubkey_pos, sig_data));
                }
                sigs.sort_by_key(|s| s.0);

                // Redeem script — read it first to get M
                let rs_len = rd_u8(&bytes, &mut pos)
                    .map_err(|_| "KSPT truncated at redeem script".to_string())?
                    as usize;
                let redeem_script = if rs_len > 0 {
                    let rs = rd_take(&bytes, &mut pos, rs_len)
                        .map_err(|_| "KSPT truncated at redeem data".to_string())?;
                    Some(rs.to_vec())
                } else {
                    None
                };

                // Extract M from redeem script (first byte = OP_1..OP_16 = 0x51..0x60)
                let m = if let Some(ref rs) = redeem_script {
                    if !rs.is_empty() && rs[0] >= 0x51 && rs[0] <= 0x60 {
                        (rs[0] - 0x50) as usize
                    } else {
                        sigs.len()
                    }
                } else {
                    sigs.len()
                };

                // Only push M signatures (sorted by pubkey position)
                let sigs_to_push = sigs.len().min(m);
                for sig in &sigs[..sigs_to_push] {
                    sig_script.push(sig.1.len() as u8);
                    sig_script.extend_from_slice(&sig.1);
                }

                // Push redeem script for P2SH
                if let Some(ref rs) = redeem_script {
                    if is_p2sh {
                        if rs.len() <= 75 {
                            sig_script.push(rs.len() as u8);
                        } else {
                            sig_script.push(0x4C); // OP_PUSHDATA1
                            sig_script.push(rs.len() as u8);
                        }
                        sig_script.extend_from_slice(rs);
                    }
                }
            } else {
                // P2PK with v2 format — use first sig
                let _pubkey_pos = rd_u8(&bytes, &mut pos)
                    .map_err(|_| "KSPT truncated at v2 P2PK sig".to_string())?;
                let sighash_type = rd_u8(&bytes, &mut pos)
                    .map_err(|_| "KSPT truncated at v2 P2PK sig".to_string())?;
                let sig_bytes = rd_take(&bytes, &mut pos, 64)
                    .map_err(|_| "KSPT truncated at v2 P2PK sig".to_string())?
                    .to_vec();
                sig_script.push(65u8);
                sig_script.extend_from_slice(&sig_bytes);
                sig_script.push(sighash_type);
                // Skip remaining sigs (saturating: overshoot only ends the
                // input's byte stream, later reads are bounds-checked)
                pos = pos.saturating_add(66 * (sig_count - 1));
                // Skip redeem script
                if let Ok(rs_len) = rd_u8(&bytes, &mut pos) {
                    pos = pos.saturating_add(rs_len as usize);
                }
            }
        }

        inputs.push(TxInput {
            prev_tx_id,
            prev_index,
            sig_script,
            sequence,
            sig_op_count,
        });
    }

    // Parse outputs
    struct TxOutput {
        value: u64,
        spk_version: u16,
        spk_script: Vec<u8>,
    }

    let mut outputs = Vec::new();
    for _o in 0..num_outputs {
        let value = rd_u64(&bytes, &mut pos).map_err(|_| "KSPT truncated at output".to_string())?;
        let spk_version =
            rd_u16(&bytes, &mut pos).map_err(|_| "KSPT truncated at output".to_string())?;
        let spk_len =
            rd_u8(&bytes, &mut pos).map_err(|_| "KSPT truncated at output".to_string())? as usize;
        let spk_script = rd_take(&bytes, &mut pos, spk_len)
            .map_err(|_| "KSPT truncated at output spk".to_string())?
            .to_vec();
        outputs.push(TxOutput {
            value,
            spk_version,
            spk_script,
        });
    }

    // Build SubmitTransactionRequest Borsh payload
    let mut req_payload = Vec::new();
    bw_u16(&mut req_payload, 1).unwrap(); // request version

    // serialize!(RpcTransaction)
    let mut tx_buf = Vec::new();
    bw_u16(&mut tx_buf, 1).unwrap(); // struct version
    bw_u16(&mut tx_buf, tx_version).unwrap();

    // serialize!(Vec<Input>)
    {
        let mut inputs_buf = Vec::new();
        bw_u32(&mut inputs_buf, num_inputs as u32).unwrap();
        for inp in &inputs {
            let mut inp_buf = Vec::new();
            bw_u8(&mut inp_buf, 1).unwrap(); // input version

            let mut op_buf = Vec::new();
            bw_u8(&mut op_buf, 1).unwrap(); // outpoint version
            op_buf.extend_from_slice(&inp.prev_tx_id);
            bw_u32(&mut op_buf, inp.prev_index).unwrap();
            bw_bytes(&mut inp_buf, &op_buf).unwrap();

            bw_bytes(&mut inp_buf, &inp.sig_script).unwrap();
            bw_u64(&mut inp_buf, inp.sequence).unwrap();
            bw_u8(&mut inp_buf, inp.sig_op_count).unwrap();

            bw_bytes(&mut inp_buf, &[0u8]).unwrap(); // None verbose data

            bw_bytes(&mut inputs_buf, &inp_buf).unwrap();
        }
        bw_bytes(&mut tx_buf, &inputs_buf).unwrap();
    }

    // serialize!(Vec<Output>)
    {
        let mut outputs_buf = Vec::new();
        bw_u32(&mut outputs_buf, num_outputs as u32).unwrap();
        for out in &outputs {
            let mut out_buf = Vec::new();
            bw_u8(&mut out_buf, 1).unwrap(); // output version
            bw_u64(&mut out_buf, out.value).unwrap();
            bw_u16(&mut out_buf, out.spk_version).unwrap();
            bw_bytes(&mut out_buf, &out.spk_script).unwrap();

            bw_bytes(&mut out_buf, &[0u8]).unwrap(); // None verbose data

            bw_bytes(&mut outputs_buf, &out_buf).unwrap();
        }
        bw_bytes(&mut tx_buf, &outputs_buf).unwrap();
    }

    bw_u64(&mut tx_buf, locktime).unwrap();
    tx_buf.extend_from_slice(&subnetwork_id);
    bw_u64(&mut tx_buf, gas).unwrap();
    bw_bytes(&mut tx_buf, &tx_payload).unwrap();
    bw_u64(&mut tx_buf, 0).unwrap(); // mass
    bw_bytes(&mut tx_buf, &[0u8]).unwrap(); // None verbose data

    bw_bytes(&mut req_payload, &tx_buf).unwrap();
    bw_u8(&mut req_payload, 0).unwrap(); // allow_orphan = false

    // Send via wRPC
    let response = ws_rpc_call(ws_url, OP_SUBMIT_TRANSACTION, &req_payload).await?;

    // Parse SubmitTransactionResponse
    if response.is_empty() {
        return Err("Empty response from SubmitTransaction".into());
    }

    // Check if response is an ASCII error message
    if response.len() > 4 {
        // Try to detect text error in response
        let text_check = String::from_utf8_lossy(&response);
        if text_check.contains("Reject")
            || text_check.contains("reject")
            || text_check.contains("error")
            || text_check.contains("Error")
        {
            return Err(format!(
                "Node rejected: {}",
                text_check.chars().take(200).collect::<String>()
            ));
        }
    }

    // wRPC Borsh error format: first byte 0x00 = error, 0x01 = success
    if response[0] == 0x00 {
        // Error response — try to extract error message
        // Format: 0x00 + len(u32) + error_bytes
        if response.len() > 5 {
            let err_len =
                u32::from_le_bytes([response[1], response[2], response[3], response[4]]) as usize;
            let end = (5 + err_len).min(response.len());
            let err_text = String::from_utf8_lossy(&response[5..end]);
            return Err(format!("Node rejected TX: {}", err_text));
        }
        return Err("Transaction rejected by node".into());
    }

    // Result tag + Vec<u8> outer wrapper + version(u16) + TransactionId([u8;32])
    let inner = if response.len() > 5 {
        let start = if response[0] == 0x01 { 1 } else { 0 };
        if start + 4 > response.len() {
            &response[..]
        } else {
            let len = u32::from_le_bytes([
                response[start],
                response[start + 1],
                response[start + 2],
                response[start + 3],
            ]) as usize;
            let end = (start + 4 + len).min(response.len());
            &response[start + 4..end]
        }
    } else {
        &response[..]
    };

    if inner.len() >= 34 {
        // Check if this looks like a text error instead of a TX ID
        let text_check = String::from_utf8_lossy(inner);
        if text_check.contains("Reject") || text_check.contains("error") {
            return Err(format!("Node rejected TX: {}", text_check));
        }
        let tx_id = hex::encode(&inner[2..34]);
        web_sys::console::log_1(&format!("[KasSee] TX broadcast: {}", tx_id).into());
        Ok(tx_id)
    } else if inner.len() >= 2 {
        let text_check = String::from_utf8_lossy(inner);
        if text_check.contains("Reject") || text_check.contains("error") {
            return Err(format!("Node rejected TX: {}", text_check));
        }
        Ok(hex::encode(inner))
    } else {
        Ok("broadcast_ok".into())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// PSKT-native broadcast path
// ═══════════════════════════════════════════════════════════════════════
//
// Submits a consensus-shape transaction assembled directly from a PSKT
// Finalizer/Extractor (see `pskt::finalize_to_consensus_tx`), bypassing
// the legacy KSPT parser at line 433. No intermediate KSPT blob exists
// on this path — PSKB JSON is walked once, sig_scripts are assembled
// per input with the partial sigs + redeem script, and the resulting
// consensus Transaction is Borsh-serialized straight onto the wire.
//
// The wire envelope (SubmitTransactionRequest / SubmitTransactionResponse)
// is byte-identical to what `broadcast_signed` produces — this function
// just takes the already-assembled inputs/outputs/tx_header, skipping
// the KSPT parse step that `broadcast_signed` runs first.

/// One finalized consensus-layer input, ready for Borsh serialization.
#[derive(Clone)]
pub struct ConsensusInput {
    pub prev_tx_id: [u8; 32],
    pub prev_index: u32,
    pub sig_script: Vec<u8>,
    pub sequence: u64,
    pub sig_op_count: u8,
}

/// One consensus-layer output, ready for Borsh serialization.
#[derive(Clone)]
pub struct ConsensusOutput {
    pub value: u64,
    pub spk_version: u16,
    pub spk_script: Vec<u8>,
    /// Optional covenant binding: (authorizing_input, covenant_id).
    /// When set, output is serialized as version 2 with covenant data.
    pub covenant: Option<(u16, [u8; 32])>,
}

/// Submit a transaction assembled directly from PSKT. No KSPT
/// intermediate. Produces the same on-wire Borsh RpcTransaction that
/// `broadcast_signed` produces — only the input assembly path differs.
#[allow(clippy::too_many_arguments)]
pub async fn submit_consensus_tx(
    ws_url: &str,
    tx_version: u16,
    inputs: &[ConsensusInput],
    outputs: &[ConsensusOutput],
    locktime: u64,
    subnetwork_id: &[u8; 20],
    gas: u64,
    tx_payload: &[u8],
) -> Result<String, String> {
    let mut req_payload = Vec::new();
    bw_u16(&mut req_payload, 1).unwrap(); // request version

    // serialize!(RpcTransaction)
    let mut tx_buf = Vec::new();
    bw_u16(&mut tx_buf, 1).unwrap(); // struct version
    bw_u16(&mut tx_buf, tx_version).unwrap();

    // Vec<Input>
    {
        let mut inputs_buf = Vec::new();
        bw_u32(&mut inputs_buf, inputs.len() as u32).unwrap();
        for (idx, inp) in inputs.iter().enumerate() {
            let mut inp_buf = Vec::new();
            bw_u8(&mut inp_buf, 2).unwrap(); // input version 2 (with compute_budget)

            let mut op_buf = Vec::new();
            bw_u8(&mut op_buf, 1).unwrap(); // outpoint version
            op_buf.extend_from_slice(&inp.prev_tx_id);
            bw_u32(&mut op_buf, inp.prev_index).unwrap();
            bw_bytes(&mut inp_buf, &op_buf).unwrap();

            bw_bytes(&mut inp_buf, &inp.sig_script).unwrap();
            bw_u64(&mut inp_buf, inp.sequence).unwrap();

            // TX version >= 1 uses compute_budget (sig_op_count must be 0).
            // TX version 0 uses sig_op_count (compute_budget must be 0).
            //
            // Budget conversion (verified against v2.0.1 units.rs):
            // one sigop = 100,000 script units; one budget unit = 10,000
            // units; every input gets 9,999 free units. So cb = sigop * 10
            // exactly covers the sigops, and cb = 0 is correct for no-sig
            // covenant inputs: pushed bytes cost 1 unit/byte and hash ops
            // 1-2 units/byte, so typical no-sig scripts run well inside
            // the free allowance. Committing budget costs 100 grams per
            // unit, so the old floor of 10 wasted 1,000 grams (100,000
            // sompi at 100 sompi/gram) on every no-sig input.
            //
            // For tx v1 the sig_op_count byte sent to the node is always 0,
            // so ConsensusInput.sig_op_count is purely this budget knob: a
            // heavy no-sig script can buy budget by setting it. Each unit
            // of the knob = 10 budget units = 1,000 grams, the same
            // mechanism the ZK path already uses with sig_op_count = 255.
            let (soc, cb) = if tx_version >= 1 {
                (0u8, (inp.sig_op_count as u16) * 10)
            } else {
                (inp.sig_op_count, 0u16)
            };

            web_sys::console::log_1(
                &format!(
                "[KasSee] submit input[{}]: sequence={}, sig_len={}, sig_op={}, compute_budget={}",
                idx, inp.sequence, inp.sig_script.len(), soc, cb
            )
                .into(),
            );
            bw_u8(&mut inp_buf, soc).unwrap();

            bw_bytes(&mut inp_buf, &[0u8]).unwrap(); // None verbose data
            bw_u16(&mut inp_buf, cb).unwrap(); // compute_budget (version 2 field)
            bw_bytes(&mut inputs_buf, &inp_buf).unwrap();
        }
        bw_bytes(&mut tx_buf, &inputs_buf).unwrap();
    }

    // Vec<Output>
    {
        let mut outputs_buf = Vec::new();
        bw_u32(&mut outputs_buf, outputs.len() as u32).unwrap();
        for out in outputs {
            let mut out_buf = Vec::new();
            if out.covenant.is_some() {
                bw_u8(&mut out_buf, 2).unwrap(); // output version 2 (with covenant)
            } else {
                bw_u8(&mut out_buf, 1).unwrap(); // output version 1 (no covenant)
            }
            bw_u64(&mut out_buf, out.value).unwrap();
            bw_u16(&mut out_buf, out.spk_version).unwrap();
            bw_bytes(&mut out_buf, &out.spk_script).unwrap();

            bw_bytes(&mut out_buf, &[0u8]).unwrap(); // None verbose data

            // Covenant binding (version 2 outputs only)
            // Format: bw_bytes(Option blob) where Option blob =
            //   None: [0x00]
            //   Some: [0x01] + bw_bytes(CovenantBinding blob) where blob =
            //     [struct_version=0x01] + [auth_input: u16 LE] + [covenant_id: 32 bytes]
            if let Some((auth_input, covenant_id)) = out.covenant.as_ref() {
                let mut cov_inner = Vec::with_capacity(35);
                cov_inner.push(0x01); // struct version
                cov_inner.extend_from_slice(&auth_input.to_le_bytes());
                cov_inner.extend_from_slice(covenant_id);

                let mut option_blob = Vec::with_capacity(40);
                option_blob.push(0x01); // Some
                bw_bytes(&mut option_blob, &cov_inner).unwrap();

                bw_bytes(&mut out_buf, &option_blob).unwrap();
            }

            bw_bytes(&mut outputs_buf, &out_buf).unwrap();
        }
        bw_bytes(&mut tx_buf, &outputs_buf).unwrap();
    }

    bw_u64(&mut tx_buf, locktime).unwrap();
    tx_buf.extend_from_slice(subnetwork_id);
    bw_u64(&mut tx_buf, gas).unwrap();
    bw_bytes(&mut tx_buf, tx_payload).unwrap();
    bw_u64(&mut tx_buf, 0).unwrap(); // mass
    bw_bytes(&mut tx_buf, &[0u8]).unwrap(); // None verbose data

    bw_bytes(&mut req_payload, &tx_buf).unwrap();
    bw_u8(&mut req_payload, 0).unwrap(); // allow_orphan = false

    let response = ws_rpc_call(ws_url, OP_SUBMIT_TRANSACTION, &req_payload).await?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] SubmitTx response: {} bytes, first={:?}",
            response.len(),
            if response.len() >= 8 {
                &response[..8]
            } else {
                &response[..]
            }
        )
        .into(),
    );

    if response.is_empty() {
        return Err("Empty response from SubmitTransaction".into());
    }

    if response.len() > 4 {
        let text_check = String::from_utf8_lossy(&response);
        if text_check.contains("Reject")
            || text_check.contains("reject")
            || text_check.contains("error")
            || text_check.contains("Error")
        {
            web_sys::console::log_1(
                &format!(
                    "[KasSee] SubmitTx REJECTED: {}",
                    text_check.chars().take(300).collect::<String>()
                )
                .into(),
            );
            return Err(format!(
                "Node rejected: {}",
                text_check.chars().take(200).collect::<String>()
            ));
        }
    }

    if response[0] == 0x00 {
        if response.len() > 5 {
            let err_len =
                u32::from_le_bytes([response[1], response[2], response[3], response[4]]) as usize;
            let end = (5 + err_len).min(response.len());
            let err_text = String::from_utf8_lossy(&response[5..end]);
            return Err(format!("Node rejected TX: {}", err_text));
        }
        return Err("Transaction rejected by node".into());
    }

    let inner = if response.len() > 5 {
        let start = if response[0] == 0x01 { 1 } else { 0 };
        if start + 4 > response.len() {
            &response[..]
        } else {
            let len = u32::from_le_bytes([
                response[start],
                response[start + 1],
                response[start + 2],
                response[start + 3],
            ]) as usize;
            let end = (start + 4 + len).min(response.len());
            &response[start + 4..end]
        }
    } else {
        &response[..]
    };

    if inner.len() >= 34 {
        let text_check = String::from_utf8_lossy(inner);
        if text_check.contains("Reject") || text_check.contains("error") {
            return Err(format!("Node rejected TX: {}", text_check));
        }
        let tx_id = hex::encode(&inner[2..34]);
        web_sys::console::log_1(&format!("[KasSee] TX broadcast (PSKT path): {}", tx_id).into());
        Ok(tx_id)
    } else if inner.len() >= 2 {
        let text_check = String::from_utf8_lossy(inner);
        if text_check.contains("Reject") || text_check.contains("error") {
            return Err(format!("Node rejected TX: {}", text_check));
        }
        Ok(hex::encode(inner))
    } else {
        Ok("broadcast_ok".into())
    }
}

/// Broadcast a pre-built frozen TX (already Borsh-encoded as hex).
/// Build a raw TX from UTXOs + sig_script + destination, then broadcast.
/// Used by adaptor swap claims where the TX is fully signed in browser (no KasSigner).
pub async fn build_and_broadcast_raw(
    ws_url: &str,
    utxos: &[UtxoEntry],
    sig_script: &[u8],
    dest_spk_version: u16,
    dest_spk_script: &[u8],
    out_amount: u64,
    sig_op_count: u8,
) -> Result<String, String> {
    let e = |err: std::io::Error| format!("IO: {}", err);

    let mut req_payload = Vec::new();
    bw_u16(&mut req_payload, 1).map_err(&e)?;

    let mut tx_buf = Vec::new();
    bw_u16(&mut tx_buf, 1).map_err(&e)?;
    bw_u16(&mut tx_buf, 1).map_err(&e)?;

    // Inputs
    {
        let mut inputs_buf = Vec::new();
        bw_u32(&mut inputs_buf, utxos.len() as u32).map_err(&e)?;
        for u in utxos {
            let mut inp_buf = Vec::new();
            bw_u8(&mut inp_buf, 2).map_err(&e)?; // input version 2 (compute_budget)

            let mut op_buf = Vec::new();
            bw_u8(&mut op_buf, 1).map_err(&e)?;
            let txid_bytes =
                hex::decode(&u.tx_id).map_err(|err| format!("Bad txid hex: {}", err))?;
            op_buf.extend_from_slice(&txid_bytes);
            bw_u32(&mut op_buf, u.index).map_err(&e)?;
            bw_bytes(&mut inp_buf, &op_buf).map_err(&e)?;

            bw_bytes(&mut inp_buf, sig_script).map_err(&e)?;
            bw_u64(&mut inp_buf, 0).map_err(&e)?; // sequence
            bw_u8(&mut inp_buf, 0).map_err(&e)?; // sig_op_count = 0 (tx version 1)
            bw_bytes(&mut inp_buf, &[0u8]).map_err(&e)?; // None verbose data
            let cb: u16 = (sig_op_count as u16) * 10; // compute_budget
            bw_u16(&mut inp_buf, cb).map_err(&e)?;

            bw_bytes(&mut inputs_buf, &inp_buf).map_err(&e)?;
        }
        bw_bytes(&mut tx_buf, &inputs_buf).map_err(&e)?;
    }

    // Outputs
    {
        let mut outputs_buf = Vec::new();
        bw_u32(&mut outputs_buf, 1).map_err(&e)?;
        let mut out_buf = Vec::new();
        bw_u8(&mut out_buf, 1).map_err(&e)?;
        bw_u64(&mut out_buf, out_amount).map_err(&e)?;
        bw_u16(&mut out_buf, dest_spk_version).map_err(&e)?;
        bw_bytes(&mut out_buf, dest_spk_script).map_err(&e)?;
        bw_bytes(&mut out_buf, &[0u8]).map_err(&e)?;
        bw_bytes(&mut outputs_buf, &out_buf).map_err(&e)?;
        bw_bytes(&mut tx_buf, &outputs_buf).map_err(&e)?;
    }

    bw_u64(&mut tx_buf, 0).map_err(&e)?;
    tx_buf.extend_from_slice(&[0u8; 20]);
    bw_u64(&mut tx_buf, 0).map_err(&e)?;
    bw_bytes(&mut tx_buf, &[]).map_err(&e)?;
    bw_u64(&mut tx_buf, 0).map_err(&e)?;
    bw_bytes(&mut tx_buf, &[0u8]).map_err(&e)?;

    bw_bytes(&mut req_payload, &tx_buf).map_err(&e)?;
    bw_u8(&mut req_payload, 0).map_err(&e)?;

    let response = ws_rpc_call(ws_url, OP_SUBMIT_TRANSACTION, &req_payload).await?;

    if response.is_empty() {
        return Err("Empty response from SubmitTransaction".into());
    }

    // Check for text errors
    if response.len() > 4 {
        let text_check = String::from_utf8_lossy(&response);
        if text_check.contains("Reject")
            || text_check.contains("reject")
            || text_check.contains("error")
            || text_check.contains("Error")
        {
            return Err(format!(
                "Node rejected: {}",
                text_check.chars().take(300).collect::<String>()
            ));
        }
    }

    // wRPC Borsh error format: 0x00 = error, 0x01 = success
    if response[0] == 0x00 {
        if response.len() > 5 {
            let err_len =
                u32::from_le_bytes([response[1], response[2], response[3], response[4]]) as usize;
            let end = (5 + err_len).min(response.len());
            let err_text = String::from_utf8_lossy(&response[5..end]);
            return Err(format!("Node rejected TX: {}", err_text));
        }
        return Err("Transaction rejected by node".into());
    }

    // Parse success response: 0x01 + u32 len + version(u16) + txid([u8;32])
    let inner = if response.len() > 5 && response[0] == 0x01 {
        let len = u32::from_le_bytes([response[1], response[2], response[3], response[4]]) as usize;
        let end = (5 + len).min(response.len());
        &response[5..end]
    } else {
        &response[..]
    };

    if inner.len() >= 34 {
        let tx_id = hex::encode(&inner[2..34]);
        web_sys::console::log_1(&format!("[KasSee] Adaptor TX broadcast: {}", tx_id).into());
        Ok(tx_id)
    } else {
        Ok("broadcast_ok".into())
    }
}

/// Fetch the current virtual DAA score from the node via GetBlockDagInfo RPC.
pub async fn get_virtual_daa_score(ws_url: &str) -> Result<u64, String> {
    let mut req = Vec::new();
    bw_u16(&mut req, 1).unwrap();

    let response = ws_rpc_call(ws_url, OP_GET_BLOCK_DAG_INFO, &req).await?;

    if response.len() < 20 {
        return Err(format!("Response too short: {} bytes", response.len()));
    }

    let mut pos: usize = 0;

    // workflow_serializer envelope: u8 version + u32 payload_len
    pos += 1; // u8 outer version
    pos += 4; // u32 payload length

    // Inner: u16 version
    pos += 2;

    // NetworkId: u8 NetworkType variant + u8 Option tag + optional u32 suffix
    pos += 1; // NetworkType (u8 enum)
    if pos >= response.len() {
        return Err("short: option tag".into());
    }
    let has_suffix = response[pos];
    pos += 1;
    if has_suffix == 1 {
        pos += 4;
    }

    // u64 block_count
    pos += 8;
    // u64 header_count
    pos += 8;

    // Vec<Hash> tip_hashes: u32 count + count*32
    if pos + 4 > response.len() {
        return Err(format!("short at tip_count pos={}", pos));
    }
    let tip_count = u32::from_le_bytes(response[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4 + tip_count * 32;

    // f64 difficulty
    pos += 8;
    // u64 past_median_time
    pos += 8;

    // Vec<Hash> virtual_parent_hashes: u32 count + count*32
    if pos + 4 > response.len() {
        return Err(format!("short at vp_count pos={}", pos));
    }
    let vp_count = u32::from_le_bytes(response[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4 + vp_count * 32;

    // Hash pruning_point_hash: 32 bytes
    pos += 32;

    // u64 virtual_daa_score
    if pos + 8 > response.len() {
        return Err(format!("short at daa pos={}/{}", pos, response.len()));
    }
    let daa = u64::from_le_bytes(response[pos..pos + 8].try_into().unwrap());

    Ok(daa)
}

/// Get the sink block hash from the node.
pub async fn get_sink_hash(ws_url: &str) -> Result<[u8; 32], String> {
    let mut req = Vec::new();
    bw_u16(&mut req, 1).unwrap();

    let response = ws_rpc_call(ws_url, OP_GET_SINK, &req).await?;

    // Envelope: u8 version + u32 payload_len + u16 inner_version + 32 bytes hash
    if response.len() < 39 {
        return Err(format!(
            "GetSink response too short: {} bytes",
            response.len()
        ));
    }
    let mut pos = 0;
    pos += 1; // outer version
    pos += 4; // payload length
    pos += 2; // inner version
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&response[pos..pos + 32]);
    Ok(hash)
}

/// Fetch a block's raw Borsh response bytes (with transactions).
pub async fn get_block_raw(ws_url: &str, hash: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut req = Vec::new();
    bw_u16(&mut req, 1).unwrap();
    req.extend_from_slice(hash); // block hash
    req.push(1); // include_transactions = true

    ws_rpc_call(ws_url, OP_GET_BLOCK, &req).await
}

/// Search recent blocks for a TX that spends a specific outpoint,
/// then extract the preimage from the sig_script.
///
/// The sig_script for an atomic claim is: <preimage_push> <sig_push> OP_FALSE <redeem_push>
/// The preimage is the first pushdata in the sig_script.
///
/// Returns the preimage as hex, or empty string if not found.
pub async fn find_preimage_for_outpoint(
    ws_url: &str,
    outpoint_txid_hex: &str,
    _covenant_address: &str,
) -> Result<String, String> {
    let txid_bytes =
        hex::decode(outpoint_txid_hex).map_err(|e| format!("Invalid txid hex: {}", e))?;
    if txid_bytes.len() != 32 {
        return Err("txid must be 32 bytes".into());
    }

    web_sys::console::log_1(
        &format!(
            "[KasSee] Preimage search: looking for outpoint {}",
            outpoint_txid_hex
        )
        .into(),
    );

    // Fast path: just check the current sink block (1 RPC call).
    // The caller retries rapidly (every 200ms), and the sink advances with each call,
    // naturally covering different blocks through the DAG.
    // On the last attempt, the caller can request a deep search with parents.

    let sink_hash = get_sink_hash(ws_url).await?;
    let raw = get_block_raw(ws_url, &sink_hash).await?;

    if let Some(preimage) = scan_raw_for_preimage(&raw, &txid_bytes) {
        web_sys::console::log_1(
            &format!("[KasSee] Preimage FOUND in sink: {} bytes", preimage.len()).into(),
        );
        return Ok(hex::encode(&preimage));
    }

    Ok(String::new())
}

/// Scan raw block bytes for a TX input that references the given outpoint txid,
/// then extract the preimage (first pushdata in the sig_script).
pub fn scan_raw_for_preimage_pub(raw: &[u8], txid: &[u8]) -> Option<Vec<u8>> {
    scan_raw_for_preimage(raw, txid)
}

fn scan_raw_for_preimage(raw: &[u8], txid: &[u8]) -> Option<Vec<u8>> {
    if txid.len() != 32 || raw.len() < 50 {
        return None;
    }

    // In Kaspa Borsh (workflow_serializer), TX input outpoint is wrapped:
    //   bw_bytes( outpoint_version(u8=0x01) + tx_id(32) + index(u32) )
    // So the byte pattern is:
    //   u32(37) 0x01 <txid:32> <index:4>
    // Followed by the sig_script also wrapped in bw_bytes:
    //   u32(sig_len) <sig_script_bytes>
    //
    // We search for 0x01 + txid pattern and check if preceded by u32(37).

    for i in 1..raw.len().saturating_sub(50) {
        // Look for version byte 0x01 followed by txid
        if raw[i] != 0x01 || &raw[i + 1..i + 33] != txid {
            continue;
        }

        // Verify the u32 length prefix before the version byte
        if i < 4 {
            continue;
        }
        let len_prefix = u32::from_le_bytes(raw[i - 4..i].try_into().ok()?) as usize;
        // Outpoint blob should be 37 bytes: 1 (version) + 32 (txid) + 4 (index)
        if len_prefix != 37 {
            continue;
        }

        // After txid: u32 index (4 bytes)
        let after_outpoint = i + 33 + 4; // version + txid + index

        // Next comes sig_script wrapped in bw_bytes: u32 length + data
        if after_outpoint + 4 > raw.len() {
            continue;
        }
        let sig_len =
            u32::from_le_bytes(raw[after_outpoint..after_outpoint + 4].try_into().ok()?) as usize;

        // Sanity check: sig_script should be 50-1000 bytes for an atomic claim
        if !(10..=1000).contains(&sig_len) {
            continue;
        }
        let sig_start = after_outpoint + 4;
        if sig_start + sig_len > raw.len() {
            continue;
        }

        let sig_script = &raw[sig_start..sig_start + sig_len];

        web_sys::console::log_1(&format!(
            "[KasSee] Preimage scanner: found outpoint at pos {}, sig_script {} bytes, first bytes: {:02x}{:02x}{:02x}",
            i, sig_len, sig_script.first().copied().unwrap_or(0), sig_script.get(1).copied().unwrap_or(0), sig_script.get(2).copied().unwrap_or(0)
        ).into());

        // Extract first pushdata from sig_script
        // Push opcodes: 0x01-0x4b = direct push of N bytes
        // 0x4c = OP_PUSHDATA1 (next byte is length)
        // 0x4d = OP_PUSHDATA2 (next 2 bytes are length LE)
        if sig_script.is_empty() {
            continue;
        }
        let first_byte = sig_script[0];
        let (preimage_start, preimage_len) = if (1..=0x4b).contains(&first_byte) {
            (1usize, first_byte as usize)
        } else if first_byte == 0x4c && sig_script.len() > 1 {
            (2usize, sig_script[1] as usize)
        } else if first_byte == 0x4d && sig_script.len() > 2 {
            let len = u16::from_le_bytes([sig_script[1], sig_script[2]]) as usize;
            (3usize, len)
        } else {
            continue;
        };

        if preimage_start + preimage_len > sig_script.len() {
            continue;
        }
        if preimage_len == 0 || preimage_len > 200 {
            continue;
        }

        let preimage = sig_script[preimage_start..preimage_start + preimage_len].to_vec();
        return Some(preimage);
    }
    None
}

/// Extract parent hashes from a GetBlock response.
/// The block header structure in Borsh (after envelope + block version + header blob):
///   header_version(u16) + parent_count(u32) + parent_hashes(32 bytes each)
fn extract_block_parents(raw: &[u8]) -> Vec<[u8; 32]> {
    let mut parents = Vec::new();
    if raw.len() < 20 {
        return parents;
    }

    // Search for a plausible parent hash array in the raw data.
    // Parent hashes are preceded by a u32 count. On TN12, typical parent count is 1-20.
    // We look for u32(N) where N is 1-30, followed by N*32 bytes that look like hashes.
    // The header blob starts early in the response, so scan the first 200 bytes.
    for i in 0..raw.len().min(200).saturating_sub(36) {
        let count = u32::from_le_bytes(match raw[i..i + 4].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        }) as usize;
        if !(1..=30).contains(&count) {
            continue;
        }
        let data_end = i + 4 + count * 32;
        if data_end > raw.len() {
            continue;
        }

        // Verify this looks like a hash array: at least some non-zero bytes
        let mut all_zero = true;
        for j in 0..count {
            let start = i + 4 + j * 32;
            if raw[start..start + 32].iter().any(|&b| b != 0) {
                all_zero = false;
            }
        }
        if all_zero {
            continue;
        }

        // Check if this is preceded by a u16 version (common pattern: u16(1) or u16(0))
        if i >= 2 {
            let ver = u16::from_le_bytes([raw[i - 2], raw[i - 1]]);
            if ver <= 2 {
                // Likely the header version + parent_count pattern
                for j in 0..count {
                    let start = i + 4 + j * 32;
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&raw[start..start + 32]);
                    parents.push(h);
                }
                return parents;
            }
        }
    }
    parents
}

/// Historical catch-up for stealth payments. Walk up to `max_blocks` recent
/// blocks starting from the sink, following the first parent each step, and
/// collect stealth ephemeral R values from any transaction payload tagged
/// b"KST1" || R(32). The live BlockAdded scan only sees blocks arriving while
/// subscribed; this recovers payments that landed while the receiver was
/// offline. Reuses the same Borsh byte-scan as the live path (a stray tag match
/// is harmless: device-side ECDH yields a P with no matching UTXO).
///
/// Returns a deduplicated list of 64-hex R values.
pub async fn scan_recent_blocks_for_stealth(
    ws_url: &str,
    max_blocks: u32,
) -> Result<Vec<String>, String> {
    const TAG: [u8; 4] = [0x4B, 0x53, 0x54, 0x31]; // "KST1"
    let mut found: Vec<String> = Vec::new();
    let mut visited: Vec<[u8; 32]> = Vec::new();

    let mut h = get_sink_hash(ws_url).await?;
    for _ in 0..max_blocks {
        if visited.iter().any(|v| v == &h) {
            break;
        }
        visited.push(h);

        let raw = match get_block_raw(ws_url, &h).await {
            Ok(r) => r,
            Err(_) => break,
        };

        // Scan the raw block (transactions included) for the KST1 tag.
        let mut i = 0usize;
        while i + 4 + 32 <= raw.len() {
            if raw[i] == TAG[0]
                && raw[i + 1] == TAG[1]
                && raw[i + 2] == TAG[2]
                && raw[i + 3] == TAG[3]
            {
                let r = &raw[i + 4..i + 4 + 32];
                if r.iter().any(|&b| b != 0) {
                    let rhex = hex::encode(r);
                    if !found.contains(&rhex) {
                        found.push(rhex);
                    }
                }
                i += 4 + 32;
            } else {
                i += 1;
            }
        }

        match extract_block_parents(&raw).first() {
            Some(p) => h = *p,
            None => break,
        }
    }

    Ok(found)
}

/// Extract tip hashes from GetBlockDagInfo response.
// Kept: retained for future use; not currently wired.
#[allow(dead_code)]
fn extract_tips(dag_info: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if dag_info.len() < 30 {
        return Err("BlockDagInfo too short".into());
    }
    let mut pos = 0;
    pos += 1; // outer version
    pos += 4; // payload length
    pos += 2; // inner version

    // NetworkId
    pos += 1; // NetworkType
    if pos >= dag_info.len() {
        return Err("short".into());
    }
    let has_suffix = dag_info[pos];
    pos += 1;
    if has_suffix == 1 {
        pos += 4;
    }

    pos += 8; // block_count
    pos += 8; // header_count

    // tip_hashes
    if pos + 4 > dag_info.len() {
        return Err("short at tips".into());
    }
    let tip_count = u32::from_le_bytes(dag_info[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    let mut tips = Vec::with_capacity(tip_count);
    for _ in 0..tip_count {
        if pos + 32 > dag_info.len() {
            break;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&dag_info[pos..pos + 32]);
        tips.push(h);
        pos += 32;
    }
    Ok(tips)
}

// ================================================================
// Covenant-ID-aware TX builders (KIP-20)
// ================================================================

/// Represents a single TX output for sighash computation.
pub struct SighashOutput {
    pub value: u64,
    pub spk_version: u16,
    pub spk_script: Vec<u8>,
    pub covenant: Option<(u16, [u8; 32])>, // (authorizing_input, covenant_id)
}

/// Compute the Kaspa Schnorr sighash for a TX version 1 input (SIGHASH_ALL).
///
/// Replicates consensus/core/src/hashing/sighash.rs::calc_schnorr_signature_hash
/// for TX version=1, sighash_type=SIGHASH_ALL (0x01).
///
/// blake2b key=b"TransactionSigningHash", hash_length=32
#[allow(clippy::too_many_arguments)]
pub fn compute_sighash_v1(
    // All inputs (outpoint + sequence)
    inputs: &[(&[u8; 32], u32, u64)], // (prev_txid, prev_index, sequence)
    // The input being signed
    input_index: usize,
    input_utxo_spk_version: u16,
    input_utxo_spk_script: &[u8],
    input_utxo_amount: u64,
    // All outputs
    outputs: &[SighashOutput],
    // TX fields
    locktime: u64,
    payload: &[u8],
    // subnetwork = native (20 zero bytes), gas = 0
) -> [u8; 32] {
    let bparams = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"TransactionSigningHash")
        .clone();

    let tx_version: u16 = 1;

    // previous_outputs_hash: hash of all input outpoints
    let prev_outputs_hash = {
        let mut h = bparams.to_state();
        for (txid, idx, _) in inputs {
            h.update(txid.as_ref());
            h.update(&idx.to_le_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // sequences_hash: hash of all input sequences
    let seq_hash = {
        let mut h = bparams.to_state();
        for (_, _, seq) in inputs {
            h.update(&seq.to_le_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // outputs_hash: hash of all outputs (version >= 1 includes covenant)
    let out_hash = {
        let mut h = bparams.to_state();
        for o in outputs {
            // hash_output for version >= 1
            h.update(&o.value.to_le_bytes());
            h.update(&o.spk_version.to_le_bytes());
            // write_var_bytes: len as u64 LE + bytes
            h.update(&(o.spk_script.len() as u64).to_le_bytes());
            h.update(&o.spk_script);
            // covenant
            match &o.covenant {
                None => {
                    h.update(&[0u8]);
                } // false
                Some((auth_input, cov_id)) => {
                    h.update(&[1u8]); // true
                    h.update(&auth_input.to_le_bytes());
                    h.update(cov_id);
                }
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // payload_hash: ZERO_HASH only for native + empty payload; otherwise blake2b(var_bytes(payload))
    // in the TransactionSigningHash domain. Covenant txs carry the revealed redeems here.
    let payload_hash = if payload.is_empty() {
        [0u8; 32]
    } else {
        let mut h = bparams.to_state();
        h.update(&(payload.len() as u64).to_le_bytes());
        h.update(payload);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // Final sighash
    let mut h = bparams.to_state();
    h.update(&tx_version.to_le_bytes());
    h.update(&prev_outputs_hash);
    h.update(&seq_hash);
    // NO sig_op_counts_hash for version >= 1

    // Current input outpoint
    let (txid, idx, seq) = &inputs[input_index];
    h.update(txid.as_ref());
    h.update(&idx.to_le_bytes());
    // Input UTXO's SPK
    h.update(&input_utxo_spk_version.to_le_bytes());
    h.update(&(input_utxo_spk_script.len() as u64).to_le_bytes());
    h.update(input_utxo_spk_script);
    // Amount and sequence
    h.update(&input_utxo_amount.to_le_bytes());
    h.update(&seq.to_le_bytes());
    // NO sig_op_count for version >= 1

    h.update(&out_hash);
    h.update(&locktime.to_le_bytes());
    h.update(&[0u8; 20]); // subnetwork_id (native)
    h.update(&0u64.to_le_bytes()); // gas
    h.update(&payload_hash);
    h.update(&[0x01u8]); // SIGHASH_ALL

    let mut result = [0u8; 32];
    result.copy_from_slice(h.finalize().as_bytes());
    result
}

/// Borsh-serialize a single TX output at version 2 (includes covenant binding).
/// If covenant is None, writes Option::None (0x00).
/// If covenant is Some((authorizing_input, covenant_id)), writes
///   0x01 (Option::Some) + 0x01 (binding version) + u16 LE + 32 bytes.
#[allow(clippy::unnecessary_unwrap)]
pub fn borsh_output_v2(
    w: &mut Vec<u8>,
    value: u64,
    spk_version: u16,
    spk_script: &[u8],
    covenant: Option<(u16, &[u8; 32])>, // (authorizing_input, covenant_id)
) -> Result<(), String> {
    let e = |err: std::io::Error| format!("IO: {}", err);
    let mut out_buf = Vec::new();

    if covenant.is_some() {
        // Version 2: includes covenant binding
        bw_u8(&mut out_buf, 2).map_err(&e)?;
        bw_u64(&mut out_buf, value).map_err(&e)?;
        bw_u16(&mut out_buf, spk_version).map_err(&e)?;
        bw_bytes(&mut out_buf, spk_script).map_err(&e)?;
        bw_bytes(&mut out_buf, &[0u8]).map_err(&e)?; // None verbose_data

        // serialize!(Option<RpcCovenantBinding>)
        // = Serializable(Option content)
        // Option::Some content = 0x01 + Serializable(binding)
        // Serializable(binding) = u32(35) + binding_bytes
        // binding = u8(1) + u16(auth) + [32]
        let (auth_input, cov_id) = covenant.unwrap();

        let mut binding_bytes = Vec::new();
        bw_u8(&mut binding_bytes, 1).map_err(&e)?; // binding version
        bw_u16(&mut binding_bytes, auth_input).map_err(&e)?;
        binding_bytes.extend_from_slice(cov_id); // 35 bytes total

        let mut option_content = Vec::new();
        option_content.push(0x01); // Some tag
        bw_bytes(&mut option_content, &binding_bytes).map_err(&e)?; // Serializable(binding)

        bw_bytes(&mut out_buf, &option_content).map_err(&e)?; // Serializable(Option)
    } else {
        // Version 1: no covenant field
        bw_u8(&mut out_buf, 1).map_err(&e)?;
        bw_u64(&mut out_buf, value).map_err(&e)?;
        bw_u16(&mut out_buf, spk_version).map_err(&e)?;
        bw_bytes(&mut out_buf, spk_script).map_err(&e)?;
        bw_bytes(&mut out_buf, &[0u8]).map_err(&e)?;
    }

    bw_bytes(w, &out_buf).map_err(&e)?;
    Ok(())
}

/// Build and broadcast a genesis Tagged Vault TX, signed in-browser.
///
/// Uses an ephemeral secret key to sign. The input UTXO must be a P2PK
/// output paying to the xonly pubkey derived from this secret key.
///
/// Input: ephemeral P2PK UTXO
/// Output 0: P2SH covenant UTXO with covenant binding (genesis)
/// Output 1: change (optional, no covenant)
///
/// Returns (txid_hex, covenant_id)
#[allow(clippy::too_many_arguments)]
pub async fn build_and_broadcast_tagged_vault_genesis(
    ws_url: &str,
    utxos: &[UtxoEntry],
    secret_key_hex: &str,
    covenant_spk_script: &[u8], // P2SH SPK
    send_amount: u64,
    change_spk: Option<&[u8]>,
    change_amount: u64,
    _redeem_script: &[u8],
) -> Result<(String, [u8; 32]), String> {
    if utxos.is_empty() {
        return Err("No UTXOs provided".into());
    }

    // Parse secret key
    let sk = crate::adaptor::scalar_from_hex(secret_key_hex)?;

    // Compute covenant_id from input[0]'s outpoint and output[0]'s fields
    let txid_bytes: [u8; 32] = hex::decode(&utxos[0].tx_id)
        .map_err(|e| format!("Bad txid: {}", e))?
        .try_into()
        .map_err(|_| "txid not 32 bytes".to_string())?;

    let auth_outputs: Vec<(u32, u64, u16, &[u8])> =
        vec![(0u32, send_amount, 0u16, covenant_spk_script)];
    let covenant_id = crate::kspt::compute_covenant_id(&txid_bytes, utxos[0].index, &auth_outputs);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Tagged Vault genesis: covenant_id={}",
            hex::encode(covenant_id)
        )
        .into(),
    );

    // Build outputs for sighash
    let mut sighash_outputs = vec![SighashOutput {
        value: send_amount,
        spk_version: 0,
        spk_script: covenant_spk_script.to_vec(),
        covenant: Some((0u16, covenant_id)),
    }];
    if let Some(chg_spk) = change_spk {
        if change_amount > 0 {
            sighash_outputs.push(SighashOutput {
                value: change_amount,
                spk_version: 0,
                spk_script: chg_spk.to_vec(),
                covenant: None,
            });
        }
    }

    // Build inputs list for sighash
    let mut inputs_for_sighash: Vec<([u8; 32], u32, u64)> = Vec::new();
    for u in utxos {
        let tid: [u8; 32] = hex::decode(&u.tx_id)
            .map_err(|e| format!("Bad txid: {}", e))?
            .try_into()
            .map_err(|_| "txid not 32 bytes".to_string())?;
        inputs_for_sighash.push((tid, u.index, 0u64));
    }
    let inputs_ref: Vec<(&[u8; 32], u32, u64)> = inputs_for_sighash
        .iter()
        .map(|(t, i, s)| (t, *i, *s))
        .collect();

    // Sign each input
    let mut sig_scripts: Vec<Vec<u8>> = Vec::new();
    for (inp_idx, u) in utxos.iter().enumerate() {
        let sighash = compute_sighash_v1(
            &inputs_ref,
            inp_idx,
            0, // P2PK spk version
            &u.script_public_key,
            u.amount,
            &sighash_outputs,
            0,   // locktime
            &[], // empty payload
        );

        let sig = crate::adaptor::bip340_sign(&sk, &sighash)?;

        // sig_script: <sig> <sighash_type>
        let mut ss = Vec::new();
        ss.push(65); // push 65 bytes
        ss.extend_from_slice(&sig);
        ss.push(0x01); // SIGHASH_ALL
        sig_scripts.push(ss);
    }

    // Serialize the TX
    let e = |err: std::io::Error| format!("IO: {}", err);

    let mut req_payload = Vec::new();
    bw_u16(&mut req_payload, 1).map_err(&e)?;

    let mut tx_buf = Vec::new();
    bw_u16(&mut tx_buf, 1).map_err(&e)?; // struct version
    bw_u16(&mut tx_buf, 1).map_err(&e)?; // tx version

    // Inputs
    {
        let mut inputs_buf = Vec::new();
        bw_u32(&mut inputs_buf, utxos.len() as u32).map_err(&e)?;
        for (i, u) in utxos.iter().enumerate() {
            let mut inp_buf = Vec::new();
            bw_u8(&mut inp_buf, 2).map_err(&e)?; // input version 2

            let mut op_buf = Vec::new();
            bw_u8(&mut op_buf, 1).map_err(&e)?;
            let txid = hex::decode(&u.tx_id).map_err(|e| format!("Bad txid: {}", e))?;
            op_buf.extend_from_slice(&txid);
            bw_u32(&mut op_buf, u.index).map_err(&e)?;
            bw_bytes(&mut inp_buf, &op_buf).map_err(&e)?;

            bw_bytes(&mut inp_buf, &sig_scripts[i]).map_err(&e)?;
            bw_u64(&mut inp_buf, 0).map_err(&e)?; // sequence
            bw_u8(&mut inp_buf, 0).map_err(&e)?; // sig_op_count field (unused in v1 TX)
            bw_bytes(&mut inp_buf, &[0u8]).map_err(&e)?; // None verbose
            bw_u16(&mut inp_buf, 10).map_err(&e)?; // compute_budget

            bw_bytes(&mut inputs_buf, &inp_buf).map_err(&e)?;
        }
        bw_bytes(&mut tx_buf, &inputs_buf).map_err(&e)?;
    }

    // Outputs
    {
        let num_outputs = sighash_outputs.len() as u32;
        let mut outputs_buf = Vec::new();
        bw_u32(&mut outputs_buf, num_outputs).map_err(&e)?;

        for o in &sighash_outputs {
            borsh_output_v2(
                &mut outputs_buf,
                o.value,
                o.spk_version,
                &o.spk_script,
                o.covenant.as_ref().map(|(ai, cid)| (*ai, cid)),
            )?;
        }

        bw_bytes(&mut tx_buf, &outputs_buf).map_err(&e)?;
    }

    bw_u64(&mut tx_buf, 0).map_err(&e)?; // locktime
    tx_buf.extend_from_slice(&[0u8; 20]); // subnetwork
    bw_u64(&mut tx_buf, 0).map_err(&e)?; // gas
    bw_bytes(&mut tx_buf, &[]).map_err(&e)?; // payload
    bw_u64(&mut tx_buf, 0).map_err(&e)?; // mass
    bw_bytes(&mut tx_buf, &[0u8]).map_err(&e)?; // None verbose

    bw_bytes(&mut req_payload, &tx_buf).map_err(&e)?;
    bw_u8(&mut req_payload, 0).map_err(&e)?;

    let response = ws_rpc_call(ws_url, OP_SUBMIT_TRANSACTION, &req_payload).await?;

    // Response is the payload from ws_rpc_call (kind=0 already verified).
    // SubmitTransactionResponse Serializable: u32(inner_len) + inner
    // inner: u16(version=1) + Hash(txid) = 34 bytes
    // So payload = u32(34) + u16(1) + [32 bytes txid]
    // txid starts at offset 6 (4 + 2)
    let txid_hex = if response.len() >= 38 {
        // u32(34) + u16(1) + 32-byte txid
        hex::encode(&response[6..38])
    } else if response.len() >= 34 {
        // Maybe no Serializable wrapper: u16(1) + 32-byte txid
        hex::encode(&response[2..34])
    } else {
        // Fallback: dump what we have
        web_sys::console::log_1(
            &format!(
                "[KasSee] TaggedVault genesis: unexpected response len={} hex={}",
                response.len(),
                hex::encode(&response)
            )
            .into(),
        );
        hex::encode(&response)
    };

    web_sys::console::log_1(
        &format!(
            "[KasSee] Tagged Vault genesis OK: txid={}, covenant_id={}",
            txid_hex,
            hex::encode(covenant_id)
        )
        .into(),
    );

    Ok((txid_hex, covenant_id))
}

/// Build and broadcast a continuation TX that spends a Tagged Vault UTXO.
///
/// The output carries the same covenant_id as the input (continuation case).
/// Signed in-browser with the owner's secret key.
///
/// Returns txid_hex on success.
#[allow(clippy::too_many_arguments)]
pub async fn build_and_broadcast_tagged_vault_continuation(
    ws_url: &str,
    utxos: &[UtxoEntry],
    secret_key_hex: &str,
    covenant_id: &[u8; 32],
    continuation_spk: &[u8], // P2SH SPK of the new covenant output
    send_amount: u64,
    change_spk: Option<&[u8]>,
    change_amount: u64,
    redeem_script: &[u8],
) -> Result<String, String> {
    if utxos.is_empty() {
        return Err("No UTXOs provided".into());
    }

    let sk = crate::adaptor::scalar_from_hex(secret_key_hex)?;

    // Build outputs for sighash
    let mut sighash_outputs = vec![SighashOutput {
        value: send_amount,
        spk_version: 0,
        spk_script: continuation_spk.to_vec(),
        covenant: Some((0u16, *covenant_id)), // continuation: same covenant_id
    }];
    if let Some(chg_spk) = change_spk {
        if change_amount > 0 {
            sighash_outputs.push(SighashOutput {
                value: change_amount,
                spk_version: 0,
                spk_script: chg_spk.to_vec(),
                covenant: None,
            });
        }
    }

    // Build inputs for sighash
    let mut inputs_for_sighash: Vec<([u8; 32], u32, u64)> = Vec::new();
    for u in utxos {
        let tid: [u8; 32] = hex::decode(&u.tx_id)
            .map_err(|e| format!("Bad txid: {}", e))?
            .try_into()
            .map_err(|_| "txid not 32 bytes".to_string())?;
        inputs_for_sighash.push((tid, u.index, 0u64));
    }
    let inputs_ref: Vec<(&[u8; 32], u32, u64)> = inputs_for_sighash
        .iter()
        .map(|(t, i, s)| (t, *i, *s))
        .collect();

    // Sign each input (P2SH: sighash uses the UTXO's SPK, which is the P2SH script)
    let mut sig_scripts: Vec<Vec<u8>> = Vec::new();
    for (inp_idx, u) in utxos.iter().enumerate() {
        let sighash = compute_sighash_v1(
            &inputs_ref,
            inp_idx,
            0,
            &u.script_public_key,
            u.amount,
            &sighash_outputs,
            0,
            &[],
        );

        let sig = crate::adaptor::bip340_sign(&sk, &sighash)?;

        // sig_script for P2SH covenant: <sig||sighash_type> OP_TRUE <redeem_script>
        let mut ss = Vec::new();
        // Push signature (65 bytes: 64-byte sig + 1-byte sighash type)
        ss.push(65);
        ss.extend_from_slice(&sig);
        ss.push(0x01); // SIGHASH_ALL
                       // OP_TRUE (selects IF branch... wait, tagged vault has no IF/ELSE)
                       // Actually tagged vault script is linear: CHECKSIGVERIFY + covenant check
                       // So sig_script is just: <sig||sighash> <redeem_script>
        crate::pskt::push_redeem_script(&mut ss, redeem_script)
            .map_err(|e| format!("push_redeem: {}", e))?;
        sig_scripts.push(ss);
    }

    // Serialize and broadcast
    let e = |err: std::io::Error| format!("IO: {}", err);

    let mut req_payload = Vec::new();
    bw_u16(&mut req_payload, 1).map_err(&e)?;

    let mut tx_buf = Vec::new();
    bw_u16(&mut tx_buf, 1).map_err(&e)?;
    bw_u16(&mut tx_buf, 1).map_err(&e)?;

    {
        let mut inputs_buf = Vec::new();
        bw_u32(&mut inputs_buf, utxos.len() as u32).map_err(&e)?;
        for (i, u) in utxos.iter().enumerate() {
            let mut inp_buf = Vec::new();
            bw_u8(&mut inp_buf, 2).map_err(&e)?;

            let mut op_buf = Vec::new();
            bw_u8(&mut op_buf, 1).map_err(&e)?;
            let txid = hex::decode(&u.tx_id).map_err(|e| format!("Bad txid: {}", e))?;
            op_buf.extend_from_slice(&txid);
            bw_u32(&mut op_buf, u.index).map_err(&e)?;
            bw_bytes(&mut inp_buf, &op_buf).map_err(&e)?;

            bw_bytes(&mut inp_buf, &sig_scripts[i]).map_err(&e)?;
            bw_u64(&mut inp_buf, 0).map_err(&e)?;
            bw_u8(&mut inp_buf, 0).map_err(&e)?;
            bw_bytes(&mut inp_buf, &[0u8]).map_err(&e)?;
            bw_u16(&mut inp_buf, 10).map_err(&e)?; // compute_budget

            bw_bytes(&mut inputs_buf, &inp_buf).map_err(&e)?;
        }
        bw_bytes(&mut tx_buf, &inputs_buf).map_err(&e)?;
    }

    {
        let num_outputs = sighash_outputs.len() as u32;
        let mut outputs_buf = Vec::new();
        bw_u32(&mut outputs_buf, num_outputs).map_err(&e)?;

        for o in &sighash_outputs {
            borsh_output_v2(
                &mut outputs_buf,
                o.value,
                o.spk_version,
                &o.spk_script,
                o.covenant.as_ref().map(|(ai, cid)| (*ai, cid)),
            )?;
        }

        bw_bytes(&mut tx_buf, &outputs_buf).map_err(&e)?;
    }

    bw_u64(&mut tx_buf, 0).map_err(&e)?;
    tx_buf.extend_from_slice(&[0u8; 20]);
    bw_u64(&mut tx_buf, 0).map_err(&e)?;
    bw_bytes(&mut tx_buf, &[]).map_err(&e)?;
    bw_u64(&mut tx_buf, 0).map_err(&e)?;
    bw_bytes(&mut tx_buf, &[0u8]).map_err(&e)?;

    bw_bytes(&mut req_payload, &tx_buf).map_err(&e)?;
    bw_u8(&mut req_payload, 0).map_err(&e)?;

    let response = ws_rpc_call(ws_url, OP_SUBMIT_TRANSACTION, &req_payload).await?;

    if response.is_empty() {
        return Err("Empty response".into());
    }

    // Parse txid from SubmitTransactionResponse
    let txid_hex = if response.len() >= 38 {
        hex::encode(&response[6..38])
    } else if response.len() >= 34 {
        hex::encode(&response[2..34])
    } else {
        hex::encode(&response)
    };

    web_sys::console::log_1(
        &format!("[KasSee] Tagged Vault continuation OK: txid={}", txid_hex).into(),
    );

    Ok(txid_hex)
}

/// Build and broadcast a split TX: one covenant input, two covenant outputs.
/// Both outputs carry the same covenant_id (continuation).
/// Used by the Split Vault PoC.
#[allow(clippy::too_many_arguments)]
pub async fn build_and_broadcast_split_vault(
    ws_url: &str,
    utxos: &[UtxoEntry],
    secret_key_hex: &str,
    covenant_id: &[u8; 32],
    split_spk: &[u8], // P2SH SPK for both outputs (same script)
    amount_a: u64,
    amount_b: u64,
    redeem_script: &[u8],
) -> Result<String, String> {
    if utxos.is_empty() {
        return Err("No UTXOs provided".into());
    }

    let sk = crate::adaptor::scalar_from_hex(secret_key_hex)?;

    // Two outputs, both with same covenant_id, both authorized by input 0
    let sighash_outputs = vec![
        SighashOutput {
            value: amount_a,
            spk_version: 0,
            spk_script: split_spk.to_vec(),
            covenant: Some((0u16, *covenant_id)),
        },
        SighashOutput {
            value: amount_b,
            spk_version: 0,
            spk_script: split_spk.to_vec(),
            covenant: Some((0u16, *covenant_id)),
        },
    ];

    let mut inputs_for_sighash: Vec<([u8; 32], u32, u64)> = Vec::new();
    for u in utxos {
        let tid: [u8; 32] = hex::decode(&u.tx_id)
            .map_err(|e| format!("Bad txid: {}", e))?
            .try_into()
            .map_err(|_| "txid not 32 bytes".to_string())?;
        inputs_for_sighash.push((tid, u.index, 0u64));
    }
    let inputs_ref: Vec<(&[u8; 32], u32, u64)> = inputs_for_sighash
        .iter()
        .map(|(t, i, s)| (t, *i, *s))
        .collect();

    let mut sig_scripts: Vec<Vec<u8>> = Vec::new();
    for (inp_idx, u) in utxos.iter().enumerate() {
        let sighash = compute_sighash_v1(
            &inputs_ref,
            inp_idx,
            0,
            &u.script_public_key,
            u.amount,
            &sighash_outputs,
            0,
            &[],
        );

        let sig = crate::adaptor::bip340_sign(&sk, &sighash)?;

        let mut ss = Vec::new();
        ss.push(65);
        ss.extend_from_slice(&sig);
        ss.push(0x01);
        crate::pskt::push_redeem_script(&mut ss, redeem_script)
            .map_err(|e| format!("push_redeem: {}", e))?;
        sig_scripts.push(ss);
    }

    let e = |err: std::io::Error| format!("IO: {}", err);

    let mut req_payload = Vec::new();
    bw_u16(&mut req_payload, 1).map_err(&e)?;

    let mut tx_buf = Vec::new();
    bw_u16(&mut tx_buf, 1).map_err(&e)?;
    bw_u16(&mut tx_buf, 1).map_err(&e)?;

    {
        let mut inputs_buf = Vec::new();
        bw_u32(&mut inputs_buf, utxos.len() as u32).map_err(&e)?;
        for (i, u) in utxos.iter().enumerate() {
            let mut inp_buf = Vec::new();
            bw_u8(&mut inp_buf, 2).map_err(&e)?;

            let mut op_buf = Vec::new();
            bw_u8(&mut op_buf, 1).map_err(&e)?;
            let txid = hex::decode(&u.tx_id).map_err(|e| format!("Bad txid: {}", e))?;
            op_buf.extend_from_slice(&txid);
            bw_u32(&mut op_buf, u.index).map_err(&e)?;
            bw_bytes(&mut inp_buf, &op_buf).map_err(&e)?;

            bw_bytes(&mut inp_buf, &sig_scripts[i]).map_err(&e)?;
            bw_u64(&mut inp_buf, 0).map_err(&e)?;
            bw_u8(&mut inp_buf, 0).map_err(&e)?;
            bw_bytes(&mut inp_buf, &[0u8]).map_err(&e)?;
            bw_u16(&mut inp_buf, 10).map_err(&e)?;

            bw_bytes(&mut inputs_buf, &inp_buf).map_err(&e)?;
        }
        bw_bytes(&mut tx_buf, &inputs_buf).map_err(&e)?;
    }

    {
        let mut outputs_buf = Vec::new();
        bw_u32(&mut outputs_buf, 2).map_err(&e)?; // 2 outputs

        for o in &sighash_outputs {
            borsh_output_v2(
                &mut outputs_buf,
                o.value,
                o.spk_version,
                &o.spk_script,
                o.covenant.as_ref().map(|(ai, cid)| (*ai, cid)),
            )?;
        }

        bw_bytes(&mut tx_buf, &outputs_buf).map_err(&e)?;
    }

    bw_u64(&mut tx_buf, 0).map_err(&e)?;
    tx_buf.extend_from_slice(&[0u8; 20]);
    bw_u64(&mut tx_buf, 0).map_err(&e)?;
    bw_bytes(&mut tx_buf, &[]).map_err(&e)?;
    bw_u64(&mut tx_buf, 0).map_err(&e)?;
    bw_bytes(&mut tx_buf, &[0u8]).map_err(&e)?;

    bw_bytes(&mut req_payload, &tx_buf).map_err(&e)?;
    bw_u8(&mut req_payload, 0).map_err(&e)?;

    web_sys::console::log_1(
        &format!("[KasSee] Split Vault payload: {} bytes", req_payload.len()).into(),
    );

    let response = ws_rpc_call(ws_url, OP_SUBMIT_TRANSACTION, &req_payload).await?;

    if response.is_empty() {
        return Err("Empty response".into());
    }

    let txid_hex = if response.len() >= 38 {
        hex::encode(&response[6..38])
    } else if response.len() >= 34 {
        hex::encode(&response[2..34])
    } else {
        hex::encode(&response)
    };

    web_sys::console::log_1(&format!("[KasSee] Split Vault OK: txid={}", txid_hex).into());

    Ok(txid_hex)
}

// ─────────────────────── Seq-Commit lane proof (KIP-21 / Toccata, v2.0.1) ───────────────────────
// v2.0.1 adds the GetSeqCommitLaneProof RPC (op 153). A "lane" is a subnetwork; its SMT key is
// the node's SeqCommitLaneKey hasher = BLAKE3 keyed, KEY = b"SeqCommitLaneKey" zero-padded to 32 bytes,
// data = subnetwork_id[20]. (The whole seq-commit family is blake3, not blake2b: crypto/hashes
// hashers.rs defines SeqCommitLaneKey under blake3_hasher!.) The proof verifies against the seq_commit
// carried in a chain block's accepted_id_merkle_root. Read-only; rides the existing ws_rpc_call transport.

/// SMT key for a lane: BLAKE3 keyed (key = b"SeqCommitLaneKey" padded to 32 bytes) over subnetwork_id[20].
/// `subnetwork_id_hex` is 20 bytes (40 hex chars). The "KST1" lane = 4b53543100..00 (4 ASCII + 16 zeros).
/// Verified against the node: lane_key(SUBNETWORK_ID_COINBASE) == COINBASE_LANE_KEY (8aa78027..b9e4).
#[wasm_bindgen]
pub fn seq_commit_lane_key(subnetwork_id_hex: &str) -> Result<String, JsValue> {
    let sid = hex::decode(subnetwork_id_hex.trim())
        .map_err(|e| JsValue::from_str(&format!("subnetwork_id hex: {}", e)))?;
    if sid.len() != 20 {
        return Err(JsValue::from_str(
            "subnetwork_id must be 20 bytes (40 hex chars)",
        ));
    }
    // Matches crypto/hashes blake3_hasher!{ SeqCommitLaneKey => b"SeqCommitLaneKey" }:
    // Hasher::new_keyed(&KEY) where KEY[0..16]=domain, KEY[16..32]=0.
    let mut key = [0u8; 32];
    key[..b"SeqCommitLaneKey".len()].copy_from_slice(b"SeqCommitLaneKey");
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(&sid);
    Ok(hex::encode(h.finalize().as_bytes()))
}

/// Precomputed lane_key(SUBNETWORK_ID_COINBASE). The coinbase lane is present in every block, so
/// fetching its proof confirms the seq_commit machinery is active without submitting any tx.
#[wasm_bindgen]
pub fn coinbase_lane_key() -> String {
    "8aa78027db66a16cb69692ee0af5cb76738ef80ad14c9d13920d7fa3cc40b9e4".to_string()
}

/// Fetch a Seq-Commit lane proof (op 153) for `lane_key_hex` against `block_hash_hex` (a
/// selected-parent-chain block). Pass "" for block_hash to use the current sink. Returns a JS
/// object; `raw_hex` is authoritative, the parsed fields are best-effort (the lane Option wrapper).
#[wasm_bindgen]
pub async fn get_seq_commit_lane_proof(
    ws_url: &str,
    block_hash_hex: &str,
    lane_key_hex: &str,
) -> Result<JsValue, JsValue> {
    let block_hash: [u8; 32] = if block_hash_hex.trim().is_empty() {
        get_sink_hash(ws_url)
            .await
            .map_err(|e| JsValue::from_str(&e))?
    } else {
        let b = hex::decode(block_hash_hex.trim())
            .map_err(|e| JsValue::from_str(&format!("block_hash hex: {}", e)))?;
        if b.len() != 32 {
            return Err(JsValue::from_str(
                "block_hash must be 32 bytes (64 hex chars)",
            ));
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    };
    let lk = hex::decode(lane_key_hex.trim())
        .map_err(|e| JsValue::from_str(&format!("lane_key hex: {}", e)))?;
    if lk.len() != 32 {
        return Err(JsValue::from_str(
            "lane_key must be 32 bytes (64 hex chars)",
        ));
    }

    // GetSeqCommitLaneProofRequest: u16 version=1 + block_hash[32] + lane_key[32]
    let mut req = Vec::new();
    bw_u16(&mut req, 1).unwrap();
    req.extend_from_slice(&block_hash);
    req.extend_from_slice(&lk);

    let obj = js_sys::Object::new();
    macro_rules! put {
        ($k:expr, $v:expr) => {{
            let _ = js_sys::Reflect::set(&obj, &JsValue::from_str($k), &$v);
        }};
    }
    put!("block_hash", JsValue::from_str(&hex::encode(block_hash)));
    put!("lane_key", JsValue::from_str(&hex::encode(&lk)));

    // op 153 = GetSeqCommitLaneProof
    let data = match ws_rpc_call(ws_url, 153, &req).await {
        Ok(d) => d,
        Err(e) => {
            put!("ok", JsValue::from_bool(false));
            put!("error", JsValue::from_str(&e));
            return Ok(obj.into());
        }
    };
    put!("ok", JsValue::from_bool(true));
    put!("raw_hex", JsValue::from_str(&hex::encode(&data)));

    // Envelope: u8 outer_version + u32 payload_len + u16 inner_version + GetSeqCommitLaneProofResponse.
    // Response fields: Vec<u8> smt_proof + serialize!(Option<RpcLaneEntry{tip:32, blue_score:u64}>)
    //   + payload_and_ctx_digest[32] + parent_seq_commit[32] + inactivity_shortcut[32].
    // The three trailing digests are the last 96 bytes -> read from the end (robust vs the Option wrapper).
    if data.len() >= 7 + 4 {
        let inner = &data[7..]; // skip outer_ver(1)+payload_len(4)+inner_ver(2)
        let sp_len = u32::from_le_bytes([inner[0], inner[1], inner[2], inner[3]]) as usize;
        put!("smt_proof_len", JsValue::from_f64(sp_len as f64));
        if 4 + sp_len <= inner.len() {
            put!(
                "smt_proof_hex",
                JsValue::from_str(&hex::encode(&inner[4..4 + sp_len]))
            );
        }
        if inner.len() >= 96 {
            let t = &inner[inner.len() - 96..];
            put!(
                "payload_and_ctx_digest",
                JsValue::from_str(&hex::encode(&t[0..32]))
            );
            put!(
                "parent_seq_commit",
                JsValue::from_str(&hex::encode(&t[32..64]))
            );
            put!(
                "inactivity_shortcut",
                JsValue::from_str(&hex::encode(&t[64..96]))
            );
        }
        // lane Option<RpcLaneEntry>, nested serialize! wrappers:
        // [u32 outer_len][Some=01][u32 inner_len][ver u8][tip 32][blue_score u64 LE]
        let b = 4 + sp_len; // option starts right after smt_proof
        if b + 5 <= inner.len() {
            if inner[b + 4] == 1 && b + 50 <= inner.len() {
                let tip_start = b + 10; // skip outer_len(4)+Some(1)+inner_len(4)+ver(1)
                put!("lane_present", JsValue::from_bool(true));
                put!(
                    "lane_tip",
                    JsValue::from_str(&hex::encode(&inner[tip_start..tip_start + 32]))
                );
                let bs = u64::from_le_bytes([
                    inner[tip_start + 32],
                    inner[tip_start + 33],
                    inner[tip_start + 34],
                    inner[tip_start + 35],
                    inner[tip_start + 36],
                    inner[tip_start + 37],
                    inner[tip_start + 38],
                    inner[tip_start + 39],
                ]);
                put!("lane_blue_score", JsValue::from_f64(bs as f64));
            } else if inner[b + 4] == 0 {
                put!("lane_present", JsValue::from_bool(false));
            }
        }
    }
    Ok(obj.into())
}

/// Like `compute_sighash_v1` but commits an explicit `subnetwork_id` (20 bytes) and `gas`.
/// `compute_sighash_v1` is the native special case (subnetwork = zeros, gas = 0); a lane tx
/// (e.g. KST1) MUST sign with this variant or the node rejects the signature.
#[allow(clippy::too_many_arguments)]
pub fn compute_sighash_v1_subnet(
    inputs: &[(&[u8; 32], u32, u64)],
    input_index: usize,
    input_utxo_spk_version: u16,
    input_utxo_spk_script: &[u8],
    input_utxo_amount: u64,
    outputs: &[SighashOutput],
    locktime: u64,
    payload: &[u8],
    subnetwork_id: &[u8; 20],
    gas: u64,
) -> [u8; 32] {
    let bparams = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"TransactionSigningHash")
        .clone();

    let tx_version: u16 = 1;

    let prev_outputs_hash = {
        let mut h = bparams.to_state();
        for (txid, idx, _) in inputs {
            h.update(txid.as_ref());
            h.update(&idx.to_le_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    let seq_hash = {
        let mut h = bparams.to_state();
        for (_, _, seq) in inputs {
            h.update(&seq.to_le_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    let out_hash = {
        let mut h = bparams.to_state();
        for o in outputs {
            h.update(&o.value.to_le_bytes());
            h.update(&o.spk_version.to_le_bytes());
            h.update(&(o.spk_script.len() as u64).to_le_bytes());
            h.update(&o.spk_script);
            match &o.covenant {
                None => {
                    h.update(&[0u8]);
                }
                Some((auth_input, cov_id)) => {
                    h.update(&[1u8]);
                    h.update(&auth_input.to_le_bytes());
                    h.update(cov_id);
                }
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    let payload_hash = if payload.is_empty() {
        [0u8; 32]
    } else {
        let mut h = bparams.to_state();
        h.update(&(payload.len() as u64).to_le_bytes());
        h.update(payload);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    let mut h = bparams.to_state();
    h.update(&tx_version.to_le_bytes());
    h.update(&prev_outputs_hash);
    h.update(&seq_hash);

    let (txid, idx, seq) = &inputs[input_index];
    h.update(txid.as_ref());
    h.update(&idx.to_le_bytes());
    h.update(&input_utxo_spk_version.to_le_bytes());
    h.update(&(input_utxo_spk_script.len() as u64).to_le_bytes());
    h.update(input_utxo_spk_script);
    h.update(&input_utxo_amount.to_le_bytes());
    h.update(&seq.to_le_bytes());

    h.update(&out_hash);
    h.update(&locktime.to_le_bytes());
    h.update(subnetwork_id); // explicit subnetwork (vs native zeros)
    h.update(&gas.to_le_bytes()); // explicit gas (vs 0)
    h.update(&payload_hash);
    h.update(&[0x01u8]); // SIGHASH_ALL

    let mut result = [0u8; 32];
    result.copy_from_slice(h.finalize().as_bytes());
    result
}
