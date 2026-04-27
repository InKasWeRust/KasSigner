// KasSee Web — Kaspa wRPC Borsh client
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// Borsh wRPC protocol over browser WebSocket.
// Request:  Option<u64>(id) + u8(op) + Vec<u8>(Serializable payload)
// Response: Option<u64>(id) + u8(kind:0=Ok,1=Err) + Option<u8>(op) + payload

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

// ─── Public types ───

#[derive(Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub tx_id: String,
    pub index: u32,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub block_daa_score: u64,
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

fn bw_u8(w: &mut impl Write, v: u8) -> std::io::Result<()> { w.write_all(&[v]) }
fn bw_u16(w: &mut impl Write, v: u16) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
fn bw_u32(w: &mut impl Write, v: u32) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
fn bw_u64(w: &mut impl Write, v: u64) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
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

// ─── Kaspa Address Borsh serialization ───

fn borsh_write_address(w: &mut impl Write, addr_str: &str) -> std::io::Result<()> {
    let (version, payload) = crate::address::decode_address(addr_str)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let prefix_byte: u8 = if addr_str.starts_with("kaspatest:") { 1 }
        else if addr_str.starts_with("kaspasim:") { 2 }
        else if addr_str.starts_with("kaspadev:") { 3 }
        else { 0 };
    bw_u8(w, prefix_byte)?;
    bw_u8(w, version)?;
    bw_u32(w, payload.len() as u32)?;
    w.write_all(&payload)?;
    Ok(())
}

// ─── GetUtxosByAddresses request payload ───

fn build_get_utxos_payload(addresses: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    bw_u16(&mut buf, 1).unwrap(); // struct version
    bw_u32(&mut buf, addresses.len() as u32).unwrap();
    for addr in addresses {
        borsh_write_address(&mut buf, addr).unwrap();
    }
    buf
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
    if tag == 1 { let _ = br_u64(&mut r)?; }

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

    Ok(RpcResponse { kind, payload: remaining[payload_start..].to_vec() })
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
        let _ue_ver = br_u8(&mut ur)?;
        let amount = br_u64(&mut ur)?;
        let _spk_ver = br_u16(&mut ur)?;
        let spk_script = br_bytes(&mut ur)?;
        let block_daa_score = br_u64(&mut ur)?;
        let _is_coinbase = br_bool(&mut ur)?;

        entries.push(UtxoEntry {
            tx_id: hex::encode(tx_id_bytes),
            index,
            amount,
            script_public_key: spk_script,
            block_daa_score,
        });
    }

    Ok(entries)
}

// ─── WebSocket RPC call ───

async fn ws_rpc_call(ws_url: &str, op: u8, payload: &[u8]) -> Result<Vec<u8>, String> {
    let ws = WebSocket::new(ws_url)
        .map_err(|e| format!("WS create: {:?}", e))?;
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
                                *res2.borrow_mut() = Some(Err(format!("RPC error kind={}", resp.kind)));
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

    JsFuture::from(promise).await.map_err(|_| "Promise failed".to_string())?;
    ws.close().ok();

    let response = result.borrow_mut().take();
    response.unwrap_or_else(|| Err("No response".into()))
}

// ─── Public API: UTXO fetch ───

pub async fn fetch_all_utxos(ws_url: &str, wallet: &WalletData) -> Result<Vec<UtxoEntry>, String> {
    let all_addresses: Vec<String> = wallet.receive_addresses.iter()
        .chain(wallet.change_addresses.iter())
        .cloned()
        .collect();

    let payload = build_get_utxos_payload(&all_addresses);
    let response = ws_rpc_call(ws_url, OP_GET_UTXOS_BY_ADDRESSES, &payload).await?;
    parse_utxo_payload(&response)
}

/// Fetch UTXOs for a single address (used for multisig P2SH)
pub async fn fetch_utxos_for_address(ws_url: &str, address: &str) -> Result<Vec<UtxoEntry>, String> {
    let addresses = vec![address.to_string()];
    let payload = build_get_utxos_payload(&addresses);
    let response = ws_rpc_call(ws_url, OP_GET_UTXOS_BY_ADDRESSES, &payload).await?;
    parse_utxo_payload(&response)
}

pub async fn fetch_balance(ws_url: &str, wallet: &WalletData) -> Result<BalanceInfo, String> {
    let utxos = fetch_all_utxos(ws_url, wallet).await?;
    let total_sompi: u64 = utxos.iter().map(|u| u.amount).sum();

    let funded_addresses = {
        let mut seen = std::collections::HashSet::new();
        for u in &utxos { seen.insert(&u.script_public_key); }
        seen.len()
    };

    let funded_scripts: std::collections::HashSet<Vec<u8>> =
        utxos.iter().map(|u| u.script_public_key.clone()).collect();

    let funded_receive_indices: Vec<usize> = wallet.receive_addresses.iter()
        .enumerate()
        .filter_map(|(i, addr)| {
            crate::address::address_to_script_pubkey(addr).ok()
                .filter(|spk| funded_scripts.contains(spk))
                .map(|_| i)
        })
        .collect();

    let funded_change_indices: Vec<usize> = wallet.change_addresses.iter()
        .enumerate()
        .filter_map(|(i, addr)| {
            crate::address::address_to_script_pubkey(addr).ok()
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
    if result_tag == 255 { r = Cursor::new(response.as_slice()); }

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
        if i == 0 { normal_feerate = fr; normal_seconds = es; }
    }

    // low_buckets
    let low_count = br_u32(&mut r)?;
    let mut low_feerate = 1.0f64;
    let mut low_seconds = 1800.0f64;
    for i in 0..low_count {
        let fr = br_f64(&mut r)?;
        let es = br_f64(&mut r)?;
        if i == 0 { low_feerate = fr; low_seconds = es; }
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

pub async fn broadcast_signed(ws_url: &str, signed_hex: &str) -> Result<String, String> {
    let bytes = hex::decode(signed_hex)
        .map_err(|e| format!("Invalid hex: {}", e))?;

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

    // Global
    let tx_version = u16::from_le_bytes([bytes[pos], bytes[pos+1]]); pos += 2;
    let num_inputs = bytes[pos] as usize; pos += 1;
    let num_outputs = bytes[pos] as usize; pos += 1;
    let locktime = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
    let subnetwork_id: Vec<u8> = bytes[pos..pos+20].to_vec(); pos += 20;
    let gas = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
    let payload_len = u16::from_le_bytes([bytes[pos], bytes[pos+1]]) as usize; pos += 2;
    let tx_payload: Vec<u8> = bytes[pos..pos+payload_len].to_vec(); pos += payload_len;

    // Parse inputs with signatures
    struct TxInput { prev_tx_id: [u8; 32], prev_index: u32, sig_script: Vec<u8>, sequence: u64, sig_op_count: u8 }

    let mut inputs = Vec::new();
    for _i in 0..num_inputs {
        if pos + 55 > bytes.len() { return Err("KSPT truncated at input".into()); }
        let mut prev_tx_id = [0u8; 32];
        prev_tx_id.copy_from_slice(&bytes[pos..pos+32]); pos += 32;
        let prev_index = u32::from_le_bytes(bytes[pos..pos+4].try_into().unwrap()); pos += 4;
        let _amount = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
        let sequence = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
        let sig_op_count = bytes[pos]; pos += 1;
        let _spk_version = u16::from_le_bytes([bytes[pos], bytes[pos+1]]); pos += 2;
        let spk_len = bytes[pos] as usize; pos += 1;
        if pos + spk_len > bytes.len() { return Err("KSPT truncated at spk".into()); }
        let spk_script = bytes[pos..pos+spk_len].to_vec(); pos += spk_len;

        let mut sig_script = Vec::new();

        if version == 0x01 {
            // v1: sig_len(1) + sig(sig_len) + sighash_type(1)
            if pos >= bytes.len() { return Err("KSPT truncated at sig".into()); }
            let sig_len = bytes[pos] as usize; pos += 1;
            if sig_len > 0 {
                if pos + sig_len + 1 > bytes.len() { return Err("KSPT truncated at sig data".into()); }
                let sig_bytes = &bytes[pos..pos+sig_len]; pos += sig_len;
                let sighash_type = bytes[pos]; pos += 1;
                sig_script.push((sig_len + 1) as u8);
                sig_script.extend_from_slice(sig_bytes);
                sig_script.push(sighash_type);
            }
        } else {
            // v2: sig_count(1) + [pubkey_pos(1) + sighash_type(1) + sig(64)] × sig_count + redeem_script
            if pos >= bytes.len() { return Err("KSPT truncated at v2 sig".into()); }
            let sig_count = bytes[pos] as usize; pos += 1;
            if sig_count == 0 { return Err("Input has no signatures".into()); }

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
                    if pos + 66 > bytes.len() { return Err("KSPT truncated at multisig sig".into()); }
                    let pubkey_pos = bytes[pos]; pos += 1;
                    let sighash_type = bytes[pos]; pos += 1;
                    let sig_bytes = &bytes[pos..pos+64]; pos += 64;
                    let mut sig_data = Vec::with_capacity(65);
                    sig_data.extend_from_slice(sig_bytes);
                    sig_data.push(sighash_type);
                    sigs.push((pubkey_pos, sig_data));
                }
                sigs.sort_by_key(|s| s.0);

                // Redeem script — read it first to get M
                if pos >= bytes.len() { return Err("KSPT truncated at redeem script".into()); }
                let rs_len = bytes[pos] as usize; pos += 1;
                let redeem_script = if rs_len > 0 {
                    if pos + rs_len > bytes.len() { return Err("KSPT truncated at redeem data".into()); }
                    let rs = &bytes[pos..pos+rs_len]; pos += rs_len;
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
                if pos + 66 > bytes.len() { return Err("KSPT truncated at v2 P2PK sig".into()); }
                let _pubkey_pos = bytes[pos]; pos += 1;
                let sighash_type = bytes[pos]; pos += 1;
                let sig_bytes = &bytes[pos..pos+64]; pos += 64;
                sig_script.push(65u8);
                sig_script.extend_from_slice(sig_bytes);
                sig_script.push(sighash_type);
                // Skip remaining sigs
                for _ in 1..sig_count {
                    pos += 66; // pubkey_pos + sighash + sig
                }
                // Skip redeem script
                if pos < bytes.len() {
                    let rs_len = bytes[pos] as usize; pos += 1;
                    pos += rs_len;
                }
            }
        }

        inputs.push(TxInput { prev_tx_id, prev_index, sig_script, sequence, sig_op_count });
    }

    // Parse outputs
    struct TxOutput { value: u64, spk_version: u16, spk_script: Vec<u8> }

    let mut outputs = Vec::new();
    for _o in 0..num_outputs {
        if pos + 11 > bytes.len() { return Err("KSPT truncated at output".into()); }
        let value = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
        let spk_version = u16::from_le_bytes([bytes[pos], bytes[pos+1]]); pos += 2;
        let spk_len = bytes[pos] as usize; pos += 1;
        if pos + spk_len > bytes.len() { return Err("KSPT truncated at output spk".into()); }
        let spk_script = bytes[pos..pos+spk_len].to_vec(); pos += spk_len;
        outputs.push(TxOutput { value, spk_version, spk_script });
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

    // Log raw response for debugging
    web_sys::console::log_1(&format!(
        "[KasSee] Broadcast raw response: {} bytes, hex: {}",
        response.len(),
        hex::encode(&response[..response.len().min(200)])
    ).into());

    // Check if response is an ASCII error message
    if response.len() > 4 {
        // Try to detect text error in response
        let text_check = String::from_utf8_lossy(&response);
        if text_check.contains("Reject") || text_check.contains("reject") || text_check.contains("error") || text_check.contains("Error") {
            return Err(format!("Node rejected: {}", text_check.chars().take(200).collect::<String>()));
        }
    }

    // wRPC Borsh error format: first byte 0x00 = error, 0x01 = success
    if response[0] == 0x00 {
        // Error response — try to extract error message
        // Format: 0x00 + len(u32) + error_bytes
        if response.len() > 5 {
            let err_len = u32::from_le_bytes([
                response[1], response[2], response[3], response[4]
            ]) as usize;
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
                response[start], response[start+1], response[start+2], response[start+3]
            ]) as usize;
            let end = (start + 4 + len).min(response.len());
            &response[start+4..end]
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
}

/// Submit a transaction assembled directly from PSKT. No KSPT
/// intermediate. Produces the same on-wire Borsh RpcTransaction that
/// `broadcast_signed` produces — only the input assembly path differs.
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
        for inp in inputs {
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

    // Vec<Output>
    {
        let mut outputs_buf = Vec::new();
        bw_u32(&mut outputs_buf, outputs.len() as u32).unwrap();
        for out in outputs {
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
    tx_buf.extend_from_slice(subnetwork_id);
    bw_u64(&mut tx_buf, gas).unwrap();
    bw_bytes(&mut tx_buf, tx_payload).unwrap();
    bw_u64(&mut tx_buf, 0).unwrap(); // mass
    bw_bytes(&mut tx_buf, &[0u8]).unwrap(); // None verbose data

    bw_bytes(&mut req_payload, &tx_buf).unwrap();
    bw_u8(&mut req_payload, 0).unwrap(); // allow_orphan = false

    let response = ws_rpc_call(ws_url, OP_SUBMIT_TRANSACTION, &req_payload).await?;

    if response.is_empty() {
        return Err("Empty response from SubmitTransaction".into());
    }

    web_sys::console::log_1(&format!(
        "[KasSee] Broadcast raw response: {} bytes, hex: {}",
        response.len(),
        hex::encode(&response[..response.len().min(200)])
    ).into());

    if response.len() > 4 {
        let text_check = String::from_utf8_lossy(&response);
        if text_check.contains("Reject") || text_check.contains("reject")
            || text_check.contains("error") || text_check.contains("Error") {
            return Err(format!("Node rejected: {}",
                text_check.chars().take(200).collect::<String>()));
        }
    }

    if response[0] == 0x00 {
        if response.len() > 5 {
            let err_len = u32::from_le_bytes([
                response[1], response[2], response[3], response[4]
            ]) as usize;
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
                response[start], response[start+1], response[start+2], response[start+3]
            ]) as usize;
            let end = (start + 4 + len).min(response.len());
            &response[start+4..end]
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
