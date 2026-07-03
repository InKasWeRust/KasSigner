// KasSee Web — adaptor-signature (atomic-swap) WASM exports.
// Split out of lib.rs; behaviour unchanged. License: GPL-3.0.

//! wasm-bindgen exports for the adaptor-signature / atomic-swap flow;
//! thin wrappers over the `crate::adaptor` primitives.

use crate::{adaptor, address, kspt, pskt, rpc};
use crate::{hex_to_pubkey32, network_to_prefix};
use wasm_bindgen::prelude::*;

/// Generate an adaptor secret (t, T) for the swap initiator.
/// Returns JSON: { t_hex, T_hex }
#[wasm_bindgen]
pub fn adaptor_generate_secret() -> Result<String, JsValue> {
    let (t, t_xonly) = adaptor::generate_adaptor_secret().map_err(|e| JsValue::from_str(&e))?;
    let result = serde_json::json!({
        "t_hex": hex::encode(adaptor::scalar_to_bytes(&t)),
        "T_hex": hex::encode(t_xonly),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate a random signing keypair (for PoC, browser-side signing).
/// Returns JSON: { secret_hex, pubkey_hex }
#[wasm_bindgen]
pub fn adaptor_generate_keypair() -> Result<String, JsValue> {
    let mut sk_bytes = [0u8; 32];
    getrandom::getrandom(&mut sk_bytes)
        .map_err(|e| JsValue::from_str(&format!("RNG failed: {}", e)))?;
    let sk = adaptor::scalar_from_hex(&hex::encode(sk_bytes)).map_err(|e| JsValue::from_str(&e))?;
    let pk_xonly = adaptor::pubkey_from_secret(&sk);
    let result = serde_json::json!({
        "secret_hex": hex::encode(adaptor::scalar_to_bytes(&sk)),
        "pubkey_hex": hex::encode(pk_xonly),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create a P2SH address for an adaptor swap UTXO.
/// Redeem script: <claimer_pubkey> OP_CHECKSIGFROMSTACK
/// Returns JSON: { address, redeem_script_hex, claimer_pubkey_hex }
#[wasm_bindgen]
pub fn adaptor_swap_address(
    claimer_pubkey_hex: &str,
    owner_pubkey_hex: &str,
    claimer_dest_addr: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let claimer_pk = hex_to_pubkey32(claimer_pubkey_hex)?;
    let owner_pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let prefix = network_to_prefix(network);

    // Resolve claimer's destination SPK (where funds MUST go when claimed)
    let dest_spk =
        address::address_to_script_pubkey(claimer_dest_addr).map_err(|e| JsValue::from_str(&e))?;
    let mut dest_spk_full = Vec::with_capacity(2 + dest_spk.len());
    dest_spk_full.extend_from_slice(&[0x00, 0x00]); // version prefix
    dest_spk_full.extend_from_slice(&dest_spk);

    let mut redeem = Vec::with_capacity(120);

    // IF: claimer path (adaptor sig via CHECKSIGFROMSTACK + destination check)
    redeem.push(0x63); // OP_IF
    redeem.push(0x20); // OP_DATA_32
    redeem.extend_from_slice(&claimer_pk);
    redeem.push(0xd7); // OP_CHECKSIGFROMSTACK
                       // Verify output[0] goes to claimer's hardcoded destination
    redeem.push(0x00); // OP_0 (output index 0)
    redeem.push(0xc3); // OP_TX_OUTPUT_SPK
                       // Push dest_spk_full
    let spk_len = dest_spk_full.len();
    if spk_len <= 75 {
        redeem.push(spk_len as u8);
    } else {
        redeem.push(0x4c); // OP_PUSHDATA1
        redeem.push(spk_len as u8);
    }
    redeem.extend_from_slice(&dest_spk_full);
    redeem.push(0x88); // OP_EQUALVERIFY (verify + consume, leaves CHECKSIGFROMSTACK result)

    // ELSE: owner refund after timeout (normal CHECKSIG)
    redeem.push(0x67); // OP_ELSE
                       // Push locktime as i64 LE (Kaspa script integer encoding)
    let locktime_bytes = (locktime_daa as i64).to_le_bytes();
    let len = if locktime_daa == 0 {
        0
    } else if locktime_daa <= 0x7f {
        1
    } else if locktime_daa <= 0x7fff {
        2
    } else if locktime_daa <= 0x7fffff {
        3
    } else if locktime_daa <= 0x7fffffff {
        4
    } else if locktime_daa <= 0x7fffffffff {
        5
    } else if locktime_daa <= 0x7fffffffffff {
        6
    } else if locktime_daa <= 0x7fffffffffffff {
        7
    } else {
        8
    };
    if len == 0 {
        redeem.push(0x00); // OP_0
    } else {
        redeem.push(len as u8); // OP_DATA_N
        redeem.extend_from_slice(&locktime_bytes[..len as usize]);
    }
    redeem.push(0xb0); // OP_CHECKLOCKTIMEVERIFY
    redeem.push(0x20); // OP_DATA_32
    redeem.extend_from_slice(&owner_pk);
    redeem.push(0xac); // OP_CHECKSIG

    redeem.push(0x68); // OP_ENDIF

    let script_hash = kspt::blake2b_hash(&redeem);
    let addr = address::encode_p2sh_address(&script_hash, prefix);
    web_sys::console::log_1(
        &format!(
            "[KasSee] Adaptor swap P2SH: redeem={}B, addr={}",
            redeem.len(),
            addr
        )
        .into(),
    );
    let result = serde_json::json!({
        "address": addr,
        "redeem_script_hex": hex::encode(&redeem),
        "claimer_pubkey_hex": claimer_pubkey_hex,
        "owner_pubkey_hex": owner_pubkey_hex,
        "claimer_dest_addr": claimer_dest_addr,
        "locktime_daa": locktime_daa,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create an adaptor signature.
/// Returns JSON: { adaptor_sig_hex, signer_pubkey_hex }
#[wasm_bindgen]
pub fn adaptor_create_sig(
    signer_secret_hex: &str,
    msg_hash_hex: &str,
    adaptor_point_hex: &str,
) -> Result<String, JsValue> {
    let sk = adaptor::scalar_from_hex(signer_secret_hex).map_err(|e| JsValue::from_str(&e))?;
    let msg = hex_to_hash32(msg_hash_hex)?;
    let t_xonly = hex_to_hash32(adaptor_point_hex)?;
    let (adaptor_sig, _k) =
        adaptor::create_adaptor_sig(&sk, &msg, &t_xonly).map_err(|e| JsValue::from_str(&e))?;
    let pk_xonly = adaptor::pubkey_from_secret(&sk);
    let result = serde_json::json!({
        "adaptor_sig_hex": hex::encode(adaptor_sig),
        "signer_pubkey_hex": hex::encode(pk_xonly),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify an adaptor signature.
#[wasm_bindgen]
pub fn adaptor_verify_sig(
    pubkey_hex: &str,
    msg_hash_hex: &str,
    adaptor_sig_hex: &str,
    adaptor_point_hex: &str,
) -> Result<bool, JsValue> {
    let pk = hex_to_hash32(pubkey_hex)?;
    let msg = hex_to_hash32(msg_hash_hex)?;
    let adaptor_sig = hex_to_sig64(adaptor_sig_hex)?;
    let t_xonly = hex_to_hash32(adaptor_point_hex)?;
    adaptor::verify_adaptor_sig(&pk, &msg, &adaptor_sig, &t_xonly)
        .map_err(|e| JsValue::from_str(&e))
}

/// Complete an adaptor signature with the secret.
/// Returns completed BIP340 signature (128 hex).
#[wasm_bindgen]
pub fn adaptor_complete_sig(adaptor_sig_hex: &str, secret_hex: &str) -> Result<String, JsValue> {
    let adaptor_sig = hex_to_sig64(adaptor_sig_hex)?;
    let t = adaptor::scalar_from_hex(secret_hex).map_err(|e| JsValue::from_str(&e))?;
    let completed = adaptor::complete_adaptor_sig(&adaptor_sig, &t);
    Ok(hex::encode(completed))
}

/// Extract the adaptor secret from on-chain completed sig vs original adaptor.
/// Returns secret t (64 hex).
#[wasm_bindgen]
pub fn adaptor_extract_secret(
    completed_sig_hex: &str,
    adaptor_sig_hex: &str,
) -> Result<String, JsValue> {
    let completed = hex_to_sig64(completed_sig_hex)?;
    let adaptor_sig = hex_to_sig64(adaptor_sig_hex)?;
    let t = adaptor::extract_adaptor_secret(&completed, &adaptor_sig)
        .map_err(|e| JsValue::from_str(&e))?;
    Ok(hex::encode(adaptor::scalar_to_bytes(&t)))
}

/// Negate a scalar (additive inverse mod curve order).
/// Used to handle BIP340 even-Y parity when extracting adaptor secrets.
#[wasm_bindgen]
pub fn adaptor_negate_scalar(scalar_hex: &str) -> Result<String, JsValue> {
    let s = adaptor::scalar_from_hex(scalar_hex).map_err(|e| JsValue::from_str(&e))?;
    let neg = adaptor::negate_scalar(&s);
    Ok(hex::encode(adaptor::scalar_to_bytes(&neg)))
}

/// BIP340 Schnorr sign (PoC, both sides in browser).
/// Returns 128 hex (64-byte sig).
#[wasm_bindgen]
pub fn adaptor_bip340_sign(secret_hex: &str, msg_hash_hex: &str) -> Result<String, JsValue> {
    let sk = adaptor::scalar_from_hex(secret_hex).map_err(|e| JsValue::from_str(&e))?;
    let msg = hex_to_hash32(msg_hash_hex)?;
    let sig = adaptor::bip340_sign(&sk, &msg).map_err(|e| JsValue::from_str(&e))?;
    Ok(hex::encode(sig))
}

/// BIP340 Schnorr verify.
#[wasm_bindgen]
pub fn adaptor_bip340_verify(
    pubkey_hex: &str,
    msg_hash_hex: &str,
    sig_hex: &str,
) -> Result<bool, JsValue> {
    let pk = hex_to_hash32(pubkey_hex)?;
    let msg = hex_to_hash32(msg_hash_hex)?;
    let sig = hex_to_sig64(sig_hex)?;
    adaptor::bip340_verify(&pk, &msg, &sig).map_err(|e| JsValue::from_str(&e))
}

/// Build sig_script for claiming an adaptor swap UTXO.
/// Layout: <push sig_64> <push msg_hash_32> <push redeem_script>
/// Returns sig_script hex.
#[wasm_bindgen]
pub fn adaptor_build_sig_script(
    completed_sig_hex: &str,
    msg_hash_hex: &str,
    redeem_hex: &str,
) -> Result<String, JsValue> {
    let completed_sig = hex::decode(completed_sig_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad sig hex: {}", e)))?;
    let msg_hash =
        hex::decode(msg_hash_hex).map_err(|e| JsValue::from_str(&format!("Bad msg hex: {}", e)))?;
    let redeem = hex::decode(redeem_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;
    if completed_sig.len() != 64 {
        return Err(JsValue::from_str(&format!(
            "Sig must be 64 bytes, got {}",
            completed_sig.len()
        )));
    }
    if msg_hash.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "Msg hash must be 32 bytes, got {}",
            msg_hash.len()
        )));
    }
    let mut ss: Vec<u8> = Vec::with_capacity(64 + 32 + redeem.len() + 10);
    ss.push(0x40); // push 64 bytes
    ss.extend_from_slice(&completed_sig);
    ss.push(0x20); // push 32 bytes
    ss.extend_from_slice(&msg_hash);
    ss.push(0x51); // OP_TRUE -> IF branch (adaptor claim path)
    pskt::push_redeem_script(&mut ss, &redeem).map_err(|e| JsValue::from_str(&e))?;
    Ok(hex::encode(ss))
}

/// Compute swap commitment hash (both parties derive the same msg_hash).
/// Returns 64 hex (32-byte SHA256).
#[wasm_bindgen]
pub fn adaptor_swap_commitment(
    alice_utxo_id: &str,
    bob_utxo_id: &str,
    alice_amount: u64,
    bob_amount: u64,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"KasSigner-AdaptorSwap-v1");
    hasher.update(alice_utxo_id.as_bytes());
    hasher.update(bob_utxo_id.as_bytes());
    hasher.update(alice_amount.to_le_bytes());
    hasher.update(bob_amount.to_le_bytes());
    hex::encode(hasher.finalize())
}

// ─── Helpers ───

fn hex_to_hash32(h: &str) -> Result<[u8; 32], JsValue> {
    if h.len() != 64 {
        return Err(JsValue::from_str(&format!(
            "Expected 64 hex chars, got {}",
            h.len()
        )));
    }
    let bytes = hex::decode(h).map_err(|e| JsValue::from_str(&format!("Bad hex: {}", e)))?;
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Not 32 bytes"))
}

fn hex_to_sig64(h: &str) -> Result<[u8; 64], JsValue> {
    if h.len() != 128 {
        return Err(JsValue::from_str(&format!(
            "Expected 128 hex chars, got {}",
            h.len()
        )));
    }
    let bytes = hex::decode(h).map_err(|e| JsValue::from_str(&format!("Bad hex: {}", e)))?;
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Not 64 bytes"))
}

/// Build and broadcast an adaptor swap claim TX.
/// Fetches UTXOs at covenant_addr, builds a raw TX with the provided sig_script,
/// sends the output to dest_addr, and broadcasts to the node.
/// Returns the TX ID on success.
#[wasm_bindgen]
pub async fn adaptor_broadcast_claim(
    covenant_addr: &str,
    dest_addr: &str,
    sig_script_hex: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let sig_script = hex::decode(sig_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad sig_script hex: {}", e)))?;

    let utxos = rpc::fetch_utxos_for_address(ws_url, covenant_addr)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str(&format!(
            "Balance {} <= fee {}",
            total, fee
        )));
    }

    let dest_spk =
        address::address_to_script_pubkey(dest_addr).map_err(|e| JsValue::from_str(&e))?;

    let out_amount = total - fee;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Adaptor claim: {} inputs, total={}, fee={}, out={}, sig_script={}B",
            utxos.len(),
            total,
            fee,
            out_amount,
            sig_script.len()
        )
        .into(),
    );

    let txid =
        rpc::build_and_broadcast_raw(ws_url, &utxos, &sig_script, 0, &dest_spk, out_amount, 1)
            .await
            .map_err(|e| JsValue::from_str(&e))?;

    Ok(txid)
}
