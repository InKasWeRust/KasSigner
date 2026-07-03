// KasSee Web — Tagged-Vault + Split-Vault (KIP-20) WASM exports.
// Split out of lib.rs; behaviour unchanged. License: GPL-3.0.

//! wasm-bindgen exports for the KIP-20 tagged/split vault flows
//! (keygen, genesis, spend).

use crate::{address, kspt, rpc};
use crate::{hex_to_pubkey32, network_to_prefix};
use wasm_bindgen::prelude::*;

// ================================================================
// Tagged Vault: KIP-20 covenant-ID-aware vault (PoC)
// ================================================================

/// Create a Tagged Vault covenant address and redeem script.
///
/// The tagged vault enforces state continuity via KIP-20 covenant IDs:
/// every spend must produce an output carrying the same covenant_id.
///
/// Returns JSON: { address, redeem_script_hex, redeem_len, sig_op_count }
#[wasm_bindgen]
pub fn covenant_tagged_vault(owner_pubkey_hex: &str, network: &str) -> Result<String, JsValue> {
    let pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let prefix = network_to_prefix(network);

    let script = kspt::build_tagged_vault_script(&pk);

    web_sys::console::log_1(
        &format!("[KasSee] Tagged Vault: {} bytes script", script.len()).into(),
    );

    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let script_hex = hex::encode(&script);

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": script_hex,
        "redeem_len": script.len(),
        "sig_op_count": kspt::TAGGED_VAULT_SIG_OP_COUNT,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Compute a KIP-20 covenant_id for a genesis Tagged Vault TX.
///
/// This must be called with the UTXO that will fund the covenant,
/// because the covenant_id is derived from the input outpoint.
///
/// prev_txid_hex: 32-byte transaction ID of the funding UTXO (hex)
/// prev_index: output index of the funding UTXO
/// send_amount: amount in sompi for the covenant output
/// covenant_spk_hex: the P2SH script public key (hex)
///
/// Returns JSON: { covenant_id_hex }
#[wasm_bindgen]
pub fn tagged_vault_covenant_id(
    prev_txid_hex: &str,
    prev_index: u32,
    send_amount: u64,
    covenant_spk_hex: &str,
) -> Result<String, JsValue> {
    let txid_bytes: [u8; 32] = hex::decode(prev_txid_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad txid hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("txid not 32 bytes"))?;

    let spk = hex::decode(covenant_spk_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad SPK hex: {}", e)))?;

    let auth_outputs = vec![(0u32, send_amount, 0u16, spk.as_slice())];
    let cov_id = kspt::compute_covenant_id(&txid_bytes, prev_index, &auth_outputs);

    let result = serde_json::json!({
        "covenant_id_hex": hex::encode(cov_id),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate an ephemeral keypair for browser-signed Tagged Vault TXs.
/// Returns JSON: { secret_key_hex, pubkey_hex, address }
#[wasm_bindgen]
pub fn tagged_vault_keygen(network: &str) -> Result<String, JsValue> {
    let (sk_hex, pk_hex) = {
        let sk_result = crate::adaptor_api::adaptor_generate_keypair()?;
        let parsed: serde_json::Value =
            serde_json::from_str(&sk_result).map_err(|e| JsValue::from_str(&e.to_string()))?;
        (
            parsed["secret_hex"].as_str().unwrap().to_string(),
            parsed["pubkey_hex"].as_str().unwrap().to_string(),
        )
    };

    let prefix = network_to_prefix(network);
    // P2PK address from xonly pubkey
    let pk_bytes =
        hex::decode(&pk_hex).map_err(|e| JsValue::from_str(&format!("Bad pk hex: {}", e)))?;
    if pk_bytes.len() != 32 {
        return Err(JsValue::from_str("Pubkey must be 32 bytes"));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let addr = address::encode_p2pk_address(&pk_arr, prefix);

    let result = serde_json::json!({
        "secret_key_hex": sk_hex,
        "pubkey_hex": pk_hex,
        "address": addr,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Fund an ephemeral address, create the covenant, and broadcast the genesis TX.
///
/// This is the main entry point for the Tagged Vault PoC.
/// Steps:
///   1. Fetch UTXOs at the ephemeral address
///   2. Build and sign the genesis TX in WASM
///   3. Broadcast
///
/// Returns JSON: { txid, covenant_id_hex, covenant_address }
#[wasm_bindgen]
pub async fn tagged_vault_genesis(
    ephemeral_address: &str,
    secret_key_hex: &str,
    owner_pubkey_hex: &str,
    send_amount: u64,
    fee: u64,
    network: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    // Build the covenant script and address
    let pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let prefix = network_to_prefix(network);
    let script = kspt::build_tagged_vault_script(&pk);
    let covenant_address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk =
        address::address_to_script_pubkey(&covenant_address).map_err(|e| JsValue::from_str(&e))?;

    // Fetch UTXOs at ephemeral address
    let utxos = rpc::fetch_utxos_for_address(ws_url, ephemeral_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str(
            "No UTXOs at ephemeral address. Fund it first.",
        ));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total < send_amount + fee {
        return Err(JsValue::from_str(&format!(
            "Insufficient: {} sompi < {} + {} fee",
            total, send_amount, fee
        )));
    }

    let change = total - send_amount - fee;

    // Change goes back to the ephemeral address
    let change_spk = if change > 0 {
        Some(
            address::address_to_script_pubkey(ephemeral_address)
                .map_err(|e| JsValue::from_str(&e))?,
        )
    } else {
        None
    };

    let (txid, covenant_id) = rpc::build_and_broadcast_tagged_vault_genesis(
        ws_url,
        &utxos,
        secret_key_hex,
        &covenant_spk,
        send_amount,
        change_spk.as_deref(),
        change,
        &script,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "txid": txid,
        "covenant_id_hex": hex::encode(covenant_id),
        "covenant_address": covenant_address,
        "redeem_script_hex": hex::encode(&script),
        "send_amount": send_amount,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Spend a Tagged Vault UTXO with covenant-ID continuity.
///
/// The output carries the same covenant_id (continuation).
/// Signed in-browser with the owner's secret key.
///
/// Returns JSON: { txid, covenant_id_hex }
#[wasm_bindgen]
pub async fn tagged_vault_spend(
    covenant_address: &str,
    secret_key_hex: &str,
    owner_pubkey_hex: &str,
    covenant_id_hex: &str,
    fee: u64,
    network: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let prefix = network_to_prefix(network);
    let script = kspt::build_tagged_vault_script(&pk);
    let cov_addr =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let cov_spk =
        address::address_to_script_pubkey(&cov_addr).map_err(|e| JsValue::from_str(&e))?;

    let covenant_id: [u8; 32] = hex::decode(covenant_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad cov_id hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("covenant_id not 32 bytes"))?;

    let utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
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
    let send_amount = total - fee;

    let txid = rpc::build_and_broadcast_tagged_vault_continuation(
        ws_url,
        &utxos,
        secret_key_hex,
        &covenant_id,
        &cov_spk,
        send_amount,
        None, // no change for simplicity
        0,
        &script,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "txid": txid,
        "covenant_id_hex": covenant_id_hex,
        "new_amount": send_amount,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ================================================================
// Split Vault: KIP-20 multi-output covenant (PoC)
// ================================================================

/// Create a Split Vault covenant address.
/// Returns JSON: { address, redeem_script_hex, redeem_len, sig_op_count }
#[wasm_bindgen]
pub fn covenant_split_vault(owner_pubkey_hex: &str, network: &str) -> Result<String, JsValue> {
    let pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let prefix = network_to_prefix(network);
    let script = kspt::build_split_vault_script(&pk);

    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "redeem_len": script.len(),
        "sig_op_count": kspt::SPLIT_VAULT_SIG_OP_COUNT,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Fund a Split Vault covenant with a genesis TX (creates covenant_id).
/// Same flow as tagged_vault_genesis but uses the split vault script.
/// Returns JSON: { txid, covenant_id_hex, covenant_address }
#[wasm_bindgen]
pub async fn split_vault_genesis(
    ephemeral_address: &str,
    secret_key_hex: &str,
    owner_pubkey_hex: &str,
    send_amount: u64,
    fee: u64,
    network: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let prefix = network_to_prefix(network);
    let script = kspt::build_split_vault_script(&pk);
    let covenant_address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk =
        address::address_to_script_pubkey(&covenant_address).map_err(|e| JsValue::from_str(&e))?;

    let utxos = rpc::fetch_utxos_for_address(ws_url, ephemeral_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at ephemeral address."));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total < send_amount + fee {
        return Err(JsValue::from_str(&format!(
            "Insufficient: {} < {} + {}",
            total, send_amount, fee
        )));
    }
    let change = total - send_amount - fee;
    let change_spk = if change > 0 {
        Some(
            address::address_to_script_pubkey(ephemeral_address)
                .map_err(|e| JsValue::from_str(&e))?,
        )
    } else {
        None
    };

    let (txid, covenant_id) = rpc::build_and_broadcast_tagged_vault_genesis(
        ws_url,
        &utxos,
        secret_key_hex,
        &covenant_spk,
        send_amount,
        change_spk.as_deref(),
        change,
        &script,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "txid": txid,
        "covenant_id_hex": hex::encode(covenant_id),
        "covenant_address": covenant_address,
        "redeem_script_hex": hex::encode(&script),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Split a covenant UTXO into two outputs, both carrying the same covenant_id.
/// The split vault script enforces AUTH_OUTPUT_COUNT==2 and COV_OUTPUT_COUNT==2.
///
/// Returns JSON: { txid, covenant_id_hex, amount_a, amount_b }
#[wasm_bindgen]
pub async fn split_vault_spend(
    covenant_address: &str,
    secret_key_hex: &str,
    owner_pubkey_hex: &str,
    covenant_id_hex: &str,
    fee: u64,
    network: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let prefix = network_to_prefix(network);
    let script = kspt::build_split_vault_script(&pk);
    let cov_addr =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let cov_spk =
        address::address_to_script_pubkey(&cov_addr).map_err(|e| JsValue::from_str(&e))?;

    let covenant_id: [u8; 32] = hex::decode(covenant_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad cov_id hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("covenant_id not 32 bytes"))?;

    let utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
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
    let after_fee = total - fee;
    let amount_a = after_fee / 2;
    let amount_b = after_fee - amount_a;

    let txid = rpc::build_and_broadcast_split_vault(
        ws_url,
        &utxos,
        secret_key_hex,
        &covenant_id,
        &cov_spk,
        amount_a,
        amount_b,
        &script,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "txid": txid,
        "covenant_id_hex": covenant_id_hex,
        "amount_a": amount_a,
        "amount_b": amount_b,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}
