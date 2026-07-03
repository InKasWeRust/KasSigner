// KasSee Web — stealth-address WASM exports.
// Split out of lib.rs; behaviour unchanged. License: GPL-3.0.

//! wasm-bindgen exports for stealth addresses: payment generation,
//! announcement scanning, and spend construction.

use crate::network_to_prefix;
use crate::{address, bip32, kspt, pskt, rpc, stealth};
use wasm_bindgen::prelude::*;

// ─── Stealth Addresses ───

/// Derive a stealth meta-address from a kpub string.
/// Returns JSON: { scan_pubkey: "hex", spend_pubkey: "hex", meta_address: "hex128" }
#[wasm_bindgen]
pub fn stealth_meta_from_kpub(kpub_str: &str) -> Result<String, JsValue> {
    let xpub = bip32::ExtPubKey::from_kpub(kpub_str).map_err(|e| JsValue::from_str(&e))?;
    let meta = stealth::derive_stealth_meta(&xpub).map_err(|e| JsValue::from_str(&e))?;
    let encoded = stealth::encode_stealth_meta(&meta);
    let scan_x = hex::encode(stealth::x_only_pub(&meta.scan_pubkey));
    let spend_x = hex::encode(stealth::x_only_pub(&meta.spend_pubkey));
    let result = serde_json::json!({
        "scan_pubkey": scan_x,
        "spend_pubkey": spend_x,
        "meta_address": encoded,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate a stealth payment: derive one-time address + ephemeral R.
/// `meta_hex` is the 128-char stealth meta-address.
/// `entropy_hex` is 64 hex chars (32 bytes) of randomness from window.crypto.
/// `network` is "mainnet" or "testnet-12" etc.
/// Returns JSON: { address, ephemeral_r, stealth_index }
#[wasm_bindgen]
pub fn stealth_generate_payment(
    meta_hex: &str,
    entropy_hex: &str,
    network: &str,
) -> Result<String, JsValue> {
    let meta = stealth::decode_stealth_meta(meta_hex).map_err(|e| JsValue::from_str(&e))?;

    let entropy_bytes = hex::decode(entropy_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad entropy hex: {}", e)))?;
    if entropy_bytes.len() != 32 {
        return Err(JsValue::from_str("Entropy must be 32 bytes"));
    }
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&entropy_bytes);

    let payment =
        stealth::generate_stealth_payment(&meta, &entropy).map_err(|e| JsValue::from_str(&e))?;

    let prefix = network_to_prefix(network);
    let address = crate::address::encode_p2pk_address(&payment.one_time_pubkey, prefix);

    let result = serde_json::json!({
        "address": address,
        "ephemeral_r": hex::encode(payment.ephemeral_pubkey),
        "stealth_index": payment.stealth_index,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Scan a single announcement: given scan_privkey + spend_pubkey + ephemeral R,
/// derive the one-time pubkey the sender paid to.
/// Returns JSON: { one_time_pubkey, address, stealth_index, tweak }
#[wasm_bindgen]
pub fn stealth_scan_announcement(
    scan_privkey_hex: &str,
    spend_pubkey_hex: &str,
    ephemeral_r_hex: &str,
    network: &str,
) -> Result<String, JsValue> {
    let scan_priv = hex::decode(scan_privkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad scan privkey: {}", e)))?;
    if scan_priv.len() != 32 {
        return Err(JsValue::from_str("Scan privkey must be 32 bytes"));
    }
    let mut scan_arr = [0u8; 32];
    scan_arr.copy_from_slice(&scan_priv);

    let spend_pk = stealth::pubkey_from_xonly(
        &hex::decode(spend_pubkey_hex)
            .map_err(|e| JsValue::from_str(&format!("Bad spend pubkey: {}", e)))?,
    )
    .map_err(|e| JsValue::from_str(&e))?;

    let r_bytes = hex::decode(ephemeral_r_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad ephemeral R: {}", e)))?;
    if r_bytes.len() != 32 {
        return Err(JsValue::from_str("Ephemeral R must be 32 bytes"));
    }
    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(&r_bytes);

    let matched = stealth::scan_announcement(&scan_arr, &spend_pk, &r_arr)
        .map_err(|e| JsValue::from_str(&e))?;

    let prefix = network_to_prefix(network);
    let address = crate::address::encode_p2pk_address(&matched.one_time_pubkey, prefix);

    let result = serde_json::json!({
        "one_time_pubkey": hex::encode(matched.one_time_pubkey),
        "address": address,
        "stealth_index": matched.stealth_index,
        "tweak": hex::encode(matched.tweak),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Get the well-known stealth announcement address for a network.
#[wasm_bindgen]
pub fn stealth_announcement_address(network: &str) -> String {
    let prefix = network_to_prefix(network);
    stealth::announcement_address(prefix)
}

/// Create a PSKB for spending a stealth UTXO.
/// The PSKB includes the stealth tweak in proprietaries so the device
/// can derive the correct signing key (account_privkey + tweak).
#[wasm_bindgen]
pub async fn create_stealth_spend(
    one_time_pubkey_hex: &str,
    tweak_hex: &str,
    dest_address: &str,
    fee: u64,
    ws_url: &str,
    network: &str,
) -> Result<String, JsValue> {
    let pubkey_bytes = hex::decode(one_time_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad pubkey hex: {}", e)))?;
    if pubkey_bytes.len() != 32 {
        return Err(JsValue::from_str("Pubkey must be 32 bytes"));
    }

    let tweak_bytes =
        hex::decode(tweak_hex).map_err(|e| JsValue::from_str(&format!("Bad tweak hex: {}", e)))?;
    if tweak_bytes.len() != 32 {
        return Err(JsValue::from_str("Tweak must be 32 bytes"));
    }

    // Derive the one-time P2PK address from the pubkey
    let prefix = network_to_prefix(network);
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&pubkey_bytes);
    let stealth_addr = address::encode_p2pk_address(&pk32, prefix);

    // Fetch UTXOs at the stealth address
    let utxos = rpc::fetch_utxos_for_address(ws_url, &stealth_addr)
        .await
        .map_err(|e| JsValue::from_str(&e))?;

    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at stealth address"));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str("Balance too low to cover fee"));
    }

    let send_amount = total - fee;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let stealth_spk =
        address::address_to_script_pubkey(&stealth_addr).map_err(|e| JsValue::from_str(&e))?;

    let stealth_spk_hex = format!("0000{}", hex::encode(&stealth_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    let mut inputs = Vec::new();
    for utxo in &utxos {
        let input = serde_json::json!({
            "previousOutpoint": {
                "transactionId": utxo.tx_id,
                "index": utxo.index
            },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": stealth_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": null,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": {
                "stealthTweak": tweak_hex
            },
            "finalScriptSig": null,
            "minTime": 0
        });
        inputs.push(input);
    }

    let outputs = vec![serde_json::json!({
        "amount": send_amount,
        "scriptPublicKey": dest_spk_hex,
        "bip32Derivations": [],
        "proprietaries": []
    })];

    let pskt = serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": null,
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": inputs.len(),
            "outputCount": 1,
            "bip32Derivations": [],
            "proprietaries": []
        },
        "inputs": inputs,
        "outputs": outputs
    });

    let pskb = serde_json::json!([pskt]);
    let json_str = serde_json::to_string(&pskb).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let json_hex = hex::encode(json_str.as_bytes());
    let mut wire_bytes: Vec<u8> = Vec::with_capacity(4 + json_hex.len());
    wire_bytes.extend_from_slice(b"PSKB");
    wire_bytes.extend_from_slice(json_hex.as_bytes());
    let wire = hex::encode(&wire_bytes);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Stealth spend PSKB: {} inputs, total {}, send {}, fee {}, tweak {}",
            utxos.len(),
            total,
            send_amount,
            fee,
            tweak_hex
        )
        .into(),
    );

    Ok(wire)
}

/// Create a stealth PAYMENT: pay `amount_sompi` to a freshly derived one-time
/// address for the receiver's stealth meta-address, embedding the ephemeral R
/// in the transaction payload so the receiver can detect the payment on-chain.
/// No burn address, no dust output, no separate announcement tx.
///
/// Payload layout: b"KST1" (4) || R (32, x-only) = 36 bytes. The firmware
/// sighash commits the payload, so the device signs over R, and
/// `finalize_and_broadcast` carries it to consensus. On Toccata the payload
/// costs ~36 compute + 144 transient mass, covered by the minimum fee.
///
/// Returns JSON: { pskb_wire, address, ephemeral_r }
#[wasm_bindgen]
pub async fn stealth_create_payment(
    wallet_json: &str,
    meta_hex: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    entropy_hex: &str,
    ws_url: &str,
    network: &str,
) -> Result<String, JsValue> {
    let meta = stealth::decode_stealth_meta(meta_hex).map_err(|e| JsValue::from_str(&e))?;

    let entropy_bytes = hex::decode(entropy_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad entropy hex: {}", e)))?;
    if entropy_bytes.len() != 32 {
        return Err(JsValue::from_str("Entropy must be 32 bytes"));
    }
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&entropy_bytes);

    let payment =
        stealth::generate_stealth_payment(&meta, &entropy).map_err(|e| JsValue::from_str(&e))?;

    let prefix = network_to_prefix(network);
    let one_time_addr = address::encode_p2pk_address(&payment.one_time_pubkey, prefix);

    // Build a normal P2PK send to the one-time address (coin selection + change
    // handled by the proven send path), then attach R as the tx payload.
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet: {}", e)))?;
    let base_wire =
        kspt::create_send_pskb(&wallet, &one_time_addr, amount_sompi, fee_sompi, ws_url)
            .await
            .map_err(|e| JsValue::from_str(&e))?;

    let mut payload: Vec<u8> = Vec::with_capacity(4 + 32);
    payload.extend_from_slice(b"KST1");
    payload.extend_from_slice(&payment.ephemeral_pubkey);

    let wire = pskt::inject_tx_payload(&base_wire, &payload).map_err(|e| JsValue::from_str(&e))?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Stealth payment: pay {} sompi to {}, R in payload, fee {}",
            amount_sompi, one_time_addr, fee_sompi
        )
        .into(),
    );

    let result = serde_json::json!({
        "pskb_wire": wire,
        "address": one_time_addr,
        "ephemeral_r": hex::encode(payment.ephemeral_pubkey),
    });
    Ok(result.to_string())
}

/// Device-signed stealth payment on the KSTL seq-commit lane.
///
/// Same as `stealth_create_payment`, but the PSKB is stamped onto subnetwork
/// KSTL (b"KSTL" + 16 zero bytes), tx_version 1, gas 0, and carries the
/// announcement payload `0x01 || R(32) || view_tag(1)` (34 bytes) instead of
/// the in-band `b"KST1" || R`. Coin selection and change come from the proven
/// `create_send_pskb` path; `set_tx_lane` then restamps the global.
///
/// The device's `calculate_sighash` for a v1 tx commits subnetwork_id, gas, and
/// payload and omits sigOpCounts (firmware sighash.rs), so it is byte-identical
/// to `compute_sighash_v1_subnet` (what the software probe signs and the node
/// already accepts on TN10). The device signs that sighash and
/// `finalize_and_broadcast` emits the matching KSTL tx, so consensus folds its
/// tx_id into the lane tip.
///
/// Returns JSON: { pskb_wire, address, ephemeral_r, view_tag }.
#[wasm_bindgen]
pub async fn stealth_create_payment_lane(
    wallet_json: &str,
    meta_hex: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    entropy_hex: &str,
    ws_url: &str,
    network: &str,
) -> Result<String, JsValue> {
    let meta = stealth::decode_stealth_meta(meta_hex).map_err(|e| JsValue::from_str(&e))?;

    let entropy_bytes = hex::decode(entropy_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad entropy hex: {}", e)))?;
    if entropy_bytes.len() != 32 {
        return Err(JsValue::from_str("Entropy must be 32 bytes"));
    }
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&entropy_bytes);

    let payment =
        stealth::generate_stealth_payment(&meta, &entropy).map_err(|e| JsValue::from_str(&e))?;

    let prefix = network_to_prefix(network);
    let one_time_addr = address::encode_p2pk_address(&payment.one_time_pubkey, prefix);

    // Coin-selected native P2PK send to the one-time address (selection + change
    // via the proven path), then restamp the global onto the KSTL lane.
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet: {}", e)))?;
    let base_wire =
        kspt::create_send_pskb(&wallet, &one_time_addr, amount_sompi, fee_sompi, ws_url)
            .await
            .map_err(|e| JsValue::from_str(&e))?;

    // Announcement payload: ver(0x01) || R(32, x-only) || view_tag(1) = 34 bytes.
    let mut payload: Vec<u8> = Vec::with_capacity(34);
    payload.push(0x01u8);
    payload.extend_from_slice(&payment.ephemeral_pubkey);
    payload.push(payment.view_tag);

    // KSTL lane subnetwork id: b"KSTL" (4b53544c) + 16 zero bytes.
    let subnet_hex = "4b53544c00000000000000000000000000000000";

    let wire = pskt::set_tx_lane(&base_wire, subnet_hex, 0u64, 1u16, &payload)
        .map_err(|e| JsValue::from_str(&e))?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Stealth LANE payment: {} sompi to {}, R+view_tag in KSTL payload, fee {}",
            amount_sompi, one_time_addr, fee_sompi
        )
        .into(),
    );

    let result = serde_json::json!({
        "pskb_wire": wire,
        "address": one_time_addr,
        "ephemeral_r": hex::encode(payment.ephemeral_pubkey),
        "view_tag": payment.view_tag,
    });
    Ok(result.to_string())
}

/// Phase 1 (KSTL stealth lane) — software-signed announcement probe.
///
/// Builds, signs, and broadcasts a stealth payment on the dedicated KSTL
/// seq-commit lane: subnetwork = b"KSTL" + 16 zero bytes (4b53544c00..00, a
/// valid user lane — bytes 0..4 nonzero, 16-byte zero tail), tx_version = 1,
/// gas = 0. The tx pays the recipient's one-time P2PK output (+ change to the
/// sender) and carries the announcement payload `0x01 || R(32) || view_tag(1)`
/// (34 bytes). Because the tx is tagged to the KSTL lane, consensus folds its
/// tx_id into the lane tip, which is then complete and op-153-provable via
/// `seq_commit_lane_key("4b53544c" + 16 zero bytes)` + `get_seq_commit_lane_proof`.
///
/// This is the SOFTWARE signer (hot key) used to validate lane behaviour on
/// TN10 without the air-gapped device in the loop. The sighash it signs
/// (`compute_sighash_v1_subnet`) is byte-identical to the firmware's
/// `calculate_sighash` for a v1 lane tx (same field order, sigOpCounts omitted
/// for version >= 1, explicit subnetwork_id + gas + payload_hash), so the
/// device path is validated by construction: same serialization, same sighash.
///
/// - `sender_secret_hex`: 64 hex, the key controlling the funding UTXO (TEST hot key).
/// - `funding_txid_hex` / `funding_index` / `funding_amount`: the P2PK UTXO to spend.
/// - `meta_hex`: the recipient's 128-hex stealth meta-address.
/// - `amount_sompi`: value sent to the one-time P2PK output (must be > 0).
/// - `fee_sompi`: network fee. Change (funding - amount - fee) returns to the sender.
/// - `entropy_hex`: 64 hex of ephemeral randomness (window.crypto).
/// - `network`: "mainnet" / "testnet-10" etc. (for address display only).
///
/// Returns JSON: { txid, one_time_address, ephemeral_r, view_tag, subnetwork_hex, lane_key }.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn stealth_announce_lane_probe(
    ws_url: &str,
    sender_secret_hex: &str,
    funding_txid_hex: &str,
    funding_index: u32,
    funding_amount: u64,
    meta_hex: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    entropy_hex: &str,
    network: &str,
    lane_gas: u64,
) -> Result<String, JsValue> {
    // Canonical script-data push (matches the node's push-only sig_script rules).
    fn ss_push(ss: &mut Vec<u8>, d: &[u8]) {
        let len = d.len();
        if len <= 75 {
            ss.push(len as u8);
        } else if len <= 255 {
            ss.push(0x4c);
            ss.push(len as u8);
        } else if len <= 65535 {
            ss.push(0x4d);
            ss.extend_from_slice(&(len as u16).to_le_bytes());
        } else {
            ss.push(0x4e);
            ss.extend_from_slice(&(len as u32).to_le_bytes());
        }
        ss.extend_from_slice(d);
    }

    if amount_sompi == 0 {
        return Err(JsValue::from_str("amount_sompi must be > 0"));
    }
    let spend_total = amount_sompi
        .checked_add(fee_sompi)
        .ok_or_else(|| JsValue::from_str("amount + fee overflow"))?;
    if funding_amount < spend_total {
        return Err(JsValue::from_str(
            "funding_amount must be >= amount_sompi + fee_sompi",
        ));
    }
    let change = funding_amount - spend_total;

    // Sender hot key -> x-only pubkey -> P2PK spk (OP_DATA_32 <xonly> OP_CHECKSIG).
    let sk =
        crate::adaptor::scalar_from_hex(sender_secret_hex).map_err(|e| JsValue::from_str(&e))?;
    let sender_xo = crate::adaptor::pubkey_from_secret(&sk);
    let mut sender_spk = Vec::with_capacity(34);
    sender_spk.push(0x20);
    sender_spk.extend_from_slice(&sender_xo);
    sender_spk.push(0xAC);

    let funding_txid: [u8; 32] = {
        let v = hex::decode(funding_txid_hex.trim())
            .map_err(|e| JsValue::from_str(&format!("funding_txid hex: {}", e)))?;
        v.try_into()
            .map_err(|_| JsValue::from_str("funding_txid must be 32 bytes"))?
    };

    // Recipient stealth meta -> one-time payment key P, ephemeral R, view tag.
    let meta = stealth::decode_stealth_meta(meta_hex).map_err(|e| JsValue::from_str(&e))?;
    let entropy_bytes = hex::decode(entropy_hex.trim())
        .map_err(|e| JsValue::from_str(&format!("entropy hex: {}", e)))?;
    if entropy_bytes.len() != 32 {
        return Err(JsValue::from_str("entropy must be 32 bytes (64 hex chars)"));
    }
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&entropy_bytes);
    let payment =
        stealth::generate_stealth_payment(&meta, &entropy).map_err(|e| JsValue::from_str(&e))?;

    // Announcement payload: ver(0x01) || R(32, x-only) || view_tag(1) = 34 bytes.
    let mut payload = Vec::with_capacity(34);
    payload.push(0x01u8);
    payload.extend_from_slice(&payment.ephemeral_pubkey);
    payload.push(payment.view_tag);

    // One-time P2PK payment output.
    let mut one_time_spk = Vec::with_capacity(34);
    one_time_spk.push(0x20);
    one_time_spk.extend_from_slice(&payment.one_time_pubkey);
    one_time_spk.push(0xAC);

    let mut outputs: Vec<crate::rpc::ConsensusOutput> = Vec::with_capacity(2);
    outputs.push(crate::rpc::ConsensusOutput {
        value: amount_sompi,
        spk_version: 0,
        spk_script: one_time_spk,
        covenant: None,
    });
    if change > 0 {
        outputs.push(crate::rpc::ConsensusOutput {
            value: change,
            spk_version: 0,
            spk_script: sender_spk.clone(),
            covenant: None,
        });
    }

    // KSTL lane subnetwork id.
    let mut subnet = [0u8; 20];
    subnet[..4].copy_from_slice(b"KSTL");

    // Sign input[0] over the v1 lane sighash (commits subnet=KSTL, gas=0, payload).
    let sighash_outputs: Vec<crate::rpc::SighashOutput> = outputs
        .iter()
        .map(|o| crate::rpc::SighashOutput {
            value: o.value,
            spk_version: o.spk_version,
            spk_script: o.spk_script.clone(),
            covenant: o.covenant,
        })
        .collect();
    let inputs_ref: Vec<(&[u8; 32], u32, u64)> = vec![(&funding_txid, funding_index, 0u64)];
    let sh = crate::rpc::compute_sighash_v1_subnet(
        &inputs_ref,
        0,
        0,
        &sender_spk,
        funding_amount,
        &sighash_outputs,
        0,
        &payload,
        &subnet,
        lane_gas,
    );
    let sig = crate::adaptor::bip340_sign(&sk, &sh).map_err(|e| JsValue::from_str(&e))?;
    let mut sig_full = sig.to_vec();
    sig_full.push(0x01); // SIGHASH_ALL
    let mut ss = Vec::new();
    ss_push(&mut ss, &sig_full);

    let inputs = vec![crate::rpc::ConsensusInput {
        prev_tx_id: funding_txid,
        prev_index: funding_index,
        sequence: 0,
        sig_script: ss,
        sig_op_count: 1,
    }];

    let prefix = network_to_prefix(network);
    let one_time_address = address::encode_p2pk_address(&payment.one_time_pubkey, prefix);
    let subnetwork_hex = hex::encode(subnet);
    let lane_key = crate::rpc::seq_commit_lane_key(&subnetwork_hex)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] KSTL announce: pay {} sompi to {} (change {}, fee {}), R+view_tag 34B payload, subnet KSTL gas {}",
            amount_sompi, one_time_address, change, fee_sompi, lane_gas
        )
        .into(),
    );

    let txid = crate::rpc::submit_consensus_tx(
        ws_url, 1, &inputs, &outputs, 0, &subnet, lane_gas, &payload,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "txid": txid,
        "one_time_address": one_time_address,
        "ephemeral_r": hex::encode(payment.ephemeral_pubkey),
        "view_tag": payment.view_tag,
        "subnetwork_hex": subnetwork_hex,
        "lane_key": lane_key,
    });
    Ok(result.to_string())
}

/// Historical catch-up: scan up to `max_blocks` recent blocks for stealth
/// payments and return a JSON array of 64-hex ephemeral R values. Pair with the
/// live BlockAdded scan to also recover payments received while offline.
#[wasm_bindgen]
pub async fn stealth_scan_recent_blocks(ws_url: &str, max_blocks: u32) -> Result<String, JsValue> {
    let rs = rpc::scan_recent_blocks_for_stealth(ws_url, max_blocks)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&rs).map_err(|e| JsValue::from_str(&e.to_string()))
}
