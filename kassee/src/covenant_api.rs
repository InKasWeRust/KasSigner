// KasSee Web — KIP-10 covenant WASM exports.
// Split out of lib.rs; behaviour unchanged. License: GPL-3.0.

//! wasm-bindgen exports for the KIP-10 covenant suite: address builders and
//! PSKB spend constructors for every covenant type.

use crate::{address, bip32, kspt, rpc};
use crate::{hex_to_pubkey32, network_to_prefix};
use wasm_bindgen::prelude::*;

// ─── Covenant (KIP-10) ───

/// Build a Piggy Bank P2SH covenant address.
/// owner_pubkey_hex: 64-char hex of the 32-byte x-only pubkey
/// threshold_sompi: savings goal (0 = no goal)
/// deadline_daa: optional deadline DAA score (0 = no deadline)
/// Returns JSON: { "address": "kaspa:...", "redeem_script_hex": "...", "threshold_sompi": ..., "deadline_daa": ... }
#[wasm_bindgen]
pub fn covenant_additive_address(
    owner_pubkey_hex: &str,
    threshold_sompi: u64,
    deadline_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let pk_bytes = hex::decode(owner_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad pubkey hex: {}", e)))?;
    if pk_bytes.len() != 32 {
        return Err(JsValue::from_str("Pubkey must be 32 bytes"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);

    let prefix = network_to_prefix(network);

    // Random 8-byte salt so identical params produce a unique address each time.
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt)
        .map_err(|e| JsValue::from_str(&format!("RNG failed: {}", e)))?;

    let script = kspt::build_piggy_bank_script(&pk, threshold_sompi, deadline_daa, &salt);
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let script_hex = hex::encode(&script);

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": script_hex,
        "threshold_sompi": threshold_sompi,
        "deadline_daa": deadline_daa,
        "salt": hex::encode(salt),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a time-locked SAVINGS covenant P2SH address.
/// wallet1_pubkey_hex / wallet2_pubkey_hex: 32-byte x-only pubkeys (hex).
///   wallet2 is the key-loss recovery key (1-of-2, not multisig). Pass the
///   same value as wallet1 if you do not want a separate recovery key.
/// locktime_daa: DAA score; funds are frozen for everyone until this score,
///   after which either wallet can sweep with a single signature.
/// Returns JSON: { "address", "redeem_script_hex", "locktime_daa" }
#[wasm_bindgen]
pub fn covenant_timelocked_savings(
    wallet1_pubkey_hex: &str,
    wallet2_pubkey_hex: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let w1 = hex::decode(wallet1_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet1 pubkey hex: {}", e)))?;
    let w2 = hex::decode(wallet2_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet2 pubkey hex: {}", e)))?;
    if w1.len() != 32 {
        return Err(JsValue::from_str("wallet1 pubkey must be 32 bytes"));
    }
    if w2.len() != 32 {
        return Err(JsValue::from_str("wallet2 pubkey must be 32 bytes"));
    }
    let mut w1pk = [0u8; 32];
    w1pk.copy_from_slice(&w1);
    let mut w2pk = [0u8; 32];
    w2pk.copy_from_slice(&w2);

    let prefix = network_to_prefix(network);
    let script = kspt::build_timelocked_savings_script(&w1pk, &w2pk, locktime_daa);
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let script_hex = hex::encode(&script);

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": script_hex,
        "locktime_daa": locktime_daa,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create a PSKB to CLAIM a time-locked savings covenant (full sweep).
///
/// Valid only after the date: the script's OP_CHECKLOCKTIMEVERIFY and the
/// node's locktime finality both gate on `locktime_daa`, which is set as the
/// TX locktime here. Sweeps every UTXO at the address to `dest_address`
/// minus `fee`. Either wallet can sign: the finalizer auto-detects the
/// signer's branch (wallet1 -> OP_IF, wallet2 -> OP_ELSE) by matching the
/// signer's pubkey, so this one builder serves the primary and the recovery
/// wallet alike. covenantBranch is left neutral ("savings") so the generic
/// covenant finalizer path runs and the selector is chosen by pubkey.
///
/// Savings is CLTV-only (no CSV), so the gate rides entirely on the TX
/// locktime. For a vault funded with many UTXOs, a batched variant can be
/// added later (mirroring create_covenant_beneficiary_spend_selected).
#[wasm_bindgen]
pub async fn create_covenant_timelocked_savings_claim(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    let tx_locktime = locktime_daa;

    let utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str("Balance too low to cover fee"));
    }
    let send_amount = total - fee;

    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    let mut inputs = Vec::new();
    for utxo in &utxos {
        inputs.push(serde_json::json!({
            "previousOutpoint": { "transactionId": utxo.tx_id, "index": utxo.index },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        }));
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
            "fallbackLockTime": tx_locktime,
            "covenantBranch": "savings",
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
        &format!("[KasSee] Savings-claim PSKB: {} inputs, total {}, send {}, fee {}, locktime {}, wire {} chars",
            utxos.len(), total, send_amount, fee, locktime_daa, wire.len()
        ).into(),
    );

    Ok(wire)
}

/// Create a PSKB to CLAIM a time-locked savings covenant from a CHOSEN subset
/// of UTXOs, for batching when the address holds too many to sweep in one TX.
/// utxos_json: JSON array of {tx_id, index, amount}. Either wallet signs; the
/// finalizer auto-detects the branch by the signer's pubkey. covenantBranch is
/// neutral ("savings"). Savings is CLTV-only, so the TX locktime carries the gate.
#[wasm_bindgen]
pub fn create_covenant_timelocked_savings_claim_selected(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    utxos_json: &str,
    fee: u64,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    let tx_locktime = locktime_daa;

    let utxo_arr: Vec<serde_json::Value> = serde_json::from_str(utxos_json)
        .map_err(|e| JsValue::from_str(&format!("Bad UTXO JSON: {}", e)))?;
    if utxo_arr.is_empty() {
        return Err(JsValue::from_str("No UTXOs provided"));
    }

    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    let mut total: u64 = 0;
    let mut inputs = Vec::new();
    for u in &utxo_arr {
        let tx_id = u
            .get("tx_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("UTXO missing tx_id"))?;
        let index = u
            .get("index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| JsValue::from_str("UTXO missing index"))? as u32;
        let amount = u
            .get("amount")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| JsValue::from_str("UTXO missing amount"))?;
        total += amount;
        inputs.push(serde_json::json!({
            "previousOutpoint": { "transactionId": tx_id, "index": index },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": amount,
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        }));
    }

    if total <= fee {
        return Err(JsValue::from_str("Selected UTXOs too small to cover fee"));
    }
    let send_amount = total - fee;
    let n_inputs = inputs.len();

    let outputs = vec![serde_json::json!({
        "amount": send_amount,
        "scriptPublicKey": dest_spk_hex,
        "bip32Derivations": [],
        "proprietaries": []
    })];

    let pskt = serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": tx_locktime,
            "covenantBranch": "savings",
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": n_inputs,
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
        &format!("[KasSee] Savings-claim (selected) PSKB: {} inputs, total {}, send {}, fee {}, locktime {}, wire {} chars",
            n_inputs, total, send_amount, fee, locktime_daa, wire.len()
        ).into(),
    );
    Ok(wire)
}

/// Build a time-locked escrow covenant P2SH address.
/// alice_pubkey_hex / bob_pubkey_hex: 32-byte x-only pubkeys (hex)
/// alice_addr / bob_addr: destination addresses for each party
/// locktime_daa: DAA score after which funds auto-refund to Alice
/// Returns JSON: { "address", "redeem_script_hex", "locktime_daa" }
#[wasm_bindgen]
pub fn covenant_timelocked_escrow(
    alice_pubkey_hex: &str,
    bob_pubkey_hex: &str,
    alice_addr: &str,
    bob_addr: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let alice_bytes = hex::decode(alice_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad alice pubkey hex: {}", e)))?;
    let bob_bytes = hex::decode(bob_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad bob pubkey hex: {}", e)))?;
    if alice_bytes.len() != 32 {
        return Err(JsValue::from_str("Alice pubkey must be 32 bytes"));
    }
    if bob_bytes.len() != 32 {
        return Err(JsValue::from_str("Bob pubkey must be 32 bytes"));
    }

    let mut alice_pk = [0u8; 32];
    alice_pk.copy_from_slice(&alice_bytes);
    let mut bob_pk = [0u8; 32];
    bob_pk.copy_from_slice(&bob_bytes);

    let alice_spk =
        address::address_to_script_pubkey(alice_addr).map_err(|e| JsValue::from_str(&e))?;
    let bob_spk = address::address_to_script_pubkey(bob_addr).map_err(|e| JsValue::from_str(&e))?;

    let prefix = network_to_prefix(network);
    let script = kspt::build_timelocked_escrow_script(
        &alice_pk,
        &bob_pk,
        &alice_spk,
        &bob_spk,
        locktime_daa,
    );
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let script_hex = hex::encode(&script);

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": script_hex,
        "locktime_daa": locktime_daa,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a true dead man's switch (CSV-based) covenant P2SH address.
/// owner_pubkey_hex / heir_pubkey_hex: 32-byte x-only pubkeys (hex)
/// inactivity_daa: relative DAA units of inactivity before heir can claim
/// Returns JSON: { "address", "redeem_script_hex", "inactivity_daa" }
#[wasm_bindgen]
pub fn covenant_dms(
    owner_pubkey_hex: &str,
    heir_pubkey_hex: &str,
    inactivity_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let owner_bytes = hex::decode(owner_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad owner pubkey hex: {}", e)))?;
    let heir_bytes = hex::decode(heir_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad heir pubkey hex: {}", e)))?;
    if owner_bytes.len() != 32 {
        return Err(JsValue::from_str("Owner pubkey must be 32 bytes"));
    }
    if heir_bytes.len() != 32 {
        return Err(JsValue::from_str("Heir pubkey must be 32 bytes"));
    }
    let mut owner_pk = [0u8; 32];
    owner_pk.copy_from_slice(&owner_bytes);
    let mut heir_pk = [0u8; 32];
    heir_pk.copy_from_slice(&heir_bytes);

    let prefix = network_to_prefix(network);
    let script = kspt::build_dms_csv_script(&owner_pk, &heir_pk, inactivity_daa);
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let script_hex = hex::encode(&script);

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": script_hex,
        "inactivity_daa": inactivity_daa,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create a PSKB for a timeout refund on a time-locked escrow.
/// No signature needed — the CLTV branch has no CHECKSIG.
/// TX locktime is set to locktime_daa; output must go to Alice's address.
#[wasm_bindgen]
pub async fn create_covenant_timeout_refund(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    let utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str("Balance too low to cover fee"));
    }

    let send_amount = total - fee;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;

    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
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
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 0,
            "bip32Derivations": [],
            "proprietaries": [],
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
            "fallbackLockTime": locktime_daa,
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
        &format!("[KasSee] Timeout-refund PSKB: {} inputs, total {}, send {}, fee {}, locktime {}, wire {} chars",
            utxos.len(), total, send_amount, fee, locktime_daa, wire.len()
        ).into(),
    );

    Ok(wire)
}

/// Create a PSKB for a beneficiary spend on a time-locked vault covenant.
/// The TX locktime is set to the vault's locktime_daa so the node
/// enforces the time gate via OP_CHECKLOCKTIMEVERIFY in the script.
/// The beneficiary provides a signature; no owner signature needed.
#[wasm_bindgen]
pub async fn create_covenant_beneficiary_spend(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    // Detect CSV vs CLTV from script
    let csv_seq = kspt::extract_csv_sequence(&redeem_bytes);
    let input_sequence = if csv_seq > 0 { csv_seq } else { 0 };
    let tx_locktime = if csv_seq > 0 { 0 } else { locktime_daa };

    // Fetch UTXOs for the covenant address
    let utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;

    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str("Balance too low to cover fee"));
    }

    let send_amount = total - fee;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;

    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    let mut inputs = Vec::new();
    for utxo in &utxos {
        let input = serde_json::json!({
            "previousOutpoint": {
                "transactionId": utxo.tx_id,
                "index": utxo.index
            },
            "sequence": input_sequence,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
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
            "fallbackLockTime": tx_locktime,
            "covenantBranch": "beneficiary",
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
        &format!("[KasSee] Beneficiary-spend PSKB: {} inputs, total {}, send {}, fee {}, locktime {}, wire {} chars",
            utxos.len(), total, send_amount, fee, locktime_daa, wire.len()
        ).into(),
    );

    Ok(wire)
}

/// Like `create_covenant_beneficiary_spend`, but sweeps only the caller-selected
/// UTXOs (so a vault/DMS funded with many UTXOs can be claimed in batches, e.g.
/// to keep the QR within KasSigner's frame limit). utxos_json: JSON array of
/// {tx_id, index, amount}. locktime_daa: CLTV unlock (0 for CSV/DMS).
#[wasm_bindgen]
pub fn create_covenant_beneficiary_spend_selected(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    utxos_json: &str,
    fee: u64,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    // CSV vs CLTV, same detection as the full-sweep beneficiary spend.
    let csv_seq = kspt::extract_csv_sequence(&redeem_bytes);
    let input_sequence = if csv_seq > 0 { csv_seq } else { 0 };
    let tx_locktime = if csv_seq > 0 { 0 } else { locktime_daa };

    let utxo_arr: Vec<serde_json::Value> = serde_json::from_str(utxos_json)
        .map_err(|e| JsValue::from_str(&format!("Bad UTXO JSON: {}", e)))?;
    if utxo_arr.is_empty() {
        return Err(JsValue::from_str("No UTXOs provided"));
    }

    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    let mut total: u64 = 0;
    let mut inputs = Vec::new();
    for u in &utxo_arr {
        let tx_id = u
            .get("tx_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("UTXO missing tx_id"))?;
        let index = u
            .get("index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| JsValue::from_str("UTXO missing index"))? as u32;
        let amount = u
            .get("amount")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| JsValue::from_str("UTXO missing amount"))?;
        total += amount;
        inputs.push(serde_json::json!({
            "previousOutpoint": { "transactionId": tx_id, "index": index },
            "sequence": input_sequence,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": amount,
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        }));
    }

    if total <= fee {
        return Err(JsValue::from_str("Selected UTXOs too small to cover fee"));
    }
    let send_amount = total - fee;
    let n_inputs = inputs.len();

    let outputs = vec![serde_json::json!({
        "amount": send_amount,
        "scriptPublicKey": dest_spk_hex,
        "bip32Derivations": [],
        "proprietaries": []
    })];

    let pskt = serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": tx_locktime,
            "covenantBranch": "beneficiary",
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": n_inputs,
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
        &format!("[KasSee] Beneficiary-spend (selected) PSKB: {} inputs, total {}, send {}, fee {}, locktime {}, wire {} chars",
            n_inputs, total, send_amount, fee, locktime_daa, wire.len()
        ).into(),
    );
    Ok(wire)
}
/// Beneficiary signs (ELSE branch with CHECKSIGVERIFY).
/// Partial spend: withdraw_sompi goes to dest, remainder goes back to covenant.
/// CSV sequence enforced on the covenant input.
#[wasm_bindgen]
pub async fn create_covenant_allowance_withdraw(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    let all_utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if all_utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    let total_balance: u64 = all_utxos.iter().map(|u| u.amount).sum();
    if withdraw_sompi + fee > total_balance {
        return Err(JsValue::from_str(&format!(
            "Withdraw {} + fee {} > total balance {}",
            withdraw_sompi, fee, total_balance
        )));
    }

    let return_amount = total_balance - withdraw_sompi - fee;

    // KIP-9 storage mass: tiny outputs cause massive fees.
    // With C=10^12 and max_storage_mass=500K, outputs below ~0.04 KAS
    // paired with large withdrawals exceed the cap. Use 0.1 KAS minimum.
    const MIN_RETURN_SOMPI: u64 = 10_000_000; // 0.1 KAS
    if return_amount > 0 && return_amount < MIN_RETURN_SOMPI {
        return Err(JsValue::from_str(&format!(
            "Return amount {} sompi ({:.4} KAS) is too small. Tiny outputs cause high storage fees. \
             Either withdraw less (leave at least 0.1 KAS) or use Owner Reclaim to sweep everything.",
            return_amount, return_amount as f64 / 1e8
        )));
    }
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));
    let redeem_hex = hex::encode(&redeem_bytes);
    let csv_seq = kspt::extract_csv_sequence(&redeem_bytes);
    let cltv_locktime = kspt::extract_cltv_locktime(&redeem_bytes);

    // Multi-input: use ALL UTXOs at the covenant address
    let inputs: Vec<serde_json::Value> = all_utxos
        .iter()
        .map(|u| {
            serde_json::json!({
                "previousOutpoint": {
                    "transactionId": u.tx_id,
                    "index": u.index
                },
                "sequence": csv_seq,
                "sigOpCount": 1,
                "utxoEntry": {
                    "amount": u.amount,
                    "scriptPublicKey": covenant_spk_hex,
                    "blockDaaScore": 0,
                    "isCoinbase": false
                },
                "redeemScript": redeem_hex,
                "partialSigs": {},
                "minimumSignatures": 1,
                "bip32Derivations": [],
                "proprietaries": [],
                "finalScriptSig": null,
                "minTime": 0
            })
        })
        .collect();

    let input_count = inputs.len();

    // Output[0] = covenant return (script checks this), Output[1] = beneficiary withdraw
    let outputs = vec![
        serde_json::json!({
            "amount": return_amount,
            "scriptPublicKey": covenant_spk_hex,
            "bip32Derivations": [],
            "proprietaries": []
        }),
        serde_json::json!({
            "amount": withdraw_sompi,
            "scriptPublicKey": dest_spk_hex,
            "bip32Derivations": [],
            "proprietaries": []
        }),
    ];

    let locktime_val: serde_json::Value = if cltv_locktime > 0 {
        serde_json::json!(cltv_locktime)
    } else {
        serde_json::Value::Null
    };

    // tx_version=1 required for covenant binding outputs on TN10
    let pskt = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": locktime_val,
            "covenantBranch": "beneficiary",
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": input_count,
            "outputCount": 2,
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
        &format!("[KasSee] Allowance-withdraw PSKB: {} inputs, total_in={}, withdraw={}, return={}, fee={}, csv_seq={}, wire {} chars",
            input_count, total_balance, withdraw_sompi, return_amount, fee, csv_seq, wire.len()
        ).into(),
    );

    Ok(wire)
}

/// Create a PSKB to claim an atomic swap covenant (counterparty reveals preimage).
/// The preimage is stored in proprietaries.atomicPreimage so the finalization
/// can include it in the sig_script.
#[wasm_bindgen]
pub async fn create_covenant_atomic_claim(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    preimage_hex: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;
    let _preimage_bytes = hex::decode(preimage_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad preimage hex: {}", e)))?;

    let utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str("Balance too low to cover fee"));
    }

    let send_amount = total - fee;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;

    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    let mut inputs = Vec::new();
    for utxo in &utxos {
        let mut proprietaries = serde_json::Map::new();
        proprietaries.insert(
            "atomicPreimage".to_string(),
            serde_json::Value::String(preimage_hex.to_string()),
        );

        let input = serde_json::json!({
            "previousOutpoint": {
                "transactionId": utxo.tx_id,
                "index": utxo.index
            },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": proprietaries,
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
            "covenantBranch": "beneficiary",
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
    let json_str = serde_json::to_string(&pskb)
        .map_err(|e| JsValue::from_str(&format!("JSON serialize: {}", e)))?;
    let json_hex = hex::encode(json_str.as_bytes());

    let mut wire_bytes: Vec<u8> = Vec::with_capacity(4 + json_hex.len());
    wire_bytes.extend_from_slice(b"PSKB");
    wire_bytes.extend_from_slice(json_hex.as_bytes());
    let wire = hex::encode(&wire_bytes);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Atomic-claim PSKB: {} inputs, total {}, send {}, fee {}, wire {} chars",
            utxos.len(),
            total,
            send_amount,
            fee,
            wire.len()
        )
        .into(),
    );

    Ok(wire)
}

/// Create a PSKB to spend a covenant UTXO via the owner path.
/// covenant_address: the P2SH covenant address (kaspatest:pz...)
/// dest_address: where to send the funds
/// redeem_script_hex: the covenant redeem script
/// fee: fee in sompi
#[wasm_bindgen]
pub async fn create_covenant_owner_spend(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    fee: u64,
    ws_url: &str,
    covenant_branch: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    // Fetch UTXOs for the covenant address
    let utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;

    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str("Balance too low to cover fee"));
    }

    let send_amount = total - fee;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;

    // Build PSKB JSON
    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
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
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
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

    // CLTV locktime is needed ONLY for the time-locked owner path
    // ("owner-time", e.g. the piggy-bank break-after-deadline branch). The
    // default owner reclaim spends the immediate branch (IF), which carries
    // no CLTV; stamping the script's future locktime onto that TX makes the
    // node reject it as "input #0 is not finalized" until the DAA is reached.
    let cltv_locktime = if covenant_branch == "owner-time" {
        kspt::extract_cltv_locktime(&redeem_bytes)
    } else {
        0
    };
    web_sys::console::log_1(
        &format!(
            "[KasSee] owner-spend: redeem_len={}, cltv_locktime={}, branch={}",
            redeem_bytes.len(),
            cltv_locktime,
            covenant_branch
        )
        .into(),
    );
    let locktime_val: serde_json::Value = if cltv_locktime > 0 {
        serde_json::json!(cltv_locktime)
    } else {
        serde_json::Value::Null
    };

    let branch_val: serde_json::Value = if covenant_branch.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::json!(covenant_branch)
    };

    let pskt = serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": locktime_val,
            "covenantBranch": branch_val,
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
    // Wire = hex("PSKB" + json_hex) — matches kspt::serialize_pskb_single_sig
    let mut wire_bytes: Vec<u8> = Vec::with_capacity(4 + json_hex.len());
    wire_bytes.extend_from_slice(b"PSKB");
    wire_bytes.extend_from_slice(json_hex.as_bytes());
    let wire = hex::encode(&wire_bytes);

    web_sys::console::log_1(
        &format!("[KasSee] Covenant owner-spend PSKB: {} inputs, total {}, send {}, fee {}, wire {} chars",
            utxos.len(), total, send_amount, fee, wire.len()
        ).into(),
    );

    Ok(wire)
}

/// Create a PSKB for a GLOBAL spending-limit withdrawal (single covenant_id thread).
///
/// Spends THE thread UTXO and continues the thread as exactly ONE tagged output
/// back to the covenant address:
///   [0] continuation back to covenant (tagged)
///   [1] withdrawal to dest (fee deducted from the withdrawal)
/// If the whole balance fits under the cap you may close the thread instead
/// (single output to dest, no continuation); the script enforces balance <= cap.
///
/// The continuation `covenantId` must equal the thread's OWN covenant id (G),
/// so the spend is a true continuation: the script counts outputs tagged with
/// the input's id via OP_INPUT_COVENANT_ID + OP_COV_OUTPUT_COUNT. The UI passes
/// G (read from the thread UTXO). `authorizingInput` points at the thread (0).
///
/// `selected_utxos_json`: JSON array with the single thread UTXO,
///   [{ "tx_id", "index", "amount", "block_daa_score" }]
/// The node enforces the CSV cooldown on the input; this builder sets the input
/// sequence to the script's CSV value.
#[wasm_bindgen]
pub async fn create_global_spending_limit_withdraw(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    selected_utxos_json: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;
    let csv_seq = kspt::extract_csv_sequence(&redeem_bytes);

    // The continuation must carry the thread's OWN covenant id (G) so the spend
    // is a CONTINUATION: the script does OP_INPUT_COVENANT_ID then
    // OP_COV_OUTPUT_COUNT, which counts outputs tagged with the *input's* id. A
    // genesis-rooted id would not be counted (count=0 -> close branch fails).
    let covenant_id: [u8; 32] = hex::decode(covenant_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad covenant_id hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("covenant_id not 32 bytes"))?;

    // The thread is a single tagged UTXO; the UI passes it in.
    let parsed: Vec<serde_json::Value> = serde_json::from_str(selected_utxos_json)
        .map_err(|e| JsValue::from_str(&format!("Bad selected UTXOs JSON: {}", e)))?;
    if parsed.is_empty() {
        return Err(JsValue::from_str("No thread UTXO selected"));
    }
    let use_utxos: Vec<rpc::UtxoEntry> = parsed
        .iter()
        .map(|v| rpc::UtxoEntry {
            tx_id: v["tx_id"].as_str().unwrap_or("").to_string(),
            index: v["index"].as_u64().unwrap_or(0) as u32,
            amount: v["amount"].as_u64().unwrap_or(0),
            block_daa_score: v["block_daa_score"].as_u64().unwrap_or(0),
            script_public_key: Vec::new(),
            covenant_id: None,
        })
        .collect();

    let total: u64 = use_utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str(&format!(
            "Balance {} too low to cover fee {}",
            total, fee
        )));
    }
    if withdraw_sompi <= fee {
        return Err(JsValue::from_str(&format!(
            "Withdrawal {} must be greater than fee {}",
            withdraw_sompi, fee
        )));
    }

    // Close = take the whole balance with no continuation (the script's ELSE branch,
    // which requires balance <= cap). Otherwise a normal capped withdrawal.
    let is_close = total <= withdraw_sompi;
    let remainder = if is_close { 0 } else { total - withdraw_sompi };
    let user_receives = if is_close {
        total - fee
    } else {
        withdraw_sompi - fee
    };
    let output_count = if is_close { 1 } else { 2 };

    // KIP-9: a tiny continuation output causes high storage mass.
    const MIN_RETURN_SOMPI: u64 = 10_000_000; // 0.1 KAS
    if !is_close && remainder > 0 && remainder < MIN_RETURN_SOMPI {
        return Err(JsValue::from_str(&format!(
            "Continuation {} sompi ({:.4} KAS) is too small. Leave at least 0.1 KAS on the thread, \
             or close it by withdrawing the whole balance (allowed only when balance <= cap).",
            remainder, remainder as f64 / 1e8
        )));
    }

    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    // Single thread input (P2SH covenant input: redeem script + CSV sequence).
    let inputs: Vec<serde_json::Value> = use_utxos
        .iter()
        .map(|u| {
            serde_json::json!({
                "previousOutpoint": { "transactionId": u.tx_id, "index": u.index },
                "sequence": csv_seq,
                "sigOpCount": 1,
                "utxoEntry": {
                    "amount": u.amount,
                    "scriptPublicKey": covenant_spk_hex,
                    "blockDaaScore": 0,
                    "isCoinbase": false
                },
                "redeemScript": redeem_hex,
                "partialSigs": {},
                "minimumSignatures": 1,
                "bip32Derivations": [],
                "proprietaries": [],
                "finalScriptSig": null,
                "minTime": 0
            })
        })
        .collect();
    let input_count = inputs.len();

    // Outputs.
    let mut outputs = Vec::new();
    if !is_close {
        // [0] continuation back to covenant, TAGGED with the same covenant_id (single thread).
        outputs.push(serde_json::json!({
            "amount": remainder,
            "scriptPublicKey": covenant_spk_hex,
            "covenantBinding": { "authorizingInput": 0, "covenantId": hex::encode(covenant_id) },
            "bip32Derivations": [],
            "proprietaries": []
        }));
    }
    // Withdrawal to destination (plain; fee deducted from the withdrawal).
    outputs.push(serde_json::json!({
        "amount": user_receives,
        "scriptPublicKey": dest_spk_hex,
        "covenantBinding": serde_json::Value::Null,
        "bip32Derivations": [],
        "proprietaries": []
    }));

    // tx_version=1 required for covenant binding outputs on TN10.
    let pskt = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": 0,
            "covenantBranch": serde_json::Value::Null,
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": input_count,
            "outputCount": output_count,
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
        &format!("[KasSee] Global spending-limit withdraw PSKB: {} input(s), total {}, withdraw {}, user_receives {}, continuation {}, fee {}, close={}, csv_seq {}, cov_id={}, wire {} chars",
            input_count, total, withdraw_sompi, user_receives, remainder, fee, is_close, csv_seq, hex::encode(covenant_id), wire.len()
        ).into(),
    );
    Ok(wire)
}

/// Create a PSKB that TOPS UP / consolidates the GLOBAL spending-limit thread.
///
/// Folds selected wallet UTXOs into the single covenant_id thread by spending
/// the thread UTXO together with those wallet UTXOs into ONE tagged continuation:
///   inputs:  [thread UTXO (P2SH, owner-signed)] + [selected wallet UTXOs (P2PK)]
///   output:  [continuation back to covenant, tagged with the thread's id (G)]
/// Exactly one tagged output, so the single thread is preserved. The selected
/// wallet UTXOs are folded in whole (no change output). The thread's CSV
/// cooldown applies to this spend, so the thread UTXO must be mature.
///
/// The firmware signs the mixed inputs per type in one pass: the thread input
/// is P2SH (redeem script + owner key), the wallet inputs are P2PK.
///
/// `thread_utxo_json`: the single thread UTXO, { "tx_id", "index", "amount" }
/// `utxo_indices_csv`: indices (into the sorted wallet UTXO list) to fold in.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_global_spending_limit_topup(
    wallet_json: &str,
    covenant_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    thread_utxo_json: &str,
    fee: u64,
    utxo_indices_csv: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet JSON: {}", e)))?;

    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;
    let csv_seq = kspt::extract_csv_sequence(&redeem_bytes);
    let redeem_hex = hex::encode(&redeem_bytes);

    // Continuation carries the thread's OWN covenant id (G) -> true continuation.
    let covenant_id: [u8; 32] = hex::decode(covenant_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad covenant_id hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("covenant_id not 32 bytes"))?;

    let tv: serde_json::Value = serde_json::from_str(thread_utxo_json)
        .map_err(|e| JsValue::from_str(&format!("Bad thread UTXO JSON: {}", e)))?;
    let thread_txid = tv["tx_id"].as_str().unwrap_or("").to_string();
    let thread_index = tv["index"].as_u64().unwrap_or(0) as u32;
    let thread_amount = tv["amount"].as_u64().unwrap_or(0);
    if thread_txid.is_empty() || thread_amount == 0 {
        return Err(JsValue::from_str("Invalid thread UTXO"));
    }

    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));

    // Wallet UTXOs to fold in (selected by the UI).
    let mut utxos = rpc::fetch_all_utxos(ws_url, &wallet)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
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
    if manual_indices.is_empty() {
        return Err(JsValue::from_str(
            "Select at least one wallet UTXO to fold into the thread",
        ));
    }
    let mut selected = Vec::new();
    let mut wallet_total = 0u64;
    for &idx in &manual_indices {
        if idx >= utxos.len() {
            return Err(JsValue::from_str(&format!(
                "UTXO index {} out of range (have {})",
                idx,
                utxos.len()
            )));
        }
        selected.push(utxos[idx].clone());
        wallet_total += utxos[idx].amount;
    }
    if wallet_total <= fee {
        return Err(JsValue::from_str(&format!(
            "Selected wallet funds {} must exceed fee {} to add to the thread",
            wallet_total, fee
        )));
    }

    let continuation = thread_amount + wallet_total - fee; // single tagged output

    // inputs: [0] thread (P2SH covenant), [1..] wallet (P2PK)
    let mut inputs: Vec<serde_json::Value> = Vec::with_capacity(1 + selected.len());
    inputs.push(serde_json::json!({
        "previousOutpoint": { "transactionId": thread_txid, "index": thread_index },
        "sequence": csv_seq,
        "sigOpCount": 1,
        "utxoEntry": { "amount": thread_amount, "scriptPublicKey": covenant_spk_hex, "blockDaaScore": 0, "isCoinbase": false },
        "redeemScript": redeem_hex,
        "partialSigs": {},
        "minimumSignatures": 1,
        "bip32Derivations": [],
        "proprietaries": [],
        "finalScriptSig": null,
        "minTime": 0
    }));
    for u in &selected {
        let w_spk_hex = format!("0000{}", hex::encode(&u.script_public_key));
        inputs.push(serde_json::json!({
            "previousOutpoint": { "transactionId": u.tx_id, "index": u.index },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": { "amount": u.amount, "scriptPublicKey": w_spk_hex, "blockDaaScore": u.block_daa_score, "isCoinbase": false },
            "redeemScript": serde_json::Value::Null,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        }));
    }
    let input_count = inputs.len();

    // output: ONE tagged continuation back to the covenant (preserves single thread)
    let outputs = vec![serde_json::json!({
        "amount": continuation,
        "scriptPublicKey": covenant_spk_hex,
        "covenantBinding": { "authorizingInput": 0, "covenantId": hex::encode(covenant_id) },
        "bip32Derivations": [],
        "proprietaries": []
    })];
    let output_count = outputs.len();

    // tx_version=1 required for covenant binding outputs on TN10.
    let pskt = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": 0,
            "covenantBranch": serde_json::Value::Null,
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": input_count,
            "outputCount": output_count,
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
        &format!("[KasSee] Global spending-limit top-up PSKB: {} input(s) (1 thread + {} wallet), thread {}, added {}, continuation {}, fee {}, csv_seq {}, cov_id={}, wire {} chars",
            input_count, selected.len(), thread_amount, wallet_total, continuation, fee, csv_seq, hex::encode(covenant_id), wire.len()
        ).into(),
    );
    Ok(wire)
}

/// Create a PSKB for a BENEFICIARY withdrawal from a GLOBAL ALLOWANCE thread.
///
/// Mirrors `create_global_spending_limit_withdraw`, with two differences:
///   1. The spend takes the beneficiary ELSE branch, so `covenantBranch` is
///      "beneficiary" (the finalizer emits the OP_FALSE selector). The firmware
///      signs with the beneficiary's active seed (candidate 1 in the script).
///   2. If the script carries a vesting start date (CLTV), `fallbackLockTime`
///      is set to it so the TX clears OP_CHECKLOCKTIMEVERIFY.
///
/// The thread is a single tagged UTXO. A normal withdrawal continues the thread
/// (one tagged continuation back to the covenant, amount >= input - max). A
/// close takes the whole balance with no continuation, allowed by the script
/// only when balance <= cap.
#[wasm_bindgen]
pub async fn create_global_allowance_withdraw(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    selected_utxos_json: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;
    let csv_seq = kspt::extract_csv_sequence(&redeem_bytes);
    let cltv_locktime = kspt::extract_cltv_locktime(&redeem_bytes);

    // The continuation must carry the thread's OWN covenant id (G) so the spend
    // is a CONTINUATION: the script does OP_INPUT_COVENANT_ID then
    // OP_COV_OUTPUT_COUNT, counting outputs tagged with the *input's* id.
    let covenant_id: [u8; 32] = hex::decode(covenant_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad covenant_id hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("covenant_id not 32 bytes"))?;

    // The thread is a single tagged UTXO; the UI passes it in.
    let parsed: Vec<serde_json::Value> = serde_json::from_str(selected_utxos_json)
        .map_err(|e| JsValue::from_str(&format!("Bad selected UTXOs JSON: {}", e)))?;
    if parsed.is_empty() {
        return Err(JsValue::from_str("No thread UTXO selected"));
    }
    let use_utxos: Vec<rpc::UtxoEntry> = parsed
        .iter()
        .map(|v| rpc::UtxoEntry {
            tx_id: v["tx_id"].as_str().unwrap_or("").to_string(),
            index: v["index"].as_u64().unwrap_or(0) as u32,
            amount: v["amount"].as_u64().unwrap_or(0),
            block_daa_score: v["block_daa_score"].as_u64().unwrap_or(0),
            script_public_key: Vec::new(),
            covenant_id: None,
        })
        .collect();

    let total: u64 = use_utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str(&format!(
            "Balance {} too low to cover fee {}",
            total, fee
        )));
    }
    if withdraw_sompi <= fee {
        return Err(JsValue::from_str(&format!(
            "Withdrawal {} must be greater than fee {}",
            withdraw_sompi, fee
        )));
    }

    // Close = take the whole balance with no continuation (the script's ELSE
    // branch, which requires balance <= cap). Otherwise a normal capped withdraw.
    let is_close = total <= withdraw_sompi;
    let remainder = if is_close { 0 } else { total - withdraw_sompi };
    let user_receives = if is_close {
        total - fee
    } else {
        withdraw_sompi - fee
    };
    let output_count = if is_close { 1 } else { 2 };

    // KIP-9: a tiny continuation output causes high storage mass.
    const MIN_RETURN_SOMPI: u64 = 10_000_000; // 0.1 KAS
    if !is_close && remainder > 0 && remainder < MIN_RETURN_SOMPI {
        return Err(JsValue::from_str(&format!(
            "Continuation {} sompi ({:.4} KAS) is too small. Leave at least 0.1 KAS on the thread, \
             or close it by withdrawing the whole balance (allowed only when balance <= cap).",
            remainder, remainder as f64 / 1e8
        )));
    }

    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    // Single thread input (P2SH covenant input: redeem script + CSV sequence).
    let inputs: Vec<serde_json::Value> = use_utxos
        .iter()
        .map(|u| {
            serde_json::json!({
                "previousOutpoint": { "transactionId": u.tx_id, "index": u.index },
                "sequence": csv_seq,
                "sigOpCount": 1,
                "utxoEntry": {
                    "amount": u.amount,
                    "scriptPublicKey": covenant_spk_hex,
                    "blockDaaScore": 0,
                    "isCoinbase": false
                },
                "redeemScript": redeem_hex,
                "partialSigs": {},
                "minimumSignatures": 1,
                "bip32Derivations": [],
                "proprietaries": [],
                "finalScriptSig": null,
                "minTime": 0
            })
        })
        .collect();
    let input_count = inputs.len();

    // Outputs.
    let mut outputs = Vec::new();
    if !is_close {
        // [0] continuation back to covenant, TAGGED with the same covenant_id.
        outputs.push(serde_json::json!({
            "amount": remainder,
            "scriptPublicKey": covenant_spk_hex,
            "covenantBinding": { "authorizingInput": 0, "covenantId": hex::encode(covenant_id) },
            "bip32Derivations": [],
            "proprietaries": []
        }));
    }
    // Withdrawal to destination (plain; fee deducted from the withdrawal).
    outputs.push(serde_json::json!({
        "amount": user_receives,
        "scriptPublicKey": dest_spk_hex,
        "covenantBinding": serde_json::Value::Null,
        "bip32Derivations": [],
        "proprietaries": []
    }));

    // Vesting start: if the script gates the beneficiary path with CLTV, the TX
    // locktime must be >= that value. Null if there is no start gate.
    let locktime_val: serde_json::Value = if cltv_locktime > 0 {
        serde_json::json!(cltv_locktime)
    } else {
        serde_json::Value::Null
    };

    // tx_version=1 required for covenant binding outputs on TN10.
    let pskt = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": locktime_val,
            "covenantBranch": "beneficiary",
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": input_count,
            "outputCount": output_count,
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
        &format!("[KasSee] Global allowance withdraw PSKB: {} input(s), total {}, withdraw {}, user_receives {}, continuation {}, fee {}, close={}, csv_seq {}, cltv {}, cov_id={}, wire {} chars",
            input_count, total, withdraw_sompi, user_receives, remainder, fee, is_close, csv_seq, cltv_locktime, hex::encode(covenant_id), wire.len()
        ).into(),
    );
    Ok(wire)
}

/// Create a PSKB that TOPS UP the GLOBAL ALLOWANCE thread (OWNER adds funds).
///
/// Mirrors `create_global_spending_limit_topup`. The owner spends the thread
/// UTXO through the free top-level OWNER path (`covenantBranch` = "owner", the
/// finalizer emits the OP_TRUE selector) together with selected wallet UTXOs,
/// folding everything into ONE tagged continuation that preserves the single
/// thread id (G). The owner path is uncapped, so any amount can be added. The
/// beneficiary's per-spend cap and cooldown continue to apply to future
/// withdrawals from the enlarged thread.
///
/// `thread_utxo_json`: the single thread UTXO, { "tx_id", "index", "amount" }
/// `utxo_indices_csv`: indices (into the sorted wallet UTXO list) to fold in.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_global_allowance_topup(
    wallet_json: &str,
    covenant_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    thread_utxo_json: &str,
    fee: u64,
    utxo_indices_csv: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet JSON: {}", e)))?;

    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;
    // Owner path: top-level IF, no CSV/CLTV gate, so the thread input does not
    // need a non-zero sequence. Use 0 (no relative timelock) on the thread input.
    let redeem_hex = hex::encode(&redeem_bytes);

    // Continuation carries the thread's OWN covenant id (G) -> true continuation.
    let covenant_id: [u8; 32] = hex::decode(covenant_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad covenant_id hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("covenant_id not 32 bytes"))?;

    let tv: serde_json::Value = serde_json::from_str(thread_utxo_json)
        .map_err(|e| JsValue::from_str(&format!("Bad thread UTXO JSON: {}", e)))?;
    let thread_txid = tv["tx_id"].as_str().unwrap_or("").to_string();
    let thread_index = tv["index"].as_u64().unwrap_or(0) as u32;
    let thread_amount = tv["amount"].as_u64().unwrap_or(0);
    if thread_txid.is_empty() || thread_amount == 0 {
        return Err(JsValue::from_str("Invalid thread UTXO"));
    }

    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));

    // Wallet UTXOs to fold in (selected by the UI).
    let mut utxos = rpc::fetch_all_utxos(ws_url, &wallet)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
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
    if manual_indices.is_empty() {
        return Err(JsValue::from_str(
            "Select at least one wallet UTXO to fold into the thread",
        ));
    }
    let mut selected = Vec::new();
    let mut wallet_total = 0u64;
    for &idx in &manual_indices {
        if idx >= utxos.len() {
            return Err(JsValue::from_str(&format!(
                "UTXO index {} out of range (have {})",
                idx,
                utxos.len()
            )));
        }
        selected.push(utxos[idx].clone());
        wallet_total += utxos[idx].amount;
    }
    if wallet_total <= fee {
        return Err(JsValue::from_str(&format!(
            "Selected wallet funds {} must exceed fee {} to add to the thread",
            wallet_total, fee
        )));
    }

    let continuation = thread_amount + wallet_total - fee; // single tagged output

    // inputs: [0] thread (P2SH covenant, owner IF), [1..] wallet (P2PK)
    let mut inputs: Vec<serde_json::Value> = Vec::with_capacity(1 + selected.len());
    inputs.push(serde_json::json!({
        "previousOutpoint": { "transactionId": thread_txid, "index": thread_index },
        "sequence": 0,
        "sigOpCount": 1,
        "utxoEntry": { "amount": thread_amount, "scriptPublicKey": covenant_spk_hex, "blockDaaScore": 0, "isCoinbase": false },
        "redeemScript": redeem_hex,
        "partialSigs": {},
        "minimumSignatures": 1,
        "bip32Derivations": [],
        "proprietaries": [],
        "finalScriptSig": null,
        "minTime": 0
    }));
    for u in &selected {
        let w_spk_hex = format!("0000{}", hex::encode(&u.script_public_key));
        inputs.push(serde_json::json!({
            "previousOutpoint": { "transactionId": u.tx_id, "index": u.index },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": { "amount": u.amount, "scriptPublicKey": w_spk_hex, "blockDaaScore": u.block_daa_score, "isCoinbase": false },
            "redeemScript": serde_json::Value::Null,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        }));
    }
    let input_count = inputs.len();

    // output: ONE tagged continuation back to the covenant (preserves single thread)
    let outputs = vec![serde_json::json!({
        "amount": continuation,
        "scriptPublicKey": covenant_spk_hex,
        "covenantBinding": { "authorizingInput": 0, "covenantId": hex::encode(covenant_id) },
        "bip32Derivations": [],
        "proprietaries": []
    })];
    let output_count = outputs.len();

    // tx_version=1 required for covenant binding outputs on TN10.
    let pskt = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": 0,
            "covenantBranch": "owner",
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": input_count,
            "outputCount": output_count,
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
        &format!("[KasSee] Global allowance top-up PSKB: {} input(s) (1 thread + {} wallet), thread {}, added {}, continuation {}, fee {}, cov_id={}, wire {} chars",
            input_count, selected.len(), thread_amount, wallet_total, continuation, fee, hex::encode(covenant_id), wire.len()
        ).into(),
    );
    Ok(wire)
}

/// Create a PSKB for an owner spend using specific UTXOs (for consolidation).
/// utxos_json: JSON array of {tx_id, index, amount} objects (selected UTXOs).
/// dest_address: where to send (covenant address for consolidation, personal address for withdrawal).
#[wasm_bindgen]
pub fn create_covenant_owner_spend_selected(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    utxos_json: &str,
    fee: u64,
    covenant_branch: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    let utxo_arr: Vec<serde_json::Value> = serde_json::from_str(utxos_json)
        .map_err(|e| JsValue::from_str(&format!("Bad UTXO JSON: {}", e)))?;

    if utxo_arr.is_empty() {
        return Err(JsValue::from_str("No UTXOs provided"));
    }

    let mut total: u64 = 0;
    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    let mut inputs = Vec::new();
    for u in &utxo_arr {
        let tx_id = u
            .get("tx_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("UTXO missing tx_id"))?;
        let index = u
            .get("index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| JsValue::from_str("UTXO missing index"))? as u32;
        let amount = u
            .get("amount")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| JsValue::from_str("UTXO missing amount"))?;
        total += amount;

        inputs.push(serde_json::json!({
            "previousOutpoint": { "transactionId": tx_id, "index": index },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": amount,
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        }));
    }

    if total <= fee {
        return Err(JsValue::from_str("Selected UTXOs too small to cover fee"));
    }
    let send_amount = total - fee;

    let outputs = vec![serde_json::json!({
        "amount": send_amount,
        "scriptPublicKey": dest_spk_hex,
        "bip32Derivations": [],
        "proprietaries": []
    })];

    // See create_covenant_owner_spend: CLTV is stamped onto the TX only for
    // the time-locked owner path; the immediate reclaim must stay final.
    let cltv_locktime = if covenant_branch == "owner-time" {
        kspt::extract_cltv_locktime(&redeem_bytes)
    } else {
        0
    };
    let locktime_val: serde_json::Value = if cltv_locktime > 0 {
        serde_json::json!(cltv_locktime)
    } else {
        serde_json::Value::Null
    };
    let branch_val: serde_json::Value = if covenant_branch.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::json!(covenant_branch)
    };

    let pskt = serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": locktime_val,
            "covenantBranch": branch_val,
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
        &format!("[KasSee] Covenant owner-spend-selected PSKB: {} inputs, total {}, send {}, fee {}, wire {} chars",
            inputs.len(), total, send_amount, fee, wire.len()
        ).into(),
    );

    Ok(wire)
}
/// No signature needed — the introspection opcodes enforce the rules.
/// The transaction spends the covenant UTXO and sends it back to the
/// SAME covenant address with at least (original amount + threshold) sompi.
/// Additional funds come from the borrower's regular P2PK UTXOs.
///
/// borrower_wallet_json: the borrower's wallet (for funding UTXOs)
/// covenant_address: the P2SH covenant address
/// redeem_script_hex: the covenant redeem script
/// add_amount_sompi: how much extra to add (must be >= threshold)
/// fee: fee in sompi
#[wasm_bindgen]
pub async fn create_covenant_borrower_spend(
    borrower_wallet_json: &str,
    covenant_address: &str,
    redeem_script_hex: &str,
    add_amount_sompi: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let borrower_wallet: bip32::WalletData = serde_json::from_str(borrower_wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    // Fetch covenant UTXOs — use only the largest one.
    // The ELSE branch checks output[input_index].spk == input[input_index].spk,
    // so multiple covenant inputs would reference wrong or missing outputs.
    // Each additive deposit merges one existing UTXO + new funds into one output.
    let all_cov_utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if all_cov_utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }
    let largest = all_cov_utxos.iter().max_by_key(|u| u.amount).unwrap();
    let covenant_utxos = vec![largest.clone()];
    let covenant_total: u64 = largest.amount;

    // Fetch borrower UTXOs to fund the added amount + fee
    let borrower_utxos = rpc::fetch_all_utxos(ws_url, &borrower_wallet)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    let needed = add_amount_sompi + fee;
    let mut funding_utxos = Vec::new();
    let mut funding_total: u64 = 0;
    for utxo in &borrower_utxos {
        if funding_total >= needed {
            break;
        }
        funding_utxos.push(utxo.clone());
        funding_total += utxo.amount;
    }
    if funding_total < needed {
        return Err(JsValue::from_str(&format!(
            "Borrower needs {} sompi but only has {}",
            needed, funding_total
        )));
    }

    let covenant_spk_hex = format!(
        "0000{}",
        hex::encode(
            address::address_to_script_pubkey(covenant_address)
                .map_err(|e| JsValue::from_str(&e))?
        )
    );
    let redeem_hex = hex::encode(&redeem_bytes);

    // Extract CSV sequence from redeem script (0 if no CSV present)
    let csv_seq = kspt::extract_csv_sequence(&redeem_bytes);

    // Build inputs: covenant UTXOs (no sigs) + borrower UTXOs (need sigs)
    let mut inputs = Vec::new();

    // Covenant inputs — redeemScript present, partialSigs empty (borrower path)
    for utxo in &covenant_utxos {
        inputs.push(serde_json::json!({
            "previousOutpoint": {
                "transactionId": utxo.tx_id,
                "index": utxo.index
            },
            "sequence": csv_seq,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 0,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        }));
    }

    // Borrower funding inputs — standard P2PK, need signature
    for utxo in &funding_utxos {
        let funding_spk_hex = format!("0000{}", hex::encode(&utxo.script_public_key));
        inputs.push(serde_json::json!({
            "previousOutpoint": {
                "transactionId": utxo.tx_id,
                "index": utxo.index
            },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": funding_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": null,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        }));
    }

    // Outputs:
    // 1. Covenant output — same address, covenant_total + add_amount
    // 2. Change back to borrower (if any)
    let covenant_output_amount = covenant_total + add_amount_sompi;
    let borrower_change = funding_total - needed;

    let chg_idx = borrower_wallet
        .next_change_index
        .min(borrower_wallet.change_addresses.len() - 1);
    let change_spk_hex = format!(
        "0000{}",
        hex::encode(
            address::address_to_script_pubkey(&borrower_wallet.change_addresses[chg_idx])
                .map_err(|e| JsValue::from_str(&e))?
        )
    );

    let mut outputs = vec![serde_json::json!({
        "amount": covenant_output_amount,
        "scriptPublicKey": covenant_spk_hex,
        "bip32Derivations": [],
        "proprietaries": []
    })];

    if borrower_change > 0 {
        outputs.push(serde_json::json!({
            "amount": borrower_change,
            "scriptPublicKey": change_spk_hex,
            "bip32Derivations": [],
            "proprietaries": []
        }));
    }

    let pskt = serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": null,
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": inputs.len(),
            "outputCount": outputs.len(),
            "bip32Derivations": [],
            "proprietaries": []
        },
        "inputs": inputs,
        "outputs": outputs
    });

    let pskb = serde_json::json!([pskt]);
    let json_str = serde_json::to_string(&pskb).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let json_hex = hex::encode(json_str.as_bytes());
    // Wire = hex("PSKB" + json_hex) — matches kspt::serialize_pskb_single_sig
    let mut wire_bytes: Vec<u8> = Vec::with_capacity(4 + json_hex.len());
    wire_bytes.extend_from_slice(b"PSKB");
    wire_bytes.extend_from_slice(json_hex.as_bytes());
    let wire = hex::encode(&wire_bytes);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Covenant borrower-spend PSKB: {} covenant + {} funding inputs, covenant_out={}, change={}, fee={}, wire {} chars",
            covenant_utxos.len(), funding_utxos.len(), covenant_output_amount, borrower_change, fee, wire.len()
        ).into(),
    );

    Ok(wire)
}

/// Create a PSKB for a borrower WITHDRAWAL from a spending-limit covenant.
/// The borrower takes up to max_withdraw sompi. Output[0] returns the remainder
/// to the same covenant address. Output[1] is the borrower's withdrawal.
/// No covenant signature — introspection opcodes enforce the cap.
/// The borrower's P2PK funding input covers the fee.
#[wasm_bindgen]
pub async fn create_covenant_borrower_withdraw(
    borrower_wallet_json: &str,
    covenant_address: &str,
    redeem_script_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let borrower_wallet: bip32::WalletData = serde_json::from_str(borrower_wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid wallet: {}", e)))?;
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    // Fetch covenant UTXOs — use only the largest one to avoid multi-input issues.
    let all_cov_utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if all_cov_utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }
    let largest = all_cov_utxos.iter().max_by_key(|u| u.amount).unwrap();
    let covenant_utxos = vec![largest.clone()];
    let covenant_total: u64 = largest.amount;
    if withdraw_sompi > covenant_total {
        return Err(JsValue::from_str(&format!(
            "Withdraw {} > covenant balance {}",
            withdraw_sompi, covenant_total
        )));
    }

    // Borrower needs a funding UTXO to cover the fee
    let borrower_utxos = rpc::fetch_all_utxos(ws_url, &borrower_wallet)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    let mut funding_utxos = Vec::new();
    let mut funding_total: u64 = 0;
    for utxo in &borrower_utxos {
        if funding_total >= fee {
            break;
        }
        funding_utxos.push(utxo.clone());
        funding_total += utxo.amount;
    }
    if funding_total < fee {
        return Err(JsValue::from_str(&format!(
            "Borrower needs {} sompi for fee but only has {}",
            fee, funding_total
        )));
    }

    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let redeem_hex = hex::encode(&redeem_bytes);

    // Extract CSV sequence from redeem script (0 if no CSV present)
    let csv_seq = kspt::extract_csv_sequence(&redeem_bytes);

    // Build inputs
    let mut inputs = Vec::new();

    // Covenant input — no signature (borrower path)
    for utxo in &covenant_utxos {
        inputs.push(serde_json::json!({
            "previousOutpoint": {
                "transactionId": utxo.tx_id,
                "index": utxo.index
            },
            "sequence": csv_seq,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 0,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        }));
    }

    // Borrower funding input — standard P2PK, needs signature
    for utxo in &funding_utxos {
        let funding_spk_hex = format!("0000{}", hex::encode(&utxo.script_public_key));
        inputs.push(serde_json::json!({
            "previousOutpoint": {
                "transactionId": utxo.tx_id,
                "index": utxo.index
            },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": funding_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": null,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        }));
    }

    // Outputs (MUST be exactly 2 for spending-limit script):
    // [0] Covenant return — same address, covenant_total - withdraw_sompi
    // [1] Borrower withdrawal + change from funding
    let covenant_return_amount = covenant_total - withdraw_sompi;
    let borrower_receive = withdraw_sompi + (funding_total - fee);

    let rcv_idx = borrower_wallet
        .next_receive_index
        .min(borrower_wallet.receive_addresses.len() - 1);
    let borrower_spk_hex = format!(
        "0000{}",
        hex::encode(
            address::address_to_script_pubkey(&borrower_wallet.receive_addresses[rcv_idx])
                .map_err(|e| JsValue::from_str(&e))?
        )
    );

    let outputs = serde_json::json!([
        {
            "amount": covenant_return_amount,
            "scriptPublicKey": covenant_spk_hex
        },
        {
            "amount": borrower_receive,
            "scriptPublicKey": borrower_spk_hex
        }
    ]);

    let global = serde_json::json!({
        "txVersion": 0,
        "fallbackLockTime": 0,
        "id": serde_json::Value::Null,
        "proprietaries": {}
    });

    let pskt = serde_json::json!({
        "global": global,
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
            "[KasSee] Covenant borrower-withdraw PSKB: {} covenant + {} funding inputs, return={}, withdraw={}, fee={}, wire {} chars",
            covenant_utxos.len(), funding_utxos.len(), covenant_return_amount, borrower_receive, fee, wire.len()
        ).into(),
    );

    Ok(wire)
}

/// Build an escrow covenant P2SH address.
/// alice_pubkey_hex, bob_pubkey_hex: 64-char hex of 32-byte x-only pubkeys
/// alice_address, bob_address: kaspa/kaspatest addresses for release destinations
/// Returns JSON: { "address", "redeem_script_hex" }
#[wasm_bindgen]
pub fn covenant_escrow(
    alice_pubkey_hex: &str,
    bob_pubkey_hex: &str,
    arbiter_pubkey_hex: &str,
    alice_address: &str,
    bob_address: &str,
    network: &str,
) -> Result<String, JsValue> {
    let alice_pk = hex_to_pubkey32(alice_pubkey_hex)?;
    let bob_pk = hex_to_pubkey32(bob_pubkey_hex)?;
    let arbiter_pk = hex_to_pubkey32(arbiter_pubkey_hex)?;
    let alice_spk =
        address::address_to_script_pubkey(alice_address).map_err(|e| JsValue::from_str(&e))?;
    let bob_spk =
        address::address_to_script_pubkey(bob_address).map_err(|e| JsValue::from_str(&e))?;

    // Generate random 8-byte salt for unique escrow address
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt)
        .map_err(|e| JsValue::from_str(&format!("RNG failed: {}", e)))?;

    let prefix = network_to_prefix(network);
    let script =
        kspt::build_escrow_script(&alice_pk, &bob_pk, &arbiter_pk, &alice_spk, &bob_spk, &salt);
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "salt": hex::encode(salt),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a shipment-escrow covenant P2SH address.
///
/// Three parties (seller, deliverer, buyer) + a dormant arbiter. The buyer
/// funds `total = product_sompi + fee_sompi`. Product price splits 50/50:
/// tranche1 to the seller at pickup, tranche2 held until delivery. Delivery
/// fee paid in full at delivery. Two CLTV deadlines back the liveness:
/// `cltv1_deadline` (no-pickup -> refund buyer) and `cltv2_deadline`
/// (no-delivery -> pay workers).
///
/// Payouts go to each party's standard schnorr address (P2PK of their key),
/// built internally from the supplied pubkeys.
///
/// Fund state 0 with exactly `total_sompi`; the pickup spend continues the
/// covenant at exactly `rem_sompi` (state 1). Returns JSON with the address,
/// redeem script, salt, and all derived amounts/deadlines for the spend UI.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn covenant_ship_escrow(
    seller_pubkey_hex: &str,
    deliverer_pubkey_hex: &str,
    buyer_pubkey_hex: &str,
    arbiter_pubkey_hex: &str,
    product_sompi: u64,
    fee_sompi: u64,
    cltv1_deadline: u64,
    cltv2_deadline: u64,
    network: &str,
) -> Result<String, JsValue> {
    let s_pk = hex_to_pubkey32(seller_pubkey_hex)?;
    let d_pk = hex_to_pubkey32(deliverer_pubkey_hex)?;
    let b_pk = hex_to_pubkey32(buyer_pubkey_hex)?;
    let arb_pk = hex_to_pubkey32(arbiter_pubkey_hex)?;

    // Random 8-byte salt so identical participants produce a unique address.
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt)
        .map_err(|e| JsValue::from_str(&format!("RNG failed: {}", e)))?;

    let prefix = network_to_prefix(network);
    let script = kspt::build_ship_escrow_script(
        &s_pk,
        &d_pk,
        &b_pk,
        &arb_pk,
        product_sompi,
        fee_sompi,
        cltv1_deadline,
        cltv2_deadline,
        &salt,
    );
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;

    let t1 = product_sompi / 2;
    let t2 = product_sompi - t1;
    let total = product_sompi + fee_sompi;
    let rem = total - t1; // = t2 + fee, the state-1 dispatch amount

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "salt": hex::encode(salt),
        "product_sompi": product_sompi,
        "fee_sompi": fee_sompi,
        "t1_sompi": t1,
        "t2_sompi": t2,
        "total_sompi": total,
        "rem_sompi": rem,
        "cltv1_deadline": cltv1_deadline,
        "cltv2_deadline": cltv2_deadline,
        "type": "ship-escrow",
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a GLOBAL spending-limit covenant P2SH address (covenant_id single-thread).
///
/// Same per-spend cap + cooldown as `covenant_spending_limit`, but the whole
/// balance lives in ONE covenant_id-tagged UTXO (the thread), so the cap is
/// global instead of per-UTXO. Fund it as a covenant genesis via
/// `create_covenant_pskb` (passing this address), which tags the first UTXO
/// with the covenant_id that identifies the thread. Spend it later with
/// `create_global_spending_limit_withdraw`, which continues the single thread.
///
/// Returns JSON: { address, redeem_script_hex, max_withdraw_sompi, cooldown_daa, salt }
#[wasm_bindgen]
pub fn covenant_global_spending_limit(
    owner_pubkey_hex: &str,
    max_withdraw_sompi: u64,
    cooldown_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let prefix = network_to_prefix(network);

    // Random 8-byte salt so identical params produce a unique address each time.
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt)
        .map_err(|e| JsValue::from_str(&format!("RNG failed: {}", e)))?;

    let script =
        kspt::build_global_spending_limit_script(&pk, max_withdraw_sompi, cooldown_daa, &salt);
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "max_withdraw_sompi": max_withdraw_sompi,
        "cooldown_daa": cooldown_daa,
        "salt": hex::encode(salt),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a GLOBAL single-thread ALLOWANCE covenant P2SH address.
///
/// Per-spend cap applied to the whole thread balance (one tagged covenant_id
/// UTXO), withdrawn by the BENEFICIARY with a cooldown between withdrawals and
/// an optional vesting start date. The OWNER keeps a free reclaim/close path.
/// Genesis is created with `create_covenant_pskb_with_payload(tag_genesis=true)`
/// (full-spend, no change). Continued by `create_global_allowance_withdraw`
/// (beneficiary) and `create_global_allowance_topup` (owner).
///
/// Returns JSON: { address, redeem_script_hex, max_withdraw_sompi,
/// cooldown_daa, start_daa, salt, type }
#[wasm_bindgen]
pub fn covenant_global_allowance(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    max_withdraw_sompi: u64,
    cooldown_daa: u64,
    start_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let owner_pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let bene_pk = hex_to_pubkey32(beneficiary_pubkey_hex)?;
    let prefix = network_to_prefix(network);

    // Random 8-byte salt so identical params produce a unique address (and a
    // distinct covenant_id) each setup.
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt)
        .map_err(|e| JsValue::from_str(&format!("RNG failed: {}", e)))?;

    let script = kspt::build_global_allowance_script(
        &owner_pk,
        &bene_pk,
        max_withdraw_sompi,
        cooldown_daa,
        start_daa,
        &salt,
    );
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "max_withdraw_sompi": max_withdraw_sompi,
        "cooldown_daa": cooldown_daa,
        "start_daa": start_daa,
        "salt": hex::encode(salt),
        "type": "global_allowance",
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build an allowance covenant P2SH address.
/// Spending limit + relative time-lock (CSV). After each withdrawal,
/// min_sequence blocks must pass before the next one.
/// Returns JSON: { "address", "redeem_script_hex", "max_withdraw_sompi", "min_sequence" }
#[wasm_bindgen]
pub fn covenant_allowance(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    max_withdraw_sompi: u64,
    min_sequence: u64,
    start_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let bene_pk = hex_to_pubkey32(beneficiary_pubkey_hex)?;
    let prefix = network_to_prefix(network);
    let script =
        kspt::build_allowance_script(&pk, &bene_pk, max_withdraw_sompi, min_sequence, start_daa);
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "max_withdraw_sompi": max_withdraw_sompi,
        "min_sequence": min_sequence,
        "start_daa": start_daa,
        "type": "allowance",
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a treasury (approved destinations) covenant P2SH address.
/// Owner can spend but ONLY to whitelisted addresses baked into the script.
/// approved_addresses_json: JSON array of kaspa/kaspatest addresses (1–4)
/// Returns JSON: { "address", "redeem_script_hex", "approved_count" }
#[wasm_bindgen]
pub fn covenant_treasury(
    owner_pubkey_hex: &str,
    approved_addresses_json: &str,
    network: &str,
) -> Result<String, JsValue> {
    let pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let addrs: Vec<String> = serde_json::from_str(approved_addresses_json)
        .map_err(|e| JsValue::from_str(&format!("Bad address list: {}", e)))?;

    if addrs.is_empty() || addrs.len() > 4 {
        return Err(JsValue::from_str(
            "Treasury supports 1–4 approved destinations",
        ));
    }

    let mut spks = Vec::new();
    for addr in &addrs {
        let spk = address::address_to_script_pubkey(addr).map_err(|e| JsValue::from_str(&e))?;
        spks.push(spk);
    }

    let prefix = network_to_prefix(network);
    let script = kspt::build_treasury_script(&pk, &spks);
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "approved_count": addrs.len(),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build an atomic swap (HTLC) covenant P2SH address.
/// Counterparty claims by revealing preimage whose Blake2b hash matches;
/// owner refunds after timeout.
/// expected_hash_hex: 64-char hex of expected 32-byte hash
/// hash_algo: "blake2b" (Kaspa-native) or "sha256" (cross-chain Bitcoin-compatible)
/// Returns JSON: { "address", "redeem_script_hex", "locktime_daa", "hash_algo" }
#[wasm_bindgen]
pub fn covenant_atomic_swap(
    owner_pubkey_hex: &str,
    counterparty_pubkey_hex: &str,
    expected_hash_hex: &str,
    locktime_daa: u64,
    hash_algo: &str,
    network: &str,
) -> Result<String, JsValue> {
    let owner_pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let counter_pk = hex_to_pubkey32(counterparty_pubkey_hex)?;
    let hash_bytes = hex::decode(expected_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad expected hash hex: {}", e)))?;
    if hash_bytes.len() != 32 {
        return Err(JsValue::from_str("Expected hash must be 32 bytes"));
    }
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&hash_bytes);

    let algo = if hash_algo == "sha256" {
        "sha256"
    } else {
        "blake2b"
    };
    let prefix = network_to_prefix(network);
    let script = kspt::build_atomic_swap_script_with_algo(
        &owner_pk,
        &counter_pk,
        &expected_hash,
        locktime_daa,
        algo,
    );
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "locktime_daa": locktime_daa,
        "hash_algo": algo,
        "expected_hash": expected_hash_hex,
        "type": "atomic-swap",
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create an oracle-gated covenant address.
///
/// Two branches:
///   - Owner refund after locktime (IF)
///   - Beneficiary claims when oracle attests (ELSE, requires OpCheckSigFromStack)
///
/// Returns JSON: { address, redeem_script_hex, locktime_daa }
#[wasm_bindgen]
pub fn covenant_oracle(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    oracle_pubkey_hex: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let owner_pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let bene_pk = hex_to_pubkey32(beneficiary_pubkey_hex)?;
    let oracle_pk = hex_to_pubkey32(oracle_pubkey_hex)?;

    // Random 8-byte salt so identical params produce a unique address each time.
    // Returned as "salt" and baked into redeem_script_hex; recovery reuses the
    // stored full script and never re-mints the salt.
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt)
        .map_err(|e| JsValue::from_str(&format!("RNG failed: {}", e)))?;

    let prefix = network_to_prefix(network);
    let script =
        kspt::build_oracle_covenant_script(&owner_pk, &bene_pk, &oracle_pk, locktime_daa, &salt);
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "locktime_daa": locktime_daa,
        "oracle_pubkey_hex": oracle_pubkey_hex,
        "beneficiary_pubkey_hex": beneficiary_pubkey_hex,
        "owner_pubkey_hex": owner_pubkey_hex,
        "salt": hex::encode(salt),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create a PayJoin covenant address.
///
/// Two branches:
///   - Owner refund after locktime (IF)
///   - Beneficiary claims only in a multi-input TX with mixed addresses (ELSE)
///
/// Returns JSON: { address, redeem_script_hex, locktime_daa }
#[wasm_bindgen]
pub fn covenant_payjoin(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    locktime_daa: u64,
    min_inputs: u64,
    min_outputs: u64,
    network: &str,
) -> Result<String, JsValue> {
    let owner_pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let bene_pk = hex_to_pubkey32(beneficiary_pubkey_hex)?;

    let prefix = network_to_prefix(network);
    let script = kspt::build_payjoin_covenant_script(
        &owner_pk,
        &bene_pk,
        locktime_daa,
        min_inputs,
        min_outputs,
    );
    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "locktime_daa": locktime_daa,
        "min_inputs": min_inputs,
        "min_outputs": min_outputs,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create a PSKB for a PayJoin covenant claim (beneficiary spend).
///
/// The TX must include the caller's own UTXOs alongside the covenant UTXO
/// to satisfy the min_inputs and different-address requirements.
///
/// `extra_utxo_address` is the caller's own address — its UTXOs will be
/// added as additional inputs to meet the PayJoin requirements.
#[wasm_bindgen]
pub async fn create_covenant_payjoin_claim(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    extra_utxo_address: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    // Fetch covenant UTXOs
    let mut cov_utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if cov_utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    // Cap the covenant inputs per claim so the signed PSKB stays within
    // KasSigner's multi-frame QR budget (the same 5-input ceiling as UTXO
    // consolidation): MAX_COV_INPUTS covenant inputs + 1 mixing input = 5 total.
    // Largest-first so the most value moves per claim; a packed address is
    // drained by repeating the claim until no covenant UTXOs remain.
    const MAX_COV_INPUTS: usize = 4;
    if cov_utxos.len() > MAX_COV_INPUTS {
        cov_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));
        cov_utxos.truncate(MAX_COV_INPUTS);
    }

    // Fetch caller's own UTXOs for mixing
    let own_utxos = rpc::fetch_utxos_for_address(ws_url, extra_utxo_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if own_utxos.is_empty() {
        return Err(JsValue::from_str(
            "No UTXOs at your address for mixing — PayJoin requires your own inputs",
        ));
    }

    let cov_total: u64 = cov_utxos.iter().map(|u| u.amount).sum();
    // Auto-select the smallest UTXO for mixing (minimizes amount in flight)
    let own_utxo = own_utxos
        .iter()
        .min_by_key(|u| u.amount)
        .ok_or_else(|| JsValue::from_str("No UTXOs for mixing"))?;
    let own_amount = own_utxo.amount;
    let total = cov_total + own_amount;

    // Scale the fee to the actual input count: N covenant P2SH inputs (each
    // carries sig + redeem) plus the one P2PK mixing input. The node's compute
    // mass grows with input count, so a flat fee under-pays multi-UTXO claims
    // and is rejected as "fees under the required amount for compute mass".
    // Same per-input model and 1.15 margin as getCovFee; max() preserves any
    // higher fee the caller passed (e.g. a priority feerate).
    let n_inputs = cov_utxos.len() as u64 + 1;
    let compute_mass = 46 + n_inputs * (300 + 1000) + 43 + 340;
    let fee = std::cmp::max(fee, (compute_mass * 100 * 115) / 100);

    if total <= fee {
        return Err(JsValue::from_str("Balance too low to cover fee"));
    }

    // Covenant funds go to destination, Bob's mixing input returns to Bob
    // Fee is split proportionally (mostly from covenant side)
    let cov_fee = fee * 3 / 4; // covenant pays 75% of fee
    let own_fee = fee - cov_fee; // mixer pays 25%
    let send_amount = cov_total.saturating_sub(cov_fee);
    let change_amount = own_amount.saturating_sub(own_fee);
    if send_amount == 0 {
        return Err(JsValue::from_str("Covenant balance too low"));
    }
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let own_spk =
        address::address_to_script_pubkey(extra_utxo_address).map_err(|e| JsValue::from_str(&e))?;

    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let own_spk_hex = format!("0000{}", hex::encode(&own_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    let mut cov_inputs: Vec<serde_json::Value> = Vec::new();

    // Covenant UTXOs (P2SH, need beneficiary sig)
    for utxo in &cov_utxos {
        let input = serde_json::json!({
            "previousOutpoint": {
                "transactionId": utxo.tx_id,
                "index": utxo.index
            },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": {},
            "finalScriptSig": null,
            "minTime": 0
        });
        cov_inputs.push(input);
    }

    // Caller's own UTXO (standard P2PK, needs caller sig)
    let own_input = serde_json::json!({
        "previousOutpoint": {
            "transactionId": own_utxo.tx_id,
            "index": own_utxo.index
        },
        "sequence": 0,
        "sigOpCount": 1,
        "utxoEntry": {
            "amount": own_utxo.amount,
            "scriptPublicKey": own_spk_hex,
            "blockDaaScore": 0,
            "isCoinbase": false
        },
        "redeemScript": null,
        "partialSigs": {},
        "minimumSignatures": 1,
        "bip32Derivations": [],
        "proprietaries": {},
        "finalScriptSig": null,
        "minTime": 0
    });

    // Place the foreign mixing UTXO at input[1] so the redeem's
    // input[0].spk != input[1].spk gate sees a different SPK at index 1 even
    // when the covenant address holds several UTXOs. Covenant #1 at [0], own
    // P2PK at [1], remaining covenant UTXOs at [2..]; every covenant input
    // checks the same absolute indices 0 and 1, so one foreign input at [1]
    // satisfies all of them. cov_utxos is non-empty (checked above).
    let mut inputs: Vec<serde_json::Value> = Vec::with_capacity(cov_inputs.len() + 1);
    inputs.push(cov_inputs.remove(0));
    inputs.push(own_input);
    inputs.extend(cov_inputs);

    let mut outputs = vec![serde_json::json!({
        "amount": send_amount,
        "scriptPublicKey": dest_spk_hex,
        "bip32Derivations": [],
        "proprietaries": []
    })];

    // Bob's mixing input returns to Bob (minus small fee contribution)
    if change_amount > 0 {
        outputs.push(serde_json::json!({
            "amount": change_amount,
            "scriptPublicKey": own_spk_hex,
            "bip32Derivations": [],
            "proprietaries": []
        }));
    }

    let pskt = serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": null,
            "covenantBranch": "beneficiary",
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": inputs.len(),
            "outputCount": outputs.len(),
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
        &format!("[KasSee] PayJoin claim PSKB: {} inputs ({}cov + 1own), total {}, send {}, change {}, fee {}",
            inputs.len(), cov_utxos.len(), total, send_amount, change_amount, fee
        ).into(),
    );

    Ok(wire)
}

/// Create a PSKB for an oracle-gated claim (beneficiary spend with oracle attestation).
///
/// The oracle signature and message hash are stored in proprietaries so
/// finalization can include them in the sig_script.
///
/// Sig_script: <oracle_sig> <msg_hash> <bene_sig> OP_FALSE <redeem>
#[wasm_bindgen]
pub async fn create_covenant_oracle_claim(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    oracle_sig_hex: &str,
    msg_hash_hex: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    // Validate oracle sig (64 bytes Schnorr)
    let oracle_sig_bytes = hex::decode(oracle_sig_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad oracle sig hex: {}", e)))?;
    if oracle_sig_bytes.len() != 64 {
        return Err(JsValue::from_str(
            "Oracle signature must be 64 bytes (Schnorr)",
        ));
    }

    // Validate msg_hash (32 bytes)
    let msg_hash_bytes = hex::decode(msg_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad msg_hash hex: {}", e)))?;
    if msg_hash_bytes.len() != 32 {
        return Err(JsValue::from_str("Message hash must be 32 bytes"));
    }

    // Fetch UTXOs for the covenant address
    let utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;

    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str("Balance too low to cover fee"));
    }

    let send_amount = total - fee;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;

    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    let mut inputs = Vec::new();
    for utxo in &utxos {
        let input = serde_json::json!({
            "previousOutpoint": {
                "transactionId": utxo.tx_id,
                "index": utxo.index
            },
            "sequence": 0,
            "sigOpCount": 2,
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": {
                "oracleSig": oracle_sig_hex,
                "oracleMsgHash": msg_hash_hex
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
            "covenantBranch": "beneficiary",
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
            "[KasSee] Oracle-claim PSKB: {} inputs, total {}, send {}, fee {}, wire {} chars",
            utxos.len(),
            total,
            send_amount,
            fee,
            wire.len()
        )
        .into(),
    );

    Ok(wire)
}

/// Oracle attestation beacon for the SIMPLE oracle covenant (`build_oracle_covenant_script`),
/// distinct from the Model B (price) oracle. Spends the covenant UTXO(s) down Path 3
/// (the inner ELSE: `<oracle> CHECKSIGVERIFY` + self-return introspection) and returns
/// the funds to the SAME covenant address, carrying the oracle's off-chain attestation
/// in the TX payload so the beneficiary's watcher can read it and claim via Path 2.
///
/// MUST be tx_version=1: Path 3 enforces `INPUT_SPK == OUTPUT_SPK[0]` via covenant
/// introspection, which only executes on v1 transactions. (The original builder emitted
/// v0, which could not run that check at all — that, not any "singleton" rule, is why it
/// failed; this simple oracle has no covenant_id and no singleton enforcement.)
///
/// Payload layout (what the KasSee watcher parses): "ORAC" (0x4f524143)
/// || attestation_sig (64B Schnorr over `msg_hash`) || msg_hash (32B) || optional UTF-8 text.
/// `oracle_sig_hex`/`msg_hash_hex` are the attestation cargo; the beacon-TX signature is
/// produced by KasSigner and assembled into the Path-3 sig_script by the finalizer
/// (covenantBranch = "oracle-heartbeat").
#[wasm_bindgen]
pub async fn create_oracle_heartbeat(
    covenant_address: &str,
    redeem_script_hex: &str,
    oracle_sig_hex: &str,
    msg_hash_hex: &str,
    attest_text: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    // Attestation fields (cargo for the payload, NOT the beacon-TX signature).
    let oracle_sig_bytes = hex::decode(oracle_sig_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad oracle sig hex: {}", e)))?;
    if oracle_sig_bytes.len() != 64 {
        return Err(JsValue::from_str(
            "Oracle signature must be 64 bytes (Schnorr)",
        ));
    }
    let msg_hash_bytes = hex::decode(msg_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad msg_hash hex: {}", e)))?;
    if msg_hash_bytes.len() != 32 {
        return Err(JsValue::from_str("Message hash must be 32 bytes"));
    }

    // Fetch the covenant UTXO(s).
    let utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err(JsValue::from_str("Balance too low to cover fee"));
    }
    let send_amount = total - fee;

    // Self-return: input and output script-pubkeys must be byte-identical (incl. the
    // 0x0000 version prefix) so Path 3's INPUT_SPK == OUTPUT_SPK[0] check passes.
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let redeem_hex = hex::encode(&redeem_bytes);

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
                "scriptPublicKey": covenant_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": {},
            "finalScriptSig": null,
            "minTime": 0
        });
        inputs.push(input);
    }

    let outputs = vec![serde_json::json!({
        "amount": send_amount,
        "scriptPublicKey": covenant_spk_hex,
        "bip32Derivations": [],
        "proprietaries": []
    })];

    // "ORAC" || sig(64B) || hash(32B) || optional text — the exact layout the watcher reads.
    let mut payload_hex = String::from("4f524143");
    payload_hex.push_str(&hex::encode(&oracle_sig_bytes));
    payload_hex.push_str(&hex::encode(&msg_hash_bytes));
    if !attest_text.is_empty() {
        payload_hex.push_str(&hex::encode(attest_text.as_bytes()));
    }

    let pskt = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": null,
            "covenantBranch": "oracle-heartbeat",
            "txPayload": payload_hex,
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
        &format!("[KasSee] Oracle beacon PSKB (v1 self-return): {} inputs, total {}, send {}, fee {}, payload {}B, wire {} chars",
            utxos.len(), total, send_amount, fee, payload_hex.len() / 2, wire.len()
        ).into(),
    );

    Ok(wire)
}
