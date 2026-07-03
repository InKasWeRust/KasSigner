// KasSee Web — crowdfund + merkle-whitelist + commit-reveal WASM exports.
// Split out of lib.rs; behaviour unchanged. License: GPL-3.0.

//! wasm-bindgen exports for the ZK/hash covenants: crowdfunding,
//! merkle-whitelist, and commit-reveal.

use crate::{adaptor, address, kspt, rpc, zkproof};
use crate::{hex_to_32, hex_to_pubkey32, network_to_prefix};
use wasm_bindgen::prelude::*;

// ─── Crowdfunding Covenant (ZK-gated) ───

/// Sweep a single crowdfund contributor UTXO using a ZK proof.
///
/// No owner signature needed. The sig_script contains:
///   <public_input> <1> <proof> <vk> OP_FALSE <redeem>
///
/// The ZK proof proves that total contributions sum to S.
/// The on-chain script verifies the VK hash and the proof.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_crowdfund_sweep(
    contributor_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    proof_hex: &str,
    public_input_hex: &str,
    vk_hex: &str,
    commitment_sig_hex: &str,
    commitment_msg_hex: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;
    let proof_bytes =
        hex::decode(proof_hex).map_err(|e| JsValue::from_str(&format!("Bad proof hex: {}", e)))?;
    let public_input_bytes = hex::decode(public_input_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad public input hex: {}", e)))?;
    let vk_bytes =
        hex::decode(vk_hex).map_err(|e| JsValue::from_str(&format!("Bad VK hex: {}", e)))?;
    let commitment_sig = hex::decode(commitment_sig_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad commitment sig hex: {}", e)))?;
    let commitment_msg = hex::decode(commitment_msg_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad commitment msg hex: {}", e)))?;

    // Fetch UTXOs at contributor's covenant address
    let utxos = rpc::fetch_utxos_for_address(ws_url, contributor_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str(
            "No UTXOs at contributor covenant address",
        ));
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;

    // Build sig_script for dual-gate ELSE branch:
    // Stack (bottom to top): commitment_sig | msg_hash | public_input | 1 | proof | vk
    // ZK_PRECOMPILE consumes top 4, CHECKSIGFROMSTACK consumes remaining 2 + script-pushed pubkey
    let mut sig_script = Vec::new();

    // Helper: push data with length prefix
    fn ss_push(ss: &mut Vec<u8>, data: &[u8]) {
        let len = data.len();
        if len <= 75 {
            ss.push(len as u8);
        } else if len <= 255 {
            ss.push(0x4c); // OP_PUSHDATA1
            ss.push(len as u8);
        } else if len <= 65535 {
            ss.push(0x4d); // OP_PUSHDATA2
            ss.extend_from_slice(&(len as u16).to_le_bytes());
        } else {
            ss.push(0x4e); // OP_PUSHDATA4
            ss.extend_from_slice(&(len as u32).to_le_bytes());
        }
        ss.extend_from_slice(data);
    }

    // Push commitment sig and msg first (deepest on stack)
    ss_push(&mut sig_script, &commitment_sig);
    ss_push(&mut sig_script, &commitment_msg);
    // Then ZK items on top
    ss_push(&mut sig_script, &public_input_bytes);
    sig_script.push(0x51); // OP_1 (n_inputs = 1)
    ss_push(&mut sig_script, &proof_bytes);
    ss_push(&mut sig_script, &vk_bytes);
    sig_script.push(0x00); // OP_FALSE (select ELSE branch)
                           // Redeem script with OP_PUSHDATA2 prefix
    sig_script.push(0x4d);
    sig_script.extend_from_slice(&(redeem_bytes.len() as u16).to_le_bytes());
    sig_script.extend_from_slice(&redeem_bytes);

    web_sys::console::log_1(&format!(
        "[KasSee] Crowdfund sweep sig_script: {} bytes (proof={}, vk={}, input={}, sig={}, msg={}, redeem={})",
        sig_script.len(), proof_bytes.len(), vk_bytes.len(),
        public_input_bytes.len(), commitment_sig.len(), commitment_msg.len(), redeem_bytes.len()
    ).into());

    // Build consensus TX directly (no signing needed)
    let mut consensus_inputs = Vec::new();
    for utxo in &utxos {
        let txid_bytes: [u8; 32] = hex::decode(&utxo.tx_id)
            .map_err(|e| JsValue::from_str(&format!("Bad txid: {}", e)))?
            .try_into()
            .map_err(|_| JsValue::from_str("txid not 32 bytes"))?;
        consensus_inputs.push(rpc::ConsensusInput {
            prev_tx_id: txid_bytes,
            prev_index: utxo.index,
            sequence: 0,
            sig_script: sig_script.clone(),
            sig_op_count: kspt::ZK_CROWDFUND_SIG_OP_COUNT,
        });
    }

    // Compute fee from actual TX mass:
    // compute_mass = tx_bytes + sig_op_count * 1000 (per input) + spk_mass
    // Estimate tx_bytes: header(~46) + per_input(~45 + sig_script_len) + per_output(~35)
    let sig_script_len = sig_script.len() as u64;
    let n_inputs = utxos.len() as u64;
    let estimated_tx_bytes = 46 + n_inputs * (45 + sig_script_len + 4) + 35 + 10;
    let sig_op_mass = n_inputs * (kspt::ZK_CROWDFUND_SIG_OP_COUNT as u64) * 1000;
    let spk_mass = dest_spk.len() as u64 * 10; // rough SPK mass estimate
    let compute_mass = estimated_tx_bytes + sig_op_mass + spk_mass;
    // Fee = compute_mass * fee_rate (100 sompi/gram default) + 10% safety margin
    let computed_fee = std::cmp::max(fee, (compute_mass * 100 * 110) / 100);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Crowdfund sweep fee: computed_mass={}, computed_fee={}, input_fee={}",
            compute_mass, computed_fee, fee
        )
        .into(),
    );

    if total <= computed_fee {
        return Err(JsValue::from_str(&format!(
            "Balance {} too low to cover computed fee {}",
            total, computed_fee
        )));
    }

    let send_amount = total - computed_fee;

    let consensus_outputs = vec![rpc::ConsensusOutput {
        value: send_amount,
        spk_script: dest_spk,
        spk_version: 0,
        covenant: None,
    }];

    let subnetwork_id = [0u8; 20];
    let tx_version: u16 = 0;

    let result = rpc::submit_consensus_tx(
        ws_url,
        tx_version,
        &consensus_inputs,
        &consensus_outputs,
        0, // locktime
        &subnetwork_id,
        0,   // gas
        &[], // no payload
    )
    .await
    .map_err(|e| JsValue::from_str(&e))?;

    Ok(result)
}

///
/// contributor_pubkey_hex: 32-byte x-only pubkey (hex) — contributor's refund key
/// organizer_pubkey_hex: 32-byte x-only pubkey (hex) — organizer's sweep commitment key
/// vk_hex: verification key from crowdfund setup (hex)
/// locktime_daa: DAA score for contributor refund timeout
///
/// Returns JSON: { address, redeem_script_hex, vk_hex, locktime_daa }
#[wasm_bindgen]
pub fn covenant_crowdfund(
    contributor_pubkey_hex: &str,
    organizer_pubkey_hex: &str,
    vk_hex: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let contributor_pk = hex_to_32(contributor_pubkey_hex, "contributor pubkey")?;
    let organizer_pk = hex_to_32(organizer_pubkey_hex, "organizer pubkey")?;
    let vk_bytes =
        hex::decode(vk_hex).map_err(|e| JsValue::from_str(&format!("Bad VK hex: {}", e)))?;

    let script =
        kspt::crowdfund_redeem_script(&contributor_pk, &organizer_pk, locktime_daa, &vk_bytes);
    let prefix = if network.contains("test") {
        "kaspatest"
    } else {
        "kaspa"
    };
    let script_hash = kspt::blake2b_hash(&script);
    let address = crate::address::encode_p2sh_address(&script_hash, prefix);

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "vk_hex": vk_hex,
        "locktime_daa": locktime_daa,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Run Groth16 trusted setup for the crowdfunding circuit (8 contributors max).
/// Returns JSON: { pk_hex, vk_hex, vk_len }
#[wasm_bindgen]
pub fn zk_crowdfund_setup() -> Result<String, JsValue> {
    let (pk_bytes, vk_bytes) =
        zkproof::crowdfund_trusted_setup().map_err(|e| JsValue::from_str(&e))?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] ZK crowdfund setup: pk={} bytes, vk={} bytes",
            pk_bytes.len(),
            vk_bytes.len()
        )
        .into(),
    );

    let result = serde_json::json!({
        "pk_hex": hex::encode(&pk_bytes),
        "vk_hex": hex::encode(&vk_bytes),
        "vk_len": vk_bytes.len(),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate a crowdfunding ZK proof.
/// `pk_hex`: proving key from setup
/// `amounts_json`: JSON array of u64 amounts in sompi, e.g. "[100000000, 200000000]"
/// Returns JSON: { proof_hex, public_input_hex, total_sompi, proof_len, verified }
#[wasm_bindgen]
pub fn zk_crowdfund_prove(
    pk_hex: &str,
    vk_hex: &str,
    amounts_json: &str,
) -> Result<String, JsValue> {
    let pk_bytes =
        hex::decode(pk_hex).map_err(|e| JsValue::from_str(&format!("Bad PK hex: {}", e)))?;
    let vk_bytes =
        hex::decode(vk_hex).map_err(|e| JsValue::from_str(&format!("Bad VK hex: {}", e)))?;

    let amounts: Vec<u64> = serde_json::from_str(amounts_json)
        .map_err(|e| JsValue::from_str(&format!("Bad amounts JSON: {}", e)))?;

    let (proof_bytes, public_input) = zkproof::crowdfund_generate_proof(&pk_bytes, &amounts)
        .map_err(|e| JsValue::from_str(&e))?;

    let verified = zkproof::verify_proof(&vk_bytes, &proof_bytes, &public_input).unwrap_or(false);

    let total: u64 = amounts.iter().sum();

    web_sys::console::log_1(
        &format!("[KasSee] ZK crowdfund proof: {} contributors, total {} sompi, proof {} bytes, verified={}",
            amounts.len(), total, proof_bytes.len(), verified
        ).into(),
    );

    let result = serde_json::json!({
        "proof_hex": hex::encode(&proof_bytes),
        "public_input_hex": hex::encode(&public_input),
        "total_sompi": total,
        "proof_len": proof_bytes.len(),
        "verified": verified,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate an ephemeral BIP340 keypair and sign a message hash.
/// For testing dual-gate ZK sweep without KaSigner firmware support.
/// Returns JSON: { pubkey_hex (32-byte x-only), signature_hex (64-byte), msg_hex }
#[wasm_bindgen]
pub fn schnorr_sign_ephemeral(msg_hex: &str) -> Result<String, JsValue> {
    let msg_bytes: [u8; 32] = hex::decode(msg_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad msg hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("Message must be 32 bytes"))?;

    // Generate ephemeral secret key
    let mut sk_bytes = [0u8; 32];
    getrandom::getrandom(&mut sk_bytes)
        .map_err(|e| JsValue::from_str(&format!("RNG failed: {}", e)))?;

    use k256::elliptic_curve::ops::Reduce;
    let sk = <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(&sk_bytes.into());

    // Derive x-only pubkey
    let pk_point = k256::ProjectivePoint::GENERATOR * sk;
    let (xonly, _) = adaptor::point_to_xonly(&pk_point);

    // Sign
    let sig = adaptor::bip340_sign(&sk, &msg_bytes).map_err(|e| JsValue::from_str(&e))?;

    // Verify locally
    let valid =
        adaptor::bip340_verify(&xonly, &msg_bytes, &sig).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "pubkey_hex": hex::encode(xonly),
        "signature_hex": hex::encode(sig),
        "msg_hex": msg_hex,
        "verified": valid,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Derive x-only pubkey from a 32-byte secret key hex.
/// Returns 32-byte x-only pubkey hex.
#[wasm_bindgen]
pub fn schnorr_derive_pubkey(secret_key_hex: &str) -> Result<String, JsValue> {
    let sk_bytes: [u8; 32] = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad key hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("Key must be 32 bytes"))?;

    use k256::elliptic_curve::ops::Reduce;
    let sk = <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(&sk_bytes.into());
    let pk_point = k256::ProjectivePoint::GENERATOR * sk;
    let (xonly, _) = adaptor::point_to_xonly(&pk_point);
    Ok(hex::encode(xonly))
}

/// Sign a message hash with a known secret key (hex).
/// For testing with a persistent ephemeral key across multiple sweeps.
/// Returns JSON: { signature_hex (64-byte), verified }
#[wasm_bindgen]
pub fn schnorr_sign_with_key(secret_key_hex: &str, msg_hex: &str) -> Result<String, JsValue> {
    let sk_bytes: [u8; 32] = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad key hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("Key must be 32 bytes"))?;
    let msg_bytes: [u8; 32] = hex::decode(msg_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad msg hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("Message must be 32 bytes"))?;

    use k256::elliptic_curve::ops::Reduce;
    let sk = <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(&sk_bytes.into());

    let pk_point = k256::ProjectivePoint::GENERATOR * sk;
    let (xonly, _) = adaptor::point_to_xonly(&pk_point);

    let sig = adaptor::bip340_sign(&sk, &msg_bytes).map_err(|e| JsValue::from_str(&e))?;

    let valid =
        adaptor::bip340_verify(&xonly, &msg_bytes, &sig).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "signature_hex": hex::encode(sig),
        "verified": valid,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Commit-Reveal Covenant (MEV Resistance) ───

/// Compute BLAKE2B hash of a preimage (for creating the commitment).
/// Returns hex string of the 32-byte hash.
#[wasm_bindgen]
pub fn commit_hash(preimage_hex: &str) -> Result<String, JsValue> {
    let preimage = hex::decode(preimage_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad preimage hex: {}", e)))?;
    let hash = kspt::blake2b_hash(&preimage);
    Ok(hex::encode(hash))
}

// ─── Merkle Whitelist Vault (OP_CAT + OP_BLAKE2B) ───

/// Compute merkle root from a JSON array of SPK hex strings.
/// Returns hex of the 32-byte root.
#[wasm_bindgen]
pub fn merkle_root_from_addresses(addresses_json: &str, _network: &str) -> Result<String, JsValue> {
    let addresses: Vec<String> = serde_json::from_str(addresses_json)
        .map_err(|e| JsValue::from_str(&format!("Bad JSON: {}", e)))?;

    let leaves: Result<Vec<Vec<u8>>, String> = addresses
        .iter()
        .map(|addr| {
            let spk = address::address_to_script_pubkey(addr)?;
            // OP_TX_OUTPUT_SPK pushes version(2B LE) + script.
            // Leaves must match: prepend 0x0000 version.
            let mut full_spk = Vec::with_capacity(2 + spk.len());
            full_spk.extend_from_slice(&[0x00, 0x00]);
            full_spk.extend_from_slice(&spk);
            Ok(full_spk)
        })
        .collect();
    let leaves = leaves.map_err(|e| JsValue::from_str(&e))?;

    let depth = (leaves.len() as f64).log2().ceil() as u8;
    let root = kspt::compute_merkle_root(&leaves);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Merkle tree: {} addresses, depth {}, root {}",
            addresses.len(),
            depth,
            hex::encode(root)
        )
        .into(),
    );

    let result = serde_json::json!({
        "root": hex::encode(root),
        "depth": depth,
        "leaf_count": addresses.len(),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate a merkle proof for a specific address.
/// Returns JSON: { proof: [{sibling, direction}], leaf_spk_hex }
#[wasm_bindgen]
pub fn merkle_proof_for_address(
    addresses_json: &str,
    target_address: &str,
) -> Result<String, JsValue> {
    let addresses: Vec<String> = serde_json::from_str(addresses_json)
        .map_err(|e| JsValue::from_str(&format!("Bad JSON: {}", e)))?;

    let leaves: Result<Vec<Vec<u8>>, String> = addresses
        .iter()
        .map(|addr| {
            let spk = address::address_to_script_pubkey(addr)?;
            let mut full_spk = Vec::with_capacity(2 + spk.len());
            full_spk.extend_from_slice(&[0x00, 0x00]);
            full_spk.extend_from_slice(&spk);
            Ok(full_spk)
        })
        .collect();
    let leaves = leaves.map_err(|e| JsValue::from_str(&e))?;

    let target_spk_raw =
        address::address_to_script_pubkey(target_address).map_err(|e| JsValue::from_str(&e))?;
    let mut target_spk = Vec::with_capacity(2 + target_spk_raw.len());
    target_spk.extend_from_slice(&[0x00, 0x00]);
    target_spk.extend_from_slice(&target_spk_raw);

    let leaf_index = leaves
        .iter()
        .position(|l| *l == target_spk)
        .ok_or_else(|| JsValue::from_str("Address not found in whitelist"))?;

    let proof = kspt::generate_merkle_proof(&leaves, leaf_index);

    let proof_json: Vec<serde_json::Value> = proof
        .iter()
        .map(|(sibling, dir)| {
            serde_json::json!({
                "sibling": hex::encode(sibling),
                "direction": *dir,
            })
        })
        .collect();

    let result = serde_json::json!({
        "proof": proof_json,
        "leaf_spk_hex": hex::encode(&target_spk),
        "leaf_index": leaf_index,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create a merkle whitelist vault covenant P2SH address.
#[wasm_bindgen]
pub fn covenant_merkle_whitelist(
    owner_pubkey_hex: &str,
    merkle_root_hex: &str,
    depth: u8,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let owner_pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let root_bytes = hex::decode(merkle_root_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad root hex: {}", e)))?;
    if root_bytes.len() != 32 {
        return Err(JsValue::from_str("Merkle root must be 32 bytes"));
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_bytes);

    let prefix = network_to_prefix(network);
    let script = kspt::build_merkle_whitelist_script(&owner_pk, &root, depth, locktime_daa);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Merkle whitelist script: {} bytes, depth {}",
            script.len(),
            depth
        )
        .into(),
    );

    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let script_hex = hex::encode(&script);

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": script_hex,
        "merkle_root": merkle_root_hex,
        "depth": depth,
        "locktime_daa": locktime_daa,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create a PSKB for spending a merkle whitelist vault to a proven address.
#[wasm_bindgen]
pub async fn create_merkle_whitelist_spend(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    proof_json: &str,
    send_amount: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    let mut utxos = rpc::fetch_utxos_for_address(ws_url, covenant_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs at covenant address"));
    }

    // Cap covenant inputs so the signed tx fits KasSigner's multi-frame QR buffer
    // (same constraint as PayJoin). Each merkle input carries a large sig_script
    // (proof + two dest_spk pushes + redeem), so keep the cap tight. Largest-first;
    // the user repeats the spend to drain the rest.
    const MAX_COV_INPUTS: usize = 4;
    if utxos.len() > MAX_COV_INPUTS {
        utxos.sort_by(|a, b| b.amount.cmp(&a.amount));
        utxos.truncate(MAX_COV_INPUTS);
    }

    let total: u64 = utxos.iter().map(|u| u.amount).sum();

    // Fee must scale with mass: each merkle input carries a large sig_script
    // (redeem ~130+6*depth, two dest_spk pushes ~74, depth*34 proof, ~66 sig) plus
    // sig-op mass. A flat fee under-pays multi-input or deeper-tree spends and the
    // node rejects. Mirror PayJoin's mass recompute; depth = proof element count,
    // assume two outputs (dest + change) as the conservative case. The caller's fee
    // is treated as a floor (network minimum).
    let depth = serde_json::from_str::<Vec<serde_json::Value>>(proof_json)
        .map(|v| v.len())
        .unwrap_or(0);
    let per_input_mass = 270 + 40 * depth + 1000;
    let compute_mass = 46 + utxos.len() * per_input_mass + 43 + 2 * 340;
    let fee = fee.max(((compute_mass as u64) * 100 * 115) / 100);

    if send_amount == 0 {
        return Err(JsValue::from_str("Send amount must be > 0"));
    }
    if total <= fee {
        return Err(JsValue::from_str("Balance too low to cover fee"));
    }
    if send_amount + fee > total {
        return Err(JsValue::from_str(&format!(
            "Send {} + fee {} = {} exceeds balance {}",
            send_amount,
            fee,
            send_amount + fee,
            total
        )));
    }

    let change = total - send_amount - fee;

    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let covenant_spk =
        address::address_to_script_pubkey(covenant_address).map_err(|e| JsValue::from_str(&e))?;

    let redeem_hex = hex::encode(&redeem_bytes);
    let covenant_spk_hex = format!("0000{}", hex::encode(&covenant_spk));
    let dest_spk_hex_full = format!("0000{}", hex::encode(&dest_spk));

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
            "proprietaries": {
                "merkleProof": proof_json,
                "merkleDestSpk": dest_spk_hex_full
            },
            "finalScriptSig": null,
            "minTime": 0
        });
        inputs.push(input);
    }

    // Output[0] = destination (script checks TX_OUTPUT_SPK[0])
    let mut outputs = vec![serde_json::json!({
        "amount": send_amount,
        "scriptPublicKey": dest_spk_hex_full,
        "bip32Derivations": [],
        "proprietaries": []
    })];

    // Output[1] = change back to covenant (if any)
    if change > 0 {
        outputs.push(serde_json::json!({
            "amount": change,
            "scriptPublicKey": covenant_spk_hex,
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
        &format!(
            "[KasSee] Merkle whitelist spend: total {}, send {}, fee {}",
            total, send_amount, fee
        )
        .into(),
    );

    Ok(wire)
}

/// Create a commit-reveal covenant P2SH address.
///
/// owner_pubkey_hex: 32-byte x-only pubkey (hex)
/// committed_hash_hex: 32-byte BLAKE2B(preimage) commitment (hex)
/// locktime_daa: DAA score for refund timeout
///
/// Returns JSON: { address, redeem_script_hex, committed_hash, locktime_daa }
#[wasm_bindgen]
pub fn covenant_commit_reveal(
    owner_pubkey_hex: &str,
    committed_hash_hex: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    let owner_pk = hex_to_pubkey32(owner_pubkey_hex)?;
    let hash_bytes = hex::decode(committed_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad hash hex: {}", e)))?;
    if hash_bytes.len() != 32 {
        return Err(JsValue::from_str("Committed hash must be 32 bytes"));
    }
    let mut committed_hash = [0u8; 32];
    committed_hash.copy_from_slice(&hash_bytes);

    let prefix = network_to_prefix(network);
    let script = kspt::build_commit_reveal_script(&owner_pk, &committed_hash, locktime_daa);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Commit-reveal covenant script: {} bytes",
            script.len()
        )
        .into(),
    );

    let address =
        kspt::covenant_script_to_address(&script, prefix).map_err(|e| JsValue::from_str(&e))?;
    let script_hex = hex::encode(&script);

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": script_hex,
        "committed_hash": committed_hash_hex,
        "locktime_daa": locktime_daa,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create a PSKB for revealing and spending a commit-reveal covenant.
///
/// The preimage is embedded in PSKB proprietaries and assembled
/// into the sig_script at finalization.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_commit_reveal_spend(
    covenant_address: &str,
    dest_address: &str,
    redeem_script_hex: &str,
    part_a_hex: &str,
    part_b_hex: &str,
    payload_hex: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;

    let _part_a = hex::decode(part_a_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad part_a hex: {}", e)))?;
    let _part_b = hex::decode(part_b_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad part_b hex: {}", e)))?;
    let payload = hex::decode(payload_hex).unwrap_or_default();

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
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": {
                "commitPartA": part_a_hex,
                "commitPartB": part_b_hex
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

    let payload_hex_str = hex::encode(&payload);
    let pskt = serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": null,
            "covenantBranch": "beneficiary",
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": inputs.len(),
            "outputCount": 1,
            "txPayload": payload_hex_str,
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
            "[KasSee] Commit-reveal spend: total {}, send {}, fee {}, part_a {} part_b {} bytes",
            total,
            send_amount,
            fee,
            _part_a.len(),
            _part_b.len()
        )
        .into(),
    );

    Ok(wire)
}
