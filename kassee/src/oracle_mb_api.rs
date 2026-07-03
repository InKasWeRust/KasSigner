// KasSee Web — Oracle (Model B) covenant WASM exports.
// Split out of lib.rs; behaviour unchanged. License: GPL-3.0.

//! wasm-bindgen exports for the Oracle (Model B) covenant: genesis, heartbeat,
//! publish and consume flows.

use crate::network_to_prefix;
use crate::{address, bip32, kspt, rpc};
use wasm_bindgen::prelude::*;

// ============================================================================
// Oracle (Model B) -- genesis WASM wiring. APPEND into kassee/src/lib.rs, beside
// covenant_zk_bridge_risc0 (its direct twin). These two functions build the two
// genesis covenant redeems + P2SH addresses; fund each returned address with a
// tx_version = 1 send so its covenant_id binds, then pin the resulting cov_ids
// (you need them later for the consume's oracle_cov_id / hb_cov_id).
//
// They reuse the existing helpers already in lib.rs: network_to_prefix(),
// kspt::covenant_script_to_address(), and the kspt::build_oracle_mb_* builders
// that just passed their byte-assert tests. No new imports needed.
//
// Publish (proof-bearing roll that recreates the oracle at the new price) and
// consume (push_oracle_mb_read) are delivered separately, since they need the
// keyless build/broadcast path.
// ============================================================================

/// Oracle (Model B) genesis: the priced oracle UTXO. Commits image_id +
/// control_id + set_root + hashfn in the redeem (from the oracle-zkvm guest), at
/// an initial price / T. The covenant only advances on a fresh succinct
/// proof from the committed guest over the committed signer set.
///
/// Fund the returned `address` with a tx_version = 1 send to bind its
/// covenant_id. image_id/control_id/set_root come from the host run:
///   image_id   = 48701b6bf4c20e734a661d2092ba9b72fe33bec8f1c4a547dc5ddaee48fe7966
///   control_id = 7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e
///   set_root   = 47652e00d8cd5ec98481ee418b38ab70c471a66ee70a0564acfe879546c47778
///   hashfn     = 01
///
/// Returns JSON: { address, redeem_script_hex, genesis_price, genesis_t,
/// image_id, control_id, set_root, redeem_len, sig_op_count }.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn covenant_oracle_mb(
    genesis_price: u64,
    genesis_t: u64,
    image_id_hex: &str,
    control_id_hex: &str,
    set_root_hex: &str,
    hashfn_hex: &str,
    heartbeat_cov_id_hex: &str,
    network: &str,
) -> Result<String, JsValue> {
    let decode32 = |h: &str, name: &str| -> Result<[u8; 32], JsValue> {
        let b =
            hex::decode(h).map_err(|e| JsValue::from_str(&format!("Bad {} hex: {}", name, e)))?;
        b.try_into()
            .map_err(|_: Vec<u8>| JsValue::from_str(&format!("{} must be 32 bytes", name)))
    };

    let image_id = decode32(image_id_hex, "image_id")?;
    let control_id = decode32(control_id_hex, "control_id")?;
    let set_root = decode32(set_root_hex, "set_root")?;
    let hashfn_bytes = hex::decode(hashfn_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad hashfn hex: {}", e)))?;
    let hashfn = *hashfn_bytes
        .first()
        .ok_or_else(|| JsValue::from_str("hashfn must be 1 byte"))?;
    let heartbeat_cov_id = decode32(heartbeat_cov_id_hex, "heartbeat_cov_id")?;

    let prefix = network_to_prefix(network);
    let redeem = kspt::build_oracle_mb_genesis_redeem(
        genesis_price,
        genesis_t,
        &image_id,
        &control_id,
        &set_root,
        hashfn,
        &heartbeat_cov_id,
    );
    let address =
        kspt::covenant_script_to_address(&redeem, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&redeem),
        "genesis_price": genesis_price,
        "genesis_t": genesis_t,
        "image_id": image_id_hex,
        "control_id": control_id_hex,
        "set_root": set_root_hex,
        "redeem_len": redeem.len(),
        "sig_op_count": kspt::ORACLE_MB_SIG_OP_COUNT,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Oracle (Model B) heartbeat genesis: the keyless strict-singleton discovery
/// signpost. Carries no price and no T. It self-sends to a FIXED address and the
/// oracle ROLL branch requires exactly one heartbeat input, so every price roll
/// co-rolls this heartbeat in the same tx; its UTXO's txid is therefore always the
/// latest roll. A wallet finds the rotating oracle by querying this fixed address
/// (no indexer). Value rolls forward (out >= in, no skim).
///
/// Fund the returned `address` with a tx_version = 1 send to bind its covenant_id
/// H. Do this FIRST: H is then passed to covenant_oracle_mb so the oracle body
/// embeds it (the binding is one-directional, so the heartbeat must exist first).
///
/// Returns JSON: { address, redeem_script_hex, redeem_len, sig_op_count }.
#[wasm_bindgen]
pub fn covenant_oracle_mb_heartbeat(network: &str) -> Result<String, JsValue> {
    let prefix = network_to_prefix(network);
    let redeem = kspt::build_oracle_mb_heartbeat_script();
    let address =
        kspt::covenant_script_to_address(&redeem, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&redeem),
        "redeem_len": redeem.len(),
        "sig_op_count": kspt::ORACLE_MB_HEARTBEAT_SIG_OP_COUNT,
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ============================================================================
// Oracle (Model B) -- PUBLISH WASM wiring. APPEND into kassee/src/lib.rs.
//
// The publish is the proof-bearing ROLL: it spends the singleton oracle UTXO via
// the committed-guest RISC0 succinct proof and RECREATES the oracle at the new
// price baked into the new redeem. Structurally it is your rollup_state_advance
// (ZK + txVersion=1 + recreate) with the covenant_id continuation tag from
// create_global_spending_limit_withdraw (the oracle must keep its covenant_id so
// consumers can locate it by OpCovInputIdx). Both halves are paths you already
// run on TN10; only the finalize dispatch branch (risc0OracleMb, in the
// companion pskt.rs patch) is new, and it just delegates to the byte-tested
// kspt::build_oracle_mb_publish_sig_script.
//
// FEE MODEL (PoC/TN10): the fee is taken from the oracle value (single output =
// in - fee), matching the body's out >= in - max_fee. The conserve-value
// hardening (separate fee-payer input, out >= in) is the mainnet change, banked.
//
// PREREQUISITES: the oracle genesis UTXO exists and carries covenant_id G (bound
// by the tx_version=1 genesis funding). Read G from the oracle UTXO and pass it
// as covenant_id_hex. The 48-byte raw journal is the host's receipt journal:
//   price[0:8] LE | T (publish_time)[8:16] LE | set_root[16:48].
// ============================================================================

/// Oracle (Model B) PUBLISH: advance the oracle to the price proven in `journal`.
///
/// Spends the singleton oracle UTXO at `oracle_address` (revealing
/// `redeem_script_hex`, priced at the OLD price) and recreates the oracle UTXO at
/// the NEW price/T read from `journal`, tagged with the SAME covenant_id
/// (continuation). The keyless ROLL branch carries the RISC0 proof
/// (seal + claim + control_index + control_digests + journal); image_id /
/// control_id / set_root / hashfn are committed in the redeem and consumed by
/// OP_ZK_PRECOMPILE from there.
///
/// Returns the "PSKB" wire (hex) to hand to pskt_finalize_and_broadcast.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_oracle_mb_publish(
    wallet_json: &str,
    oracle_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    heartbeat_cov_id_hex: &str,
    image_id_hex: &str,
    control_id_hex: &str,
    set_root_hex: &str,
    hashfn_hex: &str,
    seal_hex: &str,
    claim_hex: &str,
    control_index_hex: &str,
    control_digests_hex: &str,
    journal_hex: &str,
    fee: u64,
    change_address: &str,
    network: &str,
    ws_url: &str,
    omit_heartbeat: bool,
) -> Result<String, JsValue> {
    // B (fee model): the oracle keeps its full bonded value; the network fee is
    // paid by a wallet input the keeper/user supplies, NOT drawn from the oracle.
    // So output[0].amount == oracle input amount (delta 0), which clears the body's
    // value-conservation check (output[0] >= input - ORACLE_MB_MAX_FEE_SOMPI)
    // without raising the 1M cap, and needs no oracle re-genesis. The real fee
    // rides the wallet-in/change delta, which the covenant never sees (the wallet
    // input + change are untagged, so OP_COV_INPUT_COUNT/OUTPUT_COUNT stay 1).
    let wallet: bip32::WalletData = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Bad wallet JSON: {}", e)))?;
    let change_spk =
        address::address_to_script_pubkey(change_address).map_err(|e| JsValue::from_str(&e))?;
    let change_spk_hex = format!("0000{}", hex::encode(&change_spk));

    let decode32 = |h: &str, name: &str| -> Result<[u8; 32], JsValue> {
        let b =
            hex::decode(h).map_err(|e| JsValue::from_str(&format!("Bad {} hex: {}", name, e)))?;
        b.try_into()
            .map_err(|_: Vec<u8>| JsValue::from_str(&format!("{} must be 32 bytes", name)))
    };

    let image_id = decode32(image_id_hex, "image_id")?;
    let control_id = decode32(control_id_hex, "control_id")?;
    let set_root = decode32(set_root_hex, "set_root")?;
    let hashfn_bytes = hex::decode(hashfn_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad hashfn hex: {}", e)))?;
    let hashfn = *hashfn_bytes
        .first()
        .ok_or_else(|| JsValue::from_str("hashfn must be 1 byte"))?;

    // Validate the covenant_id to 32 bytes; it rides through as hex in the binding.
    let _covenant_id = decode32(covenant_id_hex, "covenant_id")?;

    // The 48-byte journal carries the NEW price/T and pins set_root.
    let journal_bytes = hex::decode(journal_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad journal hex: {}", e)))?;
    if journal_bytes.len() != 48 {
        return Err(JsValue::from_str(&format!(
            "journal must be 48 bytes, got {}",
            journal_bytes.len()
        )));
    }
    if journal_bytes[16..48] != set_root[..] {
        return Err(JsValue::from_str(
            "journal set_root (bytes 16..48) does not match the committed set_root",
        ));
    }
    let new_price = u64::from_le_bytes(journal_bytes[0..8].try_into().unwrap());
    let new_t = u64::from_le_bytes(journal_bytes[8..16].try_into().unwrap());

    // Recreate at the new price: next redeem -> next P2SH SPK (the body will
    // recompute and check output[0].spk against exactly this).
    let prefix = network_to_prefix(network);
    let heartbeat_cov_id = decode32(heartbeat_cov_id_hex, "heartbeat_cov_id")?;
    let next_redeem = kspt::build_oracle_mb_redeem(
        new_price,
        new_t,
        &image_id,
        &control_id,
        &set_root,
        hashfn,
        &heartbeat_cov_id,
    );
    let next_address = kspt::covenant_script_to_address(&next_redeem, prefix)
        .map_err(|e| JsValue::from_str(&e))?;
    let next_spk =
        address::address_to_script_pubkey(&next_address).map_err(|e| JsValue::from_str(&e))?;

    // Spend the singleton oracle UTXO.
    let utxos = rpc::fetch_utxos_for_address(ws_url, oracle_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str(
            "No oracle UTXO at address; run genesis + fund (tx_version=1) first",
        ));
    }
    // Strict singleton: publish ONLY the thread UTXO carrying this covenant_id. The oracle
    // address is per-state unique, so normally exactly one UTXO sits here; but a stray or
    // foreign send must not be folded into the roll (the body enforces COV_INPUT_COUNT==1,
    // and an untagged input would also break the covenant_id binding). Match the one input
    // carrying covenant_id_hex, exactly like create_oracle_mb_heartbeat_roll.
    let utxos: Vec<_> = utxos
        .into_iter()
        .filter(|u| {
            u.covenant_id
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case(covenant_id_hex))
                .unwrap_or(false)
        })
        .collect();
    if utxos.is_empty() {
        return Err(JsValue::from_str(
            "No oracle UTXO carrying this covenant_id at the address (only untagged/foreign UTXOs found); pass the genesis covenant_id",
        ));
    }
    if utxos.len() > 1 {
        return Err(JsValue::from_str(
            "Multiple UTXOs carry this covenant_id; a strict singleton must have exactly one",
        ));
    }
    let total: u64 = utxos[0].amount;
    // The oracle recreates at FULL value; the fee is NOT taken from it.
    let send_amount = total;

    // Pick ONE plain (non-covenant) wallet UTXO to pay the network fee. ONE input
    // only: the ~222 KB seal already puts this tx near the 500K mass cap, so extra
    // inputs/signatures must stay minimal. Smallest UTXO that covers the fee wins,
    // which also minimizes change.
    const ORACLE_PUBLISH_CHANGE_DUST: u64 = 20_000;
    let mut wallet_utxos = rpc::fetch_all_utxos(ws_url, &wallet)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    wallet_utxos.retain(|u| u.covenant_id.is_none());
    wallet_utxos.sort_by(|a, b| a.amount.cmp(&b.amount));
    let fee_utxo = wallet_utxos
        .iter()
        .find(|u| u.amount >= fee)
        .cloned()
        .ok_or_else(|| {
            JsValue::from_str(&format!(
                "No single wallet UTXO covers the publish fee {} sompi. Consolidate \
                 the fee wallet first (one input only: the 222 KB seal leaves little \
                 mass headroom under the 500K cap).",
                fee
            ))
        })?;
    let change = fee_utxo.amount - fee;
    let emit_change = change >= ORACLE_PUBLISH_CHANGE_DUST;

    // Co-roll the heartbeat: the oracle ROLL branch requires exactly one input
    // carrying the heartbeat covenant_id H. The heartbeat redeem/address are
    // deterministic (no price, fixed body), so derive them here, fetch the single
    // heartbeat UTXO carrying H, and spend+recreate it in this same tx. This keeps
    // the heartbeat a fixed-address discovery signpost (its txid == this roll).
    let hb_redeem = kspt::build_oracle_mb_heartbeat_script();
    let hb_redeem_hex = hex::encode(&hb_redeem);
    let hb_address =
        kspt::covenant_script_to_address(&hb_redeem, prefix).map_err(|e| JsValue::from_str(&e))?;
    let hb_spk =
        address::address_to_script_pubkey(&hb_address).map_err(|e| JsValue::from_str(&e))?;
    let hb_spk_hex = format!("0000{}", hex::encode(&hb_spk));
    // omit_heartbeat (NEGATIVE TEST ONLY): build a solo oracle roll with NO heartbeat
    // input/output, so the body's ROLL gate OP_COV_INPUT_COUNT(H)==1 must reject it.
    // The normal path keeps omit_heartbeat=false and co-rolls the heartbeat.
    let (hb_amount, hb_tx_id, hb_index): (u64, String, u32) = if omit_heartbeat {
        (0, String::new(), 0)
    } else {
        let hb_utxos = rpc::fetch_utxos_for_address(ws_url, &hb_address)
            .await
            .map_err(|e| JsValue::from_str(&e))?;
        let hb_utxos: Vec<_> = hb_utxos
            .into_iter()
            .filter(|u| {
                u.covenant_id
                    .as_deref()
                    .map(|s| s.eq_ignore_ascii_case(heartbeat_cov_id_hex))
                    .unwrap_or(false)
            })
            .collect();
        if hb_utxos.is_empty() {
            return Err(JsValue::from_str(
                "No heartbeat UTXO carrying H at the heartbeat address; run heartbeat genesis + fund (tx_version=1) first",
            ));
        }
        if hb_utxos.len() > 1 {
            return Err(JsValue::from_str(
                "Multiple heartbeat UTXOs carry H; a strict singleton must have exactly one",
            ));
        }
        (
            hb_utxos[0].amount,
            hb_utxos[0].tx_id.clone(),
            hb_utxos[0].index,
        )
    };

    let oracle_spk =
        address::address_to_script_pubkey(oracle_address).map_err(|e| JsValue::from_str(&e))?;
    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;
    let redeem_hex_str = hex::encode(&redeem_bytes);
    let oracle_spk_hex = format!("0000{}", hex::encode(&oracle_spk));
    let next_spk_hex = format!("0000{}", hex::encode(&next_spk));

    // Input[0]: the oracle UTXO carrying the RISC0 proof; keyless ROLL branch.
    // risc0Fields carries claim/controlIndex/controlDigests/journal; the seal is
    // risc0Seal. image_id/control_id/hashfn are NOT here -- the precompile reads
    // them from the committed redeem. The oracle MUST be index 0: the body reads
    // its own value via OP_TX_INPUT_INDEX, and output[0]'s covenant_id binding is
    // authorized by input 0.
    let mut inputs: Vec<serde_json::Value> = utxos
        .iter()
        .map(|u| {
            serde_json::json!({
                "previousOutpoint": { "transactionId": u.tx_id, "index": u.index },
                "sequence": 0,
                "sigOpCount": kspt::ORACLE_MB_SIG_OP_COUNT,
                "utxoEntry": {
                    "amount": u.amount,
                    "scriptPublicKey": oracle_spk_hex,
                    "blockDaaScore": 0,
                    "isCoinbase": false
                },
                "redeemScript": redeem_hex_str,
                "partialSigs": {},
                "minimumSignatures": 0,
                "bip32Derivations": [],
                "proprietaries": {
                    "risc0Seal": seal_hex,
                    "risc0OracleMb": true,
                    "risc0Fields": {
                        "claim": claim_hex,
                        "controlIndex": control_index_hex,
                        "controlDigests": control_digests_hex,
                        "journal": journal_hex
                    }
                },
                "finalScriptSig": null,
                "minTime": 0
            })
        })
        .collect();

    // Input[1]: a plain wallet UTXO that pays the network fee. redeemScript=null
    // marks it P2PK, so the review/sign step signs it (this is field-for-field the
    // shape the covenant funding serializer emits); the keyless oracle input is
    // revealed at finalize. NOT covenant-tagged, so OP_COV_INPUT_COUNT stays 1.
    let fee_spk_hex = format!("0000{}", hex::encode(&fee_utxo.script_public_key));
    inputs.push(serde_json::json!({
        "utxoEntry": {
            "amount": fee_utxo.amount,
            "scriptPublicKey": fee_spk_hex,
            "blockDaaScore": fee_utxo.block_daa_score,
            "isCoinbase": false
        },
        "previousOutpoint": { "transactionId": fee_utxo.tx_id, "index": fee_utxo.index },
        "sequence": 0,
        "minTime": serde_json::Value::Null,
        "partialSigs": {},
        "sighashType": 1,
        "redeemScript": serde_json::Value::Null,
        "sigOpCount": 1,
        "bip32Derivations": {},
        "finalScriptSig": serde_json::Value::Null,
        "proprietaries": {}
    }));

    // Input[2]: the heartbeat UTXO; keyless roll (sig_script = revealed redeem
    // only). Located by H, NOT covenant-tagged with G, so the oracle's own
    // OP_COV_INPUT_COUNT stays 1 while its H-input gate sees exactly 1.
    let hb_input_index = inputs.len();
    if !omit_heartbeat {
        inputs.push(serde_json::json!({
            "previousOutpoint": { "transactionId": hb_tx_id, "index": hb_index },
            "sequence": 0,
            "sigOpCount": kspt::ORACLE_MB_HEARTBEAT_SIG_OP_COUNT,
            "utxoEntry": {
                "amount": hb_amount,
                "scriptPublicKey": hb_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": hb_redeem_hex,
            "partialSigs": {},
            "minimumSignatures": 0,
            "bip32Derivations": [],
            "proprietaries": { "oracleMbHeartbeat": true },
            "finalScriptSig": null,
            "minTime": 0
        }));
    }
    let input_count = inputs.len();

    // Output[0]: recreated oracle, FULL value, TAGGED with the same covenant_id
    // (continuation), authorized by the oracle input (index 0).
    // Output[1] (optional): wallet change. NOT covenant-tagged, so
    // OP_COV_OUTPUT_COUNT stays 1. Omitted when it would be dust (the remainder is
    // then absorbed into the fee).
    let mut outputs = vec![serde_json::json!({
        "amount": send_amount,
        "scriptPublicKey": next_spk_hex,
        "covenantBinding": { "authorizingInput": 0, "covenantId": covenant_id_hex },
        "bip32Derivations": [],
        "proprietaries": []
    })];
    // Output[1]: recreated heartbeat, FULL value (out == in satisfies the body's
    // out >= in), tagged H, authorized by the heartbeat input. Oracle stays
    // output[0] (the body checks output[0].spk); the heartbeat locates its own
    // continuation by H via OP_COV_OUTPUT_IDX, so this index is free.
    if !omit_heartbeat {
        outputs.push(serde_json::json!({
            "amount": hb_amount,
            "scriptPublicKey": hb_spk_hex,
            "covenantBinding": { "authorizingInput": hb_input_index, "covenantId": heartbeat_cov_id_hex },
            "bip32Derivations": [],
            "proprietaries": []
        }));
    }
    if emit_change {
        outputs.push(serde_json::json!({
            "amount": change,
            "scriptPublicKey": change_spk_hex,
            "covenantBinding": serde_json::Value::Null,
            "bip32Derivations": [],
            "proprietaries": []
        }));
    }
    let output_count = outputs.len();

    // tx_version=1 for the covenant-binding continuation output.
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
        &format!(
            "[KasSee] Oracle MB publish PSKB: oracle in/out {} (full value, fee paid by \
             wallet), wallet fee in {} (fee {}, change {}{}), new_price {}, new_T {}, \
             next_addr {}, inputs {}, outputs {}, wire {} chars",
            total,
            fee_utxo.amount,
            fee,
            change,
            if emit_change {
                ""
            } else {
                " folded into fee (dust)"
            },
            new_price,
            new_t,
            next_address,
            input_count,
            output_count,
            wire.len()
        )
        .into(),
    );

    Ok(wire)
}

// ============================================================================
// Oracle (Model B) -- HEARTBEAT ROLL WASM wiring. APPEND into kassee/src/lib.rs.
//
// Keyless self-recreate of the heartbeat singleton. The heartbeat carries no
// data; its only state is its block_daa_score (the consume reads it to bound
// staleness, D_hb - D_pub <= max_age). Rolling = spend + recreate at the SAME
// redeem/SPK, which mints a fresh creation DAA. Anyone may roll it (keyless), so
// a stalled price keeper cannot stall freshness. Run it on a timer (beat-bot) at
// roughly max_age/2; it is also a building block of the consume tx.
//
// Pairs with the pskt.rs `oracleMbHeartbeat` finalize branch (sig_script = JUST
// the revealed redeem, no selector, no signature).
// ============================================================================

/// Oracle (Model B) HEARTBEAT roll: refresh the heartbeat's DAA by recreating
/// the singleton at the same redeem/SPK, tagged with the same covenant_id
/// (continuation). Fee taken from the heartbeat value.
///
/// Returns the "PSKB" wire (hex) for pskt_finalize_and_broadcast.
#[wasm_bindgen]
pub async fn create_oracle_mb_heartbeat_roll(
    heartbeat_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    // Validate the covenant_id to 32 bytes; it rides through as hex in the binding.
    let cid_bytes = hex::decode(covenant_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad covenant_id hex: {}", e)))?;
    if cid_bytes.len() != 32 {
        return Err(JsValue::from_str("covenant_id must be 32 bytes"));
    }

    let redeem_bytes = hex::decode(redeem_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad redeem hex: {}", e)))?;
    let redeem_hex_str = hex::encode(&redeem_bytes);

    let utxos = rpc::fetch_utxos_for_address(ws_url, heartbeat_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if utxos.is_empty() {
        return Err(JsValue::from_str(
            "No heartbeat UTXO at address; run heartbeat genesis + fund (tx_version=1) first",
        ));
    }
    // Strict singleton: roll ONLY the thread UTXO carrying this covenant_id. The
    // heartbeat covenant self-sends, so untagged/foreign deposits to the same P2SH
    // address pile up. Summing all of them would put a non-thread UTXO at input[0],
    // and the node then validates output[0] as a fresh genesis off the wrong
    // outpoint (WrongGenesisCovenantId). Pick the one input carrying covenant_id_hex.
    let utxos: Vec<_> = utxos
        .into_iter()
        .filter(|u| {
            u.covenant_id
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case(covenant_id_hex))
                .unwrap_or(false)
        })
        .collect();
    if utxos.is_empty() {
        return Err(JsValue::from_str(
            "No heartbeat UTXO carrying this covenant_id at the address (only untagged/foreign UTXOs found); pass the genesis covenant_id",
        ));
    }
    if utxos.len() > 1 {
        return Err(JsValue::from_str(
            "Multiple UTXOs carry this covenant_id; a strict singleton must have exactly one",
        ));
    }
    let total: u64 = utxos[0].amount;
    if total <= fee {
        return Err(JsValue::from_str(&format!(
            "Heartbeat balance {} too low for fee {}",
            total, fee
        )));
    }
    let send_amount = total - fee;

    // The heartbeat redeem is constant, so the recreated SPK is the same address.
    let hb_spk =
        address::address_to_script_pubkey(heartbeat_address).map_err(|e| JsValue::from_str(&e))?;
    let hb_spk_hex = format!("0000{}", hex::encode(&hb_spk));

    // Input: the heartbeat UTXO; keyless roll (sig_script = revealed redeem only).
    let inputs: Vec<serde_json::Value> = utxos
        .iter()
        .map(|u| {
            serde_json::json!({
                "previousOutpoint": { "transactionId": u.tx_id, "index": u.index },
                "sequence": 0,
                "sigOpCount": kspt::ORACLE_MB_HEARTBEAT_SIG_OP_COUNT,
                "utxoEntry": {
                    "amount": u.amount,
                    "scriptPublicKey": hb_spk_hex,
                    "blockDaaScore": 0,
                    "isCoinbase": false
                },
                "redeemScript": redeem_hex_str,
                "partialSigs": {},
                "minimumSignatures": 0,
                "bip32Derivations": [],
                "proprietaries": { "oracleMbHeartbeat": true },
                "finalScriptSig": null,
                "minTime": 0
            })
        })
        .collect();
    let input_count = inputs.len();

    // Output[0]: recreated heartbeat (same SPK), tagged with the same covenant_id
    // (continuation), authorized by the heartbeat input (index 0).
    let outputs = vec![serde_json::json!({
        "amount": send_amount,
        "scriptPublicKey": hb_spk_hex,
        "covenantBinding": { "authorizingInput": 0, "covenantId": covenant_id_hex },
        "bip32Derivations": [],
        "proprietaries": []
    })];

    // tx_version=1 for the covenant-binding continuation output.
    let pskt = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": 0,
            "covenantBranch": serde_json::Value::Null,
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": input_count,
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
            "[KasSee] Oracle MB heartbeat roll PSKB: in {}, total {}, send {}, fee {}, wire {} chars",
            input_count, total, send_amount, fee, wire.len()
        )
        .into(),
    );

    Ok(wire)
}

// ============================================================================
// Oracle (Model B) -- CONSUME WASM wiring. APPEND into kassee/src/lib.rs.
//
// Validates the read end-to-end on TN10 with a standalone test consumer. The
// consume tx spends TWO inputs and writes TWO outputs:
//   inputs : [0] consumer (read-gated release, keyless)
//            [1] oracle   (PASSTHROUGH, keyless) -- located by covenant_id
//   outputs: [0] oracle recreate (tagged G_oracle, same SPK, same price/T)
//            [1] consumer -> dest (untagged; the consumer pays the whole fee)
//
// NO heartbeat: the heartbeat is the discovery signpost and co-rolls only on a
// publish; a read never touches it. The oracle PASSTHROUGH recreates its own
// continuation via OP_COV_OUTPUT_IDX (covenant-tagged, any index) with
// OP_COV_OUTPUT_COUNT == 1, so output order is free; push_oracle_mb_read locates
// the oracle input by covenant_id, so input order is free. This builder fixes
// [consumer, oracle] so the authorizingInput index is stable.
//
// VALUE: the oracle is recreated at full value (out == in, satisfies
// out >= in - max_fee); the consumer covers the entire tx fee. consumer_in must
// exceed `fee`.
//
// FRESHNESS: push_oracle_mb_read leaves [price, T] on the stack, both read from
// the oracle's committed redeem (price at [1..9], T = Pyth publish_time at
// [11..19]). T is welded to the price by the proof and made monotone on-chain by
// the roll (new_T >= old_T); a PASSTHROUGH preserves it, only a proof-bearing
// publish moves it. Whether a price is recent enough RIGHT NOW is the consumer's
// call, off-chain against the wall clock or on-chain against a CLTV bound, using
// the T this leaves on the stack. No daa gate, no heartbeat.
// ============================================================================

/// Derive the standalone TEST CONSUMER address for a specific oracle lineage.
/// Fund the returned address with a normal send (it carries no covenant_id of its
/// own; only the oracle needs a tag). 2-input read: consumer + oracle, no
/// heartbeat. Returns JSON: { address, redeem_script_hex, oracle_covenant_id,
///   redeem_len }.
#[wasm_bindgen]
pub fn covenant_oracle_mb_test_consumer(
    oracle_covenant_id_hex: &str,
    network: &str,
) -> Result<String, JsValue> {
    let decode32 = |h: &str, name: &str| -> Result<[u8; 32], JsValue> {
        let b =
            hex::decode(h).map_err(|e| JsValue::from_str(&format!("Bad {} hex: {}", name, e)))?;
        b.try_into()
            .map_err(|_: Vec<u8>| JsValue::from_str(&format!("{} must be 32 bytes", name)))
    };

    let oracle_cid = decode32(oracle_covenant_id_hex, "oracle covenant_id")?;

    let prefix = network_to_prefix(network);
    let redeem = kspt::build_oracle_mb_test_consumer_script(&oracle_cid);
    let address =
        kspt::covenant_script_to_address(&redeem, prefix).map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&redeem),
        "oracle_covenant_id": oracle_covenant_id_hex,
        "redeem_len": redeem.len(),
    });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Oracle (Model B) CONSUME: read price + T from the genuine oracle lineage,
/// recreate the oracle singleton (passthrough), and release the consumer to
/// `dest_address`. 2-input (consumer + oracle), no heartbeat. Returns the "PSKB"
/// wire (hex) for pskt_finalize_and_broadcast.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn create_oracle_mb_consume(
    consumer_address: &str,
    consumer_redeem_hex: &str,
    oracle_address: &str,
    oracle_redeem_hex: &str,
    oracle_covenant_id_hex: &str,
    dest_address: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, JsValue> {
    let check32 = |h: &str, name: &str| -> Result<(), JsValue> {
        let b =
            hex::decode(h).map_err(|e| JsValue::from_str(&format!("Bad {} hex: {}", name, e)))?;
        if b.len() != 32 {
            return Err(JsValue::from_str(&format!("{} must be 32 bytes", name)));
        }
        Ok(())
    };
    check32(oracle_covenant_id_hex, "oracle covenant_id")?;

    let consumer_redeem = hex::decode(consumer_redeem_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad consumer redeem hex: {}", e)))?;
    let oracle_redeem = hex::decode(oracle_redeem_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad oracle redeem hex: {}", e)))?;

    // Fetch the two inputs. The oracle is a strict singleton (its body enforces
    // COV_INPUT_COUNT == 1); take its single UTXO by covenant_id.
    let consumer_utxos = rpc::fetch_utxos_for_address(ws_url, consumer_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if consumer_utxos.is_empty() {
        return Err(JsValue::from_str(
            "No consumer UTXO; fund the consumer address first",
        ));
    }
    let oracle_utxos = rpc::fetch_utxos_for_address(ws_url, oracle_address)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    if oracle_utxos.is_empty() {
        return Err(JsValue::from_str("No oracle UTXO at address"));
    }

    // Strict singletons: locate each thread UTXO by its covenant_id, never by [0].
    // Untagged/foreign deposits can sit at these self-sending P2SH addresses; taking
    // [0] could grab a non-thread UTXO, and the covenant read/continuation would fail.
    let consumer = &consumer_utxos[0];
    let oracle = oracle_utxos
        .iter()
        .find(|u| {
            u.covenant_id
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case(oracle_covenant_id_hex))
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            JsValue::from_str("No oracle UTXO carrying the oracle covenant_id at oracle_address")
        })?;

    if consumer.amount <= fee {
        return Err(JsValue::from_str(&format!(
            "Consumer balance {} too low to cover the whole tx fee {}",
            consumer.amount, fee
        )));
    }
    let consumer_out = consumer.amount - fee;

    // SPKs (PSKB prefixes the version as "0000"). The oracle continuation
    // recreates the SAME SPK (passthrough), so reuse its own input address SPK;
    // the consumer is released to dest.
    let consumer_spk =
        address::address_to_script_pubkey(consumer_address).map_err(|e| JsValue::from_str(&e))?;
    let oracle_spk =
        address::address_to_script_pubkey(oracle_address).map_err(|e| JsValue::from_str(&e))?;
    let dest_spk =
        address::address_to_script_pubkey(dest_address).map_err(|e| JsValue::from_str(&e))?;
    let consumer_spk_hex = format!("0000{}", hex::encode(&consumer_spk));
    let oracle_spk_hex = format!("0000{}", hex::encode(&oracle_spk));
    let dest_spk_hex = format!("0000{}", hex::encode(&dest_spk));

    // Inputs, fixed order [consumer(0), oracle(1)].
    // - consumer: keyless read-gated release (sig_script = bare redeem). The
    //   read has no sig/ZK op, sigOpCount = 1.
    // - oracle: PASSTHROUGH. The redeem contains OP_ZK_PRECOMPILE in its unused
    //   ROLL branch; a static sig-op count of that redeem is high, so declare
    //   the ZK count to stay safe under either static or dynamic accounting.
    let inputs = vec![
        serde_json::json!({
            "previousOutpoint": { "transactionId": consumer.tx_id, "index": consumer.index },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": consumer.amount,
                "scriptPublicKey": consumer_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": hex::encode(&consumer_redeem),
            "partialSigs": {},
            "minimumSignatures": 0,
            "bip32Derivations": [],
            "proprietaries": { "oracleMbConsumer": true },
            "finalScriptSig": null,
            "minTime": 0
        }),
        serde_json::json!({
            "previousOutpoint": { "transactionId": oracle.tx_id, "index": oracle.index },
            "sequence": 0,
            "sigOpCount": kspt::ORACLE_MB_SIG_OP_COUNT,
            "utxoEntry": {
                "amount": oracle.amount,
                "scriptPublicKey": oracle_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": hex::encode(&oracle_redeem),
            "partialSigs": {},
            "minimumSignatures": 0,
            "bip32Derivations": [],
            "proprietaries": { "oracleMbPassthrough": true },
            "finalScriptSig": null,
            "minTime": 0
        }),
    ];

    // Outputs. Oracle recreated at full value, tagged with its covenant_id
    // (authorized by input 1). Consumer to dest.
    let outputs = vec![
        serde_json::json!({
            "amount": oracle.amount,
            "scriptPublicKey": oracle_spk_hex,
            "covenantBinding": { "authorizingInput": 1, "covenantId": oracle_covenant_id_hex },
            "bip32Derivations": [],
            "proprietaries": []
        }),
        serde_json::json!({
            "amount": consumer_out,
            "scriptPublicKey": dest_spk_hex,
            "covenantBinding": serde_json::Value::Null,
            "bip32Derivations": [],
            "proprietaries": []
        }),
    ];

    // tx_version=1 for the covenant-binding continuation outputs.
    let pskt = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": 0,
            "covenantBranch": serde_json::Value::Null,
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": 2,
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
        &format!(
            "[KasSee] Oracle MB consume PSKB: consumer {} (-> dest {} fee {}), \
             oracle {} (recreate), wire {} chars",
            consumer.amount,
            consumer_out,
            fee,
            oracle.amount,
            wire.len()
        )
        .into(),
    );

    Ok(wire)
}
