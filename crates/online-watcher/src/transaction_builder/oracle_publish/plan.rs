use super::context::PublishContext;

pub(crate) struct PublishPlanResult {
    pub(crate) wire: String,
    pub(crate) input_count: usize,
    pub(crate) output_count: usize,
}

pub(crate) fn build(context: &PublishContext) -> Result<PublishPlanResult, String> {
    let oracle_spk_hex = format!("0000{}", hex::encode(&context.oracle_script_public_key));
    let next_spk_hex = format!("0000{}", hex::encode(&context.next_script_public_key));
    let redeem_hex = hex::encode(&context.oracle_redeem_script);

    let mut inputs = vec![serde_json::json!({
        "previousOutpoint": {
            "transactionId": context.oracle_utxo.tx_id.clone(),
            "index": context.oracle_utxo.index
        },
        "sequence": 0,
        "sigOpCount": crate::contracts::oracle::script::ORACLE_MB_SIG_OP_COUNT,
        "utxoEntry": {
            "amount": context.oracle_utxo.amount,
            "scriptPublicKey": oracle_spk_hex,
            "blockDaaScore": 0,
            "isCoinbase": false
        },
        "redeemScript": redeem_hex,
        "partialSigs": {},
        "minimumSignatures": 0,
        "bip32Derivations": [],
        "proprietaries": {
            "risc0Seal": context.request.seal_hex.clone(),
            "risc0OracleMb": true,
            "risc0Fields": {
                "claim": context.request.claim_hex.clone(),
                "controlIndex": context.request.control_index_hex.clone(),
                "controlDigests": context.request.control_digests_hex.clone(),
                "journal": context.request.journal_hex.clone()
            }
        },
        "finalScriptSig": serde_json::Value::Null,
        "minTime": 0
    })];

    let fee_spk_hex = format!("0000{}", hex::encode(&context.fee_utxo.script_public_key));
    inputs.push(serde_json::json!({
        "utxoEntry": {
            "amount": context.fee_utxo.amount,
            "scriptPublicKey": fee_spk_hex,
            "blockDaaScore": context.fee_utxo.block_daa_score,
            "isCoinbase": false
        },
        "previousOutpoint": {
            "transactionId": context.fee_utxo.tx_id.clone(),
            "index": context.fee_utxo.index
        },
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

    let heartbeat_input_index = inputs.len();
    if let Some(heartbeat) = &context.heartbeat {
        let heartbeat_spk_hex = format!("0000{}", hex::encode(&heartbeat.script_public_key));
        inputs.push(serde_json::json!({
            "previousOutpoint": {
                "transactionId": heartbeat.utxo.tx_id.clone(),
                "index": heartbeat.utxo.index
            },
            "sequence": 0,
            "sigOpCount": crate::contracts::oracle::script::ORACLE_MB_HEARTBEAT_SIG_OP_COUNT,
            "utxoEntry": {
                "amount": heartbeat.utxo.amount,
                "scriptPublicKey": heartbeat_spk_hex,
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": hex::encode(&heartbeat.redeem_script),
            "partialSigs": {},
            "minimumSignatures": 0,
            "bip32Derivations": [],
            "proprietaries": { "oracleMbHeartbeat": true },
            "finalScriptSig": serde_json::Value::Null,
            "minTime": 0
        }));
    }

    let mut outputs = vec![serde_json::json!({
        "amount": context.oracle_utxo.amount,
        "scriptPublicKey": next_spk_hex,
        "covenantBinding": {
            "authorizingInput": 0,
            "covenantId": context.request.covenant_id_hex.clone()
        },
        "bip32Derivations": [],
        "proprietaries": []
    })];

    if let Some(heartbeat) = &context.heartbeat {
        outputs.push(serde_json::json!({
            "amount": heartbeat.utxo.amount,
            "scriptPublicKey": format!("0000{}", hex::encode(&heartbeat.script_public_key)),
            "covenantBinding": {
                "authorizingInput": heartbeat_input_index,
                "covenantId": context.request.heartbeat_cov_id_hex.clone()
            },
            "bip32Derivations": [],
            "proprietaries": []
        }));
    }

    if context.emit_change {
        outputs.push(serde_json::json!({
            "amount": context.change,
            "scriptPublicKey": format!("0000{}", hex::encode(&context.request.change_spk)),
            "covenantBinding": serde_json::Value::Null,
            "bip32Derivations": [],
            "proprietaries": []
        }));
    }

    let input_count = inputs.len();
    let output_count = outputs.len();
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
    let wire = crate::transaction_builder::pskb::encode_pskt_value(pskt)?;

    Ok(PublishPlanResult {
        wire,
        input_count,
        output_count,
    })
}
