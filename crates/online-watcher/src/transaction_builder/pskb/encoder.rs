use serde_json::{json, Map, Value};

use super::{PskbInputPlan, PskbOutputPlan, PskbPlan};

fn versioned_script_hex(script_public_key: &[u8]) -> String {
    format!("0000{}", hex::encode(script_public_key))
}

fn input_value(input: &PskbInputPlan) -> Value {
    json!({
        "previousOutpoint": {
            "transactionId": input.utxo.tx_id.clone(),
            "index": input.utxo.index
        },
        "sequence": input.sequence,
        "sigOpCount": input.sig_op_count,
        "utxoEntry": {
            "amount": input.utxo.amount,
            "scriptPublicKey": versioned_script_hex(&input.source_script_public_key),
            "blockDaaScore": input.block_daa_score,
            "isCoinbase": false
        },
        "redeemScript": input.redeem_script.as_ref().map(hex::encode),
        "partialSigs": {},
        "minimumSignatures": input.minimum_signatures,
        "bip32Derivations": [],
        "proprietaries": input.proprietaries.clone(),
        "finalScriptSig": Value::Null,
        "minTime": input.min_time.clone()
    })
}

fn output_value(output: &PskbOutputPlan) -> Value {
    let mut object = Map::new();
    object.insert("amount".to_string(), Value::from(output.amount));
    object.insert(
        "scriptPublicKey".to_string(),
        Value::String(versioned_script_hex(&output.script_public_key)),
    );
    if let Some(binding) = &output.covenant_binding_field {
        object.insert("covenantBinding".to_string(), binding.clone());
    }
    object.insert("bip32Derivations".to_string(), Value::Array(Vec::new()));
    object.insert("proprietaries".to_string(), output.proprietaries.clone());
    Value::Object(object)
}

/// Encode a typed plan using the established browser PSKB envelope:
/// hex(`PSKB` + lowercase-hex(JSON-array)).
pub fn encode_wire(plan: &PskbPlan) -> Result<String, String> {
    let inputs = plan.inputs.iter().map(input_value).collect::<Vec<_>>();
    let outputs = plan.outputs.iter().map(output_value).collect::<Vec<_>>();

    let mut global = Map::new();
    global.insert("txVersion".to_string(), Value::from(plan.global.tx_version));
    global.insert(
        "fallbackLockTime".to_string(),
        plan.global.fallback_lock_time.clone(),
    );
    if let Some(branch) = &plan.global.covenant_branch {
        global.insert("covenantBranch".to_string(), branch.clone());
    }
    global.insert("inputsModifiableFlag".to_string(), Value::Bool(false));
    global.insert("outputsModifiableFlag".to_string(), Value::Bool(false));
    global.insert("inputCount".to_string(), Value::from(inputs.len()));
    global.insert("outputCount".to_string(), Value::from(outputs.len()));
    global.insert("bip32Derivations".to_string(), Value::Array(Vec::new()));
    global.insert(
        "proprietaries".to_string(),
        plan.global.proprietaries.clone(),
    );
    if let Some(payload) = &plan.global.transaction_payload {
        global.insert("txPayload".to_string(), Value::String(hex::encode(payload)));
    }

    encode_pskt_value(json!({
        "global": Value::Object(global),
        "inputs": inputs,
        "outputs": outputs
    }))
}

/// Encode a preassembled PSKT object in the established PSKB wire envelope.
/// Specialized planners can use this when their metadata is already assembled.
pub fn encode_pskt_value(pskt: Value) -> Result<String, String> {
    crate::protocol::pskt::pskb::encode_pskt_value(pskt)
}
