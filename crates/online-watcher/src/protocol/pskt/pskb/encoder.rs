use serde_json::{json, Value};

use crate::transaction_builder::model::{PlannedInput, UnsignedTransactionPlan};

use super::{json as json_model, PskbOutput};

pub fn encode_plan(plan: &UnsignedTransactionPlan) -> Result<String, String> {
    let outputs = plan
        .outputs
        .iter()
        .map(PskbOutput::from)
        .collect::<Vec<_>>();
    let payload = (!plan.payload.is_empty()).then_some(plan.payload.as_slice());
    encode_document(plan.tx_version, &plan.inputs, &outputs, payload, false)
}

pub fn encode_covenant(
    inputs: &[crate::account::utxo::UtxoEntry],
    outputs: &[PskbOutput],
) -> Result<String, String> {
    let planned_inputs = inputs
        .iter()
        .cloned()
        .map(crate::transaction_builder::model::PlannedInput::p2pk)
        .collect::<Vec<_>>();
    encode_document(1, &planned_inputs, outputs, None, true)
}

pub fn encode_covenant_with_payload(
    inputs: &[crate::account::utxo::UtxoEntry],
    outputs: &[PskbOutput],
    payload: &[u8],
) -> Result<String, String> {
    let planned_inputs = inputs
        .iter()
        .cloned()
        .map(crate::transaction_builder::model::PlannedInput::p2pk)
        .collect::<Vec<_>>();
    let tx_version = if outputs.iter().any(|output| output.covenant.is_some()) {
        1
    } else {
        0
    };
    encode_document(tx_version, &planned_inputs, outputs, Some(payload), true)
}

fn encode_document(
    tx_version: u16,
    inputs: &[PlannedInput],
    outputs: &[PskbOutput],
    payload: Option<&[u8]>,
    include_covenant_binding: bool,
) -> Result<String, String> {
    let input_count = u32::try_from(inputs.len())
        .map_err(|_| "PSKB input count exceeds KSPT v4 capacity".to_string())?;
    let output_count =
        u16::try_from(outputs.len()).map_err(|_| "PSKB output count exceeds 65535".to_string())?;
    let inputs_json = inputs
        .iter()
        .map(json_model::input_value)
        .collect::<Vec<_>>();
    let outputs_json = outputs
        .iter()
        .map(|output| json_model::output_value(output, include_covenant_binding))
        .collect::<Vec<_>>();

    let mut global = json!({
        "version": 0u8,
        "txVersion": tx_version,
        "fallbackLockTime": Value::Null,
        "inputsModifiable": false,
        "outputsModifiable": false,
        "inputCount": input_count,
        "outputCount": output_count,
        "xpubs": {},
        "id": Value::Null,
        "proprietaries": {}
    });
    if let Some(payload) = payload {
        global["txPayload"] = Value::String(hex::encode(payload));
    }

    encode_pskt_value(json!({
        "global": global,
        "inputs": inputs_json,
        "outputs": outputs_json
    }))
}

pub(crate) fn encode_pskt_value(mut pskt: Value) -> Result<String, String> {
    let global = pskt
        .get_mut("global")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "PSKT missing global object".to_string())?;
    global
        .entry("subnetworkId".to_string())
        .or_insert_with(|| Value::String("00".repeat(20)));
    crate::protocol::pskt::exact_json::canonicalize_pskt_exact_fields(&mut pskt)?;

    let document = Value::Array(vec![pskt]);
    let json_bytes =
        serde_json::to_vec(&document).map_err(|error| format!("serialize PSKB JSON: {}", error))?;
    let mut wire = Vec::with_capacity(4 + json_bytes.len() * 2);
    wire.extend_from_slice(kassigner_protocol::wire::pskt_envelope::PSKB_MAGIC);
    wire.extend_from_slice(hex::encode(json_bytes).as_bytes());
    Ok(hex::encode(wire))
}
