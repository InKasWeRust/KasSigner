use serde_json::{Map, Value};

use super::{relay_fields::find_pubkey_position, wire};
use crate::{wire::kspt as kspt_wire, Network};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Signature {
    pub(super) position: u8,
    pub(super) sighash: u8,
    pub(super) bytes: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Input {
    pub(super) tx_id: [u8; 32],
    pub(super) index: u32,
    pub(super) amount: u64,
    pub(super) sequence: u64,
    pub(super) sig_op_count: u8,
    pub(super) script_version: u16,
    pub(super) script: Vec<u8>,
    pub(super) signatures: Vec<Signature>,
    pub(super) redeem: Vec<u8>,
    pub(super) derivation: Option<(u8, u32)>,
    pub(super) ms45: Option<(u32, u32, u32)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Output {
    pub(super) amount: u64,
    pub(super) script_version: u16,
    pub(super) script: Vec<u8>,
    pub(super) derivation: Option<(u8, u32)>,
    pub(super) ms45: Option<(u32, u32, u32)>,
    pub(super) covenant: Option<(u16, [u8; 32])>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Transaction {
    pub(super) flags: u8,
    pub(super) version: u16,
    pub(super) locktime: u64,
    pub(super) subnetwork: [u8; 20],
    pub(super) gas: u64,
    pub(super) payload: Vec<u8>,
    pub(super) network: u8,
    pub(super) inputs: Vec<Input>,
    pub(super) outputs: Vec<Output>,
    pub(super) stealth: Option<[u8; 32]>,
}

impl kspt_wire::EncodeSource for Transaction {
    fn global(&self) -> kspt_wire::Global<'_> {
        kspt_wire::Global {
            flags: self.flags,
            version: self.version,
            input_count: self.inputs.len() as u32,
            output_count: self.outputs.len() as u8,
            locktime: self.locktime,
            subnetwork_id: self.subnetwork,
            gas: self.gas,
            payload: &self.payload,
        }
    }

    fn input(&self, index: usize) -> kspt_wire::Input<'_> {
        let input = &self.inputs[index];
        kspt_wire::Input {
            previous_tx_id: input.tx_id,
            previous_index: input.index,
            amount: input.amount,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
            script_version: input.script_version,
            script: &input.script,
        }
    }

    fn signature_count(&self, input: usize) -> usize {
        self.inputs[input].signatures.len()
    }
    fn signature(&self, input: usize, slot: usize) -> kspt_wire::Signature {
        let signature = &self.inputs[input].signatures[slot];
        kspt_wire::Signature {
            position: signature.position,
            sighash: signature.sighash,
            bytes: signature.bytes,
        }
    }
    fn redeem(&self, input: usize) -> &[u8] {
        &self.inputs[input].redeem
    }
    fn output(&self, index: usize) -> kspt_wire::Output<'_> {
        let output = &self.outputs[index];
        kspt_wire::Output {
            amount: output.amount,
            script_version: output.script_version,
            script: &output.script,
        }
    }
    fn network(&self) -> u8 {
        self.network
    }
    fn stealth(&self) -> Option<[u8; 32]> {
        self.stealth
    }
    fn input_derivation(&self, index: usize) -> Option<kspt_wire::Derivation> {
        self.inputs[index]
            .derivation
            .map(|(branch, index)| kspt_wire::Derivation { branch, index })
    }
    fn output_derivation(&self, index: usize) -> Option<kspt_wire::Derivation> {
        self.outputs[index]
            .derivation
            .map(|(branch, index)| kspt_wire::Derivation { branch, index })
    }
    fn input_ms45(&self, index: usize) -> Option<kspt_wire::Ms45Derivation> {
        self.inputs[index]
            .ms45
            .map(|(cosigner, chain, index)| kspt_wire::Ms45Derivation {
                cosigner,
                chain,
                index,
            })
    }
    fn output_ms45(&self, index: usize) -> Option<kspt_wire::Ms45Derivation> {
        self.outputs[index]
            .ms45
            .map(|(cosigner, chain, index)| kspt_wire::Ms45Derivation {
                cosigner,
                chain,
                index,
            })
    }
    fn covenant(&self, index: usize) -> Option<kspt_wire::Covenant> {
        self.outputs[index]
            .covenant
            .map(|(authorizing_input, id)| kspt_wire::Covenant {
                authorizing_input,
                id,
            })
    }
}

pub(crate) fn validate_and_merge(
    original_pskt_hex: &str,
    signed_kspt: &[u8],
    network: Network,
) -> Result<String, String> {
    let unsigned = super::relay::encode_pskt(original_pskt_hex, network)?;
    let expected = parse(&unsigned)?;
    let signed = parse(signed_kspt)?;
    validate_same_transaction(&expected, &signed, network)?;
    merge_signatures(original_pskt_hex, &signed)
}

fn validate_same_transaction(
    expected: &Transaction,
    signed: &Transaction,
    network: Network,
) -> Result<(), String> {
    if signed.network != network.kspt_code() || expected.network != network.kspt_code() {
        return Err("signed KSPT network does not match requested network".to_string());
    }
    let mut expected_body = expected.clone();
    let mut signed_body = signed.clone();
    expected_body.flags = 0;
    signed_body.flags = 0;
    for input in &mut expected_body.inputs {
        input.signatures.clear();
    }
    for input in &mut signed_body.inputs {
        input.signatures.clear();
    }
    if expected_body != signed_body {
        return Err("signed KSPT transaction body does not match the wallet PSKT".to_string());
    }
    if signed
        .inputs
        .iter()
        .all(|input| input.signatures.is_empty())
    {
        return Err("signed KSPT contains no signatures".to_string());
    }
    Ok(())
}

fn merge_signatures(original_pskt_hex: &str, transaction: &Transaction) -> Result<String, String> {
    let (format, mut root) = wire::decode(original_pskt_hex)?;
    let document = wire::document_mut(&mut root, format)?
        .as_object_mut()
        .ok_or_else(|| "PSKT not object".to_string())?;
    let inputs = document
        .get_mut("inputs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "missing inputs".to_string())?;
    if inputs.len() != transaction.inputs.len() {
        return Err("signed KSPT input count does not match PSKT".to_string());
    }
    for (position, signed_input) in transaction.inputs.iter().enumerate() {
        merge_input(&mut inputs[position], signed_input, position)?;
    }
    wire::encode(format, &root)
}

fn merge_input(value: &mut Value, signed: &Input, index: usize) -> Result<(), String> {
    if signed.signatures.is_empty() {
        return Ok(());
    }
    let input = value
        .as_object_mut()
        .ok_or_else(|| format!("input[{index}] not object"))?;
    let redeem_hex = input
        .get("redeemScript")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let partials = partial_signatures_mut(input)?;
    match redeem_hex {
        Some(redeem_hex) => {
            let redeem = hex::decode(redeem_hex)
                .map_err(|error| format!("input[{index}] redeem hex: {error}"))?;
            merge_multisig(partials, &redeem, &signed.signatures, index)
        }
        None => merge_p2pk(partials, signed, index),
    }
}

fn merge_p2pk(
    partials: &mut Map<String, Value>,
    signed: &Input,
    index: usize,
) -> Result<(), String> {
    if signed.script.len() != 34 || signed.script[0] != 0x20 || signed.script[33] != 0xac {
        return Err(format!("input[{index}] is not a standard P2PK input"));
    }
    let signature = signed
        .signatures
        .first()
        .ok_or_else(|| format!("input[{index}] has no signature"))?;
    require_sighash_all(signature, index)?;
    let public_key = format!("02{}", hex::encode(&signed.script[1..33]));
    insert_signature(partials, public_key, &signature.bytes);
    Ok(())
}

fn merge_multisig(
    partials: &mut Map<String, Value>,
    redeem: &[u8],
    signatures: &[Signature],
    input_index: usize,
) -> Result<(), String> {
    for signature in signatures {
        require_sighash_all(signature, input_index)?;
        let key = multisig_xonly(redeem, signature.position).ok_or_else(|| {
            format!(
                "input[{input_index}] signature position {} is invalid",
                signature.position
            )
        })?;
        let public_key = format!("02{}", hex::encode(key));
        insert_signature(partials, public_key, &signature.bytes);
    }
    Ok(())
}

fn require_sighash_all(signature: &Signature, input_index: usize) -> Result<(), String> {
    if signature.sighash == 0x01 {
        Ok(())
    } else {
        Err(format!(
            "input[{input_index}] signed KSPT changed sighash type to 0x{:02x}",
            signature.sighash
        ))
    }
}

fn partial_signatures_mut(
    input: &mut Map<String, Value>,
) -> Result<&mut Map<String, Value>, String> {
    if !matches!(input.get("partialSigs"), Some(Value::Object(_))) {
        input.insert("partialSigs".to_string(), Value::Object(Map::new()));
    }
    input
        .get_mut("partialSigs")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "partialSigs normalization failed".to_string())
}

fn insert_signature(partials: &mut Map<String, Value>, public_key: String, signature: &[u8; 64]) {
    if partials.contains_key(&public_key) {
        return;
    }
    let mut value = Map::new();
    value.insert("schnorr".to_string(), Value::String(hex::encode(signature)));
    partials.insert(public_key, Value::Object(value));
}

fn multisig_xonly(redeem: &[u8], position: u8) -> Option<[u8; 32]> {
    let public_key = (0u8..=u8::MAX).find_map(|candidate| {
        let start = 2usize.checked_add(usize::from(candidate).checked_mul(33)?)?;
        let key = redeem.get(start..start + 32)?;
        let mut prefixed = String::from("02");
        prefixed.push_str(&hex::encode(key));
        (find_pubkey_position(redeem, &prefixed) == Some(position)).then_some(key)
    })?;
    public_key.try_into().ok()
}

mod parser;
use parser::parse;
