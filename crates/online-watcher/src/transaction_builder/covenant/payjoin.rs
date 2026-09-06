use crate::{
    account::{address, utxo::UtxoEntry},
    network,
};

const MAX_COVENANT_INPUTS: usize = 4;

pub(crate) struct PayjoinClaim {
    pub(crate) wire: String,
    pub(crate) input_count: usize,
    pub(crate) covenant_input_count: usize,
    pub(crate) total: u64,
    pub(crate) send: u64,
    pub(crate) change: u64,
    pub(crate) fee: u64,
}

pub(crate) async fn create(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    mixing_address: &str,
    requested_fee: u64,
    websocket_url: &str,
) -> Result<PayjoinClaim, String> {
    let covenant = fetch_covenant_utxos(websocket_url, covenant_address).await?;
    let mixing = fetch_smallest_mixing_utxo(websocket_url, mixing_address).await?;
    let claim = build_claim(
        covenant_address,
        destination_address,
        redeem_script_hex,
        mixing_address,
        requested_fee,
        covenant,
        mixing,
    )?;
    Ok(claim)
}

pub(crate) fn build_claim(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    mixing_address: &str,
    requested_fee: u64,
    covenant_utxos: Vec<UtxoEntry>,
    mixing_utxo: UtxoEntry,
) -> Result<PayjoinClaim, String> {
    if covenant_utxos.is_empty() {
        return Err("No UTXOs at covenant address".to_string());
    }
    let redeem_script =
        hex::decode(redeem_script_hex).map_err(|error| format!("Bad redeem hex: {error}"))?;
    let amounts = calculate_amounts(&covenant_utxos, &mixing_utxo, requested_fee)?;
    let scripts = Scripts::new(covenant_address, destination_address, mixing_address)?;
    let inputs = build_inputs(&covenant_utxos, &mixing_utxo, &scripts, &redeem_script);
    let outputs = build_outputs(&scripts, amounts.send, amounts.change);
    let input_count = inputs.len();
    let output_count = outputs.len();
    let wire = encode_pskb(inputs, outputs, input_count, output_count)?;
    Ok(PayjoinClaim {
        wire,
        input_count,
        covenant_input_count: covenant_utxos.len(),
        total: amounts.total,
        send: amounts.send,
        change: amounts.change,
        fee: amounts.fee,
    })
}

pub(crate) async fn fetch_covenant_utxos(
    websocket_url: &str,
    address: &str,
) -> Result<Vec<UtxoEntry>, String> {
    let mut utxos = network::queries::utxos::fetch_for_address(websocket_url, address).await?;
    if utxos.is_empty() {
        return Err("No UTXOs at covenant address".to_string());
    }
    crate::transaction_builder::selection::sort_largest_first(&mut utxos);
    utxos.truncate(MAX_COVENANT_INPUTS);
    Ok(utxos)
}

pub(crate) async fn fetch_smallest_mixing_utxo(
    websocket_url: &str,
    address: &str,
) -> Result<UtxoEntry, String> {
    network::queries::utxos::fetch_for_address(websocket_url, address)
        .await?
        .into_iter()
        .min_by_key(|utxo| utxo.amount)
        .ok_or("No UTXOs at your address for mixing — PayJoin requires your own inputs".to_string())
}

struct ClaimAmounts {
    total: u64,
    send: u64,
    change: u64,
    fee: u64,
}

fn calculate_amounts(
    covenant_utxos: &[UtxoEntry],
    mixing_utxo: &UtxoEntry,
    requested_fee: u64,
) -> Result<ClaimAmounts, String> {
    let covenant_total = covenant_utxos.iter().try_fold(0u64, |total, utxo| {
        total
            .checked_add(utxo.amount)
            .ok_or("Covenant balance overflows u64".to_string())
    })?;
    let total = covenant_total
        .checked_add(mixing_utxo.amount)
        .ok_or("PayJoin total overflows u64".to_string())?;
    let input_count = covenant_utxos
        .len()
        .checked_add(1)
        .ok_or("PayJoin input count overflow".to_string())?;
    let fee = requested_fee.max(required_fee(input_count)?);
    if total <= fee {
        return Err("Balance too low to cover fee".to_string());
    }
    let covenant_fee = fee
        .checked_mul(3)
        .ok_or("PayJoin fee split overflow".to_string())?
        / 4;
    let mixing_fee = fee
        .checked_sub(covenant_fee)
        .ok_or("PayJoin fee split underflow".to_string())?;
    let send = covenant_total
        .checked_sub(covenant_fee)
        .filter(|value| *value > 0)
        .ok_or("Covenant balance too low".to_string())?;
    let change = mixing_utxo
        .amount
        .checked_sub(mixing_fee)
        .ok_or("Mixing UTXO is too small to cover its fee share".to_string())?;
    Ok(ClaimAmounts {
        total,
        send,
        change,
        fee,
    })
}

fn required_fee(input_count: usize) -> Result<u64, String> {
    let input_count =
        u64::try_from(input_count).map_err(|_| "PayJoin input count overflow".to_string())?;
    let compute_mass = input_count
        .checked_mul(1_300)
        .and_then(|value| value.checked_add(429))
        .ok_or("PayJoin mass overflow".to_string())?;
    compute_mass
        .checked_mul(115)
        .ok_or("PayJoin fee overflow".to_string())
}

struct Scripts {
    covenant: String,
    destination: String,
    mixing: String,
}

impl Scripts {
    fn new(covenant: &str, destination: &str, mixing: &str) -> Result<Self, String> {
        Ok(Self {
            covenant: script_hex(covenant)?,
            destination: script_hex(destination)?,
            mixing: script_hex(mixing)?,
        })
    }
}

fn script_hex(address_text: &str) -> Result<String, String> {
    let script = address::address_to_script_pubkey(address_text)?;
    Ok(format!("0000{}", hex::encode(script)))
}

fn build_inputs(
    covenant_utxos: &[UtxoEntry],
    mixing_utxo: &UtxoEntry,
    scripts: &Scripts,
    redeem_script: &[u8],
) -> Vec<serde_json::Value> {
    let redeem_hex = hex::encode(redeem_script);
    let mut covenant_inputs = covenant_utxos
        .iter()
        .map(|utxo| covenant_input(utxo, &scripts.covenant, &redeem_hex))
        .collect::<Vec<_>>();
    let mut inputs = Vec::with_capacity(covenant_inputs.len() + 1);
    inputs.push(covenant_inputs.remove(0));
    inputs.push(standard_input(mixing_utxo, &scripts.mixing));
    inputs.extend(covenant_inputs);
    inputs
}

fn covenant_input(
    utxo: &UtxoEntry,
    script_public_key: &str,
    redeem_script: &str,
) -> serde_json::Value {
    input_value(utxo, script_public_key, Some(redeem_script))
}

fn standard_input(utxo: &UtxoEntry, script_public_key: &str) -> serde_json::Value {
    input_value(utxo, script_public_key, None)
}

fn input_value(
    utxo: &UtxoEntry,
    script_public_key: &str,
    redeem_script: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "previousOutpoint": {
            "transactionId": utxo.tx_id.as_str(),
            "index": utxo.index
        },
        "sequence": 0,
        "sigOpCount": 1,
        "utxoEntry": {
            "amount": utxo.amount,
            "scriptPublicKey": script_public_key,
            "blockDaaScore": 0,
            "isCoinbase": false
        },
        "redeemScript": redeem_script,
        "partialSigs": {},
        "minimumSignatures": 1,
        "bip32Derivations": [],
        "proprietaries": {},
        "finalScriptSig": null,
        "minTime": 0
    })
}

fn build_outputs(scripts: &Scripts, send: u64, change: u64) -> Vec<serde_json::Value> {
    let mut outputs = vec![output_value(send, &scripts.destination)];
    if change > 0 {
        outputs.push(output_value(change, &scripts.mixing));
    }
    outputs
}

fn output_value(amount: u64, script_public_key: &str) -> serde_json::Value {
    serde_json::json!({
        "amount": amount,
        "scriptPublicKey": script_public_key,
        "bip32Derivations": [],
        "proprietaries": []
    })
}

fn encode_pskb(
    inputs: Vec<serde_json::Value>,
    outputs: Vec<serde_json::Value>,
    input_count: usize,
    output_count: usize,
) -> Result<String, String> {
    crate::transaction_builder::pskb::encode_pskt_value(serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": null,
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
    }))
}

#[cfg(test)]
mod unit_tests;
