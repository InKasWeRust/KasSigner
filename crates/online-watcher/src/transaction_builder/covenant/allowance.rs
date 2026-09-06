//! Local allowance covenant withdrawal planning.

use crate::{
    account::{address, utxo::UtxoEntry},
    network,
};

const MIN_RETURN_SOMPI: u64 = 10_000_000;

#[derive(Debug)]
pub(crate) struct AllowanceWithdrawal {
    pub(crate) wire: String,
    pub(crate) input_count: usize,
    pub(crate) total_balance: u64,
    pub(crate) return_amount: u64,
    pub(crate) sequence: u64,
}

pub(crate) async fn build_remote(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    websocket_url: &str,
) -> Result<AllowanceWithdrawal, String> {
    let fetched = network::queries::utxos::fetch_for_address(websocket_url, covenant_address).await;
    build_remote_result(
        fetched,
        covenant_address,
        destination_address,
        redeem_script_hex,
        withdraw_sompi,
        fee,
    )
}

pub(super) fn build_remote_result(
    fetched: Result<Vec<UtxoEntry>, String>,
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
) -> Result<AllowanceWithdrawal, String> {
    let utxos = fetched?;
    build_allowance_withdrawal(
        covenant_address,
        destination_address,
        redeem_script_hex,
        withdraw_sompi,
        fee,
        &utxos,
    )
}

pub(crate) fn build_allowance_withdrawal(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    utxos: &[UtxoEntry],
) -> Result<AllowanceWithdrawal, String> {
    let material = prepare_material(
        covenant_address,
        destination_address,
        redeem_script_hex,
        withdraw_sompi,
        fee,
        utxos,
    )?;
    encode_allowance_withdrawal(material, withdraw_sompi, utxos)
}

pub(super) struct AllowanceMaterial {
    redeem_script: Vec<u8>,
    covenant_spk_hex: String,
    destination_spk_hex: String,
    total_balance: u64,
    return_amount: u64,
    sequence: u64,
    locktime: u64,
}

pub(super) fn prepare_material(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    withdraw_sompi: u64,
    fee: u64,
    utxos: &[UtxoEntry],
) -> Result<AllowanceMaterial, String> {
    require_utxos(utxos)?;
    let redeem_script =
        hex::decode(redeem_script_hex).map_err(|error| format!("Bad redeem hex: {error}"))?;
    let total_balance = checked_total(utxos)?;
    let required = required_amount(withdraw_sompi, fee)?;
    ensure_funded(required, total_balance, withdraw_sompi, fee)?;
    let return_amount = checked_return_amount(total_balance, required)?;
    let (covenant_spk_hex, destination_spk_hex) =
        decode_allowance_scripts(covenant_address, destination_address)?;
    let sequence = crate::protocol::script::extract_csv_sequence(&redeem_script)?.unwrap_or(0);
    let locktime = crate::protocol::script::extract_cltv_locktime(&redeem_script)?.unwrap_or(0);
    Ok(AllowanceMaterial {
        redeem_script,
        covenant_spk_hex,
        destination_spk_hex,
        total_balance,
        return_amount,
        sequence,
        locktime,
    })
}

fn require_utxos(utxos: &[UtxoEntry]) -> Result<(), String> {
    if utxos.is_empty() {
        Err("No UTXOs at covenant address".to_string())
    } else {
        Ok(())
    }
}

fn required_amount(withdraw_sompi: u64, fee: u64) -> Result<u64, String> {
    withdraw_sompi
        .checked_add(fee)
        .ok_or_else(|| "Withdraw amount plus fee overflows u64".to_string())
}

fn ensure_funded(
    required: u64,
    total_balance: u64,
    withdraw_sompi: u64,
    fee: u64,
) -> Result<(), String> {
    if required > total_balance {
        Err(format!(
            "Withdraw {withdraw_sompi} + fee {fee} > total balance {total_balance}"
        ))
    } else {
        Ok(())
    }
}

fn checked_return_amount(total_balance: u64, required: u64) -> Result<u64, String> {
    let return_amount = total_balance - required;
    if (1..MIN_RETURN_SOMPI).contains(&return_amount) {
        Err(format!(
            "Return amount {return_amount} sompi ({:.4} KAS) is too small. Tiny outputs cause high storage fees. Either withdraw less (leave at least 0.1 KAS) or use Owner Reclaim to sweep everything.",
            return_amount as f64 / 1e8
        ))
    } else {
        Ok(return_amount)
    }
}

fn checked_total(utxos: &[UtxoEntry]) -> Result<u64, String> {
    utxos.iter().try_fold(0u64, |total, utxo| {
        total
            .checked_add(utxo.amount)
            .ok_or_else(|| "Covenant balance overflows u64".to_string())
    })
}

fn decode_allowance_scripts(
    covenant_address: &str,
    destination_address: &str,
) -> Result<(String, String), String> {
    let covenant_spk_hex = script_hex(covenant_address)?;
    script_hex(destination_address)
        .map(|destination_spk_hex| (covenant_spk_hex, destination_spk_hex))
}

fn script_hex(address_text: &str) -> Result<String, String> {
    address::address_to_script_pubkey(address_text)
        .map(|script| format!("0000{}", hex::encode(script)))
}

fn encode_allowance_withdrawal(
    material: AllowanceMaterial,
    withdraw_sompi: u64,
    utxos: &[UtxoEntry],
) -> Result<AllowanceWithdrawal, String> {
    let redeem_script_hex = hex::encode(&material.redeem_script);
    let inputs = utxos
        .iter()
        .map(|utxo| {
            input_value(
                utxo,
                material.sequence,
                &material.covenant_spk_hex,
                &redeem_script_hex,
            )
        })
        .collect::<Vec<_>>();
    let input_count = inputs.len();
    let outputs = vec![
        output_value(material.return_amount, &material.covenant_spk_hex),
        output_value(withdraw_sompi, &material.destination_spk_hex),
    ];
    let pskt = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": (material.locktime > 0).then_some(material.locktime),
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
    crate::transaction_builder::pskb::encode_pskt_value(pskt).map(|wire| AllowanceWithdrawal {
        wire,
        input_count,
        total_balance: material.total_balance,
        return_amount: material.return_amount,
        sequence: material.sequence,
    })
}

fn input_value(
    utxo: &UtxoEntry,
    sequence: u64,
    covenant_spk_hex: &str,
    redeem_script_hex: &str,
) -> serde_json::Value {
    serde_json::json!({
        "previousOutpoint": {"transactionId": utxo.tx_id.as_str(), "index": utxo.index},
        "sequence": sequence,
        "sigOpCount": 1,
        "utxoEntry": {
            "amount": utxo.amount,
            "scriptPublicKey": covenant_spk_hex,
            "blockDaaScore": 0,
            "isCoinbase": false
        },
        "redeemScript": redeem_script_hex,
        "partialSigs": {},
        "minimumSignatures": 1,
        "bip32Derivations": [],
        "proprietaries": [],
        "finalScriptSig": null,
        "minTime": 0
    })
}

fn output_value(amount: u64, script_public_key: &str) -> serde_json::Value {
    serde_json::json!({
        "amount": amount,
        "scriptPublicKey": script_public_key,
        "bip32Derivations": [],
        "proprietaries": []
    })
}

#[cfg(test)]
mod unit_tests;
