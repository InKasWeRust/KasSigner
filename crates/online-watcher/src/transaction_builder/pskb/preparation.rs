use serde::Deserialize;

use crate::account::{address, utxo::UtxoEntry};

use super::{encode_wire, plan_sweep, PskbGlobalPlan, SweepInputPolicy};

#[derive(Clone, Debug)]
pub(crate) struct PreparedSweep {
    pub(crate) utxos: Vec<UtxoEntry>,
    pub(crate) total: u64,
    pub(crate) send_amount: u64,
    pub(crate) source_script_public_key: Vec<u8>,
    pub(crate) destination_script_public_key: Vec<u8>,
}

pub(crate) fn prepare_sweep_from_utxos(
    utxos: Vec<UtxoEntry>,
    source_address: &str,
    destination_address: &str,
    fee: u64,
    empty_error: &str,
    low_balance_error: &str,
) -> Result<PreparedSweep, String> {
    let utxos = require_sweep_utxos(utxos, empty_error)?;
    let (total, send_amount) = sweep_amounts(&utxos, fee, low_balance_error)?;
    let (source_script_public_key, destination_script_public_key) =
        sweep_scripts(source_address, destination_address)?;
    Ok(PreparedSweep {
        utxos,
        total,
        send_amount,
        source_script_public_key,
        destination_script_public_key,
    })
}

pub(crate) fn encode_prepared_sweep(
    prepared: &PreparedSweep,
    global: PskbGlobalPlan,
    input_policy: &SweepInputPolicy,
) -> Result<String, String> {
    let plan = plan_sweep(
        &prepared.utxos,
        &prepared.source_script_public_key,
        &prepared.destination_script_public_key,
        prepared.send_amount,
        global,
        input_policy,
    );
    encode_wire(&plan)
}

#[derive(Deserialize)]
struct SelectedUtxo {
    tx_id: String,
    index: u64,
    #[serde(with = "crate::serialization::decimal_u64")]
    amount: u64,
}

pub(crate) fn prepare_selected_sweep(
    utxos_json: &str,
    source_address: &str,
    destination_address: &str,
    fee: u64,
    missing_set_error: &str,
    low_balance_error: &str,
) -> Result<PreparedSweep, String> {
    let values: Vec<SelectedUtxo> =
        serde_json::from_str(utxos_json).map_err(|error| format!("Bad UTXO JSON: {error}"))?;
    if values.is_empty() {
        return Err(missing_set_error.to_string());
    }
    let source_script_public_key = address::address_to_script_pubkey(source_address)?;
    let destination_script_public_key = address::address_to_script_pubkey(destination_address)?;
    let utxos = values
        .into_iter()
        .map(selected_utxo_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let total = checked_total(&utxos)?;
    let send_amount = require_sweep_balance(total, fee, low_balance_error)?;

    Ok(PreparedSweep {
        utxos,
        total,
        send_amount,
        source_script_public_key,
        destination_script_public_key,
    })
}

fn require_sweep_utxos(utxos: Vec<UtxoEntry>, empty_error: &str) -> Result<Vec<UtxoEntry>, String> {
    if utxos.is_empty() {
        Err(empty_error.to_string())
    } else {
        Ok(utxos)
    }
}

fn sweep_amounts(
    utxos: &[UtxoEntry],
    fee: u64,
    low_balance_error: &str,
) -> Result<(u64, u64), String> {
    let total = checked_total(utxos)?;
    let send_amount = require_sweep_balance(total, fee, low_balance_error)?;
    Ok((total, send_amount))
}

fn require_sweep_balance(total: u64, fee: u64, low_balance_error: &str) -> Result<u64, String> {
    total
        .checked_sub(fee)
        .filter(|amount| *amount > 0)
        .ok_or_else(|| low_balance_error.to_string())
}

fn sweep_scripts(
    source_address: &str,
    destination_address: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let source = address::address_to_script_pubkey(source_address)?;
    let destination = address::address_to_script_pubkey(destination_address)?;
    Ok((source, destination))
}

fn selected_utxo_entry(value: SelectedUtxo) -> Result<UtxoEntry, String> {
    if value.tx_id.len() != 64 || hex::decode(&value.tx_id).is_err() {
        return Err("UTXO tx_id must be 32-byte hex".to_string());
    }
    Ok(UtxoEntry {
        tx_id: value.tx_id,
        index: u32::try_from(value.index).map_err(|_| "UTXO index exceeds u32".to_string())?,
        amount: value.amount,
        script_public_key: Vec::new(),
        block_daa_score: 0,
        covenant_id: None,
    })
}

fn checked_total(utxos: &[UtxoEntry]) -> Result<u64, String> {
    utxos.iter().try_fold(0u64, |total, utxo| {
        total
            .checked_add(utxo.amount)
            .ok_or_else(|| "UTXO total overflow".to_string())
    })
}

#[cfg(test)]
mod unit_tests;
