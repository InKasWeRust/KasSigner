use super::fee::DepositFeePolicy;
use crate::UtxoEntry;

pub(super) struct SelectionResult {
    pub(super) selected: Vec<UtxoEntry>,
    pub(super) total: u64,
    pub(super) fee: u64,
    pub(super) target: u64,
    pub(super) used_manual_selection: bool,
}

pub(super) fn select(
    utxos: &[UtxoEntry],
    send_amount: u64,
    requested_fee: u64,
    utxo_indices_csv: &str,
    fee_policy: DepositFeePolicy,
) -> Result<SelectionResult, String> {
    let manual_indices = parse_manual_indices(utxo_indices_csv);
    let used_manual_selection = !manual_indices.is_empty();
    let (selected, total, fee, target) = if used_manual_selection {
        select_manual(
            utxos,
            &manual_indices,
            send_amount,
            requested_fee,
            fee_policy,
        )?
    } else {
        select_automatic(utxos, send_amount, requested_fee, fee_policy)?
    };
    Ok(SelectionResult {
        selected,
        total,
        fee,
        target,
        used_manual_selection,
    })
}

fn parse_manual_indices(csv: &str) -> Vec<usize> {
    csv.split(',')
        .filter_map(|value| value.trim().parse().ok())
        .collect()
}

fn checked_target(send_amount: u64, fee: u64) -> Result<u64, String> {
    send_amount
        .checked_add(fee)
        .ok_or_else(|| "Send amount plus fee exceeds supported monetary range".to_string())
}

fn checked_total(total: u64, amount: u64) -> Result<u64, String> {
    total
        .checked_add(amount)
        .ok_or_else(|| "Selected UTXO total exceeds supported monetary range".to_string())
}

fn select_manual(
    utxos: &[UtxoEntry],
    indices: &[usize],
    send_amount: u64,
    requested_fee: u64,
    fee_policy: DepositFeePolicy,
) -> Result<(Vec<UtxoEntry>, u64, u64, u64), String> {
    let mut selected = Vec::with_capacity(indices.len());
    let mut total = 0u64;
    for &index in indices {
        let utxo = utxos
            .get(index)
            .ok_or_else(|| format!("UTXO index {} out of range (have {})", index, utxos.len()))?;
        total = checked_total(total, utxo.amount)?;
        selected.push(utxo.clone());
    }
    let fee = requested_fee.max(fee_policy.calculate(selected.len() as u64)?);
    let target = checked_target(send_amount, fee)?;
    Ok((selected, total, fee, target))
}

fn select_automatic(
    utxos: &[UtxoEntry],
    send_amount: u64,
    requested_fee: u64,
    fee_policy: DepositFeePolicy,
) -> Result<(Vec<UtxoEntry>, u64, u64, u64), String> {
    let mut selected = Vec::new();
    let mut total = 0u64;
    let mut fee = requested_fee;
    let mut target = checked_target(send_amount, fee)?;
    for utxo in utxos {
        total = checked_total(total, utxo.amount)?;
        selected.push(utxo.clone());
        fee = fee.max(fee_policy.calculate(selected.len() as u64)?);
        target = checked_target(send_amount, fee)?;
        if total >= target {
            break;
        }
    }
    Ok((selected, total, fee, target))
}
