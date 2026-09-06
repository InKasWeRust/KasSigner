use crate::{
    account::utxo::UtxoEntry,
    transaction_builder::{
        model::{PlannedOutput, UnsignedTransactionPlan},
        selection::checked_total,
    },
};

use super::calculate_change;

pub fn plan_multisig(
    selected: Vec<UtxoEntry>,
    destination: PlannedOutput,
    fee: u64,
    approved_change_script: Vec<u8>,
    redeem_script: &[u8],
    sig_op_count: u8,
) -> Result<(UnsignedTransactionPlan, u64), String> {
    if selected.len() > 3 {
        return Err(format!(
            "Multisig P2SH limited to 3 inputs (selected {}). Node rejects 4+ inputs. Consolidate UTXOs in batches of 3.",
            selected.len()
        ));
    }
    let selected_total = checked_total(&selected)?;
    let change = calculate_change(selected_total, destination.amount, fee)?;
    let mut outputs = vec![destination];
    if change > 0 {
        outputs.push(PlannedOutput::new(change, approved_change_script));
    }
    Ok((
        UnsignedTransactionPlan::multisig(selected, outputs, redeem_script, sig_op_count),
        change,
    ))
}
