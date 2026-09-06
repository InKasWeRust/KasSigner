use crate::{
    account::bip32::WalletData,
    account::utxo::UtxoEntry,
    transaction_builder::{
        model::{PlannedOutput, UnsignedTransactionPlan},
        selection::checked_total,
    },
};

use super::{amounts::checked_sum, calculate_change};

pub fn plan_payment(
    wallet: &WalletData,
    selected: Vec<UtxoEntry>,
    mut recipients: Vec<PlannedOutput>,
    fee: u64,
) -> Result<UnsignedTransactionPlan, String> {
    let change = payment_change(&selected, &recipients, fee)?;
    if change > 0 {
        let address = wallet
            .change_addresses
            .get(wallet.next_change_index)
            .ok_or_else(|| "No more change addresses. Re-import kpub.".to_string())?;
        let index = u32::try_from(wallet.next_change_index)
            .map_err(|_| "Change derivation index exceeds u32".to_string())?;
        append_change(&mut recipients, change, address, index)?;
    }
    Ok(UnsignedTransactionPlan::standard(selected, recipients))
}

pub fn plan_payment_with_change(
    selected: Vec<UtxoEntry>,
    mut recipients: Vec<PlannedOutput>,
    fee: u64,
    change_address: &str,
    change_index: u32,
) -> Result<UnsignedTransactionPlan, String> {
    let change = payment_change(&selected, &recipients, fee)?;
    if change > 0 {
        append_change(&mut recipients, change, change_address, change_index)?;
    }
    Ok(UnsignedTransactionPlan::standard(selected, recipients))
}

#[cfg(test)]
pub fn plan_payment_with_change_and_derivations(
    selected: Vec<(UtxoEntry, Option<(u8, u32)>)>,
    mut recipients: Vec<PlannedOutput>,
    fee: u64,
    change_address: &str,
    change_index: u32,
) -> Result<UnsignedTransactionPlan, String> {
    let selected_utxos = selected
        .iter()
        .map(|(utxo, _)| utxo.clone())
        .collect::<Vec<_>>();
    let change = payment_change(&selected_utxos, &recipients, fee)?;
    if change > 0 {
        append_change(&mut recipients, change, change_address, change_index)?;
    }
    Ok(UnsignedTransactionPlan::standard_with_derivations(
        selected, recipients,
    ))
}

fn payment_change(
    selected: &[UtxoEntry],
    recipients: &[PlannedOutput],
    fee: u64,
) -> Result<u64, String> {
    let selected_total = checked_total(selected)?;
    let spend_total = checked_sum(recipients.iter().map(|output| output.amount))?;
    calculate_change(selected_total, spend_total, fee)
}

fn append_change(
    recipients: &mut Vec<PlannedOutput>,
    change: u64,
    address: &str,
    index: u32,
) -> Result<(), String> {
    let script = crate::account::address::address_to_script_pubkey(address)?;
    recipients.push(PlannedOutput::new(change, script).with_derivation(1, index));
    Ok(())
}

pub fn plan_consolidation(
    wallet: &WalletData,
    selected: Vec<UtxoEntry>,
    fee: u64,
) -> Result<UnsignedTransactionPlan, String> {
    let total = checked_total(&selected)?;
    let amount = total
        .checked_sub(fee)
        .ok_or_else(|| "Balance too low to cover fee".to_string())?;
    if amount == 0 {
        return Err("Balance too low to cover fee".into());
    }
    let address = wallet
        .receive_addresses
        .first()
        .ok_or_else(|| "Wallet has no receive address".to_string())?;
    let script = crate::account::address::address_to_script_pubkey(address)?;
    Ok(UnsignedTransactionPlan::standard(
        selected,
        vec![PlannedOutput::new(amount, script).with_derivation(0, 0)],
    ))
}

#[cfg(test)]
mod unit_tests;
