use crate::{
    account::{bip32::WalletData, utxo::UtxoEntry},
    protocol::pskt::pskb,
    transaction_builder::{
        model::{PlannedOutput, UnsignedTransactionPlan},
        planning::{amounts, plan_consolidation, plan_payment, plan_payment_with_change},
        selection::{select_automatic_with_limit, select_explicit, select_for_consolidation},
    },
};

const SIGNER_MAX_INPUTS: usize = kassigner_protocol::SIGNER_CAPABILITIES.max_inputs as usize;

pub(super) fn validate_signer_input_count(count: usize) -> Result<(), String> {
    if count == 0 {
        return Err("No UTXOs provided".into());
    }
    if count > SIGNER_MAX_INPUTS {
        return Err(format!(
            "transaction uses {count} inputs but KasSigner supports at most {SIGNER_MAX_INPUTS}"
        ));
    }
    Ok(())
}

pub async fn create_send(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    fee: u64,
    websocket_url: &str,
) -> Result<String, String> {
    let prepared = prepare_send(destination, amount, fee)?;
    let utxos = crate::network::queries::utxos::fetch_all(websocket_url, wallet).await?;
    create_send_from_utxos(wallet, &prepared, utxos)
}

pub async fn create_send_limited(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    fee: u64,
    max_inputs: usize,
    websocket_url: &str,
) -> Result<String, String> {
    let prepared = prepare_send(destination, amount, fee)?;
    crate::network::queries::utxos::fetch_all(websocket_url, wallet)
        .await
        .and_then(|utxos| create_limited_send_from_utxos(wallet, &prepared, utxos, max_inputs))
}

pub(super) fn create_limited_send_from_utxos(
    wallet: &WalletData,
    prepared: &PreparedSend,
    utxos: Vec<UtxoEntry>,
    max_inputs: usize,
) -> Result<String, String> {
    validate_signer_input_count(max_inputs)?;
    select_automatic_with_limit(utxos, prepared.required, max_inputs).and_then(|selected| {
        encode_payment(wallet, selected, prepared.output.clone(), prepared.fee)
    })
}

pub async fn create_send_selected(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    fee: u64,
    indices: &[usize],
    websocket_url: &str,
) -> Result<String, String> {
    let prepared = prepare_send(destination, amount, fee)?;
    let utxos = crate::network::queries::utxos::fetch_all(websocket_url, wallet).await?;
    create_send_selected_from_utxos(wallet, &prepared, indices, utxos)
}

pub async fn create_consolidation(
    wallet: &WalletData,
    fee: u64,
    websocket_url: &str,
) -> Result<String, String> {
    let utxos = crate::network::queries::utxos::fetch_all(websocket_url, wallet).await?;
    create_consolidation_from_utxos(wallet, fee, utxos)
}

pub fn create_pskb_with_utxos(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    requested_fee: u64,
    selected: Vec<UtxoEntry>,
) -> Result<String, String> {
    let (prepared, fee) = prepare_selected_send(destination, amount, requested_fee, &selected)?;
    encode_payment(wallet, selected, prepared.output, fee)
}

pub fn create_pskb_with_utxos_and_change(
    destination: &str,
    amount: u64,
    requested_fee: u64,
    selected: Vec<UtxoEntry>,
    change_address: &str,
    change_index: u32,
) -> Result<String, String> {
    let (prepared, fee) = prepare_selected_send(destination, amount, requested_fee, &selected)?;
    encode_payment_with_change(selected, prepared.output, fee, change_address, change_index)
}

fn prepare_selected_send(
    destination: &str,
    amount: u64,
    requested_fee: u64,
    selected: &[UtxoEntry],
) -> Result<(PreparedSend, u64), String> {
    let prepared = prepare_send(destination, amount, requested_fee)?;
    validate_signer_input_count(selected.len())?;
    let selected_total = crate::transaction_builder::selection::checked_total(selected)?;
    let fee = storage_mass_fee(selected, selected_total, amount, requested_fee)?;
    Ok((prepared, fee))
}

#[derive(Clone, Debug)]
pub(super) struct PreparedSend {
    output: PlannedOutput,
    required: u64,
    fee: u64,
}

pub(super) fn prepare_send(
    destination: &str,
    amount: u64,
    fee: u64,
) -> Result<PreparedSend, String> {
    validate_recipient_amount(amount)?;
    let required = amounts::checked_required(amount, fee)?;
    let output = PlannedOutput::new(
        amount,
        crate::account::address::address_to_script_pubkey(destination)?,
    );
    Ok(PreparedSend {
        output,
        required,
        fee,
    })
}

pub(super) fn create_send_from_utxos(
    wallet: &WalletData,
    prepared: &PreparedSend,
    utxos: Vec<UtxoEntry>,
) -> Result<String, String> {
    let selected = select_automatic_with_limit(utxos, prepared.required, 8)?;
    encode_payment(wallet, selected, prepared.output.clone(), prepared.fee)
}

pub(super) fn create_send_selected_from_utxos(
    wallet: &WalletData,
    prepared: &PreparedSend,
    indices: &[usize],
    utxos: Vec<UtxoEntry>,
) -> Result<String, String> {
    validate_signer_input_count(indices.len())?;
    let selected = select_explicit(utxos, indices)?;
    encode_payment(wallet, selected, prepared.output.clone(), prepared.fee)
}

pub(super) fn create_consolidation_from_utxos(
    wallet: &WalletData,
    fee: u64,
    utxos: Vec<UtxoEntry>,
) -> Result<String, String> {
    let selected = select_for_consolidation(utxos, 5)?;
    encode_plan(&plan_consolidation(wallet, selected, fee)?)
}

fn encode_payment(
    wallet: &WalletData,
    selected: Vec<UtxoEntry>,
    output: PlannedOutput,
    fee: u64,
) -> Result<String, String> {
    encode_plan(&plan_payment(wallet, selected, vec![output], fee)?)
}

fn encode_payment_with_change(
    selected: Vec<UtxoEntry>,
    output: PlannedOutput,
    fee: u64,
    change_address: &str,
    change_index: u32,
) -> Result<String, String> {
    encode_plan(&plan_payment_with_change(
        selected,
        vec![output],
        fee,
        change_address,
        change_index,
    )?)
}

fn encode_plan(plan: &UnsignedTransactionPlan) -> Result<String, String> {
    pskb::encode_plan(plan)
}

pub(super) fn validate_recipient_amount(amount: u64) -> Result<(), String> {
    if amount == 0 {
        return Err("amount must be > 0".into());
    }
    if amounts::is_dust(amount) {
        return Err(format!("amount too small ({} sompi)", amount));
    }
    Ok(())
}

pub(super) fn storage_mass_fee(
    selected: &[UtxoEntry],
    selected_total: u64,
    amount: u64,
    requested_fee: u64,
) -> Result<u64, String> {
    let minimum_fee = 300_000u64;
    let input_count = u64::try_from(selected.len())
        .map_err(|_| "Input count exceeds supported range".to_string())?;
    let compute_mass = input_count
        .checked_mul(800)
        .and_then(|mass| mass.checked_add(2_000))
        .ok_or_else(|| "Compute mass exceeds supported range".to_string())?;
    let inputs = selected
        .iter()
        .map(|utxo| (utxo.amount, 1u64))
        .collect::<Vec<_>>();
    let mut fee = minimum_fee;
    for _ in 0..3 {
        let required = amounts::checked_required(amount, fee)?;
        let change = selected_total.saturating_sub(required);
        let outputs = if !amounts::is_dust(change) {
            vec![(amount, 1u64), (change, 1u64)]
        } else {
            vec![(amount, 1u64)]
        };
        let mass = amounts::storage_mass_estimate(&inputs, &outputs)?.max(compute_mass);
        fee = mass
            .checked_mul(110)
            .ok_or_else(|| "Estimated fee exceeds supported range".to_string())?
            .max(minimum_fee);
    }
    Ok(fee.max(requested_fee))
}
