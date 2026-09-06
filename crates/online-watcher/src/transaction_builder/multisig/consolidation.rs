//! Multi-address 45' multisig consolidation planning.

use crate::{
    multisig::{build_redeem_script, resolve_address_path, MultisigDescriptor},
    protocol::pskt::pskb,
    transaction_builder::{
        model::{PlannedInput, PlannedOutput, UnsignedTransactionPlan},
        planning::amounts,
    },
};

use super::{
    address_prefix, branch::next_change_index, multisig_standard_fee_for_shape,
    MULTISIG_BRANCH_SCAN_DEPTH,
};

#[derive(Clone, serde::Deserialize)]
pub struct MultisigConsolidationSource {
    pub address: String,
    pub tx_id: String,
    pub index: u32,
}

pub(crate) struct MultiAddressRequest<'a> {
    pub descriptor_text: &'a str,
    pub sources_json: &'a str,
    pub destination_address: &'a str,
    pub amount: u64,
    pub fee: u64,
    pub cosigner: u32,
    pub change_index_hint: u32,
    pub websocket_url: &'a str,
}

pub(crate) async fn create_multi_address(
    request: MultiAddressRequest<'_>,
) -> Result<String, String> {
    let prepared = prepare_consolidation(
        request.descriptor_text,
        request.sources_json,
        request.cosigner,
    )?;
    let available = crate::network::queries::utxos::fetch_for_addresses(
        request.websocket_url,
        &prepared.unique_addresses,
    )
    .await?;
    finish_consolidation(
        prepared,
        &available,
        FinishConsolidationRequest {
            destination_address: request.destination_address,
            amount: request.amount,
            fee: request.fee,
            cosigner: request.cosigner,
            change_index_hint: request.change_index_hint,
            websocket_url: request.websocket_url,
        },
    )
    .await
}

pub(super) struct PreparedConsolidation {
    descriptor: MultisigDescriptor,
    sources: Vec<MultisigConsolidationSource>,
    resolved: ResolvedConsolidationSources,
    unique_addresses: Vec<String>,
}

pub(super) fn prepare_consolidation(
    descriptor_text: &str,
    sources_json: &str,
    cosigner: u32,
) -> Result<PreparedConsolidation, String> {
    let descriptor = MultisigDescriptor::parse(descriptor_text)?;
    require_hd45_consolidation(&descriptor)?;
    let sources = parse_consolidation_sources(sources_json)?;
    let resolved = resolve_consolidation_sources(&descriptor, &sources, cosigner)?;
    let unique_addresses = unique_source_addresses(&sources);
    Ok(PreparedConsolidation {
        descriptor,
        sources,
        resolved,
        unique_addresses,
    })
}

pub(super) struct FinishConsolidationRequest<'a> {
    pub destination_address: &'a str,
    pub amount: u64,
    pub fee: u64,
    pub cosigner: u32,
    pub change_index_hint: u32,
    pub websocket_url: &'a str,
}

pub(super) async fn finish_consolidation(
    prepared: PreparedConsolidation,
    available: &[crate::UtxoEntry],
    request: FinishConsolidationRequest<'_>,
) -> Result<String, String> {
    let (inputs, total) =
        build_consolidation_inputs(&prepared.sources, available, &prepared.resolved)?;
    let fee = consolidation_standard_fee(
        &prepared.descriptor,
        &inputs,
        request.destination_address,
        request.fee,
    )?;
    let required = required_total(request.amount, fee)?;
    require_selected_total(total, required)?;
    let outputs = consolidation_outputs(
        &prepared.descriptor,
        ConsolidationOutputRequest {
            source_address: &prepared.sources[0].address,
            destination_address: request.destination_address,
            amount: request.amount,
            change: consolidation_change(total, required)?,
            cosigner: request.cosigner,
            change_index_hint: request.change_index_hint,
            websocket_url: request.websocket_url,
        },
    )
    .await?;
    pskb::encode_plan(&UnsignedTransactionPlan {
        tx_version: 0,
        inputs,
        outputs,
        payload: Vec::new(),
    })
}

pub(super) fn consolidation_standard_fee(
    descriptor: &MultisigDescriptor,
    inputs: &[PlannedInput],
    destination_address: &str,
    requested_fee: u64,
) -> Result<u64, String> {
    const P2SH_SCRIPT_PUBLIC_KEY_LEN: usize = 35;

    let first = inputs
        .first()
        .ok_or_else(|| "Multisig consolidation has no inputs".to_string())?;
    let redeem_script_len = first
        .redeem_script
        .as_ref()
        .map(Vec::len)
        .ok_or_else(|| "Multisig consolidation input is missing redeem script".to_string())?;
    let sig_op_count = first.sig_op_count;
    if inputs.iter().any(|input| {
        input.sig_op_count != sig_op_count
            || input.redeem_script.as_ref().map(Vec::len) != Some(redeem_script_len)
    }) {
        return Err("Multisig consolidation inputs have inconsistent signing shape".to_string());
    }
    let destination_script_len =
        crate::account::address::address_to_script_pubkey(destination_address)?.len();
    multisig_standard_fee_for_shape(
        descriptor.threshold(),
        redeem_script_len,
        sig_op_count,
        inputs.len(),
        destination_script_len,
        P2SH_SCRIPT_PUBLIC_KEY_LEN,
        requested_fee,
    )
}

struct ConsolidationOutputRequest<'a> {
    source_address: &'a str,
    destination_address: &'a str,
    amount: u64,
    change: u64,
    cosigner: u32,
    change_index_hint: u32,
    websocket_url: &'a str,
}

async fn consolidation_outputs(
    descriptor: &MultisigDescriptor,
    request: ConsolidationOutputRequest<'_>,
) -> Result<Vec<PlannedOutput>, String> {
    let destination_script =
        crate::account::address::address_to_script_pubkey(request.destination_address)?;
    let mut outputs = vec![PlannedOutput::new(request.amount, destination_script)];
    append_consolidation_change(
        descriptor,
        ConsolidationChangeRequest {
            source_address: request.source_address,
            prefix: address_prefix(request.source_address),
            cosigner: request.cosigner,
            change_index_hint: request.change_index_hint,
            websocket_url: request.websocket_url,
            change: request.change,
        },
        &mut outputs,
    )
    .await?;
    Ok(outputs)
}

pub(super) type ResolvedConsolidationSources =
    std::collections::HashMap<String, (Vec<u8>, serde_json::Value, u8)>;

fn require_hd45_consolidation(descriptor: &MultisigDescriptor) -> Result<(), String> {
    if descriptor.is_hd45() {
        return Ok(());
    }
    Err("Multi-address consolidation requires a multi_hd45 descriptor".into())
}

pub(super) fn parse_consolidation_sources(
    sources_json: &str,
) -> Result<Vec<MultisigConsolidationSource>, String> {
    let sources: Vec<MultisigConsolidationSource> =
        serde_json::from_str(sources_json).map_err(|error| format!("sources_json: {error}"))?;
    require_source_count(sources.len())?;
    Ok(sources)
}

pub(super) fn require_source_count(count: usize) -> Result<(), String> {
    if (1..=3).contains(&count) {
        return Ok(());
    }
    Err("Select between 1 and 3 multisig UTXOs".into())
}

pub(super) fn resolve_consolidation_sources(
    descriptor: &MultisigDescriptor,
    sources: &[MultisigConsolidationSource],
    cosigner: u32,
) -> Result<ResolvedConsolidationSources, String> {
    let mut resolved = ResolvedConsolidationSources::new();
    for source in sources {
        resolve_consolidation_source_once(descriptor, source, cosigner, &mut resolved)?;
    }
    Ok(resolved)
}

fn resolve_consolidation_source_once(
    descriptor: &MultisigDescriptor,
    source: &MultisigConsolidationSource,
    cosigner: u32,
    resolved: &mut ResolvedConsolidationSources,
) -> Result<(), String> {
    if resolved.contains_key(&source.address) {
        return Ok(());
    }
    let material = resolve_consolidation_source(descriptor, source, cosigner)?;
    resolved.insert(source.address.clone(), material);
    Ok(())
}

fn resolve_consolidation_source(
    descriptor: &MultisigDescriptor,
    source: &MultisigConsolidationSource,
    cosigner: u32,
) -> Result<(Vec<u8>, serde_json::Value, u8), String> {
    let path = resolve_address_path(descriptor, &source.address, MULTISIG_BRANCH_SCAN_DEPTH)?;
    if path.cosigner != cosigner {
        return Err("Selected source belongs to a different cosigner branch".into());
    }
    let keys = descriptor.public_keys_at(path.index, path.cosigner, path.chain)?;
    let redeem = build_redeem_script(descriptor.threshold(), &keys)?;
    let derivations = descriptor.bip32_derivations(path.index, path.cosigner, path.chain)?;
    Ok((redeem, derivations, keys.len() as u8))
}

pub(super) fn unique_source_addresses(sources: &[MultisigConsolidationSource]) -> Vec<String> {
    let mut addresses = sources
        .iter()
        .map(|source| source.address.clone())
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    addresses
}

pub(super) fn build_consolidation_inputs(
    sources: &[MultisigConsolidationSource],
    available: &[crate::UtxoEntry],
    resolved: &ResolvedConsolidationSources,
) -> Result<(Vec<PlannedInput>, u64), String> {
    let mut inputs = Vec::with_capacity(sources.len());
    let mut total = 0u64;
    for source in sources {
        let (input, amount) = build_consolidation_input(source, available, resolved)?;
        total = total
            .checked_add(amount)
            .ok_or("selected multisig total overflow".to_string())?;
        inputs.push(input);
    }
    Ok((inputs, total))
}

fn build_consolidation_input(
    source: &MultisigConsolidationSource,
    available: &[crate::UtxoEntry],
    resolved: &ResolvedConsolidationSources,
) -> Result<(PlannedInput, u64), String> {
    let utxo = find_selected_utxo(source, available)?;
    let amount = utxo.amount;
    let (redeem, derivations, sigops) = resolved
        .get(&source.address)
        .ok_or("unresolved multisig source".to_string())?;
    Ok((
        PlannedInput::p2sh_multisig(utxo, redeem, *sigops)
            .with_bip32_derivations(derivations.clone()),
        amount,
    ))
}

fn find_selected_utxo(
    source: &MultisigConsolidationSource,
    available: &[crate::UtxoEntry],
) -> Result<crate::UtxoEntry, String> {
    for utxo in available {
        if utxo.tx_id == source.tx_id && utxo.index == source.index {
            return Ok(utxo.clone());
        }
    }
    Err(format!("UTXO {}:{} not found", source.tx_id, source.index))
}

pub(super) fn required_total(amount: u64, fee: u64) -> Result<u64, String> {
    amount
        .checked_add(fee)
        .ok_or("multisig required amount overflow".to_string())
}

pub(super) fn consolidation_change(total: u64, required: u64) -> Result<u64, String> {
    total
        .checked_sub(required)
        .ok_or_else(|| "selected multisig total is below required total".to_string())
}
pub(super) fn require_selected_total(total: u64, required: u64) -> Result<(), String> {
    if total >= required {
        return Ok(());
    }
    Err(format!("Selected {total} sompi but need {required}"))
}

pub(super) struct ConsolidationChangeRequest<'a> {
    pub source_address: &'a str,
    pub prefix: &'a str,
    pub cosigner: u32,
    pub change_index_hint: u32,
    pub websocket_url: &'a str,
    pub change: u64,
}

pub(super) async fn append_consolidation_change(
    descriptor: &MultisigDescriptor,
    request: ConsolidationChangeRequest<'_>,
    outputs: &mut Vec<PlannedOutput>,
) -> Result<(), String> {
    if !should_append_change(request.change) {
        return Ok(());
    }
    let output = consolidation_change_output(
        descriptor,
        request.source_address,
        request.prefix,
        request.cosigner,
        request.change_index_hint,
        request.websocket_url,
        request.change,
    )
    .await?;
    outputs.push(output);
    Ok(())
}

fn should_append_change(change: u64) -> bool {
    change != 0 && !amounts::is_dust(change)
}

async fn consolidation_change_output(
    descriptor: &MultisigDescriptor,
    source_address: &str,
    prefix: &str,
    cosigner: u32,
    change_index_hint: u32,
    websocket_url: &str,
    change: u64,
) -> Result<PlannedOutput, String> {
    let change_index = resolve_change_index(
        descriptor,
        source_address,
        cosigner,
        change_index_hint,
        websocket_url,
    )
    .await?;
    let keys = descriptor.public_keys_at(change_index, cosigner, 1)?;
    let redeem = build_redeem_script(descriptor.threshold(), &keys)?;
    let address = crate::protocol::script::p2sh::script_to_address(&redeem, prefix)?;
    let script = crate::account::address::address_to_script_pubkey(&address)?;
    let derivations = descriptor.bip32_derivations(change_index, cosigner, 1)?;
    Ok(PlannedOutput::new(change, script).with_bip32_derivations(derivations))
}

pub(super) async fn resolve_change_index(
    descriptor: &MultisigDescriptor,
    source_address: &str,
    cosigner: u32,
    change_index_hint: u32,
    websocket_url: &str,
) -> Result<u32, String> {
    if change_index_hint != u32::MAX {
        return Ok(change_index_hint);
    }
    next_change_index(
        descriptor,
        cosigner,
        MULTISIG_BRANCH_SCAN_DEPTH,
        websocket_url,
        source_address,
    )
    .await
}
