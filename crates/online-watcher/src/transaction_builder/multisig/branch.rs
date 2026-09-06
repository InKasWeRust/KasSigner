//! Receive/change discovery for v1.0.6 45' multisig branches.

use crate::multisig::{build_redeem_script, MultisigDescriptor};

use super::address_prefix;

#[derive(Clone, Debug, serde::Serialize)]
pub struct MultisigBranchUtxo {
    pub chain: u32,
    pub index: u32,
    pub address: String,
    pub tx_id: String,
    pub outpoint_index: u32,
    #[serde(with = "crate::serialization::decimal_u64")]
    pub amount: u64,
}

pub(super) type BranchAddress = (u32, u32, String);
pub(super) type BranchAddressMap = std::collections::HashMap<Vec<u8>, BranchAddress>;

pub(crate) async fn scan_branch_json(
    descriptor_text: &str,
    cosigner: u32,
    depth: u32,
    websocket_url: &str,
    address_prefix: &str,
) -> Result<String, String> {
    let descriptor = require_hd45_descriptor(descriptor_text)?;
    let depth = depth.min(100);
    let addresses = branch_addresses(&descriptor, cosigner, depth, address_prefix)?;
    let query = branch_query(&addresses);
    let utxos = crate::network::queries::utxos::fetch_for_addresses(websocket_url, &query).await?;
    finalize_branch_scan(
        &descriptor,
        cosigner,
        depth,
        address_prefix,
        &addresses,
        utxos,
    )
}

pub(super) fn finalize_branch_scan(
    descriptor: &MultisigDescriptor,
    cosigner: u32,
    depth: u32,
    address_prefix: &str,
    addresses: &[BranchAddress],
    utxos: Vec<crate::UtxoEntry>,
) -> Result<String, String> {
    let by_script = branch_address_map(addresses)?;
    let summary = summarize_branch_utxos(utxos, &by_script, depth)?;
    let next_receive_address = next_branch_address(
        descriptor,
        cosigner,
        0,
        &summary.receive_used,
        address_prefix,
    )?;
    let next_change_address = next_branch_address(
        descriptor,
        cosigner,
        1,
        &summary.change_used,
        address_prefix,
    )?;
    encode_branch_summary(
        summary,
        cosigner,
        depth,
        &next_receive_address,
        &next_change_address,
    )
}

fn next_branch_address(
    descriptor: &MultisigDescriptor,
    cosigner: u32,
    chain: u32,
    used: &[bool],
    address_prefix: &str,
) -> Result<String, String> {
    Ok(branch_address(
        descriptor,
        cosigner,
        chain,
        first_free(used),
        address_prefix,
    )?
    .2)
}

fn require_hd45_descriptor(descriptor_text: &str) -> Result<MultisigDescriptor, String> {
    let descriptor = MultisigDescriptor::parse(descriptor_text)?;
    if descriptor.is_hd45() {
        return Ok(descriptor);
    }
    Err("Branch scan requires a multi_hd45 descriptor".into())
}

pub(super) fn branch_addresses(
    descriptor: &MultisigDescriptor,
    cosigner: u32,
    depth: u32,
    prefix: &str,
) -> Result<Vec<BranchAddress>, String> {
    let mut result = Vec::with_capacity(depth as usize * 2);
    append_branch_addresses(&mut result, descriptor, cosigner, 0, depth, prefix)?;
    append_branch_addresses(&mut result, descriptor, cosigner, 1, depth, prefix)?;
    Ok(result)
}

fn append_branch_addresses(
    result: &mut Vec<BranchAddress>,
    descriptor: &MultisigDescriptor,
    cosigner: u32,
    chain: u32,
    depth: u32,
    prefix: &str,
) -> Result<(), String> {
    for index in 0..depth {
        result.push(branch_address(descriptor, cosigner, chain, index, prefix)?);
    }
    Ok(())
}

pub(super) fn branch_address(
    descriptor: &MultisigDescriptor,
    cosigner: u32,
    chain: u32,
    index: u32,
    prefix: &str,
) -> Result<BranchAddress, String> {
    let keys = descriptor.public_keys_at(index, cosigner, chain)?;
    let redeem = build_redeem_script(descriptor.threshold(), &keys)?;
    let address = crate::protocol::script::p2sh::script_to_address(&redeem, prefix)?;
    Ok((chain, index, address))
}

pub(super) fn branch_query(addresses: &[BranchAddress]) -> Vec<String> {
    addresses
        .iter()
        .map(|(_, _, address)| address.clone())
        .collect()
}

pub(super) fn branch_address_map(addresses: &[BranchAddress]) -> Result<BranchAddressMap, String> {
    let mut by_script = BranchAddressMap::new();
    for (chain, index, address) in addresses {
        by_script.insert(
            crate::account::address::address_to_script_pubkey(address)?,
            (*chain, *index, address.clone()),
        );
    }
    Ok(by_script)
}

pub(super) struct BranchSummary {
    pub(super) balance: u64,
    pub(super) labelled: Vec<MultisigBranchUtxo>,
    pub(super) receive_used: Vec<bool>,
    pub(super) change_used: Vec<bool>,
}

pub(super) fn summarize_branch_utxos(
    utxos: Vec<crate::UtxoEntry>,
    by_script: &BranchAddressMap,
    depth: u32,
) -> Result<BranchSummary, String> {
    let mut summary = BranchSummary {
        balance: 0,
        labelled: Vec::with_capacity(utxos.len()),
        receive_used: vec![false; depth as usize],
        change_used: vec![false; depth as usize],
    };
    for utxo in utxos {
        add_branch_utxo(&mut summary, utxo, by_script)?;
    }
    Ok(summary)
}

fn add_branch_utxo(
    summary: &mut BranchSummary,
    utxo: crate::UtxoEntry,
    by_script: &BranchAddressMap,
) -> Result<(), String> {
    let Some((chain, index, address)) = by_script.get(&utxo.script_public_key) else {
        return Ok(());
    };
    summary.balance = summary
        .balance
        .checked_add(utxo.amount)
        .ok_or("multisig branch balance overflow".to_string())?;
    mark_branch_used(summary, *chain, *index);
    summary.labelled.push(MultisigBranchUtxo {
        chain: *chain,
        index: *index,
        address: address.clone(),
        tx_id: utxo.tx_id,
        outpoint_index: utxo.index,
        amount: utxo.amount,
    });
    Ok(())
}

fn mark_branch_used(summary: &mut BranchSummary, chain: u32, index: u32) {
    let used = if chain == 0 {
        &mut summary.receive_used
    } else {
        &mut summary.change_used
    };
    if let Some(slot) = used.get_mut(index as usize) {
        *slot = true;
    }
}

pub(super) fn first_free(used: &[bool]) -> u32 {
    used.iter().position(|value| !*value).unwrap_or(used.len()) as u32
}

pub(super) fn encode_branch_summary(
    summary: BranchSummary,
    cosigner: u32,
    depth: u32,
    next_receive_address: &str,
    next_change_address: &str,
) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "balance_sompi": summary.balance.to_string(),
        "utxo_count": summary.labelled.len(),
        "utxos": summary.labelled,
        "next_receive_index": first_free(&summary.receive_used),
        "next_receive_address": next_receive_address,
        "next_change_index": first_free(&summary.change_used),
        "next_change_address": next_change_address,
        "cosigner_index": cosigner,
        "depth": depth,
    }))
    .map_err(|error| error.to_string())
}

pub(super) async fn next_change_index(
    descriptor: &MultisigDescriptor,
    cosigner: u32,
    depth: u32,
    websocket_url: &str,
    source_address: &str,
) -> Result<u32, String> {
    let change =
        change_branch_addresses(descriptor, cosigner, depth, address_prefix(source_address))?;
    let query = branch_query(&change);
    let utxos = crate::network::queries::utxos::fetch_for_addresses(websocket_url, &query).await?;
    first_unused_change_index(&change, &utxos, depth)
}

pub(super) fn change_branch_addresses(
    descriptor: &MultisigDescriptor,
    cosigner: u32,
    depth: u32,
    prefix: &str,
) -> Result<Vec<BranchAddress>, String> {
    let mut change = Vec::with_capacity(depth as usize);
    append_branch_addresses(&mut change, descriptor, cosigner, 1, depth, prefix)?;
    Ok(change)
}

pub(super) fn first_unused_change_index(
    change: &[BranchAddress],
    utxos: &[crate::UtxoEntry],
    depth: u32,
) -> Result<u32, String> {
    let used_scripts = used_script_set(utxos);
    for (_, index, address) in change {
        let script = crate::account::address::address_to_script_pubkey(address)?;
        if !used_scripts.contains(&script) {
            return Ok(*index);
        }
    }
    Ok(depth)
}

fn used_script_set(utxos: &[crate::UtxoEntry]) -> std::collections::HashSet<Vec<u8>> {
    utxos
        .iter()
        .map(|utxo| utxo.script_public_key.clone())
        .collect()
}
