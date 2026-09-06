use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::account::bip32::WalletData;

use super::utxo::UtxoEntry;

#[derive(Debug, Serialize, Deserialize)]
pub struct BalanceInfo {
    #[serde(with = "crate::serialization::decimal_u64")]
    pub total_sompi: u64,
    pub total_kas: f64,
    pub utxo_count: usize,
    pub funded_addresses: usize,
    pub funded_receive_indices: Vec<usize>,
    pub funded_change_indices: Vec<usize>,
}

/// Summarize wallet ownership from an already-fetched UTXO set.
pub fn summarize_balance(wallet: &WalletData, utxos: &[UtxoEntry]) -> Result<BalanceInfo, String> {
    let total_sompi = utxos.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.amount)
            .ok_or("Wallet balance exceeds supported monetary range".to_string())
    })?;
    let funded_scripts: HashSet<Vec<u8>> = utxos
        .iter()
        .map(|entry| entry.script_public_key.clone())
        .collect();

    let funded_receive_indices = wallet
        .receive_addresses
        .iter()
        .enumerate()
        .filter_map(|(index, address)| {
            crate::account::address::address_to_script_pubkey(address)
                .ok()
                .filter(|script| funded_scripts.contains(script))
                .map(|_| index)
        })
        .collect::<Vec<_>>();

    let funded_change_indices = wallet
        .change_addresses
        .iter()
        .enumerate()
        .filter_map(|(index, address)| {
            crate::account::address::address_to_script_pubkey(address)
                .ok()
                .filter(|script| funded_scripts.contains(script))
                .map(|_| index)
        })
        .collect::<Vec<_>>();

    Ok(BalanceInfo {
        total_sompi,
        total_kas: total_sompi as f64 / 100_000_000.0,
        utxo_count: utxos.len(),
        funded_addresses: funded_scripts.len(),
        funded_receive_indices,
        funded_change_indices,
    })
}
