//! Typed parsing/selection for global-thread PSKB requests.
//!
//! These validations are transaction-domain concerns, not browser/WASM concerns.

use serde::Deserialize;

use crate::account::utxo::UtxoEntry;

pub(crate) fn decode_redeem_script(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|error| format!("Bad redeem hex: {error}"))
}

pub(crate) fn decode_covenant_id(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("Bad covenant_id hex: {error}"))?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| "covenant_id not 32 bytes".to_string())
}

#[derive(Deserialize)]
struct ThreadUtxoJson {
    tx_id: String,
    index: u64,
    #[serde(with = "crate::serialization::decimal_u64")]
    amount: u64,
    #[serde(default, with = "crate::serialization::decimal_u64")]
    block_daa_score: u64,
}

impl ThreadUtxoJson {
    fn into_entry(self) -> Result<UtxoEntry, String> {
        if self.tx_id.is_empty() || self.amount == 0 {
            return Err("Invalid thread UTXO".to_string());
        }
        if self.tx_id.len() != 64 || hex::decode(&self.tx_id).is_err() {
            return Err("Thread UTXO tx_id must be 32-byte hex".to_string());
        }
        Ok(UtxoEntry {
            tx_id: self.tx_id,
            index: u32::try_from(self.index)
                .map_err(|_| "Thread UTXO index exceeds u32".to_string())?,
            amount: self.amount,
            script_public_key: Vec::new(),
            block_daa_score: self.block_daa_score,
            covenant_id: None,
        })
    }
}

pub(crate) fn parse_withdrawal_thread_utxos(value: &str) -> Result<Vec<UtxoEntry>, String> {
    let parsed: Vec<ThreadUtxoJson> =
        serde_json::from_str(value).map_err(|error| format!("Bad selected UTXOs JSON: {error}"))?;
    if parsed.is_empty() {
        return Err("No thread UTXO selected".to_string());
    }
    parsed.into_iter().map(ThreadUtxoJson::into_entry).collect()
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn parse_thread_utxo(value: &str) -> Result<UtxoEntry, String> {
    serde_json::from_str::<ThreadUtxoJson>(value)
        .map_err(|error| format!("Bad thread UTXO JSON: {error}"))?
        .into_entry()
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn select_wallet_utxos(
    utxos: &[UtxoEntry],
    indices_csv: &str,
) -> Result<Vec<UtxoEntry>, String> {
    let indices = indices_csv
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .trim()
                .parse::<usize>()
                .map_err(|error| format!("Invalid UTXO index: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if indices.is_empty() {
        return Err("Select at least one wallet UTXO to fold into the thread".to_string());
    }
    indices
        .into_iter()
        .map(|index| {
            utxos
                .get(index)
                .cloned()
                .ok_or_else(|| format!("UTXO index {index} out of range (have {})", utxos.len()))
        })
        .collect()
}

#[cfg(test)]
mod unit_tests;
