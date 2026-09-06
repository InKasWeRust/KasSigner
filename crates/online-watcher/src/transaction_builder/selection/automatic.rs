use crate::account::utxo::UtxoEntry;

use super::{checked_total, sort_largest_first};

pub fn select_automatic_with_limit(
    mut utxos: Vec<UtxoEntry>,
    required: u64,
    max_inputs: usize,
) -> Result<Vec<UtxoEntry>, String> {
    if max_inputs == 0 {
        return Err("UTXO selection limit must be at least 1".into());
    }
    sort_largest_first(&mut utxos);
    let mut selected = Vec::new();
    let mut total = 0u64;

    for utxo in utxos.into_iter().take(max_inputs) {
        total = total
            .checked_add(utxo.amount)
            .ok_or_else(|| "UTXO total exceeds supported monetary range".to_string())?;
        selected.push(utxo);
        if total >= required {
            return Ok(selected);
        }
    }

    let available = checked_total(&selected)?;
    Err(format!(
        "Insufficient funds within the current {}-UTXO selection limit: have {} sompi, need {} sompi. Raise the Advanced UTXO limit or choose UTXOs manually.",
        max_inputs, available, required,
    ))
}
