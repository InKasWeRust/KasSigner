use crate::account::utxo::UtxoEntry;

use super::sort_largest_first;

pub fn select_for_consolidation(
    mut utxos: Vec<UtxoEntry>,
    maximum_inputs: usize,
) -> Result<Vec<UtxoEntry>, String> {
    match utxos.len() {
        0 => return Err("No UTXOs to consolidate".into()),
        1 => return Err("Only 1 UTXO — nothing to consolidate".into()),
        _ => {}
    }
    sort_largest_first(&mut utxos);
    Ok(utxos.into_iter().take(maximum_inputs).collect())
}
