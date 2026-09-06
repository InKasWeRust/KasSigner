use std::collections::HashSet;

use crate::account::utxo::UtxoEntry;

use super::sort_for_display;

pub fn select_explicit(
    mut utxos: Vec<UtxoEntry>,
    indices: &[usize],
) -> Result<Vec<UtxoEntry>, String> {
    sort_for_display(&mut utxos);
    let mut seen = HashSet::with_capacity(indices.len());
    let mut selected = Vec::with_capacity(indices.len());

    for &index in indices {
        if !seen.insert(index) {
            return Err(format!("Duplicate UTXO index {}", index));
        }
        let utxo = utxos
            .get(index)
            .ok_or_else(|| format!("UTXO index {} out of range (have {})", index, utxos.len()))?;
        selected.push(utxo.clone());
    }

    Ok(selected)
}
