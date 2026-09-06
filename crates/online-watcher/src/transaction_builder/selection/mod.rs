mod automatic;
mod consolidation;
mod explicit;

pub use automatic::select_automatic_with_limit;
pub use consolidation::select_for_consolidation;
pub use explicit::select_explicit;

use core::cmp::Reverse;

use crate::account::utxo::UtxoEntry;

pub fn sort_largest_first(utxos: &mut [UtxoEntry]) {
    utxos.sort_by_key(|utxo| Reverse(utxo.amount));
}

pub fn sort_smallest_first(utxos: &mut [UtxoEntry]) {
    utxos.sort_by_key(|utxo| utxo.amount);
}

pub fn sort_for_display(utxos: &mut [UtxoEntry]) {
    utxos.sort_by(|left, right| {
        right
            .amount
            .cmp(&left.amount)
            .then_with(|| left.tx_id.cmp(&right.tx_id))
            .then_with(|| left.index.cmp(&right.index))
    });
}

pub fn checked_total(utxos: &[UtxoEntry]) -> Result<u64, String> {
    utxos.iter().try_fold(0u64, |total, utxo| {
        total
            .checked_add(utxo.amount)
            .ok_or_else(|| "UTXO total exceeds supported monetary range".to_string())
    })
}
