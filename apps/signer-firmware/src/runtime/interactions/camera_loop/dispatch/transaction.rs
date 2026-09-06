// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0

//! Camera transaction decoding delegates to the shared transaction-ingestion owner.

use super::super::AppData;

pub(super) fn process_kspt(
    data: &[u8],
    ad: &mut AppData,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    crate::runtime::interactions::tx::load_compact_transaction_with_checkpoint(data, ad, liveness);
}

pub(super) fn process_standard_pskt(
    data: &[u8],
    ad: &mut AppData,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    crate::runtime::interactions::tx::load_standard_transaction_with_checkpoint(data, ad, liveness);
}
