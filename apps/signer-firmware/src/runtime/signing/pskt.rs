// KasSigner — Air-gapped offline signing device for Kaspa
//! Standard PSKT/PSKB serialization after the shared per-input signer runs.

pub(super) fn serialize_transaction(ad: &mut crate::runtime::data::AppData) -> bool {
    let scratch_copy = if ad.signing.transaction.pskt_parsed.unknowns_count > 0 {
        let length = usize::from(ad.signing.transaction.pskt_parsed.json_len);
        let Ok(mut copy) = crate::services::memory::zeroed_bytes(length) else { return false; };
        copy.copy_from_slice(&ad.qr.outgoing.buffer[..length]);
        Some(copy)
    } else {
        None
    };
    let scratch_json = scratch_copy.as_deref().unwrap_or(&[]);
    offline_signer::transaction::std_pskt::move_ksp_sigs_to_pskt(
        &mut ad.signing.transaction.active,
    );
    match offline_signer::transaction::std_pskt::serialize_pskt_vec(
        &ad.signing.transaction.active,
        &ad.signing.transaction.pskt_parsed,
        scratch_json,
        ad.signing.transaction.input_format,
    ) {
        Ok(wire) => {
            if ad.qr.outgoing.ensure_len(wire.len()).is_err() { return false; }
            ad.qr.outgoing.buffer[..wire.len()].copy_from_slice(&wire);
            ad.qr.outgoing.length = wire.len();
            super::signature_status::update_pskt(ad);
            true
        }
        Err(error) => {
            log!("[pskt] serialization failed: {:?}", error);
            ad.qr.outgoing.length = 0;
            false
        }
    }
}
