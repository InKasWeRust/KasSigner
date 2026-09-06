//! Shared account export and filename preparation.

use crate::runtime::data::AppData;

pub(crate) fn derive_watch_account(
    ad: &mut AppData,
    checkpoint: &mut dyn FnMut(),
) -> Result<(), &'static str> {
    let parent_fingerprint = ad.wallet.seeds.seed_mgr.active_slot()
        .ok_or("No active wallet")?.account_parent_fingerprint;
    let account = crate::runtime::signing::derive_active_account_key_with_checkpoint(ad, checkpoint)?;
    let mut encoded = [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN];
    let result = offline_signer::derivation::xpub::serialize_account_kpub(
        &account, parent_fingerprint, &mut encoded,
    )
    .map_err(|_| "kpub serialization failed");
    match result {
        Ok(length) => {
            ad.export.kpub_data[..length].copy_from_slice(&encoded[..length]);
            ad.export.kpub_len = length;
            shared_signer::bytes::zeroize_bytes(&mut encoded);
            Ok(())
        }
        Err(error) => {
            shared_signer::bytes::zeroize_bytes(&mut encoded);
            Err(error)
        }
    }
}

pub(super) fn prepare_filename(ad: &mut AppData, name: [u8; 11]) {
    ad.storage.export_file.filename = name;
    ad.wallet.seeds.pp_input.reset();
    for byte in name[..8].iter().copied().filter(|byte| *byte != b' ') {
        ad.wallet.seeds.pp_input.push_char(byte);
    }
}
