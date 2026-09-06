// KasSigner — Air-gapped offline signing device for Kaspa
//! KSPT per-input signing, serialization, and anti-klepto finalization.

use super::loaded_accounts::LoadedSigningAccounts;

/// Deterministic wrapper used only by boot known-answer tests.
#[cfg(any(test, all(feature = "m5stack", feature = "hardware-tests")))]
#[inline(never)]
pub fn sign_and_serialize_multi(
    tx: &mut offline_signer::transaction::model::Transaction,
    seed: &[u8; 64],
    buf: &mut [u8],
) -> Result<usize, offline_signer::transaction::kspt::PsktError> {
    offline_signer::transaction::kspt::sign_transaction_multi_addr(
        tx,
        seed,
        offline_signer::transaction::model::SigHashType::All,
    )?;
    offline_signer::transaction::kspt::serialize_compact_kspt(tx, buf)
}

#[inline(never)]
pub(super) fn sign_input(
    ad: &mut crate::runtime::data::AppData,
    strategy: super::strategy::SigningStrategy,
    input_index: usize,
    signing_entropy: &[u8; 32],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<(), offline_signer::transaction::kspt::PsktError> {
    use offline_signer::transaction::{kspt, model::SigHashType};
    match strategy {
        super::strategy::SigningStrategy::RawKey => {
            let mut key = [0u8; 32];
            let loaded = ad.wallet.seeds.seed_mgr.active_slot()
                .map(|slot| slot.raw_key_bytes(&mut key))
                .unwrap_or(false);
            if !loaded { return Err(kspt::PsktError::DerivationFailed); }
            checkpoint();
            let result = kspt::sign_matching_input_in_place_with_entropy(
                &mut ad.signing.transaction.active,
                input_index,
                &key,
                SigHashType::All,
                signing_entropy,
            );
            shared_signer::bytes::zeroize_bytes(&mut key);
            checkpoint();
            result.map(|_| ())
        }
        super::strategy::SigningStrategy::Multisig => {
            let mut accounts = LoadedSigningAccounts::derive_active(
                &ad.wallet.seeds.seed_mgr,
                checkpoint,
            );
            let result = kspt::sign_multisig_account_sets_input_with_entropy(
                &mut ad.signing.transaction.active,
                input_index,
                accounts.entries(),
                accounts.ms45_entries(),
                SigHashType::All,
                accounts.active_index(),
                signing_entropy,
            );
            accounts.zeroize();
            checkpoint();
            result.map(|_| ())
        }
        super::strategy::SigningStrategy::AccountKey | super::strategy::SigningStrategy::Mnemonic => {
            let account = ad.wallet.seeds.seed_mgr.active_slot()
                .ok_or(kspt::PsktError::DerivationFailed)
                .and_then(|slot| super::derivation::derive_slot_account_key_with_checkpoint(slot, checkpoint)
                    .map_err(|_| kspt::PsktError::DerivationFailed))?;
            checkpoint();
            let result = kspt::sign_account_input_with_entropy_checkpointed(
                &mut ad.signing.transaction.active,
                input_index,
                &account,
                SigHashType::All,
                signing_entropy,
                checkpoint,
            ).map(|_| ());
            checkpoint();
            result
        }
    }
}

pub(super) fn serialize_transaction(ad: &mut crate::runtime::data::AppData) -> bool {
    match offline_signer::transaction::kspt::serialize_compact_kspt_vec(
        &ad.signing.transaction.active,
    ) {
        Ok(wire) => {
            if ad.qr.outgoing.ensure_len(wire.len()).is_err() { return false; }
            ad.qr.outgoing.buffer[..wire.len()].copy_from_slice(&wire);
            ad.qr.outgoing.length = wire.len();
            super::signature_status::update_kspt(ad);
            true
        }
        Err(error) => {
            log!("[kspt] serialization failed: {:?}", error);
            ad.qr.outgoing.length = 0;
            false
        }
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn finalize_anti_klepto(
    ad: &mut crate::runtime::data::AppData,
    strategy: super::strategy::SigningStrategy,
    host_secret: &[u8; 32],
) -> Result<(), offline_signer::transaction::kspt::PsktError> {
    let mut no_checkpoint = || {};
    finalize_anti_klepto_with_checkpoint(ad, strategy, host_secret, &mut no_checkpoint)
}

pub(super) fn finalize_anti_klepto_with_checkpoint(
    ad: &mut crate::runtime::data::AppData,
    strategy: super::strategy::SigningStrategy,
    host_secret: &[u8; 32],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<(), offline_signer::transaction::kspt::PsktError> {
    let session_id = ad.signing.anti_klepto.session_id;
    let initial_counts = ad.signing.anti_klepto.initial_sig_counts;
    match strategy {
        super::strategy::SigningStrategy::RawKey => {
            let mut key = [0u8; 32];
            let loaded = ad.wallet.seeds.seed_mgr.active_slot()
                .map(|slot| slot.raw_key_bytes(&mut key))
                .unwrap_or(false);
            if !loaded { return Err(offline_signer::transaction::kspt::PsktError::DerivationFailed); }
            checkpoint();
            let result = offline_signer::transaction::kspt::finalize_raw_key_signatures(
                &mut ad.signing.transaction.active,
                &key,
                &initial_counts,
                &session_id,
                host_secret,
            );
            shared_signer::bytes::zeroize_bytes(&mut key);
            checkpoint();
            result.map(|_| ())
        }
        super::strategy::SigningStrategy::Multisig => {
            let mut accounts = LoadedSigningAccounts::derive_active(
                &ad.wallet.seeds.seed_mgr,
                checkpoint,
            );
            let result = offline_signer::transaction::kspt::finalize_account_set_signatures_with_checkpoint(
                &mut ad.signing.transaction.active,
                accounts.entries(),
                &initial_counts,
                &session_id,
                host_secret,
                checkpoint,
            );
            accounts.zeroize();
            checkpoint();
            result.map(|_| ())
        }
        super::strategy::SigningStrategy::AccountKey | super::strategy::SigningStrategy::Mnemonic => {
            let account = ad.wallet.seeds.seed_mgr.active_slot()
                .ok_or(offline_signer::transaction::kspt::PsktError::DerivationFailed)
                .and_then(|slot| super::derivation::derive_slot_account_key_with_checkpoint(slot, checkpoint)
                    .map_err(|_| offline_signer::transaction::kspt::PsktError::DerivationFailed))?;
            checkpoint();
            let result = offline_signer::transaction::kspt::finalize_account_signatures_with_checkpoint(
                &mut ad.signing.transaction.active,
                &account,
                &initial_counts,
                &session_id,
                host_secret,
                checkpoint,
            ).map(|_| ());
            checkpoint();
            result
        }
    }
}
