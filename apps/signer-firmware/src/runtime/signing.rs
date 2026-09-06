// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Runtime signing facade.
//! Derivation, transaction serialization, verification, signing orchestration,
//! and signed-QR cycling remain isolated behind one subsystem boundary.

mod derivation;
#[cfg(all(feature = "m5stack", not(feature = "hardware-tests")))]
pub(crate) use derivation::install_worker_address_cache;
#[cfg(all(feature = "m5stack", not(feature = "hardware-tests")))]
pub(crate) use derivation::begin_mnemonic_seed;
mod kspt;
mod loaded_accounts;
mod pskt;
mod qr;
mod output;
mod review;
mod signature_status;
mod strategy;
mod verification;
mod workflow;
#[cfg(feature = "workflow-test-auto")]
mod workflow_test;
#[cfg(any(test, all(feature = "m5stack", feature = "hardware-tests")))]
pub use kspt::sign_and_serialize_multi;
pub use derivation::{
    derive_active_account_key_with_checkpoint, derive_active_private_key_with_checkpoint, derive_active_seed_with_checkpoint,
    derive_change_pubkey_from_acct, derive_pubkey_from_acct, derive_slot_pubkeys_with_checkpoint,
    populate_active_pubkeys_with_checkpoint, serialize_active_xprv_with_checkpoint,
};
#[cfg(feature = "workflow-test-auto")]
pub use derivation::{derive_active_account_key, derive_active_seed};
#[cfg(feature = "waveshare")]
pub(crate) use derivation::{begin_active_kpub_derivation, finish_active_kpub_derivation, stage_active_kpub_account_derivation, KpubDerivationStart};
#[cfg(feature = "workflow-test-auto")]
pub(crate) use derivation::derive_slot_seed;
pub(crate) use derivation::zeroize_seed;
#[cfg(all(feature = "workflow-test-auto", not(feature = "workflow-runtime-auto")))]
pub(crate) use derivation::install_workflow_receive_fixture;
#[cfg(all(not(feature = "hardware-tests"), not(feature = "workflow-test-auto")))]
pub use qr::cycle_signed_qr;
pub use verification::run_firmware_verify;
#[cfg(not(feature = "hardware-tests"))]
pub use workflow::handle_signing_operation_step;
#[cfg(feature = "workflow-test-auto")]
pub(crate) use workflow_test::{
    workflow_activate_signing_operation, workflow_signing_step, workflow_signing_step_with_policy,
};
pub use review::{
    ReviewTotals, totals as transaction_review_totals,
    verify_transaction_output_ownership_with_checkpoint,
};
#[cfg(feature = "workflow-test-auto")]
pub use review::verify_transaction_output_ownership;
pub(crate) use signature_status::rollback_added_signatures;
pub(crate) fn cancel_active_signing_operation(ad: &mut crate::runtime::data::AppData) {
    workflow::cancel_signing_operation(ad);
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn finalize_anti_klepto(
    ad: &mut crate::runtime::data::AppData,
    host_secret: &[u8; 32],
) -> Result<(), offline_signer::transaction::kspt::PsktError> {
    let strategy = strategy::select(ad)
        .ok_or(offline_signer::transaction::kspt::PsktError::DerivationFailed)?;
    kspt::finalize_anti_klepto(ad, strategy, host_secret)
}

pub(crate) fn finalize_anti_klepto_with_checkpoint(
    ad: &mut crate::runtime::data::AppData,
    host_secret: &[u8; 32],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<(), offline_signer::transaction::kspt::PsktError> {
    let strategy = strategy::select(ad)
        .ok_or(offline_signer::transaction::kspt::PsktError::DerivationFailed)?;
    kspt::finalize_anti_klepto_with_checkpoint(ad, strategy, host_secret, checkpoint)
}
