// KasSigner — Air-gapped offline signing device for Kaspa
//! Signing state-machine orchestration. Each loop iteration signs one input so
//! the progress UI reflects real cryptographic work for large transactions.

use crate::hw::display;
use crate::runtime::data::AppData;

use super::{kspt, output, pskt, strategy};

pub(super) fn prepare_anti_klepto_commitment(ad: &mut AppData) {
    use crate::runtime::data::AntiKleptoPhase;
    if ad.signing.anti_klepto.phase != AntiKleptoPhase::Reviewing { return; }
    let records = match offline_signer::transaction::kspt::nonce_commitment_records(
        &ad.signing.transaction.active,
        &ad.signing.anti_klepto.initial_sig_counts,
    ) {
        Ok(records) => records,
        Err(error) => {
            log!("   ✗ Anti-klepto nonce commitment failed: {:?}", error);
            reject_signing(ad);
            return;
        }
    };
    let required = 128usize.saturating_add(records.len().saturating_mul(96));
    if ad.qr.outgoing.ensure_len(required).is_err() {
        reject_signing(ad);
        return;
    }
    let session_id = ad.signing.anti_klepto.session_id;
    let transaction_digest = ad.signing.anti_klepto.transaction_digest;
    match shared_signer::anti_klepto::encode_commitment(
        &session_id,
        &transaction_digest,
        &records,
        &mut ad.qr.outgoing.buffer,
    ) {
        Ok(length) => {
            ad.qr.outgoing.length = length;
            ad.signing.anti_klepto.phase = AntiKleptoPhase::AwaitingReveal;
            log!("   → anti-klepto nonce commitment: {} proof(s)", records.len());
        }
        Err(error) => {
            log!("   ✗ Anti-klepto commitment encoding failed: {:?}", error);
            reject_signing(ad);
        }
    }
}

#[inline(never)]
pub fn handle_signing_operation_step(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    persistence: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    use crate::runtime::data::OperationKind;
    if !crate::runtime::presentation::operation_active(ad, OperationKind::SignTransaction) { return; }
    let input_idx = crate::runtime::presentation::operation_cursor(ad);
    if reject_missing_seed(ad) { return; }
    if input_idx >= ad.signing.transaction.active.num_inputs { reject_signing(ad); return; }

    let Some(policy_now) = authorize_policy_time(ad, i2c, persistence) else {
        rollback_session(ad);
        return;
    };
    if !authorize_review(ad, input_idx) { rollback_session(ad); return; }
    if input_idx == 0 {
        let counts = offline_signer::transaction::kspt::initial_signature_counts(&ad.signing.transaction.active);
        ad.signing.transaction.initial_signature_counts.clear();
        ad.signing.transaction.initial_signature_counts.extend_from_slice(
            &counts[..ad.signing.transaction.active.num_inputs],
        );
    }

    log!("   Signing input {}/{}...", input_idx + 1, ad.navigation.app.total_inputs);
    // Draw progress before cryptographic work begins so large input sets never
    // look frozen while one input is being processed.
    boot_display.draw_signing_screen(input_idx, ad.navigation.app.total_inputs);
    liveness();
    if !sign_one_input(ad, input_idx, liveness) {
        rollback_session(ad);
        return;
    }
    let completed = input_idx.saturating_add(1);
    let total = ad.signing.transaction.active.num_inputs.max(1);
    let progress = completed.saturating_mul(100) / total;
    crate::runtime::presentation::set_progress(ad, progress.min(100) as u8);

    let is_final = input_idx + 1 == ad.signing.transaction.active.num_inputs;
    liveness();
    if is_final && !finish_transaction(ad, boot_display, liveness) {
        rollback_session(ad);
        return;
    }
    if is_final && !persist_policy_floor(ad, delay, i2c, persistence, policy_now) {
        return;
    }
    advance_after_signing(ad);
}

#[inline(never)]
fn sign_one_input(ad: &mut AppData, input_idx: usize, liveness: &mut (impl FnMut() + ?Sized)) -> bool {
    let Some(signing_strategy) = strategy::select(ad) else { reject_signing(ad); return false; };
    let mut signing_entropy = [0u8; 32];
    if let Err(error) = crate::crypto::entropy::fill(&mut signing_entropy) {
        log!("   ✗ Signing entropy refused: {}", error.message());
        reject_signing_with(ad, crate::runtime::presentation::SIGN_ENTROPY);
        return false;
    }
    liveness();
    log!("   Signing input {} crypto BEGIN", input_idx + 1);
    let result = kspt::sign_input(ad, signing_strategy, input_idx, &signing_entropy, liveness);
    shared_signer::bytes::zeroize_bytes(&mut signing_entropy);
    log!("   Signing input {} crypto DONE ok={}", input_idx + 1, result.is_ok());
    if let Err(error) = result {
        log!("   ✗ Input {} signing failed: {:?}", input_idx, error);
        reject_signing_with(ad, crate::runtime::presentation::SIGN_INPUT);
        return false;
    }
    true
}

#[inline(never)]
fn finish_transaction(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    liveness: &mut (impl FnMut() + ?Sized),
) -> bool {
    output::reset(ad);
    boot_display.draw_saving_screen("Finalizing TX...");
    liveness();
    if ad.signing.transaction.input_format.is_pskt() {
        if !pskt::serialize_transaction(ad) { return false; }
    } else if ad.signing.anti_klepto.phase == crate::runtime::data::AntiKleptoPhase::Reviewing {
        prepare_anti_klepto_commitment(ad);
    } else if !kspt::serialize_transaction(ad) {
        return false;
    }
    liveness();
    output::log_response(ad);
    if ad.qr.outgoing.length == 0 {
        return false;
    }
    ad.qr.outgoing.purpose = if anti_klepto_is_pending(ad) {
        crate::runtime::data::OutgoingQrPurpose::AntiKlepto
    } else {
        crate::runtime::data::OutgoingQrPurpose::SignedTransaction
    };
    true
}

fn reject_missing_seed(ad: &mut AppData) -> bool {
    if ad.wallet.seeds.seed_loaded { return false; }
    reject_signing_with(ad, crate::runtime::presentation::SIGN_KEY);
    true
}

fn authorize_policy_time(
    ad: &mut AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    persistence: &crate::services::persistent_wallet::PersistentWallet<'_>,
) -> Option<Option<u64>> {
    match crate::services::signing_policy::authorize_transaction_time(
        persistence.signing_policy(), persistence.security_integrity_ok(), i2c,
    ) {
        Ok(value) => Some(value),
        Err(error) => {
            log!("   ✗ Signing policy refused: {}", error.message());
            reject_signing_with(ad, crate::runtime::presentation::SIGN_POLICY);
            None
        }
    }
}

fn authorize_review(ad: &mut AppData, input_idx: usize) -> bool {
    let authorization = signer_firmware_core::security::SigningAuthorization {
        seed_loaded: ad.wallet.seeds.seed_loaded,
        review_authorized: ad.navigation.app.review_authorized,
        reviewed_inputs: ad.navigation.app.total_inputs,
        transaction_inputs: ad.signing.transaction.active.num_inputs,
        signing_input_index: input_idx,
    };
    let Err(error) = signer_firmware_core::security::authorize_transaction_signing(authorization) else { return true; };
    log!("   ✗ Signing authorization refused: {:?}", error);
    reject_signing_with(ad, crate::runtime::presentation::SIGN_REVIEW);
    false
}

fn persist_policy_floor(
    ad: &mut AppData,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    persistence: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    policy_now: Option<u64>,
) -> bool {
    if ad.qr.outgoing.length == 0 { return true; }
    let Some(now_unix) = policy_now else { return true; };
    if anti_klepto_is_pending(ad) { return true; }
    if persistence.record_rtc_floor(now_unix, &ad.wallet.seeds.seed_mgr, i2c, delay).is_ok() {
        persistence.refresh_security_mirror(ad);
        return true;
    }
    rollback_session(ad);
    ad.qr.outgoing.length = 0;
    ad.signing.anti_klepto.reset();
    reject_signing_with(ad, crate::runtime::presentation::POLICY_SAVE);
    false
}

pub(super) fn rollback_session(ad: &mut AppData) {
    if !ad.signing.transaction.initial_signature_counts.is_empty() {
        let mut counts = [0u8; offline_signer::transaction::model::MAX_INPUTS];
        let count = ad.signing.transaction.initial_signature_counts.len().min(counts.len());
        counts[..count].copy_from_slice(&ad.signing.transaction.initial_signature_counts[..count]);
        super::rollback_added_signatures(ad, &counts[..count]);
        ad.signing.transaction.initial_signature_counts.fill(0);
        ad.signing.transaction.initial_signature_counts.clear();
    }
}

fn anti_klepto_is_pending(ad: &AppData) -> bool {
    ad.signing.anti_klepto.phase == crate::runtime::data::AntiKleptoPhase::AwaitingReveal
}

fn reject_signing(ad: &mut AppData) {
    reject_signing_with(ad, crate::runtime::presentation::SIGN_FINALIZE);
}

fn reject_signing_with(ad: &mut AppData, error: crate::runtime::presentation::ErrorSpec) {
    ad.qr.outgoing.length = 0;
    ad.navigation.app.review_authorized = false;
    if crate::runtime::presentation::operation_active(
        ad, crate::runtime::data::OperationKind::SignTransaction,
    ) {
        crate::runtime::presentation::fail_recoverable_spec(ad, error);
    } else {
        crate::runtime::presentation::show_error_spec(ad, error);
    }
}

pub(super) fn advance_after_signing(ad: &mut AppData) {
    crate::runtime::navigation::advance_signing(ad);
    ad.runtime.needs_redraw = true;
}

/// Cancel a cooperative signing operation before the hardware watchdog fires.
/// Any signatures added during the current session are rolled back first.
pub(super) fn cancel_signing_operation(ad: &mut AppData) {
    rollback_session(ad);
    ad.navigation.app.review_authorized = false;
    ad.qr.outgoing.length = 0;
}
