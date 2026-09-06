//! KasSee anti-klepto request/reveal QR workflow.

use super::super::AppData;
use crate::runtime::data::AntiKleptoPhase;

pub(super) fn process(
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    let input = &data[..len.min(data.len())];
    if let Ok(request) = shared_signer::anti_klepto::parse_request(input) {
        process_request(request, ad, liveness);
        return;
    }
    if let Ok((session_id, host_secret)) = shared_signer::anti_klepto::parse_reveal(input) {
        process_reveal(session_id, host_secret, ad, i2c, liveness);
        return;
    }
    reject(ad, "Invalid anti-klepto QR");
}


#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_process(data: &[u8], ad: &mut AppData) {
    if let Ok(request) = shared_signer::anti_klepto::parse_request(data) {
        workflow_process_request(request, ad);
        return;
    }
    if let Ok((session_id, host_secret)) = shared_signer::anti_klepto::parse_reveal(data) {
        workflow_process_reveal(session_id, host_secret, ad);
        return;
    }
    workflow_reject(ad);
}

#[cfg(feature = "workflow-test-auto")]
fn workflow_process_request(request: shared_signer::anti_klepto::Request<'_>, ad: &mut AppData) {
    ad.signing.anti_klepto.reset();
    match offline_signer::transaction::kspt::parse_compact_kspt(
        request.transaction,
        &mut ad.signing.transaction.active,
    ) {
        Ok(()) => {
            if offline_signer::transaction::kspt::validate_transaction_for_review(
                &ad.signing.transaction.active,
            )
            .is_err()
            {
                workflow_reject(ad);
                return;
            }
            if !ad.wallet.seeds.seed_mgr.network().matches_transaction_network(
                ad.signing.transaction.active.network,
            ) {
                workflow_reject(ad);
                return;
            }
            let initial_counts = offline_signer::transaction::kspt::initial_signature_counts(
                &ad.signing.transaction.active,
            );
            ad.signing.anti_klepto.begin(
                request.session_id,
                request.host_commitment,
                request.transaction_digest,
                initial_counts,
            );
            ad.signing.transaction.input_format = shared_signer::TxInputFormat::KsptCompact;
            let (present, required) = offline_signer::transaction::kspt::signature_status(
                &ad.signing.transaction.active,
            );
            ad.signing.transaction.signatures_present = present;
            ad.signing.transaction.signatures_required = required;
            if crate::runtime::signing::verify_transaction_output_ownership(ad).is_err() {
                workflow_reject(ad);
                return;
            }
            crate::runtime::effects::start_review(
                ad,
                ad.signing.transaction.active.num_outputs as u8,
                ad.signing.transaction.active.num_inputs,
            );
            crate::runtime::effects::redraw(ad);
        }
        Err(_) => workflow_reject(ad),
    }
}

#[cfg(feature = "workflow-test-auto")]
fn workflow_process_reveal(
    session_id: [u8; shared_signer::anti_klepto::SESSION_ID_LEN],
    mut host_secret: [u8; 32],
    ad: &mut AppData,
) {
    let result = validate_reveal(session_id, &host_secret, ad)
        .and_then(|()| finalize_reveal_signature(ad, &host_secret));
    shared_signer::bytes::zeroize_bytes(&mut host_secret);
    result
        .and_then(|()| build_final_response(ad))
        .map(|proof_count| present_final_response(ad, None, proof_count))
        .unwrap_or_else(|_| workflow_reject(ad));
}

#[cfg(feature = "workflow-test-auto")]
fn workflow_reject(ad: &mut AppData) {
    if ad.signing.anti_klepto.phase != AntiKleptoPhase::Inactive {
        let initial_counts = ad.signing.anti_klepto.initial_sig_counts;
        crate::runtime::signing::rollback_added_signatures(ad, &initial_counts);
    }
    ad.signing.anti_klepto.reset();
    ad.qr.outgoing.length = 0;
    if !crate::runtime::navigation::workflow_reject_scanned_transaction(ad) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(Rejected));
    }
    crate::runtime::effects::keep_frame(ad);
}

fn process_request(
    request: shared_signer::anti_klepto::Request<'_>,
    ad: &mut AppData,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    ad.signing.anti_klepto.reset();
    match offline_signer::transaction::kspt::parse_compact_kspt(
        request.transaction,
        &mut ad.signing.transaction.active,
    ) {
        Ok(()) => {
            if let Err(error) = offline_signer::transaction::kspt::validate_transaction_for_review(
                &ad.signing.transaction.active,
            ) {
                log!("   → anti-klepto review validation error: {:?}", error);
                reject(ad, "Invalid transaction amounts");
                return;
            }
            if !ad.wallet.seeds.seed_mgr.network().matches_transaction_network(
                ad.signing.transaction.active.network,
            ) {
                reject(ad, "Transaction network does not match selected network");
                return;
            }
            let initial_counts = offline_signer::transaction::kspt::initial_signature_counts(
                &ad.signing.transaction.active,
            );
            ad.signing.anti_klepto.begin(
                request.session_id,
                request.host_commitment,
                request.transaction_digest,
                initial_counts,
            );
            ad.signing.transaction.input_format = shared_signer::TxInputFormat::KsptCompact;
            let (present, required) = offline_signer::transaction::kspt::signature_status(
                &ad.signing.transaction.active,
            );
            ad.signing.transaction.signatures_present = present;
            ad.signing.transaction.signatures_required = required;
            if let Err(message) = crate::runtime::signing::verify_transaction_output_ownership_with_checkpoint(ad, liveness) {
                log!("   → anti-klepto ownership verification error: {}", message);
                reject_ownership(ad, message);
                return;
            }
            let review_outputs = ad.signing.transaction.active.num_outputs as u8;
            let review_inputs = ad.signing.transaction.active.num_inputs;
            crate::runtime::effects::start_review(ad, review_outputs, review_inputs);
            crate::runtime::effects::redraw(ad);
            log!("   → anti-klepto request: {} in, {} out, sigs {}/{}",
                ad.signing.transaction.active.num_inputs,
                ad.signing.transaction.active.num_outputs,
                present,
                required);
        }
        Err(error) => {
            log!("   → anti-klepto KSPT parse error: {:?}", error);
            reject(ad, "Invalid anti-klepto transaction");
        }
    }
}

fn process_reveal(
    session_id: [u8; shared_signer::anti_klepto::SESSION_ID_LEN],
    mut host_secret: [u8; 32],
    ad: &mut AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    liveness();
    let result = validate_reveal(session_id, &host_secret, ad);
    let result = result.and_then(|()| authorize_reveal_time(ad, i2c).map(|_| ()));
    let result = result.and_then(|()| finalize_reveal_signature_with_checkpoint(ad, &host_secret, liveness));
    shared_signer::bytes::zeroize_bytes(&mut host_secret);
    let result = result.and_then(|()| authorize_reveal_time(ad, i2c));
    let result = result.and_then(|final_policy_now| {
        build_final_response(ad).map(|proof_count| (final_policy_now, proof_count))
    });
    result
        .map(|(final_policy_now, proof_count)| {
            present_final_response(ad, final_policy_now, proof_count)
        })
        .unwrap_or_else(|message| reject(ad, message));
}

fn validate_reveal(
    session_id: [u8; shared_signer::anti_klepto::SESSION_ID_LEN],
    host_secret: &[u8; 32],
    ad: &AppData,
) -> Result<(), &'static str> {
    let session_matches = (ad.signing.anti_klepto.phase, ad.signing.anti_klepto.session_id)
        == (AntiKleptoPhase::AwaitingReveal, session_id);
    let secret_matches = shared_signer::anti_klepto::verify_host_secret(
        &ad.signing.anti_klepto.host_commitment,
        host_secret,
    );
    (session_matches && secret_matches)
        .then_some(())
        .ok_or("Anti-klepto reveal mismatch")
}

fn authorize_reveal_time(
    ad: &AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Result<Option<u64>, &'static str> {
    crate::services::signing_policy::authorize_transaction_time(
        ad.storage.persistence.advanced.policy,
        ad.storage.persistence.advanced.policy_integrity.is_valid(),
        i2c,
    )
    .map_err(|error| error.message())
}

#[cfg(feature = "workflow-test-auto")]
fn finalize_reveal_signature(ad: &mut AppData, host_secret: &[u8; 32]) -> Result<(), &'static str> {
    crate::runtime::signing::finalize_anti_klepto(ad, host_secret)
        .map_err(|_| "Anti-klepto finalization failed")
}

fn finalize_reveal_signature_with_checkpoint(
    ad: &mut AppData,
    host_secret: &[u8; 32],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<(), &'static str> {
    crate::runtime::signing::finalize_anti_klepto_with_checkpoint(ad, host_secret, checkpoint)
        .map_err(|_| "Anti-klepto finalization failed")
}

fn response_proofs(
    ad: &AppData,
) -> Result<alloc::vec::Vec<shared_signer::anti_klepto::SignatureProof>, &'static str> {
    offline_signer::transaction::kspt::proof_records(
        &ad.signing.transaction.active,
        &ad.signing.anti_klepto.initial_sig_counts,
    )
    .map_err(|_| "Anti-klepto proof failed")
}

fn response_transaction(ad: &AppData) -> Result<alloc::vec::Vec<u8>, &'static str> {
    offline_signer::transaction::kspt::serialize_compact_kspt_vec(&ad.signing.transaction.active)
        .map_err(|_| "Signed transaction serialization failed")
}

fn encode_final_response(
    ad: &mut AppData,
    proofs: &[shared_signer::anti_klepto::SignatureProof],
    signed_tx: &[u8],
) -> Result<usize, &'static str> {
    let required = signed_tx
        .len()
        .saturating_add(proofs.len().saturating_mul(128))
        .saturating_add(128);
    ad.qr.outgoing
        .ensure_len(required)
        .map_err(|_| "Anti-klepto response too large")
        .and_then(|()| {
            shared_signer::anti_klepto::encode_signed(
                &ad.signing.anti_klepto.session_id,
                &ad.signing.anti_klepto.transaction_digest,
                proofs,
                signed_tx,
                &mut ad.qr.outgoing.buffer,
            )
            .map_err(|_| "Anti-klepto response too large")
        })
}

fn build_final_response(ad: &mut AppData) -> Result<usize, &'static str> {
    response_proofs(ad).and_then(|proofs| {
        response_transaction(ad).and_then(|signed_tx| {
            encode_final_response(ad, &proofs, &signed_tx).map(|length| {
                ad.qr.outgoing.length = length;
                proofs.len()
            })
        })
    })
}

fn persist_reveal_floor(ad: &mut AppData, final_policy_now: Option<u64>) {
    if let Some(now_unix) = final_policy_now {
        ad.storage.persistence.pending_rtc_floor_unix = now_unix;
    }
}

fn present_final_response(ad: &mut AppData, final_policy_now: Option<u64>, proof_count: usize) {
    persist_reveal_floor(ad, final_policy_now);
    ad.signing.anti_klepto.phase = AntiKleptoPhase::FinalResponse;
    ad.qr.outgoing.frame = 0;
    ad.qr.outgoing.frame_count = 0;
    ad.qr.outgoing.manual_frames = false;
    ad.qr.outgoing.purpose = crate::runtime::data::OutgoingQrPurpose::AntiKlepto;
    ad.qr.presentation.large = false;
    ad.qr.presentation.mode = 0;
    ad.qr.presentation.via_density = false;
    if !crate::runtime::qr_presentation::present_anti_klepto_final(ad) {
        reject(ad, "Anti-klepto final QR presentation failed");
        return;
    }
    crate::runtime::effects::redraw(ad);
    log!("   → anti-klepto final response: {} proof(s)", proof_count);
}

fn reject_ownership(ad: &mut AppData, message: &'static str) {
    if ad.signing.anti_klepto.phase != AntiKleptoPhase::Inactive {
        let initial_counts = ad.signing.anti_klepto.initial_sig_counts;
        crate::runtime::signing::rollback_added_signatures(ad, &initial_counts);
    }
    ad.signing.anti_klepto.reset();
    ad.qr.outgoing.length = 0;
    crate::log!("   Anti-klepto request rejected: {}", message);
    crate::runtime::presentation::show_error_spec_previous(
        ad,
        crate::runtime::presentation::TX_OWNERSHIP,
    );
}

fn reject(ad: &mut AppData, message: &'static str) {
    if ad.signing.anti_klepto.phase != AntiKleptoPhase::Inactive {
        let initial_counts = ad.signing.anti_klepto.initial_sig_counts;
        crate::runtime::signing::rollback_added_signatures(ad, &initial_counts);
    }
    ad.signing.anti_klepto.reset();
    ad.qr.outgoing.length = 0;
    crate::log!("   Anti-klepto request rejected: {}", message);
    crate::runtime::presentation::show_error_spec_previous(ad, crate::runtime::presentation::ANTI_KLEPTO);
}
