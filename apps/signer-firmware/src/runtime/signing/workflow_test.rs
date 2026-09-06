// KasSigner — Air-gapped offline signing device for Kaspa
//! Connected workflow signing adapter. This module is compiled only into the
//! automated workflow image and deliberately excludes persistent RTC-policy I/O.

use crate::runtime::data::{AppData, OperationKind, OperationPhase};

use super::{kspt, output, pskt, strategy};

/// Execute one production signing transition with deterministic auxiliary
/// entropy for the connected workflow image. Persistent RTC-policy enforcement
/// is intentionally excluded here and covered by the dedicated policy/HIL
/// tranche; all key selection, authorization, per-input signing, serialization,
/// and navigation are the same production owners used by `handle_signing_operation_step`.
pub(crate) fn workflow_signing_step(ad: &mut AppData) -> bool {
    if !crate::runtime::presentation::operation_active(ad, OperationKind::SignTransaction)
        || !matches!(
            crate::runtime::presentation::operation_phase(ad),
            OperationPhase::Running | OperationPhase::Progress(_)
        )
    {
        return false;
    }
    let input_idx = crate::runtime::presentation::operation_cursor(ad);
    if !ad.wallet.seeds.seed_loaded || input_idx >= ad.signing.transaction.active.num_inputs {
        reject_workflow_signing(ad);
        return false;
    }
    let authorization = signer_firmware_core::security::SigningAuthorization {
        seed_loaded: ad.wallet.seeds.seed_loaded,
        review_authorized: ad.navigation.app.review_authorized,
        reviewed_inputs: ad.navigation.app.total_inputs,
        transaction_inputs: ad.signing.transaction.active.num_inputs,
        signing_input_index: input_idx,
    };
    if signer_firmware_core::security::authorize_transaction_signing(authorization).is_err() {
        reject_workflow_signing(ad);
        return false;
    }
    if input_idx == 0 {
        let counts = offline_signer::transaction::kspt::initial_signature_counts(&ad.signing.transaction.active);
        ad.signing.transaction.initial_signature_counts.clear();
        ad.signing.transaction.initial_signature_counts.extend_from_slice(
            &counts[..ad.signing.transaction.active.num_inputs],
        );
    }
    let Some(signing_strategy) = strategy::select(ad) else {
        reject_workflow_signing(ad);
        return false;
    };
    let signing_entropy = [0x5au8; 32];
    let mut checkpoint = || {};
    if kspt::sign_input(ad, signing_strategy, input_idx, &signing_entropy, &mut checkpoint).is_err() {
        super::workflow::rollback_session(ad);
        reject_workflow_signing(ad);
        return false;
    }
    let completed = input_idx.saturating_add(1);
    let total = ad.signing.transaction.active.num_inputs.max(1);
    let progress = completed.saturating_mul(100) / total;
    crate::runtime::presentation::set_progress(ad, progress.min(100) as u8);
    let is_final = input_idx + 1 == ad.signing.transaction.active.num_inputs;
    if is_final && !finish_transaction(ad) {
        super::workflow::rollback_session(ad);
        reject_workflow_signing(ad);
        return false;
    }
    super::workflow::advance_after_signing(ad);
    true
}

fn finish_transaction(ad: &mut AppData) -> bool {
    use crate::runtime::data::{AntiKleptoPhase, OutgoingQrPurpose};
    output::reset(ad);
    let serialized = if ad.signing.transaction.input_format.is_pskt() {
        pskt::serialize_transaction(ad)
    } else if ad.signing.anti_klepto.phase == AntiKleptoPhase::Reviewing {
        super::workflow::prepare_anti_klepto_commitment(ad);
        ad.signing.anti_klepto.phase == AntiKleptoPhase::AwaitingReveal
            && ad.qr.outgoing.length != 0
    } else {
        kspt::serialize_transaction(ad)
    };
    if !serialized || ad.qr.outgoing.length == 0 {
        return false;
    }
    ad.qr.outgoing.purpose = if ad.signing.anti_klepto.phase == AntiKleptoPhase::AwaitingReveal {
        OutgoingQrPurpose::AntiKlepto
    } else {
        OutgoingQrPurpose::SignedTransaction
    };
    true
}

fn reject_workflow_signing(ad: &mut AppData) {
    ad.qr.outgoing.length = 0;
    let _ = crate::runtime::navigation::reject_active_signing(ad);
}

/// Move a queued workflow signing operation through the same one-shot
/// presentation boundary used by production. Runtime-display tests render the
/// queued surface first; non-display workflow tests call this helper directly.
pub(crate) fn workflow_activate_signing_operation(ad: &mut AppData) -> bool {
    match crate::runtime::presentation::operation_phase(ad) {
        OperationPhase::Queued => crate::runtime::presentation::mark_operation_presented(ad),
        OperationPhase::Presented => {}
        OperationPhase::Running | OperationPhase::Progress(_) => return true,
        _ => return false,
    }
    crate::runtime::presentation::take_ready_operation(ad) == Some(OperationKind::SignTransaction)
        && crate::runtime::presentation::operation_phase(ad) == OperationPhase::Running
}

/// Execute the real connected signing transition only when the supplied
/// deterministic trusted-time sample satisfies the production policy engine.
pub(crate) fn workflow_signing_step_with_policy(
    ad: &mut AppData,
    policy: signer_firmware_core::advanced_policy::SigningPolicy,
    integrity_ok: bool,
    now_unix: u64,
) -> bool {
    if crate::services::signing_policy::workflow_authorize_transaction_time(
        policy, integrity_ok, now_unix,
    ).is_err() {
        reject_workflow_signing(ad);
        return false;
    }
    workflow_signing_step(ad)
}
