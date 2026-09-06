// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use super::{display, AppData};
use crate::{
    runtime::interactions::feedback::{show_rejection, ErrorSound},
    runtime::input::AppState,
};

mod utxo_inspection;
mod standard_pskt_context;
#[cfg(feature = "workflow-test-auto")]
pub(crate) use standard_pskt_context::{
    workflow_mark_standard_pskt_review_state_failure,
    workflow_replay_standard_pskt_failure_reason,
};
use signer_firmware_core::presentation::transaction::{
    ScanReturn, TransactionDecision, TransactionEffect, TransactionScreen, reduce_touch,
};

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if matches!(ad.navigation.app.state, AppState::AntiKleptoRevealGuide) {
        return Some(handle_anti_klepto_reveal_guide(ad, x, y, is_back));
    }
    if utxo_inspection::handle(ad, x, y, is_back) { return Some(true); }
    let screen = transaction_screen(ad)?;
    let decision = reduce_touch(screen, x, y, is_back);
    apply_decision(ad, boot_display, delay, liveness, decision);
    Some(decision.redraw)
}

fn handle_anti_klepto_reveal_guide(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    use crate::runtime::data::AntiKleptoPhase;

    if ad.signing.anti_klepto.phase != AntiKleptoPhase::AwaitingReveal {
        crate::runtime::effects::home(ad);
        return true;
    }
    if is_back {
        let initial_counts = ad.signing.anti_klepto.initial_sig_counts;
        crate::runtime::signing::rollback_added_signatures(ad, &initial_counts);
        ad.signing.anti_klepto.reset();
        ad.qr.outgoing.length = 0;
        crate::runtime::effects::home(ad);
        return true;
    }
    if crate::ui::layout::ERROR_OK_ZONE.contains(x, y) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ScanQR));
        return true;
    }
    false
}

fn transaction_screen(ad: &AppData) -> Option<TransactionScreen> {
    match ad.navigation.app.state {
        AppState::SignTxGuide => Some(TransactionScreen::Guide {
            seed_loaded: ad.wallet.seeds.seed_loaded,
        }),
        AppState::ScanQR => Some(TransactionScreen::ScanQr {
            return_target: scan_return(ad),
        }),
        AppState::ReviewTx { .. } => Some(TransactionScreen::Review),
        AppState::ConfirmTx => Some(TransactionScreen::Confirm),
        _ => None,
    }
}

fn scan_return(ad: &AppData) -> ScanReturn {
    if ad.signing.multisig.creating.n > 0 && !ad.signing.multisig.creating.active {
        ScanReturn::MultisigAddKey(first_empty_multisig_slot(ad))
    } else {
        ScanReturn::MainMenu
    }
}

fn first_empty_multisig_slot(ad: &AppData) -> u8 {
    (0..ad.signing.multisig.creating.n)
        .find(|index| ad.signing.multisig.creating.slot_empty(*index as usize))
        .unwrap_or(0)
}

fn apply_decision(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    decision: TransactionDecision,
) {
    match decision.effect {
        TransactionEffect::None => {}
        TransactionEffect::GuideBack => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SingleSigMenu));
        }
        TransactionEffect::DeriveAccount => derive_account(ad, boot_display, delay, liveness),
        TransactionEffect::BeginScan => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(ScanQR),
            );
        }
        TransactionEffect::ScanBack(target) => apply_scan_back(ad, target),
        TransactionEffect::ReviewBack => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ConfirmTx));
        }
        TransactionEffect::ConfirmBack => {
            crate::runtime::effects::home(ad);
        }
        TransactionEffect::ReviewAdvance => {
            crate::runtime::effects::advance_review(ad);
        }
        TransactionEffect::ConfirmChoice(cursor) => {
            if cursor == 0 {
                if let Some(output) = offline_signer::transaction::model::find_forged_change(
                    &ad.signing.transaction.active,
                    &ad.signing.multisig.store.configs,
                ) {
                    crate::log!(
                        "   REFUSED: output {} claims multisig change not produced by trusted descriptor",
                        output + 1
                    );
                    show_rejection(
                        boot_display,
                        delay,
                        "Forged change output",
                        2500,
                        ErrorSound::Beep,
                    );
                    crate::runtime::effects::home(ad);
                    return;
                }
            }
            crate::runtime::effects::confirm_transaction(ad, cursor);
        }
    }
}

fn derive_account(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) {
    boot_display.draw_saving_screen("Deriving account key...");
    if crate::runtime::interactions::export::derive_watch_account(ad, liveness).is_ok() {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub));
    } else {
        show_rejection(
            boot_display,
            delay,
            "Account-key derivation failed",
            2000,
            ErrorSound::Silent,
        );
    }
}

fn apply_scan_back(ad: &mut AppData, target: ScanReturn) {
    #[cfg(feature = "waveshare")]
    {
        ad.camera.cam_tune_active = false;
    }
    match target {
        ScanReturn::MultisigAddKey(key_idx) => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigAddKey { key_idx }));
        }
        ScanReturn::MainMenu => crate::runtime::effects::home(ad),
    }
}


#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_load_compact_transaction(data: &[u8], ad: &mut AppData) {
    ad.signing.anti_klepto.reset();
    crate::log!(
        "KASSIGNER_WORKFLOW_TESTS: COMPACT KSPT PARSER BEGIN retained-input-slots={}",
        ad.signing.transaction.active.inputs.len(),
    );
    let parsed = offline_signer::transaction::kspt::parse_compact_kspt(
        data,
        &mut ad.signing.transaction.active,
    );
    crate::log!("KASSIGNER_WORKFLOW_TESTS: COMPACT KSPT PARSER RETURN");
    match parsed {
        Ok(()) => {
            crate::log!("KASSIGNER_WORKFLOW_TESTS: COMPACT KSPT PARSER ACCEPT");
            workflow_finish_compact_import(ad);
        }
        Err(_) => {
            crate::log!("KASSIGNER_WORKFLOW_TESTS: COMPACT KSPT PARSER REJECT");
            workflow_reject_transaction_import(ad);
        }
    }
}

#[cfg(feature = "workflow-test-auto")]
fn workflow_finish_compact_import(ad: &mut AppData) {
    if offline_signer::transaction::kspt::validate_transaction_for_review(
        &ad.signing.transaction.active,
    )
    .is_err()
    {
        workflow_reject_transaction_import(ad);
        return;
    }
    if !selected_network_matches_transaction(ad) {
        workflow_reject_transaction_import(ad);
        return;
    }
    ad.signing.transaction.input_format = shared_signer::TxInputFormat::KsptCompact;
    let (present, required) =
        offline_signer::transaction::kspt::signature_status(&ad.signing.transaction.active);
    ad.signing.transaction.signatures_present = present;
    ad.signing.transaction.signatures_required = required;
    begin_import_review(ad);
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn load_compact_transaction(
    data: &[u8],
    ad: &mut AppData,
) {
    let mut no_checkpoint = || {};
    load_compact_transaction_with_checkpoint(data, ad, &mut no_checkpoint);
}

pub(crate) fn load_compact_transaction_with_checkpoint(
    data: &[u8],
    ad: &mut AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) {
    ad.signing.anti_klepto.reset();
    checkpoint();
    match offline_signer::transaction::kspt::parse_compact_kspt(data, &mut ad.signing.transaction.active) {
        Ok(()) => finish_compact_import_with_checkpoint(ad, checkpoint),
        Err(error) => {
            crate::log!("   → compact KSPT parse error: {:?}", error);
            reject_transaction_import(ad, "Scan a current KSPT");
        }
    }
}

fn finish_compact_import_with_checkpoint(
    ad: &mut AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) {
    if offline_signer::transaction::kspt::validate_transaction_for_review(&ad.signing.transaction.active).is_err() {
        reject_transaction_import(ad, "Invalid monetary totals");
        return;
    }
    if !selected_network_matches_transaction(ad) {
        reject_transaction_import(ad, "Transaction network does not match selected network");
        return;
    }
    ad.signing.transaction.input_format = shared_signer::TxInputFormat::KsptCompact;
    let (present, required) = offline_signer::transaction::kspt::signature_status(&ad.signing.transaction.active);
    ad.signing.transaction.signatures_present = present;
    ad.signing.transaction.signatures_required = required;
    begin_import_review_with_checkpoint(ad, checkpoint);
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_load_standard_transaction(data: &[u8], ad: &mut AppData) {
    standard_pskt_context::reset();
    ad.signing.anti_klepto.reset();
    ad.signing.transaction.signatures_present = 0;
    ad.signing.transaction.signatures_required = 0;
    if ad
        .qr
        .outgoing
        .ensure_len(data.len().saturating_mul(2).max(4_352))
        .is_err()
    {
        standard_pskt_context::mark(1);
        workflow_reject_transaction_import(ad);
        return;
    }
    match offline_signer::transaction::std_pskt::parse_pskt(
        data,
        &mut ad.qr.outgoing.buffer,
        &mut ad.signing.transaction.active,
        &mut ad.signing.transaction.pskt_parsed,
    ) {
        Ok(()) => workflow_finish_standard_import(data, ad),
        Err(error) => {
            standard_pskt_context::mark(2);
            crate::log!("KASSIGNER_WORKFLOW_TESTS: STANDARD PSKT PARSER REJECT error={:?}", error);
            workflow_reject_transaction_import(ad);
        }
    }
}

#[cfg(feature = "workflow-test-auto")]
fn workflow_finish_standard_import(data: &[u8], ad: &mut AppData) {
    if let Err(error) = offline_signer::transaction::kspt::validate_transaction_for_review(
        &ad.signing.transaction.active,
    ) {
        standard_pskt_context::mark(3);
        crate::log!("KASSIGNER_WORKFLOW_TESTS: STANDARD PSKT REVIEW VALIDATION REJECT error={:?}", error);
        workflow_reject_transaction_import(ad);
        return;
    }
    // Standard ecosystem PSKT has no KasSigner compact-KSPT network trailer.
    // Bind only the in-memory signing model to the already-selected wallet
    // network; never extend or require a non-standard PSKT wire field.
    standard_pskt_context::bind_selected_network(ad);
    ad.signing.transaction.input_format =
        match offline_signer::transaction::std_pskt::detect_tx_format(data) {
            offline_signer::transaction::std_pskt::DetectedFormat::PsktSingle => {
                shared_signer::TxInputFormat::PsktSingle
            }
            _ => shared_signer::TxInputFormat::PsktPskb,
        };
    let (present, required) = offline_signer::transaction::std_pskt::pskt_signature_status(
        &ad.signing.transaction.active,
    );
    ad.signing.transaction.signatures_present = present;
    ad.signing.transaction.signatures_required = required;
    begin_import_review(ad);
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn load_standard_transaction(
    data: &[u8],
    ad: &mut AppData,
) {
    let mut no_checkpoint = || {};
    load_standard_transaction_with_checkpoint(data, ad, &mut no_checkpoint);
}

pub(crate) fn load_standard_transaction_with_checkpoint(
    data: &[u8],
    ad: &mut AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) {
    ad.signing.anti_klepto.reset();
    ad.signing.transaction.signatures_present = 0;
    ad.signing.transaction.signatures_required = 0;
    checkpoint();
    if ad.qr.outgoing.ensure_len(data.len().saturating_mul(2).max(4_352)).is_err() {
        reject_transaction_import(ad, "Insufficient working memory");
        return;
    }
    match offline_signer::transaction::std_pskt::parse_pskt(
        data,
        &mut ad.qr.outgoing.buffer,
        &mut ad.signing.transaction.active,
        &mut ad.signing.transaction.pskt_parsed,
    ) {
        Ok(()) => finish_standard_import_with_checkpoint(data, ad, checkpoint),
        Err(error) => {
            crate::log!("   → PSKT parse error: {:?}", error);
            reject_transaction_import(ad, "Scan a valid PSKT");
        }
    }
}

fn finish_standard_import_with_checkpoint(
    data: &[u8],
    ad: &mut AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) {
    if offline_signer::transaction::kspt::validate_transaction_for_review(&ad.signing.transaction.active).is_err() {
        reject_transaction_import(ad, "Invalid monetary totals");
        return;
    }
    // PSKT is an ecosystem format and does not carry KasSigner's compact-KSPT
    // network trailer. The selected wallet/network is trusted local context for
    // review/signing; no network field is added to or required from PSKT.
    standard_pskt_context::bind_selected_network(ad);
    ad.signing.transaction.input_format = match offline_signer::transaction::std_pskt::detect_tx_format(data) {
        offline_signer::transaction::std_pskt::DetectedFormat::PsktSingle => shared_signer::TxInputFormat::PsktSingle,
        _ => shared_signer::TxInputFormat::PsktPskb,
    };
    let (present, required) = offline_signer::transaction::std_pskt::pskt_signature_status(&ad.signing.transaction.active);
    ad.signing.transaction.signatures_present = present;
    ad.signing.transaction.signatures_required = required;
    begin_import_review_with_checkpoint(ad, checkpoint);
}

#[cfg(feature = "workflow-test-auto")]
fn begin_import_review(ad: &mut AppData) {
    let mut no_checkpoint = || {};
    begin_import_review_with_checkpoint(ad, &mut no_checkpoint);
}

fn begin_import_review_with_checkpoint(
    ad: &mut AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) {
    crate::log!("   TX import ownership verification BEGIN");
    checkpoint();
    if let Err(message) = crate::runtime::signing::verify_transaction_output_ownership_with_checkpoint(ad, checkpoint) {
        crate::log!("   Transaction ownership verification rejected: {}", message);
        #[cfg(feature = "workflow-test-auto")]
        if matches!(
            ad.signing.transaction.input_format,
            shared_signer::TxInputFormat::PsktSingle | shared_signer::TxInputFormat::PsktPskb
        ) {
            standard_pskt_context::mark(4);
        }
        crate::runtime::presentation::show_error_spec_previous(
            ad,
            crate::runtime::presentation::TX_OWNERSHIP,
        );
        return;
    }
    checkpoint();
    crate::log!("   TX import ownership verification DONE");
    crate::runtime::effects::start_review(
        ad,
        ad.signing.transaction.active.num_outputs as u8,
        ad.signing.transaction.active.num_inputs,
    );
    crate::runtime::effects::redraw(ad);
}

pub(crate) fn selected_network_matches_transaction(ad: &AppData) -> bool {
    ad.wallet
        .seeds
        .seed_mgr
        .network()
        .matches_transaction_network(ad.signing.transaction.active.network)
}

#[cfg(feature = "workflow-test-auto")]
fn workflow_reject_transaction_import(ad: &mut AppData) {
    crate::log!("KASSIGNER_WORKFLOW_TESTS: TRANSACTION REJECTION NAV BEGIN");
    let rejected = crate::runtime::navigation::workflow_reject_scanned_transaction(ad);
    crate::log!(
        "KASSIGNER_WORKFLOW_TESTS: TRANSACTION REJECTION NAV RETURNED ok={}",
        rejected,
    );
}

fn reject_transaction_import(ad: &mut AppData, detail: &str) {
    crate::log!("   Transaction import rejected: {}", detail);
    crate::runtime::presentation::show_error_spec_previous(ad, crate::runtime::presentation::TX_IMPORT);
}
