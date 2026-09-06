use core::sync::atomic::{AtomicU8, Ordering};
use super::SdWorkflowContext;
use crate::runtime::{data::TextFileKind, input::AppState};

static FAILURE_STAGE: AtomicU8 = AtomicU8::new(0);

const KPUB: &[u8] = b"kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
const DESCRIPTOR: &[u8] = concat!(
    "multi_hd45(2,",
    "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK,",
    "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
    ")"
).as_bytes();

pub(super) fn exercise(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    FAILURE_STAGE.store(0, Ordering::Relaxed);
    let transactions_ok = transaction_formats(ctx);
    let text_ok = text_formats(ctx);
    let generic_ok = generic_payload_rejection(ctx);
    transactions_ok && text_ok && generic_ok
}

pub(super) fn replay_failure_stage() {
    const NAMES: [&str; 7] = [
        "TX-COMPACT", "TX-STANDARD-PSKT", "TX-INVALID",
        "TEXT-KPUB", "TEXT-DESCRIPTOR", "TEXT-MALFORMED-KPUB", "GENERIC-UNKNOWN",
    ];
    let stage = FAILURE_STAGE.load(Ordering::Relaxed);
    if let Some(name) = stage.checked_sub(1).and_then(|index| NAMES.get(usize::from(index))) {
        log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED SD IMPORT STAGE {}", name);
        if *name == "TX-STANDARD-PSKT" {
            crate::runtime::interactions::tx::workflow_replay_standard_pskt_failure_reason();
        }
    }
}

fn fail(stage: u8) -> bool {
    let _ = FAILURE_STAGE.compare_exchange(0, stage, Ordering::Relaxed, Ordering::Relaxed);
    false
}

fn transaction_formats(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    let Some(compact) = super::super::signing::fixture::wire(
        ctx.ad, super::super::signing::fixture::WireFormat::CompactKspt,
    ) else { return fail(1); };
    if !ctx.enter_import_list(AppState::SdKsptFileList) { return fail(1); }
    crate::runtime::interactions::sd::workflow_import_transaction_payload(
        ctx.ad, ctx.display, ctx.delay, &compact,
    );
    if ctx.ad.navigation.app.state != AppState::ConfirmTx || ctx.ad.navigation.app.total_inputs != 2 {
        log!(
            "KASSIGNER_WORKFLOW_TESTS: SD TX COMPACT REVIEW FAIL state={:?} total_inputs={}",
            ctx.ad.navigation.app.state,
            ctx.ad.navigation.app.total_inputs,
        );
        return fail(1);
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SD TX COMPACT IMPORT REVIEW PASS");

    // Each imported transaction is an independent SD case. Do not let the
    // previous parser's transaction/review/QR state become input to the next.
    if !reset_transaction_case(ctx) { return fail(2); }
    let Some(pskt) = super::super::signing::fixture::wire(
        ctx.ad, super::super::signing::fixture::WireFormat::StandardPskt,
    ) else { return fail(2); };
    if !ctx.enter_import_list(AppState::SdKsptFileList) { return fail(2); }
    crate::runtime::interactions::sd::workflow_import_transaction_payload(
        ctx.ad, ctx.display, ctx.delay, &pskt,
    );
    if ctx.ad.navigation.app.state != AppState::ConfirmTx || ctx.ad.navigation.app.total_inputs != 2 {
        log!(
            "KASSIGNER_WORKFLOW_TESTS: SD TX STANDARD PSKT REVIEW FAIL state={:?} total_inputs={}",
            ctx.ad.navigation.app.state,
            ctx.ad.navigation.app.total_inputs,
        );
        crate::runtime::interactions::tx::workflow_mark_standard_pskt_review_state_failure();
        return fail(2);
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SD TX STANDARD PSKT IMPORT REVIEW PASS");

    if !reset_transaction_case(ctx) || !ctx.enter_import_list(AppState::SdKsptFileList) {
        return fail(3);
    }
    crate::runtime::interactions::sd::workflow_import_transaction_payload(
        ctx.ad, ctx.display, ctx.delay, b"KSPT\x04\x00",
    );
    let rejected = ctx.ad.navigation.app.state == AppState::Rejected;
    let reset = ctx.home();
    if !rejected || !reset { return fail(3); }
    log!("KASSIGNER_WORKFLOW_TESTS: SD TX KSPT/PSKT REVIEW + INVALID REJECT PASS");
    true
}

fn reset_transaction_case(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    if !ctx.home() { return false; }
    ctx.ad.signing.zeroize_sensitive();
    ctx.ad.qr.clear_sensitive();
    super::super::signing::fixture::install_wallet(ctx.ad)
}

fn text_formats(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    if !ctx.enter_import_list(AppState::SdKpubFileList) { return fail(4); }
    crate::runtime::interactions::sd::workflow_import_text_payload(
        ctx.ad, ctx.display, ctx.delay, TextFileKind::Kpub, KPUB,
    );
    if ctx.ad.navigation.app.state != AppState::ExportKpub || ctx.ad.export.kpub_len == 0 {
        return fail(4);
    }

    if !ctx.enter_import_list(AppState::SdKpubFileList) { return fail(5); }
    crate::runtime::interactions::sd::workflow_import_text_payload(
        ctx.ad, ctx.display, ctx.delay, TextFileKind::MultisigDescriptor, DESCRIPTOR,
    );
    if ctx.ad.navigation.app.state != AppState::MultisigDescriptor
        || ctx.ad.signing.multisig.creating.m != 2
    {
        return fail(5);
    }

    if !ctx.enter_import_list(AppState::SdKpubFileList) { return fail(6); }
    crate::runtime::interactions::sd::workflow_import_text_payload(
        ctx.ad, ctx.display, ctx.delay, TextFileKind::Kpub, b"not-a-kpub",
    );
    if ctx.ad.navigation.app.state == AppState::ExportKpub { return fail(6); }
    log!("KASSIGNER_WORKFLOW_TESTS: SD KPUB/DESCRIPTOR VALID + MALFORMED REJECT PASS");
    true
}

fn generic_payload_rejection(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    if !ctx.enter_import_list(AppState::SdFileList) { return fail(7); }
    let handled = crate::runtime::interactions::sd::workflow_import_payload(
        ctx.ad, ctx.display, ctx.delay, b"unknown payload",
    );
    let ok = !handled && ctx.ad.navigation.app.state == AppState::SdFileList;
    if !ok { return fail(7); }
    log!("KASSIGNER_WORKFLOW_TESTS: SD GENERIC UNKNOWN PAYLOAD REJECT PASS");
    true
}
