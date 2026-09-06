use super::MultisigContext;
use crate::runtime::{data::TextFileKind, input::AppState};
use core::sync::atomic::{AtomicU8, Ordering};

static FAILURE_STAGE: AtomicU8 = AtomicU8::new(0);

fn fail(stage: u8, name: &str) -> bool {
    let _ = FAILURE_STAGE.compare_exchange(0, stage, Ordering::Relaxed, Ordering::Relaxed);
    log!(
        "KASSIGNER_WORKFLOW_TESTS: MULTISIG OUTPUT STAGE {} FAILED",
        name
    );
    false
}

pub(super) fn failure_stage() -> u8 {
    FAILURE_STAGE.load(Ordering::Relaxed)
}

const FAILURE_STAGE_NAMES: [&str; 14] = [
    "ADDRESS-ENTRY",
    "ADDRESS-FAMILY",
    "ADDRESS-CHAIN",
    "INDEX-PICKER-ENTRY",
    "INDEX-DIGIT",
    "INDEX-SUBMIT",
    "INDEX-COMMIT",
    "ADDRESS-QR",
    "ADDRESS-SAVE-PROMPT",
    "DESCRIPTOR-ENTRY",
    "DESCRIPTOR-QR",
    "DESCRIPTOR-PARSE",
    "INVALID-DESCRIPTOR-REJECT",
    "DESCRIPTOR-ROUND-TRIP",
];

pub(super) fn replay_failure_stage(stage: u8) {
    let name = FAILURE_STAGE_NAMES
        .get(stage.wrapping_sub(1) as usize)
        .copied()
        .unwrap_or("UNKNOWN");
    log!(
        "KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED MULTISIG OUTPUT STAGE {}",
        name
    );
}

pub(super) fn replay_failure() {
    replay_failure_stage(failure_stage());
}

pub(super) fn exercise(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    FAILURE_STAGE.store(0, Ordering::Relaxed);
    if !address_controls(ctx) {
        return false;
    }
    if !qr_and_descriptor(ctx) {
        return false;
    }
    descriptor_round_trip(ctx)
}

fn address_controls(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    if ctx.ad.navigation.app.state != AppState::MultisigShowAddress {
        return fail(1, "ADDRESS-ENTRY");
    }
    let original_cosigner = ctx.ad.signing.multisig.creating.cosigner_index;
    if ctx.tx_touch(85, 210, false) != Some(true)
        || ctx.ad.signing.multisig.creating.cosigner_index == original_cosigner
    {
        return fail(2, "ADDRESS-FAMILY");
    }
    if ctx.tx_touch(138, 210, false) != Some(true)
        || ctx.ad.signing.multisig.creating.chain != 1
    {
        return fail(3, "ADDRESS-CHAIN");
    }
    if ctx.tx_touch(205, 210, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::AddrIndexPicker
    {
        return fail(4, "INDEX-PICKER-ENTRY");
    }
    // Numeric entry updates the picker field in place. Normal connected E2E
    // suppresses the physical LCD mutation but preserves this Some(false)
    // production redraw contract; HIL/production still render the field.
    if ctx.export_touch(72, 82, false) != Some(false) {
        return fail(5, "INDEX-DIGIT");
    }
    if ctx.export_touch(235, 192, false) != Some(true) {
        return fail(6, "INDEX-SUBMIT");
    }
    if ctx.ad.navigation.app.state != AppState::MultisigShowAddress
        || ctx.ad.signing.multisig.creating.addr_index != 1
    {
        return fail(7, "INDEX-COMMIT");
    }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG ADDRESS FAMILY/CHAIN/INDEX CONTROLS PASS");
    true
}

fn qr_and_descriptor(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    if ctx.tx_touch(160, 120, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::MultisigShowAddressQR
    {
        return fail(8, "ADDRESS-QR");
    }
    ctx.redraw_step();
    if ctx.tx_touch(160, 120, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::MultisigSaveAddrAsk
    {
        return fail(9, "ADDRESS-SAVE-PROMPT");
    }
    if ctx.tx_touch(230, 160, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::MultisigDescriptor
    {
        return fail(10, "DESCRIPTOR-ENTRY");
    }
    if !crate::runtime::navigation::handle_back(ctx.ad)
        || ctx.ad.navigation.app.state != AppState::MultisigShowAddress
    {
        return fail(10, "DESCRIPTOR-BACK");
    }
    if ctx.tx_touch(160, 120, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::MultisigShowAddressQR
    {
        return fail(10, "DESCRIPTOR-BACK-REENTER-QR");
    }
    ctx.redraw_step();
    if ctx.tx_touch(160, 120, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::MultisigSaveAddrAsk
    {
        return fail(10, "DESCRIPTOR-BACK-REENTER-SAVE");
    }
    if ctx.tx_touch(230, 160, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::MultisigDescriptor
    {
        return fail(10, "DESCRIPTOR-BACK-REENTER");
    }
    if ctx.tx_touch(80, 210, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::ShowQR
        || ctx.ad.qr.outgoing.length == 0
    {
        return fail(11, "DESCRIPTOR-QR");
    }
    let descriptor = &ctx.ad.qr.outgoing.buffer[..ctx.ad.qr.outgoing.length];
    if kassigner_protocol::wire::multisig_descriptor::parse_multisig_descriptor(descriptor)
        .is_err()
    {
        return fail(12, "DESCRIPTOR-PARSE");
    }
    if ctx.menu_touch(160, 120, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::MultisigDescriptor
    {
        return fail(11, "DESCRIPTOR-QR");
    }
    if ctx.tx_touch(80, 210, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::ShowQR
        || ctx.ad.qr.outgoing.length == 0
    {
        return fail(11, "DESCRIPTOR-QR");
    }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG ADDRESS/QR/DESCRIPTOR PRESENTATION PASS");
    true
}

fn descriptor_round_trip(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    let descriptor = ctx.ad.qr.outgoing.buffer[..ctx.ad.qr.outgoing.length].to_vec();
    crate::runtime::interactions::sd::workflow_import_text_payload(
        ctx.ad, ctx.display, ctx.delay, TextFileKind::MultisigDescriptor, b"multi_hd45(2,bad)",
    );
    if ctx.ad.navigation.app.state == AppState::MultisigDescriptor {
        return fail(13, "INVALID-DESCRIPTOR-REJECT");
    }
    crate::runtime::interactions::sd::workflow_import_text_payload(
        ctx.ad, ctx.display, ctx.delay, TextFileKind::MultisigDescriptor, &descriptor,
    );
    let config = &ctx.ad.signing.multisig.creating;
    let ok = ctx.ad.navigation.app.state == AppState::MultisigDescriptor
        && !config.active
        && config.m == 2
        && config.n == 3
        && config.script_len != 0;
    if !ok {
        return fail(14, "DESCRIPTOR-ROUND-TRIP");
    }
    if !crate::runtime::navigation::handle_back(ctx.ad)
        || ctx.ad.navigation.app.state != AppState::SdImportMenu
    {
        return fail(14, "IMPORTED-DESCRIPTOR-BACK");
    }
    log!(
        "KASSIGNER_WORKFLOW_TESTS: MULTISIG DESCRIPTOR INVALID-REJECT/EXPORT-IMPORT ROUND-TRIP PASS"
    );
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG DESCRIPTOR BACK ROUTES PASS");
    true
}
