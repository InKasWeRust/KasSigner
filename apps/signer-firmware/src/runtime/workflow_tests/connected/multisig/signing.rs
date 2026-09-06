use super::MultisigContext;
use crate::runtime::input::AppState;
use core::sync::atomic::{AtomicU8, Ordering};
use offline_signer::{
    derivation::xpub::KpubParts,
    transaction::model::{
        Ms45Hint, MultisigConfig, SigHashType, Transaction, OP_BLAKE2B, OP_DATA_32,
        OP_EQUAL,
    },
};

const EXPECTED_THRESHOLD: u8 = 2;
const EXTERNAL_COSIGNER_ENTROPY: u8 = 0x99;
static FAILURE_STAGE: AtomicU8 = AtomicU8::new(0);

fn fail(stage: u8, name: &str) -> bool {
    let _ = FAILURE_STAGE.compare_exchange(0, stage, Ordering::Relaxed, Ordering::Relaxed);
    log!(
        "KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN STAGE {} FAILED",
        name
    );
    false
}

pub(super) fn failure_stage() -> u8 {
    FAILURE_STAGE.load(Ordering::Relaxed)
}

pub(super) fn replay_failure_stage(stage: u8) {
    let name = match stage {
        1 => "CONTEXT-RESET",
        2 => "FIXTURE-BUILD",
        3 => "FIXTURE-IMPORT",
        4 => "FIRST-REVIEW",
        5 => "FIRST-AUTHORIZATION",
        6 => "FIRST-PARTIAL",
        7 => "WALLET-SWITCH-REIMPORT",
        8 => "SECOND-REVIEW-AUTHORIZATION",
        9 => "FINAL-RESULT",
        _ => "UNKNOWN",
    };
    log!(
        "KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED MULTISIG SIGN STAGE {}",
        name
    );
}

pub(super) fn replay_failure() {
    replay_failure_stage(failure_stage());
}

pub(super) fn exercise(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    FAILURE_STAGE.store(0, Ordering::Relaxed);
    if !reset_signing_context(ctx) {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN FIXTURE CONTEXT RESET FAILED");
        return fail(1, "CONTEXT-RESET");
    }
    let Some((wire, expected_hint)) = multisig_wire(ctx.ad) else {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN FIXTURE BUILD FAILED");
        return fail(2, "FIXTURE-BUILD");
    };
    crate::runtime::interactions::tx::load_compact_transaction(&wire, ctx.ad);
    if !fixture_import_ok(ctx.ad, expected_hint) {
        return fail(3, "FIXTURE-IMPORT");
    }
    if !drive_review(ctx) {
        return fail(4, "FIRST-REVIEW");
    }
    if !authorize_signing(ctx) {
        return fail(5, "FIRST-AUTHORIZATION");
    }
    if !run_signing_step(ctx.ad) || !partial_result_ok(ctx.ad) {
        return fail(6, "FIRST-PARTIAL");
    }
    let partial_wire = ctx.ad.qr.outgoing.buffer[..ctx.ad.qr.outgoing.length].to_vec();
    if !switch_wallet_and_reimport(ctx, &partial_wire, expected_hint) {
        return fail(7, "WALLET-SWITCH-REIMPORT");
    }
    if !drive_review(ctx) || !authorize_signing(ctx) {
        return fail(8, "SECOND-REVIEW-AUTHORIZATION");
    }
    if !run_signing_step(ctx.ad) || !verify_signing_result(ctx.ad) {
        return fail(9, "FINAL-RESULT");
    }
    true
}

fn reset_signing_context(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    if !crate::services::wallet_session::install_workflow_multisig_mnemonic_inventory(ctx.ad) {
        return false;
    }
    // The preceding output/descriptor probe intentionally leaves a pending
    // inactive multisig descriptor behind. Signing is an independent probe,
    // so clear only that transient builder before entering the normal Home ->
    // Scan QR transaction route. Stored trusted descriptors remain intact.
    ctx.ad.signing.multisig.creating = MultisigConfig::new();
    crate::runtime::effects::home(ctx.ad);
    if !enter_scan_route(ctx.ad) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN FIXTURE CONTEXT RESET PASS");
    true
}

fn fixture_import_ok(ad: &crate::runtime::data::AppData, expected_hint: Ms45Hint) -> bool {
    let (present, required) = offline_signer::transaction::kspt::signature_status(
        &ad.signing.transaction.active,
    );
    let input = &ad.signing.transaction.active.inputs[0];
    let ok = ad.navigation.app.state == AppState::ConfirmTx
        && input.ms45_hint == expected_hint
        && input.sig_count == 0
        && present == 0
        && required == u32::from(EXPECTED_THRESHOLD);
    if ok {
        log!(
            "KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN FIXTURE IMPORT PASS family={} chain={} index={} required={}",
            expected_hint.cosigner,
            expected_hint.chain,
            expected_hint.index,
            required,
        );
    } else {
        log!(
            "KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN FIXTURE IMPORT FAILED sigs={} present={} required={} state={:?}",
            input.sig_count,
            present,
            required,
            ad.navigation.app.state,
        );
    }
    ok
}

fn drive_review(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    let review_pages = ctx.ad.navigation.app.review_pages;
    if ctx.ad.navigation.app.state != AppState::ConfirmTx
        || ctx.tx_touch(160, 208, false) != Some(true)
        || !review_entry_ok(ctx, review_pages)
    {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN REVIEW ENTRY FAILED");
        return false;
    }
    for page in 1..review_pages {
        if ctx.tx_touch(260, 210, false) != Some(true)
            || ctx.ad.navigation.app.state != (AppState::ReviewTx { page })
        {
            log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN REVIEW PAGE FAILED page={}", page);
            return false;
        }
    }
    if ctx.tx_touch(260, 210, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::ConfirmTx
    {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN CONFIRM ENTRY FAILED");
        return false;
    }
    log!(
        "KASSIGNER_WORKFLOW_TESTS: MULTISIG REVIEW PAGES {}/{} PASS",
        review_pages,
        review_pages,
    );
    true
}

fn review_entry_ok(ctx: &MultisigContext<'_, '_, '_>, review_pages: u8) -> bool {
    ctx.ad.navigation.app.state == (AppState::ReviewTx { page: 0 })
        && ctx.ad.navigation.app.total_inputs == 1
        && review_pages == 1 + ctx.ad.signing.transaction.active.num_outputs as u8
}

fn authorize_signing(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    let accepted = ctx.tx_touch(60, 208, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::ConfirmTx
        && crate::runtime::presentation::operation_active(
            ctx.ad, crate::runtime::data::OperationKind::SignTransaction,
        )
        && crate::runtime::presentation::operation_cursor(ctx.ad) == 0
        && ctx.ad.navigation.app.review_authorized;
    if !accepted {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN AUTHORIZATION FAILED");
        return false;
    }
    log!(
        "KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN AUTHORIZATION PASS threshold={} active-slot={}",
        EXPECTED_THRESHOLD,
        ctx.ad.wallet.seeds.seed_mgr.active,
    );
    true
}

fn run_signing_step(ad: &mut crate::runtime::data::AppData) -> bool {
    let before = ad.signing.transaction.active.inputs[0].sig_count;
    let step_ok = crate::runtime::signing::workflow_signing_step(ad);
    let after = ad.signing.transaction.active.inputs[0].sig_count;
    log!(
        "KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN CRYPTO STEP ok={} before={} after={} qr={} state={:?}",
        step_ok,
        before,
        after,
        ad.qr.outgoing.length,
        ad.navigation.app.state,
    );
    if !step_ok {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN STEP FAILED");
    }
    step_ok
}

fn partial_result_ok(ad: &crate::runtime::data::AppData) -> bool {
    let input = &ad.signing.transaction.active.inputs[0];
    let (present, required) = offline_signer::transaction::kspt::signature_status(
        &ad.signing.transaction.active,
    );
    let ok = input.sig_count == 1
        && present == 1
        && required == u32::from(EXPECTED_THRESHOLD)
        && ad.qr.outgoing.length != 0
        && ad.navigation.app.state == AppState::ShowQR;
    if ok {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG FIRST SIGNER PARTIAL 1/{} PASS", required);
    }
    ok
}

fn switch_wallet_and_reimport(
    ctx: &mut MultisigContext<'_, '_, '_>,
    partial_wire: &[u8],
    expected_hint: Ms45Hint,
) -> bool {
    let mut checkpoint = || {};
    if crate::services::wallet_session::activate_slot_with_cache(ctx.ad, 1, &mut checkpoint).is_err()
        || ctx.ad.wallet.seeds.seed_mgr.active != 1
    {
        return false;
    }
    crate::runtime::effects::home(ctx.ad);
    if !enter_scan_route(ctx.ad) { return false; }
    crate::runtime::interactions::tx::load_compact_transaction(partial_wire, ctx.ad);
    let input = &ctx.ad.signing.transaction.active.inputs[0];
    let (present, required) = offline_signer::transaction::kspt::signature_status(
        &ctx.ad.signing.transaction.active,
    );
    let ok = ctx.ad.navigation.app.state == AppState::ConfirmTx
        && input.ms45_hint == expected_hint
        && input.sig_count == 1
        && present == 1
        && required == u32::from(EXPECTED_THRESHOLD);
    if ok {
        log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG RELAY SWITCH WALLET + PARTIAL KSPT REIMPORT PASS active=1 sigs=1/{}", required);
    }
    ok
}

fn enter_scan_route(ad: &mut crate::runtime::data::AppData) -> bool {
    if ad.navigation.app.state != AppState::MainMenu
        || !crate::runtime::navigation::reconcile(ad)
    {
        return false;
    }
    let zone = crate::ui::layout::HOME_GRID_ZONES[1];
    crate::runtime::interactions::menu::handle_root_touch(
        ad, zone.x + zone.w / 2, zone.y + zone.h / 2,
    ) && ad.navigation.app.state == AppState::ScanQR
        && crate::runtime::navigation::reconcile(ad)
}

fn verify_signing_result(ad: &crate::runtime::data::AppData) -> bool {
    let input = &ad.signing.transaction.active.inputs[0];
    let (present, required) = offline_signer::transaction::kspt::signature_status(
        &ad.signing.transaction.active,
    );
    log!(
        "KASSIGNER_WORKFLOW_TESTS: MULTISIG SIGN RESULT sigs={} present={} required={} qr={} state={:?}",
        input.sig_count,
        present,
        required,
        ad.qr.outgoing.length,
        ad.navigation.app.state,
    );
    let threshold_met = input.sig_count == EXPECTED_THRESHOLD
        && required == u32::from(EXPECTED_THRESHOLD)
        && present == required;
    let ok = threshold_met
        && ad.qr.outgoing.length != 0
        && ad.navigation.app.state == AppState::ShowQR;
    if ok {
        log!(
            "KASSIGNER_WORKFLOW_TESTS: MULTISIG REVIEW/SIGN THRESHOLD PASS sigs={}",
            input.sig_count,
        );
    }
    ok
}

/// Build a self-contained 2-of-3 45' signing fixture with exactly two local
/// mnemonic cosigners and one deterministic external participant. This probe
/// intentionally does not reuse the mutable Multisig UI/export/import object:
/// those behaviors are covered by the preceding probes, while signing needs a
/// stable threshold fixture whose locally available keys are unambiguous.
fn multisig_wire(ad: &crate::runtime::data::AppData) -> Option<(alloc::vec::Vec<u8>, Ms45Hint)> {
    let config = deterministic_signing_config(ad)?;
    let hint = Ms45Hint {
        present: true,
        cosigner: u32::from(config.cosigner_index),
        chain: u32::from(config.chain),
        index: config.addr_index,
    };
    let wire = build_multisig_transaction(ad, &config, hint)?;
    Some((wire, hint))
}

fn deterministic_signing_config(ad: &crate::runtime::data::AppData) -> Option<MultisigConfig> {
    let first = local_parts(ad, 0)?;
    let second = local_parts(ad, 1)?;
    let external = external_parts()?;
    let mut config = MultisigConfig::new();
    config.m = EXPECTED_THRESHOLD;
    config.n = 3;
    config.v45 = true;
    config.set_cosigner(0, &first).then_some(())?;
    config.set_cosigner(1, &second).then_some(())?;
    config.set_cosigner(2, &external).then_some(())?;
    config.sort_cosigners();
    if !config.resolve_cosigner_index(&first) { return None; }
    let mut second_check = config.clone();
    if !second_check.resolve_cosigner_index(&second) { return None; }
    let mut external_check = config.clone();
    if !external_check.resolve_cosigner_index(&external) { return None; }
    config.chain = 0;
    config.addr_index = 0;
    (config.build_script() != 0).then_some(config)
}

fn local_parts(ad: &crate::runtime::data::AppData, slot_index: usize) -> Option<KpubParts> {
    let slot = ad.wallet.seeds.seed_mgr.slots.get(slot_index)?;
    let mut seed = crate::runtime::signing::derive_slot_seed(slot).ok()?;
    let parts = offline_signer::derivation::xpub::derive_multisig_account_parts(&seed.bytes, 0).ok();
    crate::runtime::signing::zeroize_seed(&mut seed.bytes);
    parts
}

fn external_parts() -> Option<KpubParts> {
    let mut seed = [EXTERNAL_COSIGNER_ENTROPY; 64];
    let parts = offline_signer::derivation::xpub::derive_multisig_account_parts(&seed, 0).ok();
    shared_signer::bytes::zeroize_bytes(&mut seed);
    parts
}

fn build_multisig_transaction(
    ad: &crate::runtime::data::AppData,
    config: &MultisigConfig,
    hint: Ms45Hint,
) -> Option<alloc::vec::Vec<u8>> {
    let mut tx = Transaction::try_new().ok()?;
    tx.version = 0;
    tx.network = ad.wallet.seeds.seed_mgr.network().kaspa_network();
    tx.ensure_input_slots(1).ok()?;
    tx.num_inputs = 1;
    tx.num_outputs = 1;
    populate_multisig_input(&mut tx, config, hint)?;
    populate_fixture_output(&mut tx, ad);
    offline_signer::transaction::kspt::serialize_compact_kspt_vec(&tx).ok()
}

fn populate_multisig_input(
    tx: &mut Transaction,
    config: &MultisigConfig,
    hint: Ms45Hint,
) -> Option<()> {
    let input = &mut tx.inputs[0];
    input.previous_outpoint.transaction_id = [0x71; 32];
    input.previous_outpoint.index = 0;
    input.utxo_entry.amount = 100_000_000;
    input.sequence = u64::MAX;
    input.sig_op_count = config.n;
    input.sighash_type = SigHashType::All.to_byte();
    let redeem = &config.script[..config.script_len];
    tx.store_redeem(0, redeem).ok()?;
    let hash = offline_signer::transaction::sighash::blake2b_hash(redeem);
    let outer = &mut tx.inputs[0].utxo_entry.script_public_key;
    outer.script[0] = OP_BLAKE2B;
    outer.script[1] = OP_DATA_32;
    outer.script[2..34].copy_from_slice(&hash);
    outer.script[34] = OP_EQUAL;
    outer.script_len = 35;
    tx.inputs[0].ms45_hint = hint;
    Some(())
}

fn populate_fixture_output(tx: &mut Transaction, ad: &crate::runtime::data::AppData) {
    tx.outputs[0].value = 99_000_000;
    let output = &mut tx.outputs[0].script_public_key;
    output.script[0] = 0x20;
    output.script[1..33].copy_from_slice(&ad.wallet.addresses.pubkey_cache[0]);
    output.script[33] = 0xac;
    output.script_len = 34;
}
