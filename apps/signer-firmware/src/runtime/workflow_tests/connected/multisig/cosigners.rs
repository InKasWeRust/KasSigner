use super::MultisigContext;
use crate::runtime::input::AppState;

pub(super) fn exercise(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    local_first(ctx) && duplicate_local_rejected(ctx) && local_second(ctx) && scanned_third(ctx)
}

fn local_first(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    if ctx.tx_touch(160, 165, false) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::MultisigPickSeed { key_idx: 0 })
    { return false; }
    ctx.redraw_step();
    if ctx.tx_touch(300, 112, false) != Some(true) || ctx.ad.signing.multisig.scroll != 3 { return false; }
    if ctx.tx_touch(300, 112, false) != Some(false) || ctx.ad.signing.multisig.scroll != 3 { return false; }
    if ctx.tx_touch(20, 112, false) != Some(true) || ctx.ad.signing.multisig.scroll != 0 { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG WALLET PICKER PAGING BOUNDARIES PASS");

    // The canonical wallet picker exposes the same '+' Add Wallet row as the
    // normal WALLETS screen and Back must resume this exact multisig key slot.
    if ctx.tx_touch(160, 60, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::AddWalletChoice
        || ctx.ad.wallet.seeds.pending_multisig_wallet_key != 0
    { return false; }
    if ctx.seed_navigation_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::MultisigPickSeed { key_idx: 0 })
        || ctx.ad.wallet.seeds.pending_multisig_wallet_key != u8::MAX
    { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG ADD-WALLET RETURN CONTINUATION PASS");

    // Right-side taps are selection, never an invisible destructive zone.
    ctx.ad.wallet.seeds.pending_delete_slot = u8::MAX;
    if ctx.tx_touch(250, 112, false) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::MultisigAddKey { key_idx: 1 })
        || ctx.ad.signing.multisig.creating.slot_empty(0)
        || ctx.ad.wallet.seeds.pending_delete_slot != u8::MAX
    { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG WALLET PICKER NON-DESTRUCTIVE SELECTION PASS");
    true
}

fn duplicate_local_rejected(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    if ctx.tx_touch(160, 165, false) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::MultisigPickSeed { key_idx: 1 })
    { return false; }
    if ctx.tx_touch(250, 112, false) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::MultisigPickSeed { key_idx: 1 })
        || !ctx.ad.signing.multisig.creating.slot_empty(1)
        || ctx.ad.wallet.seeds.pending_delete_slot != u8::MAX
    { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG DUPLICATE LOCAL COSIGNER REJECT PASS");
    true
}

fn local_second(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    if ctx.tx_touch(160, 158, false) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::MultisigAddKey { key_idx: 2 })
        || ctx.ad.signing.multisig.creating.slot_empty(1)
    { return false; }
    true
}

fn scanned_third(ctx: &mut MultisigContext<'_, '_, '_>) -> bool {
    if ctx.tx_touch(160, 112, false) != Some(true) || ctx.ad.navigation.app.state != AppState::ScanQR { return false; }
    crate::runtime::interactions::camera_loop::dispatch::workflow_process_kpub_payload(b"not-a-kpub", ctx.ad);
    if ctx.ad.navigation.app.state != AppState::ScanQR || !ctx.ad.signing.multisig.creating.slot_empty(2) { return false; }
    let Some(duplicate) = kpub_for_slot(ctx.ad, 0) else { return false; };
    crate::runtime::interactions::camera_loop::dispatch::workflow_process_kpub_payload(&duplicate, ctx.ad);
    if ctx.ad.navigation.app.state != AppState::ScanQR || !ctx.ad.signing.multisig.creating.slot_empty(2) { return false; }
    let Some(valid) = kpub_for_slot(ctx.ad, 2) else { return false; };
    crate::runtime::interactions::camera_loop::dispatch::workflow_process_kpub_payload(&valid, ctx.ad);
    if ctx.ad.navigation.app.state != AppState::MultisigShowAddress
        || !ctx.ad.signing.multisig.creating.active
        || ctx.ad.signing.multisig.creating.slot_empty(2)
        || ctx.ad.signing.multisig.creating.script_len == 0
    { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: MULTISIG SCANNED KPUB INVALID/DUPLICATE/VALID PASS");
    true
}

fn kpub_for_slot(ad: &mut crate::runtime::data::AppData, slot_index: usize) -> Option<alloc::vec::Vec<u8>> {
    let slot = ad.wallet.seeds.seed_mgr.slots.get(slot_index)?;
    let mut seed = crate::runtime::signing::derive_slot_seed(slot).ok()?;
    let parts = offline_signer::derivation::xpub::derive_multisig_account_parts(&seed.bytes, 0).ok()?;
    crate::runtime::signing::zeroize_seed(&mut seed.bytes);
    let mut out = alloc::vec![0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN];
    let length = offline_signer::derivation::xpub::serialize_legacy_kpub_parts(&parts, &mut out);
    if length != offline_signer::derivation::xpub::LEGACY_KPUB_LEN { return None; }
    out.truncate(length);
    Some(out)
}
