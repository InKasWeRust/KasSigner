use crate::{runtime::input::AppState, wallet::seed_manager};

use super::{begin_restore, choose_no_passphrase, finish_restored_session, RestoreIo};

pub(super) fn standard_seedqr(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if !begin_restore(ctx) || ctx.source_touch(1) != Some(true)
        || ctx.base.ad.navigation.app.state != AppState::ScanQR
    {
        return false;
    }
    let invalid = [b'0'; 48];
    crate::runtime::interactions::camera_loop::workflow_process_seed_payload(&invalid, false, ctx.base.ad);
    if ctx.base.ad.navigation.app.state != AppState::ScanQR {
        return false;
    }
    let mut indices = [0u16; 24];
    indices[11] = 3;
    let mut encoded = [0u8; 96];
    let length = seed_manager::encode_seedqr(&indices, 12, &mut encoded);
    crate::runtime::interactions::camera_loop::workflow_process_seed_payload(&encoded[..length], false, ctx.base.ad);
    if ctx.base.ad.navigation.app.state != AppState::PassphraseChoice
        || !choose_no_passphrase(ctx) || !finish_restored_session(ctx, 12)
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE STANDARD SEEDQR INVALID/VALID 12 PASS");
    true
}

pub(super) fn compact_seedqr(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if !begin_restore(ctx) || ctx.source_touch(3) != Some(true)
        || ctx.advanced_touch(0) != Some(true) || ctx.base.ad.navigation.app.state != AppState::ScanQR
    {
        return false;
    }
    let invalid = [0u8; 15];
    crate::runtime::interactions::camera_loop::workflow_process_seed_payload(&invalid, true, ctx.base.ad);
    if ctx.base.ad.navigation.app.state != AppState::ScanQR {
        return false;
    }
    let entropy = [0u8; 32];
    crate::runtime::interactions::camera_loop::workflow_process_seed_payload(&entropy, true, ctx.base.ad);
    if ctx.base.ad.navigation.app.state != AppState::PassphraseChoice
        || !choose_no_passphrase(ctx) || !finish_restored_session(ctx, 24)
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE COMPACT SEEDQR INVALID/VALID 24 PASS");
    true
}
