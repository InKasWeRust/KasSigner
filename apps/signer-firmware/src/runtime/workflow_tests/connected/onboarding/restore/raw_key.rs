use crate::{runtime::interactions::TouchInput, runtime::input::AppState, wallet::seed_manager};

use super::{begin_restore, RestoreIo, BUTTON_X};

const HEX_ZERO: (u16, u16) = (54, 118);
const HEX_ONE: (u16, u16) = (19, 80);
const HEX_UPPER_A: (u16, u16) = (89, 118);
const HEX_BACKSPACE: (u16, u16) = (0, 210);
const HEX_OK: (u16, u16) = (295, 210);

pub(super) fn restore(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if !begin_restore(ctx) || ctx.source_touch(3) != Some(true)
        || ctx.advanced_touch(3) != Some(true) || ctx.base.ad.navigation.app.state != AppState::ImportPrivKey
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE RAW KEY CASE-NORMALIZATION BEGIN");
    if !case_normalization(ctx) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE RAW KEY CASE-NORMALIZATION PASS");
    if !zero_rejection(ctx) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE RAW KEY ZERO-REJECTION PASS");
    if !valid_one(ctx) { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE RAW KEY VALID-IMPORT PASS");
    if !import_ready(ctx) { return false; }
    if !finalize_back_clears(ctx) || !reimport_valid_one(ctx) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE RAW KEY REIMPORT PASS");
    if crate::runtime::interactions::persistence::workflow_handle_finalize_choice(
        TouchInput::new(BUTTON_X, 142, false),
        ctx.base.ad,
    ) != Some(true) || !super::super::super::root::home_ok(ctx.base.ad) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE RAW KEY CASE/LENGTH/INVALID/VALID PASS");
    true
}

fn case_normalization(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if ctx.base.seed_touch(HEX_UPPER_A.0, HEX_UPPER_A.1, false) != Some(false)
        || ctx.base.ad.wallet.keys.hex_input_len != 1
        || ctx.base.ad.wallet.keys.hex_input[0] != b'a'
    {
        return false;
    }
    ctx.base.seed_touch(HEX_BACKSPACE.0, HEX_BACKSPACE.1, false) == Some(false)
        && ctx.base.ad.wallet.keys.hex_input_len == 0
}

fn zero_rejection(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    for _ in 0..64 {
        if ctx.base.seed_touch(HEX_ZERO.0, HEX_ZERO.1, false) != Some(false) {
            return false;
        }
    }
    if ctx.base.seed_touch(HEX_ONE.0, HEX_ONE.1, false) != Some(false)
        || ctx.base.ad.wallet.keys.hex_input_len != 64
    {
        return false;
    }
    ctx.base.seed_touch(HEX_OK.0, HEX_OK.1, false) == Some(true)
        && ctx.base.ad.navigation.app.state == AppState::ImportPrivKey
        && ctx.base.ad.wallet.keys.hex_input_len == 64
}

fn valid_one(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    ctx.base.seed_touch(HEX_BACKSPACE.0, HEX_BACKSPACE.1, false) == Some(false)
        && ctx.base.seed_touch(HEX_ONE.0, HEX_ONE.1, false) == Some(false)
        && ctx.base.seed_touch(HEX_OK.0, HEX_OK.1, false) == Some(true)
}

fn import_ready(ctx: &RestoreIo<'_, '_, '_>) -> bool {
    ctx.base.ad.navigation.app.state == AppState::StorageFinalizeChoice
        && ctx.base.ad.wallet.seeds.active_source == seed_manager::WalletSource::RawPrivateKey
        && ctx.base.ad.storage.persistence.recovery_words_acknowledged
        && ctx.base.ad.wallet.keys.hex_input_len == 0
        && ctx.base.ad.wallet.keys.hex_input.iter().all(|byte| *byte == 0)
}

fn finalize_back_clears(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if crate::runtime::interactions::persistence::workflow_handle_finalize_choice(
        TouchInput::new(20, 20, true),
        ctx.base.ad,
    ) != Some(true)
        || ctx.base.ad.navigation.app.state != AppState::AdvancedRestoreMenu
        || ctx.base.ad.wallet.seeds.seed_loaded
        || ctx.base.ad.wallet.seeds.active_source != seed_manager::WalletSource::Empty
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE RAW KEY FINALIZE BACK/CLEAR OK");
    true
}

fn reimport_valid_one(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if ctx.advanced_touch(3) != Some(true) || ctx.base.ad.navigation.app.state != AppState::ImportPrivKey {
        return false;
    }
    for _ in 0..63 {
        if ctx.base.seed_touch(HEX_ZERO.0, HEX_ZERO.1, false) != Some(false) {
            return false;
        }
    }
    ctx.base.seed_touch(HEX_ONE.0, HEX_ONE.1, false) == Some(false)
        && ctx.base.seed_touch(HEX_OK.0, HEX_OK.1, false) == Some(true)
        && import_ready(ctx)
}
