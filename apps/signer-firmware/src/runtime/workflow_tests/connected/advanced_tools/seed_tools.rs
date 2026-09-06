use crate::runtime::input::AppState;

use super::AdvancedToolsContext;

const KEY_A: (u16, u16) = (19, 100);
const KEY_B: (u16, u16) = (54, 100);
const KEY_Z: (u16, u16) = (299, 164);
const KEY_BACKSPACE: (u16, u16) = (0, 210);
const SUGGESTION_FIRST: (u16, u16) = (4, 80);

pub(super) fn exercise(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    let bip85_ok = bip85(ctx);
    let last_word_ok = last_word(ctx);
    bip85_ok && last_word_ok
}

fn install_parent(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad)
}

fn choose_tool_word_count(ctx: &mut AdvancedToolsContext<'_, '_, '_>, item: usize, y: u16) -> bool {
    if !install_parent(ctx)
        || !ctx.open_advanced_item(item, AppState::ChooseWordCount { action: if item == 0 { 4 } else { 3 } })
    {
        return false;
    }
    crate::runtime::interactions::menu::seed_generation::workflow_existing_tool_word_count(
        ctx.ad, 160, y, false,
    )
}

fn bip85(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !bip85_first_child(ctx) {
        return false;
    }
    let child_zero = ctx.ad.wallet.seeds.bip85_child_indices;
    if !walk_bip85_words(ctx, 12)
        || ctx.ad.navigation.app.state != AppState::WalletAdvancedMenu
        || !bip85_determinism(ctx, &child_zero)
        || !bip85_24_words(ctx)
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED BIP85 12/24 INDEX/BOUNDARY/DETERMINISM PASS");
    true
}

fn bip85_first_child(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !choose_tool_word_count(ctx, 0, 100)
        || ctx.ad.navigation.app.state != (AppState::Bip85Index { word_count: 12 })
    {
        return false;
    }
    if ctx.seed_touch(105, 115, false) != Some(false) || ctx.ad.wallet.seeds.bip85_index != 0 {
        return false;
    }
    ctx.ad.wallet.seeds.bip85_index = 99;
    if ctx.seed_touch(215, 115, false) != Some(false) || ctx.ad.wallet.seeds.bip85_index != 99 {
        return false;
    }
    ctx.ad.wallet.seeds.bip85_index = 0;
    ctx.seed_touch(160, 166, false) == Some(true)
        && ctx.ad.navigation.app.state == (AppState::Bip85ShowWord { word_idx: 0, word_count: 12 })
}

fn bip85_determinism(ctx: &mut AdvancedToolsContext<'_, '_, '_>, child_zero: &[u16; 24]) -> bool {
    if !derive_bip85(ctx, 0) || &ctx.ad.wallet.seeds.bip85_child_indices != child_zero {
        return false;
    }
    if !walk_bip85_words(ctx, 12)
        || !derive_bip85(ctx, 1)
        || &ctx.ad.wallet.seeds.bip85_child_indices == child_zero
    {
        return false;
    }
    walk_bip85_words(ctx, 12)
}

fn bip85_24_words(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    choose_tool_word_count(ctx, 0, 180)
        && ctx.ad.navigation.app.state == (AppState::Bip85Index { word_count: 24 })
        && ctx.seed_touch(160, 166, false) == Some(true)
        && walk_bip85_words(ctx, 24)
}

fn derive_bip85(ctx: &mut AdvancedToolsContext<'_, '_, '_>, index: u8) -> bool {
    if !choose_tool_word_count(ctx, 0, 100) {
        return false;
    }
    ctx.ad.wallet.seeds.bip85_index = index;
    ctx.seed_touch(160, 166, false) == Some(true)
        && matches!(ctx.ad.navigation.app.state, AppState::Bip85ShowWord { word_idx: 0, word_count: 12 })
}

fn walk_bip85_words(ctx: &mut AdvancedToolsContext<'_, '_, '_>, count: u8) -> bool {
    for _ in 0..count {
        if ctx.seed_touch(160, 120, false) != Some(true) {
            return false;
        }
    }
    true
}

fn last_word(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !last_word_12(ctx) || !last_word_24(ctx) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED BIP39 LAST-WORD 12/24 KEYBOARD/CHECKSUM/BACK PASS");
    true
}

fn last_word_12(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !choose_tool_word_count(ctx, 1, 100)
        || ctx.ad.navigation.app.state != (AppState::CalcLastWord { word_idx: 0, word_count: 12 })
    {
        return false;
    }
    if ctx.seed_touch(KEY_Z.0, KEY_Z.1, false) != Some(false)
        || ctx.seed_touch(KEY_Z.0, KEY_Z.1, false) != Some(false)
        || ctx.ad.wallet.seeds.word_input.match_count != 0
        || ctx.seed_touch(KEY_BACKSPACE.0, KEY_BACKSPACE.1, false) != Some(false)
        || ctx.seed_touch(KEY_BACKSPACE.0, KEY_BACKSPACE.1, false) != Some(false)
    {
        return false;
    }
    for _ in 0..11 {
        if !enter_abandon(ctx) {
            return false;
        }
    }
    if ctx.ad.navigation.app.state != AppState::PassphraseChoice
        || ctx.ad.wallet.seeds.mnemonic_indices[11] != 3
    {
        return false;
    }
    ctx.seed_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::WalletAdvancedMenu
}

fn last_word_24(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !choose_tool_word_count(ctx, 1, 180)
        || ctx.ad.navigation.app.state != (AppState::CalcLastWord { word_idx: 0, word_count: 24 })
    {
        return false;
    }
    for _ in 0..23 {
        if !enter_abandon(ctx) {
            return false;
        }
    }
    if ctx.ad.navigation.app.state != AppState::PassphraseChoice
        || !crate::wallet::mnemonic::validate(&ctx.ad.wallet.seeds.mnemonic_indices, 24)
    {
        return false;
    }
    ctx.seed_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::WalletAdvancedMenu
}

fn enter_abandon(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    let before = ctx.ad.navigation.app.state;
    if ctx.seed_touch(KEY_A.0, KEY_A.1, false) != Some(false)
        || ctx.seed_touch(KEY_B.0, KEY_B.1, false) != Some(false)
    {
        return false;
    }
    // Accepting a non-terminal checksum word updates the header directly and
    // therefore deliberately returns `Some(false)`. The final accepted word
    // redraws the passphrase screen and returns `Some(true)`. State progress,
    // not the redraw bit, is the contract that matters here.
    let Some(_) = ctx.seed_touch(SUGGESTION_FIRST.0, SUGGESTION_FIRST.1, false) else {
        return false;
    };
    ctx.ad.navigation.app.state != before
        && ctx.ad.wallet.seeds.word_input.prefix_len == 0
}
