use crate::{runtime::interactions::TouchInput, runtime::input::AppState};

use super::OnboardingContext;

const WORD_COUNT_X: u16 = 160;
const WORD_COUNT_12_Y: u16 = 100;
const WORD_COUNT_24_Y: u16 = 180;
const BUTTON_X: u16 = 160;

pub(super) fn create_12_session_only(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if !begin_create(ctx, 12) || !exercise_additive_choices(ctx, 12) {
        return false;
    }
    if !exercise_passphrase_back(ctx) || !choose_no_passphrase(ctx) {
        return false;
    }
    if !exercise_recovery_words(ctx, 12) || !acknowledge_recovery(ctx) {
        return false;
    }
    if !finalize_back_boundary(ctx) {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_finalize_choice(
        TouchInput::new(BUTTON_X, 142, false), ctx.ad,
    ) != Some(true) || !super::super::root::home_ok(ctx.ad) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: CREATE 12-WORD SESSION-ONLY PASS");
    true
}

pub(super) fn create_24_passphrase(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if !super::reset_to_storage_choice(ctx.ad)
        || !begin_create(ctx, 24)
        || !exercise_additive_choices(ctx, 24)
    {
        return false;
    }
    if !choose_passphrase(ctx) || !exercise_recovery_words(ctx, 24) || !acknowledge_recovery(ctx) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: CREATE 24-WORD PASSPHRASE/RECOVERY PASS");
    true
}

fn begin_create(ctx: &mut OnboardingContext<'_, '_, '_>, word_count: u8) -> bool {
    if ctx.ad.navigation.app.state != AppState::StorageModeChoice {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_mode_choice(
        TouchInput::new(BUTTON_X, 59, false), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != (AppState::WalletNameEntry { purpose: 0 }) {
        return false;
    }
    if ctx.seed_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StorageModeChoice
    {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_mode_choice(
        TouchInput::new(BUTTON_X, 59, false), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != (AppState::WalletNameEntry { purpose: 0 }) {
        return false;
    }
    ctx.ad.wallet.seeds.pp_input.reset();
    for byte in b"QA Wallet" { ctx.ad.wallet.seeds.pp_input.push_char(*byte); }
    if ctx.seed_touch(300, 210, false) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::StorageSeedWordCountChoice { action: 0 })
        || ctx.ad.wallet.seeds.pending_wallet_name_len == 0
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: CREATE WALLET NAME BACK/SUBMIT OK");
    ctx.redraw_step();
    if crate::runtime::interactions::menu::seed_generation::workflow_stage_word_count(
        ctx.ad, 10, 20, false,
    ) || ctx.ad.navigation.app.state != (AppState::StorageSeedWordCountChoice { action: 0 }) {
        return false;
    }
    if !crate::runtime::interactions::menu::seed_generation::workflow_stage_word_count(
        ctx.ad, WORD_COUNT_X, if word_count == 24 { WORD_COUNT_24_Y } else { WORD_COUNT_12_Y }, false,
    ) || ctx.ad.navigation.app.state != AppState::StorageSeedDiceChoice
        || ctx.ad.wallet.seeds.word_count != word_count
        || !ctx.ad.wallet.seeds.pending_seed_entropy_valid
    {
        return false;
    }
    ctx.redraw_step();
    log!("KASSIGNER_WORKFLOW_TESTS: CREATE WORD COUNT {} + ENTROPY FIXTURE READY", word_count);
    true
}

fn exercise_additive_choices(ctx: &mut OnboardingContext<'_, '_, '_>, word_count: u8) -> bool {
    if !restart_staged_entropy(ctx, word_count) || !enter_dice_count(ctx) {
        return false;
    }
    if !dice_count_matrix(ctx) || !dice_input_matrix(ctx) || !touch_choice_matrix(ctx) {
        return false;
    }
    ctx.redraw_step();
    log!("KASSIGNER_WORKFLOW_TESTS: CREATE DICE/TOUCH CHOICES + BOUNDARIES OK");
    true
}

fn restart_staged_entropy(ctx: &mut OnboardingContext<'_, '_, '_>, word_count: u8) -> bool {
    if ctx.additive_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::StorageSeedWordCountChoice { action: 0 })
        || ctx.ad.wallet.seeds.pending_seed_entropy_valid
    {
        return false;
    }
    crate::runtime::interactions::menu::seed_generation::workflow_stage_word_count(
        ctx.ad,
        WORD_COUNT_X,
        if word_count == 24 { WORD_COUNT_24_Y } else { WORD_COUNT_12_Y },
        false,
    ) && ctx.ad.navigation.app.state == AppState::StorageSeedDiceChoice
}

fn enter_dice_count(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    ctx.additive_touch(BUTTON_X, 129, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StorageSeedDiceCountChoice
}

fn touch_choice_matrix(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if ctx.additive_touch(BUTTON_X, 75, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StorageSeedTouchChoice
    {
        return false;
    }
    if ctx.additive_touch(BUTTON_X, 129, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::TouchEntropy
    {
        return false;
    }
    ctx.redraw_step();
    if ctx.additive_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StorageSeedTouchChoice
        || !ctx.ad.wallet.seeds.pending_seed_entropy_valid
    {
        return false;
    }
    ctx.additive_touch(BUTTON_X, 75, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::PassphraseChoice
        && !ctx.ad.wallet.seeds.pending_seed_entropy_valid
}

fn dice_count_matrix(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    const CASES: [(u16, usize); 4] = [(65, 25), (107, 50), (149, 100), (191, 200)];
    for (y, target) in CASES {
        if ctx.additive_touch(BUTTON_X, y, false) != Some(true)
            || ctx.ad.navigation.app.state != AppState::DiceRoll
            || ctx.ad.wallet.seeds.dice_collector.target != target
        {
            return false;
        }
        if !ctx.dice_touch(20, 20, true)
            || ctx.ad.navigation.app.state != AppState::StorageSeedDiceCountChoice
        {
            return false;
        }
    }
    true
}

fn dice_input_matrix(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if ctx.additive_touch(BUTTON_X, 65, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::DiceRoll
    {
        return false;
    }
    const DICE: [(u16, u16); 6] = [
        (60, 102), (160, 102), (260, 102),
        (60, 167), (160, 167), (260, 167),
    ];
    for (index, (x, y)) in DICE.into_iter().enumerate() {
        if ctx.dice_touch(x, y, false) || ctx.ad.wallet.seeds.dice_collector.count != index + 1 {
            return false;
        }
    }
    if ctx.dice_touch(5, 50, false) || ctx.ad.wallet.seeds.dice_collector.count != 6 {
        return false;
    }
    if ctx.dice_touch(160, 210, false) || ctx.ad.wallet.seeds.dice_collector.count != 5 {
        return false;
    }
    if !ctx.dice_touch(20, 20, true)
        || ctx.ad.navigation.app.state != AppState::StorageSeedDiceCountChoice
    {
        return false;
    }
    ctx.additive_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StorageSeedDiceChoice
}

fn exercise_passphrase_back(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if ctx.seed_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StorageSeedTouchChoice
        || !ctx.ad.wallet.seeds.pending_seed_entropy_valid
    {
        return false;
    }
    ctx.additive_touch(BUTTON_X, 75, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::PassphraseChoice
}

fn choose_no_passphrase(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if ctx.seed_touch(BUTTON_X, 143, false) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::SeedBackup { word_idx: 0 })
        || !ctx.ad.wallet.seeds.seed_loaded
    {
        return false;
    }
    ctx.redraw_step();
    if crate::runtime::interactions::export::seed_backup::handle(ctx.ad, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::PassphraseChoice
        || ctx.ad.wallet.seeds.seed_loaded
    {
        return false;
    }
    ctx.seed_touch(BUTTON_X, 143, false) == Some(true)
        && ctx.ad.navigation.app.state == (AppState::SeedBackup { word_idx: 0 })
        && ctx.ad.wallet.seeds.seed_loaded
}

fn choose_passphrase(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if !enter_passphrase_with_back(ctx) || !type_passphrase_a1(ctx) {
        return false;
    }
    if ctx.seed_touch(295, 210, false) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::SeedBackup { word_idx: 0 })
    {
        return false;
    }
    ctx.redraw_step();
    true
}

fn enter_passphrase_with_back(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if ctx.seed_touch(BUTTON_X, 193, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::PassphraseEntry
    {
        return false;
    }
    ctx.redraw_step();
    if ctx.seed_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::PassphraseChoice
    {
        return false;
    }
    ctx.seed_touch(BUTTON_X, 193, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::PassphraseEntry
}

fn type_passphrase_a1(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if ctx.seed_touch(18, 97, false) != Some(false) || ctx.ad.wallet.seeds.pp_input.len != 1 {
        return false;
    }
    if !advance_passphrase_pages(ctx) {
        return false;
    }
    if ctx.seed_touch(18, 97, false) != Some(false) || ctx.ad.wallet.seeds.pp_input.len != 2 {
        return false;
    }
    if ctx.seed_touch(20, 210, false) != Some(false) || ctx.ad.wallet.seeds.pp_input.len != 1 {
        return false;
    }
    ctx.seed_touch(18, 97, false) == Some(false) && ctx.ad.wallet.seeds.pp_input.len == 2
}

fn advance_passphrase_pages(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    ctx.seed_touch(18, 170, false) == Some(false)
        && ctx.seed_touch(18, 170, false) == Some(false)
        && ctx.ad.wallet.seeds.pp_input.page == 2
}

fn exercise_recovery_words(ctx: &mut OnboardingContext<'_, '_, '_>, word_count: u8) -> bool {
    for next in 1u8..word_count {
        if crate::runtime::interactions::export::seed_backup::handle(ctx.ad, false) != Some(true)
            || ctx.ad.navigation.app.state != (AppState::SeedBackup { word_idx: next })
        {
            return false;
        }
        if next == 1 || next + 1 == word_count {
            ctx.redraw_step();
        }
    }
    if crate::runtime::interactions::export::seed_backup::handle(ctx.ad, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StorageRecoveryAcknowledgement
    {
        return false;
    }
    ctx.redraw_step();
    log!("KASSIGNER_WORKFLOW_TESTS: CREATE RECOVERY WORDS {}/{} OK", word_count, word_count);
    true
}

fn acknowledge_recovery(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if crate::runtime::interactions::persistence::workflow_handle_recovery_acknowledgement(
        TouchInput::new(310, 120, false), ctx.ad, ctx.display, ctx.delay,
    ).is_some() || ctx.ad.navigation.app.state != AppState::StorageRecoveryAcknowledgement {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_recovery_acknowledgement(
        TouchInput::new(20, 20, true), ctx.ad, ctx.display, ctx.delay,
    ) != Some(true) || !matches!(ctx.ad.navigation.app.state, AppState::SeedBackup { .. }) {
        return false;
    }
    if crate::runtime::interactions::export::seed_backup::handle(ctx.ad, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StorageRecoveryAcknowledgement
    {
        return false;
    }
    crate::runtime::interactions::persistence::workflow_handle_recovery_acknowledgement(
        TouchInput::new(BUTTON_X, 188, false), ctx.ad, ctx.display, ctx.delay,
    ) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StorageFinalizeChoice
        && ctx.ad.storage.persistence.recovery_words_acknowledged
}

fn finalize_back_boundary(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if crate::runtime::interactions::persistence::workflow_handle_finalize_choice(
        TouchInput::new(20, 20, true), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::StorageRecoveryAcknowledgement {
        return false;
    }
    crate::runtime::interactions::persistence::workflow_handle_recovery_acknowledgement(
        TouchInput::new(BUTTON_X, 188, false), ctx.ad, ctx.display, ctx.delay,
    ) == Some(true) && ctx.ad.navigation.app.state == AppState::StorageFinalizeChoice
}
