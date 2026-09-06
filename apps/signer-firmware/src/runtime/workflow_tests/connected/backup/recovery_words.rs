use super::BackupContext;
use crate::runtime::input::AppState;

pub(super) fn exercise(ctx: &mut BackupContext<'_, '_, '_>) -> bool {
    let Some(slot) = ctx.ad.wallet.seeds.seed_mgr.active_slot() else { return false; };
    let original_indices = slot.indices;
    let original_fingerprint = slot.fingerprint;

    log!("KASSIGNER_WORKFLOW_TESTS: BACKUP RECOVERY WORDS WORD0 BACK BEGIN");
    if !word_zero_back_boundary(ctx) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: BACKUP RECOVERY WORDS WORD0 BACK OK");

    log!("KASSIGNER_WORKFLOW_TESTS: BACKUP RECOVERY WORDS WORD1 BACK BEGIN");
    if !word_one_back_boundary(ctx) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: BACKUP RECOVERY WORDS WORD1 BACK OK");

    log!("KASSIGNER_WORKFLOW_TESTS: BACKUP RECOVERY WORDS WALK BEGIN");
    if !walk_recovery_words(ctx) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: BACKUP RECOVERY WORDS WALK OK");

    ctx.ad.wallet.seeds.seed_mgr.active_slot().is_some_and(|after| {
        after.indices == original_indices && after.fingerprint == original_fingerprint
    })
}

fn word_zero_back_boundary(ctx: &mut BackupContext<'_, '_, '_>) -> bool {
    if !ctx.menu_select(0)
        || ctx.ad.navigation.app.state != (AppState::SeedBackup { word_idx: 0 })
    {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    ctx.export_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::WalletBackupMethodsMenu
}

fn word_one_back_boundary(ctx: &mut BackupContext<'_, '_, '_>) -> bool {
    if !ctx.menu_select(0)
        || ctx.export_touch(160, 120, false) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::SeedBackup { word_idx: 1 })
    {
        return false;
    }
    ctx.export_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::WalletBackupMethodsMenu
}

fn walk_recovery_words(ctx: &mut BackupContext<'_, '_, '_>) -> bool {
    if !ctx.menu_select(0)
        || ctx.ad.navigation.app.state != (AppState::SeedBackup { word_idx: 0 })
    {
        return false;
    }
    for next in 1u8..12 {
        if ctx.export_touch(160, 120, false) != Some(true)
            || ctx.ad.navigation.app.state != (AppState::SeedBackup { word_idx: next })
        {
            return false;
        }
        ctx.redraw();
    }
    ctx.export_touch(160, 120, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::WalletBackupMethodsMenu
}
