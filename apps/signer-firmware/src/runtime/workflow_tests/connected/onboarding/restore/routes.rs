use crate::{runtime::interactions::TouchInput, runtime::input::AppState};

use super::{begin_restore, RestoreIo, RESTORE_ROWS};

pub(super) fn menu_routes(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if !begin_restore(ctx) {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_seed_source_choice(
        TouchInput::new(20, RESTORE_ROWS[0], false),
        ctx.base.ad,
    ).is_some() || ctx.base.ad.navigation.app.state != AppState::StorageSeedSourceChoice {
        return false;
    }
    if !scan_seedqr_back(ctx) || !sd_back(ctx) || !advanced_back_matrix(ctx) {
        return false;
    }
    if ctx.source_back() != Some(true) || ctx.base.ad.navigation.app.state != AppState::StorageModeChoice {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE MENU ROUTES/OWNERS/NOOP OK");
    true
}

fn scan_seedqr_back(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if ctx.source_touch(1) != Some(true) || ctx.base.ad.navigation.app.state != AppState::ScanQR {
        return false;
    }
    crate::runtime::interactions::camera_loop::route_camera_back(ctx.base.ad);
    ctx.base.ad.navigation.app.state == AppState::StorageSeedSourceChoice
}

fn sd_back(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if ctx.source_touch(2) != Some(true)
        || ctx.base.ad.navigation.app.state != AppState::SdWalletBackupFileList
    {
        return false;
    }
    let zone = ctx.list[0];
    if ctx.sd_touch(zone.x + 8, zone.y + 8, false) != Some(false)
        || ctx.base.ad.navigation.app.state != AppState::SdWalletBackupFileList
    {
        return false;
    }
    ctx.sd_touch(20, 20, true) == Some(true)
        && ctx.base.ad.navigation.app.state == AppState::StorageSeedSourceChoice
}

fn advanced_back_matrix(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if ctx.source_touch(3) != Some(true) || ctx.base.ad.navigation.app.state != AppState::AdvancedRestoreMenu {
        return false;
    }
    if ctx.advanced_back() != Some(true) || ctx.base.ad.navigation.app.state != AppState::StorageSeedSourceChoice {
        return false;
    }
    if ctx.source_touch(3) != Some(true)
        || !compact_back(ctx)
        || !plain_text_back(ctx)
        || !stego_back(ctx)
        || !raw_key_back(ctx)
    {
        return false;
    }
    ctx.advanced_back() == Some(true) && ctx.base.ad.navigation.app.state == AppState::StorageSeedSourceChoice
}

fn compact_back(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if ctx.advanced_touch(0) != Some(true) || ctx.base.ad.navigation.app.state != AppState::ScanQR {
        return false;
    }
    crate::runtime::interactions::camera_loop::route_camera_back(ctx.base.ad);
    ctx.base.ad.navigation.app.state == AppState::AdvancedRestoreMenu
}


fn plain_text_back(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if ctx.advanced_touch(1) != Some(true) || ctx.base.ad.navigation.app.state != AppState::ScanQR {
        return false;
    }
    crate::runtime::interactions::camera_loop::route_camera_back(ctx.base.ad);
    ctx.base.ad.navigation.app.state == AppState::AdvancedRestoreMenu
}

fn raw_key_back(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if ctx.advanced_touch(3) != Some(true) || ctx.base.ad.navigation.app.state != AppState::ImportPrivKey {
        return false;
    }
    ctx.base.seed_touch(20, 20, true) == Some(true)
        && ctx.base.ad.navigation.app.state == AppState::AdvancedRestoreMenu
}

fn stego_back(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if ctx.advanced_touch(2) != Some(true) || ctx.base.ad.navigation.app.state != AppState::StegoImportPick {
        return false;
    }
    ctx.stego_back() == Some(true) && ctx.base.ad.navigation.app.state == AppState::AdvancedRestoreMenu
}

pub(super) fn sd_empty_back(ctx: &mut RestoreIo<'_, '_, '_>) -> bool {
    if !begin_restore(ctx) || ctx.source_touch(2) != Some(true)
        || ctx.base.ad.navigation.app.state != AppState::SdWalletBackupFileList
    {
        return false;
    }
    let zone = ctx.list[0];
    if ctx.sd_touch(zone.x + zone.w / 2, zone.y + zone.h / 2, false) != Some(false)
        || ctx.base.ad.navigation.app.state != AppState::SdWalletBackupFileList
    {
        return false;
    }
    if ctx.sd_touch(20, 20, true) != Some(true)
        || ctx.base.ad.navigation.app.state != AppState::StorageSeedSourceChoice
        || ctx.source_back() != Some(true)
        || ctx.base.ad.navigation.app.state != AppState::StorageModeChoice
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: RESTORE SD EMPTY-LIST/BACK OWNER OK");
    true
}
