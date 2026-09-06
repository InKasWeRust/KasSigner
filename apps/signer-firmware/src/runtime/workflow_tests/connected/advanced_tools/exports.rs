use crate::runtime::input::AppState;

use super::AdvancedToolsContext;

pub(super) fn exercise(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    let xprv_ok = xprv(ctx);
    let private_key_ok = private_key(ctx);
    xprv_ok && private_key_ok
}

fn xprv(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !xprv_show_and_zeroize(ctx) || !xprv_no_sd(ctx) || !xprv_raw_key_reject(ctx) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED XPRV SHOW/ZEROIZE/NO-SD/RAW-KEY REJECT PASS");
    true
}

fn xprv_show_and_zeroize(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad)
        || !ctx.open_backup_advanced_item(3, AppState::XprvExportMenu)
    {
        return false;
    }
    let first = ctx.list[0];
    if ctx.export_touch(first.x + first.w / 2, first.y + first.h / 2, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::ExportXprv
        || ctx.ad.export.xprv_len < 4
        || &ctx.ad.export.xprv_data[..4] != b"kprv"
    {
        return false;
    }
    ctx.export_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::BackupRecoveryMenu
        && ctx.ad.export.xprv_len == 0
        && ctx.ad.export.xprv_data.iter().all(|byte| *byte == 0)
}

fn xprv_no_sd(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad)
        || !ctx.open_backup_advanced_item(3, AppState::XprvExportMenu)
    {
        return false;
    }
    let second = ctx.list[1];
    // Exercise the controller's no-card branch deterministically. A physical
    // QA card may be inserted, but normal workflow E2E must not mutate media.
    ctx.export_touch_without_sd(second.x + second.w / 2, second.y + second.h / 2, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::XprvExportMenu
        && ctx.export_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::BackupRecoveryMenu
}

fn xprv_raw_key_reject(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !crate::services::wallet_session::install_workflow_wallet_inventory_fixture(ctx.ad)
        || !ctx.open_backup_advanced_item(3, AppState::XprvExportMenu)
    {
        return false;
    }
    let first = ctx.list[0];
    ctx.export_touch(first.x + first.w / 2, first.y + first.h / 2, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::XprvExportMenu
        && ctx.ad.export.xprv_len == 0
}

fn private_key(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !mnemonic_private_key(ctx) || !raw_private_key(ctx) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED PRIVATE-KEY INDEX/HEX/RAW-KEY/ZEROIZE PASS");
    true
}

fn mnemonic_private_key(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad)
        || !ctx.open_backup_advanced_item(4, AppState::ExportPrivKeyIndex)
    {
        return false;
    }
    if ctx.export_touch(235, 193, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::ExportPrivKeyIndex
    {
        return false;
    }
    if ctx.export_touch(235, 90, false) != Some(true)
        || ctx.export_touch(235, 193, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::ExportPrivKey
        || !is_hex(&ctx.ad.export.export_key_hex)
    {
        return false;
    }
    ctx.export_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::BackupRecoveryMenu
        && ctx.ad.export.export_key_hex.iter().all(|byte| *byte == 0)
}

fn raw_private_key(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !crate::services::wallet_session::install_workflow_wallet_inventory_fixture(ctx.ad)
        || !ctx.open_backup_advanced_item(4, AppState::ExportPrivKeyIndex)
    {
        return false;
    }
    // Raw-key wallets expose exactly one private key at child index 0.
    if ctx.export_touch(160, 193, false) != Some(true)
        || ctx.export_touch(235, 193, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::ExportPrivKey
        || !is_hex(&ctx.ad.export.export_key_hex)
    {
        return false;
    }
    ctx.export_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::BackupRecoveryMenu
}

fn is_hex(value: &[u8; 64]) -> bool {
    value.iter().all(|byte| byte.is_ascii_hexdigit())
}
