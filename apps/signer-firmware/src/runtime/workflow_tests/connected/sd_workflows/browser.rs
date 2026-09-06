use super::SdWorkflowContext;
use crate::runtime::input::AppState;

pub(super) fn exercise(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    if !physical_card_scan_when_hil(ctx) {
        return false;
    }
    paging_and_delete_cancel(ctx)
}

fn physical_card_scan_when_hil(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    #[cfg(feature = "workflow-hil-auto")]
    {
        return import_menu_card_scan(ctx);
    }

    #[cfg(not(feature = "workflow-hil-auto"))]
    {
        let _ = ctx;
        log!(
            "KASSIGNER_WORKFLOW_TESTS: SD IMPORT MENU PHYSICAL CARD SCAN DEFERRED TO workflow-hil"
        );
        true
    }
}

#[cfg(feature = "workflow-hil-auto")]
fn import_menu_card_scan(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    if ctx.sd.is_none() { return false; }
    if !ctx.enter_import_menu() { return false; }
    let transaction = ctx.list[1];
    if ctx.sd_touch(transaction.x + transaction.w / 2, transaction.y + transaction.h / 2, false) != Some(true) {
        return false;
    }
    match ctx.ad.navigation.app.state {
        AppState::SdImportMenu => {}
        AppState::SdKsptFileList => {
            if ctx.sd_touch(20, 20, true) != Some(true)
                || ctx.ad.navigation.app.state != AppState::SdImportMenu
            { return false; }
        }
        _ => return false,
    }
    if ctx.sd_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::BackupRecoveryMenu
    { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SD IMPORT MENU REAL-CARD SCAN/BACK OWNER OK");
    true
}

fn paging_and_delete_cancel(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    for index in 0..8usize {
        let mut name = *b"FILE000 TXT";
        name[4] = b'0' + index as u8;
        ctx.ad.storage.browser.file_list[index] = name;
    }
    ctx.ad.storage.browser.file_count = 8;
    ctx.ad.storage.browser.file_scroll = 0;
    if !ctx.enter_import_list(AppState::SdFileList) { return false; }
    if ctx.sd_touch(300, 80, false) != Some(true) || ctx.ad.storage.browser.file_scroll != 4 { return false; }
    if ctx.sd_touch(20, 80, false) != Some(true) || ctx.ad.storage.browser.file_scroll != 0 { return false; }
    let first = ctx.list[0];
    if ctx.sd_touch(first.x + first.w - 5, first.y + first.h / 2, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SdDeleteConfirm
    { return false; }
    if ctx.sd_touch(90, 205, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SdFileList
        || ctx.ad.storage.browser.file_count != 8
    { return false; }
    if ctx.sd_touch(20, 20, true) != Some(true) || ctx.ad.navigation.app.state != AppState::SdImportMenu { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SD FILE LIST PAGING/DELETE-CANCEL/BACK OK");
    true
}
