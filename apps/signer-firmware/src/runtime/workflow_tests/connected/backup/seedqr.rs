use crate::runtime::input::AppState;

use super::BackupContext;

pub(super) fn standard(ctx: &mut BackupContext<'_, '_, '_>) -> bool {
    if !ctx.menu_select(1) || ctx.ad.navigation.app.state != AppState::ExportSeedQR {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    if ctx.export_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::WalletBackupMethodsMenu
    {
        return false;
    }
    if !ctx.menu_select(1)
        || ctx.export_touch(160, 120, false) != Some(true)
        || ctx.ad.navigation.app.state
            != (AppState::SeedQrGrid {
                pan_x: 0,
                pan_y: 0,
                compact: false,
            })
    {
        return false;
    }
    ctx.redraw();
    if ctx.export_touch(20, 80, false) != Some(false)
        || ctx.export_touch(300, 80, false) != Some(false)
        || !pan_to_dynamic_max(ctx)
    {
        return false;
    }
    ctx.export_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::WalletBackupMethodsMenu
}

fn pan_to_dynamic_max(ctx: &mut BackupContext<'_, '_, '_>) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: BACKUP STANDARD SEEDQR HORIZONTAL WALK BEGIN");
    let Some(max_pan_x) = walk_axis(ctx, true, 0) else {
        return false;
    };
    log!(
        "KASSIGNER_WORKFLOW_TESTS: BACKUP STANDARD SEEDQR HORIZONTAL MAX {}",
        max_pan_x
    );
    if max_pan_x == 0
        || ctx.export_touch(20, 160, false) != Some(false)
        || ctx.ad.navigation.app.state
            != (AppState::SeedQrGrid {
                pan_x: max_pan_x,
                pan_y: 0,
                compact: false,
            })
    {
        return false;
    }

    log!("KASSIGNER_WORKFLOW_TESTS: BACKUP STANDARD SEEDQR VERTICAL WALK BEGIN");
    let Some(max_pan_y) = walk_axis(ctx, false, max_pan_x) else {
        return false;
    };
    log!(
        "KASSIGNER_WORKFLOW_TESTS: BACKUP STANDARD SEEDQR VERTICAL MAX {}",
        max_pan_y
    );
    max_pan_y == max_pan_x
        && ctx.export_touch(300, 160, false) == Some(false)
        && ctx.ad.navigation.app.state
            == (AppState::SeedQrGrid {
                pan_x: max_pan_x,
                pan_y: max_pan_y,
                compact: false,
            })
}

fn walk_axis(
    ctx: &mut BackupContext<'_, '_, '_>,
    horizontal: bool,
    fixed_pan_x: u8,
) -> Option<u8> {
    let mut pan = 0u8;
    loop {
        let result = if horizontal {
            ctx.export_touch(20, 160, false)
        } else {
            ctx.export_touch(300, 160, false)
        };
        if result == Some(false) {
            return Some(pan);
        }
        if result != Some(true) || pan >= 64 {
            return None;
        }
        pan = pan.checked_add(1)?;
        let expected = if horizontal {
            AppState::SeedQrGrid {
                pan_x: pan,
                pan_y: 0,
                compact: false,
            }
        } else {
            AppState::SeedQrGrid {
                pan_x: fixed_pan_x,
                pan_y: pan,
                compact: false,
            }
        };
        if ctx.ad.navigation.app.state != expected {
            return None;
        }
    }
}
