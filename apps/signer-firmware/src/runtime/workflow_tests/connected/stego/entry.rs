use super::StegoContext;
use crate::{runtime::input::AppState, services::stego::{StegoCarrier, StegoSecurity}};

const JPEG_NAMES: [[u8; 11]; 5] = [
    *b"PHOTO1  JPG",
    *b"PHOTO2  JPG",
    *b"PHOTO3  JPG",
    *b"PHOTO4  JPG",
    *b"PHOTO5  JPG",
];

pub(super) fn exercise(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    entry_failures(ctx) && carrier_security(ctx) && jpeg_picker(ctx)
}

fn entry_failures(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if !ctx.enter_export_mode() {
        return false;
    }
    if ctx.touch(20, 20, true, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::BackupRecoveryMenu
    {
        return false;
    }

    if !ctx.enter_export_mode() {
        return false;
    }
    if ctx.touch(80, 90, false, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::BackupRecoveryMenu
    {
        return false;
    }

    if !crate::services::wallet_session::install_workflow_wallet_inventory_fixture(ctx.ad) {
        return false;
    }
    if !ctx.enter_export_mode() {
        return false;
    }
    if ctx.touch(80, 90, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::BackupRecoveryMenu
    {
        return false;
    }

    ctx.ad.wallet.seeds.seed_mgr.zeroize_all();
    if !ctx.enter_export_mode() {
        return false;
    }
    if ctx.touch(80, 90, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::BackupRecoveryMenu
    {
        return false;
    }
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: STEGO ENTRY BACK/NO-SD/RAW-KEY/NO-MNEMONIC REJECT PASS");
    true
}

fn carrier_security(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if !ctx.enter_export_mode() {
        return false;
    }
    if ctx.touch(80, 90, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoSecuritySelect
        || ctx.ad.stego.export_flow.carrier != StegoCarrier::Descriptor
    {
        return false;
    }
    if ctx.touch(20, 20, true, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoModeSelect
    {
        return false;
    }
    if ctx.touch(80, 165, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoSecuritySelect
        || ctx.ad.stego.export_flow.carrier != StegoCarrier::Picture
    {
        return false;
    }
    if !crate::runtime::interactions::stego::workflow_select_security_with_jpegs(
        ctx.ad,
        StegoSecurity::Portable,
        &JPEG_NAMES,
    ) || ctx.ad.navigation.app.state != AppState::StegoJpegPick
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: STEGO CARRIER/SECURITY DEVICE-BOUND+PORTABLE ROUTES PASS");
    true
}

fn jpeg_picker(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if ctx.touch(ctx.down.x + 10, ctx.down.y + 10, false, true) != Some(true)
        || ctx.ad.stego.export_flow.jpeg_selected != 4
    {
        return false;
    }
    if ctx.touch(ctx.down.x + 10, ctx.down.y + 10, false, true) != Some(false)
        || ctx.ad.stego.export_flow.jpeg_selected != 4
    {
        return false;
    }
    if ctx.touch(ctx.up.x + 10, ctx.up.y + 10, false, true) != Some(true)
        || ctx.ad.stego.export_flow.jpeg_selected != 0
    {
        return false;
    }
    if ctx.touch(ctx.up.x + 10, ctx.up.y + 10, false, true) != Some(false) {
        return false;
    }
    let zone = ctx.list[0];
    if ctx.touch(zone.x + zone.w / 2, zone.y + zone.h / 2, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoJpegDescChoice
    {
        return false;
    }
    if ctx.touch(20, 20, true, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoJpegPick
    {
        return false;
    }
    if ctx.touch(20, 20, true, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoSecuritySelect
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: STEGO JPEG PICKER PAGING/SELECT/BACK BOUNDARIES PASS");
    true
}
