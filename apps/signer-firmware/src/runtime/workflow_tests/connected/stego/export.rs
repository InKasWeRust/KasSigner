use super::StegoContext;
use crate::{runtime::input::AppState, services::stego::StegoSecurity};

const JPEG_NAME: [[u8; 11]; 1] = [*b"PHOTO1  JPG"];
const DESCRIPTOR: &[u8] = b"KasSigner E2E carrier";
const PASSWORD: &[u8] = b"CorrectHorse9";
const WRONG_PASSWORD: &[u8] = b"WrongHorse9";

pub(super) fn exercise(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    description_and_hint(ctx) && portable_password(ctx) && final_confirmation(ctx)
}

fn prepare(ctx: &mut StegoContext<'_, '_, '_>, security: StegoSecurity) -> bool {
    if !ctx.enter_export_mode() {
        return false;
    }
    if ctx.touch(80, 90, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoSecuritySelect
    {
        return false;
    }
    if !crate::runtime::interactions::stego::workflow_select_security_with_jpegs(ctx.ad, security, &JPEG_NAME) {
        return false;
    }
    let zone = ctx.list[0];
    ctx.touch(zone.x + zone.w / 2, zone.y + zone.h / 2, false, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StegoJpegDescChoice
}

fn description_file_boundary(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(StegoJpegDescFile));
    if crate::runtime::interactions::stego::workflow_accept_description_file(ctx.ad, b"").is_ok() {
        return false;
    }
    let oversized = [b'x'; 97];
    if crate::runtime::interactions::stego::workflow_accept_description_file(ctx.ad, &oversized).is_ok() {
        return false;
    }
    if crate::runtime::interactions::stego::workflow_accept_description_file(ctx.ad, DESCRIPTOR).is_err()
        || ctx.ad.navigation.app.state != AppState::StegoJpegDescPreview
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: STEGO DESCRIPTION TXT EMPTY/OVERSIZED/VALID BOUNDARY PASS");
    true
}

fn type_descriptor(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if ctx.touch(100, 90, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoJpegDesc
    {
        return false;
    }
    if ctx.touch(18, 97, false, true) != Some(false)
        || ctx.ad.wallet.seeds.pp_input.len != 1
    {
        return false;
    }
    if ctx.touch(20, 210, false, true) != Some(false)
        || ctx.ad.wallet.seeds.pp_input.len != 0
    {
        return false;
    }
    ctx.set_text(DESCRIPTOR);
    ctx.touch(290, 215, false, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StegoJpegDescPreview
        && ctx.ad.stego.export_flow.jpeg_desc_len == DESCRIPTOR.len()
}

fn description_and_hint(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    description_preview(ctx) && preset_hint(ctx) && custom_hint(ctx)
}

fn description_preview(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if !prepare(ctx, StegoSecurity::DeviceBound) || !description_file_boundary(ctx) {
        return false;
    }
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(StegoJpegDescChoice));
    if !type_descriptor(ctx) { return false; }
    if ctx.touch(80, 205, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoJpegDescChoice
    {
        return false;
    }
    type_descriptor(ctx)
        && ctx.touch(230, 205, false, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StegoJpegPpAsk
}

fn preset_hint(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if ctx.touch(230, 195, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoJpegPpInfo
    {
        return false;
    }
    if ctx.touch(100, 80, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoJpegConfirm
        || ctx.ad.stego.hint.length == 0
    {
        return false;
    }
    ctx.touch(20, 20, true, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StegoJpegPpAsk
}

fn custom_hint(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if ctx.touch(230, 195, false, true) != Some(true)
        || ctx.touch(100, 180, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoJpegPpEntry
    {
        return false;
    }
    ctx.set_text(b"custom recovery hint");
    let ok = ctx.touch(290, 215, false, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StegoJpegConfirm
        && &ctx.ad.stego.hint.buffer[..ctx.ad.stego.hint.length] == b"custom recovery hint";
    if ok {
        log!("KASSIGNER_WORKFLOW_TESTS: STEGO DESCRIPTION EDIT/PREVIEW + PRESET/CUSTOM HINT PASS");
    }
    ok
}

fn portable_password(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    portable_password_entry(ctx) && portable_password_mismatch_retry(ctx)
}

fn portable_password_entry(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if !prepare(ctx, StegoSecurity::Portable) || !type_descriptor(ctx) {
        return false;
    }
    if ctx.touch(230, 205, false, true) != Some(true)
        || ctx.touch(80, 195, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoPortablePassword
    {
        return false;
    }
    ctx.set_text(b"short1");
    if ctx.touch(290, 215, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoPortablePassword
    {
        return false;
    }
    ctx.set_text(PASSWORD);
    ctx.touch(290, 215, false, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StegoPortablePasswordConfirm
}

fn portable_password_mismatch_retry(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    ctx.set_text(WRONG_PASSWORD);
    if ctx.touch(290, 215, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoPortablePassword
    {
        return false;
    }
    ctx.set_text(PASSWORD);
    if ctx.touch(290, 215, false, true) != Some(true) { return false; }
    ctx.set_text(PASSWORD);
    let ok = ctx.touch(290, 215, false, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StegoJpegConfirm
        && ctx.ad.stego.session.portable.password() == PASSWORD;
    if ok {
        log!("KASSIGNER_WORKFLOW_TESTS: STEGO PORTABLE PASSWORD INVALID/MISMATCH/CONFIRM/BACK PASS");
    }
    ok
}

fn final_confirmation(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if ctx.touch(20, 20, true, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoJpegPpAsk
        || !ctx.ad.stego.session.portable.password().is_empty()
    {
        return false;
    }
    if ctx.touch(80, 195, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoPortablePassword
    {
        return false;
    }
    if ctx.touch(20, 20, true, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoJpegPpAsk
    {
        return false;
    }
    ctx.ad.stego.export_flow.security = StegoSecurity::DeviceBound;
    if ctx.touch(80, 195, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoJpegConfirm
    {
        return false;
    }
    if ctx.touch(80, 205, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::BackupRecoveryMenu
        || ctx.ad.stego.hint.length != 0
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: STEGO FINAL REVIEW BACK/CANCEL OWNER/CLEAR PASS");
    true
}
