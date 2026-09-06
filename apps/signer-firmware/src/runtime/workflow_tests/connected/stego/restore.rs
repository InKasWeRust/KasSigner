use super::{media::{MediaArtifacts, DESCRIPTOR, HINT, PASSWORD, WRONG_PASSWORD}, StegoContext};
use crate::{runtime::input::AppState, services::stego::{self, StegoCarrier}};
pub(super) fn exercise(ctx: &mut StegoContext<'_, '_, '_>, artifacts: MediaArtifacts) -> bool {
    import_picker(ctx) && device_bound_round_trip(ctx, &artifacts) && portable_round_trip(ctx, &artifacts)
}

fn import_picker(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    let ok = import_picker_navigation(ctx) && descriptor_file_validation(ctx) && import_back_owners(ctx);
    let cleanup_ok = crate::runtime::navigation::workflow_cleanup_onboarding_to_home(ctx.ad);
    let ok = ok && cleanup_ok && crate::runtime::workflow_tests::connected::root::home_ok(ctx.ad);
    if ok {
        log!("KASSIGNER_WORKFLOW_TESTS: STEGO RESTORE PICKER/DESCRIPTOR TXT VALIDATION/BACK OWNERS PASS");
    }
    ok
}

fn import_picker_navigation(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if !ctx.enter_onboarding_import_picker() {
        return false;
    }
    ctx.ad.stego.import.jpeg_count = 5;
    ctx.ad.stego.import.jpeg_selected = 0;
    if ctx.touch(ctx.down.x + 10, ctx.down.y + 10, false, true) != Some(true)
        || ctx.ad.stego.import.jpeg_selected != 4
    {
        return false;
    }
    if ctx.touch(ctx.up.x + 10, ctx.up.y + 10, false, true) != Some(true)
        || ctx.ad.stego.import.jpeg_selected != 0
    {
        return false;
    }
    let zone = ctx.list[0];
    ctx.touch(zone.x + zone.w / 2, zone.y + zone.h / 2, false, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::StegoImportDescChoice
}

fn descriptor_file_validation(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(StegoImportDescFile));
    if crate::runtime::interactions::stego::workflow_accept_descriptor_file(ctx.ad, b"").is_ok() {
        return false;
    }
    let oversized = [b'x'; 97];
    if crate::runtime::interactions::stego::workflow_accept_descriptor_file(ctx.ad, &oversized).is_ok() {
        return false;
    }
    crate::runtime::interactions::stego::workflow_accept_descriptor_file(ctx.ad, DESCRIPTOR).is_ok()
        && ctx.ad.navigation.app.state == AppState::StegoImportPass
}

fn import_back_owners(ctx: &mut StegoContext<'_, '_, '_>) -> bool {
    if ctx.touch(20, 20, true, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoImportDescChoice
    {
        return false;
    }
    if ctx.touch(20, 20, true, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoImportPick
    {
        return false;
    }
    ctx.touch(20, 20, true, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::AdvancedRestoreMenu
}

fn device_bound_round_trip(ctx: &mut StegoContext<'_, '_, '_>, artifacts: &MediaArtifacts) -> bool {
    let Some(payload) = extract_descriptor(&artifacts.descriptor_jpeg) else { return false; };
    if !ctx.enter_onboarding_import_descriptor() {
        return false;
    }
    ctx.ad.wallet.seeds.seed_mgr.zeroize_all();
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(StegoImportPass));
    if !crate::runtime::interactions::stego::workflow_open_payload(
        ctx.ad,
        ctx.display,
        ctx.delay,
        &mut ctx.backup_device,
        StegoCarrier::Descriptor,
        &payload,
        DESCRIPTOR,
        None,
    ) || ctx.ad.navigation.app.state != AppState::StegoHintReveal
        || &ctx.ad.stego.import.recovered_hint[..ctx.ad.stego.import.recovered_hint_len] != HINT
    {
        return false;
    }
    if ctx.touch(160, 120, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StegoHintPassphrase
    {
        return false;
    }
    if ctx.touch(20, 20, true, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StorageRecoveryAcknowledgement
        || !recovered_matches(ctx, artifacts)
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: STEGO DEVICE-BOUND JPEG HINT/RESTORE ROUND-TRIP PASS");
    true
}

fn portable_round_trip(ctx: &mut StegoContext<'_, '_, '_>, artifacts: &MediaArtifacts) -> bool {
    let mut payload = [0u8; stego::STEGO_PAYLOAD_SIZE];
    let Ok(length) = stego::extract_picture(&artifacts.picture_jpeg, DESCRIPTOR, &mut payload) else {
        return false;
    };
    if length != stego::STEGO_PAYLOAD_SIZE { return false; }
    if !ctx.enter_onboarding_import_descriptor() {
        return false;
    }
    ctx.ad.wallet.seeds.seed_mgr.zeroize_all();
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(StegoImportPass));
    if ctx.ad.navigation.app.state != AppState::StegoImportPass
        || !crate::runtime::interactions::stego::workflow_stage_portable_payload(
        ctx.ad, StegoCarrier::Picture, &payload, DESCRIPTOR,
    ) {
        return false;
    }
    ctx.set_text(WRONG_PASSWORD);
    if ctx.touch(290, 215, false, true) != Some(false)
        || ctx.ad.navigation.app.state != AppState::StegoImportPortablePassword
        || ctx.ad.wallet.seeds.seed_mgr.active_slot().is_some()
    {
        return false;
    }
    ctx.set_text(PASSWORD);
    if ctx.touch(290, 215, false, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StorageRecoveryAcknowledgement
        || !recovered_matches(ctx, artifacts)
    {
        return false;
    }
    let ok = crate::runtime::navigation::workflow_cleanup_onboarding_to_home(ctx.ad)
        && crate::runtime::workflow_tests::connected::root::home_ok(ctx.ad);
    if ok {
        log!("KASSIGNER_WORKFLOW_TESTS: STEGO PORTABLE WRONG-PASSWORD REJECT + CROSS-DEVICE RESTORE PASS");
    }
    ok
}

fn extract_descriptor(jpeg: &[u8]) -> Option<[u8; stego::STEGO_PAYLOAD_SIZE]> {
    let (offset, length) = stego::find_exif_app1(jpeg)?;
    let mut payload = [0u8; stego::STEGO_PAYLOAD_SIZE];
    if stego::extract_user_comment(&jpeg[offset..offset + length], &mut payload)
        != stego::STEGO_PAYLOAD_SIZE
    {
        return None;
    }
    Some(payload)
}

fn recovered_matches(ctx: &StegoContext<'_, '_, '_>, artifacts: &MediaArtifacts) -> bool {
    let Some(slot) = ctx.ad.wallet.seeds.seed_mgr.active_slot() else { return false; };
    slot.mnemonic_word_count() == Some(artifacts.word_count)
        && slot.indices[..usize::from(artifacts.word_count)]
            == artifacts.original_indices[..usize::from(artifacts.word_count)]
}
