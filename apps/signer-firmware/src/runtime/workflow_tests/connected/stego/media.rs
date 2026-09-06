use alloc::vec::Vec;
use super::StegoContext;
use crate::services::stego::{self, StegoCarrier, StegoSecurity};
use offline_signer::crypto::{device_bound_storage::NONCE_SIZE, password_kdf::SALT_SIZE};

pub(super) const DESCRIPTOR: &[u8] = b"KasSigner E2E carrier";
pub(super) const PASSWORD: &[u8] = b"CorrectHorse9";
pub(super) const WRONG_PASSWORD: &[u8] = b"WrongHorse9";
pub(super) const HINT: &[u8] = b"favorite station";
const NOISE_JPEG: &[u8] = include_bytes!("../../fixtures/stego_noise.jpg");
const FLAT_JPEG: &[u8] = include_bytes!("../../fixtures/stego_flat.jpg");
const SALT: [u8; SALT_SIZE] = [0x54; SALT_SIZE];
const NONCE: [u8; NONCE_SIZE] = [0x48; NONCE_SIZE];

pub(super) struct MediaArtifacts {
    pub(super) original_indices: [u16; 24],
    pub(super) word_count: u8,
    pub(super) device_descriptor_payload: [u8; stego::STEGO_PAYLOAD_SIZE],
    pub(super) portable_picture_payload: [u8; stego::STEGO_PAYLOAD_SIZE],
    pub(super) descriptor_jpeg: Vec<u8>,
    pub(super) picture_jpeg: Vec<u8>,
}

pub(super) fn exercise(ctx: &mut StegoContext<'_, '_, '_>) -> Option<MediaArtifacts> {
    let artifacts = build_artifacts(ctx)?;
    if !descriptor_carrier(&artifacts) || !picture_carrier(&artifacts) {
        return None;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: STEGO DESCRIPTOR JPEG VALID/EXTRACT ROUND-TRIP PASS");
    log!("KASSIGNER_WORKFLOW_TESTS: STEGO PICTURE CAPACITY/EMBED/EXTRACT + LOW-CAPACITY REJECT PASS");
    if !ctx.enter_export_mode() {
        return None;
    }
    ctx.ad.stego.session.result_ok = true;
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(StegoResult));
    ctx.redraw_step();
    if ctx.touch(160, 120, false, true) != Some(true)
        || !crate::runtime::workflow_tests::connected::root::home_ok(ctx.ad)
    {
        return None;
    }
    Some(artifacts)
}

fn build_artifacts(ctx: &mut StegoContext<'_, '_, '_>) -> Option<MediaArtifacts> {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad) {
        return None;
    }
    let slot = ctx.ad.wallet.seeds.seed_mgr.active_slot()?;
    let original_indices = slot.indices;
    let word_count = slot.mnemonic_word_count()?;
    let mut device_descriptor_payload = [0u8; stego::STEGO_PAYLOAD_SIZE];
    stego::pack_for_test(
        StegoSecurity::DeviceBound,
        StegoCarrier::Descriptor,
        &original_indices,
        word_count,
        HINT,
        DESCRIPTOR,
        b"",
        &mut ctx.backup_device,
        &SALT,
        &NONCE,
        &mut device_descriptor_payload,
    ).ok()?;
    let mut portable_picture_payload = [0u8; stego::STEGO_PAYLOAD_SIZE];
    stego::pack_for_test(
        StegoSecurity::Portable,
        StegoCarrier::Picture,
        &original_indices,
        word_count,
        b"",
        DESCRIPTOR,
        PASSWORD,
        &mut ctx.backup_device,
        &SALT,
        &NONCE,
        &mut portable_picture_payload,
    ).ok()?;
    let descriptor_jpeg = descriptor_jpeg(&device_descriptor_payload)?;
    let picture_jpeg = picture_jpeg(&portable_picture_payload)?;
    Some(MediaArtifacts {
        original_indices,
        word_count,
        device_descriptor_payload,
        portable_picture_payload,
        descriptor_jpeg,
        picture_jpeg,
    })
}

fn descriptor_jpeg(payload: &[u8]) -> Option<Vec<u8>> {
    let (width, height) = stego::jpeg_dimensions(NOISE_JPEG)?;
    let mut app1 = alloc::vec![0u8; 65_537];
    let datetime = *b"2026:08:20 20:48:00";
    let app1_len = stego::build_exif_template(
        DESCRIPTOR,
        payload,
        width,
        height,
        b"KasSigner E2E",
        &datetime,
        &mut app1,
    );
    if app1_len == 0 { return None; }
    let mut output = alloc::vec![0u8; NOISE_JPEG.len() + app1_len + 16];
    let length = stego::inject_exif(NOISE_JPEG, &app1[..app1_len], &mut output);
    if length == 0 { return None; }
    output.truncate(length);
    Some(output)
}

fn picture_jpeg(payload: &[u8]) -> Option<Vec<u8>> {
    let required = ((payload.len() + 2) * 8) as u32;
    if stego::capacity_bits(NOISE_JPEG, DESCRIPTOR).ok()? < required { return None; }
    let mut output = alloc::vec![0u8; NOISE_JPEG.len() * 2 + 4_096];
    let length = stego::embed_picture(NOISE_JPEG, payload, DESCRIPTOR, &mut output).ok()?;
    output.truncate(length);
    Some(output)
}

fn descriptor_carrier(artifacts: &MediaArtifacts) -> bool {
    if !artifacts.descriptor_jpeg.starts_with(&[0xff, 0xd8])
        || stego::jpeg_dimensions(&artifacts.descriptor_jpeg).is_none()
    {
        return false;
    }
    let Some((offset, length)) = stego::find_exif_app1(&artifacts.descriptor_jpeg) else { return false; };
    let mut extracted = [0u8; stego::STEGO_PAYLOAD_SIZE];
    let count = stego::extract_user_comment(
        &artifacts.descriptor_jpeg[offset..offset + length],
        &mut extracted,
    );
    count == stego::STEGO_PAYLOAD_SIZE && extracted == artifacts.device_descriptor_payload
}

fn picture_carrier(artifacts: &MediaArtifacts) -> bool {
    let required = ((stego::STEGO_PAYLOAD_SIZE + 2) * 8) as u32;
    if stego::capacity_bits(FLAT_JPEG, DESCRIPTOR).unwrap_or(0) >= required {
        return false;
    }
    let mut extracted = [0u8; stego::STEGO_PAYLOAD_SIZE];
    let Ok(length) = stego::extract_picture(&artifacts.picture_jpeg, DESCRIPTOR, &mut extracted) else {
        return false;
    };
    if length != stego::STEGO_PAYLOAD_SIZE || extracted != artifacts.portable_picture_payload {
        return false;
    }
    let mut wrong = [0u8; stego::STEGO_PAYLOAD_SIZE];
    match stego::extract_picture(&artifacts.picture_jpeg, b"wrong descriptor", &mut wrong) {
        Ok(length) => length != stego::STEGO_PAYLOAD_SIZE || wrong != artifacts.portable_picture_payload,
        Err(_) => true,
    }
}
