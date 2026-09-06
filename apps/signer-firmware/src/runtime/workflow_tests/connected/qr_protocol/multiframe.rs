use alloc::vec;
use crate::runtime::input::AppState;
use super::QrContext;

const FRAGMENT: usize = 120;

pub(super) fn exercise(ctx: &mut QrContext<'_, '_, '_>) -> bool {
    let Some(payload) = super::super::signing::fixture::wire(
        ctx.ad,
        super::super::signing::fixture::WireFormat::CompactKspt,
    ) else { return false; };
    let Some(frames) = encode_frames(&payload) else { return false; };
    if frames.len() < 3 || !enter_scan(ctx) { return false; }
    let mut session = new_camera_session();
    feed(ctx, &mut session, &frames[1]);
    feed(ctx, &mut session, &frames[1]);
    if ctx.ad.navigation.app.state != AppState::ScanQR { return false; }
    let Some(mixed) = mixed_frame(&frames[1]) else { return false; };
    feed(ctx, &mut session, &mixed);
    let Some(conflict) = conflicting_duplicate(&frames[1]) else { return false; };
    feed(ctx, &mut session, &conflict);
    if ctx.ad.navigation.app.state != AppState::ScanQR { return false; }
    feed(ctx, &mut session, &frames[0]);
    if ctx.ad.navigation.app.state != AppState::ScanQR { return false; }
    for frame in frames.iter().skip(2) { feed(ctx, &mut session, frame); }
    if ctx.ad.navigation.app.state != AppState::ConfirmTx { return false; }
    if !ctx.tx_back() || !super::super::root::home_ok(ctx.ad) { return false; }
    if !invalid_frame_matrix() { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: QR MULTIFRAME OUT-OF-ORDER/DUPLICATE/MIXED/MISSING/COMPLETE PASS {}", frames.len());
    true
}


#[cfg(feature = "m5stack")]
fn new_camera_session() -> crate::runtime::interactions::camera_loop::CameraSessionState {
    crate::runtime::interactions::camera_loop::CameraSessionState::new()
}

#[cfg(feature = "waveshare")]
fn new_camera_session() -> crate::runtime::interactions::camera_loop::CameraSessionState {
    crate::runtime::interactions::camera_loop::CameraSessionState::new(cfg!(feature = "ov2640-wide"))
}

fn enter_scan(ctx: &mut QrContext<'_, '_, '_>) -> bool {
    if !super::super::root::home_ok(ctx.ad) { return false; }
    let zone = crate::ui::layout::HOME_GRID_ZONES[1];
    crate::runtime::interactions::menu::handle_connected_root_probe(ctx.ad, zone.x + zone.w / 2, zone.y + zone.h / 2)
        && ctx.ad.navigation.app.state == AppState::ScanQR
}

fn feed(
    ctx: &mut QrContext<'_, '_, '_>,
    session: &mut crate::runtime::interactions::camera_loop::CameraSessionState,
    frame: &[u8],
) {
    crate::runtime::interactions::camera_loop::workflow_process_multiframe(
        session, frame, ctx.ad, ctx.display, ctx.delay, ctx.i2c,
    );
}

fn encode_frames(payload: &[u8]) -> Option<alloc::vec::Vec<alloc::vec::Vec<u8>>> {
    let total = payload.len().div_ceil(FRAGMENT);
    let total_u8 = u8::try_from(total).ok()?;
    let id = shared_signer::qr_frame::session_id(payload);
    let mut frames = alloc::vec::Vec::with_capacity(total);
    for (index, fragment) in payload.chunks(FRAGMENT).enumerate() {
        let mut frame = vec![0u8; shared_signer::qr_frame::FRAME_HEADER_LEN + fragment.len() + 8];
        let len = shared_signer::qr_frame::encode_frame(&id, index as u8, total_u8, fragment, &mut frame).ok()?;
        frame.truncate(len);
        frames.push(frame);
    }
    Some(frames)
}

fn mixed_frame(source: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let parsed = shared_signer::qr_frame::parse_frame(source).ok()?;
    let other = shared_signer::qr_frame::session_id(b"different QR session");
    let mut output = vec![0u8; source.len() + 8];
    let len = shared_signer::qr_frame::encode_frame(
        &other, parsed.frame_index, parsed.total_frames, parsed.fragment, &mut output,
    ).ok()?;
    output.truncate(len);
    Some(output)
}

fn conflicting_duplicate(source: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let parsed = shared_signer::qr_frame::parse_frame(source).ok()?;
    let mut fragment = parsed.fragment.to_vec();
    fragment[0] ^= 0x01;
    let mut output = vec![0u8; source.len() + 8];
    let len = shared_signer::qr_frame::encode_frame(
        &parsed.session_id, parsed.frame_index, parsed.total_frames, &fragment, &mut output,
    ).ok()?;
    output.truncate(len);
    Some(output)
}

fn invalid_frame_matrix() -> bool {
    let id = shared_signer::qr_frame::session_id(b"frame bounds");
    let mut output = [0u8; 64];
    let too_many = u8::try_from(shared_signer::qr_frame::MAX_FRAMES + 1).unwrap_or(u8::MAX);
    shared_signer::qr_frame::encode_frame(&id, 0, 1, b"x", &mut output).is_err()
        && shared_signer::qr_frame::encode_frame(&id, 2, 2, b"x", &mut output).is_err()
        && shared_signer::qr_frame::encode_frame(&id, 0, too_many, b"x", &mut output).is_err()
        && shared_signer::qr_frame::parse_frame(b"KQ\x01").is_err()
}
