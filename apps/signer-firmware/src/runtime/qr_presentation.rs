//! Signed-QR presentation preparation before any renderer runs.

use crate::runtime::{data::AppData, input::AppState, navigation::ContinuationRoute};

const SINGLE_FRAME_LIMIT: usize = 134;

pub(crate) fn payload_limit(ad: &AppData) -> usize {
    match ad.qr.presentation.mode {
        1 => 70,
        2 => 40,
        3 => 25,
        4 => 12,
        _ if ad.qr.presentation.large => 40,
        _ => 91,
    }
}

pub(crate) fn is_single_frame(ad: &AppData) -> bool {
    !ad.qr.presentation.large
        && ad.qr.presentation.mode == 0
        && ad.qr.outgoing.length <= SINGLE_FRAME_LIMIT
}

/// Prepare multi-frame QR state before rendering so UI code never proposes a
/// navigation transition. Oversized payloads remain in `ShowQR` so the renderer
/// can display the existing "Payload Too Large" rejection surface.
pub(crate) fn prepare_navigation(ad: &mut AppData) {
    if ad.navigation.app.state != AppState::ShowQR
        || ad.qr.outgoing.length == 0
        || ad.qr.outgoing.frame_count != 0
        || is_single_frame(ad)
    {
        return;
    }
    let frame_count = ad.qr.outgoing.length.div_ceil(payload_limit(ad));
    if frame_count > shared_signer::qr_frame::MAX_FRAMES { return; }
    ad.qr.outgoing.frame = 0;
    ad.qr.outgoing.frame_count = frame_count as u8;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowQrModeChoice));
}

/// Present an anti-klepto final response without re-entering the generic
/// signed-transaction destination/density chooser. The anti-klepto request
/// already fixes the protocol peer and transport; only the multi-frame
/// auto/manual presentation decision remains relevant.
pub(crate) fn present_anti_klepto_final(ad: &mut AppData) -> bool {
    use crate::runtime::data::AntiKleptoPhase;
    use crate::runtime::navigation::NavigationOwner;

    if ad.navigation.app.state != AppState::ScanQR
        || ad.navigation.owner != NavigationOwner::Signing
        || ad.signing.anti_klepto.phase != AntiKleptoPhase::FinalResponse
        || ad.qr.outgoing.length == 0
    {
        return false;
    }

    ad.qr.presentation.large = false;
    ad.qr.presentation.mode = 0;
    ad.qr.presentation.via_density = false;
    ad.qr.outgoing.frame = 0;
    ad.qr.outgoing.frame_count = 0;
    ad.qr.outgoing.manual_frames = false;

    if is_single_frame(ad) {
        return crate::runtime::effects::route(
            ad,
            crate::runtime::navigation::route!(ShowQR),
        );
    }

    let frame_count = ad.qr.outgoing.length.div_ceil(payload_limit(ad));
    if frame_count > shared_signer::qr_frame::MAX_FRAMES {
        // Preserve the existing renderer-owned oversized-payload error surface.
        return crate::runtime::effects::route(
            ad,
            crate::runtime::navigation::route!(ShowQR),
        );
    }
    ad.qr.outgoing.frame_count = frame_count as u8;
    crate::runtime::effects::route(
        ad,
        crate::runtime::navigation::route!(ShowQrModeChoice),
    )
}


/// Queue a controller-produced payload for the normal event-loop-owned QR
/// presentation flow. This replaces modal controller loops that used to own
/// touch transport while cycling QR frames.
pub(crate) fn present_payload(
    ad: &mut AppData,
    payload: &[u8],
    close_state: ContinuationRoute,
) -> Result<(), ()> {
    ad.qr.outgoing.ensure_len(payload.len())?;
    ad.qr.outgoing.clear();
    ad.qr.outgoing.buffer[..payload.len()].copy_from_slice(payload);
    ad.qr.outgoing.length = payload.len();
    ad.qr.outgoing.close_state = Some(close_state);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowQR));
    Ok(())
}
