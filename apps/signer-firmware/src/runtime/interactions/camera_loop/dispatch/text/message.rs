//! Safe Sign Message QR source: accepts message bytes, never a generic digest.
use super::super::super::{AppData, display};
use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::runtime::input::AppState;

pub(in crate::runtime::interactions::camera_loop::dispatch) fn is_pending(ad: &AppData) -> bool {
    ad.navigation.app.state == AppState::SignMsgScan
}

#[cfg(feature = "workflow-test-auto")]
pub(in crate::runtime::interactions::camera_loop::dispatch) fn workflow_process(
    data: &[u8],
    ad: &mut AppData,
) {
    if data.is_empty()
        || data.len() > ad.signing.message.payload.len()
        || core::str::from_utf8(data).is_err()
        || data
            .iter()
            .any(|byte| *byte < 0x20 && !matches!(*byte, b'\n' | b'\r' | b'\t'))
    {
        crate::runtime::effects::redraw(ad);
        return;
    }
    ad.signing.message.payload[..data.len()].copy_from_slice(data);
    ad.signing.message.payload_len = data.len();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgPreview));
    crate::runtime::effects::redraw(ad);
}

pub(in crate::runtime::interactions::camera_loop::dispatch) fn process(
    data: &[u8], len: usize, ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>, delay: &mut esp_hal::delay::Delay,
) {
    let message = &data[..len.min(data.len())];
    if message.is_empty() || message.len() > ad.signing.message.payload.len()
        || core::str::from_utf8(message).is_err()
        || message.iter().any(|byte| *byte < 0x20 && !matches!(*byte, b'\n' | b'\r' | b'\t'))
    {
        show_rejection(
            boot_display, delay, "Message QR must contain readable text", 1_200, ErrorSound::Beep,
        );
        crate::runtime::effects::redraw(ad);
        return;
    }
    ad.signing.message.payload[..message.len()].copy_from_slice(message);
    ad.signing.message.payload_len = message.len();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgPreview));
    crate::runtime::effects::redraw(ad);
}
