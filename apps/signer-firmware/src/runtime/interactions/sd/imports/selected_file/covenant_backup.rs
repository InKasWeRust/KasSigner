//! Covenant backup presentation loaded from SD.
//!
//! QR presentation is owned by the normal event loop. This controller only
//! queues the payload and selects the state to return to after presentation.

pub(super) fn present(
    ad: &mut crate::runtime::data::AppData,
    payload: &[u8],
) {
    if crate::runtime::qr_presentation::present_payload(
        ad,
        payload,
        crate::runtime::navigation::continuation!(SdFileList),
    ).is_err() {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdFileList));
    }
}
