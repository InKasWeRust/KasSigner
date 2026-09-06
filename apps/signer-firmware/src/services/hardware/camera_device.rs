//! Controller-facing camera transport/decode service facade.

#[cfg(feature = "waveshare")]
pub(crate) use crate::hw::decode_core::DecodeOutcome;
#[cfg(any(feature = "waveshare", feature = "m5stack"))]
pub(crate) use crate::hw::shared::dvp::FrameCaptureStatus;

#[cfg(feature = "waveshare")]
pub(crate) const FRAME_W: usize = crate::hw::cam_dma::FRAME_W;
#[cfg(feature = "waveshare")]
pub(crate) const FRAME_H: usize = crate::hw::cam_dma::FRAME_H;
#[cfg(feature = "waveshare")]
pub(crate) const BPL: usize = crate::hw::cam_dma::BPL;

#[cfg(feature = "waveshare")]
pub(crate) fn log_status() { crate::hw::cam_dma::log_status(); }
#[cfg(feature = "waveshare")]
pub(crate) fn stop() { crate::hw::cam_dma::stop(); }
#[cfg(feature = "waveshare")]
pub(crate) fn start_capture() { crate::hw::cam_dma::start_capture(); }
#[cfg(feature = "waveshare")]
pub(crate) fn poll_done() -> bool { crate::hw::cam_dma::poll_done() }
#[cfg(feature = "waveshare")]
pub(crate) fn with_frame<R>(operation: impl FnOnce(&[u8]) -> R) -> Option<R> {
    crate::hw::cam_dma::with_frame(operation)
}
#[cfg(feature = "waveshare")]
pub(crate) fn bump_generation() { crate::hw::decode_core::bump_generation(); }
#[cfg(feature = "waveshare")]
pub(crate) fn current_generation() -> u8 { crate::hw::decode_core::current_generation() }
#[cfg(feature = "waveshare")]
pub(crate) fn submit_decode(gray: &[u8], width: usize, height: usize) -> bool {
    crate::hw::decode_core::submit(gray, width, height)
}
#[cfg(feature = "waveshare")]
pub(crate) fn take_decode_result() -> Option<DecodeOutcome> {
    crate::hw::decode_core::take_result()
}
#[cfg(any(feature = "waveshare", feature = "m5stack"))]
pub(crate) fn receive_full_frame<'a>(
    camera: esp_hal::lcd_cam::cam::Camera<'a>,
    buffer: esp_hal::dma::DmaRxBuf,
    delay: &mut esp_hal::delay::Delay,
) -> (FrameCaptureStatus, esp_hal::lcd_cam::cam::Camera<'a>, esp_hal::dma::DmaRxBuf) {
    crate::hw::shared::dvp::receive_full_frame(camera, buffer, delay)
}
