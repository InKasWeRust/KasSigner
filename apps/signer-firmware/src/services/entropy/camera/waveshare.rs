//! Waveshare raw-DMA acquisition adapter for camera entropy.

use esp_hal::delay::Delay;
use signer_firmware_core::entropy::frame_noise::CameraEntropyTracker;

pub(super) fn mix_frame(
    pool: &mut [u8; 32],
    frame_tag: u8,
    idle_ticks: u32,
    delay: &mut Delay,
    tracker: &mut CameraEntropyTracker,
    #[cfg(feature = "e12-capture")] capture: Option<&mut crate::diagnostics::e12_capture::Capture>,
) -> bool {
    delay.delay_millis(80);
    crate::hw::cam_dma::poll_done();
    delay.delay_millis(80);
    crate::hw::cam_dma::poll_done();

    let Ok(mut pixels) = crate::services::memory::zeroed_bytes(4096) else { return false; };
    let captured = crate::hw::cam_dma::copy_entropy_sample(&mut pixels);
    if captured == 0 { return false; }
    super::mix_observation(
        pool, frame_tag, idle_ticks, &pixels[..captured], tracker,
        #[cfg(feature = "e12-capture")]
        capture,
    );
    shared_signer::bytes::zeroize_bytes(&mut pixels);
    true
}
