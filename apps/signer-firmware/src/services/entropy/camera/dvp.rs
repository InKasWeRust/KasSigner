//! ESP-HAL DVP acquisition adapter for camera entropy.

use esp_hal::{delay::Delay, dma::DmaRxBuf, lcd_cam::cam::Camera};
use signer_firmware_core::entropy::frame_noise::CameraEntropyTracker;

use crate::hw::shared::dvp::{receive_full_frame, FrameCaptureStatus};

pub(super) fn mix_frame<'a>(
    pool: &mut [u8; 32],
    frame_tag: u8,
    idle_ticks: u32,
    delay: &mut Delay,
    camera: &mut Option<Camera<'a>>,
    dma_buffer: &mut Option<DmaRxBuf>,
    tracker: &mut CameraEntropyTracker,
    #[cfg(feature = "e12-capture")] capture: Option<&mut crate::diagnostics::e12_capture::Capture>,
) -> bool {
    let Some(camera_value) = camera.take() else { return false; };
    let Some(buffer_value) = dma_buffer.take() else {
        *camera = Some(camera_value);
        return false;
    };

    let (status, camera_back, buffer_back) = receive_full_frame(camera_value, buffer_value, delay);
    let captured = status == FrameCaptureStatus::Complete;
    if captured {
        super::mix_observation(
            pool, frame_tag, idle_ticks, buffer_back.as_slice(), tracker,
            #[cfg(feature = "e12-capture")]
            capture,
        );
    } else {
        match status {
            FrameCaptureStatus::TimedOut => crate::log!("   Entropy DVP frame timed out; partial buffer rejected"),
            FrameCaptureStatus::ReceiveFailed => crate::log!("   Entropy DVP receive failed"),
            FrameCaptureStatus::Complete => {}
        }
    }
    *dma_buffer = Some(buffer_back);
    *camera = Some(camera_back);
    captured
}
