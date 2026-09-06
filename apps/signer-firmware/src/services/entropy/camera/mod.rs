//! Camera-entropy façade: checked capture windows, retry policy, and mixing.

use esp_hal::{delay::Delay, dma::DmaRxBuf, lcd_cam::cam::Camera};
use sha2::{Digest, Sha256};

use signer_firmware_core::entropy::frame_noise::{
    CameraEntropyReport, CameraEntropyTracker, MAX_CAMERA_HEALTH_WINDOWS, should_retry_camera_window,
};

use super::{mixer, platform, trng};
mod dvp;
#[cfg(feature = "waveshare")]
mod waveshare;

const FRAMES_PER_WINDOW: u8 = 8;
const INTER_FRAME_DELAY_MS: u32 = 10;
const RETRY_SETTLE_MS: u32 = 150;
pub(crate) fn mix_frames<'a>(
    pool: &mut [u8; 32],
    #[cfg(feature = "m5stack")] i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut Delay,
    liveness: &mut dyn FnMut(),
    idle_ticks: u32,
    camera: &mut Option<Camera<'a>>,
    dma_buffer: &mut Option<DmaRxBuf>,
    #[cfg(feature = "e12-capture")] capture: Option<&mut crate::diagnostics::e12_capture::Capture>,
) -> CameraEntropyReport {
    #[cfg(feature = "waveshare")]
    prepare_waveshare_camera(delay, camera);
    #[cfg(feature = "m5stack")]
    let camera_isp_restore = crate::hw::camera::begin_entropy_capture(i2c);
    #[cfg(feature = "m5stack")]
    if camera_isp_restore.is_none() {
        crate::log!("   GC0308 entropy mode unavailable; camera health remains fail-closed");
    }

    #[cfg(feature = "e12-capture")]
    let mut capture = capture;
    let mut report = CameraEntropyTracker::new().report();
    for window_index in 0..MAX_CAMERA_HEALTH_WINDOWS {
        report = mix_window(
            pool, idle_ticks, delay, camera, dma_buffer, window_index,
            #[cfg(feature = "e12-capture")]
            capture.as_deref_mut(),
        );
        // One completed camera-health window is a bounded liveness checkpoint.
        // A frame/capture that hangs inside the window still cannot feed TIMG0.
        liveness();
        if report.healthy() { break; }
        if should_retry_camera_window(window_index, report) {
            log_retry(window_index, report);
            // Give auto-exposure and the physical scene a short settling window
            // before the next independent health sample. Acceptance thresholds
            // remain unchanged and every retry starts with a fresh tracker.
            delay.delay_millis(RETRY_SETTLE_MS);
        }
    }

    #[cfg(feature = "waveshare")]
    restore_waveshare_camera(camera);
    #[cfg(feature = "m5stack")]
    if let Some(prior) = camera_isp_restore {
        if !crate::hw::camera::end_entropy_capture(i2c, prior) {
            crate::log!("   GC0308 entropy-mode restore failed");
        }
    }
    report
}
fn mix_window<'a>(
    pool: &mut [u8; 32],
    idle_ticks: u32,
    delay: &mut Delay,
    camera: &mut Option<Camera<'a>>,
    dma_buffer: &mut Option<DmaRxBuf>,
    window_index: u8,
    #[cfg(feature = "e12-capture")] capture: Option<&mut crate::diagnostics::e12_capture::Capture>,
) -> CameraEntropyReport {
    let mut tracker = CameraEntropyTracker::new();
    #[cfg(feature = "e12-capture")]
    let mut capture = capture;
    for frame_index in 0..FRAMES_PER_WINDOW {
        let tag = window_index.saturating_mul(FRAMES_PER_WINDOW).saturating_add(frame_index);
        let captured = capture_frame(
            pool, tag, idle_ticks, delay, camera, dma_buffer, &mut tracker,
            #[cfg(feature = "e12-capture")]
            capture.as_deref_mut(),
        );
        if !captured {
            crate::log!("   Camera entropy frame {} unavailable", tag + 1);
        }
        delay.delay_millis(INTER_FRAME_DELAY_MS);
    }
    tracker.report()
}

fn capture_frame<'a>(
    pool: &mut [u8; 32], frame_tag: u8, idle_ticks: u32, delay: &mut Delay,
    camera: &mut Option<Camera<'a>>, dma_buffer: &mut Option<DmaRxBuf>,
    tracker: &mut CameraEntropyTracker,
    #[cfg(feature = "e12-capture")] capture: Option<&mut crate::diagnostics::e12_capture::Capture>,
) -> bool {
    #[cfg(feature = "e12-capture")]
    let mut capture = capture;
    let captured = dvp::mix_frame(
        pool, frame_tag, idle_ticks, delay, camera, dma_buffer, tracker,
        #[cfg(feature = "e12-capture")]
        capture.as_deref_mut(),
    );
    #[cfg(feature = "waveshare")]
    let captured = captured || (camera.is_none() && waveshare::mix_frame(
        pool, frame_tag, idle_ticks, delay, tracker,
        #[cfg(feature = "e12-capture")]
        capture.as_deref_mut(),
    ));
    captured
}

pub(super) fn mix_observation(
    pool: &mut [u8; 32], frame_tag: u8, idle_ticks: u32, pixels: &[u8],
    tracker: &mut CameraEntropyTracker,
    #[cfg(feature = "e12-capture")] capture: Option<&mut crate::diagnostics::e12_capture::Capture>,
) {
    #[cfg(feature = "e12-capture")]
    if let Some(capture) = capture { capture.push_frame(pixels); }
    let _ = tracker.observe(pixels);
    let mut hasher = Sha256::new();
    hasher.update(pixels);
    hasher.update([frame_tag, (idle_ticks & 0xff) as u8]);
    hasher.update(platform::systimer_low().to_le_bytes());
    hasher.update(trng::sample().to_le_bytes());
    mixer::xor_digest(pool, &hasher.finalize());
}

fn log_retry(window_index: u8, report: CameraEntropyReport) {
    crate::log!(
        "   Camera entropy auto-retry {}/{}: frames {} live {}/{} stale-run {}",
        window_index + 2, MAX_CAMERA_HEALTH_WINDOWS, report.frames_captured,
        report.live_deltas, report.deltas_observed, report.max_consecutive_stale_deltas
    );
}

#[cfg(feature = "waveshare")]
fn prepare_waveshare_camera(delay: &mut Delay, camera: &mut Option<Camera<'_>>) {
    if camera.is_none() { crate::hw::cam_dma::start_capture(); delay.delay_millis(50); }
}

#[cfg(feature = "waveshare")]
fn restore_waveshare_camera(camera: &mut Option<Camera<'_>>) {
    if camera.is_none() { crate::hw::cam_dma::stop(); }
}
