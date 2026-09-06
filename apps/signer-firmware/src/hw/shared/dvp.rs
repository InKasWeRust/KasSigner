//! Bounded ESP-HAL DVP DMA capture primitive shared by camera consumers.

use esp_hal::{delay::Delay, dma::DmaRxBuf, lcd_cam::cam::Camera};

const CAPTURE_POLL_US: u32 = 50;
const CAPTURE_MAX_POLLS: u32 = 10_000; // 500 ms: UI must never block for multi-second camera waits.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameCaptureStatus {
    Complete,
    TimedOut,
    ReceiveFailed,
}

/// Receive one descriptor-bounded DVP buffer without an unbounded `wait()` spin.
///
/// `Camera::receive` enables CAM_STOP_EN. Once `is_done()` is true, ESP-HAL has
/// observed the camera stop after the DMA path stopped draining (normally because
/// the supplied descriptor-backed buffer is full). Only then is `wait()` used;
/// on timeout the partial transfer is stopped and must not be consumed as a frame.
pub(crate) fn receive_full_frame<'a>(
    camera: Camera<'a>,
    buffer: DmaRxBuf,
    delay: &mut Delay,
) -> (FrameCaptureStatus, Camera<'a>, DmaRxBuf) {
    let transfer = match camera.receive(buffer) {
        Ok(transfer) => transfer,
        Err((_error, camera, buffer)) => {
            return (FrameCaptureStatus::ReceiveFailed, camera, buffer);
        }
    };

    let mut polls = 0u32;
    loop {
        if transfer.is_done() {
            let (_dma_result, camera, buffer) = transfer.wait();
            return (FrameCaptureStatus::Complete, camera, buffer);
        }
        polls = polls.saturating_add(1);
        if polls > CAPTURE_MAX_POLLS {
            let (camera, buffer) = transfer.stop();
            return (FrameCaptureStatus::TimedOut, camera, buffer);
        }
        delay.delay_micros(CAPTURE_POLL_US);
    }
}
