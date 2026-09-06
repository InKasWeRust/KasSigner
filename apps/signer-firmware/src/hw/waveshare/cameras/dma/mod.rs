// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Callback-scoped façade for Waveshare ping-pong camera DMA.

mod buffers;
mod capture;
mod descriptors;
mod owner;
mod registers;

use capture::CameraDma;
use owner::CameraDmaSlot;

#[cfg(not(feature = "cam640"))]
pub const FRAME_W: usize = 480;
#[cfg(not(feature = "cam640"))]
pub const FRAME_H: usize = 480;
#[cfg(feature = "cam640")]
pub const FRAME_W: usize = 640;
#[cfg(feature = "cam640")]
pub const FRAME_H: usize = 640;
pub const BPL: usize = FRAME_W;
pub const FRAME_BYTES: usize = BPL * FRAME_H;

static CAMERA_DMA: CameraDmaSlot = CameraDmaSlot::new();

pub fn init() -> bool {
    crate::log!(
        "   cam_dma: init {}×{} double-buffered PSRAM",
        FRAME_W,
        FRAME_H
    );
    if CAMERA_DMA.is_initialized() {
        return true;
    }
    let Some(owner) = CameraDma::allocate() else {
        return false;
    };
    CAMERA_DMA.initialize(owner);
    let configured = CAMERA_DMA.with_mut(CameraDma::configure).is_some();
    if configured {
        crate::log!("   cam_dma: ready");
    }
    configured
}

pub fn start_capture() {
    let _ = CAMERA_DMA.with_mut(CameraDma::start);
}

pub fn poll_done() -> bool {
    CAMERA_DMA.with_mut(CameraDma::poll).unwrap_or(false)
}

pub fn with_frame<R>(operation: impl FnOnce(&[u8]) -> R) -> Option<R> {
    CAMERA_DMA
        .with_mut(|owner| owner.completed_frame().map(operation))
        .flatten()
}

pub fn copy_entropy_sample(output: &mut [u8]) -> usize {
    CAMERA_DMA
        .with_mut(|owner| owner.copy_entropy_sample(output))
        .unwrap_or(0)
}

pub fn stop() {
    let _ = CAMERA_DMA.with_mut(CameraDma::stop);
}

pub fn log_status() {
    let _ = CAMERA_DMA.with_mut(|owner| owner.log_status());
}
