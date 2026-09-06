// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Stable platform-adaptive camera capture façade.

use super::{AppData, DmaRxBuf, DvpCamera, camera, display};
#[cfg(feature = "m5stack")]
use super::dvp_capture::CaptureOutcome;
use super::session::prepare_cycle;
use super::state::CameraSessionState;
use crate::runtime::data::CameraScanFault;

#[cfg(feature = "m5stack")]
const CAPTURE_OUTCOME_FAULT: [CameraScanFault; 4] = [
    CameraScanFault::None,
    CameraScanFault::CaptureTimeout,
    CameraScanFault::CaptureFailed,
    CameraScanFault::RuntimeResources,
];

fn fault_error(fault: CameraScanFault) -> crate::runtime::presentation::ErrorSpec {
    match fault {
        CameraScanFault::None => crate::runtime::presentation::CAMERA_CAPTURE,
        CameraScanFault::MemoryUnavailable => crate::runtime::presentation::CAMERA_MEMORY,
        #[cfg(feature = "m5stack")]
        CameraScanFault::StartupUnavailable | CameraScanFault::RuntimeResources => {
            crate::runtime::presentation::CAMERA_UNAVAILABLE
        }
        #[cfg(feature = "m5stack")]
        CameraScanFault::CaptureTimeout | CameraScanFault::CaptureFailed => {
            crate::runtime::presentation::CAMERA_CAPTURE
        }
    }
}

fn latch_fault(ad: &mut AppData, fault: CameraScanFault) {
    ad.qr.scan.latch_camera_fault(fault);
    log!("   CAMERA fault {:?}", fault);
    let return_to = crate::runtime::presentation::previous_stable_screen(ad);
    crate::runtime::presentation::show_error_spec_to(ad, return_to, fault_error(fault));
}

#[cfg(feature = "m5stack")]
fn m5_preflight_fault(
    status: camera::CameraStatus,
    camera_ready: bool,
    dma_ready: bool,
) -> CameraScanFault {
    if status == camera::CameraStatus::Error { return CameraScanFault::StartupUnavailable; }
    if !camera_ready || !dma_ready { return CameraScanFault::RuntimeResources; }
    CameraScanFault::None
}

#[cfg(feature = "m5stack")]
fn handle_m5_outcome(
    session: &mut CameraSessionState,
    ad: &mut AppData,
    outcome: CaptureOutcome,
) {
    let fault = CAPTURE_OUTCOME_FAULT[outcome as usize];
    if !fault.is_fault() {
        session.capture_succeeded();
        return;
    }
    if session.capture_failed() {
        latch_fault(ad, fault);
    }
}

fn camera_entry_reset(session: &mut CameraSessionState, ad: &mut AppData) -> bool {
    let entered = session.enter_screen(ad.navigation.app.state);
    if entered {
        ad.qr.scan.begin_camera_entry();
        log!("   CAMERA session entry: {:?}", ad.navigation.app.state);
    }
    ad.qr.scan.take_camera_reset_request()
}

/// Run one camera capture and QR-decode cycle.
#[inline(never)]
pub fn run_camera_cycle(
    session: &mut CameraSessionState,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    dvp_camera_opt: &mut Option<DvpCamera<'_>>,
    cam_status: &mut camera::CameraStatus,
    cam_dma_buf_opt: &mut Option<DmaRxBuf>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    let reset_entry = camera_entry_reset(session, ad);
    if ad.qr.scan.has_camera_fault() { return; }

    #[cfg(feature = "m5stack")]
    {
        let fault = m5_preflight_fault(
            *cam_status,
            dvp_camera_opt.is_some(),
            cam_dma_buf_opt.is_some(),
        );
        if fault.is_fault() {
            latch_fault(ad, fault);
            return;
        }
    }

    let buffers = {
        #[cfg(feature = "waveshare")]
        let mut platform = super::session::CyclePlatform::new(ad, dvp_camera_opt);
        #[cfg(feature = "m5stack")]
        let mut platform = super::session::CyclePlatform::new(ad);
        prepare_cycle(session, &mut platform, boot_display, cam_status, reset_entry)
    };
    let Some(buffers) = buffers else {
        latch_fault(ad, CameraScanFault::MemoryUnavailable);
        return;
    };

    unsafe {
        #[cfg(feature = "waveshare")]
        if dvp_camera_opt.is_none() {
            super::waveshare_capture::run_capture(
                session, ad, boot_display, delay, i2c,
                buffers.db_ptr, buffers.crop_ptr, liveness,
            );
            return;
        }

        let outcome = super::dvp_capture::run_capture(
            session, ad, boot_display, delay, i2c, dvp_camera_opt,
            cam_dma_buf_opt, buffers.db_ptr, buffers.crop_ptr, liveness,
        );
        #[cfg(feature = "m5stack")]
        handle_m5_outcome(session, ad, outcome);
        #[cfg(feature = "waveshare")]
        let _ = outcome;
    }
}
