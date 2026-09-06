// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! ESP-HAL DVP capture path used by M5Stack and the Waveshare fallback.

use super::{AppData, DmaRxBuf, DvpCamera, display};
use super::decoder::{handle_decode_result, rqrr_decode};
#[cfg(feature = "waveshare")]
use super::decoder::{consume_worker_result, submit_worker};
use super::state::CameraSessionState;

#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CaptureOutcome {
    Captured = 0,
    TimedOut = 1,
    ReceiveFailed = 2,
    ResourcesUnavailable = 3,
}

fn render_and_copy_frame(
    session: &mut CameraSessionState,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    data: &[u8],
    decode: &mut [u8],
    crop: &mut [u8],
) -> (usize, bool, bool) {
    session.frame.number = session.frame.number.wrapping_add(1);
    let bpl = platform_bytes_per_line();
    let full_h = (data.len() / bpl).min(240);
    let frame_ok = full_h >= 100;
    if frame_ok && !session.decoder.error_showing {
        render_dvp_view(session, ad, boot_display, data, crop, bpl, full_h);
    }
    let is_decode_frame = is_dvp_decode_frame(session, ad);
    if is_decode_frame && frame_ok && !session.decoder.error_showing {
        copy_dvp_decode_frame(data, decode, bpl, full_h);
    }
    (full_h, frame_ok, is_decode_frame)
}

fn platform_bytes_per_line() -> usize {
    #[cfg(feature = "waveshare")]
    { 640 }
    #[cfg(feature = "m5stack")]
    { 320 }
}

fn is_dvp_decode_frame(session: &CameraSessionState, ad: &AppData) -> bool {
    #[cfg(feature = "waveshare")]
    { session.frame.number % 2 == 0 && !ad.camera.cam_tune_active }
    #[cfg(feature = "m5stack")]
    { let _ = ad; session.frame.number % 2 == 0 }
}

fn render_dvp_view(
    session: &CameraSessionState,
    ad: &AppData,
    boot_display: &mut display::BootDisplay<'_>,
    data: &[u8],
    crop: &mut [u8],
    bpl: usize,
    full_h: usize,
) {
    let render_w = 240usize;
    let render_h = 180usize;
    #[cfg(feature = "waveshare")]
    render_dvp_waveshare(data, crop, bpl, full_h, render_w, render_h);
    #[cfg(feature = "m5stack")]
    render_dvp_m5stack(data, crop, bpl, full_h, render_w, render_h);
    let crop_slice = &crop[..render_w * render_h];
    let guide_base = session.decoder.guide_version
        | if session.decoder.finders_beeped { 0x80 } else { 0 };
    #[cfg(feature = "waveshare")]
    let guide = guide_base | if ad.camera.cam_tune_active { 0x40 } else { 0 };
    #[cfg(feature = "m5stack")]
    let guide = { let _ = ad; guide_base };
    boot_display.blit_camera_frame(crop_slice, render_w, render_h, guide);
}

#[cfg(feature = "waveshare")]
fn render_dvp_waveshare(
    data: &[u8], crop: &mut [u8], bpl: usize, full_h: usize, render_w: usize, render_h: usize,
) {
    let cam_col0 = (320usize - render_h) / 2;
    let max_safe = full_h * bpl;
    for cy in 0..render_h {
        for cx in 0..render_w {
            let y_idx = cx * bpl + cam_col0 + cy;
            crop[cy * render_w + cx] = if y_idx + 1 < max_safe { data[y_idx] } else { 0 };
        }
    }
}

#[cfg(feature = "m5stack")]
fn render_dvp_m5stack(
    data: &[u8], crop: &mut [u8], bpl: usize, full_h: usize, render_w: usize, render_h: usize,
) {
    for cy in 0..render_h {
        let src_y = full_h - 1 - (30 + cy);
        for cx in 0..render_w {
            let idx = src_y * bpl + 40 + cx;
            crop[cy * render_w + cx] = data.get(idx).copied().unwrap_or(0);
        }
    }
}

fn copy_dvp_decode_frame(data: &[u8], decode: &mut [u8], bpl: usize, full_h: usize) {
    for dy in 0..full_h {
        let dst_off = dy * 320;
        for dx in 0..320usize {
            #[cfg(feature = "waveshare")]
            let idx = dy * bpl + dx * 2;
            #[cfg(feature = "m5stack")]
            let idx = (full_h - 1 - dy) * bpl + dx;
            decode[dst_off + dx] = data.get(idx).copied().unwrap_or(0);
        }
    }
}

unsafe fn process_captured_frame<'cam>(
    session: &mut CameraSessionState,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    dvp_camera_opt: &mut Option<DvpCamera<'cam>>,
    cam_dma_buf_opt: &mut Option<DmaRxBuf>,
    db_ptr: *mut u8,
    crop_ptr: *mut u8,
    cam_back: DvpCamera<'cam>,
    buf_back: DmaRxBuf,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    #[cfg(feature = "waveshare")]
    if consume_worker_result(session, ad, boot_display, delay, i2c, liveness) {
        return;
    }


    let data = buf_back.as_slice();
    // SAFETY: the camera loop allocates independent decode (320x240) and
    // viewfinder crop (240x180) buffers for the lifetime of this capture.
    // Convert the raw storage once at the reviewed boundary; helpers below
    // operate only on bounded slices.
    let decode = core::slice::from_raw_parts_mut(db_ptr, 320 * 240);
    let crop = core::slice::from_raw_parts_mut(crop_ptr, 240 * 180);
    let (full_h, frame_ok, is_decode_frame) =
        render_and_copy_frame(session, ad, boot_display, data, decode, crop);

    // ── Release DMA buffer + camera for next capture ──
    *cam_dma_buf_opt = Some(buf_back);
    *dvp_camera_opt = Some(cam_back);

    if !frame_ok { return; }

    // Handle error cooldown
    if session.decoder.error_showing {
        if session.decoder.cooldown > 0 {
            session.decoder.cooldown -= 1;
        } else {
            session.decoder.error_showing = false;
        }
        return;
    }


    // Skip QR decode on display-only frames
    if !is_decode_frame { return; }

    if session.decoder.cooldown > 0 {
        session.decoder.cooldown -= 1;
    } else {
        // m5stack: crop center 240x240 from 320x240 for rqrr.
        // Compact rows in-place in DB buffer.
        let rqw: usize = 240;
        let rqh: usize = full_h.min(240);
        let x0: usize = 40; // (320 - 240) / 2
        for ry in 0..rqh {
            let src = ry * 320 + x0;
            let dst = ry * rqw;
            if src != dst {
                decode.copy_within(src..src + rqw, dst);
            }
        }
        let crop_slice = &decode[..rqw * rqh];
        #[cfg(feature = "waveshare")]
        if crate::CORE1_OK.load(core::sync::atomic::Ordering::Relaxed) {
            let _ = submit_worker(crop_slice, rqw, rqh);
            return;
        }
        let results = rqrr_decode(crop_slice, rqw, rqh);
        if let Some((ver, ref decoded)) = results.first() {
            handle_decode_result(session, *ver, decoded, decoded.len(), ad, boot_display, delay, i2c, liveness);
        } else {
            session.decoder.finders_beeped = false;
        }
    }
}

pub(super) unsafe fn run_capture(
    session: &mut CameraSessionState,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    dvp_camera_opt: &mut Option<DvpCamera<'_>>,
    cam_dma_buf_opt: &mut Option<DmaRxBuf>,
    db_ptr: *mut u8,
    crop_ptr: *mut u8,
    liveness: &mut (impl FnMut() + ?Sized),
) -> CaptureOutcome {
    let Some(cam) = dvp_camera_opt.take() else {
        return CaptureOutcome::ResourcesUnavailable;
    };
    let cam_dma_buf = match cam_dma_buf_opt.take() {
        Some(buffer) => buffer,
        None => {
            *dvp_camera_opt = Some(cam);
            return CaptureOutcome::ResourcesUnavailable;
        }
    };


    let (status, cam_back, buf_back) =
        crate::services::camera_device::receive_full_frame(cam, cam_dma_buf, delay);
    match status {
        crate::services::camera_device::FrameCaptureStatus::Complete => {
            process_captured_frame(
                session, ad, boot_display, delay, i2c, dvp_camera_opt, cam_dma_buf_opt,
                db_ptr, crop_ptr, cam_back, buf_back, liveness,
            );
            CaptureOutcome::Captured
        }
        crate::services::camera_device::FrameCaptureStatus::TimedOut => {
            log!("   dvp: transfer timeout — partial frame rejected");
            *cam_dma_buf_opt = Some(buf_back);
            *dvp_camera_opt = Some(cam_back);
            CaptureOutcome::TimedOut
        }
        crate::services::camera_device::FrameCaptureStatus::ReceiveFailed => {
            log!("   dvp: receive failed");
            *cam_dma_buf_opt = Some(buf_back);
            *dvp_camera_opt = Some(cam_back);
            CaptureOutcome::ReceiveFailed
        }
    }
}
