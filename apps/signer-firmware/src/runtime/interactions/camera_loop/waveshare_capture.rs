// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Waveshare raw-GDMA capture, viewfinder rendering, touch polling, and QR decoding.

use super::{AppData, display};
use super::decoder::{
    consume_worker_result, handle_decode_result, rqrr_decode, submit_worker,
};
use super::state::CameraSessionState;

fn process_frame(
    session: &mut CameraSessionState,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    decode: &mut [u8],
    crop: &mut [u8],
    liveness: &mut (impl FnMut() + ?Sized),
) {
    use crate::services::camera_device as cam_dma;
    if consume_worker_result(session, ad, boot_display, delay, i2c, liveness) {
        return;
    }
    session.frame.number = session.frame.number.wrapping_add(1);
    let _ = cam_dma::with_frame(|data| {
        render_frame(session, ad, boot_display, data, crop);
        decode_frame(session, ad, boot_display, delay, i2c, data, decode, liveness);
    });
}

fn render_frame(
    session: &CameraSessionState,
    ad: &AppData,
    boot_display: &mut display::BootDisplay<'_>,
    data: &[u8],
    crop: &mut [u8],
) {
    use crate::services::camera_device as cam_dma;
    let render_w = 240usize;
    let render_h = 180usize;
    let bpl = cam_dma::BPL;
    #[cfg(feature = "ov2640-wide")]
    render_wide_crop(data, crop, render_w, render_h, bpl, cam_dma::FRAME_H);
    #[cfg(not(feature = "ov2640-wide"))]
    render_standard_crop(data, crop, render_w, render_h, bpl, cam_dma::FRAME_W, cam_dma::FRAME_H);

    let crop_slice = &crop[..render_w * render_h];
    let mut guide = session.decoder.guide_version
        | if session.decoder.finders_beeped { 0x80 } else { 0 };
    if ad.camera.cam_tune_active {
        guide |= 0x40;
    }
    let _ = ad;
    boot_display.blit_camera_frame(crop_slice, render_w, render_h, guide);
}

#[cfg(feature = "ov2640-wide")]
fn render_wide_crop(
    data: &[u8],
    crop: &mut [u8],
    render_w: usize,
    render_h: usize,
    bpl: usize,
    cam_h: usize,
) {
    const K1_X: i32 = -1966;
    const K1_Y: i32 = -2051;
    const CX: i32 = 265;
    const CY: i32 = 358;
    let max_safe = cam_h * bpl;
    let col0 = (crate::services::camera_device::FRAME_W - render_h * 2) / 2;
    for cy in 0..render_h {
        for cx in 0..render_w {
            let y_idx = corrected_wide_index(cx, cy, col0, bpl, K1_X, K1_Y, CX, CY);
            crop[cy * render_w + cx] = if y_idx + 1 < max_safe { data[y_idx] } else { 0 };
        }
    }
}

#[cfg(feature = "ov2640-wide")]
fn corrected_wide_index(
    cx: usize,
    cy: usize,
    col0: usize,
    bpl: usize,
    k1_x: i32,
    k1_y: i32,
    center_x: i32,
    center_y: i32,
) -> usize {
    let raw_row = (cx * 2) as i32;
    let raw_col = (col0 + cy * 2) as i32;
    let dx = raw_row - center_x;
    let dy = raw_col - center_y;
    let dx_n = ((i64::from(dx)) << 16) / 240;
    let dy_n = ((i64::from(dy)) << 16) / 240;
    let r2_q16 = ((dx_n * dx_n + dy_n * dy_n) >> 16) as i32;
    let fx = 65536 + ((i64::from(k1_x) * i64::from(r2_q16)) >> 16) as i32;
    let fy = 65536 + ((i64::from(k1_y) * i64::from(r2_q16)) >> 16) as i32;
    let corrected_row = center_x + ((i64::from(dx) * i64::from(fx)) >> 16) as i32;
    let corrected_col = center_y + ((i64::from(dy) * i64::from(fy)) >> 16) as i32;
    let row = corrected_row.clamp(0, 479) as usize;
    let col = corrected_col.clamp(0, 479) as usize;
    row * bpl + col
}

#[cfg(not(feature = "ov2640-wide"))]
fn render_standard_crop(
    data: &[u8],
    crop: &mut [u8],
    render_w: usize,
    render_h: usize,
    bpl: usize,
    cam_w: usize,
    cam_h: usize,
) {
    let col0 = (cam_w - render_h * 2) / 2;
    let max_safe = cam_h * bpl;
    for cy in 0..render_h {
        for cx in 0..render_w {
            let y_idx = (cx * 2) * bpl + col0 + cy * 2;
            crop[cy * render_w + cx] = if y_idx + 1 < max_safe { data[y_idx] } else { 0 };
        }
    }
}

fn decode_frame(
    session: &mut CameraSessionState,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    data: &[u8],
    decode: &mut [u8],
    liveness: &mut (impl FnMut() + ?Sized),
) {
    if session.decoder.cooldown > 0 {
        session.decoder.cooldown -= 1;
        return;
    }
    if session.frame.number % 2 != 0 || ad.camera.cam_tune_active {
        return;
    }
    let dw = 240usize;
    let dh = 240usize;
    let bpl = crate::services::camera_device::BPL;
    for dy in 0..dh {
        let src_col = dy * 2;
        let dst_off = dy * dw;
        for dx in 0..dw {
            decode[dst_off + dx] = averaged_pixel(data, bpl, dx * 2, src_col);
        }
    }
    dispatch_decode(session, ad, boot_display, delay, i2c, &decode[..dw * dh], dw, dh, liveness);
}

fn averaged_pixel(data: &[u8], bpl: usize, src_row: usize, src_col: usize) -> u8 {
    let y00 = src_row * bpl + src_col;
    let y01 = src_row * bpl + src_col + 1;
    let y10 = (src_row + 1) * bpl + src_col;
    let y11 = (src_row + 1) * bpl + src_col + 1;
    let sample = |index: usize| data.get(index).copied().map_or(0, u16::from);
    ((sample(y00) + sample(y01) + sample(y10) + sample(y11) + 2) >> 2) as u8
}

fn dispatch_decode(
    session: &mut CameraSessionState,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    data: &[u8],
    width: usize,
    height: usize,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    if crate::CORE1_OK.load(core::sync::atomic::Ordering::Relaxed) {
        let _ = submit_worker(data, width, height);
        return;
    }
    let results = rqrr_decode(data, width, height);
    if let Some((version, decoded)) = results.first() {
        handle_decode_result(session, *version, decoded, decoded.len(), ad, boot_display, delay, i2c, liveness);
    } else {
        session.decoder.finders_beeped = false;
    }
}

pub(super) unsafe fn run_capture(
    session: &mut CameraSessionState,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    db_ptr: *mut u8,
    crop_ptr: *mut u8,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    use crate::services::camera_device as cam_dma;

    // Start continuous capture (only inits on first call)
    cam_dma::start_capture();

    // Poll until frame done with a wall-clock deadline. Touch remains owned by
    // the outer event loop and a missing DMA completion cannot monopolize it.
    let capture_started = esp_hal::time::Instant::now();
    while !cam_dma::poll_done() {
        if capture_started.elapsed() >= esp_hal::time::Duration::from_millis(500) {
            log!("   cam_dma: 500ms timeout — reinit");
            cam_dma::log_status();
            cam_dma::stop();
            return;
        }
    }

    // SAFETY: these are independent fixed-size buffers owned by the camera
    // loop. Convert raw storage once here so frame helpers remain safe.
    let decode = core::slice::from_raw_parts_mut(db_ptr, 240 * 240);
    let crop = core::slice::from_raw_parts_mut(crop_ptr, 240 * 180);
    process_frame(session, ad, boot_display, delay, i2c, decode, crop, liveness);

    return;
}
