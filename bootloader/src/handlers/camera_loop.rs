// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// handlers/camera_loop.rs — QVGA camera capture + QR decode pipeline
//
// OV5640 outputs 320×240 YUV422 YUYV (2 bytes/pixel: Y,U,Y,V).
// Y channel extracted from even bytes → 320×240 grayscale.
// Display uses center crop 240×180 from 320×240 frame.

use crate::log;
use crate::{app::data::AppData, hw::camera, hw::display, features::fw_update, features::stego, ui::seed_manager, hw::touch, wallet};
use crate::ui::helpers::validate_mnemonic;
use esp_hal::lcd_cam::cam::Camera as DvpCamera;
use esp_hal::dma::DmaRxBuf;

/// Check raw TouchState for Contact/PressDown in safe button zones (back, gear, EXIT).
/// These zones have no drag/swipe behavior, so firing on first Contact is safe.
/// Returns true if an immediate tap was stored.
#[inline(always)]
fn check_immediate_tap(ts: &touch::TouchState, ad: &mut AppData) -> bool {
    if ad.cam_tap_ready { return false; } // don't overwrite pending tap
    match ts {
        touch::TouchState::One(pt) => {
            let x = pt.x;
            let y = pt.y;
            match pt.event {
                touch::TouchEventType::PressDown | touch::TouchEventType::Contact => {
                    // Back button zone: x<=40, y<=40
                    // Gear icon zone: x>=275, y<=45 (when NOT in cam-tune)
                    // EXIT button zone: x>=200, y<34 (when IN cam-tune)
                    let is_back = x <= 40 && y <= 40;
                    let is_gear = !ad.cam_tune_active && x >= 275 && y <= 45;
                    let is_exit = ad.cam_tune_active && x >= 200 && y < 34;
                    if is_back || is_gear || is_exit {
                        ad.cam_tap_x = x;
                        ad.cam_tap_y = y;
                        ad.cam_tap_ready = true;
                        return true;
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    false
}

#[cfg(not(feature = "silent"))]
// Static buffers for QR state (persist across calls)
// DB and CROP buffers are in PSRAM (allocated once, pointer stored here)
static mut FN: u32 = 0;
// DB in SRAM for fast random access during QR decode
// (PSRAM random reads are ~15x slower than SRAM)
static mut DB: [u8; 320*240] = [0u8; 320*240];
// CROP buffer in SRAM for fast display blit
static mut CROP_BUF: [u8; 240*180] = [0u8; 240*180];
static mut QR_LAST: [u8; 256] = [0u8; 256];
static mut QR_LAST_LEN: usize = 0;
static mut QR_CONSEC: u8 = 0;
static mut QR_COOLDOWN: u32 = 0;
static mut QR_FINDERS_BEEPED: bool = false;
static mut QR_ERROR_SHOWING: bool = false;
static mut QR_GUIDE_VER: u8 = 0;
static mut QR_FINDERS_ACTIVE: bool = false; // true when finders detected recently
static mut QR_VER_SAME_CNT: u8 = 0;
static mut MF_BUF: [u8; 512] = [0u8; 512];
static mut MF_RECEIVED: [bool; 8] = [false; 8];
static mut MF_FRAG_SIZE: [u16; 8] = [0; 8];
static mut MF_TOTAL: u8 = 0;
static mut MF_LEN: usize = 0;
static mut LAST_AVG: u32 = 128; // last good frame Y average — for flash detection

// Voting confirmation for CompactSeedQR:
// Track up to 4 candidate results with vote counts.
// First candidate to reach VOTE_THRESHOLD wins.
// This handles alternating noise (f9e0d960 vs f9e0d860) by picking the majority.
const VOTE_SLOTS: usize = 4;
const VOTE_THRESHOLD: u8 = 5; // require 5 total votes for a candidate to win
static mut QR_VOTES: [[u8; 32]; VOTE_SLOTS] = [[0u8; 32]; VOTE_SLOTS];
static mut QR_VOTE_LENS: [u8; VOTE_SLOTS] = [0u8; VOTE_SLOTS];
static mut QR_VOTE_COUNTS: [u8; VOTE_SLOTS] = [0u8; VOTE_SLOTS];
static mut QR_VOTE_ACTIVE: usize = 0; // number of active slots

/// Run one camera capture + QR decode cycle. Called from main loop when in ScanQR state.
#[inline(never)]
pub fn run_camera_cycle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    dvp_camera_opt: &mut Option<DvpCamera<'_>>,
    cam_status: &mut camera::CameraStatus,
    cam_dma_buf_opt: &mut Option<DmaRxBuf>,
    tracker: &mut touch::TouchTracker,
) {
            // QR consecutive match state
            // Multi-frame QR accumulation

            unsafe {
                // DB and CROP are SRAM statics — fast random access for QR decode
                let db_ptr = core::ptr::addr_of_mut!(DB) as *mut u8;
                let crop_ptr = core::ptr::addr_of_mut!(CROP_BUF) as *mut u8;

                if FN == 0 {
                    log!("   DB(76KB) + CROP(43KB) in SRAM");
                }

                // Reset QR state when re-entering ScanQR
                if crate::QR_RESET_FLAG {
                    crate::QR_RESET_FLAG = false;
                    QR_CONSEC = 0;
                    QR_COOLDOWN = 0;
                    QR_LAST_LEN = 0;
                    QR_FINDERS_BEEPED = false;
                    QR_FINDERS_ACTIVE = false;
                    QR_ERROR_SHOWING = false;
                    QR_VOTE_ACTIVE = 0;
                    for i in 0..VOTE_SLOTS { QR_VOTE_COUNTS[i] = 0; QR_VOTE_LENS[i] = 0; }
                    MF_TOTAL = 0;
                    MF_LEN = 0;
                    for i in 0..8 { MF_RECEIVED[i] = false; }
                    for i in 0..8 { MF_FRAG_SIZE[i] = 0; }
                    // Clear DB buffer to prevent stale QR from previous session
                    for i in 0..(320*240) {
                        *db_ptr.add(i) = 0;
                    }
                    // Clear QR_LAST hash
                    QR_LAST = [0u8; 256];
                }

                // One-time init
                if *cam_status == camera::CameraStatus::SensorReady {
                    // Fix LCD_CLOCK.CLK_EN
                    let lcd_clk = core::ptr::read_volatile(0x6004_1000u32 as *const u32);
                    if lcd_clk & (1u32 << 31) == 0 {
                        core::ptr::write_volatile(0x6004_1000u32 as *mut u32, lcd_clk | (1u32 << 31));
                    }
                    // Enable VSYNC-based EOF + cam_start NOW (camera is running, PCLK confirmed)
                    camera::configure_cam_vsync_eof();
                    *cam_status = camera::CameraStatus::Streaming;
                    // Apply cam_tune defaults on first stream start
                    ad.cam_tune_dirty = true;
                    log!("   CIF raw Bayer streaming started (400x296, direct grayscale)");
                }

                // Capture one frame
                if let Some(cam) = dvp_camera_opt.take() {
                    let cam_dma_buf = match cam_dma_buf_opt.take() {
                        Some(b) => b,
                        None => { *dvp_camera_opt = Some(cam); return; }
                    };

                    // Pre-capture touch — store any tap in AppData for main loop
                    {
                        let (ts, gest) = touch::read_touch_with_gesture(i2c);
                        // Immediate tap for safe button zones (back, gear, EXIT)
                        if check_immediate_tap(&ts, ad) {
                            *cam_dma_buf_opt = Some(cam_dma_buf);
                            *dvp_camera_opt = Some(cam);
                            return;
                        }
                        let act = tracker.update(ts, gest);
                        match act {
                            touch::TouchAction::Tap { x, y } => {
                                ad.cam_tap_x = x;
                                ad.cam_tap_y = y;
                                ad.cam_tap_ready = true;
                                *cam_dma_buf_opt = Some(cam_dma_buf);
                                *dvp_camera_opt = Some(cam);
                                return;
                            }
                            touch::TouchAction::None => {}
                            touch::TouchAction::Drag { x, y, .. } if ad.cam_tune_active && y >= 196 && x >= 56 && x <= 264 => {
                                let clamped = (x as i32 - 56).max(0).min(208) as u32;
                                ad.cam_tune_vals[ad.cam_tune_param as usize] = ((clamped * 255) / 208) as u8;
                                ad.cam_tune_dirty = true;
                                boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                            }
                            _other => {}
                        }
                    }

                    // Diagnostic: check DVP signal states before first receive
                    if FN == 0 {
                        // Dump all LCD_CAM register state (esp-hal configured)
                        let lcd_clock = {
                            core::ptr::read_volatile(0x6004_1000u32 as *const u32)
                        };
                        let cam_ctrl = {
                            core::ptr::read_volatile(0x6004_1004u32 as *const u32)
                        };
                        let cam_ctrl1 = {
                            core::ptr::read_volatile(0x6004_1008u32 as *const u32)
                        };
                        log!("[CAM-DVP] LCD_CLOCK=0x{:08x} lcd_clk_sel={} div={}",
                            lcd_clock, (lcd_clock >> 28) & 3, lcd_clock & 0xFF);
                        log!("[CAM-DVP] CAM_CTRL=0x{:08x} cam_clk_sel(21:20)={} div={} clk_en(b29)={}",
                            cam_ctrl, (cam_ctrl >> 20) & 3, cam_ctrl & 0xFF, (cam_ctrl >> 29) & 1);
                        log!("[CAM-DVP] CAM_CTRL1=0x{:08x} cam_start={}",
                            cam_ctrl1, cam_ctrl1 & 1);

                        // GPIO8 (XCLK) routing
                        let gpio8_out = {
                            core::ptr::read_volatile((0x6000_4554u32 + 8 * 4) as *const u32)
                        };
                        let iomux8 = {
                            core::ptr::read_volatile((0x6000_9000u32 + 0x04 + 8 * 4) as *const u32)
                        };
                        let gpio_en = {
                            core::ptr::read_volatile(0x6000_4020u32 as *const u32)
                        };
                        log!("[CAM-DVP] GPIO8: FUNC_OUT_SEL={} IOMUX=0x{:08x} OE={} IE={}",
                            gpio8_out & 0x1FF, iomux8, (gpio_en >> 8) & 1, (iomux8 >> 9) & 1);

                        // VSYNC/HREF/PCLK states + toggle check
                        let gpio_in = {
                            core::ptr::read_volatile(0x6000_403Cu32 as *const u32)
                        };
                        log!("[CAM-DVP] VSYNC(6)={} HREF(4)={} PCLK(9)={}",
                            (gpio_in >> 6) & 1, (gpio_in >> 4) & 1, (gpio_in >> 9) & 1);

                        // VSYNC toggle check
                        let mut vtog = 0u32;
                        let mut vlast = (gpio_in >> 6) & 1;
                        for _ in 0..200_000u32 {
                            let v = {
                                (core::ptr::read_volatile(0x6000_403Cu32 as *const u32) >> 6) & 1
                            };
                            if v != vlast { vtog += 1; vlast = v; }
                        }
                        log!("[CAM-DVP] VSYNC toggles in 200K reads: {}", vtog);
                    }

                    match cam.receive(cam_dma_buf) {
                        Ok(transfer) => {
                            // Poll GDMA CH0 IN_SUC_EOF while reading touch between checks.
                            // GDMA base=0x6003F000, IN_INT_RAW_CH0=base+0x0008, bit1=IN_SUC_EOF
                            // IN_INT_CLR_CH0=base+0x0014, bit1=clear IN_SUC_EOF
                            // This gives touch polling at ~500Hz during the ~33ms DMA window.
                            let gdma_in_int_raw = 0x6003_F008u32 as *const u32;
                            let gdma_in_int_clr = 0x6003_F014u32 as *mut u32;
                            loop {
                                let raw = core::ptr::read_volatile(gdma_in_int_raw);
                                if raw & (1 << 1) != 0 {
                                    // DMA complete — clear the interrupt flag
                                    core::ptr::write_volatile(gdma_in_int_clr, 1 << 1);
                                    break;
                                }
                                // DMA still running — read touch while we wait
                                let (ts, gest) = touch::read_touch_with_gesture(i2c);
                                check_immediate_tap(&ts, ad);
                                let act = tracker.update(ts, gest);
                                match act {
                                    touch::TouchAction::Tap { x, y } => {
                                        ad.cam_tap_x = x;
                                        ad.cam_tap_y = y;
                                        ad.cam_tap_ready = true;
                                    }
                                    touch::TouchAction::None => {}
                                    touch::TouchAction::Drag { x, y, .. } => {
                                        // Handle slider drag directly during DMA wait
                                        if ad.cam_tune_active && y >= 196 && x >= 56 && x <= 264 {
                                            let clamped = (x as i32 - 56).max(0).min(208) as u32;
                                            ad.cam_tune_vals[ad.cam_tune_param as usize] = ((clamped * 255) / 208) as u8;
                                            ad.cam_tune_dirty = true;
                                            boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                                        }
                                    }
                                    _other => {}
                                }
                            }
                            // DMA done — wait() returns immediately, reclaims ownership
                            let (_result, cam_back, buf_back) = transfer.wait();

                            FN += 1;

                            // ── QVGA YUV422: 640 bytes/line (2 bytes/pixel) ──
                            let data = buf_back.as_slice();
                            let data_len = data.len();
                            let bpl: usize = 640;
                            let full_h: usize = (data_len / bpl).min(240);
                            let frame_ok = full_h >= 200;

                            if FN <= 1 {
                                log!("[CAM] Geometry: {}x{} SVGA->QVGA YUV422", bpl, full_h);
                            }

                            // Fast brightness check: sample ~400 Y pixels, compare to last frame
                            // DMA tearing produces frames with sudden brightness jumps → skip
                            let (frame_valid, cur_avg) = if frame_ok {
                                let step_y = full_h / 20;
                                let step_x = 32usize; // sample every 32 raw pixels
                                let mut ysum = 0u32;
                                let mut cnt = 0u32;
                                for sy in (0..full_h).step_by(step_y.max(1)) {
                                    let off = sy * bpl;
                                    for sx in (0..320usize).step_by(step_x) {
                                        let idx = off + sx * 2;
                                        if idx < data_len {
                                            ysum += data[idx] as u32;
                                            cnt += 1;
                                        }
                                    }
                                }
                                if cnt > 0 {
                                    let avg = ysum / cnt;
                                    let diff = if avg > LAST_AVG { avg - LAST_AVG } else { LAST_AVG - avg };
                                    // Allow first 3 frames unconditionally (auto-exposure settling)
                                    // After that, reject if brightness jumps > 50 from last good frame
                                    let ok = FN <= 3 || diff < 50;
                                    (ok, avg)
                                } else { (false, 128) }
                            } else { (false, 128) };

                            // Update LAST_AVG only on accepted frames
                            if frame_valid {
                                LAST_AVG = cur_avg;
                            }

                            // Frame diagnostic (first 8 frames)
                            if FN <= 8 {
                                log!("[CAM] F{}: len={} lines={} valid={} avg={} last_avg={} raw8=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}]",
                                    FN, data_len, full_h, frame_valid, cur_avg, LAST_AVG,
                                    data[0], data[1], data[2], data[3],
                                    data[4], data[5], data[6], data[7]);
                            }

                            let render_w: usize = 240;
                            let render_h: usize = 180;
                            let cam_col0: usize = (320 - render_h) / 2;
                            let max_safe: usize = full_h * bpl;

                            let is_decode_frame = FN % 2 == 0;

                            // Display on non-decode frames
                            if !is_decode_frame && frame_valid && !QR_ERROR_SHOWING {
                                for cy in 0..render_h {
                                    for cx in 0..render_w {
                                        let src_row = cx;
                                        let src_col = cam_col0 + cy;
                                        let y_idx = src_row * bpl + src_col * 2;
                                        *crop_ptr.add(cy * render_w + cx) = if y_idx < max_safe {
                                            data[y_idx]
                                        } else { 0 };
                                    }
                                }
                                let crop_slice = core::slice::from_raw_parts(
                                    crop_ptr as *const u8, render_w * render_h);

                                // bit 7 = finders active, bit 6 = cam-tune overlay active
                                let mut guide_flags = QR_GUIDE_VER | if QR_FINDERS_ACTIVE { 0x80 } else { 0 };
                                if ad.cam_tune_active {
                                    guide_flags |= 0x40;
                                }
                                boot_display.blit_camera_frame(crop_slice, render_w, render_h, guide_flags);

                                // Touch read after blit — catches taps during ~15ms SPI transfer
                                {
                                    let (ts, gest) = touch::read_touch_with_gesture(i2c);
                                    check_immediate_tap(&ts, ad);
                                    let act = tracker.update(ts, gest);
                                    if let touch::TouchAction::Tap { x, y } = act {
                                        ad.cam_tap_x = x;
                                        ad.cam_tap_y = y;
                                        ad.cam_tap_ready = true;
                                    }
                                }
                            }

                            // Copy Y channel to DB on decode frames
                            if is_decode_frame && frame_valid && !QR_ERROR_SHOWING {
                                for dy in 0..full_h.min(240) {
                                    let dst_off = dy * 320;
                                    for dx in 0..320usize {
                                        let y_idx = dy * bpl + dx * 2;
                                        *db_ptr.add(dst_off + dx) = if y_idx < max_safe {
                                            data[y_idx]
                                        } else { 0 };
                                    }
                                }
                            }

                            let fs = 320 * 240;

                            // ── Release DMA buffer + camera for next capture ──
                            *cam_dma_buf_opt = Some(buf_back);
                            *dvp_camera_opt = Some(cam_back);

                            if !frame_ok { return; }

                            // Handle error cooldown
                            if QR_ERROR_SHOWING {
                                if QR_COOLDOWN > 0 {
                                    QR_COOLDOWN -= 1;
                                } else {
                                    QR_ERROR_SHOWING = false;
                                }
                                return;
                            }

                            // ── Touch check ──
                            {
                                let (ts, gest) = touch::read_touch_with_gesture(i2c);
                                check_immediate_tap(&ts, ad);
                                let act = tracker.update(ts, gest);
                                match act {
                                    touch::TouchAction::Tap { x, y } => {
                                        ad.cam_tap_x = x;
                                        ad.cam_tap_y = y;
                                        ad.cam_tap_ready = true;
                                    }
                                    touch::TouchAction::None => {}
                                    touch::TouchAction::Drag { x, y, .. } if ad.cam_tune_active && y >= 196 && x >= 56 && x <= 264 => {
                                        let clamped = (x as i32 - 56).max(0).min(208) as u32;
                                        ad.cam_tune_vals[ad.cam_tune_param as usize] = ((clamped * 255) / 208) as u8;
                                        ad.cam_tune_dirty = true;
                                        boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                                    }
                                    _other => {}
                                }
                            }

                            // Skip QR decode on display-only frames or when cam-tune is active
                            if !is_decode_frame || ad.cam_tune_active { return; }

                            if QR_COOLDOWN > 0 {
                                QR_COOLDOWN -= 1;
                            } else {
                                let db_slice = core::slice::from_raw_parts(db_ptr as *const u8, fs);

                                // Try 1: raw orientation (landscape QR)
                                let qr_thr = crate::qr::decoder::get_threshold(db_slice);
                                let mut qr_result = crate::qr::decoder::decode(db_slice, 320, 240);

                                // Touch read after QR decode — catches taps during the ~10-30ms decode
                                {
                                    let (ts, gest) = touch::read_touch_with_gesture(i2c);
                                    check_immediate_tap(&ts, ad);
                                    let act = tracker.update(ts, gest);
                                    if let touch::TouchAction::Tap { x, y } = act {
                                        ad.cam_tap_x = x;
                                        ad.cam_tap_y = y;
                                        ad.cam_tap_ready = true;
                                    }
                                }

                                // ── Plausibility pre-filter ──
                                // Reject noise decodes that don't match ANY known format.
                                // Without this, random ECC-valid garbage resets QR_CONSEC and
                                // prevents the real QR from reaching consec=2.
                                if let Ok(ref r) = qr_result {
                                    let d = &r.data[..r.len];
                                    let plausible = 
                                        // CompactSeedQR: 16 or 32 bytes raw entropy
                                        r.len == 16 || r.len == 32
                                        // Standard SeedQR: 48 or 96 ASCII digits
                                        || ((r.len == 48 || r.len == 96) && d.iter().all(|&b| b >= b'0' && b <= b'9'))
                                        // Kaspa address: starts with "kaspa:" or "KASPA:"
                                        || (r.len >= 6 && (&d[..6] == b"kaspa:" || &d[..6] == b"KASPA:"))
                                        // PSKT transaction: starts with "KSPT"
                                        || (r.len >= 4 && &d[..4] == b"KSPT")
                                        // Firmware update: 104 bytes starting with "KSFU"
                                        || (r.len == 104 && r.len >= 4 && &d[..4] == b"KSFU")
                                        // Multi-frame fragment: frame_num < total, total 2-8, frag_len > 0
                                        || (r.len >= 7 && d[1] >= 2 && d[1] <= 8 && d[0] < d[1] && d[2] > 0)
                                        // Stego text (contains zero-width chars)
                                        || stego::contains_stego(d, r.len);
                                    if !plausible {
                                        // Noise decode — don't count, don't reset consec
                                        if FN <= 20 || FN % 30 == 0 {
                                            log!("[QR] F{} t={}: noise ver={} len={} (filtered)", FN, ad.idle_ticks,
                                                crate::qr::decoder::last_raw_info().4, r.len);
                                        }
                                        qr_result = Err(crate::qr::decoder::DecodeError::DataOverflow);
                                    }
                                }

                                let (fcnt, _, _, _, _det_ver) = crate::qr::decoder::last_raw_info();
                                // Log AFTER match check so consec is accurate
                                // (moved below match logic — see post-match log)
                                        match qr_result {
                                            Ok(result) => {
                                                QR_FINDERS_ACTIVE = true;
                                                // Tick sound on first successful decode (QR positioned)
                                                if !QR_FINDERS_BEEPED {
                                                    
                                                    QR_FINDERS_BEEPED = true;
                                                }
                                                // Update guide version (smoothed — needs 2 same in a row)
                                                let (_, _, _, _, det_ver) = crate::qr::decoder::last_raw_info();
                                                if det_ver == QR_GUIDE_VER {
                                                    QR_VER_SAME_CNT = QR_VER_SAME_CNT.saturating_add(1);
                                                } else if QR_VER_SAME_CNT == 0 || det_ver != 0 {
                                                    QR_VER_SAME_CNT = 1;
                                                    if det_ver >= 1 && det_ver <= 8 {
                                                        QR_GUIDE_VER = det_ver;
                                                    }
                                                }

                                                // Log with data bytes for diagnostics
                                                {
                                                    let dd = &result.data;
                                                    log!("[QR] OK t={} v={} th={} f={} l={} c={} d=[{:02x}{:02x}{:02x}{:02x}]", ad.idle_ticks,
                                                        det_ver, qr_thr, fcnt, result.len, QR_CONSEC,
                                                        dd[0], dd[1], dd[2], dd[3]);
                                                }

                                                // Check for multi-frame fragment — accept immediately (no 3-match filter)
                                                // Exclude len=16 and len=32 — those are CompactSeedQR sizes
                                                // that can false-match the loose multi-frame header check.
                                                let d = &result.data[..result.len];
                                                let is_mf = result.len >= 7
                                                    && result.len != 16 && result.len != 32
                                                    && d[1] >= 2 && d[1] <= 8
                                                    && d[0] < d[1] && d[2] > 0
                                                    && (d[0] > 0 || (result.len >= 7 && &d[3..7] == b"KSPT"));

                                                if is_mf {
                                                    // Multi-frame: process immediately, no consecutive match needed
                                                    let data = d;
                                                    let frame_num = data[0] as usize;
                                                    let total = data[1];
                                                    let frag_len = data[2] as usize;

                                                    if frag_len + 3 <= result.len {
                                                        if MF_TOTAL == 0 || MF_TOTAL != total {
                                                            MF_TOTAL = total;
                                                            MF_LEN = 0;
                                                            for i in 0..8 { MF_RECEIVED[i] = false; }
                                                            for i in 0..8 { MF_FRAG_SIZE[i] = 0; }
                                                        }

                                                        if !MF_RECEIVED[frame_num] {
                                                            MF_FRAG_SIZE[frame_num] = frag_len as u16;
                                                            MF_RECEIVED[frame_num] = true;
                                                            let slot_offset = frame_num * 131;
                                                            let end = slot_offset + frag_len;
                                                            if end <= 512 {
                                                                MF_BUF[slot_offset..end]
                                                                    .copy_from_slice(&data[3..3 + frag_len]);
                                                            }
                                                            

                                                            let received = MF_RECEIVED[..total as usize]
                                                                .iter().filter(|&&r| r).count();
                                                            log!("   → Frame {}/{} ({} bytes), {}/{}",
                                                                frame_num + 1, total, frag_len,
                                                                received, total);

                                                            let all_received = MF_RECEIVED[..total as usize]
                                                                .iter().all(|&r| r);
                                                            if all_received {
                                                                let mut assembled = [0u8; 512];
                                                                let mut pos = 0usize;
                                                                for f in 0..total as usize {
                                                                    let sl = f * 131;
                                                                    let sz = MF_FRAG_SIZE[f] as usize;
                                                                    assembled[pos..pos + sz]
                                                                        .copy_from_slice(&MF_BUF[sl..sl + sz]);
                                                                    pos += sz;
                                                                }
                                                                log!("   → All {} frames, {} bytes", total, pos);
                                                                
                                                                match wallet::pskt::parse_pskt(
                                                                    &assembled[..pos], &mut ad.demo_tx) {
                                                                    Ok(()) => {
                                                                        log!("   → PSKT: {} in, {} out",
                                                                            ad.demo_tx.num_inputs, ad.demo_tx.num_outputs);
                                                                        ad.app.start_review(
                                                                            ad.demo_tx.num_outputs as u8,
                                                                            ad.demo_tx.num_inputs as u8);
                                                                        ad.needs_redraw = true;
                                                                    }
                                                                    Err(e) => {
                                                                        log!("   → PSKT error: {:?}", e);
                                                                    }
                                                                }
                                                                MF_TOTAL = 0;
                                                            }
                                                        }
                                                    }
                                                    // No cooldown between multi-frame fragments
                                                } else {
                                                // Normal single-frame QR — consec=3
                                                // Errors don't reset chain.
                                                // Exact match for CompactSeedQR (binary — 1-byte noise = different seed)
                                                // Fuzzy match (≤3 diff bytes) for text-based QR (addresses, SeedQR ASCII)
                                                if ad.app.state != crate::app::input::AppState::PassphraseEntry {
                                                let is_match = if result.len == QR_LAST_LEN {
                                                    if result.len == 16 || result.len == 32 {
                                                        // CompactSeedQR: exact match required
                                                        // (BIP39 checksum too weak for fuzzy — 1/256 false positive)
                                                        result.data[..result.len] == QR_LAST[..QR_LAST_LEN]
                                                    } else {
                                                        // Text-based QR: fuzzy match, allow ≤3 differing bytes
                                                        let mut diff = 0u32;
                                                        for i in 0..result.len {
                                                            if result.data[i] != QR_LAST[i] { diff += 1; }
                                                        }
                                                        diff <= 3
                                                    }
                                                } else { false };
                                                if is_match {
                                                    QR_CONSEC += 1;
                                                    // Update LAST with latest decode
                                                    QR_LAST[..result.len]
                                                        .copy_from_slice(&result.data[..result.len]);
                                                } else {
                                                    QR_CONSEC = 1;
                                                    QR_LAST_LEN = result.len;
                                                    QR_LAST[..result.len]
                                                        .copy_from_slice(&result.data[..result.len]);
                                                }
                                                if QR_CONSEC >= 3 {
                                                    let data = &result.data[..result.len];
                                                    let is_compact = result.len == 16 || result.len == 32;

                                                    // CompactSeedQR: voting confirmation
                                                    // Each unique decode result gets a vote slot.
                                                    // First to reach VOTE_THRESHOLD wins.
                                                    // Handles alternating noise (d960 vs d860) by majority.
                                                    if is_compact {
                                                        // Find existing slot or create new
                                                        let mut slot_idx: Option<usize> = None;
                                                        for i in 0..QR_VOTE_ACTIVE {
                                                            if QR_VOTE_LENS[i] as usize == result.len
                                                                && QR_VOTES[i][..result.len] == data[..result.len]
                                                            {
                                                                slot_idx = Some(i);
                                                                break;
                                                            }
                                                        }
                                                        let idx = if let Some(i) = slot_idx {
                                                            i
                                                        } else if QR_VOTE_ACTIVE < VOTE_SLOTS {
                                                            let i = QR_VOTE_ACTIVE;
                                                            QR_VOTES[i][..result.len].copy_from_slice(data);
                                                            QR_VOTE_LENS[i] = result.len as u8;
                                                            QR_VOTE_COUNTS[i] = 0;
                                                            QR_VOTE_ACTIVE += 1;
                                                            i
                                                        } else {
                                                            // All slots full — replace lowest count
                                                            let mut min_i = 0;
                                                            for i in 1..VOTE_SLOTS {
                                                                if QR_VOTE_COUNTS[i] < QR_VOTE_COUNTS[min_i] { min_i = i; }
                                                            }
                                                            QR_VOTES[min_i][..result.len].copy_from_slice(data);
                                                            QR_VOTE_LENS[min_i] = result.len as u8;
                                                            QR_VOTE_COUNTS[min_i] = 0;
                                                            min_i
                                                        };
                                                        QR_VOTE_COUNTS[idx] = QR_VOTE_COUNTS[idx].saturating_add(1);
                                                        QR_CONSEC = 0;

                                                        log!("[QR] vote: d=[{:02x}{:02x}{:02x}{:02x}] → {}/{}",
                                                            data[0], data[1], data[2], data[3],
                                                            QR_VOTE_COUNTS[idx], VOTE_THRESHOLD);

                                                        if QR_VOTE_COUNTS[idx] >= VOTE_THRESHOLD {
                                                            // Winner — accept this candidate
                                                            let winner = &QR_VOTES[idx][..result.len];
                                                            QR_VOTE_ACTIVE = 0;
                                                            for i in 0..VOTE_SLOTS { QR_VOTE_COUNTS[i] = 0; }
                                                            QR_COOLDOWN = 90;
                                                            QR_FINDERS_BEEPED = false;

                                                            let mut import_indices = [0u16; 24];
                                                            let wc = seed_manager::decode_compact_seedqr(winner, &mut import_indices);
                                                            if wc > 0 && validate_mnemonic(&import_indices, wc) {
                                                                ad.mnemonic_indices = import_indices;
                                                                ad.word_count = wc;
                                                                log!("   → CompactSeedQR voted ({} words, {} votes) → passphrase",
                                                                    wc, VOTE_THRESHOLD);
                                                                ad.pp_input.reset();
                                                                ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                                                ad.needs_redraw = true;
                                                            } else {
                                                                log!("   → CompactSeedQR: checksum fail after vote");
                                                            }
                                                        }
                                                    } else {
                                                    // Non-CompactSeedQR: single consec=3 (fuzzy) + downstream validation
                                                    QR_CONSEC = 0;
                                                    QR_COOLDOWN = 90;
                                                    QR_FINDERS_BEEPED = false;

                                                    let is_kaspa = result.len >= 6 && (
                                                        &data[..6] == b"kaspa:" || &data[..6] == b"KASPA:");
                                                    if is_kaspa {
                                                        let copy_len = result.len.min(ad.scanned_addr.len());
                                                        for i in 0..copy_len {
                                                            ad.scanned_addr[i] = if data[i] >= b'A' && data[i] <= b'Z' {
                                                                data[i] + 32 } else { data[i] };
                                                        }
                                                        ad.scanned_addr_len = copy_len;
                                                        let valid = wallet::address::validate_kaspa_address(
                                                            &ad.scanned_addr[..ad.scanned_addr_len]);
                                                        ad.scanned_addr_valid = valid;
                                                        log!("   → Kaspa address (valid={})", valid);
                                                        ad.app.state = crate::app::input::AppState::ShowAddress;
                                                        ad.needs_redraw = true;
                                                    } else if result.len >= 4 && &data[..4] == b"KSPT" {
                                                        let pv = if result.len >= 5 { data[4] } else { 0x01 };
                                                        if pv == 0x02 {
                                                            match wallet::pskt::parse_signed_pskt_v2(data, &mut ad.demo_tx) {
                                                                Ok(()) => {
                                                                    let (p, r) = wallet::pskt::signature_status(&ad.demo_tx);
                                                                    log!("   → PSKT v2: {} in, {} out, sigs {}/{}",
                                                                        ad.demo_tx.num_inputs, ad.demo_tx.num_outputs, p, r);
                                                                    ad.app.start_review(ad.demo_tx.num_outputs as u8, ad.demo_tx.num_inputs as u8);
                                                                    ad.needs_redraw = true;
                                                                }
                                                                Err(e) => { log!("   → PSKT v2 error: {:?}", e); }
                                                            }
                                                        } else {
                                                            match wallet::pskt::parse_pskt(data, &mut ad.demo_tx) {
                                                                Ok(()) => {
                                                                    log!("   → PSKT v1: {} in, {} out",
                                                                        ad.demo_tx.num_inputs, ad.demo_tx.num_outputs);
                                                                    ad.app.start_review(ad.demo_tx.num_outputs as u8, ad.demo_tx.num_inputs as u8);
                                                                    ad.needs_redraw = true;
                                                                }
                                                                Err(e) => { log!("   → PSKT v1 error: {:?}", e); }
                                                            }
                                                        }
                                                    } else if (result.len == 48 || result.len == 96)
                                                        && data.iter().all(|&b| b >= b'0' && b <= b'9')
                                                    {
                                                        let mut import_indices = [0u16; 24];
                                                        let wc = seed_manager::decode_seedqr(data, &mut import_indices);
                                                        if wc > 0 && validate_mnemonic(&import_indices, wc) {
                                                            ad.mnemonic_indices = import_indices;
                                                            ad.word_count = wc;
                                                            log!("   → SeedQR imported ({} words) → passphrase", wc);
                                                            ad.pp_input.reset();
                                                            ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                                            ad.needs_redraw = true;
                                                        } else {
                                                            log!("   → SeedQR: invalid checksum");
                                                        }
                                                    } else if result.len == 104 && &data[..4] == b"KSFU" {
                                                        if let Some(update) = fw_update::parse_update_qr(data) {
                                                            ad.fw_update_verified = fw_update::verify_update(&update);
                                                            ad.fw_update_info = update;
                                                            ad.app.state = crate::app::input::AppState::FwUpdateResult;
                                                            ad.needs_redraw = true;
                                                            log!("   → FW update: v{}, verified={}",
                                                                ad.fw_update_info.version, ad.fw_update_verified);
                                                        }
                                                    } else if stego::contains_stego(data, result.len) {
                                                        let mut sp = [0u8; stego::MAX_STEGO_PAYLOAD];
                                                        let ext = stego::decode_stego_text(data, result.len, &mut sp);
                                                        if ext > 0 {
                                                            log!("   → Stego: {} bytes", ext);
                                                            boot_display.draw_success_screen("Stego Detected!");
                                                            delay.delay_millis(2000);
                                                            ad.needs_redraw = true;
                                                        }
                                                    } else {
                                                        log!("   → Unknown QR format");
                                                    }
                                                } // end non-compact else
                                                } // end if compact double-confirm / else
                                                } // end if state != PassphraseEntry
                                                } // end else (non-multi-frame)
                                            }
                                            Err(e) => {
                                                QR_FINDERS_ACTIVE = false;
                                                if FN <= 20 || FN % 30 == 0 {
                                                    log!("[QR] F{} t={}: {:?} thr={} f={}", FN, ad.idle_ticks, e, qr_thr, fcnt);
                                                }
                                                // NOTE: QR_CONSEC NOT reset on errors.
                                                // Ghost frames produce EccFailed/NoFinders between
                                                // good decodes — preserving consec lets the chain
                                                // survive intermittent bad frames.
                                                QR_FINDERS_BEEPED = false;
                                            }
                                        }
                                    } // end QR decode else (not on cooldown)
                        }
                        Err((e, cam_back, buf_back)) => {
                            log!("   receive failed: {:?}", e);
                            *cam_dma_buf_opt = Some(buf_back);
                            *dvp_camera_opt = Some(cam_back);
                        }
                    }
                }
            } // unsafe
}
