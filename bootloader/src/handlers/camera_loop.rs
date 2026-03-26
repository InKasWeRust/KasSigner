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
// Platform-adaptive frame extraction:
//   Waveshare (OV5640): 640 bytes/line YUV422 YUYV → extract Y from even bytes
//   M5Stack (GC0308):   320 bytes/line Y-only → direct copy
// Display uses center crop 240×180 from 320×240 frame.

#![allow(unused_imports)]
#![allow(static_mut_refs)]
use crate::log;
use crate::{app::data::AppData, hw::camera, hw::display, features::fw_update, features::stego, ui::seed_manager, hw::sound, hw::touch, wallet};
use crate::ui::helpers::validate_mnemonic;
use esp_hal::lcd_cam::cam::Camera as DvpCamera;
use esp_hal::dma::DmaRxBuf;

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
static mut QR_VER_SAME_CNT: u8 = 0;
static mut MF_BUF: [u8; 512] = [0u8; 512];
static mut MF_RECEIVED: [bool; 8] = [false; 8];
static mut MF_FRAG_SIZE: [u16; 8] = [0; 8];
static mut MF_TOTAL: u8 = 0;
static mut MF_LEN: usize = 0;

/// Run one camera capture + QR decode cycle.
/// Returns true if a QR was successfully decoded and processed.
#[allow(unused_variables, unused_assignments, unused_mut, unused_unsafe)]
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
                    QR_ERROR_SHOWING = false;
                    MF_TOTAL = 0;
                    MF_LEN = 0;
                    for i in 0..8 { MF_RECEIVED[i] = false; }
                    for i in 0..8 { MF_FRAG_SIZE[i] = 0; }
                }

                // One-time init
                if *cam_status == camera::CameraStatus::SensorReady {
                    // Fix LCD_CLOCK.CLK_EN
                    let lcd_clk = core::ptr::read_volatile(0x6004_1000u32 as *const u32);
                    if lcd_clk & (1u32 << 31) == 0 {
                        core::ptr::write_volatile(0x6004_1000u32 as *mut u32, lcd_clk | (1u32 << 31));
                    }
                    *cam_status = camera::CameraStatus::Streaming;
                    log!("   QVGA Y-only streaming started (320x240)");
                }

                // Capture one frame
                if let Some(cam) = dvp_camera_opt.take() {
                    let cam_dma_buf = match cam_dma_buf_opt.take() {
                        Some(b) => b,
                        None => { *dvp_camera_opt = Some(cam); return; }
                    };

                    // Pre-capture touch check — catch back taps before receive() blocks
                    {
                        let ts = touch::read_touch(i2c);
                        #[cfg(feature = "waveshare")]
                        let act = tracker.update(ts, touch::HwGesture::None);
                        #[cfg(feature = "m5stack")]
                        let act = tracker.update(ts);
                        if let touch::TouchAction::Tap { x, y } = act {
                            if (x <= 40 && y <= 40) || (x >= 268 && y <= 40) {
                                sound::click(delay);
                                *cam_dma_buf_opt = Some(cam_dma_buf);
                                *dvp_camera_opt = Some(cam);
                                if ad.ms_creating.n > 0 && !ad.ms_creating.active {
                                    let mut ki: u8 = 0;
                                    for i in 0..ad.ms_creating.n {
                                        if ad.ms_creating.pubkeys[i as usize] == [0u8; 32] { ki = i; break; }
                                    }
                                    ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: ki };
                                } else {
                                    ad.app.go_main_menu();
                                }
                                ad.needs_redraw = true;
                                return;
                            }
                        }
                    }

                    match cam.receive(cam_dma_buf) {
                        Ok(transfer) => {
                            // wait() blocks until VSYNC EOF (~33ms at 30fps).
                            let (_result, cam_back, buf_back) = transfer.wait();

                            // Touch check — catch taps during wait()
                            {
                                let ts = touch::read_touch(i2c);
                                #[cfg(feature = "waveshare")]
                                let act = tracker.update(ts, touch::HwGesture::None);
                                #[cfg(feature = "m5stack")]
                                let act = tracker.update(ts);
                                if let touch::TouchAction::Tap { x, y } = act {
                                    if (x <= 40 && y <= 40) || (x >= 268 && y <= 40) {
                                        sound::click(delay);
                                        *cam_dma_buf_opt = Some(buf_back);
                                        *dvp_camera_opt = Some(cam_back);
                                        if ad.ms_creating.n > 0 && !ad.ms_creating.active {
                                    let mut ki: u8 = 0;
                                    for i in 0..ad.ms_creating.n {
                                        if ad.ms_creating.pubkeys[i as usize] == [0u8; 32] { ki = i; break; }
                                    }
                                    ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: ki };
                                } else {
                                    ad.app.go_main_menu();
                                }
                                        ad.needs_redraw = true;
                                        return;
                                    }
                                }
                            }

                            FN += 1;

                            // ── Platform-adaptive frame extraction ──
                            // Waveshare OV5640: 640 bytes/line (YUV422 YUYV, 2 bytes/pixel)
                            // M5Stack GC0308: 320 bytes/line (Y-only, 1 byte/pixel)
                            let data = buf_back.as_slice();
                            let data_len = data.len();
                            #[cfg(feature = "waveshare")]
                            let bpl: usize = 640; // YUV422: 320 pixels × 2 bytes
                            #[cfg(feature = "m5stack")]
                            let bpl: usize = 320; // Y-only: 320 pixels × 1 byte
                            let total_lines = data_len / bpl;
                            let full_h: usize = total_lines.min(240);
                            let frame_ok = full_h >= 100;

                            let render_w: usize = 240;
                            let render_h: usize = 180;
                            let crop_x0: usize = 40;
                            let crop_y0: usize = 30;

                            // ── Display: blit crop from DMA buffer ──
                            if frame_ok && !QR_ERROR_SHOWING {
                                for cy in 0..render_h {
                                    let src_y = full_h - 1 - (crop_y0 + cy);
                                    for cx in 0..render_w {
                                        #[cfg(feature = "waveshare")]
                                        let idx = src_y * bpl + (crop_x0 + cx) * 2; // Y byte at even offset
                                        #[cfg(feature = "m5stack")]
                                        let idx = src_y * bpl + (crop_x0 + cx);
                                        *crop_ptr.add(cy * render_w + cx) = if idx < data_len {
                                            data[idx]
                                        } else { 0 };
                                    }
                                }
                                let crop_slice = core::slice::from_raw_parts(
                                    crop_ptr as *const u8, render_w * render_h);
                                let guide = QR_GUIDE_VER | if QR_FINDERS_BEEPED { 0x80 } else { 0 };
                                boot_display.blit_camera_frame(crop_slice, render_w, render_h, guide);
                            }

                            // ── Copy full frame to DB on decode frames ──
                            let is_decode_frame = FN % 2 == 0;

                            if is_decode_frame && frame_ok && !QR_ERROR_SHOWING {
                                for dy in 0..full_h {
                                    let src_y = full_h - 1 - dy;
                                    let dst_off = dy * 320;
                                    for dx in 0..320usize {
                                        #[cfg(feature = "waveshare")]
                                        let idx = src_y * bpl + dx * 2; // Y from even bytes
                                        #[cfg(feature = "m5stack")]
                                        let idx = src_y * bpl + dx;
                                        *db_ptr.add(dst_off + dx) = if idx < data_len {
                                            data[idx]
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
                                let ts = touch::read_touch(i2c);
                                #[cfg(feature = "waveshare")]
                                let act = tracker.update(ts, touch::HwGesture::None);
                                #[cfg(feature = "m5stack")]
                                let act = tracker.update(ts);
                                if let touch::TouchAction::Tap { x, y } = act {
                                    if (x <= 40 && y <= 40) || (x >= 268 && y <= 40) {
                                        sound::click(delay);
                                        if ad.ms_creating.n > 0 && !ad.ms_creating.active {
                                    let mut ki: u8 = 0;
                                    for i in 0..ad.ms_creating.n {
                                        if ad.ms_creating.pubkeys[i as usize] == [0u8; 32] { ki = i; break; }
                                    }
                                    ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: ki };
                                } else {
                                    ad.app.go_main_menu();
                                }
                                        ad.needs_redraw = true;
                                        return;
                                    }
                                }
                            }

                            // Skip QR decode on display-only frames
                            if !is_decode_frame { return; }

                            if QR_COOLDOWN > 0 {
                                QR_COOLDOWN -= 1;
                            } else {
                                let db_slice = core::slice::from_raw_parts(db_ptr as *const u8, fs);
                                let qr_result = crate::qr::decoder::decode(db_slice, 320, 240);
                                        match qr_result {
                                            Ok(result) => {
                                                // Tick sound on first successful decode (QR positioned)
                                                if !QR_FINDERS_BEEPED {
                                                    sound::qr_found(delay);
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

                                                // Check for multi-frame fragment — accept immediately (no 3-match filter)
                                                let d = &result.data[..result.len];
                                                let is_mf = result.len >= 7
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
                                                            sound::qr_found(delay);

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
                                                                sound::qr_decoded(delay);
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
                                                // Normal single-frame QR

                                                // SeedQR: 3-consecutive-match + checksum validation
                                                let d = &result.data[..result.len];
                                                let is_compact_seedqr = result.len == 16 || result.len == 32;
                                                let is_standard_seedqr = (result.len == 48 || result.len == 96)
                                                    && d.iter().all(|&b| b >= b'0' && b <= b'9');
                                                let _is_seedqr = is_compact_seedqr || is_standard_seedqr;

                                                // Use standard 3-consecutive-match for everything

                                                // Standard 3-consecutive-match filter for other QR types
                                                if ad.app.state != crate::app::input::AppState::PassphraseEntry {
                                                let matches_last = result.len == QR_LAST_LEN
                                                    && result.data[..result.len] == QR_LAST[..QR_LAST_LEN];
                                                if matches_last {
                                                    QR_CONSEC += 1;
                                                } else {
                                                    QR_CONSEC = 1;
                                                    QR_LAST_LEN = result.len;
                                                    QR_LAST[..result.len]
                                                        .copy_from_slice(&result.data[..result.len]);
                                                }
                                                if QR_CONSEC >= 3 {
                                                    // Decode confirmed — play success chirp
                                                    sound::qr_decoded(delay);
                                                    let data = &result.data[..result.len];
                                                    QR_CONSEC = 0;
                                                    QR_COOLDOWN = 90;
                                                    QR_FINDERS_BEEPED = false;

                                                    // Route based on content type
                                                    let is_kaspa = result.len >= 6 && (
                                                        &data[..6] == b"kaspa:" ||
                                                        &data[..6] == b"KASPA:");
                                                    if is_kaspa {
                                                        // Kaspa address — lowercase and store
                                                        let copy_len = result.len.min(ad.scanned_addr.len());
                                                        for i in 0..copy_len {
                                                            ad.scanned_addr[i] = if data[i] >= b'A' && data[i] <= b'Z' {
                                                                data[i] + 32
                                                            } else {
                                                                data[i]
                                                            };
                                                        }
                                                        ad.scanned_addr_len = copy_len;

                                                        let valid = wallet::address::validate_kaspa_address(
                                                            &ad.scanned_addr[..ad.scanned_addr_len]);
                                                        ad.scanned_addr_valid = valid;
                                                        if valid {
                                                            log!("   → Valid Kaspa address");
                                                            sound::qr_decoded(delay);
                                                        } else {
                                                            log!("   → Kaspa address (invalid checksum)");
                                                            sound::beep_error(delay);
                                                        }
                                                        ad.app.state = crate::app::input::AppState::ShowAddress;
                                                        ad.needs_redraw = true;
                                                    } else if result.len >= 4 && &data[..4] == b"KSPT" {
                                                        // PSKT transaction — check version
                                                        let pskt_version = if result.len >= 5 { data[4] } else { 0x01 };
                                                        if pskt_version == 0x02 {
                                                            // v2 PSKT: partially signed (from another signer)
                                                            match wallet::pskt::parse_signed_pskt_v2(data, &mut ad.demo_tx) {
                                                                Ok(()) => {
                                                                    let (present, required) = wallet::pskt::signature_status(&ad.demo_tx);
                                                                    log!("   → PSKT v2: {} in, {} out, sigs {}/{}",
                                                                        ad.demo_tx.num_inputs, ad.demo_tx.num_outputs, present, required);
                                                                    ad.app.start_review(
                                                                        ad.demo_tx.num_outputs as u8,
                                                                        ad.demo_tx.num_inputs as u8);
                                                                    ad.needs_redraw = true;
                                                                }
                                                                Err(e) => {
                                                                    log!("   → PSKT v2 parse error: {:?}", e);
                                                                }
                                                            }
                                                        } else {
                                                            // v1 PSKT: unsigned (original format)
                                                            match wallet::pskt::parse_pskt(data, &mut ad.demo_tx) {
                                                                Ok(()) => {
                                                                    log!("   → PSKT v1: {} in, {} out",
                                                                        ad.demo_tx.num_inputs, ad.demo_tx.num_outputs);
                                                                    ad.app.start_review(
                                                                        ad.demo_tx.num_outputs as u8,
                                                                        ad.demo_tx.num_inputs as u8);
                                                                    ad.needs_redraw = true;
                                                                }
                                                                Err(e) => {
                                                                    log!("   → PSKT v1 parse error: {:?}", e);
                                                                }
                                                            }
                                                        }
                                                    } else if (result.len == 48 || result.len == 96)
                                                        && data.iter().all(|&b| b >= b'0' && b <= b'9')
                                                    {
                                                        // Standard SeedQR — numeric digit string (48=12w, 96=24w)
                                                        let mut import_indices = [0u16; 24];
                                                        let wc = seed_manager::decode_seedqr(data, &mut import_indices);
                                                        if wc > 0 && validate_mnemonic(&import_indices, wc) {
                                                            ad.mnemonic_indices = import_indices;
                                                            ad.word_count = wc;
                                                            log!("   → SeedQR imported ({} words) → passphrase", wc);
                                                            sound::qr_decoded(delay);
                                                            ad.pp_input.reset();
                                                            ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                                            ad.needs_redraw = true;
                                                        } else {
                                                            log!("   → SeedQR: invalid checksum");
                                                            sound::beep_error(delay);
                                                        }
                                                    } else if result.len == 16 || result.len == 32 {
                                                        // CompactSeedQR — raw entropy (16=12w, 32=24w)
                                                        let mut import_indices = [0u16; 24];
                                                        let wc = seed_manager::decode_compact_seedqr(data, &mut import_indices);
                                                        if wc > 0 && validate_mnemonic(&import_indices, wc) {
                                                            ad.mnemonic_indices = import_indices;
                                                            ad.word_count = wc;
                                                            log!("   → CompactSeedQR imported ({} words) → passphrase", wc);
                                                            sound::qr_decoded(delay);
                                                            ad.pp_input.reset();
                                                            ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                                            ad.needs_redraw = true;
                                                        } else {
                                                            log!("   → CompactSeedQR: invalid checksum");
                                                            sound::beep_error(delay);
                                                        }
                                                    } else if result.len == 104 && &data[..4] == b"KSFU" {
                                                        // Firmware update QR — verify signature
                                                        if let Some(update) = fw_update::parse_update_qr(data) {
                                                            ad.fw_update_verified = fw_update::verify_update(&update);
                                                            ad.fw_update_info = update;
                                                            ad.app.state = crate::app::input::AppState::FwUpdateResult;
                                                            ad.needs_redraw = true;
                                                            log!("   → Firmware update QR: v{}, verified={}",
                                                                ad.fw_update_info.version, ad.fw_update_verified);
                                                        } else {
                                                            log!("   → KSFU: parse failed");
                                                            sound::beep_error(delay);
                                                        }
                                                    } else {
                                                        log!("   → Unknown QR format");
                                                    }
                                                }
                                                } // end if not already accepted by fast path
                                                } // end else (non-multi-frame)
                                            }
                                            Err(_) => {
                                                QR_CONSEC = 0;
                                                QR_FINDERS_BEEPED = false;
                                                // BB camera decode removed — unreliable at QVGA resolution.
                                                // BB import from SD card works perfectly.
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
