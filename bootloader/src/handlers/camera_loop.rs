// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
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

// handlers/camera_loop.rs — Camera capture + QR decode pipeline
//
// Platform-adaptive frame extraction:
//   Waveshare (OV5640): cam_dma 480×480 YUV422 → rqrr decode from Y plane
//   M5Stack (GC0308):   DvpCamera 320×240 Y-only → rqrr decode from SRAM DB
//   DvpCamera fallback:  320×240 YUV422 → rqrr decode from SRAM DB
//
// QR decoding: rqrr 0.10.1 (no_std fork) — V1-V40, all ECC levels,
// perspective correction, Berlekamp-Massey RS error correction.

use crate::log;
use crate::{app::data::AppData, hw::camera, hw::display, features::fw_update, features::stego, ui::seed_manager, hw::sound, hw::touch, wallet};
use crate::ui::helpers::validate_mnemonic;
use esp_hal::lcd_cam::cam::Camera as DvpCamera;
use esp_hal::dma::DmaRxBuf;

extern crate alloc;
use alloc::vec::Vec;

#[cfg(not(feature = "silent"))]
// Static buffers for QR state (persist across calls)
static mut FN: u32 = 0;
// DB in SRAM for 320×240 QR decode buffer (76KB) — DvpCamera path only
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
static mut MF_BUF: [u8; 5120] = [0u8; 5120];
static mut MF_RECEIVED: [bool; 20] = [false; 20];
static mut MF_FRAG_SIZE: [u16; 20] = [0; 20];
static mut MF_TOTAL: u8 = 0;
static mut MF_LEN: usize = 0;

// Waveshare-only: flash detection and voting confirmation
#[cfg(feature = "waveshare")]
static mut QR_FINDERS_ACTIVE: bool = false;
#[cfg(feature = "waveshare")]
static mut LAST_AVG: u32 = 128;
#[cfg(feature = "waveshare")]
const VOTE_SLOTS: usize = 4;
#[cfg(feature = "waveshare")]
const VOTE_THRESHOLD: u8 = 5;
#[cfg(feature = "waveshare")]
static mut QR_VOTES: [[u8; 32]; 4] = [[0u8; 32]; 4];
#[cfg(feature = "waveshare")]
static mut QR_VOTE_LENS: [u8; 4] = [0u8; 4];
#[cfg(feature = "waveshare")]
static mut QR_VOTE_COUNTS: [u8; 4] = [0u8; 4];
#[cfg(feature = "waveshare")]
static mut QR_VOTE_ACTIVE: usize = 0;

/// Read SYSTIMER UNIT0 counter for timing (16MHz clock)
/// Returns value in 16MHz ticks. Divide by 16000 for ms.
#[inline(always)]
fn systick() -> u32 {
    const SYSTIMER_BASE: u32 = 0x6002_3000;
    unsafe {
        // Trigger UNIT0 value update (bit 30 of UNIT0_OP_REG)
        core::ptr::write_volatile((SYSTIMER_BASE + 0x0004) as *mut u32, 1 << 30);
        // Small delay for value to latch
        let _ = core::ptr::read_volatile((SYSTIMER_BASE + 0x0004) as *const u32);
        // Read UNIT0_VALUE_LO
        core::ptr::read_volatile((SYSTIMER_BASE + 0x0044) as *const u32)
    }
}

/// Decode QR codes from a grayscale image using rqrr.
/// Returns Vec of (version, raw_bytes) for each detected QR.
/// Uses decode_to() for raw bytes — critical for binary payloads (KSPT).
#[inline(never)]
fn rqrr_decode(gray: &[u8], w: usize, h: usize) -> Vec<(u8, Vec<u8>)> {
    let t0 = systick();
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| {
        gray[y * w + x]
    });
    let t1 = systick();

    let grids = img.detect_grids();
    let t2 = systick();

    let prep_ms = t1.wrapping_sub(t0) / 16_000;
    let det_ms = t2.wrapping_sub(t1) / 16_000;
    log!("   [rqrr] {}x{} prep={}ms det={}ms grids={}", w, h, prep_ms, det_ms, grids.len());

    let mut results = Vec::new();
    for grid in grids {
        let mut out = Vec::new();
        match grid.decode_to(&mut out) {
            Ok(meta) => {
                log!("   [rqrr] decoded V{} {} bytes", meta.version.0, out.len());
                results.push((meta.version.0 as u8, out));
            }
            Err(e) => {
                log!("   [rqrr] decode err: {}", e);
            }
        }
    }
    results
}

/// Check raw TouchState for Contact/PressDown in safe button zones (back, gear, EXIT).
/// Waveshare only — stores tap coordinates for tx.rs to process.
/// Gear and exit are handled directly here for instant response.
/// When cam-tune is active, captures ANY touch on PressDown for instant response.
#[cfg(feature = "waveshare")]
#[inline(always)]
fn check_immediate_tap(
    ts: &touch::TouchState,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    if ad.cam_tap_ready { return false; }
    match ts {
        touch::TouchState::One(pt) => {
            let x = pt.x;
            let y = pt.y;
            match pt.event {
                touch::TouchEventType::PressDown | touch::TouchEventType::Contact => {
                    let is_back = x <= 48 && y <= 48;

                    // Back button — handle directly for instant response
                    if is_back {
                        ad.cam_tune_active = false;
                        if ad.ms_creating.n > 0 && !ad.ms_creating.active {
                            let mut key_idx: u8 = 0;
                            for i in 0..ad.ms_creating.n {
                                if ad.ms_creating.slot_empty(i as usize) {
                                    key_idx = i;
                                    break;
                                }
                            }
                            ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx };
                        } else if ad.app.state
                            == crate::app::input::AppState::CameraSettings
                        {
                            // From Camera Settings, back goes to parent Settings menu
                            ad.app.state =
                                crate::app::input::AppState::SettingsMenu;
                        } else {
                            ad.app.go_main_menu();
                        }
                        ad.needs_redraw = true;
                        return true;
                    }

                    // When cam-tune is active (Camera Settings screen), route
                    // taps by zone. Param buttons and EXIT are handled INLINE
                    // for snappy UI — no waiting for the next camera cycle.
                    // Slider strip falls through to the TouchTracker so it
                    // can emit Drag events.
                    if ad.cam_tune_active {
                        if x >= 198 && y <= 36 {
                            // EXIT button
                            ad.cam_tune_active = false;
                            ad.app.state =
                                crate::app::input::AppState::SettingsMenu;
                            ad.needs_redraw = true;
                            return true;
                        }
                        // Param button grid — handle ONLY on PressDown to
                        // debounce (Contact fires repeatedly while holding).
                        // Inline handling = no 30-60ms camera-cycle wait.
                        if matches!(pt.event, touch::TouchEventType::PressDown)
                            && x >= 198 && y > 36 && y < 190
                        {
                            let col: u8 = if x < 259 { 0 } else { 1 };
                            let row: Option<u8> = if (38..=82).contains(&y) {
                                Some(0)
                            } else if (85..=129).contains(&y) {
                                Some(1)
                            } else if (132..=176).contains(&y) {
                                Some(2)
                            } else {
                                None
                            };
                            if let Some(r) = row {
                                let idx = r * 2 + col;
                                if idx < 6 && idx != ad.cam_tune_param {
                                    ad.cam_tune_param = idx;
                                    boot_display.draw_cam_tune_overlay(
                                        ad.cam_tune_param, &ad.cam_tune_vals);
                                }
                            }
                            return true;
                        }
                        // Slider strip (y>=190) and viewfinder — do NOT
                        // return true. Fall through so the tracker sees the
                        // events and can emit Drag/Tap actions normally.
                        return false;
                    }

                    if is_back {
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

/// Process a decoded QR payload — routes to kaspa address, KSPT, SeedQR, kpub, KSFU handlers.
/// Called for both cam_dma and DvpCamera paths after consecutive match confirmation.
#[inline(never)]
fn process_confirmed_qr(
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    delay: &mut esp_hal::delay::Delay,
) {
    sound::qr_decoded(delay);

    // Route based on content type
    if len >= 6 && (&data[..6] == b"kaspa:" || &data[..6] == b"KASPA:") {
        // Kaspa address — lowercase and store
        let copy_len = len.min(ad.scanned_addr.len());
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
    } else if len >= 4 && &data[..4] == b"KSPT" {
        // KSPT transaction — check version
        let pskt_version = if len >= 5 { data[4] } else { 0x01 };
        if pskt_version == 0x02 {
            // v2 KSPT: partially signed (from another signer)
            match wallet::pskt::parse_signed_pskt_v2(data, &mut ad.demo_tx) {
                Ok(()) => {
                    let (present, required) = wallet::pskt::signature_status(&ad.demo_tx);
                    ad.tx_sigs_present = present;
                    ad.tx_sigs_required = required;
                    log!("   → KSPT v2: {} in, {} out, sigs {}/{}",
                        ad.demo_tx.num_inputs, ad.demo_tx.num_outputs, present, required);
                    ad.app.start_review(
                        ad.demo_tx.num_outputs as u8,
                        ad.demo_tx.num_inputs as u8);
                    ad.needs_redraw = true;
                }
                Err(e) => {
                    log!("   → KSPT v2 parse error: {:?}", e);
                }
            }
        } else {
            // v1 KSPT: unsigned (original format)
            ad.tx_sigs_present = 0;
            ad.tx_sigs_required = 0;
            match wallet::pskt::parse_pskt(data, &mut ad.demo_tx) {
                Ok(()) => {
                    log!("   → KSPT v1: {} in, {} out",
                        ad.demo_tx.num_inputs, ad.demo_tx.num_outputs);
                    ad.app.start_review(
                        ad.demo_tx.num_outputs as u8,
                        ad.demo_tx.num_inputs as u8);
                    ad.needs_redraw = true;
                }
                Err(e) => {
                    log!("   → KSPT v1 parse error: {:?}", e);
                }
            }
        }
    } else if (len == 48 || len == 96)
        && data.iter().all(|&b| b.is_ascii_digit())
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
    } else if len == 16 || len == 32 {
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
    } else if len == 104 && &data[..4] == b"KSFU" {
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
    } else if (len >= 4 && &data[..4] == b"kpub")
        || (len == 79 && data[0] == crate::qr::payload::PAYLOAD_V1_RAW)
    {
        // kpub detected — two accepted formats:
        //   Legacy:  base58check-encoded "kpub..." ASCII string
        //   V1_RAW:  1-byte header (0x01) + 78 raw payload bytes
        // import_kpub_any() peeks the header byte and routes correctly.
        if ad.ms_creating.n > 0 && !ad.ms_creating.active {
            // Multisig creation mode: import as cosigner key
            match wallet::xpub::import_kpub_any(&data[..len]) {
                Ok(xpub) => {
                    // Find the next empty slot
                    let mut ki: u8 = 0;
                    for i in 0..ad.ms_creating.n {
                        if ad.ms_creating.slot_empty(i as usize) {
                            ki = i;
                            break;
                        }
                    }
                    // Store cosigner account-level xpub (parent pubkey + chain code)
                    // — required for per-address HD derivation in build_script.
                    ad.ms_creating.cosigner_pubkeys[ki as usize] = xpub.pubkey;
                    ad.ms_creating.cosigner_chain_codes[ki as usize] = xpub.chain_code;
                    log!("   → kpub imported for multisig key {}/{}", ki + 1, ad.ms_creating.n);
                    sound::qr_decoded(delay);
                    let next = ki + 1;
                    if next >= ad.ms_creating.n {
                        ad.ms_creating.build_script();
                        ad.ms_creating.active = true;
                        if let Some(ms_slot) = ad.ms_store.find_free() {
                            ad.ms_store.configs[ms_slot] = ad.ms_creating.clone();
                        }
                        ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                    } else {
                        ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: next };
                    }
                    ad.needs_redraw = true;
                }
                Err(_) => {
                    log!("   → kpub decode failed");
                    sound::beep_error(delay);
                }
            }
        } else {
            // Standalone: store kpub and show as multi-frame QR
            if len <= wallet::xpub::KPUB_MAX_LEN {
                ad.kpub_data[..len].copy_from_slice(&data[..len]);
                ad.kpub_len = len;
                ad.kpub_frame = 0;
                ad.kpub_nframes = 0;
                ad.kpub_user_nframes = 0;
                log!("   → kpub scanned ({} bytes), showing options", len);
                sound::qr_decoded(delay);
                ad.app.state = crate::app::input::AppState::KpubScannedPopup;
                ad.needs_redraw = true;
            } else {
                log!("   → kpub too long ({} bytes)", len);
                sound::beep_error(delay);
            }
        }
    } else {
        log!("   → Unknown QR format ({} bytes)", len);
    }
}

/// Process a multi-frame fragment. Accumulates frames, assembles when complete.
#[inline(never)]
fn process_multiframe(
    d: &[u8],
    len: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    unsafe {
        let frame_num = d[0] as usize;
        let total = d[1];
        let frag_len = d[2] as usize;

        if frag_len + 3 > len { return; }

        if MF_TOTAL == 0 || MF_TOTAL != total {
            MF_TOTAL = total;
            MF_LEN = 0;
            for i in 0..20 { MF_RECEIVED[i] = false; }
            for i in 0..20 { MF_FRAG_SIZE[i] = 0; }
        }

        if !MF_RECEIVED[frame_num] {
            let slot_offset = frame_num * 256;
            let end = slot_offset + frag_len;
            if end <= 5120 {
                MF_BUF[slot_offset..end]
                    .copy_from_slice(&d[3..3 + frag_len]);
                MF_FRAG_SIZE[frame_num] = frag_len as u16;
                MF_RECEIVED[frame_num] = true;
            } else {
                return; // frame won't fit — skip
            }
            sound::qr_found(delay);

            let received = MF_RECEIVED[..total as usize]
                .iter().filter(|&&r| r).count();
            log!("   → Frame {}/{} ({} bytes), {}/{}",
                frame_num + 1, total, frag_len,
                received, total);

            // Draw frame counter in left margin (e.g. "3/8")
            draw_mf_counter(boot_display, received as u8, total);

            let all_received = MF_RECEIVED[..total as usize]
                .iter().all(|&r| r);
            if all_received {
                let mut assembled = [0u8; 5120];
                let mut pos = 0usize;
                for f in 0..total as usize {
                    let sl = f * 256;
                    let sz = MF_FRAG_SIZE[f] as usize;
                    assembled[pos..pos + sz]
                        .copy_from_slice(&MF_BUF[sl..sl + sz]);
                    pos += sz;
                }
                log!("   → All {} frames, {} bytes", total, pos);
                MF_TOTAL = 0;
                process_confirmed_qr(&assembled[..pos], pos, ad, delay);
            }
        }
    }
}

/// Draw multi-frame scan progress dots in the bottom strip below the camera viewfinder.
/// Gray dot = pending, teal dot = received. One dot per frame, horizontally centered.
#[inline(never)]
fn draw_mf_counter(
    boot_display: &mut display::BootDisplay<'_>,
    _received: u8,
    total: u8,
) {
    use embedded_graphics::prelude::*;
    use embedded_graphics::primitives::{Circle, Rectangle, PrimitiveStyle};
    use embedded_graphics::pixelcolor::Rgb565;

    let total_clamped = (total as usize).min(20);
    if total_clamped == 0 { return; }

    let dot_sz: u32 = 6;
    let gap: i32 = 4;
    let dot_y: i32 = 230;

    // Center dots horizontally
    let total_w = total_clamped as i32 * dot_sz as i32 + (total_clamped as i32 - 1) * gap;
    let x_start = (320 - total_w) / 2;

    // Clear the bottom strip once
    Rectangle::new(
        embedded_graphics::geometry::Point::new(0, 226),
        embedded_graphics::geometry::Size::new(320, 14),
    ).into_styled(PrimitiveStyle::with_fill(Rgb565::BLACK))
        .draw(&mut boot_display.display).ok();

    let teal = display::KASPA_TEAL;
    let dim = Rgb565::new(6, 12, 6); // dark gray

    unsafe {
        for i in 0..total_clamped {
            let cx = x_start + i as i32 * (dot_sz as i32 + gap);
            let color = if MF_RECEIVED[i] { teal } else { dim };
            Circle::new(
                embedded_graphics::geometry::Point::new(cx, dot_y),
                dot_sz,
            ).into_styled(PrimitiveStyle::with_fill(color))
                .draw(&mut boot_display.display).ok();
        }
    }
}

/// Check if decoded data is a multi-frame fragment.
#[inline(always)]
fn is_multiframe(d: &[u8], len: usize) -> bool {
    // Multi-frame wire format: [frame_idx, total_frames, frag_len, ...payload]
    // Frame index > 0: accept by shape alone (previous frame 0 established the type).
    // Frame index == 0: first payload byte must be a recognized format marker:
    //   - "KSPT" or "kpub" (legacy ASCII formats)
    //   - PAYLOAD_V1_RAW (0x01) — compact binary format (kpub, KSPT, etc.)
    len >= 7
        && d[1] >= 2 && d[1] <= 20
        && d[0] < d[1] && d[2] > 0
        && (d[0] > 0
            || (len >= 7 && (
                &d[3..7] == b"KSPT"
                || &d[3..7] == b"kpub"
                || d[3] == crate::qr::payload::PAYLOAD_V1_RAW
            )))
}

/// Handle a single rqrr decode result through the consecutive-match filter and routing.
/// Used by both cam_dma and DvpCamera paths.
#[inline(never)]
fn handle_decode_result(
    ver: u8,
    decoded: &[u8],
    len: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    unsafe {
        if !QR_FINDERS_BEEPED {
            sound::qr_found(delay);
            QR_FINDERS_BEEPED = true;
        }

        // Update guide version
        if ver != QR_GUIDE_VER && (1..=40).contains(&ver) {
            if ver == QR_GUIDE_VER {
                QR_VER_SAME_CNT = QR_VER_SAME_CNT.saturating_add(1);
            } else if QR_VER_SAME_CNT == 0 || ver != 0 {
                QR_VER_SAME_CNT = 1;
                QR_GUIDE_VER = ver;
            }
        }

        // Skip QR processing while cam-tune is active
        #[cfg(feature = "waveshare")]
        if ad.cam_tune_active { return; }

        // Multi-frame: accept immediately (no 3-match filter)
        if is_multiframe(decoded, len) {
            process_multiframe(decoded, len, ad, boot_display, delay);
            return;
        }

        // rqrr decode is RS-verified — single pass accept
        // (quirc/rqrr does full Reed-Solomon ECC + format verification internally)
        if ad.app.state == crate::app::input::AppState::PassphraseEntry { return; }

        QR_COOLDOWN = 90;
        QR_FINDERS_BEEPED = false;
        log!("   rqrr QR OK: {} bytes (V{})", len, ver);
        process_confirmed_qr(decoded, len, ad, delay);
    }
}

/// Run one camera capture + QR decode cycle. Called from main loop when in ScanQR state.
#[allow(unused_variables, unused_assignments, unused_mut, unused_unsafe)]
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
            unsafe {
                let db_ptr = core::ptr::addr_of_mut!(DB) as *mut u8;
                let crop_ptr = core::ptr::addr_of_mut!(CROP_BUF) as *mut u8;

                if FN == 0 {
                    log!("   DB(76KB) + CROP(43KB) SRAM — rqrr V1-V40 decoder");
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
                    for i in 0..20 { MF_RECEIVED[i] = false; }
                    for i in 0..20 { MF_FRAG_SIZE[i] = 0; }
                }

                // One-time init
                if *cam_status == camera::CameraStatus::SensorReady {
                    // LCD persistence fix: wash screen with mid-gray then black
                    {
                        use embedded_graphics::primitives::{Rectangle, PrimitiveStyle};
                        use embedded_graphics::prelude::*;
                        use embedded_graphics::pixelcolor::Rgb565;
                        let gray = Rgb565::new(16, 32, 16);
                        Rectangle::new(
                            embedded_graphics::geometry::Point::new(0, 0),
                            embedded_graphics::geometry::Size::new(320, 240),
                        ).into_styled(PrimitiveStyle::with_fill(gray))
                            .draw(&mut boot_display.display).ok();
                        delay.delay_millis(80);
                        Rectangle::new(
                            embedded_graphics::geometry::Point::new(0, 0),
                            embedded_graphics::geometry::Size::new(320, 240),
                        ).into_styled(PrimitiveStyle::with_fill(Rgb565::BLACK))
                            .draw(&mut boot_display.display).ok();
                        delay.delay_millis(30);
                    }
                    // Redraw chrome after wash — branch by mode.
                    // ScanQR gets the scan chrome; CameraSettings gets the
                    // cam-tune overlay. Without this branch, first entry to
                    // CameraSettings wiped the overlay drawn by redraw_screen.
                    #[cfg(feature = "waveshare")]
                    if ad.cam_tune_active {
                        boot_display.draw_cam_tune_overlay(
                            ad.cam_tune_param, &ad.cam_tune_vals);
                    } else {
                        boot_display.draw_camera_screen_chrome();
                    }
                    #[cfg(feature = "m5stack")]
                    {
                        // Back icon only — ScanQR has no home shortcut in v1.0.3
                        use embedded_graphics::image::{Image, ImageRawLE};
                        use embedded_graphics::pixelcolor::Rgb565;
                        let back: ImageRawLE<Rgb565> = ImageRawLE::new(
                            crate::hw::icon_data::ICON_BACK,
                            crate::hw::icon_data::ICON_BACK_W);
                        use embedded_graphics::prelude::*;
                        Image::new(&back,
                            embedded_graphics::geometry::Point::new(0, 0))
                            .draw(&mut boot_display.display).ok();

                        use embedded_graphics::primitives::{Line, PrimitiveStyle};
                        let tw = crate::hw::display::measure_header("SCAN QR");
                        crate::hw::display::draw_oswald_header(
                            &mut boot_display.display, "SCAN QR", (320 - tw) / 2, 30, crate::hw::display::COLOR_TEXT);
                        Line::new(
                            embedded_graphics::geometry::Point::new(20, 40),
                            embedded_graphics::geometry::Point::new(300, 40))
                            .into_styled(PrimitiveStyle::with_stroke(
                                crate::hw::display::KASPA_TEAL, 1))
                            .draw(&mut boot_display.display).ok();
                    }

                    // Fix LCD_CLOCK.CLK_EN
                    let lcd_clk = core::ptr::read_volatile(0x6004_1000u32 as *const u32);
                    if lcd_clk & (1u32 << 31) == 0 {
                        core::ptr::write_volatile(0x6004_1000u32 as *mut u32, lcd_clk | (1u32 << 31));
                    }
                    *cam_status = camera::CameraStatus::Streaming;
                    #[cfg(feature = "waveshare")]
                    {
                        if dvp_camera_opt.is_some() {
                            camera::configure_cam_vsync_eof();
                        }
                        // Only force cam_tune on OV5640 — OV2640 auto exposure works better untouched
                        if !unsafe { crate::SENSOR_OV2640 } {
                            ad.cam_tune_dirty = true;
                        }
                    }
                    #[cfg(feature = "waveshare")]
                    log!("   YUV422 streaming started (cam_dma 480x480, rqrr)");
                    #[cfg(feature = "m5stack")]
                    log!("   QVGA Y-only streaming started (320x240, rqrr)");
                }

                // ── Waveshare cam_dma path: raw GDMA→PSRAM 480×480 ──
                #[cfg(feature = "waveshare")]
                if dvp_camera_opt.is_none() {
                    use crate::hw::cam_dma;

                    // Pre-capture touch check
                    {
                        let (ts, gest) = touch::read_touch_with_gesture(i2c);
                        if check_immediate_tap(&ts, ad, boot_display) { return; }
                        let act = tracker.update(ts, gest);
                        match act {
                            touch::TouchAction::Tap { x, y } => {
                                ad.cam_tap_x = x;
                                ad.cam_tap_y = y;
                                ad.cam_tap_ready = true;
                                return;
                            }
                            touch::TouchAction::Drag { x, y, .. } if ad.cam_tune_active && y >= 198 && (52..=268).contains(&x) => {
                                let clamped = (x as i32 - 56).max(0).min(208) as u32;
                                ad.cam_tune_vals[ad.cam_tune_param as usize] = ((clamped * 255) / 208) as u8;
                                ad.cam_tune_dirty = true;
                                boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                            }
                            _ => {}
                        }
                    }

                    // Start continuous capture (only inits on first call)
                    cam_dma::start_capture();

                    // Poll until frame done.
                    // Also periodically sample the touch sensor so a tap on
                    // the back button during the ~30ms DMA wait feels
                    // instant (no waiting for the next frame cycle). We
                    // only check for back — full touch handling still
                    // happens pre-capture.
                    //
                    // Debounce: require 2 consecutive "finger on back zone"
                    // samples before firing. Single-frame noise would
                    // otherwise back-out spuriously under EMI / light.
                    let mut poll_count = 0u32;
                    let mut back_confirm: u8 = 0;
                    while !cam_dma::poll_done() {
                        poll_count += 1;
                        if poll_count % 2000 == 0 {
                            let ts = touch::read_touch(i2c);
                            let on_back = if let touch::TouchState::One(pt) = ts {
                                matches!(pt.event,
                                    touch::TouchEventType::PressDown
                                    | touch::TouchEventType::Contact)
                                    && pt.x <= 48 && pt.y <= 48
                            } else {
                                false
                            };
                            if on_back {
                                back_confirm += 1;
                            } else {
                                back_confirm = 0;
                            }
                            if back_confirm >= 2 {
                                // Confirmed back tap during DMA wait — exit now.
                                ad.cam_tune_active = false;
                                if ad.ms_creating.n > 0
                                    && !ad.ms_creating.active
                                {
                                    let mut key_idx: u8 = 0;
                                    for i in 0..ad.ms_creating.n {
                                        if ad.ms_creating
                                            .slot_empty(i as usize)
                                        {
                                            key_idx = i;
                                            break;
                                        }
                                    }
                                    ad.app.state =
                                        crate::app::input::AppState::MultisigAddKey {
                                            key_idx,
                                        };
                                } else if ad.app.state
                                    == crate::app::input::AppState::CameraSettings
                                {
                                    ad.app.state =
                                        crate::app::input::AppState::SettingsMenu;
                                } else {
                                    ad.app.go_main_menu();
                                }
                                ad.needs_redraw = true;
                                return;
                            }
                        }
                        if poll_count > 10_000_000 {
                            log!("   cam_dma: timeout");
                            if FN < 3 { cam_dma::log_status(); }
                            return;
                        }
                    }

                    FN += 1;

                    if let Some(data) = cam_dma::get_frame() {
                        let cam_w: usize = cam_dma::FRAME_W;
                        let cam_h: usize = cam_dma::FRAME_H;
                        let bpl: usize = cam_dma::BPL;

                        // ── Display (every frame, 90° rotation, 2× downsample) ──
                        let render_w: usize = 240;
                        let render_h: usize = 180;
                        let col0: usize = (cam_w - render_h * 2) / 2;
                        let max_safe: usize = cam_h * bpl;

                        #[cfg(feature = "ov2640-wide")]
                        {
                            // Display-only barrel correction
                            const K1_X: i32 = -1966; // -0.0300
                            const K1_Y: i32 = -2051; // -0.0313
                            const CX: i32 = 265;
                            const CY: i32 = 358;

                            for cy in 0..render_h {
                                for cx in 0..render_w {
                                    let raw_row: i32 = (cx * 2) as i32;
                                    let raw_col: i32 = (col0 + cy * 2) as i32;

                                    let dx: i32 = raw_row - CX;
                                    let dy: i32 = raw_col - CY;

                                    let dx_n: i64 = ((dx as i64) << 16) / 240;
                                    let dy_n: i64 = ((dy as i64) << 16) / 240;
                                    let r2_q16: i32 = ((dx_n * dx_n + dy_n * dy_n) >> 16) as i32;

                                    let fx: i32 = 65536 + ((K1_X as i64 * r2_q16 as i64) >> 16) as i32;
                                    let fy: i32 = 65536 + ((K1_Y as i64 * r2_q16 as i64) >> 16) as i32;

                                    let cr: i32 = CX + ((dx as i64 * fx as i64) >> 16) as i32;
                                    let cc: i32 = CY + ((dy as i64 * fy as i64) >> 16) as i32;

                                    let sr = if cr < 0 { 0 } else if cr >= 480 { 479 } else { cr as usize };
                                    let sc = if cc < 0 { 0 } else if cc >= 480 { 479 } else { cc as usize };

                                    let y_idx = sr * bpl + sc;
                                    *crop_ptr.add(cy * render_w + cx) = if y_idx + 1 < max_safe {
                                        data[y_idx]
                                    } else { 0 };
                                }
                            }
                        }
                        #[cfg(not(feature = "ov2640-wide"))]
                        {
                            for cy in 0..render_h {
                                for cx in 0..render_w {
                                    let src_row = cx * 2;
                                    let src_col = col0 + cy * 2;
                                    let y_idx = src_row * bpl + src_col;
                                    *crop_ptr.add(cy * render_w + cx) = if y_idx + 1 < max_safe {
                                        data[y_idx]
                                    } else { 0 };
                                }
                            }
                        }
                        cam_dma::poll_done();
                        let crop_slice = core::slice::from_raw_parts(
                            crop_ptr as *const u8, render_w * render_h);
                        let mut guide = QR_GUIDE_VER | if QR_FINDERS_BEEPED { 0x80 } else { 0 };
                        if ad.cam_tune_active { guide |= 0x40; }
                        boot_display.blit_camera_frame(crop_slice, render_w, render_h, guide);
                        cam_dma::poll_done();

                        // ── QR decode — single-pass 240×240 ──
                        // Skip entirely when cam-tune is active (Camera Settings):
                        // no point decoding, and it saves ~20ms per frame.
                        if QR_COOLDOWN > 0 {
                            QR_COOLDOWN -= 1;
                        } else if FN % 2 == 0 && !ad.cam_tune_active {
                            let dw: usize = 240;
                            let dh: usize = 240;
                            for dy in 0..dh {
                                let src_col = dy * 2;
                                let dst_off = dy * dw;
                                for dx in 0..dw {
                                    let src_row = dx * 2;
                                    let y00 = src_row * bpl + src_col;
                                    let y01 = src_row * bpl + (src_col + 1);
                                    let y10 = (src_row + 1) * bpl + src_col;
                                    let y11 = (src_row + 1) * bpl + (src_col + 1);
                                    let a = if y00 < data.len() { data[y00] as u16 } else { 0 };
                                    let b = if y01 < data.len() { data[y01] as u16 } else { 0 };
                                    let c = if y10 < data.len() { data[y10] as u16 } else { 0 };
                                    let d = if y11 < data.len() { data[y11] as u16 } else { 0 };
                                    *db_ptr.add(dst_off + dx) = ((a + b + c + d + 2) >> 2) as u8;
                                }
                            }
                            let db_slice = core::slice::from_raw_parts(
                                db_ptr as *const u8, dw * dh);
                            let results = rqrr_decode(db_slice, dw, dh);
                            if let Some((ver, ref decoded)) = results.first() {
                                handle_decode_result(*ver, decoded, decoded.len(), ad, boot_display, delay);
                            } else {
                                QR_CONSEC = 0;
                                QR_FINDERS_BEEPED = false;
                            }
                        }
                    }

                    return;
                }
                // ── DvpCamera path (M5Stack + Waveshare fallback, 320×240) ──
                if let Some(cam) = dvp_camera_opt.take() {
                    let cam_dma_buf = match cam_dma_buf_opt.take() {
                        Some(b) => b,
                        None => { *dvp_camera_opt = Some(cam); return; }
                    };

                    // Pre-capture touch check
                    {
                        #[cfg(feature = "waveshare")]
                        {
                            let (ts, gest) = touch::read_touch_with_gesture(i2c);
                            if check_immediate_tap(&ts, ad, boot_display) {
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
                                touch::TouchAction::Drag { x, y, .. } if ad.cam_tune_active && y >= 198 && (52..=268).contains(&x) => {
                                    let clamped = (x as i32 - 56).max(0).min(208) as u32;
                                    ad.cam_tune_vals[ad.cam_tune_param as usize] = ((clamped * 255) / 208) as u8;
                                    ad.cam_tune_dirty = true;
                                    boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                                }
                                _ => {}
                            }
                        }
                        #[cfg(feature = "m5stack")]
                        {
                            let ts = touch::read_touch(i2c);
                            let act = tracker.update(ts);
                            if let touch::TouchAction::Tap { x, y } = act {
                                if x <= 48 && y <= 48 {
                                    sound::click(delay);
                                    *cam_dma_buf_opt = Some(cam_dma_buf);
                                    *dvp_camera_opt = Some(cam);
                                    if ad.ms_creating.n > 0 && !ad.ms_creating.active {
                                        let mut ki: u8 = 0;
                                        for i in 0..ad.ms_creating.n {
                                            if ad.ms_creating.slot_empty(i as usize) { ki = i; break; }
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
                    }

                    match cam.receive(cam_dma_buf) {
                        Ok(transfer) => {
                            let (_result, cam_back, buf_back) = transfer.wait();

                            // Touch check during wait()
                            {
                                #[cfg(feature = "waveshare")]
                                {
                                    let (ts, gest) = touch::read_touch_with_gesture(i2c);
                                    check_immediate_tap(&ts, ad, boot_display);
                                    let act = tracker.update(ts, gest);
                                    match act {
                                        touch::TouchAction::Tap { x, y } => {
                                            ad.cam_tap_x = x;
                                            ad.cam_tap_y = y;
                                            ad.cam_tap_ready = true;
                                        }
                                        touch::TouchAction::Drag { x, y, .. } if ad.cam_tune_active && y >= 198 && (52..=268).contains(&x) => {
                                            let clamped = (x as i32 - 56).max(0).min(208) as u32;
                                            ad.cam_tune_vals[ad.cam_tune_param as usize] = ((clamped * 255) / 208) as u8;
                                            ad.cam_tune_dirty = true;
                                            boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                                        }
                                        _ => {}
                                    }
                                }
                                #[cfg(feature = "m5stack")]
                                {
                                    let ts = touch::read_touch(i2c);
                                    let act = tracker.update(ts);
                                    if let touch::TouchAction::Tap { x, y } = act {
                                        if x <= 48 && y <= 48 {
                                            sound::click(delay);
                                            *cam_dma_buf_opt = Some(buf_back);
                                            *dvp_camera_opt = Some(cam_back);
                                            if ad.ms_creating.n > 0 && !ad.ms_creating.active {
                                                let mut ki: u8 = 0;
                                                for i in 0..ad.ms_creating.n {
                                                    if ad.ms_creating.slot_empty(i as usize) { ki = i; break; }
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
                            }

                            FN += 1;

                            // ── Platform-adaptive frame extraction ──
                            let data = buf_back.as_slice();
                            let data_len = data.len();
                            #[cfg(feature = "waveshare")]
                            let bpl: usize = 640; // YUV422: 320 pixels × 2 bytes
                            #[cfg(feature = "m5stack")]
                            let bpl: usize = 320;
                            let total_lines = data_len / bpl;
                            let full_h: usize = total_lines.min(240);
                            let frame_ok = full_h >= 100;

                            let render_w: usize = 240;
                            let render_h: usize = 180;
                            let cam_w: usize = 320;
                            let crop_x0: usize = 40;
                            let crop_y0: usize = 30;

                            // ── Display: blit crop from DMA buffer ──
                            if frame_ok && !QR_ERROR_SHOWING {
                                #[cfg(feature = "waveshare")]
                                {
                                    let cam_col0: usize = (cam_w - render_h) / 2;
                                    let max_safe: usize = full_h * bpl;
                                    for cy in 0..render_h {
                                        for cx in 0..render_w {
                                            let src_row = cx;
                                            let src_col = cam_col0 + cy;
                                            let y_idx = src_row * bpl + src_col;
                                            *crop_ptr.add(cy * render_w + cx) = if y_idx + 1 < max_safe {
                                                data[y_idx]
                                            } else { 0 };
                                        }
                                    }
                                }
                                #[cfg(feature = "m5stack")]
                                {
                                    for cy in 0..render_h {
                                        let src_y = full_h - 1 - (crop_y0 + cy);
                                        for cx in 0..render_w {
                                            let idx = src_y * bpl + (crop_x0 + cx);
                                            *crop_ptr.add(cy * render_w + cx) = if idx < data_len {
                                                data[idx]
                                            } else { 0 };
                                        }
                                    }
                                }
                                let crop_slice = core::slice::from_raw_parts(
                                    crop_ptr as *const u8, render_w * render_h);
                                let mut guide = QR_GUIDE_VER | if QR_FINDERS_BEEPED { 0x80 } else { 0 };
                                #[cfg(feature = "waveshare")]
                                if ad.cam_tune_active { guide |= 0x40; }
                                boot_display.blit_camera_frame(crop_slice, render_w, render_h, guide);
                            }

                            // ── Copy full frame to DB on decode frames ──
                            // Skip when cam-tune is active — saves copy + decode time.
                            // cam_tune_active is Waveshare-only; on M5Stack we
                            // always run the decoder.
                            #[cfg(feature = "waveshare")]
                            let is_decode_frame = FN % 2 == 0 && !ad.cam_tune_active;
                            #[cfg(feature = "m5stack")]
                            let is_decode_frame = FN % 2 == 0;

                            if is_decode_frame && frame_ok && !QR_ERROR_SHOWING {
                                for dy in 0..full_h {
                                    let dst_off = dy * cam_w;
                                    for dx in 0..cam_w {
                                        #[cfg(feature = "waveshare")]
                                        let idx = dy * bpl + dx * 2;
                                        #[cfg(feature = "m5stack")]
                                        let idx = (full_h - 1 - dy) * bpl + dx;
                                        *db_ptr.add(dst_off + dx) = if idx < data_len {
                                            data[idx]
                                        } else { 0 };
                                    }
                                }
                            }

                            let fs: usize = 320 * 240;

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
                                #[cfg(feature = "waveshare")]
                                {
                                    let (ts, gest) = touch::read_touch_with_gesture(i2c);
                                    check_immediate_tap(&ts, ad, boot_display);
                                    let act = tracker.update(ts, gest);
                                    match act {
                                        touch::TouchAction::Tap { x, y } => {
                                            ad.cam_tap_x = x;
                                            ad.cam_tap_y = y;
                                            ad.cam_tap_ready = true;
                                        }
                                        touch::TouchAction::Drag { x, y, .. } if ad.cam_tune_active && y >= 198 && (52..=268).contains(&x) => {
                                            let clamped = (x as i32 - 56).max(0).min(208) as u32;
                                            ad.cam_tune_vals[ad.cam_tune_param as usize] = ((clamped * 255) / 208) as u8;
                                            ad.cam_tune_dirty = true;
                                            boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                                        }
                                        _ => {}
                                    }
                                }
                                #[cfg(feature = "m5stack")]
                                {
                                    let ts = touch::read_touch(i2c);
                                    let act = tracker.update(ts);
                                    if let touch::TouchAction::Tap { x, y } = act {
                                        if x <= 48 && y <= 48 {
                                            sound::click(delay);
                                            if ad.ms_creating.n > 0 && !ad.ms_creating.active {
                                                let mut ki: u8 = 0;
                                                for i in 0..ad.ms_creating.n {
                                                    if ad.ms_creating.slot_empty(i as usize) { ki = i; break; }
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
                            }

                            // Skip QR decode on display-only frames
                            if !is_decode_frame { return; }

                            if QR_COOLDOWN > 0 {
                                QR_COOLDOWN -= 1;
                            } else {
                                let db_slice = core::slice::from_raw_parts(db_ptr as *const u8, fs);

                                let results = rqrr_decode(db_slice, cam_w, full_h);
                                if let Some((ver, ref decoded)) = results.first() {
                                    handle_decode_result(*ver, decoded, decoded.len(), ad, boot_display, delay);
                                } else {
                                    QR_CONSEC = 0;
                                    QR_FINDERS_BEEPED = false;
                                }
                            }
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
