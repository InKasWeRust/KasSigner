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

/// Convert a hex ASCII byte to a nibble (0-15). Returns 0xFF on invalid input.
#[inline]
fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0xFF,
    }
}

// Static buffers for QR state (persist across calls)
static mut FN: u32 = 0;
// DB decode buffer: heap-allocated (PSRAM) to free ~76KB SRAM for stack.
static mut DB_PTR: *mut u8 = core::ptr::null_mut();
// CROP buffer in SRAM for fast display blit
static mut CROP_BUF: [u8; 240*180] = [0u8; 240*180];
static mut QR_LAST: [u8; 256] = [0u8; 256];
static mut QR_LAST_LEN: usize = 0;
static mut QR_CONSEC: u8 = 0;
static mut QR_COOLDOWN: u32 = 0;
static mut QR_FINDERS_BEEPED: bool = false;
// Full-resolution escalation throttle: after a failed full-res pass,
// skip escalation for this many fast passes to keep the viewfinder alive.
#[cfg(feature = "waveshare")]
static mut QR_ESC_COOLDOWN: u8 = 0;
// Adaptive-threshold window in use, as a divisor of image width. 8 is the
// quirc default and suits dense symbols; 3 is the wide window that rescues
// V1/V2. Sticky: switches only after two consecutive misses, so a decoding
// stream never pays for the window it isn't using.
static mut QR_DENOM: usize = 8;
static mut QR_DENOM_MISS: u8 = 0;
// Frames left of green border after a successful decode.
#[cfg(feature = "waveshare")]
static mut QR_DECODE_FLASH: u8 = 0;
// M5Stack synchronous decode working image, internal SRAM. The 240x240 crop
// used to be compacted in PSRAM and then copied AGAIN into a PSRAM Vec by
// prepare — every decode access paid the PSRAM/cache tax that measured 3-10x
// on the Waveshare before its SRAM buffer landed. Affordable now: v1.0.4
// evicted the DB from SRAM when rqrr needed >96KB of stack; heap-backed rqrr
// needs ~4KB, so 57.6KB of .bss is fine.
// EXPERIMENT, 2026-07-31. 57,600 bytes of internal SRAM .bss, restored to find
// out whether the margin now exists for it.
//
// This buffer is why V11 decodes tripped the ProCpu stack guard inside
// rqrr::decode::correct_format (audit section 2a); removing it is what made
// them work. It buys roughly 100 ms per decode attempt: prep 81 -> 31 ms,
// det ~88 -> 35 ms, and a scan takes several attempts.
//
// Expected to panic again. Since the removal the image has GROWN, not shrunk:
// the SAR ADC entropy code, the keyboard length caps, the wall-clock idle wipe
// and the whole BIP32/SCHNORR test surface are all compiled in now. The
// boot-kats-full feature changes which tests RUN, not which are COMPILED.
//
// If it does NOT panic, that is not permission to keep it. Working and having
// margin are different things, and confusing the two is what cost a day.
#[cfg(feature = "m5stack")]
static mut QR_SRAM_IMG: [u8; 240 * 240] = [0; 240 * 240];
// Async escalation state (core-1 worker): a full-resolution job is owed, and
// whether the second (alternate-window) attempt has been spent.
#[cfg(feature = "waveshare")]
static mut ESC_PENDING: bool = false;
/// Consecutive fast-pass (240x240) results with zero grids. Dense codes
/// (V11 at typical distance ~1.2 px/module after downscale) can be
/// invisible to the finder at 240 while trivially readable at full
/// resolution — but escalation only armed on located-not-decoded results,
/// so a grids=0 streak hunted for tens of seconds. A streak now owes one
/// full-resolution pass too.
static mut QR_MISS_STREAK: u8 = 0;
#[cfg(feature = "waveshare")]
static mut ESC_TRIED_ALT: bool = false;
#[cfg(feature = "waveshare")]
static mut ESC_ALT_DENOM: usize = 3;
static mut QR_ERROR_SHOWING: bool = false;
static mut QR_GUIDE_VER: u8 = 0;
static mut QR_VER_SAME_CNT: u8 = 0;
// Multi-frame receive buffers. Increased from 20 to 40 frames (v1.0.3-wip)
// to handle signed PSKBs which run ~2,600 bytes after adding two signatures
// and chunk to 26 frames at the device's default 106-byte-per-frame output.
// Slot size stays at 256 (max frag_len is 255 due to u8 header field).
const MF_MAX_FRAMES: usize = 40;
const MF_SLOT_SIZE: usize = 256;
const MF_BUF_SIZE: usize = MF_MAX_FRAMES * MF_SLOT_SIZE; // 10,240 bytes

static mut MF_BUF: [u8; MF_BUF_SIZE] = [0u8; MF_BUF_SIZE];
static mut MF_RECEIVED: [bool; MF_MAX_FRAMES] = [false; MF_MAX_FRAMES];
static mut MF_FRAG_SIZE: [u16; MF_MAX_FRAMES] = [0; MF_MAX_FRAMES];
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

/// Zero every buffer a scanned QR payload can land in (M-10).
///
/// `QR_LAST`, `MF_BUF` and `QR_VOTES` are the generic decode buffers, so a
/// scanned SeedQR ends up in them: 48 or 96 decimal digits for a standard one,
/// or 16/32 bytes of raw entropy for CompactSeedQR. They are `static mut`, so
/// the payload persisted for the rest of the session with nothing to clear it.
/// The re-entry reset set `QR_LAST_LEN = 0` but left the bytes, which hides the
/// data from the code without removing it.
///
/// Called at two points: immediately after a decoded seed is handed to
/// `AppData`, which is the moment it stops being needed, and on re-entry to the
/// scan state, which catches payloads from a session that ended some other way.
///
/// Volatile writes, so the compiler cannot elide stores to memory it can see is
/// never read again.
fn wipe_qr_buffers() {
    unsafe {
        let p = core::ptr::addr_of_mut!(QR_LAST) as *mut u8;
        for i in 0..QR_LAST.len() {
            core::ptr::write_volatile(p.add(i), 0);
        }
        QR_LAST_LEN = 0;

        let m = core::ptr::addr_of_mut!(MF_BUF) as *mut u8;
        for i in 0..MF_BUF_SIZE {
            core::ptr::write_volatile(m.add(i), 0);
        }

        // Waveshare-only: the vote buffers belong to the dual-core decode
        // path. M5Stack uses the synchronous path and has none of them.
        #[cfg(feature = "waveshare")]
        {
            let v = core::ptr::addr_of_mut!(QR_VOTES) as *mut u8;
            for i in 0..(VOTE_SLOTS * 32) {
                core::ptr::write_volatile(v.add(i), 0);
            }
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
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

/// Decode in place over a caller-owned buffer (no prepare copy: the buffer
/// IS the working image and gets thresholded destructively). Same output
/// contract as rqrr_decode. Used by the M5Stack synchronous path with the
/// SRAM working image, mirroring the core-1 worker's zero-copy recipe.
#[cfg(feature = "m5stack")]
#[inline(never)]
fn rqrr_decode_inplace(gray: &mut [u8], w: usize, h: usize, denom: usize) -> (usize, Vec<(u8, Vec<u8>)>) {
    // STACK MARGIN, measured 2026-07-31: 12,380 bytes free at this point,
    // deterministic across frames (sp = 0x3FCC2CFC). main.rs records rqrr's
    // measured need after the heap-backing fix as ~4 KB for a 240x240 decode,
    // so this is roughly 3x headroom, and it survives the hardest case: a
    // 13-frame V11 multiframe consolidation, 32 inputs, 3,069 bytes.
    //
    // For contrast, the core-1 worker on waveshare gets 48 KB for the same job.
    // M5Stack does it in a quarter of that, so the margin is real but not
    // generous. Transaction is 78,952 bytes and AppData is 13 KB: one large
    // local anywhere in main's call chain consumes this. Re-test a V11
    // multiframe scan after any change that adds code, wherever it lands.
    //
    // To re-measure: a `let probe: u32 = 0;` here, its address is the stack
    // pointer, minus 0x3FCBFCA0 (the guard, from the A1 register in three
    // panic dumps). See audit section 2a.
    let t0 = systick();
    let mut img = rqrr::PreparedImage::prepare_borrowed_with_denom(w, h, denom, gray);
    let t1 = systick();

    let grids = img.detect_grids();
    let t2 = systick();

    let prep_ms = t1.wrapping_sub(t0) / 16_000;
    let det_ms = t2.wrapping_sub(t1) / 16_000;
    log!("   [rqrr] {}x{} s=w/{} prep={}ms det={}ms grids={} (sram)", w, h, denom, prep_ms, det_ms, grids.len());

    let n_grids = grids.len();
    let mut results = Vec::new();
    for grid in grids {
        let mut out = Vec::new();
        // The stack-guard panics all die inside `decode_to`, between the log
        // line above and the one below. Reporting on both sides brackets it:
        // "before decode" is the depth everything else reached, "after decode"
        // includes whatever rqrr needed. If it panics, the last line printed is
        // the before-figure, which is still the headroom number that mattered.
        crate::app::stack_probe::report("before rqrr decode");
        match grid.decode_to(&mut out) {
            Ok(meta) => {
                crate::app::stack_probe::report("after rqrr decode");
                log!("   [rqrr] decoded V{} {} bytes", meta.version.0, out.len());
                results.push((meta.version.0 as u8, out));
            }
            Err(e) => {
                crate::app::stack_probe::report("after rqrr decode (err)");
                log!("   [rqrr] decode err: {}", e);
            }
        }
    }
    (n_grids, results)
}

/// Decode QR codes from a grayscale image using rqrr.
/// Returns (grids_detected, decoded results). grids > 0 with empty results =
/// QR located but not decodable at this resolution — the caller can escalate.
/// `denom` sets the adaptive-threshold window (~w/denom px). 8 = quirc
/// default, good for V3+. 3 = wide window, needed for V1/V2 rendered with
/// huge modules (interior of large black areas washes out at w/8).
/// Uses decode_to() for raw bytes — critical for binary payloads (KSPT).
#[inline(never)]
fn rqrr_decode(gray: &[u8], w: usize, h: usize, denom: usize) -> (usize, Vec<(u8, Vec<u8>)>) {
    let t0 = systick();
    let mut img = rqrr::PreparedImage::prepare_from_greyscale_with_denom(w, h, denom, |x, y| {
        gray[y * w + x]
    });
    let t1 = systick();

    let grids = img.detect_grids();
    let t2 = systick();

    let prep_ms = t1.wrapping_sub(t0) / 16_000;
    let det_ms = t2.wrapping_sub(t1) / 16_000;
    log!("   [rqrr] {}x{} s=w/{} prep={}ms det={}ms grids={}", w, h, denom, prep_ms, det_ms, grids.len());

    let n_grids = grids.len();
    let mut results = Vec::new();
    for grid in grids {
        let mut out = Vec::new();
        // The stack-guard panics all die inside `decode_to`, between the log
        // line above and the one below. Reporting on both sides brackets it:
        // "before decode" is the depth everything else reached, "after decode"
        // includes whatever rqrr needed. If it panics, the last line printed is
        // the before-figure, which is still the headroom number that mattered.
        crate::app::stack_probe::report("before rqrr decode");
        match grid.decode_to(&mut out) {
            Ok(meta) => {
                crate::app::stack_probe::report("after rqrr decode");
                log!("   [rqrr] decoded V{} {} bytes", meta.version.0, out.len());
                results.push((meta.version.0 as u8, out));
            }
            Err(e) => {
                crate::app::stack_probe::report("after rqrr decode (err)");
                log!("   [rqrr] decode err: {}", e);
            }
        }
    }
    (n_grids, results)
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
                            ad.app.state =
                                crate::app::input::AppState::SettingsMenu;
                        } else if ad.app.state
                            == crate::app::input::AppState::DecryptSecretScan
                        {
                            ad.app.state =
                                crate::app::input::AppState::SingleSigMenu;
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
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
    sound::qr_decoded(delay);

    // Sign Message: Scan hash QR — extract 32-byte hash and go to preview
    if ad.sign_msg_scan_hash {
        ad.sign_msg_scan_hash = false;
        let mut hash = [0u8; 32];
        let ok = if len == 32 {
            // Raw 32 bytes
            hash.copy_from_slice(&data[..32]);
            true
        } else if len == 64 {
            // 64 hex chars
            let mut valid = true;
            for i in 0..32 {
                let hi = hex_nibble(data[i * 2]);
                let lo = hex_nibble(data[i * 2 + 1]);
                if hi == 0xFF || lo == 0xFF { valid = false; break; }
                hash[i] = (hi << 4) | lo;
            }
            valid
        } else {
            false
        };
        if ok {
            ad.sign_msg_hash = hash;
            ad.app.state = crate::app::input::AppState::SignMsgHashPreview;
            ad.needs_redraw = true;
        } else {
            boot_display.draw_rejected_screen("Not a 32-byte hash");
            sound::beep_error(delay);
            delay.delay_millis(1500);
            ad.needs_redraw = true;
        }
        return;
    }

    // Decrypt Secret: scan ciphertext, ECIES decrypt, show result
    if matches!(ad.app.state, crate::app::input::AppState::DecryptSecretScan) {
        // QR contains hex-encoded ciphertext as ASCII text.
        let hex_str = core::str::from_utf8(&data[..len]).unwrap_or("");
        let hex_clean = hex_str.trim();
        if hex_clean.len() < 122 || hex_clean.len() % 2 != 0 {
            boot_display.draw_rejected_screen("Invalid ciphertext hex");
            sound::beep_error(delay);
            delay.delay_millis(1500);
            ad.needs_redraw = true;
            return;
        }
        // Hex decode
        let mut ct_bytes = alloc::vec![0u8; hex_clean.len() / 2];
        let mut ok = true;
        for (i, chunk) in hex_clean.as_bytes().chunks(2).enumerate() {
            let hi = match chunk[0] {
                b'0'..=b'9' => chunk[0] - b'0',
                b'a'..=b'f' => chunk[0] - b'a' + 10,
                b'A'..=b'F' => chunk[0] - b'A' + 10,
                _ => { ok = false; break; }
            };
            let lo = match chunk[1] {
                b'0'..=b'9' => chunk[1] - b'0',
                b'a'..=b'f' => chunk[1] - b'a' + 10,
                b'A'..=b'F' => chunk[1] - b'A' + 10,
                _ => { ok = false; break; }
            };
            ct_bytes[i] = (hi << 4) | lo;
        }
        if !ok || ct_bytes.len() < 61 {
            boot_display.draw_rejected_screen("Bad hex data");
            sound::beep_error(delay);
            delay.delay_millis(1500);
            ad.needs_redraw = true;
            return;
        }
        let pp = ad.seed_mgr.active_slot()
            .map(|s| s.passphrase_str())
            .unwrap_or("");
        // `derive_seed` is None for raw-key and xprv slots, which have no
        // BIP39 seed. Previously it read their packed key bytes as word
        // indices and panicked; now it folds into the existing failure arm.
        let decrypt_result = match crate::app::signing::derive_seed(
            &ad.mnemonic_indices, ad.word_count, pp)
        {
            Some(seed) => match wallet::bip32::derive_account_key(&seed.bytes) {
                Ok(acct_key) => wallet::ecies::decrypt(acct_key.private_key_bytes(), &ct_bytes),
                Err(_) => Err("key derivation failed"),
            },
            None => Err("needs a mnemonic seed"),
        };
        match decrypt_result {
            Ok(plaintext) => {
                let copy_len = plaintext.len().min(ad.jpeg_desc_buf.len());
                ad.jpeg_desc_buf[..copy_len].copy_from_slice(&plaintext[..copy_len]);
                ad.jpeg_desc_len = copy_len;
                sound::success(delay);
                ad.app.state = crate::app::input::AppState::DecryptSecretResult;
                ad.needs_redraw = true;
            }
            Err(e) => {
                let msg = match e {
                    "ciphertext too short" => "Data too short",
                    "bad ephemeral pubkey" | "invalid ephemeral point" => "Bad ciphertext",
                    "bad private key" => "Key error",
                    "decryption failed" => "Wrong key or corrupt",
                    _ => "Decrypt failed",
                };
                boot_display.draw_rejected_screen(msg);
                sound::beep_error(delay);
                delay.delay_millis(2000);
                ad.needs_redraw = true;
            }
        }
        return;
    }

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
        if pskt_version == 0x02 || pskt_version == 0x03 {
            // v2/v3 KSPT: partially signed (from another signer)
            match wallet::pskt::parse_signed_pskt_v2(data, &mut ad.demo_tx) {
                Ok(()) => {
                    ad.tx_input_format = crate::app::data::TxInputFormat::KsptV2;
                    let (present, required) = wallet::pskt::signature_status(&ad.demo_tx);
                    ad.tx_sigs_present = present;
                    ad.tx_sigs_required = required;
                    log!("   → KSPT v{}: {} in, {} out, sigs {}/{}",
                        pskt_version, ad.demo_tx.num_inputs, ad.demo_tx.num_outputs, present, required);
                    ad.app.start_review(
                        ad.demo_tx.num_outputs as u8,
                        ad.demo_tx.num_inputs as u8);
                    ad.needs_redraw = true;
                }
                Err(e) => {
                    log!("   → KSPT v{} parse error: {:?}", pskt_version, e);
                    // Name the failure. `log!` compiles out under
                    // `production`, so this screen is the only channel.
                    let (l1, l2) = e.screen_text();
                    boot_display.draw_tx_error_screen(l1, l2);
                    sound::beep_error(delay);
                    ad.app.state = crate::app::input::AppState::Rejected;
                    ad.needs_redraw = false; // already drawn
                }
            }
        } else {
            // v1 KSPT: unsigned (original format)
            ad.tx_sigs_present = 0;
            ad.tx_sigs_required = 0;
            match wallet::pskt::parse_pskt(data, &mut ad.demo_tx) {
                Ok(()) => {
                    ad.tx_input_format = crate::app::data::TxInputFormat::KsptV1;
                    log!("   → KSPT v1: {} in, {} out",
                        ad.demo_tx.num_inputs, ad.demo_tx.num_outputs);
                    ad.app.start_review(
                        ad.demo_tx.num_outputs as u8,
                        ad.demo_tx.num_inputs as u8);
                    ad.needs_redraw = true;
                }
                Err(e) => {
                    log!("   → KSPT v1 parse error: {:?}", e);
                    let (l1, l2) = e.screen_text();
                    boot_display.draw_tx_error_screen(l1, l2);
                    sound::beep_error(delay);
                    ad.app.state = crate::app::input::AppState::Rejected;
                    ad.needs_redraw = false;
                }
            }
        }
    } else if len >= 4 && (&data[..4] == b"PSKB" || &data[..4] == b"PSKT") {
        // Kaspa-standard PSKT payload (PSKB bundle or single PSKT).
        // See wallet/std_pskt.rs for the parser, and docs/pskt/
        // PSKT_WIRE_FORMAT.md for the envelope details.
        //
        // Scratch: use signed_qr_buf as a 4 KB hex-decode destination.
        // Safe to clobber — any pending outgoing QR content is stale
        // by the time a new transaction is received.
        //
        // Disjoint mutable borrows: demo_tx, pskt_parsed, signed_qr_buf
        // are separate AppData fields so Rust's borrow checker allows
        // simultaneous &mut access via direct field projection.
        ad.tx_sigs_present = 0;
        ad.tx_sigs_required = 0;
        match wallet::std_pskt::parse_pskt(
            data,
            &mut ad.signed_qr_buf[..],
            &mut ad.demo_tx,
            &mut ad.pskt_parsed,
        ) {
            Ok(()) => {
                // detect_tx_format distinguishes PSKB vs PSKT-single.
                ad.tx_input_format = match wallet::std_pskt::detect_tx_format(data) {
                    wallet::std_pskt::DetectedFormat::PsktPskb =>
                        crate::app::data::TxInputFormat::PsktPskb,
                    wallet::std_pskt::DetectedFormat::PsktSingle =>
                        crate::app::data::TxInputFormat::PsktSingle,
                    // Unreachable: we already matched the magic above,
                    // but the match must be exhaustive. Fall back to
                    // PsktPskb so serializer still emits a valid format.
                    _ => crate::app::data::TxInputFormat::PsktPskb,
                };
                // PSKT-aware sig counter (counts incoming_partial_sigs).
                let (present, required) =
                    wallet::std_pskt::pskt_signature_status(&ad.demo_tx);
                ad.tx_sigs_present = present;
                ad.tx_sigs_required = required;
                log!("   → PSKT: {} in, {} out, sigs {}/{}, unknownRegions {}",
                    ad.demo_tx.num_inputs, ad.demo_tx.num_outputs,
                    present, required,
                    ad.pskt_parsed.unknowns_count);
                ad.app.start_review(
                    ad.demo_tx.num_outputs as u8,
                    ad.demo_tx.num_inputs as u8);
                ad.needs_redraw = true;
            }
            Err(e) => {
                log!("   → PSKT parse error: {:?}", e);
                let (l1, l2) = e.screen_text();
                boot_display.draw_tx_error_screen(l1, l2);
                sound::beep_error(delay);
                ad.app.state = crate::app::input::AppState::Rejected;
                ad.needs_redraw = false;
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
            #[cfg(feature = "waveshare")]
            crate::hw::cam_dma::stop();
            ad.pp_input.reset();
            // The words are in `AppData` now; the decode buffers still hold the
            // scanned payload (M-10).
            wipe_qr_buffers();
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
            #[cfg(feature = "waveshare")]
            crate::hw::cam_dma::stop();
            ad.pp_input.reset();
            // The words are in `AppData` now; the decode buffers still hold the
            // scanned payload (M-10).
            wipe_qr_buffers();
            ad.app.state = crate::app::input::AppState::PassphraseEntry;
            ad.needs_redraw = true;
        } else {
            log!("   → CompactSeedQR: invalid checksum");
            sound::beep_error(delay);
        }
    } else if len >= 37 && &data[..4] == b"STLH" {
        // Stealth scan request: STLH + count(1) + R1(32) + R2(32) + ...
        // Device derives scan privkey /2/0, computes ECDH for each R,
        // returns one-time pubkeys: STLR + count(1) + P1(32) + P2(32) + ...
        let count = data[4] as usize;
        let expected_len = 5 + count * 32;
        // <=2 results (133B) show as one static QR; more is returned as an
        // auto-cycling multi-frame STLR. Cap at 64; KasSee sends the candidate
        // set as a multi-frame STLH that process_multiframe reassembles here.
        if count == 0 || count > 64 || len < expected_len {
            log!("   → STLH: bad count {} or len {}", count, len);
            sound::beep_error(delay);
        } else if ad.word_count == 0 {
            log!("   → STLH: no seed loaded");
            boot_display.draw_rejected_screen("Load seed first");
            sound::beep_error(delay);
            delay.delay_millis(1500);
            ad.needs_redraw = true;
        } else {
            log!("   → STLH: {} R values to scan", count);
            #[cfg(feature = "waveshare")]
            crate::hw::cam_dma::stop();

            boot_display.draw_loading_screen("Stealth scanning...");

            // Derive scan private key: m/44'/111111'/0'/2/0
            let pp = ad.seed_mgr.active_slot()
                .map(|s| s.passphrase_str())
                .unwrap_or("");
            // Stealth scanning is BIP32-path based, so it is meaningless
            // for a slot with no mnemonic. Bail the same way a failed
            // derivation does rather than panicking on packed key bytes.
            let seed = match crate::app::signing::derive_seed(
                &ad.mnemonic_indices, ad.word_count, pp)
            {
                Some(s) => s,
                None => {
                    boot_display.draw_rejected_screen("Needs mnemonic seed");
                    sound::beep_error(delay);
                    delay.delay_millis(1500);
                    ad.needs_redraw = true;
                    return;
                }
            };

            let scan_path: [u32; 5] = [
                44 | 0x80000000,
                111_111 | 0x80000000,
                0 | 0x80000000,
                2,
                0,
            ];
            let scan_key = match wallet::bip32::derive_path(&seed.bytes, &scan_path) {
                Ok(k) => k,
                Err(_) => {
                    boot_display.draw_rejected_screen("Key derivation failed");
                    sound::beep_error(delay);
                    delay.delay_millis(1500);
                    ad.needs_redraw = true;
                    return;
                }
            };
            let scan_priv = scan_key.private_key_bytes();

            // Also derive spend pubkey (account level m/44'/111111'/0')
            let account_key = match wallet::bip32::derive_account_key(&seed.bytes) {
                Ok(k) => k,
                Err(_) => {
                    boot_display.draw_rejected_screen("Account key failed");
                    sound::beep_error(delay);
                    delay.delay_millis(1500);
                    ad.needs_redraw = true;
                    return;
                }
            };
            // Derive x-only pubkey from account privkey
            use k256::elliptic_curve::ScalarPrimitive;
            use k256::elliptic_curve::ops::Add;
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            use k256::{ProjectivePoint, Scalar, PublicKey};
            use sha2::{Sha256, Digest};

            let spend_pub = {
                let prim = ScalarPrimitive::<k256::Secp256k1>::from_slice(
                    account_key.private_key_bytes()).unwrap();
                let scalar = Scalar::from(prim);
                let point = (ProjectivePoint::GENERATOR * scalar).to_affine();
                let encoded = point.to_encoded_point(true);
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&encoded.as_bytes()[1..33]);
                xonly
            };

            boot_display.update_progress_bar(30);

            // Build response: STLR + count + (P1(32) + tweak1(32)) + ...
            // 64 bytes per result. Heap (PSRAM) so a large multi-frame response
            // does not sit on the ~8KB main stack; count<=64 => up to 4101 bytes.
            let mut response = alloc::vec![0u8; 5 + count * 64];
            response[..4].copy_from_slice(b"STLR");
            response[4] = count as u8;

            let v_scalar = {
                let prim = ScalarPrimitive::<k256::Secp256k1>::from_slice(scan_priv)
                    .unwrap();
                Scalar::from(prim)
            };

            for i in 0..count {
                let r_offset = 5 + i * 32;
                let r_bytes = &data[r_offset..r_offset + 32];

                // Parse R (x-only → compressed with 0x02 prefix)
                let mut r_compressed = [0u8; 33];
                r_compressed[0] = 0x02;
                r_compressed[1..].copy_from_slice(r_bytes);
                let r_pub = match PublicKey::from_sec1_bytes(&r_compressed) {
                    Ok(p) => p,
                    Err(_) => {
                        // Invalid R — fill with zeros
                        let out_offset = 5 + i * 64;
                        response[out_offset..out_offset + 64].fill(0);
                        continue;
                    }
                };

                // ECDH: S = v * R
                let s_point = r_pub.to_projective() * v_scalar;
                let s_affine = s_point.to_affine();
                let s_encoded = s_affine.to_encoded_point(true);
                let s_x = &s_encoded.as_bytes()[1..33];

                // Tweak: t = SHA256("KasStealth" || S.x || 0u32)
                let mut hasher = Sha256::new();
                hasher.update(b"KasStealth");
                hasher.update(s_x);
                hasher.update(0u32.to_be_bytes());
                let tweak_hash = hasher.finalize();
                let tweak_prim = ScalarPrimitive::<k256::Secp256k1>::from_slice(&tweak_hash)
                    .unwrap_or_else(|_| {
                        let mut adj = [0u8; 32];
                        adj[1..].copy_from_slice(&tweak_hash[..31]);
                        ScalarPrimitive::<k256::Secp256k1>::from_slice(&adj).unwrap()
                    });
                let tweak_scalar = Scalar::from(tweak_prim);

                // One-time pubkey: P = B + t*G
                let mut b_compressed = [0u8; 33];
                b_compressed[0] = 0x02;
                b_compressed[1..].copy_from_slice(&spend_pub);
                let b_pub = PublicKey::from_sec1_bytes(&b_compressed).unwrap();
                let p_point = b_pub.to_projective()
                    .add(&(ProjectivePoint::GENERATOR * tweak_scalar));
                let p_affine = p_point.to_affine();
                let p_encoded = p_affine.to_encoded_point(true);
                let p_x = &p_encoded.as_bytes()[1..33];

                // Write P (32 bytes) + tweak (32 bytes)
                let out_offset = 5 + i * 64;
                response[out_offset..out_offset + 32].copy_from_slice(p_x);
                response[out_offset + 32..out_offset + 64].copy_from_slice(&tweak_hash);

                boot_display.update_progress_bar(30 + ((i + 1) * 60 / count) as u8);
            }

            boot_display.update_progress_bar(100);

            // Display result. response_len <= 134 (count <= 2): one static QR,
            // returns on next touch as before. Larger: chunk into
            // [idx][total][frag_len][payload] frames (the wire format KasSee
            // accumulates) and auto-cycle a few passes. process_confirmed_qr has
            // no i2c here, so there is no touch-to-exit yet; KasSee collects every
            // frame across the passes.
            let response_len = 5 + count * 64;
            if response_len <= 134 {
                boot_display.draw_qr_fullscreen(&response[..response_len], "STEALTH SCAN");
                delay.delay_millis(300);
                ad.app.state = crate::app::input::AppState::MainMenu;
                ad.needs_redraw = false; // QR is on screen, next touch redraws
            } else {
                // Halt the busy tick from draw_loading_screen; the single-frame
                // branch stops it via draw_qr_fullscreen, but draw_qr_screen_left
                // does not, so without this it beeps through the whole cycle.
                sound::stop_ticking();
                let max_frag: usize = 100;
                let n_frames = (response_len + max_frag - 1) / max_frag;
                let balanced = (response_len + n_frames - 1) / n_frames;
                boot_display.clear_screen();
                // Cycle the frames indefinitely so KasSee can capture every one;
                // leave only when the user taps the screen. A single stop_ticking()
                // before the loop does not hold across the redraw window on M5, so
                // re-silence on every touch poll (no-op on waveshare). Require one
                // no-touch sample before arming exit so a stray contact from the
                // scan does not bail out immediately.
                let mut frame = 0usize;
                let mut touch_armed = false;
                'stlr_show: loop {
                    let offset = frame * balanced;
                    let remaining = response_len.saturating_sub(offset);
                    let frag_len = remaining.min(balanced);
                    let mut fb = [0u8; 134];
                    fb[0] = frame as u8;
                    fb[1] = n_frames as u8;
                    fb[2] = frag_len as u8;
                    fb[3..3 + frag_len].copy_from_slice(&response[offset..offset + frag_len]);
                    let qr_len = if frag_len < 20 { 3 + 20 } else { 3 + frag_len };
                    boot_display.draw_qr_screen_left(&fb[..qr_len]);
                    // Hold ~400ms per frame, polling touch every 20ms.
                    let mut held = 0u32;
                    while held < 400 {
                        sound::stop_ticking();
                        match touch::read_touch(i2c) {
                            touch::TouchState::NoTouch => { touch_armed = true; }
                            _ => { if touch_armed { break 'stlr_show; } }
                        }
                        delay.delay_millis(20);
                        held += 20;
                    }
                    frame = (frame + 1) % n_frames;
                }
                // Consume the exit tap fully (wait for release) before returning,
                // so the main loop's tracker never sees this press as a Tap and
                // routes it onto a main-menu tile. Then clear the screen so the
                // menu loads with no leftover QR artifacts.
                while !matches!(touch::read_touch(i2c), touch::TouchState::NoTouch) {
                    sound::stop_ticking();
                    delay.delay_millis(20);
                }
                sound::stop_ticking();
                boot_display.clear_screen();
                ad.app.state = crate::app::input::AppState::MainMenu;
                ad.needs_redraw = true;
            }
        }
    // H-03: firmware-update-over-QR was an abandoned design. Nothing ever
// installed anything: the flow stopped at a screen showing a verified tick,
// and the signature covered only the hash, never the version, so a replayed
// signature with any version number displayed as verified. Commented out
// rather than deleted so the abandoned design stays visible.
    // } else if len == 104 && &data[..4] == b"KSFU" {
    //     if let Some(update) = fw_update::parse_update_qr(data) {
    //         ad.fw_update_verified = fw_update::verify_update(&update);
    //         ad.fw_update_info = update;
    //         ad.app.state = crate::app::input::AppState::FwUpdateResult;
    //         ad.needs_redraw = true;
    //         log!("   -> Firmware update QR: v{}, verified={}",
    //             ad.fw_update_info.version, ad.fw_update_verified);
    //     } else {
    //         log!("   -> KSFU: parse failed");
    //         sound::beep_error(delay);
    //     }
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
    } else if len >= 5 && data[0] == b'C' && data[1] == b'O' && data[2] == b'V'
        && (data[3] == b'B' || data[3] == b'I')
    {
        // Raw binary COVB/COVI (from multi-frame assembly). Store directly.
        let n = len.min(4096);
        ad.signed_qr_buf[..n].copy_from_slice(&data[..n]);
        ad.covb_len = n;
        ad.pp_input.reset();
        boot_display.clear_screen();
        ad.app.state = crate::app::input::AppState::CovBackupName;
        ad.needs_redraw = true;
        log!("   → COVB raw: {} bytes", n);
    } else if len >= 10 && len <= 1024
        && data[0] == b'4' && data[1] == b'3' && data[2] == b'4' && data[3] == b'f'
        && data[4] == b'5' && data[5] == b'6' && data[6] == b'4'
        && (data[7] == b'2' || data[7] == b'9')
    {
        // Hex-encoded COVB/COVI (from single-frame KasSee export QR). Hex-decode.
        let n = len / 2;
        for i in 0..n {
            let h = data[i * 2];
            let l = data[i * 2 + 1];
            let hi = if h >= b'a' { h - b'a' + 10 } else { h - b'0' };
            let lo = if l >= b'a' { l - b'a' + 10 } else { l - b'0' };
            ad.signed_qr_buf[i] = (hi << 4) | lo;
        }
        ad.covb_len = n;
        ad.pp_input.reset();
        boot_display.clear_screen();
        ad.app.state = crate::app::input::AppState::CovBackupName;
        ad.needs_redraw = true;
        log!("   → COVB: {} hex → {} bytes", len, n);
    } else {
        // Say so on screen, not only in the log.
        //
        // This is the end of a chain of format sniffs: kpub, COVB raw, COVB
        // hex, KSPT, PSKT and the rest each recognise their own prefix, and
        // anything matching none of them landed here and produced NOTHING.
        // No screen, no sound, no state change. Under `production`, `log!`
        // compiles out, so a user scanning a QR from the wrong app, or a
        // corrupted bundle whose magic did not survive, saw the scanner sit
        // there as though it had not read the code at all. It had: the frame
        // decoded, and the device decided in silence that it was unusable.
        //
        // Note this also means `PskError::BadMagic` is unreachable from the
        // QR path. The magic is checked here, before any parser runs, so the
        // parser's own variant only fires on a bundle arriving another way.
        log!("   → Unknown QR format ({} bytes)", len);
        boot_display.draw_tx_error_screen("Unrecognised QR", "Not a KasSigner code");
        sound::beep_error(delay);
        ad.app.state = crate::app::input::AppState::Rejected;
        ad.needs_redraw = false; // already drawn
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
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
    unsafe {
        let frame_num = d[0] as usize;
        let total = d[1];
        let frag_len = d[2] as usize;

        if frag_len + 3 > len { return; }
        // Bounds: reject frames outside the slot table (malformed QR would
        // otherwise index past MF_RECEIVED). 32-input transactions run ~30
        // frames, close enough to the 40-slot bound to make this guard real.
        if frame_num >= MF_MAX_FRAMES || total as usize > MF_MAX_FRAMES { return; }

        if MF_TOTAL == 0 || MF_TOTAL != total {
            MF_TOTAL = total;
            MF_LEN = 0;
            for i in 0..MF_MAX_FRAMES { MF_RECEIVED[i] = false; }
            for i in 0..MF_MAX_FRAMES { MF_FRAG_SIZE[i] = 0; }
        }

        if !MF_RECEIVED[frame_num] {
            let slot_offset = frame_num * MF_SLOT_SIZE;
            let end = slot_offset + frag_len;
            if end <= MF_BUF_SIZE {
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
                // Heap-allocate the 5 KB reassembly buffer into PSRAM
                // instead of putting it on the main thread stack. The
                // main stack on esp-hal 1.0.0 is ~8 KB and run_camera_cycle
                // already carries rqrr scratch and the outer AppData
                // reborrow chain — a 5 KB stack buffer here tips past
                // the guard during 2-frame+ multi-frame receives (stack
                // guard panic observed during kpub import on M5Stack).
                //
                // PSRAM allocator is wired up in main via
                // `esp_alloc::psram_allocator!`, so this Vec lives in
                // external RAM for the ~microseconds between assembly
                // and `process_confirmed_qr`. Dropped at end of scope.
                // `Zeroizing` (M-09): a multiframe payload can be a SeedQR, so
                // this 10 KB PSRAM buffer can hold a mnemonic. `esp-alloc` does
                // not clear freed blocks.
                let mut assembled: zeroize::Zeroizing<alloc::vec::Vec<u8>> =
                    zeroize::Zeroizing::new(alloc::vec![0u8; MF_BUF_SIZE]);
                let mut pos = 0usize;
                for f in 0..total as usize {
                    let sl = f * MF_SLOT_SIZE;
                    let sz = MF_FRAG_SIZE[f] as usize;
                    assembled[pos..pos + sz]
                        .copy_from_slice(&MF_BUF[sl..sl + sz]);
                    pos += sz;
                }
                log!("   → All {} frames, {} bytes", total, pos);
                MF_TOTAL = 0;
                process_confirmed_qr(&assembled[..pos], pos, ad, boot_display, delay, i2c);
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
    //   - "PSKB" (kaspa-wallet-pskt bundle envelope, multi-frame)
    //   - PAYLOAD_V1_RAW (0x01) — compact binary format (kpub, KSPT, etc.)
    len >= 7
        && d[1] >= 2 && d[1] as usize <= MF_MAX_FRAMES
        && d[0] < d[1] && d[2] > 0
        && (d[0] > 0
            || (len >= 7 && (
                &d[3..7] == b"KSPT"
                || &d[3..7] == b"kpub"
                || &d[3..7] == b"PSKB"
                || &d[3..7] == b"COVB"
                || &d[3..7] == b"COVI"
                || &d[3..7] == b"STLH"
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
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
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
            process_multiframe(decoded, len, ad, boot_display, delay, i2c);
            return;
        }

        // rqrr decode is RS-verified — single pass accept
        // (quirc/rqrr does full Reed-Solomon ECC + format verification internally)
        if ad.app.state == crate::app::input::AppState::PassphraseEntry { return; }

        QR_COOLDOWN = 90;
        QR_FINDERS_BEEPED = false;
        log!("   rqrr QR OK: {} bytes (V{})", len, ver);
        process_confirmed_qr(decoded, len, ad, boot_display, delay, i2c);
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
                // Allocate DB on heap (PSRAM) at first frame — frees 76KB SRAM for stack
                if DB_PTR.is_null() {
                    let layout = core::alloc::Layout::from_size_align(320 * 240, 4).unwrap();
                    DB_PTR = alloc::alloc::alloc_zeroed(layout);
                    if DB_PTR.is_null() {
                        log!("   FATAL: DB heap alloc failed");
                        return;
                    }
                }
                let db_ptr = DB_PTR;
                let crop_ptr = core::ptr::addr_of_mut!(CROP_BUF) as *mut u8;

                if FN == 0 {
                    log!("   DB(76KB heap) + CROP(43KB) — rqrr V1-V40 decoder");
                }

                // Reset QR state when re-entering ScanQR
                // (atomic swap = test-and-clear in one operation)
                if crate::QR_RESET_FLAG.swap(false, core::sync::atomic::Ordering::Relaxed) {
                    QR_CONSEC = 0;
                    QR_COOLDOWN = 0;
                    // Clears the bytes, not just the length (M-10).
                    wipe_qr_buffers();
                    QR_FINDERS_BEEPED = false;
                    QR_ERROR_SHOWING = false;
                    // Border starts red on every new scan session: the green
                    // TTL survives the previous session's final decode
                    // otherwise (charged 10, screen routed away, remainder
                    // shown on re-entry). The escalation/worker state below is
                    // waveshare-only (dual-core decode path); m5stack uses the
                    // synchronous path and has none of these statics.
                    QR_DENOM = 8;
                    QR_DENOM_MISS = 0;
                    #[cfg(feature = "waveshare")]
                    {
                        QR_DECODE_FLASH = 0;
                        QR_ESC_COOLDOWN = 0;
                        ESC_PENDING = false;
                        ESC_TRIED_ALT = false;
                        // Invalidate in-flight/undelivered worker results from
                        // the previous session — the cause of the previous
                        // QR's action (e.g. the passphrase keyboard) re-firing
                        // on re-entry.
                        crate::hw::decode_core::bump_generation();
                    }
                    MF_TOTAL = 0;
                    MF_LEN = 0;
                    for i in 0..MF_MAX_FRAMES { MF_RECEIVED[i] = false; }
                    for i in 0..MF_MAX_FRAMES { MF_FRAG_SIZE[i] = 0; }

                    // Force chrome repaint on re-entry to a camera state.
                    // The "one-time init" block below only fires when
                    // cam_status == SensorReady (i.e. cold boot into the
                    // first camera screen). After the first entry the
                    // sensor stays streaming, so a subsequent entry (e.g.
                    // CameraSettings → SettingsMenu → ScanQR) skips that
                    // block entirely and relies on redraw_screen having
                    // painted the ScanQR chrome. This can race with the
                    // viewfinder blit — particularly when cam_tune_active
                    // was just toggled — producing a broken overlay where
                    // only the visor paints and back/header are missing.
                    //
                    // Fix: always repaint chrome on re-entry. Cheap (one
                    // back icon + header line) and guarantees the layout
                    // the blit will overlay is correct for the current
                    // mode. Branch on cam_tune_active so CameraSettings
                    // re-entries also work.
                    #[cfg(feature = "waveshare")]
                    if ad.cam_tune_active {
                        boot_display.draw_cam_tune_overlay(
                            ad.cam_tune_param, &ad.cam_tune_vals);
                    } else {
                        boot_display.draw_camera_screen_chrome();
                    }
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
                    log!("   YUV422 streaming started (cam_dma {}x{}, rqrr)", crate::hw::cam_dma::FRAME_W, crate::hw::cam_dma::FRAME_H);
                    // Waveshare-only: reset the green-border TTL and allocate
                    // the core-1 worker's job buffer. m5stack decodes
                    // synchronously and has neither.
                    #[cfg(feature = "waveshare")]
                    {
                        QR_DECODE_FLASH = 0;
                        // Job buffer for the core-1 worker (one-time PSRAM
                        // alloc, FRAME_BYTES so escalation jobs fit). On OOM
                        // the flag drops and the synchronous path takes over
                        // permanently.
                        if crate::CORE1_OK.load(core::sync::atomic::Ordering::Relaxed)
                            && !crate::hw::decode_core::init(crate::hw::cam_dma::FRAME_BYTES) {
                            crate::CORE1_OK.store(false, core::sync::atomic::Ordering::Relaxed);
                            log!("   decode_core: buffer alloc failed — synchronous decode");
                        }
                    }
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
                                // On ScanQR: only process back-button taps (top-left).
                                // Ignore all other taps to prevent phantom fires.
                                let is_scan = matches!(ad.app.state,
                                    crate::app::input::AppState::ScanQR
                                    | crate::app::input::AppState::SignMsgScanQr | crate::app::input::AppState::DecryptSecretScan);
                                if !is_scan || (x <= 48 && y <= 48) {
                                    ad.cam_tap_x = x;
                                    ad.cam_tap_y = y;
                                    ad.cam_tap_ready = true;
                                    return;
                                }
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
                                } else if ad.app.state
                                    == crate::app::input::AppState::DecryptSecretScan
                                {
                                    ad.app.state =
                                        crate::app::input::AppState::SingleSigMenu;
                                } else {
                                    ad.app.go_main_menu();
                                }
                                ad.needs_redraw = true;
                                return;
                            }
                        }
                        if poll_count > 10_000_000 {
                            // Stalled DMA (descriptor error / VSYNC loss).
                            // Without stop(), STARTED stays true, the next
                            // start_capture() early-returns, and the stall
                            // is permanent — frozen viewfinder. stop() here
                            // makes the next cycle reinit the GDMA channel
                            // and restart capture cleanly.
                            log!("   cam_dma: timeout — reinit");
                            cam_dma::log_status();
                            cam_dma::stop();
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
                            // Same pixels as before, opposite loop order. The
                            // rotation means dst[cy][cx] = src[cx*2][col0+cy*2],
                            // so walking cx on the inside strides the source by
                            // a whole line (960 B at 480 wide) and every read
                            // misses cache — 43k line fills from PSRAM per
                            // frame. Walking the source row on the inside reads
                            // sequentially and pushes the stride onto the
                            // writes, which land in CROP_BUF in internal SRAM
                            // where stride is free.
                            let dp = data.as_ptr();
                            for cx in 0..render_w {
                                let src_row = cx * 2;
                                if src_row >= cam_h { break; }
                                let row_off = src_row * bpl;
                                for cy in 0..render_h {
                                    let src_col = col0 + cy * 2;
                                    let y_idx = row_off + src_col;
                                    *crop_ptr.add(cy * render_w + cx) = if y_idx + 1 < max_safe {
                                        *dp.add(y_idx)
                                    } else { 0 };
                                }
                            }
                        }
                        cam_dma::poll_done();
                        let crop_slice = core::slice::from_raw_parts(
                            crop_ptr as *const u8, render_w * render_h);
                        let mut guide = QR_GUIDE_VER;
                        if ad.cam_tune_active { guide |= 0x40; }
                        // Border: two states. Green rides a TTL charged the
                        // moment a symbol is FOUND (and recharged by decodes),
                        // so it lights on finding like earlier firmware, stays
                        // solid while the code is in view, and returns to red
                        // when the code leaves the frame.
                        let scan_state: u8 = if QR_DECODE_FLASH > 0 {
                            QR_DECODE_FLASH -= 1;
                            2
                        } else {
                            0
                        };
                        boot_display.blit_camera_frame(crop_slice, render_w, render_h, guide, scan_state);
                        cam_dma::poll_done();

                        // ── QR decode ──
                        // Skip entirely when cam-tune is active (Camera Settings).
                        if QR_COOLDOWN > 0 {
                            QR_COOLDOWN -= 1;
                        } else if !ad.cam_tune_active
                            && crate::CORE1_OK.load(core::sync::atomic::Ordering::Relaxed) {
                            // ── Pipelined decode on core 1 ──
                            // The viewfinder no longer halts during decode:
                            // core 0 only pays the 240x240 downsample (a few
                            // ms) or, when escalating, one frame copy, and
                            // keeps blitting while core 1 chews on rqrr.
                            use crate::hw::decode_core;

                            // Consume a finished job first.
                            if let Some(o) = decode_core::take_results() {
                                if o.gen != decode_core::current_generation() {
                                    // Computed from a frame of the previous
                                    // scan session; acting on it would replay
                                    // that session's QR. Drop it.
                                    log!("   [rqrr] stale result (gen {} != {}) discarded", o.gen, decode_core::current_generation());
                                } else {
                                log!("   [rqrr] {}x{} s=w/{} prep={}ms det={}ms grids={} (core1)",
                                     o.w, o.w, o.denom, o.prep_ms, o.det_ms, o.grids);
                                for (v, d) in o.results.iter() {
                                    log!("   [rqrr] decoded V{} {} bytes", v, d.len());
                                }
                                if o.grids > 0 {
                                    if !QR_FINDERS_BEEPED {
                                        sound::qr_found(delay);
                                        QR_FINDERS_BEEPED = true;
                                    }
                                    QR_DECODE_FLASH = 10;
                                }
                                if let Some((ver, ref decoded)) = o.results.first() {
                                    QR_DENOM_MISS = 0;
                                    QR_ESC_COOLDOWN = 0;
                                    ESC_PENDING = false;
                                    ESC_TRIED_ALT = false;
                                    if o.kind == decode_core::KIND_ESC && o.denom != QR_DENOM {
                                        // The window that actually read this
                                        // source becomes the sticky one.
                                        QR_DENOM = o.denom;
                                    }
                                    QR_DECODE_FLASH = 10;
                                    handle_decode_result(*ver, decoded, decoded.len(), ad, boot_display, delay, i2c);
                                } else if o.kind == decode_core::KIND_FAST {
                                    QR_DENOM_MISS = QR_DENOM_MISS.saturating_add(1);
                                    if QR_DENOM_MISS >= 2 {
                                        QR_DENOM = if QR_DENOM == 8 { 3 } else { 8 };
                                        QR_DENOM_MISS = 0;
                                    }
                                    if o.grids > 0 && QR_ESC_COOLDOWN == 0 && MF_TOTAL == 0 {
                                        // Located but not decoded: owe one
                                        // full-resolution pass. Not during a
                                        // multi-frame stream (stale by the
                                        // time it lands, and density is the
                                        // sender's choice there).
                                        ESC_PENDING = true;
                                        ESC_TRIED_ALT = false;
                                    } else if QR_ESC_COOLDOWN > 0 {
                                        QR_ESC_COOLDOWN -= 1;
                                    }
                                    if o.grids == 0 {
                                        QR_MISS_STREAK = QR_MISS_STREAK.saturating_add(1);
                                        // A sustained streak of empty fast
                                        // passes: the code may be too dense
                                        // for 240 — owe one full-res pass.
                                        if QR_MISS_STREAK >= 8 && QR_ESC_COOLDOWN == 0 && MF_TOTAL == 0 && !ESC_PENDING {
                                            ESC_PENDING = true;
                                            ESC_TRIED_ALT = false;
                                            QR_MISS_STREAK = 0;
                                        }
                                    } else {
                                        QR_MISS_STREAK = 0;
                                    }
                                    QR_CONSEC = 0;
                                    if o.grids == 0 { QR_FINDERS_BEEPED = false; }
                                } else {
                                    // Escalation failed at o.denom.
                                    if !ESC_TRIED_ALT {
                                        ESC_TRIED_ALT = true;
                                        ESC_ALT_DENOM = if o.denom == 8 { 3 } else { 8 };
                                        ESC_PENDING = true;
                                    } else {
                                        ESC_PENDING = false;
                                        QR_ESC_COOLDOWN = 3;
                                        QR_CONSEC = 0;
                                    }
                                }
                                } // gen check
                            }

                            // Submit the next job if the worker is free.
                            if decode_core::is_idle() {
                                if ESC_PENDING && MF_TOTAL == 0 {
                                    if let Some(buf) = decode_core::buf_for_fill(cam_h * bpl) {
                                        buf.copy_from_slice(data);
                                        let den = if ESC_TRIED_ALT { ESC_ALT_DENOM } else { QR_DENOM };
                                        decode_core::submit(cam_w, cam_h, den, decode_core::KIND_ESC);
                                        ESC_PENDING = false; // in flight
                                    }
                                } else if let Some(buf) = decode_core::buf_for_fill(240 * 240) {
                                    let dw: usize = 240;
                                    let dh: usize = 240;
                                    let dp = data.as_ptr();
                                    let bp = buf.as_mut_ptr();
                                    for dy in 0..dh {
                                        let sr0 = (dy * cam_h) / dh;
                                        let sr1 = (sr0 + 1).min(cam_h - 1);
                                        let r0 = sr0 * bpl;
                                        let r1 = sr1 * bpl;
                                        let dst_off = dy * dw;
                                        for dx in 0..dw {
                                            let sc0 = (dx * cam_w) / dw;
                                            let sc1 = (sc0 + 1).min(cam_w - 1);
                                            let a = *dp.add(r0 + sc0) as u16;
                                            let b = *dp.add(r0 + sc1) as u16;
                                            let c = *dp.add(r1 + sc0) as u16;
                                            let d = *dp.add(r1 + sc1) as u16;
                                            *bp.add(dst_off + dx) = ((a + b + c + d + 2) >> 2) as u8;
                                        }
                                    }
                                    decode_core::submit(dw, dh, QR_DENOM, decode_core::KIND_FAST);
                                }
                            }
                        } else if !ad.cam_tune_active {
                            // ── Fast pass: 240x240 box-filtered downsample ──
                            //
                            // No rotation here. The display path rotates because
                            // the panel is mounted turned; rqrr locates the
                            // finder patterns itself and decodes at any
                            // orientation, which the full-resolution escalation
                            // pass already proves by feeding it the raw frame.
                            // The transpose was inherited from the display loop
                            // and cost 230k stride-960 PSRAM reads per pass,
                            // one cache line fill each. Reading along the source
                            // row instead makes both the reads and the writes
                            // sequential.
                            //
                            // Row offsets are computed once per row and the two
                            // source rows are clamped, so the four samples are
                            // provably inside the frame and the per-pixel bounds
                            // checks (4 per output pixel, 230k per pass) come
                            // out. Scaled mapping still covers 480 (exact 2x)
                            // and 640 (cam640, 8/3 step).
                            let dw: usize = 240;
                            let dh: usize = 240;
                            let dp = data.as_ptr();
                            debug_assert!(data.len() >= cam_h * bpl);
                            for dy in 0..dh {
                                let sr0 = (dy * cam_h) / dh;
                                let sr1 = (sr0 + 1).min(cam_h - 1);
                                let r0 = sr0 * bpl;
                                let r1 = sr1 * bpl;
                                let dst_off = dy * dw;
                                for dx in 0..dw {
                                    let sc0 = (dx * cam_w) / dw;
                                    let sc1 = (sc0 + 1).min(cam_w - 1);
                                    let a = *dp.add(r0 + sc0) as u16;
                                    let b = *dp.add(r0 + sc1) as u16;
                                    let c = *dp.add(r1 + sc0) as u16;
                                    let d = *dp.add(r1 + sc1) as u16;
                                    *db_ptr.add(dst_off + dx) = ((a + b + c + d + 2) >> 2) as u8;
                                }
                            }
                            let db_slice = core::slice::from_raw_parts(
                                db_ptr as *const u8, dw * dh);

                            // Threshold window: w/8 suits dense symbols, w/3
                            // rescues V1/V2 whose huge modules wash out under
                            // the narrow window. Alternating every pass spends
                            // most frames on the wrong one, so stick with
                            // whatever last decoded and only switch after two
                            // consecutive misses. An animated transfer settles
                            // on one window and never pays for the other again.
                            let (grids, results) = rqrr_decode(db_slice, dw, dh, QR_DENOM);
                            // ── Feedback on finding, before any decode ──
                            // The moment a symbol is located: beep (M5Stack;
                            // no-op on Waveshare) and border to green, exactly
                            // like earlier firmware. Decode is not required.
                            if grids > 0 {
                                if !QR_FINDERS_BEEPED {
                                    sound::qr_found(delay);
                                    QR_FINDERS_BEEPED = true;
                                }
                                // Green on finding, as before: charge the TTL
                                // the moment a symbol is located, decode or
                                // not. Decode passes recharge it too, so the
                                // border is green the whole time a code is in
                                // view and falls back to red when it leaves.
                                QR_DECODE_FLASH = 10;
                            }
                            if let Some((ver, ref decoded)) = results.first() {
                                QR_DENOM_MISS = 0;
                                QR_ESC_COOLDOWN = 0;
                                QR_DECODE_FLASH = 10;
                                handle_decode_result(*ver, decoded, decoded.len(), ad, boot_display, delay, i2c);
                            } else {
                                QR_DENOM_MISS = QR_DENOM_MISS.saturating_add(1);
                                if QR_DENOM_MISS >= 2 {
                                    QR_DENOM = if QR_DENOM == 8 { 3 } else { 8 };
                                    QR_DENOM_MISS = 0;
                                }
                                // ── Escalation pass: full resolution ──
                                // rqrr found a symbol but could not decode it:
                                // too dense for 240x240, or blurred. One pass at
                                // native resolution, 4x the pixels at 480.
                                //
                                // Not while a multi-frame transfer is running.
                                // The sender is already showing the next frame
                                // by the time this returns, so it trades a
                                // guaranteed miss on a live frame for a retry on
                                // a stale one. Density is not the problem there
                                // anyway: the frame version is whatever the
                                // sender chose, and if that were too dense the
                                // first frame would never have landed.
                                if grids > 0 && QR_ESC_COOLDOWN == 0 && MF_TOTAL == 0 {
                                    cam_dma::poll_done();
                                    // Sticky window first, then the other one.
                                    // Bench (96 simulated hand-drawn V1/V2):
                                    // 16 frames only decode at full res, and 4
                                    // of those only under the wide window — a
                                    // single-window escalation would sit
                                    // through sticky flips to reach them. The
                                    // second pass runs only when the first
                                    // full-res pass fails, inside the same
                                    // cooldown budget.
                                    let alt = if QR_DENOM == 8 { 3 } else { 8 };
                                    let (_hg, hires) = rqrr_decode(data, cam_w, cam_h, QR_DENOM);
                                    let (hires, hit_alt) = if hires.is_empty() {
                                        cam_dma::poll_done();
                                        (rqrr_decode(data, cam_w, cam_h, alt).1, true)
                                    } else {
                                        (hires, false)
                                    };
                                    cam_dma::poll_done();
                                    if let Some((ver, ref decoded)) = hires.first() {
                                        if hit_alt {
                                            // The other window is the one that
                                            // reads this source — adopt it.
                                            QR_DENOM = alt;
                                            QR_DENOM_MISS = 0;
                                        }
                                        QR_ESC_COOLDOWN = 0;
                                        QR_DECODE_FLASH = 10;
                                        handle_decode_result(*ver, decoded, decoded.len(), ad, boot_display, delay, i2c);
                                    } else {
                                        // Failed at full res too — throttle, or
                                        // the viewfinder crawls while the user
                                        // holds an undecodable frame.
                                        QR_ESC_COOLDOWN = 3;
                                        QR_CONSEC = 0;
                                    }
                                } else {
                                    if QR_ESC_COOLDOWN > 0 { QR_ESC_COOLDOWN -= 1; }
                                    QR_CONSEC = 0;
                                    if grids == 0 { QR_FINDERS_BEEPED = false; }
                                }
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
                                    let is_scan = matches!(ad.app.state,
                                        crate::app::input::AppState::ScanQR
                                        | crate::app::input::AppState::SignMsgScanQr | crate::app::input::AppState::DecryptSecretScan);
                                    if !is_scan || (x <= 48 && y <= 48) {
                                        ad.cam_tap_x = x;
                                        ad.cam_tap_y = y;
                                        ad.cam_tap_ready = true;
                                        *cam_dma_buf_opt = Some(cam_dma_buf);
                                        *dvp_camera_opt = Some(cam);
                                        return;
                                    }
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
                                    } else if ad.app.state == crate::app::input::AppState::DecryptSecretScan {
                                        ad.app.state = crate::app::input::AppState::SingleSigMenu;
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
                            // Bounded wait. transfer.wait() is a bare spin on
                            // is_done(); if the sensor stops clocking pixels
                            // the buffer never fills, is_done() never turns
                            // true, and the whole device freezes (touch
                            // included). Poll with a timeout instead and
                            // escape via stop(), which halts LCD_CAM + DMA on
                            // the spot. ~50µs/poll × 60_000 ≈ 3s worst case,
                            // far above any legit frame time.
                            let mut wait_polls: u32 = 0;
                            let mut dvp_timed_out = false;
                            let (cam_back, buf_back) = loop {
                                if transfer.is_done() {
                                    // is_done() == true → wait() cannot block.
                                    let (_result, c, b) = transfer.wait();
                                    break (c, b);
                                }
                                wait_polls += 1;
                                if wait_polls > 60_000 {
                                    log!("   dvp: transfer timeout — stop + re-arm");
                                    dvp_timed_out = true;
                                    break transfer.stop();
                                }
                                delay.delay_micros(50);
                            };
                            if dvp_timed_out {
                                // Partial frame — don't render or decode it.
                                // Hand the peripherals back; the next cycle
                                // starts a fresh receive().
                                *cam_dma_buf_opt = Some(buf_back);
                                *dvp_camera_opt = Some(cam_back);
                                return;
                            }

                            // Touch check during wait()
                            {
                                #[cfg(feature = "waveshare")]
                                {
                                    let (ts, gest) = touch::read_touch_with_gesture(i2c);
                                    check_immediate_tap(&ts, ad, boot_display);
                                    let act = tracker.update(ts, gest);
                                    match act {
                                        touch::TouchAction::Tap { x, y } => {
                                            let is_scan = matches!(ad.app.state,
                                                crate::app::input::AppState::ScanQR
                                                | crate::app::input::AppState::SignMsgScanQr | crate::app::input::AppState::DecryptSecretScan);
                                            if !is_scan || (x <= 48 && y <= 48) {
                                                ad.cam_tap_x = x;
                                                ad.cam_tap_y = y;
                                                ad.cam_tap_ready = true;
                                            }
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
                                                if ad.app.state == crate::app::input::AppState::DecryptSecretScan { ad.app.state = crate::app::input::AppState::SingleSigMenu; } else { ad.app.go_main_menu(); }
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

                            // Ambient camera harvest. The camera is already
                            // powered and streaming for the scan, so a frame
                            // delta costs nothing beyond the measurement -
                            // which is the same `frame_noise` call the seed
                            // path makes, and it is gated on `is_live` inside
                            // `stage_camera_frame`. A frozen sensor still
                            // returns frames and looks busy: one 8-frame
                            // capture measured ZERO min-entropy under the full
                            // SP 800-90B suite while four of its seven deltas
                            // were bit-identical.
                            //
                            // Every 8th frame, not every frame: the scan loop
                            // runs at camera rate and the entropy is in the
                            // delta, not the count. `fill()` re-mixes whatever
                            // is staged on every call regardless.
                            //
                            // SHARED BASELINE. `measure` compares against a
                            // `static mut NOISE_SNAP` that the seed path also
                            // uses. Safe because the two cannot overlap - they
                            // are different screens, and the seed path calls
                            // `reset_baseline()` before its own capture loop
                            // (handlers/menu.rs:713) so it never inherits a
                            // frame left here. Both callers are on core 0; the
                            // core-1 worker runs rqrr, not frame_noise. A
                            // third caller would need this checked again.
                            if FN % 8 == 0 {
                                crate::crypto::entropy::stage_camera_frame(data);
                            }
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
                                let mut guide = QR_GUIDE_VER;
                                #[cfg(feature = "waveshare")]
                                if ad.cam_tune_active { guide |= 0x40; }
                                // Two-state on this path (no detection plumbing
                                // here yet): green after decode, red otherwise.
                                let scan_state: u8 = if QR_FINDERS_BEEPED { 2 } else { 0 };
                                // Lock-frame overlay is wired on the cam_dma
                                // path only; this path passes None for now.
                                boot_display.blit_camera_frame(crop_slice, render_w, render_h, guide, scan_state);
                            }

                            // ── Copy full frame to DB on decode frames ──
                            // Skip when cam-tune is active — saves copy + decode time.
                            // cam_tune_active is Waveshare-only; on M5Stack we
                            // always run the decoder.
                            #[cfg(feature = "waveshare")]
                            let is_decode_frame = FN % 2 == 0 && !ad.cam_tune_active;
                            // Every frame on m5stack: the FN%2 gate halved the
                            // decode cadence, and with the SRAM in-place decode
                            // below each attempt is cheap enough to run always.
                            #[cfg(feature = "m5stack")]
                            let is_decode_frame = true;

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
                                            let is_scan = matches!(ad.app.state,
                                                crate::app::input::AppState::ScanQR
                                                | crate::app::input::AppState::SignMsgScanQr | crate::app::input::AppState::DecryptSecretScan);
                                            if !is_scan || (x <= 48 && y <= 48) {
                                                ad.cam_tap_x = x;
                                                ad.cam_tap_y = y;
                                                ad.cam_tap_ready = true;
                                            }
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
                                                if ad.app.state == crate::app::input::AppState::DecryptSecretScan { ad.app.state = crate::app::input::AppState::SingleSigMenu; } else { ad.app.go_main_menu(); }
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
                                // Crop center 240x240 from 320x240 for rqrr.
                                let rqw: usize = 240;
                                let rqh: usize = full_h.min(240);
                                let x0: usize = 40; // (320 - 240) / 2
                                // m5stack: copy the crop rows into the SRAM
                                // working image and decode in place. The fast
                                // path, and the one that used to overflow the
                                // stack on a V11. See QR_SRAM_IMG above.
                                #[cfg(feature = "m5stack")]
                                let (grids, results) = {
                                    let dstp = core::ptr::addr_of_mut!(QR_SRAM_IMG) as *mut u8;
                                    for ry in 0..rqh {
                                        core::ptr::copy_nonoverlapping(
                                            db_ptr.add(ry * 320 + x0) as *const u8,
                                            dstp.add(ry * rqw),
                                            rqw,
                                        );
                                    }
                                    let img = core::slice::from_raw_parts_mut(dstp, rqw * rqh);
                                    rqrr_decode_inplace(img, rqw, rqh, QR_DENOM)
                                };
                                // waveshare-dvp fallback: existing PSRAM path.
                                #[cfg(feature = "waveshare")]
                                let (grids, results) = {
                                    for ry in 0..rqh {
                                        let src = ry * 320 + x0;
                                        let dst = ry * rqw;
                                        if src != dst {
                                            core::ptr::copy(db_ptr.add(src) as *const u8, db_ptr.add(dst), rqw);
                                        }
                                    }
                                    let crop_slice = core::slice::from_raw_parts(db_ptr as *const u8, rqw * rqh);
                                    rqrr_decode(crop_slice, rqw, rqh, QR_DENOM)
                                };
                                // Green on finding here too: latch the flag the
                                // moment a symbol is located, release it when
                                // no symbol is in view.
                                if grids > 0 && !QR_FINDERS_BEEPED {
                                    sound::qr_found(delay);
                                    QR_FINDERS_BEEPED = true;
                                }
                                if let Some((ver, ref decoded)) = results.first() {
                                    QR_DENOM_MISS = 0;
                                    handle_decode_result(*ver, decoded, decoded.len(), ad, boot_display, delay, i2c);
                                } else {
                                    QR_DENOM_MISS = QR_DENOM_MISS.saturating_add(1);
                                    if QR_DENOM_MISS >= 2 {
                                        QR_DENOM = if QR_DENOM == 8 { 3 } else { 8 };
                                        QR_DENOM_MISS = 0;
                                    }
                                    QR_CONSEC = 0;
                                    if grids == 0 { QR_FINDERS_BEEPED = false; }
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
