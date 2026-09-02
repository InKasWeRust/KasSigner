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

//! Second-core rqrr worker.
//!
//! The viewfinder used to halt for the duration of every decode because the
//! whole pipeline lived on one core: blit → rqrr (20ms fast, 100ms+ when the
//! full-resolution escalation fires) → next frame. The ESP32-S3 has a second
//! LX7 core doing nothing. This module parks rqrr on it.
//!
//! Protocol: a single job slot with a four-state atomic.
//!
//!   IDLE  — core 0 owns JOB_BUF and may fill it and submit
//!   READY — job parameters and buffer are valid; core 1 may take it
//!   BUSY  — core 1 is decoding
//!   DONE  — RESULTS is valid; core 0 must consume, then back to IDLE
//!
//! All cross-core handoff is ordered by Acquire/Release on JOB_STATE, so the
//! plain statics behind it (buffer pointer, params, results) never race: each
//! side only touches them in the states it owns. Core 1 never logs — the UART
//! writer is not cross-core safe — so timings travel back inside the result.
//!
//! Memory: one PSRAM job buffer of FRAME_BYTES (fast 240x240 jobs use its
//! first 57,600 bytes; full-resolution escalation jobs fill it). The heap
//! allocator (esp-alloc) is critical-section locked and esp-hal's
//! critical-section implementation is multicore-aware, so rqrr's Vec/Box
//! traffic from core 1 is safe.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

pub const IDLE: u8 = 0;
pub const READY: u8 = 1;
pub const BUSY: u8 = 2;
pub const DONE: u8 = 3;

/// Job kind, so the consumer can route fast-pass and escalation results
/// through their respective state machines.
pub const KIND_FAST: u8 = 0;
pub const KIND_ESC: u8 = 1;

pub static JOB_STATE: AtomicU8 = AtomicU8::new(IDLE);
// Scan-session generation. The consumer bumps it when a scan session resets;
// jobs are stamped at submit and results carry the stamp back, so a result
// computed from a frame of the PREVIOUS session (job still in flight while
// the user was routed away after a decode) is recognisably stale and gets
// dropped instead of re-firing the previous QR's action on re-entry.
static GEN: AtomicU8 = AtomicU8::new(0);
static JOB_GEN: AtomicU8 = AtomicU8::new(0);
static JOB_W: AtomicUsize = AtomicUsize::new(0);
static JOB_H: AtomicUsize = AtomicUsize::new(0);
static JOB_DENOM: AtomicUsize = AtomicUsize::new(8);
static JOB_KIND: AtomicU8 = AtomicU8::new(KIND_FAST);

// Owned by whichever side the state machine says. Published before READY.
static mut JOB_BUF: *mut u8 = core::ptr::null_mut();
static mut JOB_BUF_LEN: usize = 0;

/// Fast-job working image, in internal SRAM. rqrr thresholds it in place and
/// detect/decode read it thousands of times per pass; keeping that traffic
/// off the PSRAM bus (shared with the display crop, the blit, and the camera
/// DMA writing frames continuously) is what makes core-1 detect times stable
/// instead of varying 10x with bus load. 57.6KB — full-resolution escalation
/// jobs don't fit and stay on the PSRAM job buffer, which is fine: they are
/// rare and latency-tolerant.
pub const FAST_LEN: usize = 240 * 240;
static mut FAST_IMG: [u8; FAST_LEN] = [0; FAST_LEN];

/// Result of the last completed job. Valid only in DONE.
pub struct DecodeOutcome {
    /// Session generation this job was submitted under.
    pub gen: u8,
    pub kind: u8,
    pub denom: usize,
    pub grids: usize,
    /// Decoded payloads. `Zeroizing` (K14): a decoded QR can be a SeedQR, and
    /// this is the CROSS-CORE path, so the bytes sit in `RESULTS`, a
    /// `static mut`, until the next job replaces them. The allocation is PSRAM
    /// and `esp-alloc` does not clear freed blocks, so a plain `Vec` left the
    /// seed in external RAM after the drop. Same reasoning as M-09 applied to
    /// the multi-frame buffer; this path and the single-core one both missed
    /// it.
    pub results: Vec<(u8, zeroize::Zeroizing<Vec<u8>>)>,
    pub prep_ms: u32,
    pub det_ms: u32,
    pub w: usize,
}

static mut RESULTS: Option<DecodeOutcome> = None;

fn systick() -> u32 {
    // Per-core cycle counter (CCOUNT via xtensa-lx, which carries the asm
    // internally). The SYSTIMER UNIT0 latch is shared between cores: both
    // sides triggering updates races the latch, and core-1 deltas came back
    // quantized to core-0's call cadence (the repeated 101/112/12ms values
    // in the bench logs were that artifact, not real durations).
    esp_hal::xtensa_lx::timer::get_cycle_count()
}

/// One-time buffer setup, core 0, before any submit. Returns false on OOM.
pub fn init(bytes: usize) -> bool {
    unsafe {
        if !JOB_BUF.is_null() {
            return true;
        }
        let layout = core::alloc::Layout::from_size_align(bytes, 4).unwrap();
        let p = alloc::alloc::alloc_zeroed(layout);
        if p.is_null() {
            return false;
        }
        JOB_BUF = p;
        JOB_BUF_LEN = bytes;
    }
    true
}

/// Core 0: borrow the job buffer for filling. Only valid in IDLE.
/// Jobs that fit the SRAM working image get that (zero further copies, and
/// the whole decode runs off-PSRAM); larger jobs get the PSRAM buffer.
pub fn buf_for_fill(len: usize) -> Option<&'static mut [u8]> {
    if JOB_STATE.load(Ordering::Acquire) != IDLE {
        return None;
    }
    unsafe {
        if len <= FAST_LEN {
            return Some(core::slice::from_raw_parts_mut(
                core::ptr::addr_of_mut!(FAST_IMG) as *mut u8, len));
        }
        if JOB_BUF.is_null() || len > JOB_BUF_LEN {
            return None;
        }
        Some(core::slice::from_raw_parts_mut(JOB_BUF, len))
    }
}

/// Core 0: submit the filled buffer as a job. Only valid in IDLE.
pub fn submit(w: usize, h: usize, denom: usize, kind: u8) -> bool {
    if JOB_STATE.load(Ordering::Acquire) != IDLE {
        return false;
    }
    if unsafe { JOB_BUF.is_null() } || w * h > unsafe { JOB_BUF_LEN } {
        return false;
    }
    JOB_W.store(w, Ordering::Relaxed);
    JOB_H.store(h, Ordering::Relaxed);
    JOB_DENOM.store(denom, Ordering::Relaxed);
    JOB_KIND.store(kind, Ordering::Relaxed);
    JOB_GEN.store(GEN.load(Ordering::Relaxed), Ordering::Relaxed);
    JOB_STATE.store(READY, Ordering::Release);
    true
}

/// Consumer: start a new scan session. Results stamped with an older
/// generation are stale and must be discarded by the consumer.
pub fn bump_generation() {
    GEN.fetch_add(1, Ordering::Relaxed);
}

/// The generation fresh results carry.
pub fn current_generation() -> u8 {
    GEN.load(Ordering::Relaxed)
}

/// Core 0: take a finished result, freeing the slot for the next job.
pub fn take_results() -> Option<DecodeOutcome> {
    if JOB_STATE.load(Ordering::Acquire) != DONE {
        return None;
    }
    // `RESULTS.take()` needed `&mut RESULTS`, which is a stronger claim than
    // this code makes and the one `static_mut_refs` objects to: a `&mut` to a
    // static asserts that no other pointer to it is used for the whole of its
    // life, and the compiler may optimise on that. The protocol above already
    // gives exclusivity, through JOB_STATE rather than through the type
    // system, so the reference was never needed to be sound; it was just the
    // only way `Option::take` can be spelled.
    //
    // `ptr::replace` is `take` through a pointer: it reads the old value out,
    // writes `None` in, and returns the old, creating no reference at all.
    // `addr_of_mut!` rather than `&raw mut` to match the idiom already used at
    // `:133` and `:213` in this file.
    //
    // Reachable only with JOB_STATE == DONE, which core 1 stores with Release
    // after the write at `:236` and this side loads with Acquire above, so the
    // read is ordered after that write and core 1 has finished with the slot.
    let out = unsafe { core::ptr::replace(core::ptr::addr_of_mut!(RESULTS), None) };
    JOB_STATE.store(IDLE, Ordering::Release);
    out
}

/// Whether a submit would be accepted right now.
pub fn is_idle() -> bool {
    JOB_STATE.load(Ordering::Acquire) == IDLE
}

/// Core 1 entry: spin for jobs forever. No logging in here — the UART path
/// is not cross-core safe. Timings ride back inside the outcome.
pub fn core1_main() -> ! {
    // Tripwire: only compiles against the heap-backed rqrr decode.rs. If this
    // line errors, rqrr_nostd/src/decode.rs in the tree is the old version
    // whose inline payload arrays need >96KB of stack and will smash the
    // core-1 guard at the first decode_to.
    let _ = rqrr::RQRR_HEAP_BACKED;
    loop {
        if JOB_STATE
            .compare_exchange(READY, BUSY, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Nothing to do. WAITI would save power but also needs an
            // interrupt source to wake; a relaxed spin keeps this simple and
            // the camera loop keeps the slot busy whenever scanning.
            core::hint::spin_loop();
            continue;
        }

        let w = JOB_W.load(Ordering::Relaxed);
        let h = JOB_H.load(Ordering::Relaxed);
        let denom = JOB_DENOM.load(Ordering::Relaxed);
        let kind = JOB_KIND.load(Ordering::Relaxed);
        let gen = JOB_GEN.load(Ordering::Relaxed);
        let gray: &'static mut [u8] = unsafe {
            if w * h <= FAST_LEN {
                core::slice::from_raw_parts_mut(
                    core::ptr::addr_of_mut!(FAST_IMG) as *mut u8, w * h)
            } else {
                core::slice::from_raw_parts_mut(JOB_BUF, w * h)
            }
        };

        let t0 = systick();
        // In-place: the job buffer IS the working image; no prepare copy.
        let mut img = rqrr::PreparedImage::prepare_borrowed_with_denom(w, h, denom, gray);
        let t1 = systick();
        let grids = img.detect_grids();
        let t2 = systick();

        let n_grids = grids.len();
        let mut results = Vec::new();
        for grid in grids {
            let mut out = Vec::new();
            if let Ok(meta) = grid.decode_to(&mut out) {
                results.push((meta.version.0 as u8, zeroize::Zeroizing::new(out)));
            }
        }

        unsafe {
            RESULTS = Some(DecodeOutcome {
                gen,
                kind,
                denom,
                grids: n_grids,
                results,
                // CCOUNT at CpuClock::max() = 240MHz -> 240_000 cycles/ms.
                prep_ms: t1.wrapping_sub(t0) / 240_000,
                det_ms: t2.wrapping_sub(t1) / 240_000,
                w,
            });
        }
        JOB_STATE.store(DONE, Ordering::Release);
    }
}
