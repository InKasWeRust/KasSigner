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

//! Second-core QR worker, for both S3 units.
//!
//! The decoder runs on the second LX7 core, so the viewfinder on core 0
//! keeps going during a decode and the decode's frames stay off core 0's
//! stack (decoding on core 0, the M5 reached 78,608 bytes of its 140,888;
//! a core-1 job takes 16,112). Each unit's decoder module fills the image;
//! this module runs the job.
//!
//! Protocol: a single job slot with a four-state atomic.
//!
//!   IDLE  — core 0 owns the working image and may fill it and submit
//!   READY — job parameters and buffer are valid; core 1 may take it
//!   BUSY  — core 1 is decoding
//!   DONE  — the result is valid; core 0 must consume it, then back to IDLE
//!
//! Acquire/Release on `JOB_STATE` orders every cross-core handoff, so the
//! plain statics behind it (image, payload, result) never race: each side
//! touches them only in the states it owns. Core 1 never logs (the UART
//! writer is not cross-core safe), so timings travel back in the result.
//!
//! # Where a decoded code lives
//!
//! Only in `PAYLOAD`, a static in internal RAM, until core 0 takes it,
//! copying it out and wiping it. The decode (`kassigner-qr`, the P4's path
//! too) writes straight into it and works in `SCRATCH` beside it, which
//! every decode leaves wiped.
//!
//! No byte of a code goes through the heap (PSRAM here): a growing buffer
//! frees each smaller one it outgrows, and `esp-alloc` does not clear what
//! it frees. For a SeedQR those bytes would be the seed.
//!
//! What does go through it is the finder's working lists, in the vendored
//! decoder (`vendor/rqrr`): the corner squares it found, the groups it
//! tried, and its flood fill's queue. They hold positions in the picture,
//! where a code sat and which pixels a fill passed over, not what the code
//! says, and they are left in freed heap as any freed list is.
//!
//! # A cancelled job is drained, never left
//!
//! A job core 1 has started cannot be recalled. [`drain`] waits for it,
//! bounded, and wipes what it produced, so a cancel leaves the worker
//! `IDLE`, not stuck in `DONE` with the decoded bytes.
//!
//! # Core 1's stack
//!
//! A code's bytes pass through the decode's frames on core 1's stack. After
//! every job core 1 zeroes that stack below the loop, from just above the
//! guard word to just under its own frame; nothing below the loop is live.
//!
//! The job runs in `serve`, never inlined, below the loop's frame: inlined,
//! the decode's locals would sit in the loop's frame, out of the clear's
//! reach. The clear runs once the job has returned, in two passes: the
//! first leaves the spot its own frame stands on, the second covers that
//! spot with a pad and clears below it again.
//!
//! # On a host
//!
//! No core 1: a submit runs the job at once through `serve`, so a host test
//! drives a decoder as the device does. No stack is cleared there.
//!
//! # Its twin
//!
//! The P4 crate's `decode_core.rs`: the same four states and handoff,
//! generations, scratch, cancel by draining, and stack clear after every
//! job. What differs is each chip's: the job (here a frame's size and a
//! fast or escalated pass, there a green plane and an attempt) and the
//! wait (core 1 here sleeps until core 0 wakes it, there it polls). A
//! change to the shared part is made to both.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use kassigner_hal::decoder::Outcome;
use kassigner_qr::DecodeError;

pub const IDLE: u8 = 0;
pub const READY: u8 = 1;
pub const BUSY: u8 = 2;
pub const DONE: u8 = 3;

/// Job kind, so the consumer can route fast-pass and escalation results
/// each to its own state machine.
pub const KIND_FAST: u8 = 0;
pub const KIND_ESC: u8 = 1;

pub static JOB_STATE: AtomicU8 = AtomicU8::new(IDLE);
// Scan-session generation, bumped by the consumer when a session resets.
// A job's result carries the generation it was submitted under, so a stale
// one is dropped rather than re-firing the previous QR's action.
static GEN: AtomicU8 = AtomicU8::new(0);
static JOB_GEN: AtomicU8 = AtomicU8::new(0);
static JOB_W: AtomicUsize = AtomicUsize::new(0);
static JOB_H: AtomicUsize = AtomicUsize::new(0);
static JOB_DENOM: AtomicUsize = AtomicUsize::new(8);
static JOB_KIND: AtomicU8 = AtomicU8::new(KIND_FAST);

// Owned by whichever side the state machine says. Published before READY.

/// The working image, 57.6 KB in internal SRAM; every job is this size.
/// rqrr thresholds it in place and reads it thousands of times a pass: on
/// the PSRAM bus, shared with the display and the camera DMA, detect times
/// would vary tenfold with load.
pub const FAST_LEN: usize = 240 * 240;
static mut FAST_IMG: [u8; FAST_LEN] = [0; FAST_LEN];

/// Largest payload one code can carry, version 40 in byte mode.
pub const MAX_PAYLOAD: usize = 2953;

/// The decoded code of the last job, when it found one. Internal RAM.
static mut PAYLOAD: [u8; MAX_PAYLOAD] = [0; MAX_PAYLOAD];

/// Where the decode works: its bit stream, corrected bytes and the
/// binarizer's row accumulator. Internal RAM, and only core 1 references it.
static mut SCRATCH: kassigner_qr::Scratch = kassigner_qr::Scratch::new();

/// Result of the last completed job. Valid only in DONE. The payload itself
/// is in `PAYLOAD`.
#[derive(Clone, Copy, Debug)]
pub struct DecodeOutcome {
    /// Session generation this job was submitted under.
    pub gen: u8,
    pub kind: u8,
    pub denom: usize,
    /// What the pass found; for `Found`, `len` bytes of `PAYLOAD`.
    pub outcome: Outcome,
    /// Core 1's time for the whole decode, in milliseconds.
    pub decode_ms: u32,
    pub w: usize,
}

static mut RESULTS: Option<DecodeOutcome> = None;

/// How long [`drain`] waits for a job in flight, in core cycles: one second
/// at 240 MHz. A decode takes a few hundred milliseconds, so a job still
/// running then means core 1 has stopped.
const DRAIN_CYCLES: u32 = 240_000_000;

/// Bytes at the bottom of core 1's stack the clear leaves alone: esp-hal's
/// guard word sits 60 bytes up by default, and a write to it is reported as
/// an overflow.
#[cfg(target_arch = "xtensa")]
const STACK_FLOOR_MARGIN: usize = 256;

fn systick() -> u32 {
    // Per-core cycle counter (CCOUNT, via xtensa-lx). Not SYSTIMER: its
    // UNIT0 latch is shared, and with both cores triggering updates core 1's
    // deltas come back quantized to core 0's call cadence.
    //
    // Zero off target: the timings are diagnostics, and with no core 1
    // `drain` never finds a job in flight on a host.
    #[cfg(target_arch = "xtensa")]
    {
        esp_hal::xtensa_lx::timer::get_cycle_count()
    }
    #[cfg(not(target_arch = "xtensa"))]
    {
        0
    }
}

/// Set while [`fill_image`] lends the image, so a fill inside a fill is
/// refused rather than handed a second reference to it.
static FILLING: AtomicBool = AtomicBool::new(false);

/// Core 0: fill the first `len` bytes of the working image with `fill`,
/// before [`submit`]. False, and `fill` not called, unless the worker is
/// `IDLE`, nothing else is filling, and `len` is at most [`FAST_LEN`].
///
/// The frame is downsampled straight into `FAST_IMG`, internal SRAM, and
/// decoded in place. The image is lent for the call, never returned: a
/// reference kept past the submit would alias what core 1 decodes and wipes.
pub fn fill_image(len: usize, fill: impl FnOnce(&mut [u8])) -> bool {
    if len > FAST_LEN || FILLING.swap(true, Ordering::Acquire) {
        return false;
    }
    let lent = JOB_STATE.load(Ordering::Acquire) == IDLE;
    if lent {
        // SAFETY: in `IDLE` core 1 is not touching the image: it takes it
        // only from `READY`, which only `submit` sets, on this core and not
        // during this call. `FILLING` keeps a second fill from lending it
        // again, and the borrow ends with the call.
        let image = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(FAST_IMG) as *mut u8, len)
        };
        fill(image);
    }
    FILLING.store(false, Ordering::Release);
    lent
}

/// Core 0: submit the filled buffer as a job. Only valid in IDLE.
pub fn submit(w: usize, h: usize, denom: usize, kind: u8) -> bool {
    if JOB_STATE.load(Ordering::Acquire) != IDLE {
        return false;
    }
    if w * h > FAST_LEN {
        return false;
    }
    JOB_W.store(w, Ordering::Relaxed);
    JOB_H.store(h, Ordering::Relaxed);
    JOB_DENOM.store(denom, Ordering::Relaxed);
    JOB_KIND.store(kind, Ordering::Relaxed);
    JOB_GEN.store(GEN.load(Ordering::Relaxed), Ordering::Relaxed);
    JOB_STATE.store(READY, Ordering::Release);
    wake_core1();
    true
}

// ── Core 1 asleep between jobs ──────────────────────────────────────────────
//
// Core 1 waits in `WAITI`, the core's clock-gated wait, rather than spinning
// at 240 MHz, which with the main loop runs two cores flat out on every
// screen and heats the unit. Core 0 wakes it with cross-core interrupt 1
// when it posts a job.
//
// A job posted between core 1's look and its `WAITI` is not lost: the
// interrupt stays raised until core 1's handler clears it, so `WAITI` returns
// at once and the loop looks again.

/// `SYSTEM_CPU_INTR_FROM_CPU_1_REG`: bit 0 raises cross-core interrupt 1
/// (`esp32s3` PAC 0.36, `SYSTEM` at `0x600C_0000`, the array at `0x30`).
#[cfg(target_arch = "xtensa")]
const FROM_CPU_1: *mut u32 = 0x600C_0034 as *mut u32;

/// Raise cross-core interrupt 1, which only core 1 has enabled. On a host,
/// run the posted job instead.
fn wake_core1() {
    // SAFETY: a fixed MMIO word, always mapped; writing 1 raises the
    // interrupt, and only this module touches it.
    #[cfg(target_arch = "xtensa")]
    unsafe {
        core::ptr::write_volatile(FROM_CPU_1, 1)
    };
    #[cfg(not(target_arch = "xtensa"))]
    serve();
}

/// Bind the waking interrupt's handler. On core 1, before
/// [`core1_main`]: the binding goes to the core that makes it.
#[cfg(target_arch = "xtensa")]
pub fn bind_wake(mut wake: esp_hal::interrupt::software::SoftwareInterrupt<'static, 1>) {
    wake.set_interrupt_handler(woken);
}

/// Core 1's handler: lower the interrupt. Waking was the point.
#[cfg(target_arch = "xtensa")]
#[esp_hal::handler]
fn woken() {
    // SAFETY: as in `wake_core1`; writing 0 lowers it.
    unsafe { core::ptr::write_volatile(FROM_CPU_1, 0) };
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
///
/// A found payload is copied into `out` when it fits and the job is of the
/// current generation; `PAYLOAD` is wiped either way, since a result nobody
/// copies is still a decoded code. The flag says whether it was copied. A
/// job of an earlier generation (a scan abandoned since) is never copied,
/// so its code never reaches the caller's buffer.
pub fn take_results(out: &mut [u8]) -> Option<(DecodeOutcome, bool)> {
    if JOB_STATE.load(Ordering::Acquire) != DONE {
        return None;
    }
    // `ptr::replace` is `take` through a pointer, creating no reference.
    //
    // SAFETY: only in `DONE`, which core 1 stores with Release after writing
    // both statics and this side loaded with Acquire: core 1 is finished
    // with them and core 0 is alone.
    let Some(o) = (unsafe { core::ptr::replace(core::ptr::addr_of_mut!(RESULTS), None) }) else {
        // Core 1 never leaves `DONE` without a result; freed anyway, so the
        // slot cannot wedge.
        JOB_STATE.store(IDLE, Ordering::Release);
        return None;
    };
    let mut copied = false;
    let mut len = 0;
    if let Outcome::Found { len: n } = o.outcome {
        len = n.min(MAX_PAYLOAD);
        if out.len() >= len && o.gen == GEN.load(Ordering::Relaxed) {
            // SAFETY: as above: `DONE`, and core 0 is the only side left.
            let payload = unsafe { &*core::ptr::addr_of!(PAYLOAD) };
            out[..len].copy_from_slice(&payload[..len]);
            copied = true;
        }
    }
    wipe_payload(len);
    JOB_STATE.store(IDLE, Ordering::Release);
    Some((o, copied))
}

/// Core 0: end whatever job is pending, and leave the worker `IDLE`.
///
/// A job core 1 has not taken is withdrawn; one it is decoding is waited
/// for, up to `DRAIN_CYCLES`, and its result wiped unread. Once the worker
/// is idle the image is wiped too: core 1 clears only an image it decoded,
/// and a withdrawn job's picture is, for a SeedQR, the seed.
///
/// False only if core 1 kept a job past the bound. That job later finishes
/// into `DONE`; until a decoder with nothing in flight clears it with
/// [`discard_finished`], every submit gets `Busy` and its code stays in
/// `PAYLOAD`. Its generation is the abandoned scan's, so none of it is
/// copied out.
pub fn drain() -> bool {
    let _ = JOB_STATE.compare_exchange(READY, IDLE, Ordering::AcqRel, Ordering::Relaxed);
    let t0 = systick();
    while JOB_STATE.load(Ordering::Acquire) == BUSY {
        if systick().wrapping_sub(t0) >= DRAIN_CYCLES {
            break;
        }
        core::hint::spin_loop();
    }
    let _ = take_results(&mut []);
    let idle = JOB_STATE.load(Ordering::Acquire) == IDLE;
    if idle {
        wipe_image();
    }
    idle
}

/// Clear [`FAST_IMG`]. Core 0, in `IDLE` only: core 1 takes the image only
/// from `READY`, which only core 0 sets, so core 0 is alone with it.
fn wipe_image() {
    // SAFETY: `IDLE`, as above: core 1 is not reading the image.
    let image = unsafe { &mut *core::ptr::addr_of_mut!(FAST_IMG) };
    for b in image.iter_mut() {
        // SAFETY: a valid reference to a byte this core owns now.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Core 0: wipe and drop a finished job no decoder waits for, one [`drain`]
/// gave up on. A decoder with nothing in flight calls it before it submits;
/// it does nothing when no job is finished.
pub fn discard_finished() {
    let _ = take_results(&mut []);
}

/// Whether a submit would be accepted right now.
pub fn is_idle() -> bool {
    JOB_STATE.load(Ordering::Acquire) == IDLE
}

/// Clear the first `len` bytes of [`PAYLOAD`]. Core 0, in `DONE` only.
fn wipe_payload(len: usize) {
    // SAFETY: called from `take_results` in `DONE`, where core 1 is done
    // with the buffer and core 0 is alone.
    let payload = unsafe { &mut *core::ptr::addr_of_mut!(PAYLOAD) };
    for b in payload[..len.min(MAX_PAYLOAD)].iter_mut() {
        // SAFETY: a valid reference to a byte this core owns now.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Clear the image, the payload and the decode's scratch, whatever state
/// the job is in. For a panic, after core 1 is parked
/// (`stack::wipe_and_halt`): a decode cut short leaves a code's picture and
/// bytes behind, a SeedQR's included.
pub fn clear_for_panic() {
    let spans = [
        (core::ptr::addr_of_mut!(FAST_IMG).cast::<u8>(), FAST_LEN),
        (core::ptr::addr_of_mut!(PAYLOAD).cast::<u8>(), MAX_PAYLOAD),
        (
            core::ptr::addr_of_mut!(SCRATCH).cast::<u8>(),
            core::mem::size_of::<kassigner_qr::Scratch>(),
        ),
    ];
    for (at, len) in spans {
        for i in 0..len {
            // SAFETY: inside one of this module's statics, each `len` bytes
            // long. Core 1 is parked and core 0 is halting, so nothing reads
            // or writes them again; all three hold only integers, for which
            // all-zero bytes are a valid value.
            unsafe { core::ptr::write_volatile(at.add(i), 0) };
        }
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// What the panic probe plants and then looks for: on core 1's stack when
/// core 1 panics, and wherever else the probe puts it.
#[cfg(feature = "panic-probe")]
pub const PROBE_MARKER: [u8; 32] = *b"KasSigner panic probe, marker 32";

/// Set by the panic probe: core 1's next job panics instead of decoding,
/// with [`PROBE_MARKER`] on its stack. Nothing that ships has this.
#[cfg(feature = "panic-probe")]
pub static PANIC_NEXT_JOB: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// The image's bounds, for the panic probe to look in once the panic has
/// cleared it.
#[cfg(feature = "panic-probe")]
pub fn probe_image() -> (usize, usize) {
    let at = core::ptr::addr_of!(FAST_IMG) as usize;
    (at, at + FAST_LEN)
}

/// Panic on core 1 with the marker in this frame, as a decode would have a
/// code's bytes in its frames.
#[cfg(feature = "panic-probe")]
#[inline(never)]
fn probe_panic() -> ! {
    let marker = core::hint::black_box(PROBE_MARKER);
    let _ = core::hint::black_box(&marker);
    panic!("panic probe: core 1");
}

/// Core 1 entry: serve jobs forever, waiting in `WAITI` between them. No
/// logging: the UART path is not cross-core safe.
///
/// `stack_bottom` is the lowest address of core 1's stack, which the worker
/// clears after every job, once the job's frame has returned.
pub fn core1_main(stack_bottom: usize) -> ! {
    #[cfg(not(target_arch = "xtensa"))]
    let _ = stack_bottom;
    loop {
        if serve() {
            #[cfg(all(target_arch = "xtensa", feature = "stack-probe"))]
            crate::stack::probe::note_core1(STACK_FLOOR_MARGIN);
            // Both passes are called from this frame, so each stands
            // directly under the loop: the first leaves only its own spot,
            // the second's pad covers it. A wrapper would itself stand on
            // the job's top bytes, out of both passes' reach.
            #[cfg(target_arch = "xtensa")]
            {
                clear_stack_below(stack_bottom);
                clear_under_pad(stack_bottom);
            }
        } else {
            // Nothing to do: sleep until core 0 posts a job, or any other
            // interrupt comes.
            // SAFETY: `WAITI 0` waits with every interrupt level enabled,
            // and changes nothing else.
            #[cfg(target_arch = "xtensa")]
            unsafe {
                core::arch::asm!("waiti 0")
            };
            #[cfg(not(target_arch = "xtensa"))]
            core::hint::spin_loop();
        }
    }
}

/// Take the posted job, if any, and run it to `DONE`; false when there was
/// none. Called by core 1's loop, or on a host by the submit.
///
/// Never inlined, so the decode's frames are below the loop's and gone when
/// this returns, for the loop to clear (the module's "Core 1's stack").
#[inline(never)]
fn serve() -> bool {
    if JOB_STATE
        .compare_exchange(READY, BUSY, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    #[cfg(feature = "panic-probe")]
    if PANIC_NEXT_JOB.load(Ordering::Acquire) {
        probe_panic();
    }

    let w = JOB_W.load(Ordering::Relaxed);
    let h = JOB_H.load(Ordering::Relaxed);
    let denom = JOB_DENOM.load(Ordering::Relaxed);
    let kind = JOB_KIND.load(Ordering::Relaxed);
    let gen = JOB_GEN.load(Ordering::Relaxed);
    // SAFETY: `BUSY` is core 1's state: core 0 touches neither the image
    // nor the payload until `DONE`. `w * h` was bounded at submit.
    let (gray, payload) = unsafe {
        (
            core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(FAST_IMG) as *mut u8, w * h),
            &mut *core::ptr::addr_of_mut!(PAYLOAD),
        )
    };

    // SAFETY: only core 1 references the scratch, here, and the last job's
    // reference is gone. On a host, only the submit that runs the job.
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) };

    let t0 = systick();
    let outcome = match kassigner_qr::Decoder::new(scratch).decode(w, h, denom, gray, payload) {
        Ok(decoded) => Outcome::Found { len: decoded.len },
        Err(DecodeError::NotFound) | Err(DecodeError::BadFrame) => Outcome::NotFound,
        Err(DecodeError::Unreadable) | Err(DecodeError::BufferTooSmall) => Outcome::Unreadable,
    };
    let t1 = systick();

    // The picture the code was read from, gone as soon as it has been read:
    // a picture of a code is the code.
    for b in gray.iter_mut() {
        // SAFETY: core 1 owns the image while the state is `BUSY`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    // SAFETY: still `BUSY`; core 0 reads this only after `DONE` below.
    unsafe {
        core::ptr::addr_of_mut!(RESULTS).write(Some(DecodeOutcome {
            gen,
            kind,
            denom,
            outcome,
            // CCOUNT at CpuClock::max() = 240MHz -> 240_000 cycles/ms.
            decode_ms: t1.wrapping_sub(t0) / 240_000,
            w,
        }));
    }
    JOB_STATE.store(DONE, Ordering::Release);
    true
}

/// Bytes of the second pass's pad ([`clear_under_pad`]): more than the first
/// pass leaves, its own frame and the save area under it.
#[cfg(target_arch = "xtensa")]
const CLEAR_PAD: usize = 512;

/// The second pass of the clear: a pad of zeros where the first pass's
/// frame and the save area it kept stood, then the clear again below it.
/// Left below the loop: zeros and the two passes' own frames.
#[cfg(target_arch = "xtensa")]
#[inline(never)]
fn clear_under_pad(stack_bottom: usize) {
    let pad = [0u8; CLEAR_PAD];
    core::hint::black_box(&pad);
    clear_stack_below(stack_bottom);
}

/// Zero core 1's stack from just above its guard word to just under this
/// function's own frame: everything there was the returned decode's.
///
/// Never inlined, which is load-bearing: its stack pointer is then under
/// every frame still in use. Inlined, it would sit inside the loop's frame,
/// and the clear could zero the loop's own values (a `LoadProhibited` at
/// address 0).
///
/// It keeps the save area under its stack pointer,
/// [`crate::stack::BASE_SAVE`], where an interrupt spills the first four
/// registers of this function's caller: cleared, the return would read
/// them back as zeros. The panic's wipe keeps the same 16 bytes.
#[cfg(target_arch = "xtensa")]
#[inline(never)]
fn clear_stack_below(stack_bottom: usize) {
    let sp = esp_hal::xtensa_lx::get_stack_pointer() as usize;
    let from = stack_bottom
        .saturating_add(STACK_FLOOR_MARGIN)
        .next_multiple_of(4);
    let to = sp.saturating_sub(crate::stack::BASE_SAVE);
    let to = to - to % 4;
    let mut at = from;
    while at < to {
        // SAFETY: `at` is word-aligned, above the floor clear of the guard
        // word, and below the save area under this frame, the lowest live
        // one: core 1's own stack, unused since the decode returned.
        // Nothing else runs on this core but an interrupt, whose frame is
        // gone when it returns.
        unsafe { core::ptr::write_volatile(at as *mut u32, 0) };
        at += 4;
    }
}
