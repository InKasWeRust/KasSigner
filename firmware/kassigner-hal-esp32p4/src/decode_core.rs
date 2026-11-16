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

//! The decoder's worker on core 1, shaped as the S3 crate's.
//!
//! Core 0 captures and draws; core 1 decodes. One job links them: core 0
//! copies the green plane into the worker's buffer and marks it `READY`;
//! core 1 takes it to `BUSY`, decodes, leaves the result and marks `DONE`;
//! core 0 reads the result and marks `IDLE`. Acquire/release on that one
//! atomic orders every handoff, so the plain statics behind it (buffer,
//! result) never race: each side touches them only in the states it owns.
//!
//! The plane buffer, a static of 57,600 bytes in the square mode, is the
//! price of decoding beside the capture rather than in the frame buffer
//! between captures. The worker's 24 KB stack is a static too (the
//! Waveshare S3's is 48 KB; `rqrr`'s frames are smaller on the P4), with
//! the stack guard to say if it is short. The decode works in `SCRATCH`,
//! its bit stream and corrected bytes, which every decode leaves wiped.
//!
//! A cancel drains the job and wipes the plane ([`cancel`]); after every job
//! core 1 zeroes its own stack below the loop ([`core1_main`]).
//!
//! Its twin is the S3 crate's `decode_core.rs`: the same four states and
//! handoff, generations, scratch, cancel by draining, and stack clear after
//! every job. What differs is each chip's: the job (here a green plane and
//! an attempt, there a frame's size and a fast or escalated pass) and the
//! wait (core 1 here polls, there it sleeps until core 0 wakes it). A
//! change to the shared part is made to both.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use esp_hal::time::{Duration, Instant};
use kassigner_hal::decoder::Attempt;
use kassigner_qr::DecodeError;

use crate::decoder::{IMAGE_BYTES, MAX_PAYLOAD, PLANE_H, PLANE_W};

/// No job.
pub const IDLE: u8 = 0;
/// A plane is in the buffer, waiting for core 1.
pub const READY: u8 = 1;
/// Core 1 is decoding it.
pub const BUSY: u8 = 2;
/// A result is waiting for core 0.
pub const DONE: u8 = 3;

/// The job's state.
pub static STATE: AtomicU8 = AtomicU8::new(IDLE);
static DENOM: AtomicUsize = AtomicUsize::new(4);

/// The scan the worker serves: [`cancel`] moves it on, and a job carries
/// the one it was submitted under, so a result of an abandoned scan is
/// recognised.
static GEN: AtomicU8 = AtomicU8::new(0);
static JOB_GEN: AtomicU8 = AtomicU8::new(0);

/// What the worker found: no code in the plane.
pub const NOT_FOUND: u8 = 0;
/// A code, that would not decode.
pub const UNREADABLE: u8 = 1;
/// A code, decoded; `RESULT_LEN` is the payload's length.
pub const FOUND: u8 = 2;
static RESULT_KIND: AtomicU8 = AtomicU8::new(NOT_FOUND);
static RESULT_LEN: AtomicUsize = AtomicUsize::new(0);

static mut IMAGE: [u8; IMAGE_BYTES] = [0; IMAGE_BYTES];
static mut PAYLOAD: [u8; MAX_PAYLOAD] = [0; MAX_PAYLOAD];
/// Where the decode works. Core 1's alone: nothing else ever references it.
static mut SCRATCH: kassigner_qr::Scratch = kassigner_qr::Scratch::new();

/// The detector's downscale denominator: 240 wide at 4 is a 60-pixel
/// search image for the fast pass, 2 the thorough one.
const DENOM_FAST: usize = 4;
const DENOM_THOROUGH: usize = 2;

/// Set while [`fill_image`] lends the plane, so a nested fill is refused,
/// not handed a second reference.
static FILLING: AtomicBool = AtomicBool::new(false);

/// Core 0: fill the first `len` bytes of the plane buffer with `fill`,
/// before [`submit`]. False, and `fill` not called, unless the job is
/// `IDLE`, nothing else is filling, and `len` is at most [`IMAGE_BYTES`].
/// The plane is lent for the call, never returned: a safe function must not
/// hand out a `&'static mut` valid only while the job is idle.
pub fn fill_image(len: usize, fill: impl FnOnce(&mut [u8])) -> bool {
    if len > IMAGE_BYTES || FILLING.swap(true, Ordering::Acquire) {
        return false;
    }
    let lent = STATE.load(Ordering::Acquire) == IDLE;
    if lent {
        // SAFETY: `IDLE`: core 1 takes the plane only from `READY`, which only
        // `submit` sets, on this core and not during this call. `FILLING`
        // keeps a second fill from lending it again while `fill` has it, and
        // the borrow ends with the call.
        let image = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(IMAGE).cast::<u8>(), len)
        };
        fill(image);
    }
    FILLING.store(false, Ordering::Release);
    lent
}

/// The plane's bounds, for the panic probe to check after the panic.
#[cfg(feature = "panic-probe")]
pub fn probe_image() -> (usize, usize) {
    let at = core::ptr::addr_of!(IMAGE) as usize;
    (at, at + IMAGE_BYTES)
}

/// Core 0: hand the filled buffer to the worker. `false` if the job is
/// not idle.
///
/// The slot is looked at first, as the S3's worker does: a job still running
/// keeps the window and the generation it was posted with, so a result of a
/// scan [`cancel`] has abandoned cannot pass for this one's. Only core 0
/// moves the slot out of `IDLE`, so nothing overtakes the look.
pub fn submit(attempt: Attempt) -> bool {
    if STATE.load(Ordering::Acquire) != IDLE {
        return false;
    }
    let denom = match attempt {
        Attempt::Fast => DENOM_FAST,
        Attempt::Thorough => DENOM_THOROUGH,
    };
    DENOM.store(denom, Ordering::Relaxed);
    JOB_GEN.store(GEN.load(Ordering::Relaxed), Ordering::Relaxed);
    STATE
        .compare_exchange(IDLE, READY, Ordering::Release, Ordering::Relaxed)
        .is_ok()
}

/// Core 0: take a finished result: the kind, the payload's length, and
/// whether it was copied into `out` (a found code longer than `out` is
/// wiped uncopied). `None` until a result waits. A result of a scan
/// [`cancel`] has since abandoned is wiped, dropped and `None` too: it would
/// otherwise come out as the next scan's first result, a code the user has
/// put away, perhaps a SeedQR.
pub fn take(out: &mut [u8]) -> Option<(u8, usize, bool)> {
    if STATE.load(Ordering::Acquire) != DONE {
        return None;
    }
    let kind = RESULT_KIND.load(Ordering::Relaxed);
    let len = RESULT_LEN.load(Ordering::Relaxed);
    let current = JOB_GEN.load(Ordering::Relaxed) == GEN.load(Ordering::Relaxed);
    let copied = current && kind == FOUND && out.len() >= len;
    if copied {
        // SAFETY: core 1 wrote this in `BUSY` and left it at `DONE`; core 0
        // is the only reader in `DONE`.
        let payload = unsafe { &mut *core::ptr::addr_of_mut!(PAYLOAD) };
        out[..len].copy_from_slice(&payload[..len]);
    }
    // Copied or refused, it is a decoded code, perhaps a SeedQR: cleared on
    // the way out.
    wipe(len);
    STATE.store(IDLE, Ordering::Release);
    current.then_some((kind, len, copied))
}

/// Clear the first `len` bytes of the shared payload, volatile so no write
/// is dropped as dead. Core 0 only, in `DONE`, when core 1 is done with it.
fn wipe(len: usize) {
    // SAFETY: as `take`: `DONE` means core 1 is done and core 0 is alone.
    let payload = unsafe { &mut *core::ptr::addr_of_mut!(PAYLOAD) };
    let n = len.min(payload.len());
    for b in payload[..n].iter_mut() {
        // SAFETY: a valid reference to a byte this thread owns.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// How long [`cancel`] waits for a job core 1 is decoding: a decode is well
/// under a second here, so a job still running after one means core 1 has
/// stopped.
const DRAIN: Duration = Duration::from_millis(1_000);

/// Clear the plane buffer. Core 0 only, in `IDLE`: core 1 takes the plane
/// only from `READY`, which only core 0 sets.
fn wipe_image() {
    // SAFETY: `IDLE`, as above: core 1 is not reading the plane.
    let image = unsafe { &mut *core::ptr::addr_of_mut!(IMAGE) };
    for b in image.iter_mut() {
        // SAFETY: a valid reference to a byte this thread owns.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Core 0: end whatever is pending and leave the worker idle.
///
/// A job core 1 has not taken is withdrawn; one it is decoding is waited
/// for, up to `DRAIN`, and its result wiped unread. Once idle, the plane is
/// wiped: core 1 clears a plane it decoded, but the plane of a job withdrawn
/// before core 1 took it still holds its picture, for a SeedQR the seed.
/// False only if core 1 kept a job past the bound; the next [`take`] then
/// wipes and drops it, its scan being over.
pub fn cancel() -> bool {
    GEN.fetch_add(1, Ordering::Relaxed);
    let _ = STATE.compare_exchange(READY, IDLE, Ordering::AcqRel, Ordering::Relaxed);
    let started = Instant::now();
    while STATE.load(Ordering::Acquire) == BUSY && started.elapsed() < DRAIN {
        core::hint::spin_loop();
    }
    // A finished result is dropped with its bytes wiped: the camera goes off
    // right when a SeedQR may have been read, and the loop reads touch
    // before polling the decoder, so a tap in the pass where a decode
    // finished lands here, not at `take`. Wiped while still `DONE`, when
    // core 0 owns the buffer, and only then freed.
    if STATE.load(Ordering::Acquire) == DONE {
        wipe(RESULT_LEN.load(Ordering::Relaxed));
        STATE.store(IDLE, Ordering::Release);
    }
    let idle = STATE.load(Ordering::Acquire) == IDLE;
    if idle {
        wipe_image();
    }
    idle
}

/// Bytes of core 1's stack left alone at its bottom, clear of the guard
/// word esp-hal places there. The S3 worker's margin.
const STACK_FLOOR_MARGIN: usize = 256;

/// Clear the plane, the payload and the scratch, whatever state the job is
/// in: for a panic, which parks core 1 first (`stack::wipe_and_halt`). A
/// decode cut short leaves a code's picture in the plane and its bytes in
/// the other two, a SeedQR's included.
pub fn clear_for_panic() {
    let spans = [
        (core::ptr::addr_of_mut!(IMAGE).cast::<u8>(), IMAGE_BYTES),
        (core::ptr::addr_of_mut!(PAYLOAD).cast::<u8>(), MAX_PAYLOAD),
        (
            core::ptr::addr_of_mut!(SCRATCH).cast::<u8>(),
            core::mem::size_of::<kassigner_qr::Scratch>(),
        ),
    ];
    for (at, len) in spans {
        for i in 0..len {
            // SAFETY: inside one of this module's statics, each `len` bytes
            // long. Core 1 is parked and core 0 is halting, so nothing
            // touches them again; all are integer arrays (the scratch's of
            // bytes and `usize`), for which zero bytes are valid.
            unsafe { core::ptr::write_volatile(at.add(i), 0) };
        }
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// What the panic probe plants and looks for, on core 1's stack and
/// wherever else it puts it.
#[cfg(feature = "panic-probe")]
pub const PROBE_MARKER: [u8; 32] = *b"KasSigner panic probe, marker 32";

/// Set by the panic probe: core 1's next job panics instead of decoding,
/// with [`PROBE_MARKER`] on its stack. Nothing that ships has this.
#[cfg(feature = "panic-probe")]
pub static PANIC_NEXT_JOB: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Panic on core 1 with the marker in this frame, as a decode would have a
/// code's bytes in its frames.
#[cfg(feature = "panic-probe")]
#[inline(never)]
fn probe_panic() -> ! {
    let marker = core::hint::black_box(PROBE_MARKER);
    let _ = core::hint::black_box(&marker);
    panic!("panic probe: core 1");
}

/// Core 1's whole life. Once each job has returned, core 1 clears its stack
/// below this loop (`stack_bottom` is the lowest address): a code's bytes
/// pass through the decode's frames.
///
/// The job runs in `serve`, never inlined, below this loop's frame: inlined,
/// the decode's frames would be part of the loop's, which the clear never
/// reaches. The clear runs in two passes from this frame, each directly
/// under it: the first leaves only the spot its own frame stands on, the
/// second lays a pad over that spot and clears below it again.
pub fn core1_main(stack_bottom: usize) -> ! {
    loop {
        if serve() {
            clear_stack_below(stack_bottom);
            clear_under_pad(stack_bottom);
        } else {
            core::hint::spin_loop();
        }
    }
}

/// Take the posted job, if any, and run it to `DONE`; false when there was
/// none. Never inlined, so the decode's frames, this one the largest, are
/// below the loop's and gone when it returns, for the loop to clear.
#[inline(never)]
fn serve() -> bool {
    if STATE
        .compare_exchange(READY, BUSY, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    #[cfg(feature = "panic-probe")]
    if PANIC_NEXT_JOB.load(Ordering::Acquire) {
        probe_panic();
    }
    let denom = DENOM.load(Ordering::Relaxed);
    // SAFETY: `BUSY` is core 1's state; core 0 touches neither static until
    // `DONE`.
    let (image, payload) = unsafe {
        (
            &mut *core::ptr::addr_of_mut!(IMAGE),
            &mut *core::ptr::addr_of_mut!(PAYLOAD),
        )
    };
    // SAFETY: only core 1 references the scratch, here, and the last job's
    // reference is gone.
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) };
    let (kind, len) =
        match kassigner_qr::Decoder::new(scratch).decode(PLANE_W, PLANE_H, denom, image, payload) {
            Ok(decoded) => (FOUND, decoded.len),
            Err(DecodeError::NotFound) | Err(DecodeError::BadFrame) => (NOT_FOUND, 0),
            Err(DecodeError::Unreadable) | Err(DecodeError::BufferTooSmall) => (UNREADABLE, 0),
        };
    // The plane, cleared as the payload is: a SeedQR's image decodes back to
    // the seed. The loop clears the decode's stack frames once this returns.
    for b in image.iter_mut() {
        // SAFETY: core 1 owns the image while the state is `BUSY`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    RESULT_KIND.store(kind, Ordering::Relaxed);
    RESULT_LEN.store(len, Ordering::Relaxed);
    STATE.store(DONE, Ordering::Release);
    true
}

/// Bytes [`clear_under_pad`]'s pad covers: more than the first pass's frame.
const CLEAR_PAD: usize = 512;

/// The second pass of the clear after a job: the pad over where the first
/// pass's frame stood, then the clear again below it, leaving below the
/// loop only zeros and the two passes' own frames.
#[inline(never)]
fn clear_under_pad(stack_bottom: usize) {
    let pad = [0u8; CLEAR_PAD];
    core::hint::black_box(&pad);
    clear_stack_below(stack_bottom);
}

/// Zero core 1's stack from just above its guard word to this function's
/// stack pointer ([`crate::stack::stack_pointer`]): everything there
/// belonged to the decode, which has returned. A copy of the S3 crate's
/// `clear_stack_below`, as the two board crates share nothing that can hold
/// `unsafe`.
///
/// Never inlined: its frame is below the loop's, so its stack pointer is
/// under every frame still in use; inlined, the clear could zero the loop's
/// own values.
#[inline(never)]
fn clear_stack_below(stack_bottom: usize) {
    let sp = crate::stack::stack_pointer();
    let from = stack_bottom
        .saturating_add(STACK_FLOOR_MARGIN)
        .next_multiple_of(4);
    let to = sp - sp % 4;
    let mut at = from;
    while at < to {
        // SAFETY: word-aligned, above the floor that keeps clear of the
        // guard word, and below the stack pointer of this frame, the lowest
        // live one: core 1's own stack, unused, as the decode has returned
        // and nothing else runs on this core but an interrupt, whose frame
        // is gone when it returns.
        unsafe { core::ptr::write_volatile(at as *mut u32, 0) };
        at += 4;
    }
}
