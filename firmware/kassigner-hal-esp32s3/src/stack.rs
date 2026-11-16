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

//! Where the main stack is.
//!
//! `kassigner-fw`'s scrub descends to the deepest point a secret reached,
//! only on the stack it started on: it refuses any note outside the window
//! the caller gives, and the window is this, the main stack as linked.
//!
//! esp-hal's `ld/sections/stack.x` lays the main stack over the rest of
//! `RWDATA` and exports both ends: `_stack_end_cpu0`, the lowest address,
//! right after `.bss`, and `_stack_start_cpu0`, the highest, where the stack
//! pointer starts.
//!
//! A panic clears the same window ([`wipe_and_halt`]), so a halted unit
//! holds no seed on its stack. Core 1's stack, a static the board hands to
//! `start_app_core`, lies below `.bss`'s end, outside the window, which
//! keeps notes out of that region; the board gives its place
//! ([`core1_started`]) so a panic clears it too.
//!
//! Device only: a host build has no such symbols, and its tests measure
//! their own windows from a mark.
//!
//! Its twin is the P4 crate's `stack.rs`: the same bounds, lent buffers,
//! order and kept frame, for the P4's RISC-V cores. What differs is each
//! architecture's: the register windows spilled here are Xtensa's, and the
//! P4 writes its data cache back over the statics and stacks where this
//! writes back only lent buffers in PSRAM. A change to the shared part is
//! made to both.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use esp_hal::system::{Cpu, CpuControl};

extern "C" {
    static _stack_end_cpu0: u32;
    static _stack_start_cpu0: u32;
}

/// The main stack's bounds, lowest address first, `top` exclusive: two
/// linker symbols esp-hal defines for every S3 image, taken as addresses
/// and never dereferenced, so no `unsafe`.
pub fn core0() -> (usize, usize) {
    let bottom = core::ptr::addr_of!(_stack_end_cpu0) as usize;
    let top = core::ptr::addr_of!(_stack_start_cpu0) as usize;
    (bottom, top)
}

/// Core 1's stack, lowest address and top, once the board has started it
/// there; zero until then. Both units start it.
static CORE1_BOTTOM: AtomicUsize = AtomicUsize::new(0);
static CORE1_TOP: AtomicUsize = AtomicUsize::new(0);

/// A panic is already stopping the unit: set by the first core into
/// [`wipe_and_halt`], so a second panicking core only waits to be parked
/// and the two do not park each other.
static HALTING: AtomicBool = AtomicBool::new(false);

/// Where core 1's stack is, `top` exclusive, for a panic to stop that core
/// and clear its stack. Called by the board before it starts core 1 there.
pub fn core1_started(bottom: usize, top: usize) {
    CORE1_BOTTOM.store(bottom, Ordering::Relaxed);
    CORE1_TOP.store(top, Ordering::Release);
}

/// Core 1's stack, if the board started it, lowest address first, `top`
/// exclusive.
pub fn core1() -> Option<(usize, usize)> {
    let top = CORE1_TOP.load(Ordering::Acquire);
    (top != 0).then(|| (CORE1_BOTTOM.load(Ordering::Relaxed), top))
}

// ── Buffers a panic clears too ──────────────────────────────────────────────

/// What a panic zeroes besides the stacks: up to two buffers given to
/// [`clear_on_panic`], by address; zero for a free slot.
static ALSO_AT: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
static ALSO_LEN: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

/// Have a panic zero `buf` too, after the stacks and before the board's
/// `quiesce`, writing the zeros out of the data cache when it is in PSRAM,
/// which keeps its contents through a reset.
///
/// For a buffer lent for the program's life that may hold a secret, such as
/// the frame reassembler's buffer and the payload it builds, which a seed's
/// words pass through mid-scan: their wipe at a scan's end never runs on a
/// panic. Two at most; `false`, and nothing kept, for a third or an empty
/// one.
pub fn clear_on_panic(buf: &mut [u8]) -> bool {
    take(buf)
}

/// A slot for `buf`, if one is free.
fn take(buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    let at = buf.as_mut_ptr().expose_provenance();
    for (slot, len) in ALSO_AT.iter().zip(&ALSO_LEN) {
        if slot
            .compare_exchange(0, at, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            len.store(buf.len(), Ordering::Release);
            return true;
        }
    }
    false
}

/// Zero what [`clear_on_panic`] was given, and push the zeros out of the
/// data cache into PSRAM. Bytes cleared.
fn clear_also() -> usize {
    let mut cleared = 0;
    for (slot, len) in ALSO_AT.iter().zip(&ALSO_LEN) {
        let (at, len) = (slot.load(Ordering::Acquire), len.load(Ordering::Acquire));
        if at == 0 || len == 0 {
            continue;
        }
        let p = core::ptr::with_exposed_provenance_mut::<u8>(at);
        // SAFETY: `len` bytes at `p`, lent to `clear_on_panic` for the
        // program's life. Whoever held it never runs again: interrupts are
        // off, the other core is parked, and `halt_here` does not return.
        unsafe { clear(p, len) };
        if crate::cache::is_external(p) && crate::cache::is_external(p.wrapping_add(len - 1)) {
            // SAFETY: the range is wholly in PSRAM, checked just above.
            unsafe { crate::cache::write_back(p, len) };
        }
        cleared += len;
    }
    cleared
}

// ── For the probes ──────────────────────────────────────────────────────────

/// Each place `needle` is written in `from..to`, handed to `each`, and how
/// many, so the probes need no `unsafe` to look for what a scrub or a panic
/// left. `None`, and nothing read, unless the range is inside [`core0`] or
/// [`core1`].
pub fn find(from: usize, to: usize, needle: &[u8], each: impl FnMut(usize)) -> Option<u32> {
    let inside = |(bottom, top): (usize, usize)| bottom <= from && from <= to && to <= top;
    (inside(core0()) || core1().is_some_and(inside)).then(|| scan(from, to, needle, each))
}

/// [`find`] in the decode worker's image, for the panic probe.
#[cfg(feature = "panic-probe")]
pub fn find_in_image(needle: &[u8], each: impl FnMut(usize)) -> u32 {
    let (from, to) = crate::decode_core::probe_image();
    scan(from, to, needle, each)
}

/// [`find`] in the buffers [`clear_on_panic`] was given, for the panic
/// probe.
#[cfg(feature = "panic-probe")]
pub fn find_in_cleared(needle: &[u8], mut each: impl FnMut(usize)) -> u32 {
    let mut found = 0;
    for (slot, len) in ALSO_AT.iter().zip(&ALSO_LEN) {
        let (at, len) = (slot.load(Ordering::Acquire), len.load(Ordering::Acquire));
        if at != 0 {
            found += scan(at, at + len, needle, &mut each);
        }
    }
    found
}

/// Bytes not zero in `from..to`, for the panic probe's look at the buffers
/// a board's `quiesce` clears: its own statics and allocations, which it
/// names, mapped while the unit runs.
#[cfg(feature = "panic-probe")]
pub(crate) fn set_in(from: usize, to: usize) -> usize {
    (from..to)
        .filter(|&at| {
            // SAFETY: inside one of the board's own buffers, as the board's
            // probe hook names them; volatile byte reads, never a write.
            unsafe { core::ptr::read_volatile(at as *const u8) != 0 }
        })
        .count()
}

/// [`find`] in memory the caller holds, initialised or not: a vector's spare
/// capacity, for the seed probe's look at heap the decoder just freed.
pub fn find_in(
    region: &[core::mem::MaybeUninit<u8>],
    needle: &[u8],
    each: impl FnMut(usize),
) -> u32 {
    let from = region.as_ptr() as usize;
    scan(from, from + region.len(), needle, each)
}

/// Every start of `needle` in `from..to`.
fn scan(from: usize, to: usize, needle: &[u8], mut each: impl FnMut(usize)) -> u32 {
    if needle.is_empty() {
        return 0;
    }
    let mut found = 0;
    let mut at = from;
    while at + needle.len() <= to {
        // SAFETY: inside a range the four callers above checked or were
        // lent (a stack of this unit, the decode image, a buffer lent to
        // `clear_on_panic`, the caller's own allocation), all mapped while
        // the unit runs. Volatile byte reads, never a write: the memory's
        // bytes, initialised or not, which is what a probe asks about.
        let same = needle
            .iter()
            .enumerate()
            .all(|(k, &b)| unsafe { core::ptr::read_volatile((at + k) as *const u8) } == b);
        if same {
            each(at);
            found += 1;
        }
        at += 1;
    }
    found
}

/// The base save area: the 16 bytes under a frame's stack pointer, where a
/// spilled caller's first four registers go.
///
/// The one under [`halt_here`]'s stack pointer survives the wipe: it holds
/// [`padded`]'s stack pointer, which the window handlers read to find the
/// save area whenever `halt_here`'s registers spill or are restored, as
/// `quiesce` and `report` cause. Zeroed, the handler stores through address
/// 0, a double exception follows, and the second panic spins with the screen
/// lit. [`crate::decode_core`] keeps it under core 1's clearing frame too.
pub(crate) const BASE_SAVE: usize = 16;

/// Zeros between the frames the wipe clears and [`padded`]'s. They start
/// where [`halt_here`]'s frame ends, so the wipe keeps exactly that frame,
/// from [`BASE_SAVE`] under its stack pointer up to the padding, and clears
/// the padding and above.
const PAD: usize = 512;

/// Stop the unit and clear both cores' stacks, for the panic handler on
/// whichever core panicked.
///
/// # What is cleared
///
/// Each stack from `floor_margin` above its end to its top (core 1's when
/// the board started it), but for the clearing frame, [`halt_here`]'s, from
/// [`BASE_SAVE`] under its stack pointer up to [`padded`]'s zeros. Below
/// that frame is what the panic left (derivation intermediates, a decoded
/// code, a hash state); above it, every caller, `main`'s frame with the seed
/// slots and keys among them. The parked core's stack is cleared whole.
/// None of these frames runs again: nothing returns from here.
///
/// Then the board's `quiesce`: what it holds outside the stacks that a
/// panic must not leave, the decoder's buffers, and the backlight off so
/// the last screen, perhaps a SeedQR, does not stay lit.
///
/// `floor_margin` is the scrub's, so the guard word esp-hal watches at a
/// stack's end is never written and the wipe cannot look like an overflow.
///
/// # What is not
///
/// The heap (PSRAM, which should hold no secret) but for the buffers lent
/// to [`clear_on_panic`]; statics but for those `quiesce` clears.
///
/// # Order
///
/// Interrupts off, so no handler pushes a frame or spills into cleared
/// memory. The other core parked, so nothing runs on a stack being cleared
/// or holds a seed meanwhile. The wipe and the lent buffers, then
/// `quiesce`, after them because the M5's backlight is an I2C write that
/// could hang. Then `report` with the stack bytes cleared, and a spin. All
/// of it runs below this frame, in memory already cleared.
///
/// # The register windows
///
/// A caller's registers stay in the register file until a deep enough call
/// spills them to its save area on the stack. Spilled after the wipe, a
/// caller would write into cleared memory, and read its own caller's stack
/// pointer from it to find where. So every caller is spilled first, from
/// the clearing frame, by nested calls deeper than the file; the clearing
/// frame's window is then the only one left, and its spills read only
/// [`BASE_SAVE`], which is kept. The parked core's windows stay in its own
/// register file, which nothing reads.
#[inline(never)]
pub fn wipe_and_halt(floor_margin: usize, quiesce: fn(), report: fn(usize)) -> ! {
    let _ = esp_hal::xtensa_lx::interrupt::disable();
    // The other core got here first: it parks this one.
    if HALTING.swap(true, Ordering::AcqRel) {
        loop {
            core::hint::spin_loop();
        }
    }
    park_other();
    padded(floor_margin, quiesce, report)
}

/// [`PAD`] bytes of zeros on the stack, then [`halt_here`] below them. The
/// padding is passed in: its start is the top of what the wipe keeps, and
/// the call cannot become a jump that drops this frame first.
#[inline(never)]
fn padded(floor_margin: usize, quiesce: fn(), report: fn(usize)) -> ! {
    let pad = [0u8; PAD];
    halt_here(core::hint::black_box(&pad), floor_margin, quiesce, report)
}

/// Stall the core this is not running on, if the board started core 1.
fn park_other() {
    if core1().is_none() {
        return;
    }
    let other = match Cpu::current() {
        Cpu::ProCpu => Cpu::AppCpu,
        Cpu::AppCpu => Cpu::ProCpu,
    };
    // SAFETY: the unit is halting. The board's `CpuControl` started core 1
    // and was forgotten; this one only writes the stall code, and the
    // stalled core never runs again.
    unsafe { CpuControl::new(esp_hal::peripherals::CPU_CTRL::steal()).park_core(other) };
}

/// Nested calls that push every caller's registers out of the file. The
/// core has 64 address registers and a call rotates the window by 4, 8 or
/// 12 of them, so sixteen nested calls are enough even at the smallest.
const SPILL_DEPTH: u32 = 16;

/// Call itself `depth` times, using its frame after each call so the
/// recursion is not turned into a loop.
#[inline(never)]
fn spill(depth: u32) -> u32 {
    let frame = [depth, 1];
    let d = core::hint::black_box(&frame)[0];
    if d == 0 {
        return 0;
    }
    spill(d - 1).wrapping_add(core::hint::black_box(&frame)[1])
}

/// Spill every caller, zero both stacks but this frame, run `quiesce`,
/// report, and stop.
///
/// Never inlined: its frame is the lowest live one, so below its stack
/// pointer only [`BASE_SAVE`] is in use, and every frame above, the
/// caller's included, is dead as this does not return. Inlined, its frame
/// would be the caller's, and the clear could zero the caller's values.
#[inline(never)]
fn halt_here(pad: &[u8; PAD], floor_margin: usize, quiesce: fn(), report: fn(usize)) -> ! {
    // Every caller out of the register file, this frame's own caller
    // included, before anything is cleared.
    let _ = core::hint::black_box(spill(SPILL_DEPTH));
    // What is kept: this frame, from the save area under its stack pointer
    // up to the padding, which starts in the caller's frame.
    let sp = esp_hal::xtensa_lx::get_stack_pointer() as usize;
    let keep_from = sp.saturating_sub(BASE_SAVE);
    let keep_to = core::hint::black_box(pad).as_ptr() as usize;
    // The stack this frame is on, but for the frame; the parked core's,
    // whole.
    let clear = |(bottom, top): (usize, usize)| {
        let floor = bottom.saturating_add(floor_margin);
        if sp < bottom || sp >= top {
            zero(floor, top)
        } else {
            zero(floor, keep_from) + zero(keep_to, top)
        }
    };
    let cleared = clear(core0()) + core1().map_or(0, clear);
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    // The buffers lent to `clear_on_panic`, before `quiesce`, which on the
    // M5 is an I2C write that could hang.
    let _ = clear_also();
    quiesce();
    report(cleared);
    loop {
        core::hint::spin_loop();
    }
}

/// Zero the whole words between two addresses. Bytes cleared.
#[inline(always)]
fn zero(from: usize, to: usize) -> usize {
    let from = from.next_multiple_of(4);
    let to = to - to % 4;
    let mut at = from;
    while at < to {
        // SAFETY: word-aligned, in a core's stack above the floor that keeps
        // clear of the guard word and below the stack's top, outside
        // `halt_here`'s span, in frames that never run again (`halt_here`
        // does not return, interrupts are off, the other core is parked).
        // Volatile, so no write is dropped.
        unsafe { core::ptr::write_volatile(at as *mut u32, 0) };
        at += 4;
    }
    to.saturating_sub(from)
}

/// Zero `len` bytes from `at`, each write volatile so none is dropped: for
/// the statics a board's `quiesce` clears.
///
/// # Safety
///
/// `at..at + len` must be memory the caller may write, and nothing may read
/// it again expecting what was there: the unit is halting.
pub unsafe fn clear(at: *mut u8, len: usize) {
    for i in 0..len {
        // SAFETY: inside the span the caller vouched for.
        unsafe { core::ptr::write_volatile(at.add(i), 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

// ── At boot ─────────────────────────────────────────────────────────────────

/// Bytes kept below the clearing frame at boot, a kilobyte as in the stack
/// probe: room for what an interrupt pushes while the clear runs.
const BOOT_KEEP_BELOW: usize = 1024;

/// Bytes of zeros laid down after the clear over its frame and what it kept
/// below: more than both.
const BOOT_COVER: usize = 2048;
const _: () = assert!(BOOT_COVER > BOOT_KEEP_BELOW + 512);

/// Zero the main stack below the caller at boot, before anything else runs
/// on it. Bytes cleared.
///
/// A reset that is not a power cut keeps internal RAM: start-up rewrites
/// the statics, but the stack keeps the last run's bytes, a seed among them
/// if a watchdog, a panic or a reset button ended a run that held one.
/// `main` calls this first, from a small frame with everything below it
/// free: that is cleared from `floor_margin` above the stack's end, then a
/// call at the same depth zeroes the span the clear ran in, so the
/// program's next frame starts on zeros. Inlined, so both calls are the
/// caller's and no frame comes between.
#[inline(always)]
pub fn clear_at_boot(floor_margin: usize) -> usize {
    let cleared = boot_below(floor_margin);
    boot_cover();
    cleared
}

/// Zero the main stack from `floor_margin` above its end to
/// [`BOOT_KEEP_BELOW`] under this frame.
#[inline(never)]
fn boot_below(floor_margin: usize) -> usize {
    let local = [0u8; 4];
    let here = core::hint::black_box(&local).as_ptr() as usize;
    let (bottom, _) = core0();
    let from = bottom.saturating_add(floor_margin).next_multiple_of(4);
    let to = here.saturating_sub(BOOT_KEEP_BELOW) & !3;
    let mut at = from;
    while at < to {
        // SAFETY: word-aligned, above the floor that keeps clear of the
        // guard word, and a kilobyte below this frame, the lowest live one:
        // nothing has used the stack below it since the reset.
        unsafe { core::ptr::write_volatile(at as *mut u32, 0) };
        at += 4;
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    to.saturating_sub(from)
}

/// [`BOOT_COVER`] bytes of zeros at the depth [`boot_below`] ran at, over
/// its frame and the span it kept below it.
#[inline(never)]
fn boot_cover() {
    let pad = [0u8; BOOT_COVER];
    let _ = core::hint::black_box(&pad);
}

/// How deep the stacks go, for sizing them, as core 1's stack comes out of
/// the main stack's RAM. Probe builds only.
///
/// The main stack's free part is painted with [`probe::PATTERN`] at boot
/// and read back for the lowest word overwritten; the scrubs, which would
/// zero it, are off in these builds (`kassigner-fw`'s `stack-probe`). Core
/// 1's stack is zero from boot and after every job's clear, so its lowest
/// non-zero word, read just before the clear, is that job's depth.
#[cfg(feature = "stack-probe")]
pub mod probe {
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// What the free main stack holds until something uses it.
    pub const PATTERN: u32 = 0x5AA5_C33C;

    /// Bytes of core 1's stack the deepest job used, from its top.
    static CORE1_USED: AtomicUsize = AtomicUsize::new(0);

    /// Paint the main stack from `floor_margin` above its end to a kilobyte
    /// below this frame. First thing in the signer's `run`, after `main`'s
    /// `clear_at_boot`.
    #[inline(never)]
    pub fn paint(floor_margin: usize) {
        let local = [0u8; 4];
        let here = core::hint::black_box(&local).as_ptr() as usize;
        let (bottom, _) = super::core0();
        let mut at = bottom.saturating_add(floor_margin).next_multiple_of(4);
        let to = here.saturating_sub(1024);
        while at + 4 <= to {
            // SAFETY: word-aligned, above the guard word's margin and a
            // kilobyte below this frame, the lowest live one: free stack.
            unsafe { core::ptr::write_volatile(at as *mut u32, PATTERN) };
            at += 4;
        }
    }

    /// Bytes of the main stack used at the deepest, from its top, and its
    /// size above the floor margin.
    pub fn main_used(floor_margin: usize) -> (usize, usize) {
        let (bottom, top) = super::core0();
        let mut at = bottom.saturating_add(floor_margin).next_multiple_of(4);
        // SAFETY: reads of the main stack, inside its bounds.
        while at + 4 <= top && unsafe { core::ptr::read_volatile(at as *const u32) } == PATTERN {
            at += 4;
        }
        (
            top.saturating_sub(at),
            top.saturating_sub(bottom + floor_margin),
        )
    }

    /// For core 1's worker, before it clears its stack after a job: note
    /// how deep the job wrote.
    pub fn note_core1(floor_margin: usize) {
        let Some((bottom, top)) = super::core1() else {
            return;
        };
        let mut at = bottom.saturating_add(floor_margin).next_multiple_of(4);
        // SAFETY: reads of core 1's own stack, inside its bounds, on core 1.
        while at + 4 <= top && unsafe { core::ptr::read_volatile(at as *const u32) } == 0 {
            at += 4;
        }
        CORE1_USED.fetch_max(top.saturating_sub(at), Ordering::Relaxed);
    }

    /// Core 1's deepest job, and its stack's size above the floor margin;
    /// `None` when core 1 is not started.
    pub fn core1_used(floor_margin: usize) -> Option<(usize, usize)> {
        let (bottom, top) = super::core1()?;
        Some((
            CORE1_USED.load(Ordering::Relaxed),
            top.saturating_sub(bottom + floor_margin),
        ))
    }
}
