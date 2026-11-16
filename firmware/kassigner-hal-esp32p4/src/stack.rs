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

//! Where the main stack is, from the linker, for `kassigner-fw`'s scrub and
//! for the panic's wipe ([`wipe_and_halt`]), which clears core 1's stack
//! too once the unit names it ([`core1_started`]).
//!
//! esp-hal's `ld/sections/stack.x` exports both ends for the P4 too; the
//! fork's ECO2 RAM ceiling, `0x4FFA0000`, keeps the top in backed memory.
//!
//! Its twin is the S3 crate's `stack.rs`: the same bounds, lent buffers,
//! order and kept frame, for the S3's Xtensa cores. What differs is each
//! architecture's: RISC-V has no register windows to spill first, and the
//! data cache is written back here over the statics and stacks where the
//! S3 writes back only lent buffers in PSRAM. A change to the shared part
//! is made to both.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use esp_hal::system::{Cpu, CpuControl};

extern "C" {
    static _stack_end_cpu0: u32;
    static _stack_start_cpu0: u32;
    static _data_start: u32;
}

/// The main stack's bounds, lowest address first, `top` exclusive.
pub fn core0() -> (usize, usize) {
    let bottom = core::ptr::addr_of!(_stack_end_cpu0) as usize;
    let top = core::ptr::addr_of!(_stack_start_cpu0) as usize;
    (bottom, top)
}

/// What a panic's zeros must reach, `top` exclusive: every static, core 1's
/// stack among them, and the main stack, last in RAM.
fn statics_and_stack() -> (usize, usize) {
    let bottom = core::ptr::addr_of!(_data_start) as usize;
    (bottom, core0().1)
}

/// Core 1's stack bounds once the unit has started it; zero before.
static CORE1_BOTTOM: AtomicUsize = AtomicUsize::new(0);
static CORE1_TOP: AtomicUsize = AtomicUsize::new(0);

/// Set by the first core into [`wipe_and_halt`]: a second core that panics
/// too only waits to be parked, so the two do not park each other.
static HALTING: AtomicBool = AtomicBool::new(false);

/// Where core 1's stack is, `top` exclusive, for a panic to stop that core
/// and clear it. The unit calls this before starting core 1.
pub fn core1_started(bottom: usize, top: usize) {
    CORE1_BOTTOM.store(bottom, Ordering::Relaxed);
    CORE1_TOP.store(top, Ordering::Release);
}

/// Core 1's stack, if the unit started it, lowest address first, `top`
/// exclusive.
pub fn core1() -> Option<(usize, usize)> {
    let top = CORE1_TOP.load(Ordering::Acquire);
    (top != 0).then(|| (CORE1_BOTTOM.load(Ordering::Relaxed), top))
}

// ── Buffers a panic clears too ──────────────────────────────────────────────

/// Up to two buffers a panic zeroes besides the stacks, as
/// [`clear_on_panic`] was given them; zero marks a free slot.
static ALSO_AT: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
static ALSO_LEN: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

/// Have a panic zero `buf` too, after the stacks and before `quiesce`: for
/// a buffer lent for the program's life that may hold a secret, such as the
/// frame reassembler's buffer and payload, which a seed's words pass
/// through mid-scan; their end-of-scan wipe never runs on a panic. Two at
/// most; `false`, and nothing kept, for a third, an empty one, or one in
/// PSRAM's cached window, whose zeros could stay in the cache
/// ([`crate::psram::buffer`]'s are uncached).
pub fn clear_on_panic(buf: &mut [u8]) -> bool {
    if crate::psram::CACHED.contains(&(buf.as_ptr() as usize)) {
        return false;
    }
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

/// Zero what [`clear_on_panic`] was given. Bytes cleared.
fn clear_also() -> usize {
    let mut cleared = 0;
    for (slot, len) in ALSO_AT.iter().zip(&ALSO_LEN) {
        let (at, len) = (slot.load(Ordering::Acquire), len.load(Ordering::Acquire));
        if at == 0 || len == 0 {
            continue;
        }
        let p = core::ptr::with_exposed_provenance_mut::<u8>(at);
        // SAFETY: `len` bytes at `p`, lent to `clear_on_panic` for the
        // program's life and outside PSRAM's cached window, so the zeros
        // reach memory, at once or by the write-back after the wipe.
        // Whoever held it never runs again: interrupts are off, the other
        // core is parked, and `halt_here` does not return.
        unsafe { clear(p, len) };
        cleared += len;
    }
    cleared
}

// ── For the probes ──────────────────────────────────────────────────────────

/// Each place `needle` is in `from..to`, handed to `each`, and how many, so
/// the probes need no `unsafe` to look for what a scrub or a panic left.
/// `None`, and nothing read, unless the range is inside [`core0`] or
/// [`core1`].
pub fn find(from: usize, to: usize, needle: &[u8], each: impl FnMut(usize)) -> Option<u32> {
    let inside = |(bottom, top): (usize, usize)| bottom <= from && from <= to && to <= top;
    (inside(core0()) || core1().is_some_and(inside)).then(|| scan(from, to, needle, each))
}

/// Drop the data cache's lines over `from..to`, so the panic probe reads
/// memory after the wipe, not the cache. Only where no frame still runs: a
/// line dropped before its write-back loses its writes.
#[cfg(feature = "panic-probe")]
pub fn from_memory(from: usize, to: usize) {
    let (from, to) = (from & !63, to.next_multiple_of(64));
    crate::soc::cache::invalidate(from as u32, (to - from) as u32);
}

/// Write back the data cache's lines over `from..to`, dropping nothing, so
/// the panic probe's markers are in memory before the panic, for
/// [`from_memory`] to test.
#[cfg(feature = "panic-probe")]
pub fn to_memory(from: usize, to: usize) {
    let (from, to) = (from & !63, to.next_multiple_of(64));
    crate::soc::cache::writeback(from as u32, (to - from) as u32);
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

/// Bytes not zero in `from..to`, for the panic probe to check the buffers
/// the board's `quiesce` clears: the board names them, its own statics and
/// allocations, mapped while the unit runs.
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

/// [`find`] in memory the caller holds, initialised or not: a vector's
/// spare capacity, for the seed probe's look at heap the decoder just freed.
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

/// Bytes of zeros in [`padded`]'s frame, between the frames the wipe clears
/// and the one it runs in, [`halt_here`]'s, which ends where they start: the
/// wipe keeps exactly that frame and clears the padding and above. A guessed
/// span would not do: opt-level `z` with LTO can lay out a larger frame, and
/// clearing part of it loses its function pointers, so the panic spins
/// without `quiesce`.
const PAD: usize = 512;

/// Stop the unit and clear both cores' stacks, for the panic handler on
/// whichever core panicked.
///
/// # What is cleared
///
/// Each stack from `floor_margin` above its end to its top (core 1's once
/// started). On the stack the wipe runs on, the clearing frame,
/// `halt_here`'s, is kept, from its stack pointer to `padded`'s zeros; the
/// other stack is cleared whole, its core parked first and never run again.
/// Below that frame is what the panic left (derivation intermediates, a
/// decoded code, a hash state); above it, every caller, `main`'s frame with
/// its seed slots and keys among them.
/// None of these frames runs again: nothing returns from here.
/// `floor_margin` is the scrub's, so the guard word esp-hal watches at a
/// stack's end is never written and the wipe cannot look like an overflow.
///
/// Then the unit's `quiesce`: the decoder's buffers, and the backlight off
/// so the last screen, perhaps a SeedQR, does not stay lit.
///
/// Then the data cache, which internal memory sits behind, written back
/// over the statics and the stacks: else the last zeros, up to the cache's
/// size, could stay in the cache while memory keeps the old bytes until
/// power is cut. Through `soc::cache`'s sync registers, not the ROM's cache
/// calls, so it does not depend on the ROM table the build links.
///
/// # What is not
///
/// The heap (PSRAM, which should hold no secret) but for the buffers lent
/// to [`clear_on_panic`]; statics but for those `quiesce` clears.
///
/// # Order
///
/// Interrupts off, so no handler pushes a frame into cleared memory; the
/// other core parked, so nothing runs on a stack being cleared or holds a
/// seed meanwhile; then the steps above, `report` with the stack bytes
/// cleared, and a spin, all below this frame on stack already cleared. No
/// register windows to spill (unlike Xtensa): a RISC-V caller's registers
/// are already on the stack, or in registers nothing will write back.
#[inline(never)]
pub fn wipe_and_halt(floor_margin: usize, quiesce: fn(), report: fn(usize)) -> ! {
    esp_hal::riscv::interrupt::disable();
    // The other core got here first: it parks this one.
    if HALTING.swap(true, Ordering::AcqRel) {
        loop {
            core::hint::spin_loop();
        }
    }
    park_other();
    padded(floor_margin, quiesce, report)
}

/// [`PAD`] bytes of zeros on the stack, then [`halt_here`] below them,
/// handed the padding so the call cannot become a jump that drops this
/// frame first.
#[inline(never)]
fn padded(floor_margin: usize, quiesce: fn(), report: fn(usize)) -> ! {
    let pad = [0u8; PAD];
    halt_here(core::hint::black_box(&pad), floor_margin, quiesce, report)
}

/// Stall the core this is not running on, if the unit started core 1.
fn park_other() {
    if core1().is_none() {
        return;
    }
    let other = match Cpu::current() {
        Cpu::ProCpu => Cpu::AppCpu,
        Cpu::AppCpu => Cpu::ProCpu,
    };
    // SAFETY: the unit is halting. The unit's `CpuControl` started core 1
    // and was forgotten; this one only writes the PMU's stall code, and the
    // core it stalls never runs again.
    unsafe { CpuControl::new(esp_hal::peripherals::CPU_CTRL::steal()).park_core(other) };
}

/// Zero both stacks but this frame, run `quiesce`, write the cache back,
/// report, and stop.
///
/// Never inlined: its frame is the lowest live one, so nothing below its
/// stack pointer is in use, and every frame above, the caller's included,
/// is dead as this does not return. Inlined, its frame would be the
/// caller's, and the clear could zero the caller's values.
///
/// The clearing itself is [`zero`], inlined, so no function's frame, with
/// its return address, sits in a span being cleared: the return would jump
/// to address 0. A function called between or after the clears
/// (`clear_also`, `quiesce`, `report`) builds its frame on zeros, which is
/// all it needs.
#[inline(never)]
fn halt_here(pad: &[u8; PAD], floor_margin: usize, quiesce: fn(), report: fn(usize)) -> ! {
    // What is kept: this frame, from its stack pointer up to the padding,
    // which starts in the caller's frame.
    let sp = stack_pointer();
    let keep_to = core::hint::black_box(pad).as_ptr() as usize;
    // The stack this frame is on, but for the frame; the parked core's,
    // whole. A core 1 not started reads as an empty stack.
    let stacks = [core0(), core1().unwrap_or((0, 0))];
    let mut cleared = 0;
    for (bottom, top) in stacks {
        let floor = bottom.saturating_add(floor_margin);
        cleared += if top == 0 {
            0
        } else if sp < bottom || sp >= top {
            zero(floor, top)
        } else {
            zero(floor, sp) + zero(keep_to, top)
        };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    // The buffers lent to `clear_on_panic`, before `quiesce`, as the stacks.
    let _ = clear_also();
    quiesce();
    // The cache written back over the statics and both stacks, in its
    // 64-byte lines.
    let (bottom, top) = statics_and_stack();
    let from = bottom & !63;
    let to = top.next_multiple_of(64);
    crate::soc::cache::writeback(from as u32, (to - from) as u32);
    report(cleared);
    loop {
        core::hint::spin_loop();
    }
}

/// The stack pointer of the function this is inlined into: where its frame
/// ends. Below it RISC-V keeps nothing but an interrupt's frame, gone when
/// the interrupt returns. For the panic's wipe and core 1's clear after
/// every job ([`crate::decode_core`]).
#[inline(always)]
pub(crate) fn stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: copies the stack pointer into a register; no memory is read
    // or written, and the stack pointer is left as it was.
    unsafe {
        core::arch::asm!("mv {0}, sp", out(reg) sp, options(nomem, nostack, preserves_flags))
    };
    sp
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
/// the statics the unit's `quiesce` clears.
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

/// Bytes kept below the clearing frame at boot, a kilobyte as in the S3's
/// stack probe: room for what an interrupt pushes while the clear runs.
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
/// if a watchdog, a panic or the reset button ended a run that held one.
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
        // guard word, and a kilobyte below this frame, the lowest one live:
        // nothing has used this stack below it since the reset.
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
