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

//! L1/L2 cache maintenance.
//!
//! Through the CACHE peripheral's sync registers, not the ROM's
//! `Cache_Invalidate_Addr()`, so it does not depend on the ROM table the
//! build links (`esp-hal-fork/eco2-fix.patch`).
//!
//! Registers through the `esp32p4` PAC, whose layout matches the offsets
//! that ran on this silicon: `sync_ctrl` invalidate b0, clean b1, writeback
//! b2, done b4; `sync_map` bit 4 the L1 data cache; `sync_size` 28 bits.
//! `sync_rgid`, a 4-bit permission-region id, stays 0.
//!
//! The handshake below (wait idle, issue, wait done) is hygiene, not a fix:
//! stack values reading back as zero on ECO2 come from the unbacked top
//! 128 KB of L2MEM, which the patch's `memory.x` keeps the stack out of.

use crate::soc::uart;
use core::sync::atomic::{compiler_fence, Ordering};
use esp32p4::{cache::RegisterBlock, CACHE};

/// Only the sync engine is used; esp-hal has no driver for it, but its ROM
/// `Cache_*` calls (PSRAM init, DMA buffers) drive the same engine, on the
/// same core, never during a sync here.
#[inline(always)]
fn regs() -> &'static RegisterBlock {
    // SAFETY: fixed MMIO block, always mapped; nothing else writes these
    // four registers while a sync here runs.
    unsafe { &*CACHE::PTR }
}

/// Largest range per operation: one 1.5 MB operation fails on this
/// silicon; 32 KB chunks work.
const CHUNK: u32 = 32 * 1024;

/// The L1 data cache in the sync map. L2MEM (internal SRAM) is synced in it
/// alone, as only the L1 caches front it; ESP-IDF's `cache_ll` for P4 does
/// the same.
const MAP_L1_DCACHE: u8 = 1 << 4;

/// The L2 cache in the sync map (bit 5 in the PAC). It fronts flash and
/// PSRAM, so a PSRAM range is synced in both.
const MAP_L2_CACHE: u8 = 1 << 5;

/// Which caches hold lines of `addr`: the L1 data cache always, the L2
/// cache too for an address in PSRAM's cached window.
fn map_for(addr: u32) -> u8 {
    if (0x4800_0000..0x4C00_0000).contains(&addr) {
        MAP_L1_DCACHE | MAP_L2_CACHE
    } else {
        MAP_L1_DCACHE
    }
}

#[derive(Copy, Clone)]
enum Op {
    Invalidate,
    Writeback,
}

/// Wait for the operation's enable bit to clear, which the hardware does
/// when done. Bounded.
fn wait_enable_clear(op: Op, what: &str) -> bool {
    let mut spins = 0u32;
    loop {
        let c = regs().sync_ctrl().read();
        let busy = match op {
            Op::Invalidate => c.invalidate_ena().bit_is_set(),
            Op::Writeback => c.writeback_ena().bit_is_set(),
        };
        if !busy {
            return true;
        }
        spins += 1;
        if spins > 20_000_000 {
            uart::puts("  !! cache ");
            uart::puts(what);
            uart::puts(" never cleared its enable bit\r\n");
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Wait for `sync_done` to read 1. Bounded.
fn wait_done(what: &str) -> bool {
    let mut spins = 0u32;
    while !regs().sync_ctrl().read().sync_done().bit_is_set() {
        spins += 1;
        if spins > 2_000_000 {
            uart::puts("  !! cache ");
            uart::puts(what);
            uart::puts(" never completed\r\n");
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

fn sync(addr: u32, size: u32, op: Op, what: &str) {
    // Lines are 64 bytes: an unaligned range sweeps the neighbouring line,
    // and an invalidate would discard its dirty data.
    debug_assert!(
        addr.is_multiple_of(64) && size.is_multiple_of(64),
        "cache op must be 64-byte aligned"
    );

    compiler_fence(Ordering::SeqCst);
    let r = regs();
    let mut done = 0u32;
    while done < size {
        let n = if size - done > CHUNK {
            CHUNK
        } else {
            size - done
        };

        // Engine idle before its parameters are touched.
        if !wait_done(what) {
            return;
        }
        r.sync_map()
            // SAFETY: bits 4 and 5, the L1 data cache and the L2 cache.
            // Callers invalidate only lines they mean to drop (the camera's
            // frame, PSRAM just zeroed or handed out through its uncached
            // window, and for the panic probe memory no frame still runs
            // in), so no live object's data is lost; a write-back drops
            // nothing.
            .write(|w| unsafe { w.sync_map().bits(map_for(addr)) });
        r.sync_addr()
            // SAFETY: this chunk's address, inside the caller's range.
            .write(|w| unsafe { w.sync_addr().bits(addr + done) });
        // SAFETY: the chunk size, at most `CHUNK`, inside the 28-bit field.
        r.sync_size().write(|w| unsafe { w.sync_size().bits(n) });
        r.sync_ctrl().write(|w| match op {
            Op::Invalidate => w.invalidate_ena().set_bit(),
            Op::Writeback => w.writeback_ena().set_bit(),
        });
        // Flush the posted write, then wait for the operation's enable bit
        // to clear, which the hardware does when it is done. Waiting for
        // `sync_done` to drop and rise misses the drop on this silicon: a
        // chunk reads as done before it starts, and the next chunk's
        // parameters land under a running operation.
        let _ = r.sync_ctrl().read();
        if !wait_enable_clear(op, what) {
            return;
        }
        if !wait_done(what) {
            return;
        }
        done += n;
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(feature = "unstable")] // diagnostics: used by the self-tests, not by the HAL
/// Print the sync registers. Diagnostic.
pub fn dump(tag: &str) {
    let r = regs();
    uart::puts("  [cache ");
    uart::puts(tag);
    uart::puts("] ctrl=");
    uart::puthex(r.sync_ctrl().read().bits());
    uart::puts(" map=");
    uart::puthex(r.sync_map().read().bits());
    uart::puts(" addr=");
    uart::puthex(r.sync_addr().read().bits());
    uart::puts(" size=");
    uart::puthex(r.sync_size().read().bits());
    uart::puts("\r\n");
}

/// Discard cached lines so the CPU sees what DMA wrote. Dirty lines go too:
/// a buffer filled through the cache and not written back loses that data.
pub fn invalidate(addr: u32, size: u32) {
    sync(addr, size, Op::Invalidate, "invalidate");
}

/// Push dirty lines out to memory. Call before DMA reads a buffer the CPU
/// has written, and at a panic, so the wipe's zeros reach memory
/// ([`crate::stack::wipe_and_halt`]).
pub fn writeback(addr: u32, size: u32) {
    sync(addr, size, Op::Writeback, "writeback");
}
