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

//! PSRAM's two windows.
//!
//! The CPU reaches PSRAM through the L1 and L2 caches at [`CACHED`], and
//! the same bytes [`UNCACHED_OFFSET`] above with no cache between (TRM
//! 9.3.3.1). Zeros written through the cached window sit in the caches
//! until evicted, so a reset can lose them (no L2 write-back was seen to
//! reach PSRAM, measured on the camera's frame); a write through the
//! uncached window is in PSRAM when it returns.

use core::ops::Range;

/// PSRAM's cached window, where the heap is.
pub const CACHED: Range<usize> = 0x4800_0000..0x4C00_0000;

/// From PSRAM's cached window to its uncached one (`0x8800_0000` on for
/// `0x4800_0000` on).
pub const UNCACHED_OFFSET: usize = 0x4000_0000;

/// A cache line, either cache's, which buffers here fill whole.
const LINE: usize = 128;

/// Zero all of PSRAM through the uncached window at boot, before the heap
/// is made in it, then drop the caches' lines over it so none written
/// earlier is evicted over the zeros. Returns the bytes cleared: zero if
/// no PSRAM is mapped in the cached window.
///
/// A reset short of a power cut leaves the last run's heap in PSRAM: the
/// frames of a SeedQR, a seed's words, Argon2id's blocks. Every boot clears
/// it, not only one after a watchdog: the centre button's reset reads to
/// the chip as a power-on, and PSRAM may keep its bytes through it.
pub fn clear(psram: &esp_hal::psram::Psram) -> usize {
    let (at, len) = psram.raw_parts();
    let start = at as usize;
    if len == 0 || !CACHED.contains(&start) || !CACHED.contains(&(start + len - 1)) {
        return 0;
    }
    let direct = (start + UNCACHED_OFFSET) as *mut u32;
    for i in 0..len / 4 {
        // SAFETY: the uncached alias of the range the driver mapped,
        // word-aligned, and not yet the heap's: nothing else holds it.
        unsafe { direct.add(i).write_volatile(0) };
    }
    crate::soc::cache::invalidate(start as u32, len as u32);
    len
}

/// `n` values of `T` in PSRAM, from the heap for the program's life, each
/// `T::default()`, handed out through the uncached window so every write,
/// a wipe included, is in PSRAM when it returns. For secrets too large for
/// internal RAM: the frames' reassembler and payload, which carry a seed's
/// words in Plain Text QR's KasSigner frames, and Argon2id's 16 MiB of
/// blocks derived from a backup's password, which `kassigner-crypto` wipes
/// after each use.
///
/// `T` is plain data, `Copy`: nothing to drop, and no atomic, which
/// uncached memory is not promised to support.
///
/// `None` if the heap cannot give it, or gives it outside PSRAM.
pub fn buffer<T: Copy + Default>(n: usize) -> Option<&'static mut [T]> {
    let bytes = n.checked_mul(core::mem::size_of::<T>())?;
    let size = bytes.max(1).div_ceil(LINE) * LINE;
    let align = core::mem::align_of::<T>().max(LINE);
    let layout = core::alloc::Layout::from_size_align(size, align).ok()?;
    // SAFETY: a layout of nonzero size; the block is never freed.
    let p = unsafe { alloc::alloc::alloc(layout) };
    let at = p as usize;
    if p.is_null() || !CACHED.contains(&at) || !CACHED.contains(&(at + size - 1)) {
        return None;
    }
    // Drop the caches' lines here from the heap's earlier use (the boot's
    // PSRAM test writes through them), so no dirty line is evicted over
    // this buffer's writes. The block is whole lines.
    crate::soc::cache::invalidate(at as u32, size as u32);
    let direct = (at + UNCACHED_OFFSET) as *mut T;
    // SAFETY: the block just allocated, aligned for `T`, through its
    // uncached alias: all `n` values are written before the slice is made,
    // and only the slice touches them after, never the cached window.
    unsafe {
        for i in 0..n {
            direct.add(i).write(T::default());
        }
        Some(core::slice::from_raw_parts_mut(direct, n))
    }
}
