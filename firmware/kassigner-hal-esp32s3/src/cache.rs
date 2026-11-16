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

//! The data cache in front of PSRAM, as far as a wipe needs it.
//!
//! The S3 reaches PSRAM only through its data cache, so a wipe's zeros sit
//! in the cache and PSRAM keeps the old bytes until the lines are evicted;
//! a reset in between loses the zeros. Measured on the Waveshare: a wipe
//! alone left 65,312 bytes, one data cache's worth, in PSRAM; with
//! [`write_back`] after it, none.

/// External memory on the data bus: esp-hal's `psram.extmem_origin` for the
/// S3 and the 32 MB above, where PSRAM follows the flash's read-only pages.
/// Internal RAM starts at `0x3FC8_8000`.
const EXTERNAL: core::ops::Range<usize> = 0x3C00_0000..0x3E00_0000;

/// Whether `p` is in external memory, behind the data cache: a buffer there
/// needs [`write_back`] after its wipe.
pub fn is_external(p: *const u8) -> bool {
    EXTERNAL.contains(&(p as usize))
}

// The ROM's cache operations, named as in esp-rom-sys's `esp32s3.rom.ld`.
// `write_back` suspends the data cache's autoload around the write-back, as
// ESP-IDF does.
extern "C" {
    fn rom_Cache_WriteBack_Addr(addr: u32, size: u32) -> i32;
    fn Cache_Suspend_DCache_Autoload() -> u32;
    fn Cache_Resume_DCache_Autoload(autoload: u32);
}

/// Push the data cache's dirty lines over `len` bytes at `p` out to PSRAM;
/// null is a no-op. Lines at an unaligned range's ends go out whole, which
/// writes a neighbour's bytes out unchanged.
///
/// # Safety
///
/// `p` is null or points at `len` bytes of PSRAM.
pub unsafe fn write_back(p: *mut u8, len: usize) {
    if p.is_null() {
        return;
    }
    let autoload = Cache_Suspend_DCache_Autoload();
    rom_Cache_WriteBack_Addr(p as u32, len as u32);
    Cache_Resume_DCache_Autoload(autoload);
}

/// Zero all of PSRAM and push the zeros out of the cache, at boot, before
/// the heap is made in it. Bytes cleared: zero when the driver mapped no
/// PSRAM or mapped it outside the external window.
///
/// A reset that is not a power cut leaves the heap in PSRAM as the last run
/// left it: the frames a SeedQR was read from, the payload a seed's words
/// came in. Every boot clears it, not only one after a watchdog: a reset
/// button reads to the chip as a power-on, and PSRAM may keep its bytes
/// through one.
#[cfg(target_arch = "xtensa")]
pub fn clear_psram(psram: &esp_hal::psram::Psram) -> usize {
    let (at, len) = psram.raw_parts();
    let start = at as usize;
    if len == 0 || !EXTERNAL.contains(&start) || !EXTERNAL.contains(&(start + len - 1)) {
        return 0;
    }
    let words = at.cast::<u32>();
    for i in 0..len / 4 {
        // SAFETY: inside the range the driver mapped, word-aligned as its
        // start is, and not yet the heap's: nothing else holds any of it.
        unsafe { words.add(i).write_volatile(0) };
    }
    // SAFETY: the same range, all of it PSRAM.
    unsafe { write_back(at, len) };
    len
}

/// A PSRAM buffer kept by its address, so its wipe's zeros can be pushed
/// out of the cache whoever holds it by then: for a buffer lent for the
/// program's life to something that wipes it, such as the frames'
/// reassembler and its payload, which a seed's words cross (Plain Text
/// QR's KasSigner frames).
#[derive(Clone, Copy, Debug)]
pub struct Region {
    at: usize,
    len: usize,
}

impl Region {
    /// `buf`'s place; empty unless it is wholly in PSRAM, as internal RAM
    /// has no cache in front of it.
    pub fn of(buf: &[u8]) -> Self {
        let at = buf.as_ptr() as usize;
        let whole = !buf.is_empty()
            && is_external(buf.as_ptr())
            && EXTERNAL.contains(&(at + buf.len() - 1));
        Self {
            at,
            len: if whole { buf.len() } else { 0 },
        }
    }

    /// Push the cache's dirty lines over the region out to PSRAM. Safe
    /// whoever holds the buffer: a write-back changes no byte anyone reads.
    pub fn write_back(&self) {
        if self.len == 0 {
            return;
        }
        // SAFETY: `of` kept a length only for a range wholly in PSRAM, and
        // a write-back changes no byte.
        unsafe { write_back(self.at as *mut u8, self.len) };
    }
}
