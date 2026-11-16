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

//! The running image's bytes, read from flash through the data cache,
//! behind `kassigner-hal`'s [`Image`].
//!
//! # Why through the cache
//!
//! The firmware runs from the same flash chip, over the same wires. ESP-IDF
//! sends the flash a command only with the cache off ("For all SPI1
//! operations (read/write), caches are disabled during these operations by
//! default", ESP-IDF v6.1, SPI flash concurrency constraints), so that no
//! cache fill meets it on the wires. Nothing here sends a command: a page
//! is mapped into the data bus through one free mapping entry, read as
//! memory like any constant, and the entry given back. `esp-storage` is not
//! used: creating its handle sends an ID command with the cache on and
//! waits for the answer in code fetched from flash.
//!
//! # The mapping table
//!
//! 512 entries at `0x600C_5000` (`MMU_TABLE` in the `esp32s3` PAC 0.36,
//! ESP-IDF's `DR_REG_MMU_TABLE`), one per 64 KB page of the 32 MB data bus
//! from `0x3C00_0000`; the instruction bus shares them. An entry holds a
//! flash page number in bits 13:0, bit 14 set for an unused entry, and bit
//! 15 set for one that maps PSRAM. Mapping writes the page number with both
//! bits clear, then drops the cache's lines over the entry's 64 KB with the
//! ROM's `Cache_Invalidate_Addr`, so no line of an earlier mapping is read;
//! giving it back writes bit 14 and drops them again. The order is
//! ESP-IDF's in `esp_mmu_map`, and esp-storage's.
//!
//! The entry borrowed is the highest unused one but the last, which ESP-IDF
//! keeps for the bootloader. Entries in use are never touched, so core 1 or
//! an interrupt reads through entries this never writes.
//!
//! # Where the image starts
//!
//! The app descriptor sits `0x20` bytes in, after the 24-byte image header
//! and the first segment's 8-byte header. The bootloader mapped that segment
//! for the firmware's constants, so the entry behind the descriptor's
//! address names its flash page, and the image starts `0x20` before the
//! descriptor there, wherever the partition table put it.

use kassigner_hal::image::{Image, ReadFailed};

/// The mapping table.
const MMU_TABLE: usize = 0x600C_5000;

/// Entries in it.
const ENTRIES: usize = 512;

/// Bytes an entry maps.
const PAGE: u32 = 0x1_0000;

/// Where the data bus's mapped window starts.
const DBUS: u32 = 0x3C00_0000;

/// An unused entry.
const INVALID: u32 = 1 << 14;

/// An entry mapping PSRAM, not flash.
const SPIRAM: u32 = 1 << 15;

/// An entry's flash page number.
const PAGE_NUMBER: u32 = 0x3FFF;

/// How far into the image the app descriptor sits.
const APP_DESC_AT: u32 = 0x20;

extern "C" {
    /// The ROM's: drop the cache's lines over a range of the address space
    /// (`esp32s3.rom.ld`, `0x4000_16b0`).
    fn Cache_Invalidate_Addr(addr: u32, size: u32);

    /// The app descriptor `esp_app_desc!` places first in the image's first
    /// segment.
    static esp_app_desc: u8;
}

/// Entry `i`'s word.
fn entry(i: usize) -> *mut u32 {
    (MMU_TABLE + 4 * i) as *mut u32
}

/// Read entry `i`, which must be below [`ENTRIES`].
fn get(i: usize) -> u32 {
    // SAFETY: one of the mapping table's 512 words, mapped on every S3;
    // reading it changes nothing.
    unsafe { core::ptr::read_volatile(entry(i)) }
}

/// Write entry `i`, which must be the entry [`Running`] borrowed.
fn set(i: usize, value: u32) {
    // SAFETY: the entry `Running::find` found unused and borrowed; nothing
    // else maps through it, so writing it disturbs no other mapping.
    unsafe { core::ptr::write_volatile(entry(i), value) }
}

/// Drop the cache's lines over the borrowed entry's window.
fn invalidate(slot: usize) {
    // SAFETY: a ROM function taking a range of the data bus; the range is
    // the borrowed entry's own 64 KB, which nothing else reads.
    unsafe { Cache_Invalidate_Addr(window(slot), PAGE) }
}

/// Where entry `slot` shows on the data bus.
fn window(slot: usize) -> u32 {
    DBUS + slot as u32 * PAGE
}

/// The running image, read through one borrowed mapping entry, given back
/// when dropped.
pub struct Running {
    /// Where the image starts in flash.
    start: u32,
    /// Bytes from there to the end of the flash.
    limit: u32,
    /// The borrowed entry.
    slot: usize,
    /// The flash page it maps now, if any.
    mapped: Option<u32>,
}

impl Running {
    /// The image running, and an entry to read it through: none if the
    /// descriptor is not where an image's is, or no entry is free.
    pub fn find() -> Option<Self> {
        let desc = core::ptr::addr_of!(esp_app_desc) as u32;
        let offset = desc.checked_sub(DBUS)?;
        let i = (offset / PAGE) as usize;
        if i >= ENTRIES {
            return None;
        }
        let e = get(i);
        if e & (INVALID | SPIRAM) != 0 {
            return None;
        }
        let start = ((e & PAGE_NUMBER) * PAGE + offset % PAGE).checked_sub(APP_DESC_AT)?;
        let slot = (0..ENTRIES - 1).rev().find(|&k| get(k) & INVALID != 0)?;
        let mut running = Self {
            start,
            limit: 0,
            slot,
            mapped: None,
        };
        // The flash size the image's header gives, as the bootloader reads
        // it: bits 7:4 of its fourth byte, 1 MB shifted by that much.
        let mut head = [0u8; 4];
        running.copy(0, &mut head);
        let code = u32::from(head[3] >> 4);
        if code > 7 {
            return None;
        }
        running.limit = (0x10_0000u32 << code).checked_sub(start)?;
        Some(running)
    }

    /// Where the image starts in flash: what a read-back of it starts at.
    pub fn start(&self) -> u32 {
        self.start
    }

    /// Point the borrowed entry at flash page `page`.
    fn map(&mut self, page: u32) {
        if self.mapped == Some(page) {
            return;
        }
        set(self.slot, page & PAGE_NUMBER);
        invalidate(self.slot);
        self.mapped = Some(page);
    }

    /// Copy the image's bytes from `offset`, with no bound checked.
    fn copy(&mut self, offset: u32, buf: &mut [u8]) {
        let mut done = 0;
        while done < buf.len() {
            let at = self.start + offset + done as u32;
            let within = at % PAGE;
            let n = (buf.len() - done).min((PAGE - within) as usize);
            self.map(at / PAGE);
            let src = (window(self.slot) + within) as *const u8;
            for (k, byte) in buf[done..done + n].iter_mut().enumerate() {
                // SAFETY: inside the borrowed entry's 64 KB window, mapping
                // the page `map` just wrote; a cached read, as of any
                // constant in flash.
                *byte = unsafe { core::ptr::read_volatile(src.add(k)) };
            }
            done += n;
        }
    }
}

impl Image for Running {
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ReadFailed> {
        let end = offset.checked_add(buf.len() as u32).ok_or(ReadFailed)?;
        if end > self.limit {
            return Err(ReadFailed);
        }
        self.copy(offset, buf);
        Ok(())
    }

    fn limit(&self) -> u32 {
        self.limit
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.mapped.is_some() {
            set(self.slot, INVALID);
            invalidate(self.slot);
        }
    }
}
