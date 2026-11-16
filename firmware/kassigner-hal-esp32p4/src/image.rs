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

//! The running image's bytes, read from flash through the cache, behind
//! `kassigner-hal`'s [`Image`].
//!
//! Why through the cache, never by flash command, is as on the S3 (its
//! crate's `image` module); the P4's mapping table differs.
//!
//! The flash table belongs to the memory controller at `0x5008_C000`
//! (`SPI0` in the `esp32p4` PAC 0.3): `MMU_ITEM_INDEX` picks one of 512
//! entries, `MMU_ITEM_CONTENT` reads or writes it. Each maps a page (64 KB
//! shifted right by `MMU_POWER_CTRL` bits 4:3) into the window from
//! `0x4000_0000`; an entry is the page number in bits 9:0, bit 10 for
//! PSRAM, bit 12 for in use. Mapping writes the page with bit 12, then the
//! ROM's `Cache_Invalidate_Addr` drops the window's lines from the L1 data
//! and L2 caches, both on the flash read path; unmapping writes zero and
//! drops them again (ESP-IDF's and esp-storage's order). The entry
//! borrowed is the highest unused one below the last. The image starts
//! `0x20` before the app descriptor, as on the S3.
//!
//! Verified on 24 October 2026: on a P4 running the release's image, the
//! hash it shows at boot matched that image's line in the release's
//! `SHA256SUMS`. A read through the wrong page or a stale cache line would
//! give another hash.

use esp32p4::{spi0::RegisterBlock, SPI0};
use kassigner_hal::image::{Image, ReadFailed};

/// Entries in the flash table.
const ENTRIES: u32 = 512;

/// Where flash shows in the address space.
const FLASH: u32 = 0x4000_0000;

/// An entry in use.
const VALID: u32 = 1 << 12;

/// An entry mapping PSRAM, not flash.
const SPIRAM: u32 = 1 << 10;

/// An entry's page number.
const PAGE_NUMBER: u32 = 0x3FF;

/// How far into the image the app descriptor sits.
const APP_DESC_AT: u32 = 0x20;

/// `Cache_Invalidate_Addr`'s map bits: L1 data cache and L2 cache.
const CACHES: u32 = (1 << 4) | (1 << 5);

extern "C" {
    /// ROM: drop the lines of the caches in `map` over an address range
    /// (`esp32p4.rom.ld`, `0x4fc0_03e4`).
    fn Cache_Invalidate_Addr(map: u32, addr: u32, size: u32);

    /// The app descriptor, which `esp_app_desc!` places first in the image's
    /// first segment.
    static esp_app_desc: u8;
}

/// The memory controller's registers.
fn regs() -> &'static RegisterBlock {
    // SAFETY: fixed MMIO block, always mapped; only its table registers are
    // used.
    unsafe { &*SPI0::PTR }
}

/// Bytes an entry maps.
fn page() -> u32 {
    0x1_0000 >> regs().mmu_power_ctrl().read().spi_mmu_page_size().bits()
}

/// Read entry `i`.
fn get(i: u32) -> u32 {
    let r = regs();
    // SAFETY: an entry below 512; every selection, here or in `set`, comes
    // just before the access that uses it.
    r.mmu_item_index()
        .write(|w| unsafe { w.mmu_item_index().bits(i) });
    r.mmu_item_content().read().bits()
}

/// Write entry `i`, which must be the entry [`Running`] borrowed.
fn set(i: u32, value: u32) {
    let r = regs();
    // SAFETY: the entry `Running::find` found unused and borrowed; nothing
    // else maps through it meanwhile.
    r.mmu_item_index()
        .write(|w| unsafe { w.mmu_item_index().bits(i) });
    // SAFETY: as above.
    r.mmu_item_content().write(|w| unsafe { w.bits(value) });
}

/// The running image, read through one borrowed entry, given back on drop.
pub struct Running {
    /// Where the image starts in flash.
    start: u32,
    /// Bytes from there to the end of the flash.
    limit: u32,
    /// Bytes an entry maps.
    page: u32,
    /// The borrowed entry.
    slot: u32,
    /// The flash page it maps now, if any.
    mapped: Option<u32>,
}

impl Running {
    /// The running image and an entry to read it through: none if the
    /// descriptor is not where an image's is, or no entry is free.
    pub fn find() -> Option<Self> {
        let page = page();
        let desc = core::ptr::addr_of!(esp_app_desc) as u32;
        let offset = desc.checked_sub(FLASH)?;
        let i = offset / page;
        if i >= ENTRIES {
            return None;
        }
        let e = get(i);
        if e & VALID == 0 || e & SPIRAM != 0 {
            return None;
        }
        let start = ((e & PAGE_NUMBER) * page + offset % page).checked_sub(APP_DESC_AT)?;
        let slot = (0..ENTRIES - 1).rev().find(|&k| get(k) & VALID == 0)?;
        let mut running = Self {
            start,
            limit: 0,
            page,
            slot,
            mapped: None,
        };
        // The flash size the image's header gives: bits 7:4 of its fourth
        // byte, 1 MB shifted by that much.
        let mut head = [0u8; 4];
        running.copy(0, &mut head);
        let code = u32::from(head[3] >> 4);
        if code > 7 {
            return None;
        }
        running.limit = (0x10_0000u32 << code).checked_sub(start)?;
        Some(running)
    }

    /// Where the borrowed entry shows.
    fn window(&self) -> u32 {
        FLASH + self.slot * self.page
    }

    /// Drop the caches' lines over the borrowed entry's window.
    fn invalidate(&self) {
        // SAFETY: a ROM routine over an address range: the borrowed entry's
        // own window, which nothing else reads.
        unsafe { Cache_Invalidate_Addr(CACHES, self.window(), self.page) }
    }

    /// Where the image starts in flash, for a read-back.
    pub fn start(&self) -> u32 {
        self.start
    }

    /// Point the borrowed entry at flash page `n`.
    fn map(&mut self, n: u32) {
        if self.mapped == Some(n) {
            return;
        }
        set(self.slot, (n & PAGE_NUMBER) | VALID);
        self.invalidate();
        self.mapped = Some(n);
    }

    /// Copy the image's bytes from `offset`, with no bound checked.
    fn copy(&mut self, offset: u32, buf: &mut [u8]) {
        let mut done = 0;
        while done < buf.len() {
            let at = self.start + offset + done as u32;
            let within = at % self.page;
            let n = (buf.len() - done).min((self.page - within) as usize);
            self.map(at / self.page);
            let src = (self.window() + within) as *const u8;
            for (k, byte) in buf[done..done + n].iter_mut().enumerate() {
                // SAFETY: inside the borrowed entry's window, mapping the
                // flash page `map` just set; a cached read, as of any
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
            set(self.slot, 0);
            self.invalidate();
        }
    }
}
