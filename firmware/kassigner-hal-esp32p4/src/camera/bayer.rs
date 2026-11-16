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

//! Bayer green extraction. With demosaic off each byte is one photosite of
//! a 2x2 colour pattern, half of it green: the green cells alone are a
//! half-resolution greyscale image, enough for QR at about 3 px a module.
//!
//!   BGGR:  B G     GBRG:  G B     GRBG:  G R     RGGB:  R G
//!          G R            R G            B G            G B
//!
//! This samples (odd x, even y): green in BGGR and RGGB, not GBRG or GRBG.
//!
//! The DMA, not Rust, writes the frame buffer, and under fat LTO the
//! optimiser acts on a `&[u8]`'s promise that nothing else does. So every
//! read is a `read_volatile` through a raw pointer: about 58k reads for a
//! 240 by 240 plane.

/// A DMA-written region: pointer + length, never a slice.
#[derive(Copy, Clone)]
pub struct Raw {
    ptr: *const u8,
    len: usize,
}

impl Raw {
    /// # Safety
    /// The caller ensures `ptr` points to `len` readable bytes for as long
    /// as the `Raw` is used, and has run the cache invalidate.
    pub const unsafe fn new(ptr: *const u8, len: usize) -> Self {
        Self { ptr, len }
    }

    /// Base address.
    pub const fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Length in bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True if empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// One byte, volatile. Panics on out-of-range like a slice would.
    #[inline]
    pub fn at(&self, i: usize) -> u8 {
        assert!(i < self.len, "Raw index {i} out of {}", self.len);
        // SAFETY: bounds checked above; validity is `new`'s contract.
        unsafe { core::ptr::read_volatile(self.ptr.add(i)) }
    }
}

/// Green-plane dimensions for a raw frame of `w` x `h`.
pub const fn green_dims(w: u32, h: u32) -> (u32, u32) {
    (w / 2, h / 2)
}

/// One green pixel of a raw frame with row stride `stride`; `gx`, `gy`
/// index the green plane.
#[inline]
pub fn green_at(raw: Raw, stride: u32, gx: u32, gy: u32) -> u8 {
    let x = gx * 2 + 1; // odd column
    let y = gy * 2; // even row
    raw.at((y * stride + x) as usize)
}

/// Copy the green plane into `dst`, which must hold at least
/// `(w/2) * (h/2)` bytes. Returns the plane dimensions.
pub fn extract_green(raw: Raw, w: u32, h: u32, dst: &mut [u8]) -> (u32, u32) {
    let (gw, gh) = green_dims(w, h);
    let mut i = 0usize;
    for gy in 0..gh {
        for gx in 0..gw {
            if i < dst.len() {
                dst[i] = green_at(raw, w, gx, gy);
                i += 1;
            }
        }
    }
    (gw, gh)
}

/// min, max and mean of the green plane. All 32-bit: on ECO2, 64-bit
/// division hits a wrong ROM routine without `esp-hal-fork/eco2-fix.patch`.
pub fn green_stats(raw: Raw, w: u32, h: u32) -> (u8, u8, u32) {
    let (gw, gh) = green_dims(w, h);
    let mut min = 255u8;
    let mut max = 0u8;
    let mut sum = 0u32;
    let mut n = 0u32;
    for gy in 0..gh {
        for gx in 0..gw {
            let g = green_at(raw, w, gx, gy);
            min = min.min(g);
            max = max.max(g);
            sum += g as u32;
            n += 1;
        }
    }
    (min, max, sum.checked_div(n).unwrap_or(0))
}
