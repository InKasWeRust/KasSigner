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

//! Pictures and icons.
//!
//! A picture ([`Image`]) is RGB565 as in `assets/images/`: little-endian,
//! rows from the top, and opaque, so it is drawn only on the colour it was
//! made on. An icon is a four-bit coverage mask in a [`Sheet`], drawn in
//! any colour over what lies under it, as text is.

/// A picture, borrowed from flash.
#[derive(Clone, Copy, Debug)]
pub struct Image {
    pub width: u16,
    pub height: u16,
    pixels: &'static [u8],
}

impl Image {
    /// A picture over its bytes.
    ///
    /// # Panics
    ///
    /// If the bytes are not `width * height` pixels: a build error, as every
    /// picture is a `static`.
    pub const fn new(width: u16, height: u16, pixels: &'static [u8]) -> Self {
        assert!(pixels.len() == width as usize * height as usize * 2);
        Self {
            width,
            height,
            pixels,
        }
    }

    /// Where its pixels are: the same picture, whoever names it.
    pub fn id(&self) -> usize {
        self.pixels.as_ptr() as usize
    }

    /// The pixel at `x`, `y`, which must be inside the picture.
    pub fn pixel(&self, x: u16, y: u16) -> u16 {
        let at = (usize::from(y) * usize::from(self.width) + usize::from(x)) * 2;
        u16::from_le_bytes([self.pixels[at], self.pixels[at + 1]])
    }
}

/// Square icons of one size, one after another, packed as glyphs are.
#[derive(Clone, Copy, Debug)]
pub struct Sheet {
    /// The side of every icon, in pixels.
    pub side: u8,
    bits: &'static [u8],
}

impl Sheet {
    /// A sheet of `count` icons over their bits.
    ///
    /// # Panics
    ///
    /// If the bits are not `count` icons of `side`: a build error, as every
    /// sheet is a `static`.
    pub const fn new(side: u8, count: usize, bits: &'static [u8]) -> Self {
        let side_px = side as usize;
        assert!(bits.len() == count * side_px * side_px.div_ceil(2));
        Self { side, bits }
    }

    /// The coverage of one pixel of icon `index`, 0 to 15.
    pub fn coverage(&self, index: usize, x: u8, y: u8) -> u8 {
        let side = usize::from(self.side);
        let stride = side.div_ceil(2);
        let at = (index * side + usize::from(y)) * stride + usize::from(x) / 2;
        let byte = self.bits[at];
        if x.is_multiple_of(2) {
            byte >> 4
        } else {
            byte & 0x0F
        }
    }
}
