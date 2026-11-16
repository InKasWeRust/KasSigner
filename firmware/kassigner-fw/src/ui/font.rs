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

//! Fonts: glyph bitmaps with 16 levels of coverage.
//!
//! Printable ASCII only, `0x20` to `0x7E`: everything the keyboard types, and
//! every BIP39 word, `kaspa:` address and label. Anything else is a filled
//! block in the text's colour, a digit wide and a capital tall, which
//! cannot be typed and so is never mistaken for a character of the text.
//!
//! A glyph is its tight bitmap, placed against the pen and baseline: four
//! bits a pixel (15 fully inside), two a byte, high nibble first, rows
//! byte-aligned. The tables come from `assets/fonts/` by
//! `tests/ui_assets.rs`.

/// The first byte a font has a glyph for.
pub const FIRST: u8 = 0x20;
/// The last.
pub const LAST: u8 = 0x7E;
/// How many glyphs a font holds.
pub const GLYPHS: usize = (LAST - FIRST) as usize + 1;

/// One glyph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Glyph {
    /// How far the pen moves after it, in pixels.
    pub advance: u8,
    /// Where the bitmap starts, right of the pen.
    pub left: i8,
    /// Where the bitmap starts, above the baseline.
    pub top: i8,
    /// The bitmap's size.
    pub width: u8,
    pub height: u8,
    /// Where its rows start in [`Font::bits`].
    pub offset: u32,
}

impl Glyph {
    /// A glyph from the generated table.
    pub const fn new(advance: u8, left: i8, top: i8, width: u8, height: u8, offset: u32) -> Self {
        Self {
            advance,
            left,
            top,
            width,
            height,
            offset,
        }
    }

    /// Bytes a row takes.
    pub const fn stride(&self) -> usize {
        (self.width as usize).div_ceil(2)
    }
}

/// A font at one size.
#[derive(Clone, Copy, Debug)]
pub struct Font {
    /// Pixels the tallest glyph reaches above the baseline.
    pub ascent: u8,
    /// Pixels the deepest glyph reaches below it.
    pub descent: u8,
    /// One glyph per byte, [`FIRST`] to [`LAST`].
    pub glyphs: &'static [Glyph; GLYPHS],
    /// The bitmaps.
    pub bits: &'static [u8],
}

/// [`Glyph::offset`] of the block drawn for a character with no glyph: no
/// bitmap, fully covered.
const BLOCK: u32 = u32::MAX;

impl Font {
    /// The glyph a character is drawn with: its own, or the block.
    pub fn glyph(&self, c: char) -> Glyph {
        match u8::try_from(c) {
            Ok(b) if (FIRST..=LAST).contains(&b) => self.own(b),
            _ => self.block(),
        }
    }

    /// The glyph of a byte the font has, [`FIRST`] to [`LAST`].
    fn own(&self, b: u8) -> Glyph {
        self.glyphs[usize::from(b - FIRST)]
    }

    /// The block: a digit's advance, filled but for a pixel each side, a
    /// capital's height.
    fn block(&self) -> Glyph {
        let (digit, capital) = (self.own(b'0'), self.own(b'H'));
        Glyph {
            advance: digit.advance,
            left: 1,
            top: capital.top,
            width: digit.advance.saturating_sub(2).max(1),
            height: capital.height,
            offset: BLOCK,
        }
    }

    /// How wide a text is drawn, pen start to pen end.
    pub fn width(&self, text: &str) -> i32 {
        text.chars().map(|c| i32::from(self.glyph(c).advance)).sum()
    }

    /// `text` fitted to `room` pixels, into `out`: whole, or as much of its
    /// start and longer end as fits around `...` (file names differ at the
    /// end); empty if nothing fits or `out` is too short.
    pub fn fit<'o>(&self, text: &str, room: i32, out: &'o mut [u8]) -> &'o str {
        const CUT: &str = "...";
        let put = |out: &'o mut [u8], parts: [&str; 3]| -> &'o str {
            let n: usize = parts.iter().map(|p| p.len()).sum();
            if n > out.len() {
                return "";
            }
            let mut at = 0;
            for p in parts {
                out[at..at + p.len()].copy_from_slice(p.as_bytes());
                at += p.len();
            }
            core::str::from_utf8(&out[..n]).unwrap_or("")
        };
        if self.width(text) <= room {
            return put(out, [text, "", ""]);
        }
        // Where each character starts, so a cut never splits one.
        let starts = |k: usize| text.char_indices().nth(k).map_or(text.len(), |(i, _)| i);
        let chars = text.chars().count();
        for keep in (0..chars).rev() {
            let tail = keep.div_ceil(2);
            let (head, tail) = (&text[..starts(keep - tail)], &text[starts(chars - tail)..]);
            if self.width(head) + self.width(CUT) + self.width(tail) <= room {
                return put(out, [head, CUT, tail]);
            }
        }
        ""
    }

    /// How wide a text is drawn with `gap` pixels between characters
    /// ([`crate::ui::band::Band::text_spaced`]).
    pub fn width_spaced(&self, text: &str, gap: i32) -> i32 {
        let gaps = i32::try_from(text.chars().count().saturating_sub(1)).unwrap_or(0);
        self.width(text) + gap * gaps
    }

    /// The coverage of one pixel of a glyph, 0 to 15 (15 all over the
    /// block). `x` and `y` must be inside the glyph's bitmap.
    pub fn coverage(&self, glyph: &Glyph, x: u8, y: u8) -> u8 {
        if glyph.offset == BLOCK {
            return 15;
        }
        let at = glyph.offset as usize + usize::from(y) * glyph.stride() + usize::from(x) / 2;
        let byte = self.bits[at];
        if x.is_multiple_of(2) {
            byte >> 4
        } else {
            byte & 0x0F
        }
    }
}
