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

//! Colour: RGB565, the brand palette, and blending.
//!
//! A pixel is a `u16` in RGB565, as every panel and
//! `kassigner_hal::display` take it, so there is no colour type to convert.

/// A colour from its channels at the panel's depth: red and blue 0 to 31,
/// green 0 to 63, the levels the palette is chosen in.
pub const fn rgb565(r: u16, g: u16, b: u16) -> u16 {
    ((r & 0x1F) << 11) | ((g & 0x3F) << 5) | (b & 0x1F)
}

// ── The palette ─────────────────────────────────────────────────────────────
//
// The Kaspa brand teal and its accent, on black.

/// Kaspa teal, #70C7BA: rules, borders, links.
pub const TEAL: u16 = rgb565(14, 49, 23);
/// Bright teal, #49EACB: what is active or pressed.
pub const ACCENT: u16 = rgb565(9, 58, 25);
/// The background, pure black.
pub const BACKGROUND: u16 = 0x0000;
/// A card, #080808: a step off the background.
pub const CARD: u16 = rgb565(1, 2, 1);
/// Text, white.
pub const TEXT: u16 = rgb565(31, 63, 31);
/// Secondary text, #B6B6B6.
pub const TEXT_DIM: u16 = rgb565(22, 45, 22);
/// Hint grey, darker than [`TEXT_DIM`].
pub const HINT: u16 = rgb565(12, 24, 12);
/// The edge of a card that is not the one in use, #505050.
pub const CARD_EDGE: u16 = rgb565(10, 20, 10);
/// Teal all but gone: an arrow or a page dot with nothing behind it.
pub const TEAL_DARK: u16 = rgb565(1, 4, 2);
/// A teal button's face, #216173.
pub const TEAL_BUTTON: u16 = rgb565(4, 24, 14);
/// A destructive button's face, dark red.
pub const RED_BUTTON: u16 = rgb565(12, 0, 0);
/// A hold filling a destructive button: full red.
pub const RED: u16 = rgb565(31, 0, 0);
/// An accepting button's face, dark green.
pub const GREEN_BUTTON: u16 = rgb565(0, 40, 0);
/// A mark that needs noticing: a passphrase on a seed.
pub const ORANGE: u16 = rgb565(31, 35, 0);
/// Danger red: the title of something that failed.
pub const DANGER: u16 = rgb565(28, 8, 2);
/// Warning amber: the backup warning's title and rule.
pub const AMBER: u16 = rgb565(31, 24, 0);
/// Warning orange: the lines of a warning that matter most.
pub const WARN: u16 = rgb565(31, 20, 0);
/// A dimmed key's face, edge and label: a key not taken where it is.
pub const SHADOW_FACE: u16 = rgb565(2, 4, 2);
pub const SHADOW_EDGE: u16 = rgb565(3, 6, 3);
pub const SHADOW_TEXT: u16 = rgb565(6, 12, 6);
/// A dark face under a teal edge: the backup warning's button.
pub const TEAL_FACE: u16 = rgb565(2, 8, 2);

/// `fg` over `bg`, `alpha` from 0 (all `bg`) to 255 (all `fg`), per
/// channel and rounded; 0 and 255 are exact.
pub const fn blend(bg: u16, fg: u16, alpha: u8) -> u16 {
    match alpha {
        0 => bg,
        255 => fg,
        _ => {
            let a = alpha as u32;
            let na = 255 - a;
            let (bg, fg) = (bg as u32, fg as u32);
            let r = (((fg >> 11) & 0x1F) * a + ((bg >> 11) & 0x1F) * na + 127) / 255;
            let g = (((fg >> 5) & 0x3F) * a + ((bg >> 5) & 0x3F) * na + 127) / 255;
            let b = ((fg & 0x1F) * a + (bg & 0x1F) * na + 127) / 255;
            ((r << 11) | (g << 5) | b) as u16
        }
    }
}
