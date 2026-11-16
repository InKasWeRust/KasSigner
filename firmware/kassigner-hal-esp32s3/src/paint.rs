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

//! What both units draw the same way: the viewfinder's grey pixel. Which
//! frame row lands on which panel row is the camera's, in each unit's own
//! module; drawing a code is `kassigner_fw::paint`'s.

/// Black and white, RGB565.
pub const BLACK: u16 = 0x0000;
pub const WHITE: u16 = 0xFFFF;

/// A luminance byte as neutral grey, dithered over a 2x2 cell.
///
/// RGB565 gives green six bits and red and blue five, so a luminance byte
/// lands between levels, and 31 and 63 do not divide alike. Rounding each
/// channel to its nearest level shows 32 visible steps; rounding green on
/// its own finer grid misses red and blue by a few parts in 255, one way or
/// the other by tone, which shows as magenta and green patches.
///
/// So each channel keeps a quarter-level of precision, and where the pixel
/// sits in a 2x2 cell decides the fraction (an ordered dither). All three
/// channels use the same threshold, so the ramp climbs in quarter steps and
/// stays neutral.
///
/// `x` and `y_pos` are the pixel's own coordinates.
pub const fn grey(y: u8, x: u16, y_pos: u16) -> u16 {
    // The 2x2 Bayer matrix, as thresholds in quarters.
    let threshold = match (y_pos & 1, x & 1) {
        (0, 0) => 0,
        (0, _) => 2,
        (_, 0) => 3,
        (_, _) => 1,
    };
    let v = y as u16;
    let five4 = (v * 31 * 4 + 127) / 255;
    let six4 = (v * 63 * 4 + 127) / 255;
    let five = (five4 >> 2) + if (five4 & 3) > threshold { 1 } else { 0 };
    let six = (six4 >> 2) + if (six4 & 3) > threshold { 1 } else { 0 };
    let five = if five > 31 { 31 } else { five };

    // Green follows red and blue: twice their level or half a step above,
    // and zero when they are zero. On its own rounding it lights pixels they
    // cannot (green specks on black) and drifts from them elsewhere (the
    // patches).
    let floor = five * 2;
    let six = if five == 0 {
        0
    } else if six < floor {
        floor
    } else if six > floor + 1 {
        floor + 1
    } else {
        six
    };
    (five << 11) | (six << 5) | five
}
