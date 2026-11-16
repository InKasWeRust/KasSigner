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

//! Drawing over the `Display` trait that every board shares: a QR code,
//! black on white, and the two colours.
//!
//! A drawn code can be a SeedQR, and the panel path under it is the deepest
//! in a seed flow: the binary notes that depth for the stack scrub, then
//! calls [`draw_code`].

use kassigner_hal::display::{Display, Rect, Size};

/// Black and white, RGB565.
pub const BLACK: u16 = 0x0000;
/// White, RGB565.
pub const WHITE: u16 = 0xFFFF;

/// Draw a code centred on a white square the panel's short side wide, with
/// at least three and a half modules of white round it (see `place`). The
/// rest of the panel is black, so the square is the whole quiet zone.
pub fn draw_code<D: Display>(lcd: &mut D, code: &kassigner_qr::encode::QrMatrix, margin: u16) {
    let size = lcd.size();
    let short = size.width.min(size.height);
    let (x0, target) = place(size, code, margin, false);
    // A true square: white only under the code and its margin, the panel's
    // longer sides black.
    let (sx, sy) = ((size.width - short) / 2, (size.height - short) / 2);
    let _ = lcd.clear(BLACK);
    let _ = lcd.fill(Rect::new(sx, sy, short, short), WHITE);
    modules(lcd, code, x0, target);
}

/// `code` at the panel's left, on a white square the panel's height wide,
/// the rest black for the frame counter beside it: the layout for a code in
/// frames. On a landscape panel the height limits a code, so its modules are
/// as large as [`draw_code`]'s.
pub fn draw_code_left<D: Display>(lcd: &mut D, code: &kassigner_qr::encode::QrMatrix, margin: u16) {
    let size = lcd.size();
    let square = size.height.min(size.width);
    let (x0, target) = place(size, code, margin, true);
    let _ = lcd.fill(Rect::new(0, 0, square, size.height), WHITE);
    let _ = lcd.fill(
        Rect::new(square, 0, size.width - square, size.height),
        BLACK,
    );
    modules(lcd, code, x0, target);
}

/// The next frame of a code in frames, over the last, where [`draw_code`]
/// (`left` false) or [`draw_code_left`] put it: only its modules, each row
/// whole. The white square is already there, so nothing is cleared and the
/// panel never flashes white between frames.
pub fn code_again<D: Display>(
    lcd: &mut D,
    code: &kassigner_qr::encode::QrMatrix,
    margin: u16,
    left: bool,
) {
    let (x0, target) = place(lcd.size(), code, margin, left);
    modules(lcd, code, x0, target);
}

/// White round every code, in half modules: three and a half modules.
///
/// The most a version 9, the densest code, has room for on the smallest
/// panel (the S3s' 240 pixels) with four-pixel modules: 212 pixels of code,
/// 14 of white each side. ISO 18004's four would make those modules 3.92
/// pixels, and from 3.8 to 3.99 pixels a module the camera's decoder misses
/// a code even off a perfect image of the panel, while at four and over it
/// reads every one. One rule for every code and both panels.
const QUIET_HALVES: u32 = 7;

/// Where a code goes: its left edge and its side, centred, or in the square
/// at the left when `left`.
///
/// As large as the panel's shorter side allows with [`QUIET_HALVES`] half
/// modules of white on every side and at least `margin` pixels; the margin
/// alone can be under one module of a version-1 code (a compact SeedQR).
/// The side is even, so the white either side is the same.
fn place(size: Size, code: &kassigner_qr::encode::QrMatrix, margin: u16, left: bool) -> (u16, u16) {
    let short = size.width.min(size.height);
    let n = u32::from(code.size);
    let fits = u32::from(short.saturating_sub(margin * 2)) & !1;
    let quiet = (u32::from(short) * 2 * n / (2 * n + 2 * QUIET_HALVES)) & !1;
    let target = (quiet.min(fits).max(n)) as u16;
    let x0 = if left {
        (short - target) / 2
    } else {
        (size.width - target) / 2
    };
    (x0, target)
}

/// Pixels of a code's row painted at once: the shorter side of the largest
/// panel a unit has, the P4's 320, so a row is one blit on every board. A
/// wider code goes in pieces, never past the buffer.
const ROW_PIECE: usize = 320;

/// The modules of `code`, `target` pixels a side from `x0`, centred down
/// the panel, a row at a time, each in pieces of at most [`ROW_PIECE`].
fn modules<D: Display>(lcd: &mut D, code: &kassigner_qr::encode::QrMatrix, x0: u16, target: u16) {
    let size = lcd.size();
    let y0 = (size.height - target) / 2;
    let side = u32::from(code.size);

    let mut line = [WHITE; ROW_PIECE];
    for py in 0..target {
        // Which module row this pixel row falls in.
        let my = (u32::from(py) * side / u32::from(target)) as u8;
        let mut from = 0u16;
        while from < target {
            let n = (target - from).min(ROW_PIECE as u16);
            let piece = &mut line[..usize::from(n)];
            for (k, slot) in piece.iter_mut().enumerate() {
                let px = u32::from(from) + k as u32;
                let mx = (px * side / u32::from(target)) as u8;
                *slot = if code.get(mx, my) { BLACK } else { WHITE };
            }
            let _ = lcd.blit(Rect::new(x0 + from, y0 + py, n, 1), piece);
            from += n;
        }
    }
}
