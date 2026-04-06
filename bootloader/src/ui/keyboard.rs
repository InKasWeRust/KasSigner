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

// ui/keyboard.rs — Unified keyboard: same layout for all modes
//
// Full mode: all keys active, 4 page layers
// Alpha mode: same layout but numbers/symbols/space shadowed (gray)
// Hex mode: same layout but only 0-9 A-F active
// All modes share identical key positions for visual consistency.

use embedded_graphics::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle, RoundedRectangle, CornerRadii, Line};
use embedded_graphics::image::Image;
use embedded_iconoir::prelude::*;
use embedded_iconoir::icons::size24px;
use crate::hw::display::*;

const SW: i32 = 320;
const KC: u32 = 4;

#[derive(Clone, Copy, PartialEq)]
pub enum KeyboardMode { Alpha, Full, Hex, Numeric }

#[derive(Clone, Copy, PartialEq)]
pub enum KeyAction { None, Char(u8), Backspace, Space, Ok, Cancel, Page, CursorLeft, CursorRight }

// ═══════════════════════════════════════════════════════════════
// Shared layout constants (used by ALL modes)
// ═══════════════════════════════════════════════════════════════

const KW: u32 = 33;   // key width
const KH: u32 = 34;   // key height (full mode)
const KH_S: u32 = 28; // key height (compact mode — Alpha/Hex bottom row)
const KG: i32 = 2;    // gap

// Full mode Y positions (keyboard fills from y=80)
const F_RY: [i32; 3] = [80, 118, 156];
const F_AY: i32 = 194;
const F_AH: u32 = 38;

// Compact mode Y positions (keyboard pushed down, thinner bottom row)
const C_RY: [i32; 3] = [96, 130, 164];
const C_AY: i32 = 196;
const C_AH: u32 = 32;

const DEL_W: u32 = 50;
const OK_W: u32 = 50;
const ARR_W: u32 = 38; // cursor arrow button width

// Shadow color for inactive keys
const SHADOW_BG: Rgb565 = Rgb565::new(0b00010, 0b000100, 0b00010);  // very dark gray
const SHADOW_BORDER: Rgb565 = Rgb565::new(0b00011, 0b000110, 0b00011); // slightly lighter
const SHADOW_TEXT: Rgb565 = Rgb565::new(0b00110, 0b001100, 0b00110); // dim text

// ═══════════════════════════════════════════════════════════════
// Key data — always page 0 layout for non-Full modes
// ═══════════════════════════════════════════════════════════════

fn rows_for_page(page: u8) -> [&'static [u8]; 3] {
    match page {
        0 => [b"abcdefghi", b"jklmnopqr", b"stuvwxyz"],
        1 => [b"ABCDEFGHI", b"JKLMNOPQR", b"STUVWXYZ"],
        2 => [b"123456789", b"0!@#$%^&*", b"()-_=+.,"],
        3 => [b"?/\\|~`<>;", b"\"'{}[]:-!", b"@#$%^&*+"],
        _ => [b"123456789", b" 0ABCDEF ", b"        "],
    }
}

fn page_label(page: u8) -> &'static str {
    match page { 0 => "Aa", 1 => "#", 2 => "@", _ => "ab" }
}

/// Hex mode uses a special page (page 99) that shows 0-9 and A-F
const HEX_PAGE: u8 = 99;

/// Check if a character is active in the given mode
fn is_active(ch: u8, mode: KeyboardMode) -> bool {
    if ch == b' ' { return false; } // space placeholder = always inactive
    match mode {
        KeyboardMode::Full => true,
        KeyboardMode::Alpha => ch.is_ascii_lowercase(),
        KeyboardMode::Hex => ch.is_ascii_digit() || (b'A'..=b'F').contains(&ch),
        KeyboardMode::Numeric => ch.is_ascii_digit(),
    }
}

/// Is the page key active in this mode?
fn page_active(mode: KeyboardMode) -> bool { matches!(mode, KeyboardMode::Full) }

/// Is the space bar active in this mode?
fn space_active(mode: KeyboardMode) -> bool { matches!(mode, KeyboardMode::Full) }

/// Use compact (thinner) layout?
fn is_compact(mode: KeyboardMode) -> bool {
    matches!(mode, KeyboardMode::Alpha)
}

// ═══════════════════════════════════════════════════════════════
// Drawing
// ═══════════════════════════════════════════════════════════════

pub fn draw_keyboard(d: &mut impl DrawTarget<Color = Rgb565>, mode: KeyboardMode, page: u8) {
    let kc = CornerRadii::new(Size::new(KC, KC));
    let bc = CornerRadii::new(Size::new(5, 5));
    let compact = is_compact(mode);
    let ry = if compact { C_RY } else { F_RY };
    let kh = if compact { KH_S } else { KH };
    let ay = if compact { C_AY } else { F_AY };
    let ah = if compact { C_AH } else { F_AH };

    // Select which page to display
    let draw_page = match mode {
        KeyboardMode::Full => page,
        KeyboardMode::Hex => HEX_PAGE,  // special layout with 0-9 + A-F
        _ => 0,  // Alpha, Numeric show lowercase page
    };
    let rows = rows_for_page(draw_page);

    // ── Rows 1 & 2 ──
    for ri in 0..2usize {
        let rc = rows[ri];
        let n = rc.len() as i32;
        let tw = n * (KW as i32 + KG) - KG;
        let x0 = (SW - tw) / 2;
        for (ci, &ch) in rc.iter().enumerate() {
            let kx = x0 + (ci as i32) * (KW as i32 + KG);
            if is_active(ch, mode) {
                draw_key(d, kx, ry[ri], KW, kh, ch, kc, COLOR_CARD, COLOR_CARD_BORDER, COLOR_TEXT);
            } else {
                draw_key(d, kx, ry[ri], KW, kh, ch, kc, SHADOW_BG, SHADOW_BORDER, SHADOW_TEXT);
            }
        }
    }

    // ── Row 3: [PAGE] + N keys ──
    let r3 = rows[2];
    let n3 = r3.len() as i32;
    let lw = n3 * (KW as i32 + KG) - KG;
    let tot = KW as i32 + KG + lw;
    let x0 = (SW - tot) / 2;

    // Page key
    if page_active(mode) {
        if draw_page == 0 {
            draw_shift_icon(d, x0, ry[2], KW, kh, bc);
        } else {
            let pl = page_label(draw_page);
            let pr = Rectangle::new(Point::new(x0, ry[2]), Size::new(KW, kh));
            RoundedRectangle::new(pr, bc).into_styled(PrimitiveStyle::with_fill(COLOR_BG)).draw(d).ok();
            RoundedRectangle::new(pr, bc).into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2)).draw(d).ok();
            let pw = measure_header(pl);
            draw_oswald_header(d, pl, x0 + (KW as i32 - pw) / 2, ry[2] + kh as i32 - 8, KASPA_TEAL);
        }
    } else {
        // Shadow page key
        let pr = Rectangle::new(Point::new(x0, ry[2]), Size::new(KW, kh));
        RoundedRectangle::new(pr, bc).into_styled(PrimitiveStyle::with_fill(SHADOW_BG)).draw(d).ok();
        RoundedRectangle::new(pr, bc).into_styled(PrimitiveStyle::with_stroke(SHADOW_BORDER, 1)).draw(d).ok();
    }

    // Letter keys in row 3
    let lx = x0 + KW as i32 + KG;
    for (ci, &ch) in r3.iter().enumerate() {
        let kx = lx + (ci as i32) * (KW as i32 + KG);
        if is_active(ch, mode) {
            draw_key(d, kx, ry[2], KW, kh, ch, kc, COLOR_CARD, COLOR_CARD_BORDER, COLOR_TEXT);
        } else {
            draw_key(d, kx, ry[2], KW, kh, ch, kc, SHADOW_BG, SHADOW_BORDER, SHADOW_TEXT);
        }
    }

    // ── Action row: [DEL] [◀] [SPACE] [▶] [OK] ──
    let sw = SW - 4 - DEL_W as i32 - KG - ARR_W as i32 - KG - ARR_W as i32 - KG - OK_W as i32 - KG;
    draw_del_icon(d, 2, ay, DEL_W, ah, bc);

    // ◀ cursor left button — iconoir ArrowLeft
    let lax = 2 + DEL_W as i32 + KG;
    {
        let r = Rectangle::new(Point::new(lax, ay), Size::new(ARR_W, ah));
        RoundedRectangle::new(r, bc).into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(d).ok();
        RoundedRectangle::new(r, bc).into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1)).draw(d).ok();
        let icon = size24px::navigation::ArrowLeft::new(KASPA_TEAL);
        let ix = lax + (ARR_W as i32 - 24) / 2;
        let iy = ay + (ah as i32 - 24) / 2;
        Image::new(&icon, Point::new(ix, iy)).draw(d).ok();
    }

    // Space bar
    let sx = lax + ARR_W as i32 + KG;
    if space_active(mode) {
        draw_btn(d, sx, ay, sw as u32, ah, "SPACE",
                 COLOR_CARD, COLOR_CARD_BORDER, COLOR_TEXT_DIM, bc);
    } else {
        // Shadow space bar
        let sr = Rectangle::new(
            Point::new(sx, ay),
            Size::new(sw as u32, ah));
        RoundedRectangle::new(sr, bc).into_styled(PrimitiveStyle::with_fill(SHADOW_BG)).draw(d).ok();
        RoundedRectangle::new(sr, bc).into_styled(PrimitiveStyle::with_stroke(SHADOW_BORDER, 1)).draw(d).ok();
        let slw = measure_18("SPACE");
        draw_lato_18(d, "SPACE", sx + (sw - slw) / 2,
                     ay + (ah as i32 + 15) / 2, SHADOW_TEXT);
    }

    // ▶ cursor right button — iconoir ArrowRight
    let rax = sx + sw + KG;
    {
        let r = Rectangle::new(Point::new(rax, ay), Size::new(ARR_W, ah));
        RoundedRectangle::new(r, bc).into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(d).ok();
        RoundedRectangle::new(r, bc).into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1)).draw(d).ok();
        let icon = size24px::navigation::ArrowRight::new(KASPA_TEAL);
        let ix = rax + (ARR_W as i32 - 24) / 2;
        let iy = ay + (ah as i32 - 24) / 2;
        Image::new(&icon, Point::new(ix, iy)).draw(d).ok();
    }

    let ox = rax + ARR_W as i32 + KG;
    draw_btn(d, ox, ay, OK_W, ah, "OK",
             COLOR_GREEN_BTN, COLOR_GREEN_BTN, COLOR_TEXT, bc);
}

// ═══════════════════════════════════════════════════════════════
// Hit-testing (same for all modes — only active keys respond)
// ═══════════════════════════════════════════════════════════════

pub fn hit_test(x: u16, y: u16, mode: KeyboardMode, page: u8) -> KeyAction {
    let xi = x as i32;
    let yi = y as i32;
    let compact = is_compact(mode);
    let ry = if compact { C_RY } else { F_RY };
    let kh = if compact { KH_S } else { KH };
    let ay = if compact { C_AY } else { F_AY };
    let _ah = if compact { C_AH } else { F_AH };

    let draw_page = match mode {
        KeyboardMode::Full => page,
        KeyboardMode::Hex => HEX_PAGE,
        _ => 0,
    };
    let rows = rows_for_page(draw_page);

    // ── Rows 1 & 2 ──
    for ri in 0..2usize {
        let rc = rows[ri];
        if yi >= ry[ri] && yi < ry[ri] + kh as i32 {
            let n = rc.len() as i32;
            let tw = n * (KW as i32 + KG) - KG;
            let x0 = (SW - tw) / 2;
            for (ci, &ch) in rc.iter().enumerate() {
                let kx = x0 + (ci as i32) * (KW as i32 + KG);
                if xi >= kx && xi < kx + KW as i32 {
                    if is_active(ch, mode) { return KeyAction::Char(ch); }
                    return KeyAction::None; // shadow key — no action
                }
            }
        }
    }

    // ── Row 3 ──
    let r3 = rows[2];
    if yi >= ry[2] && yi < ry[2] + kh as i32 {
        let n3 = r3.len() as i32;
        let lw = n3 * (KW as i32 + KG) - KG;
        let tot = KW as i32 + KG + lw;
        let x0 = (SW - tot) / 2;

        // Page key
        if xi >= x0 && xi < x0 + KW as i32 {
            if page_active(mode) { return KeyAction::Page; }
            return KeyAction::None;
        }

        // Letter keys
        let lx = x0 + KW as i32 + KG;
        for (ci, &ch) in r3.iter().enumerate() {
            let kx = lx + (ci as i32) * (KW as i32 + KG);
            if xi >= kx && xi < kx + KW as i32 {
                if is_active(ch, mode) { return KeyAction::Char(ch); }
                return KeyAction::None;
            }
        }
    }

    // ── Action row: [DEL] [◀] [SPACE] [▶] [OK] — expanded zones ──
    if yi >= ay - 4 {
        let lax = 2 + DEL_W as i32 + KG;
        let sw = SW - 4 - DEL_W as i32 - KG - ARR_W as i32 - KG - ARR_W as i32 - KG - OK_W as i32 - KG;
        let sx = lax + ARR_W as i32 + KG;
        let rax = sx + sw + KG;
        let ox = rax + ARR_W as i32 + KG;

        if xi < lax { return KeyAction::Backspace; }
        if xi >= lax && xi < lax + ARR_W as i32 { return KeyAction::CursorLeft; }
        if xi >= sx && xi < sx + sw {
            if space_active(mode) { return KeyAction::Space; }
            return KeyAction::None;
        }
        if xi >= rax && xi < rax + ARR_W as i32 { return KeyAction::CursorRight; }
        if xi >= ox { return KeyAction::Ok; }
    }

    KeyAction::None
}

// ═══════════════════════════════════════════════════════════════
// Public helpers
// ═══════════════════════════════════════════════════════════════

pub fn has_space(mode: KeyboardMode) -> bool { space_active(mode) }
// ═══════════════════════════════════════════════════════════════
// Drawing helpers
// ═══════════════════════════════════════════════════════════════

fn draw_row(d: &mut impl DrawTarget<Color = Rgb565>,
    chars: &[u8], y: i32, kw: u32, kh: u32, gap: i32, corner: CornerRadii)
{
    let n = chars.len() as i32;
    let tw = n * (kw as i32 + gap) - gap;
    let x0 = (SW - tw) / 2;
    for (c, &ch) in chars.iter().enumerate() {
        let kx = x0 + (c as i32) * (kw as i32 + gap);
        draw_key(d, kx, y, kw, kh, ch, corner, COLOR_CARD, COLOR_CARD_BORDER, COLOR_TEXT);
    }
}

fn draw_key(d: &mut impl DrawTarget<Color = Rgb565>,
    x: i32, y: i32, w: u32, h: u32, ch: u8,
    corner: CornerRadii, bg: Rgb565, border: Rgb565, tc: Rgb565)
{
    let r = Rectangle::new(Point::new(x, y), Size::new(w, h));
    RoundedRectangle::new(r, corner).into_styled(PrimitiveStyle::with_fill(bg)).draw(d).ok();
    RoundedRectangle::new(r, corner).into_styled(PrimitiveStyle::with_stroke(border, 1)).draw(d).ok();
    let mut cb = [0u8; 1];
    cb[0] = ch;
    if let Ok(s) = core::str::from_utf8(&cb) {
        let cw = measure_22(s);
        // LATO_22: ascent=19. Center: baseline = y + (h + 19) / 2
        draw_lato_22(d, s, x + (w as i32 - cw) / 2, y + (h as i32 + 19) / 2, tc);
    }
}

fn draw_btn(d: &mut impl DrawTarget<Color = Rgb565>,
    x: i32, y: i32, w: u32, h: u32, label: &str,
    bg: Rgb565, border: Rgb565, tc: Rgb565, corner: CornerRadii)
{
    let r = Rectangle::new(Point::new(x, y), Size::new(w, h));
    RoundedRectangle::new(r, corner).into_styled(PrimitiveStyle::with_fill(bg)).draw(d).ok();
    if bg != border {
        RoundedRectangle::new(r, corner).into_styled(PrimitiveStyle::with_stroke(border, 1)).draw(d).ok();
    }
    // Lato 18 for button labels
    let lw = measure_18(label);
    draw_lato_18(d, label, x + (w as i32 - lw) / 2, y + (h as i32 + 15) / 2, tc);
}

/// Draw DEL button with backspace icon centered
fn draw_del_icon(d: &mut impl DrawTarget<Color = Rgb565>,
    x: i32, y: i32, w: u32, h: u32, corner: CornerRadii)
{
    use embedded_graphics::image::{Image, ImageRawLE};
    let r = Rectangle::new(Point::new(x, y), Size::new(w, h));
    RoundedRectangle::new(r, corner).into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN)).draw(d).ok();
    let iw = crate::hw::icon_data::ICON_DEL_W as i32;
    let ih = crate::hw::icon_data::ICON_DEL_H as i32;
    let ix = x + (w as i32 - iw) / 2;
    let iy = y + (h as i32 - ih) / 2;
    let raw: ImageRawLE<Rgb565> = ImageRawLE::new(crate::hw::icon_data::ICON_DEL, iw as u32);
    Image::new(&raw, Point::new(ix, iy)).draw(d).ok();
}

/// Draw SHIFT icon (page key page 0) — black bg, teal border + icon
fn draw_shift_icon(d: &mut impl DrawTarget<Color = Rgb565>,
    x: i32, y: i32, w: u32, h: u32, corner: CornerRadii)
{
    use embedded_graphics::image::{Image, ImageRawLE};
    let r = Rectangle::new(Point::new(x, y), Size::new(w, h));
    RoundedRectangle::new(r, corner).into_styled(PrimitiveStyle::with_fill(COLOR_BG)).draw(d).ok();
    RoundedRectangle::new(r, corner).into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2)).draw(d).ok();
    let iw = crate::hw::icon_data::ICON_SHIFT_W as i32;
    let ih = crate::hw::icon_data::ICON_SHIFT_H as i32;
    let ix = x + (w as i32 - iw) / 2;
    let iy = y + (h as i32 - ih) / 2;
    let raw: ImageRawLE<Rgb565> = ImageRawLE::new(crate::hw::icon_data::ICON_SHIFT, iw as u32);
    Image::new(&raw, Point::new(ix, iy)).draw(d).ok();
}
