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


// hw/display.rs — ILI9342C display driver, BootDisplay struct, core draw primitives

use esp_hal::delay::Delay;
use esp_hal::spi::master::Spi;
use esp_hal::gpio::Output;

use embedded_hal_bus::spi::ExclusiveDevice;
use mipidsi::{
    Builder,
    interface::SpiInterface,
    models::ILI9342CRgb565,
    options::{Orientation, Rotation},
};
use embedded_graphics::{
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle, RoundedRectangle, Circle, CornerRadii},
    image::Image,
};
use static_cell::StaticCell;

use embedded_iconoir::prelude::*;
use embedded_iconoir::icons::size24px;

// ═══════════════════════════════════════════════════════════════
// Display Constants

// AXP2101 PMU I2C address
// AW9523B IO Expander I2C address

// ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════

// Voltage = 500mV + (value * 100mV), so 0x1C = 500 + 28*100 = 3300mV
// Bit 7 = DLDO1 enable

// ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════════
// Display Constants
// ═══════════════════════════════════════════════════════════════

/// Display width in pixels
pub const DISPLAY_W: u32 = 320;
/// Display height in pixels
pub const DISPLAY_H: u32 = 240;

// KasSigner color palette (Kaspa brand: ~#49EACB)
// Display uses Bgr color order (handled by mipidsi driver)
// ── Official Kaspa Brand Colors ──────────────────────────────
// Primary:   #70C7BA  RGB(112,199,186) — main teal
// Dark:      #231F20  RGB(35,31,32)    — near-black
// Gray:      #B6B6B6  RGB(182,182,182) — secondary text
// Accent:    #49EACB  RGB(73,234,203)  — bright teal highlights
// ─────────────────────────────────────────────────────────────
pub(crate) const KASPA_TEAL: Rgb565 = Rgb565::new(0b01110, 0b110001, 0b10111);   // #70C7BA — primary brand teal
pub(crate) const KASPA_ACCENT: Rgb565 = Rgb565::new(0b01001, 0b111010, 0b11001); // #49EACB — bright accent teal
pub(crate) const COLOR_BG: Rgb565 = Rgb565::BLACK;                                        // pure black — cleanest on LCD
pub(crate) const COLOR_CARD: Rgb565 = Rgb565::new(0b00001, 0b000010, 0b00001);   // #080808 — neutral near-black
pub(crate) const COLOR_CARD_BORDER: Rgb565 = Rgb565::new(0b01010, 0b010100, 0b01010); // #505050 — subtle border
pub(crate) const COLOR_TEXT: Rgb565 = Rgb565::new(0b11111, 0b111111, 0b11111);    // #FFFFFF — white
pub(crate) const COLOR_TEXT_DIM: Rgb565 = Rgb565::new(0b10110, 0b101101, 0b10110); // #B6B6B6 — official gray
pub(crate) const COLOR_DANGER: Rgb565 = Rgb565::new(0b11100, 0b001000, 0b00010);  // red
pub(crate) const COLOR_ORANGE: Rgb565 = Rgb565::new(0b11111, 0b100011, 0b00000);  // orange
// Button colors
pub(crate) const COLOR_GREEN_BTN: Rgb565 = Rgb565::new(0b00000, 0b101000, 0b00000); // dark green
pub(crate) const COLOR_RED_BTN: Rgb565 = Rgb565::new(0b01100, 0b000000, 0b00000); // dark red
#[allow(dead_code)]
pub(crate) const COLOR_ERR_TEXT: Rgb565 = Rgb565::new(0b11111, 0b000000, 0b00000); // bright red
pub(crate) const COLOR_HINT: Rgb565 = Rgb565::new(0b01100, 0b011000, 0b01100); // dim gray for hints

// Static SPI buffer — mipidsi needs a buffer for batched writes
static SPI_BUF: StaticCell<[u8; 512]> = StaticCell::new();

// ── Lato proportional font helpers ──────────────────────────────
use crate::ui::prop_fonts;

/// Draw text using Lato Bold 18px (titles)
pub(crate) fn draw_lato_title<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::LATO_BOLD_18_WIDTHS, &prop_fonts::LATO_BOLD_18_OFFSETS,
        &prop_fonts::LATO_BOLD_18_DATA, prop_fonts::LATO_BOLD_18_HEIGHT,
        prop_fonts::LATO_BOLD_18_ASCENT, prop_fonts::LATO_BOLD_18_FIRST, prop_fonts::LATO_BOLD_18_LAST)
}

/// Draw text using Lato Regular 15px (body)
pub(crate) fn draw_lato_body<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::LATO_15_WIDTHS, &prop_fonts::LATO_15_OFFSETS,
        &prop_fonts::LATO_15_DATA, prop_fonts::LATO_15_HEIGHT,
        prop_fonts::LATO_15_ASCENT, prop_fonts::LATO_15_FIRST, prop_fonts::LATO_15_LAST)
}

/// Draw text using Lato Regular 18px (input fields)
pub(crate) fn draw_lato_18<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::LATO_18_WIDTHS, &prop_fonts::LATO_18_OFFSETS,
        &prop_fonts::LATO_18_DATA, prop_fonts::LATO_18_HEIGHT,
        prop_fonts::LATO_18_ASCENT, prop_fonts::LATO_18_FIRST, prop_fonts::LATO_18_LAST)
}

/// Draw text using DejaVu Sans Regular ~22px (keyboard input text — clean, non-bold)
pub(crate) fn draw_lato_22<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::LATO_22_WIDTHS, &prop_fonts::LATO_22_OFFSETS,
        &prop_fonts::LATO_22_DATA, prop_fonts::LATO_22_HEIGHT,
        prop_fonts::LATO_22_ASCENT, prop_fonts::LATO_22_FIRST, prop_fonts::LATO_22_LAST)
}

/// Lato-22 with opaque background — flicker-free for keyboard input redraw.
/// See `draw_prop_text_opaque` doc for rationale.
pub(crate) fn draw_lato_22_opaque<D: DrawTarget<Color = Rgb565>>(
    d: &mut D, text: &str, x: i32, y: i32, fg: Rgb565, bg: Rgb565,
) -> i32 {
    prop_fonts::draw_prop_text_opaque(d, text, x, y, fg, bg,
        &prop_fonts::LATO_22_WIDTHS, &prop_fonts::LATO_22_OFFSETS,
        &prop_fonts::LATO_22_DATA, prop_fonts::LATO_22_HEIGHT,
        prop_fonts::LATO_22_ASCENT, prop_fonts::LATO_22_FIRST, prop_fonts::LATO_22_LAST)
}

/// Draw text using Lato Regular 12px (hints)
pub(crate) fn draw_lato_hint<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::LATO_12_WIDTHS, &prop_fonts::LATO_12_OFFSETS,
        &prop_fonts::LATO_12_DATA, prop_fonts::LATO_12_HEIGHT,
        prop_fonts::LATO_12_ASCENT, prop_fonts::LATO_12_FIRST, prop_fonts::LATO_12_LAST)
}

/// Draw text using Rubik Bold 22px (headers)
pub(crate) fn draw_oswald_header<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::OSWALD_BOLD_22_WIDTHS, &prop_fonts::OSWALD_BOLD_22_OFFSETS,
        &prop_fonts::OSWALD_BOLD_22_DATA, prop_fonts::OSWALD_BOLD_22_HEIGHT,
        prop_fonts::OSWALD_BOLD_22_ASCENT, prop_fonts::OSWALD_BOLD_22_FIRST, prop_fonts::OSWALD_BOLD_22_LAST)
}

/// Draw text using Rubik Bold 26px (brand/logo ONLY)
pub(crate) fn draw_rubik_big<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::RUBIK_BOLD_26_WIDTHS, &prop_fonts::RUBIK_BOLD_26_OFFSETS,
        &prop_fonts::RUBIK_BOLD_26_DATA, prop_fonts::RUBIK_BOLD_26_HEIGHT,
        prop_fonts::RUBIK_BOLD_26_ASCENT, prop_fonts::RUBIK_BOLD_26_FIRST, prop_fonts::RUBIK_BOLD_26_LAST)
}

/// Draw text using Oswald SemiBold 16px (sub-headers)
pub(crate) fn draw_oswald_sub<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::OSWALD_SB_16_WIDTHS, &prop_fonts::OSWALD_SB_16_OFFSETS,
        &prop_fonts::OSWALD_SB_16_DATA, prop_fonts::OSWALD_SB_16_HEIGHT,
        prop_fonts::OSWALD_SB_16_ASCENT, prop_fonts::OSWALD_SB_16_FIRST, prop_fonts::OSWALD_SB_16_LAST)
}

/// Measure title text width
pub(crate) fn measure_title(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::LATO_BOLD_18_WIDTHS,
        prop_fonts::LATO_BOLD_18_FIRST, prop_fonts::LATO_BOLD_18_LAST, prop_fonts::LATO_BOLD_18_HEIGHT)
}

/// Measure body text width
pub(crate) fn measure_body(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::LATO_15_WIDTHS,
        prop_fonts::LATO_15_FIRST, prop_fonts::LATO_15_LAST, prop_fonts::LATO_15_HEIGHT)
}

/// Measure Lato Regular 18px text width
#[allow(dead_code)]
pub(crate) fn measure_18(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::LATO_18_WIDTHS,
        prop_fonts::LATO_18_FIRST, prop_fonts::LATO_18_LAST, prop_fonts::LATO_18_HEIGHT)
}

/// Measure DejaVu Sans 22px width
pub(crate) fn measure_22(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::LATO_22_WIDTHS,
        prop_fonts::LATO_22_FIRST, prop_fonts::LATO_22_LAST, prop_fonts::LATO_22_HEIGHT)
}

/// Measure Rubik header width
pub(crate) fn measure_header(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::OSWALD_BOLD_22_WIDTHS,
        prop_fonts::OSWALD_BOLD_22_FIRST, prop_fonts::OSWALD_BOLD_22_LAST, prop_fonts::OSWALD_BOLD_22_HEIGHT)
}

/// Measure Rubik big width (brand/logo)
pub(crate) fn measure_big(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::RUBIK_BOLD_26_WIDTHS,
        prop_fonts::RUBIK_BOLD_26_FIRST, prop_fonts::RUBIK_BOLD_26_LAST, prop_fonts::RUBIK_BOLD_26_HEIGHT)
}

/// Measure Oswald sub-header width
pub(crate) fn measure_sub(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::OSWALD_SB_16_WIDTHS,
        prop_fonts::OSWALD_SB_16_FIRST, prop_fonts::OSWALD_SB_16_LAST, prop_fonts::OSWALD_SB_16_HEIGHT)
}

/// Measure hint text width
pub(crate) fn measure_hint(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::LATO_12_WIDTHS,
        prop_fonts::LATO_12_FIRST, prop_fonts::LATO_12_LAST, prop_fonts::LATO_12_HEIGHT)
}

/// Draw a 24×24 Iconoir icon matching a menu label.
/// Matches on first few chars of the label to select an icon.
/// Falls back to a generic circle if no match.
pub(crate) fn draw_menu_icon<D: DrawTarget<Color = Rgb565>>(d: &mut D, label: &str, pos: Point) {
    let color = KASPA_TEAL;
    // Match by label prefix to pick the right icon
    macro_rules! draw_icon {
        ($icon_type:ty) => {{
            let icon = <$icon_type>::new(color);
            Image::new(&icon, pos).draw(d).ok();
        }};
    }
    match label {
        // Tools menu
        s if s.starts_with("New Seed") && !s.contains("Dice") => draw_icon!(size24px::photos_and_videos::Camera),
        s if s.starts_with("Dice")        => {
            // Custom dice-five: teal filled square with black dots
            let sz = 24u32;
            let corner = embedded_graphics::primitives::CornerRadii::new(
                embedded_graphics::geometry::Size::new(4, 4));
            embedded_graphics::primitives::RoundedRectangle::new(
                Rectangle::new(pos, embedded_graphics::geometry::Size::new(sz, sz)), corner
            ).into_styled(PrimitiveStyle::with_fill(KASPA_TEAL)).draw(d).ok();
            let cx = pos.x + sz as i32 / 2;
            let cy = pos.y + sz as i32 / 2;
            let dx = sz as i32 / 4;
            let dy = sz as i32 / 4;
            let r = 2u32;
            let black = COLOR_BG;
            for &(px, py) in &[(cx-dx,cy-dy),(cx+dx,cy-dy),(cx,cy),(cx-dx,cy+dy),(cx+dx,cy+dy)] {
                Circle::new(Point::new(px - r as i32, py - r as i32), r * 2 + 1)
                    .into_styled(PrimitiveStyle::with_fill(black)).draw(d).ok();
            }
        }
        s if s.starts_with("Import Words") => draw_icon!(size24px::actions::Download),
        s if s.starts_with("Calc Last")   => draw_icon!(size24px::editor::NumberedListRight),
        s if s.starts_with("BIP85")       => draw_icon!(size24px::git::GitFork),
        s if s.starts_with("Import Key") || s.starts_with("Import Raw")  => draw_icon!(size24px::security::Lock),
        s if s.starts_with("Import from") => draw_icon!(size24px::docs::AddFolder),
        s if s.starts_with("Create Multi")=> draw_icon!(size24px::users::Group),
        s if s.starts_with("Stego Imp")   => draw_icon!(size24px::actions::EyeOff),
        s if s.starts_with("Sign TX")     => draw_icon!(size24px::editor::EditPencil),
        s if s.starts_with("Sign Mess")   => draw_icon!(size24px::editor::EditPencil),
        // Export menu
        s if s.starts_with("Show Seed")   => draw_icon!(size24px::actions::OpenNewWindow),
        s if s.starts_with("Show as QR")  => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("Encrypt to")  => draw_icon!(size24px::actions::UploadSquare),
        s if s.starts_with("CompactSeed") => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("Standard Seed")=> draw_icon!(size24px::other::QrCode),
        s if s.starts_with("Plain Words") => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("QR Export")   => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("kpub")        => draw_icon!(size24px::finance::AppleWallet),
        s if s.starts_with("xprv")        => draw_icon!(size24px::security::Lock),
        s if s.starts_with("Seed Backup") => draw_icon!(size24px::actions::Upload),
        s if s.starts_with("Private Key") => draw_icon!(size24px::security::PasswordCursor),
        s if s.starts_with("Multisig A")  => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("Multisig D")  => draw_icon!(size24px::docs::Page),
        s if s.starts_with("Transaction") => draw_icon!(size24px::users::Group),
        s if s.starts_with("XPrv Backup") => draw_icon!(size24px::actions::UploadSquare),
        s if s.starts_with("JPEG Stego")  => draw_icon!(size24px::actions::EyeOff),
        // Settings menu
        s if s.starts_with("Display")     => draw_icon!(size24px::devices::Laptop),
        s if s.starts_with("Audio")       => draw_icon!(size24px::audio::SoundHigh),
        s if s.starts_with("SD Card")     => draw_icon!(size24px::devices::SaveFloppyDisk),
        s if s.starts_with("About")       => draw_icon!(size24px::actions::HelpCircle),
        // Fallback — small teal circle
        _ => {
            Circle::new(pos + Point::new(4, 4), 16)
                .into_styled(PrimitiveStyle::with_stroke(color, 1))
                .draw(d).ok();
        }
    }
}

/// Assess password strength for descriptor text.
/// Returns 0=weak, 1=fair, 2=strong.
pub(crate) fn password_strength(text: &str) -> u8 {
    let len = text.len();
    if len < 8 { return 0; }

    let bytes = text.as_bytes();
    let has_upper = bytes.iter().any(|b| *b >= b'A' && *b <= b'Z');
    let has_lower = bytes.iter().any(|b| *b >= b'a' && *b <= b'z');
    let has_digit = bytes.iter().any(|b| *b >= b'0' && *b <= b'9');
    let has_space = bytes.contains(&b' ');
    let variety = has_upper as u8 + has_lower as u8 + has_digit as u8 + has_space as u8;

    // All same character?
    let all_same = bytes.iter().all(|b| *b == bytes[0]);
    if all_same { return 0; }

    if len >= 16 && variety >= 2 { return 2; }
    if len >= 12 { return if variety >= 2 { 2 } else { 1 }; }
    if variety >= 2 { return 1; }
    0
}

// ═══════════════════════════════════════════════════════════════
// PMU & IO Expander Init (raw I2C)
// ═══════════════════════════════════════════════════════════════

// Initialize AXP2101 PMU — enable power rails for CoreS3
// ═══════════════════════════════════════════════════════════════
// Display type alias
// ═══════════════════════════════════════════════════════════════

/// Full display type for M5Stack CoreS3 ILI9342C
pub(crate) type Ili9342Display<'a> = mipidsi::Display<
    SpiInterface<
        'a,
        ExclusiveDevice<Spi<'a, esp_hal::Blocking>, Output<'a>, embedded_hal_bus::spi::NoDelay>,
        Output<'a>,
    >,
    ILI9342CRgb565,
    Output<'a>,
>;

// ═══════════════════════════════════════════════════════════════
// TeeDisplay — writes to both real display and screenshot buffer
// ═══════════════════════════════════════════════════════════════

/// When the `screenshot` feature is enabled, TeeDisplay wraps the real display
/// and simultaneously copies all pixel writes to a PSRAM shadow buffer.
/// When disabled, BootDisplayTarget is just the raw Ili9342Display (zero overhead).
#[cfg(feature = "screenshot")]
pub struct TeeDisplay<'a> {
    pub(crate) real: Ili9342Display<'a>,
    pub(crate) shadow: *mut u8,  // PSRAM buffer (320*240*2 bytes), null if not active
    pub(crate) shadow_active: bool,
}

#[cfg(feature = "screenshot")]
impl<'a> TeeDisplay<'a> {
    pub fn new(real: Ili9342Display<'a>) -> Self {
        Self { real, shadow: core::ptr::null_mut(), shadow_active: false }
    }

    /// Enable shadow capture (call after PSRAM is ready)
    pub fn enable_shadow(&mut self) {
        if let Some(fb) = super::screenshot::fb_slice() {
            self.shadow = fb.as_mut_ptr();
            self.shadow_active = true;
        }
    }
}

#[cfg(feature = "screenshot")]
impl<'a> embedded_graphics::prelude::DrawTarget for TeeDisplay<'a> {
    type Color = Rgb565;
    type Error = <Ili9342Display<'a> as embedded_graphics::prelude::DrawTarget>::Error;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = embedded_graphics::prelude::Pixel<Self::Color>>,
    {
        use embedded_graphics::pixelcolor::raw::RawU16;

        if self.shadow_active && !self.shadow.is_null() {
            let px_vec: alloc::vec::Vec<embedded_graphics::prelude::Pixel<Rgb565>> =
                pixels.into_iter().collect();

            for &embedded_graphics::prelude::Pixel(point, color) in &px_vec {
                let x = point.x;
                let y = point.y;
                if (0..320).contains(&x) && (0..240).contains(&y) {
                    let idx = ((y as usize) * 320 + (x as usize)) * 2;
                    let raw = RawU16::from(color).into_inner();
                    unsafe {
                        *self.shadow.add(idx) = (raw >> 8) as u8;
                        *self.shadow.add(idx + 1) = (raw & 0xFF) as u8;
                    }
                }
            }

            self.real.draw_iter(px_vec.into_iter())
        } else {
            self.real.draw_iter(pixels)
        }
    }

    fn fill_contiguous<I>(&mut self, area: &embedded_graphics::primitives::Rectangle, colors: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Self::Color>,
    {
        use embedded_graphics::pixelcolor::raw::RawU16;

        if self.shadow_active && !self.shadow.is_null() {
            let color_vec: alloc::vec::Vec<Rgb565> = colors.into_iter().collect();

            // Write to shadow
            let mut px = area.top_left.x;
            let mut py = area.top_left.y;
            let x_end = area.top_left.x + area.size.width as i32;
            for &color in &color_vec {
                if (0..320).contains(&px) && (0..240).contains(&py) {
                    let idx = ((py as usize) * 320 + (px as usize)) * 2;
                    let raw = RawU16::from(color).into_inner();
                    unsafe {
                        *self.shadow.add(idx) = (raw >> 8) as u8;
                        *self.shadow.add(idx + 1) = (raw & 0xFF) as u8;
                    }
                }
                px += 1;
                if px >= x_end {
                    px = area.top_left.x;
                    py += 1;
                }
            }

            self.real.fill_contiguous(area, color_vec.into_iter())
        } else {
            self.real.fill_contiguous(area, colors)
        }
    }

    fn fill_solid(&mut self, area: &embedded_graphics::primitives::Rectangle, color: Self::Color) -> Result<(), Self::Error>
    {
        use embedded_graphics::pixelcolor::raw::RawU16;

        if self.shadow_active && !self.shadow.is_null() {
            let raw = RawU16::from(color).into_inner();
            let hi = (raw >> 8) as u8;
            let lo = (raw & 0xFF) as u8;
            let x_start = area.top_left.x.max(0) as usize;
            let y_start = area.top_left.y.max(0) as usize;
            let x_end = (area.top_left.x + area.size.width as i32).min(320) as usize;
            let y_end = (area.top_left.y + area.size.height as i32).min(240) as usize;
            for py in y_start..y_end {
                for px in x_start..x_end {
                    let idx = (py * 320 + px) * 2;
                    unsafe {
                        *self.shadow.add(idx) = hi;
                        *self.shadow.add(idx + 1) = lo;
                    }
                }
            }
        }
        self.real.fill_solid(area, color)
    }

    fn clear(&mut self, color: Self::Color) -> Result<(), Self::Error>
    {
        use embedded_graphics::pixelcolor::raw::RawU16;

        if self.shadow_active && !self.shadow.is_null() {
            let raw = RawU16::from(color).into_inner();
            let hi = (raw >> 8) as u8;
            let lo = (raw & 0xFF) as u8;
            let fb = unsafe { core::slice::from_raw_parts_mut(self.shadow, 320 * 240 * 2) };
            for i in (0..fb.len()).step_by(2) {
                fb[i] = hi;
                fb[i + 1] = lo;
            }
        }
        self.real.clear(color)
    }
}

#[cfg(feature = "screenshot")]
impl<'a> embedded_graphics::prelude::OriginDimensions for TeeDisplay<'a> {
    fn size(&self) -> embedded_graphics::prelude::Size {
        self.real.size()
    }
}

/// The type used as the display field in BootDisplay.
#[cfg(feature = "screenshot")]
pub(crate) type BootDisplayTarget<'a> = TeeDisplay<'a>;
#[cfg(not(feature = "screenshot"))]
pub(crate) type BootDisplayTarget<'a> = Ili9342Display<'a>;

// ═══════════════════════════════════════════════════════════════
// BootDisplay wrapper
// ═══════════════════════════════════════════════════════════════

/// BootDisplay for M5Stack CoreS3 — 320x240 IPS color LCD
pub struct BootDisplay<'a> {
    pub(crate) display: BootDisplayTarget<'a>,
}

impl<'a> BootDisplay<'a> {
    /// Create display from already-initialized SPI and GPIO pins.
    /// IMPORTANT: Call init_axp2101() and init_aw9523b() BEFORE this!
    pub fn new(
        spi: Spi<'a, esp_hal::Blocking>,
        cs_pin: Output<'a>,
        dc_pin: Output<'a>,
        reset_pin: Output<'a>,
        delay: &mut Delay,
    ) -> Result<Self, &'static str> {
        let buffer: &'a mut [u8; 512] = SPI_BUF.init([0u8; 512]);

        let spi_dev = ExclusiveDevice::new_no_delay(spi, cs_pin)
            .map_err(|_| "Failed to create SPI device")?;

        let spi_iface = SpiInterface::new(spi_dev, dc_pin, buffer);

        let mut display = Builder::new(ILI9342CRgb565, spi_iface)
            .reset_pin(reset_pin)
            .color_order(mipidsi::options::ColorOrder::Bgr)
            .invert_colors(mipidsi::options::ColorInversion::Inverted)
            .init(delay)
            .map_err(|_| "Failed to init ILI9342C")?;

        // Orientation: CoreS3 display is mounted landscape by default
        display
            .set_orientation(Orientation::default().rotate(Rotation::Deg180))
            .map_err(|_| "Failed to set orientation")?;

        display
            .clear(COLOR_BG)
            .map_err(|_| "Failed to clear display")?;

        delay.delay_millis(100);

        #[cfg(feature = "screenshot")]
        let display = {
            let mut tee = TeeDisplay::new(display);
            tee.enable_shadow();
            tee
        };

        Ok(Self { display })
    }

    // ─── Boot sequence screens ──────────────────────────────────

    /// Show verification screen with version, hash, and status
    pub fn show_verification_screen(
        &mut self,
        version: &str,
        hash: &str,
        status: BootStatus,
    ) -> Result<(), &'static str> {
        use embedded_graphics::image::{Image, ImageRawLE};

        self.display.clear(COLOR_BG).map_err(|_| "Clear failed")?;

        // Kaspa coin logo 90x90, centered horizontally, top portion
        static KASCOIN: &[u8] = include_bytes!("../../assets/kascoin_90.raw");
        let raw_coin: ImageRawLE<Rgb565> = ImageRawLE::new(KASCOIN, 90);
        Image::new(&raw_coin, Point::new(115, 10))
            .draw(&mut self.display).ok();

        // Version — Lato Bold 18px, centered below coin
        let mut version_text = heapless::String::<48>::new();
        use core::fmt::Write;
        write!(&mut version_text, "Version: {}", version).ok();
        let vw = measure_title(version_text.as_str());
        draw_lato_title(&mut self.display, version_text.as_str(), (320 - vw) / 2, 125, COLOR_TEXT);

        // Hash — Lato Regular 15px, centered
        let mut hash_text = heapless::String::<48>::new();
        let hash_display = &hash[..core::cmp::min(16, hash.len())];
        write!(&mut hash_text, "Hash: {}", hash_display).ok();
        let hw = measure_body(hash_text.as_str());
        draw_lato_body(&mut self.display, hash_text.as_str(), (320 - hw) / 2, 155, COLOR_TEXT_DIM);

        // Status — Lato Bold 18px, centered, colored
        let status_text = match status {
            BootStatus::Verifying => "Verifying...",
            BootStatus::Valid => "Verified OK",
            BootStatus::Invalid => "INVALID!",
            BootStatus::Error => "ERROR!",
        };
        let status_color = match status {
            BootStatus::Valid => KASPA_TEAL,
            BootStatus::Invalid | BootStatus::Error => COLOR_DANGER,
            _ => COLOR_ORANGE,
        };
        let sw = measure_title(status_text);
        draw_lato_title(&mut self.display, status_text, (320 - sw) / 2, 215, status_color);

        Ok(())
    }

    /// Show logo screen with BMP logo and firmware version
    pub fn show_logo_screen(&mut self) -> Result<(), &'static str> {
        use embedded_graphics::image::{Image, ImageRawLE};

        self.display.clear(COLOR_BG).map_err(|_| "Clear failed")?;

        static LOGO_DATA: &[u8] = include_bytes!("../../assets/logo_320x240.raw");
        let raw_img: ImageRawLE<Rgb565> = ImageRawLE::new(LOGO_DATA, 320);
        Image::new(&raw_img, Point::new(0, -20))
            .draw(&mut self.display).ok();

        let mut vbuf = [0u8; 12];
        let vlen = crate::features::fw_update::format_version(
            crate::features::fw_update::CURRENT_VERSION, &mut vbuf[1..]);
        vbuf[0] = b'v';
        let vtxt = core::str::from_utf8(&vbuf[..vlen + 1]).unwrap_or("v?");
        let vw = measure_title(vtxt);
        draw_lato_title(&mut self.display, vtxt, (320 - vw) / 2, 122, COLOR_TEXT);

        let s1 = "Secure Hardware Wallet for Kaspa";
        draw_lato_body(&mut self.display, s1, (320 - measure_body(s1)) / 2, 146, COLOR_TEXT_DIM);

        let s2 = "100% Rust | Air-Gapped | no_std";
        draw_lato_body(&mut self.display, s2, (320 - measure_body(s2)) / 2, 166, COLOR_TEXT_DIM);

        let s3 = "M5Stack CoreS3 Lite";
        draw_lato_hint(&mut self.display, s3, (320 - measure_hint(s3)) / 2, 186, COLOR_TEXT_DIM);

        let s4 = "kaspa.org";
        draw_lato_hint(&mut self.display, s4, (320 - measure_hint(s4)) / 2, 206, KASPA_TEAL);

        Ok(())
    }
    /// Show panic/error screen
    pub fn show_panic_screen(&mut self, message: &str) -> Result<(), &'static str> {
        self.display.clear(COLOR_DANGER).map_err(|_| "Clear failed")?;

        let pw = measure_header("!!! PANIC !!!");
        draw_oswald_header(&mut self.display, "!!! PANIC !!!", (320 - pw) / 2, 60, COLOR_TEXT);

        let truncated = if message.len() > 35 { &message[..35] } else { message };
        let mw = measure_body(truncated);
        draw_lato_body(&mut self.display, truncated, (320 - mw) / 2, 120, COLOR_TEXT);

        let nw = measure_header("NO BOOT");
        draw_oswald_header(&mut self.display, "NO BOOT", (320 - nw) / 2, 180, COLOR_TEXT);

        Ok(())
    }

    // ─── Wallet UI methods ──────────────────────────────────────

    /// Clear screen to black
    pub fn clear_screen(&mut self) {
        self.display.clear(COLOR_BG).ok();
    }

    /// Draw a frame counter overlay at bottom-right of screen (e.g. "1/3")
    pub fn draw_frame_counter(&mut self, text: &str) {
        // Small dark rounded rect at bottom-right with white text
        let tw = measure_body(text);
        let pad = 8i32;
        let bx = 320 - tw - pad * 2 - 4;
        let by = 224i32;
        let bw = (tw + pad * 2) as u32;
        let bh = 14u32;
        let corner = CornerRadii::new(Size::new(4, 4));
        RoundedRectangle::new(
            Rectangle::new(Point::new(bx, by), Size::new(bw, bh)),
            corner,
        )
        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
        .draw(&mut self.display).ok();
        draw_lato_hint(&mut self.display, text, bx + pad, by + 11, KASPA_TEAL);
    }

    /// Draw multisig signature status overlay on the QR screen.
    pub fn draw_sig_status(&mut self, present: u8, required: u8) {
        let (label, color) = if present >= required {
            ("FULLY SIGNED", KASPA_TEAL)
        } else {
            ("PARTIAL", COLOR_ORANGE)
        };
        let tw = measure_hint(label);
        let pad = 6i32;
        let corner = CornerRadii::new(Size::new(4, 4));
        RoundedRectangle::new(
            Rectangle::new(Point::new(4, 224), Size::new((tw + pad * 2) as u32, 14)),
            corner,
        ).into_styled(PrimitiveStyle::with_fill(COLOR_BG)).draw(&mut self.display).ok();
        draw_lato_hint(&mut self.display, label, 4 + pad, 235, color);
        let mut sc: heapless::String<8> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut sc, format_args!("{}/{}", present, required)).ok();
        let sw = measure_hint(sc.as_str());
        let sx = 4 + pad + tw + 6;
        RoundedRectangle::new(
            Rectangle::new(Point::new(sx, 224), Size::new((sw + pad * 2) as u32, 14)),
            corner,
        ).into_styled(PrimitiveStyle::with_fill(COLOR_BG)).draw(&mut self.display).ok();
        draw_lato_hint(&mut self.display, &sc, sx + pad, 235, color);
    }

    /// Draw back button (top-left) and home button (top-right)
    /// Both 34x34. Back at (0,0), Home at (286,0).
    /// Touch zones: back x=0..36, y=0..36. Home x=284..320, y=0..36.
    pub fn draw_back_button(&mut self) {
        use embedded_graphics::image::{Image, ImageRawLE};
        let back: ImageRawLE<Rgb565> = ImageRawLE::new(
            crate::hw::icon_data::ICON_BACK, crate::hw::icon_data::ICON_BACK_W);
        Image::new(&back, Point::new(0, 0))
            .draw(&mut self.display).ok();
        let home: ImageRawLE<Rgb565> = ImageRawLE::new(
            crate::hw::icon_data::ICON_HOME, crate::hw::icon_data::ICON_HOME_W);
        Image::new(&home, Point::new(286, 0))
            .draw(&mut self.display).ok();
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
/// Boot verification status for the splash screen.
pub enum BootStatus {
    Verifying,
    Valid,
    Invalid,
    Error,
}