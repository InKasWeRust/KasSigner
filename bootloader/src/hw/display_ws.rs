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

// hw/display.rs — ST7789T3 display driver for Waveshare ESP32-S3-Touch-LCD-2
// Ported from ILI9342C (CoreS3). Same resolution (320×240), same color depth.
//
// Key differences from CoreS3:
//   - Driver chip: ILI9342C → ST7789T3 (mipidsi supports both)
//   - Backlight: AXP2101 DLDO1 → direct GPIO1 via transistor
//   - Reset: AW9523B IO expander → direct GPIO0
//   - Orientation: may differ (ST7789 native is 240×320 portrait)
//   - Color order: may be RGB instead of BGR
//
// The display API (BootDisplay) remains identical — all UI code works unchanged.


use esp_hal::delay::Delay;
use esp_hal::spi::master::Spi;
use esp_hal::gpio::Output;

use embedded_hal_bus::spi::ExclusiveDevice;
use mipidsi::{
    Builder,
    interface::SpiInterface,
    models::ST7789,
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
// Display Constants (unchanged — same resolution)
// ═══════════════════════════════════════════════════════════════

pub const DISPLAY_W: u32 = 320;
pub const DISPLAY_H: u32 = 240;

// KasSigner color palette — identical to CoreS3 version
pub(crate) const KASPA_TEAL: Rgb565 = Rgb565::new(0b01110, 0b110001, 0b10111);
pub(crate) const KASPA_ACCENT: Rgb565 = Rgb565::new(0b01001, 0b111010, 0b11001);
pub(crate) const COLOR_BG: Rgb565 = Rgb565::BLACK;
pub(crate) const COLOR_CARD: Rgb565 = Rgb565::new(0b00001, 0b000010, 0b00001);
pub(crate) const COLOR_CARD_BORDER: Rgb565 = Rgb565::new(0b01010, 0b010100, 0b01010);
pub(crate) const COLOR_TEXT: Rgb565 = Rgb565::new(0b11111, 0b111111, 0b11111);
pub(crate) const COLOR_TEXT_DIM: Rgb565 = Rgb565::new(0b10110, 0b101101, 0b10110);
pub(crate) const COLOR_DANGER: Rgb565 = Rgb565::new(0b11100, 0b001000, 0b00010);
pub(crate) const COLOR_ORANGE: Rgb565 = Rgb565::new(0b11111, 0b100011, 0b00000);
pub(crate) const COLOR_GREEN_BTN: Rgb565 = Rgb565::new(0b00000, 0b101000, 0b00000);
pub(crate) const COLOR_RED_BTN: Rgb565 = Rgb565::new(0b01100, 0b000000, 0b00000);
pub(crate) const COLOR_ERR_TEXT: Rgb565 = Rgb565::new(0b11111, 0b000000, 0b00000);
pub(crate) const COLOR_HINT: Rgb565 = Rgb565::new(0b01100, 0b011000, 0b01100);

static SPI_BUF: StaticCell<[u8; 512]> = StaticCell::new();

// ── Lato proportional font helpers (unchanged) ──────────────────
use crate::ui::prop_fonts;

pub(crate) fn draw_lato_title<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::LATO_BOLD_18_WIDTHS, &prop_fonts::LATO_BOLD_18_OFFSETS,
        &prop_fonts::LATO_BOLD_18_DATA, prop_fonts::LATO_BOLD_18_HEIGHT,
        prop_fonts::LATO_BOLD_18_ASCENT, prop_fonts::LATO_BOLD_18_FIRST, prop_fonts::LATO_BOLD_18_LAST)
}

pub(crate) fn draw_lato_body<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::LATO_15_WIDTHS, &prop_fonts::LATO_15_OFFSETS,
        &prop_fonts::LATO_15_DATA, prop_fonts::LATO_15_HEIGHT,
        prop_fonts::LATO_15_ASCENT, prop_fonts::LATO_15_FIRST, prop_fonts::LATO_15_LAST)
}

pub(crate) fn draw_lato_18<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::LATO_18_WIDTHS, &prop_fonts::LATO_18_OFFSETS,
        &prop_fonts::LATO_18_DATA, prop_fonts::LATO_18_HEIGHT,
        prop_fonts::LATO_18_ASCENT, prop_fonts::LATO_18_FIRST, prop_fonts::LATO_18_LAST)
}

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

pub(crate) fn draw_lato_hint<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::LATO_12_WIDTHS, &prop_fonts::LATO_12_OFFSETS,
        &prop_fonts::LATO_12_DATA, prop_fonts::LATO_12_HEIGHT,
        prop_fonts::LATO_12_ASCENT, prop_fonts::LATO_12_FIRST, prop_fonts::LATO_12_LAST)
}

pub(crate) fn draw_oswald_header<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::OSWALD_BOLD_22_WIDTHS, &prop_fonts::OSWALD_BOLD_22_OFFSETS,
        &prop_fonts::OSWALD_BOLD_22_DATA, prop_fonts::OSWALD_BOLD_22_HEIGHT,
        prop_fonts::OSWALD_BOLD_22_ASCENT, prop_fonts::OSWALD_BOLD_22_FIRST, prop_fonts::OSWALD_BOLD_22_LAST)
}

pub(crate) fn draw_rubik_big<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::RUBIK_BOLD_26_WIDTHS, &prop_fonts::RUBIK_BOLD_26_OFFSETS,
        &prop_fonts::RUBIK_BOLD_26_DATA, prop_fonts::RUBIK_BOLD_26_HEIGHT,
        prop_fonts::RUBIK_BOLD_26_ASCENT, prop_fonts::RUBIK_BOLD_26_FIRST, prop_fonts::RUBIK_BOLD_26_LAST)
}

pub(crate) fn draw_oswald_sub<D: DrawTarget<Color = Rgb565>>(d: &mut D, text: &str, x: i32, y: i32, color: Rgb565) -> i32 {
    prop_fonts::draw_prop_text(d, text, x, y, color,
        &prop_fonts::OSWALD_SB_16_WIDTHS, &prop_fonts::OSWALD_SB_16_OFFSETS,
        &prop_fonts::OSWALD_SB_16_DATA, prop_fonts::OSWALD_SB_16_HEIGHT,
        prop_fonts::OSWALD_SB_16_ASCENT, prop_fonts::OSWALD_SB_16_FIRST, prop_fonts::OSWALD_SB_16_LAST)
}

pub(crate) fn measure_title(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::LATO_BOLD_18_WIDTHS,
        prop_fonts::LATO_BOLD_18_FIRST, prop_fonts::LATO_BOLD_18_LAST, prop_fonts::LATO_BOLD_18_HEIGHT)
}
pub(crate) fn measure_body(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::LATO_15_WIDTHS,
        prop_fonts::LATO_15_FIRST, prop_fonts::LATO_15_LAST, prop_fonts::LATO_15_HEIGHT)
}
pub(crate) fn measure_18(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::LATO_18_WIDTHS,
        prop_fonts::LATO_18_FIRST, prop_fonts::LATO_18_LAST, prop_fonts::LATO_18_HEIGHT)
}
pub(crate) fn measure_22(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::LATO_22_WIDTHS,
        prop_fonts::LATO_22_FIRST, prop_fonts::LATO_22_LAST, prop_fonts::LATO_22_HEIGHT)
}
pub(crate) fn measure_header(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::OSWALD_BOLD_22_WIDTHS,
        prop_fonts::OSWALD_BOLD_22_FIRST, prop_fonts::OSWALD_BOLD_22_LAST, prop_fonts::OSWALD_BOLD_22_HEIGHT)
}
pub(crate) fn measure_big(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::RUBIK_BOLD_26_WIDTHS,
        prop_fonts::RUBIK_BOLD_26_FIRST, prop_fonts::RUBIK_BOLD_26_LAST, prop_fonts::RUBIK_BOLD_26_HEIGHT)
}
pub(crate) fn measure_sub(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::OSWALD_SB_16_WIDTHS,
        prop_fonts::OSWALD_SB_16_FIRST, prop_fonts::OSWALD_SB_16_LAST, prop_fonts::OSWALD_SB_16_HEIGHT)
}
pub(crate) fn measure_hint(text: &str) -> i32 {
    prop_fonts::measure_prop_text(text, &prop_fonts::LATO_12_WIDTHS,
        prop_fonts::LATO_12_FIRST, prop_fonts::LATO_12_LAST, prop_fonts::LATO_12_HEIGHT)
}

// Menu icon drawing (unchanged)
pub(crate) fn draw_menu_icon<D: DrawTarget<Color = Rgb565>>(d: &mut D, label: &str, pos: Point) {
    let color = KASPA_TEAL;
    macro_rules! draw_icon {
        ($icon_type:ty) => {{
            let icon = <$icon_type>::new(color);
            Image::new(&icon, pos).draw(d).ok();
        }};
    }
    match label {
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
        s if s.starts_with("Show Seed")   => draw_icon!(size24px::actions::OpenNewWindow),
        s if s.starts_with("Show as QR")  => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("Encrypt to")  => draw_icon!(size24px::actions::UploadSquare),
        s if s.starts_with("CompactSeed") => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("Standard Seed")=> draw_icon!(size24px::other::QrCode),
        s if s.starts_with("Plain Text") => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("QR Export")   => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("kpub as")     => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("kpub to")     => draw_icon!(size24px::finance::AppleWallet),
        s if s.starts_with("kpub")        => draw_icon!(size24px::actions::EyeEmpty),
        s if s.starts_with("xprv")        => draw_icon!(size24px::security::Lock),
        s if s.starts_with("Seed Backup") => draw_icon!(size24px::actions::Upload),
        s if s.starts_with("Watch-Only")  => draw_icon!(size24px::actions::EyeEmpty),
        s if s.starts_with("Signing Key") => draw_icon!(size24px::editor::EditPencil),
        s if s.starts_with("Steganogra")  => draw_icon!(size24px::actions::EyeOff),
        s if s.starts_with("Backup to")   => draw_icon!(size24px::devices::SaveFloppyDisk),
        s if s.starts_with("Private Key") => draw_icon!(size24px::security::PasswordCursor),
        s if s.starts_with("Multisig A")  => draw_icon!(size24px::other::QrCode),
        s if s.starts_with("Multisig D")  => draw_icon!(size24px::docs::Page),
        s if s.starts_with("Transaction") => draw_icon!(size24px::users::Group),
        s if s.starts_with("XPrv Backup") => draw_icon!(size24px::actions::UploadSquare),
        s if s.starts_with("JPEG Stego")  => draw_icon!(size24px::actions::EyeOff),
        s if s.starts_with("Display")     => draw_icon!(size24px::devices::Laptop),
        s if s.starts_with("Camera")      => draw_icon!(size24px::photos_and_videos::Camera),
        s if s.starts_with("SD Card")     => draw_icon!(size24px::devices::SaveFloppyDisk),
        s if s.starts_with("About")       => draw_icon!(size24px::actions::HelpCircle),
        _ => {
            Circle::new(pos + Point::new(4, 4), 16)
                .into_styled(PrimitiveStyle::with_stroke(color, 1))
                .draw(d).ok();
        }
    }
}

pub(crate) fn password_strength(text: &str) -> u8 {
    let len = text.len();
    if len < 8 { return 0; }
    let bytes = text.as_bytes();
    let has_upper = bytes.iter().any(|b| *b >= b'A' && *b <= b'Z');
    let has_lower = bytes.iter().any(|b| *b >= b'a' && *b <= b'z');
    let has_digit = bytes.iter().any(|b| *b >= b'0' && *b <= b'9');
    let has_space = bytes.contains(&b' ');
    let variety = has_upper as u8 + has_lower as u8 + has_digit as u8 + has_space as u8;
    let all_same = bytes.iter().all(|b| *b == bytes[0]);
    if all_same { return 0; }
    if len >= 16 && variety >= 2 { return 2; }
    if len >= 12 { return if variety >= 2 { 2 } else { 1 }; }
    if variety >= 2 { return 1; }
    0
}

// ═══════════════════════════════════════════════════════════════
// Display type alias — ST7789 instead of ILI9342C
// ═══════════════════════════════════════════════════════════════

pub(crate) type Ili9342Display<'a> = mipidsi::Display<
    SpiInterface<
        'a,
        ExclusiveDevice<Spi<'a, esp_hal::Blocking>, Output<'a>, embedded_hal_bus::spi::NoDelay>,
        Output<'a>,
    >,
    ST7789,
    Output<'a>,
>;

// ═══════════════════════════════════════════════════════════════
// TeeDisplay (screenshot feature — unchanged)
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "screenshot")]
pub struct TeeDisplay<'a> {
    pub(crate) real: Ili9342Display<'a>,
    pub(crate) shadow: *mut u8,
    pub(crate) shadow_active: bool,
}

#[cfg(feature = "screenshot")]
impl<'a> TeeDisplay<'a> {
    pub fn new(real: Ili9342Display<'a>) -> Self {
        Self { real, shadow: core::ptr::null_mut(), shadow_active: false }
    }
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
    where I: IntoIterator<Item = embedded_graphics::prelude::Pixel<Self::Color>> {
        use embedded_graphics::pixelcolor::raw::RawU16;
        if self.shadow_active && !self.shadow.is_null() {
            let px_vec: alloc::vec::Vec<embedded_graphics::prelude::Pixel<Rgb565>> =
                pixels.into_iter().collect();
            for &embedded_graphics::prelude::Pixel(point, color) in &px_vec {
                let x = point.x; let y = point.y;
                if (0..320).contains(&x) && (0..240).contains(&y) {
                    let idx = ((y as usize) * 320 + (x as usize)) * 2;
                    let raw = RawU16::from(color).into_inner();
                    unsafe { *self.shadow.add(idx) = (raw >> 8) as u8; *self.shadow.add(idx + 1) = (raw & 0xFF) as u8; }
                }
            }
            self.real.draw_iter(px_vec.into_iter())
        } else { self.real.draw_iter(pixels) }
    }

    fn fill_contiguous<I>(&mut self, area: &embedded_graphics::primitives::Rectangle, colors: I) -> Result<(), Self::Error>
    where I: IntoIterator<Item = Self::Color> {
        use embedded_graphics::pixelcolor::raw::RawU16;
        if self.shadow_active && !self.shadow.is_null() {
            let color_vec: alloc::vec::Vec<Rgb565> = colors.into_iter().collect();
            let mut px = area.top_left.x; let mut py = area.top_left.y;
            let x_end = area.top_left.x + area.size.width as i32;
            for &color in &color_vec {
                if (0..320).contains(&px) && (0..240).contains(&py) {
                    let idx = ((py as usize) * 320 + (px as usize)) * 2;
                    let raw = RawU16::from(color).into_inner();
                    unsafe { *self.shadow.add(idx) = (raw >> 8) as u8; *self.shadow.add(idx + 1) = (raw & 0xFF) as u8; }
                }
                px += 1;
                if px >= x_end { px = area.top_left.x; py += 1; }
            }
            self.real.fill_contiguous(area, color_vec.into_iter())
        } else { self.real.fill_contiguous(area, colors) }
    }

    fn fill_solid(&mut self, area: &embedded_graphics::primitives::Rectangle, color: Self::Color) -> Result<(), Self::Error> {
        use embedded_graphics::pixelcolor::raw::RawU16;
        if self.shadow_active && !self.shadow.is_null() {
            let raw = RawU16::from(color).into_inner();
            let hi = (raw >> 8) as u8; let lo = (raw & 0xFF) as u8;
            let x_start = area.top_left.x.max(0) as usize; let y_start = area.top_left.y.max(0) as usize;
            let x_end = (area.top_left.x + area.size.width as i32).min(320) as usize;
            let y_end = (area.top_left.y + area.size.height as i32).min(240) as usize;
            for py in y_start..y_end { for px in x_start..x_end {
                let idx = (py * 320 + px) * 2;
                unsafe { *self.shadow.add(idx) = hi; *self.shadow.add(idx + 1) = lo; }
            }}
        }
        self.real.fill_solid(area, color)
    }

    fn clear(&mut self, color: Self::Color) -> Result<(), Self::Error> {
        use embedded_graphics::pixelcolor::raw::RawU16;
        if self.shadow_active && !self.shadow.is_null() {
            let raw = RawU16::from(color).into_inner();
            let hi = (raw >> 8) as u8; let lo = (raw & 0xFF) as u8;
            let fb = unsafe { core::slice::from_raw_parts_mut(self.shadow, 320 * 240 * 2) };
            for i in (0..fb.len()).step_by(2) { fb[i] = hi; fb[i + 1] = lo; }
        }
        self.real.clear(color)
    }
}

#[cfg(feature = "screenshot")]
impl<'a> embedded_graphics::prelude::OriginDimensions for TeeDisplay<'a> {
    fn size(&self) -> embedded_graphics::prelude::Size { self.real.size() }
}

#[cfg(feature = "screenshot")]
pub(crate) type BootDisplayTarget<'a> = TeeDisplay<'a>;
#[cfg(not(feature = "screenshot"))]
pub(crate) type BootDisplayTarget<'a> = Ili9342Display<'a>;

// ═══════════════════════════════════════════════════════════════
// BootDisplay wrapper — ST7789T3 version
// ═══════════════════════════════════════════════════════════════

pub struct BootDisplay<'a> {
    pub(crate) display: BootDisplayTarget<'a>,
}

impl<'a> BootDisplay<'a> {
    /// Create ST7789T3 display from SPI and GPIO pins.
    /// No PMU init needed — backlight is controlled via separate GPIO.
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

        // ST7789T3 on Waveshare — 240×320 native, rotated to 320×240 landscape
        let orientation = Orientation::default().rotate(Rotation::Deg90);
        let mut display = Builder::new(ST7789, spi_iface)
            .reset_pin(reset_pin)
            .color_order(mipidsi::options::ColorOrder::Rgb)
            .invert_colors(mipidsi::options::ColorInversion::Inverted)
            .display_size(240, 320)
            .orientation(orientation)
            .init(delay)
            .map_err(|_| "Failed to init ST7789T3")?;

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

    // ─── Boot sequence screens (identical to CoreS3) ────────────

    pub fn show_verification_screen(
        &mut self, version: &str, hash: &str, status: BootStatus,
    ) -> Result<(), &'static str> {
        use embedded_graphics::image::{Image, ImageRawLE};
        self.display.clear(COLOR_BG).map_err(|_| "Clear failed")?;

        static KASCOIN: &[u8] = include_bytes!("../../assets/kascoin_90.raw");
        let raw_coin: ImageRawLE<Rgb565> = ImageRawLE::new(KASCOIN, 90);
        Image::new(&raw_coin, Point::new(115, 10)).draw(&mut self.display).ok();

        let mut version_text = heapless::String::<48>::new();
        use core::fmt::Write;
        write!(&mut version_text, "Version: {version}").ok();
        let vw = measure_title(version_text.as_str());
        draw_lato_title(&mut self.display, version_text.as_str(), (320 - vw) / 2, 135, COLOR_TEXT);

        let mut hash_text = heapless::String::<48>::new();
        let hash_display = &hash[..core::cmp::min(16, hash.len())];
        write!(&mut hash_text, "Hash: {hash_display}").ok();
        let hw = measure_body(hash_text.as_str());
        draw_lato_body(&mut self.display, hash_text.as_str(), (320 - hw) / 2, 165, COLOR_TEXT_DIM);

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

    pub fn show_logo_screen(&mut self) -> Result<(), &'static str> {
        use embedded_graphics::image::{Image, ImageRawLE};
        self.display.clear(COLOR_BG).map_err(|_| "Clear failed")?;

        static LOGO_DATA: &[u8] = include_bytes!("../../assets/logo_320x240.raw");
        let raw_img: ImageRawLE<Rgb565> = ImageRawLE::new(LOGO_DATA, 320);
        Image::new(&raw_img, Point::new(0, -20)).draw(&mut self.display).ok();

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

        let s3 = "Waveshare ESP32-S3-Touch-LCD-2";
        draw_lato_hint(&mut self.display, s3, (320 - measure_hint(s3)) / 2, 186, COLOR_TEXT_DIM);

        let s4 = "kaspa.org";
        draw_lato_hint(&mut self.display, s4, (320 - measure_hint(s4)) / 2, 206, KASPA_TEAL);

        Ok(())
    }
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

    pub fn clear_screen(&mut self) { self.display.clear(COLOR_BG).ok(); }

    /// Draw the multi-frame QR page counter as a 2-line badge in the
    /// right info column reserved by `draw_qr_screen_left`.
    ///
    /// Layout:
    ///   Line 1: "FRAMES" (label, dim)
    ///   Line 2: "F/N"    (frame / total frames, teal)
    ///
    /// Position: centred in x=240..316 (right column), y-range ≈ 150..210.
    /// The QR-left layout leaves this strip empty so there's no overlap.
    pub fn draw_frame_counter(&mut self, text: &str) {
        let col_cx: i32 = 278;

        // Line 1: "FRAMES" label (dim)
        let label = "FRAMES";
        let lw = measure_hint(label);
        draw_lato_hint(&mut self.display, label, col_cx - lw / 2, 160, COLOR_TEXT_DIM);

        // Line 2: frame/total in teal
        let tw = measure_title(text);
        draw_lato_title(&mut self.display, text, col_cx - tw / 2, 190, KASPA_TEAL);
    }

    /// Draw multisig signature status as a 2-line badge in the right
    /// info column reserved by `draw_qr_screen_left`.
    ///
    /// Layout:
    ///   Line 1: "SIGNER" (label, dim)
    ///   Line 2: "P/R"    (present/required — teal when fully signed,
    ///                      orange while partial)
    ///
    /// Colour conveys state: orange = more signers needed, teal = done
    /// and ready to broadcast. This matches the Confirm screen semantics
    /// and gives signers a clear visual cue when the tx is complete.
    pub fn draw_sig_status(&mut self, present: u8, required: u8) {
        let color = if present >= required { KASPA_TEAL } else { COLOR_ORANGE };
        let col_cx: i32 = 278; // midpoint of x=240..316

        // Line 1: "SIGNER" label (dim)
        let label = "SIGNER";
        let lw = measure_hint(label);
        draw_lato_hint(&mut self.display, label, col_cx - lw / 2, 40, COLOR_TEXT_DIM);

        // Line 2: present/required — teal (done) or orange (partial)
        let mut sc: heapless::String<8> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut sc, format_args!("{present}/{required}")).ok();
        let sw = measure_title(sc.as_str());
        draw_lato_title(&mut self.display, &sc, col_cx - sw / 2, 70, color);
    }

    pub fn draw_back_button(&mut self) {
        use embedded_graphics::image::{Image, ImageRawLE};
        let back: ImageRawLE<Rgb565> = ImageRawLE::new(
            crate::hw::icon_data::ICON_BACK, crate::hw::icon_data::ICON_BACK_W);
        Image::new(&back, Point::new(0, 0)).draw(&mut self.display).ok();
        let home: ImageRawLE<Rgb565> = ImageRawLE::new(
            crate::hw::icon_data::ICON_HOME, crate::hw::icon_data::ICON_HOME_W);
        Image::new(&home, Point::new(286, 0)).draw(&mut self.display).ok();
    }

    /// Clear the screen but preserve the back/home icon POSITIONS.
    /// Repaints both icons to ensure stale content (coin/battery from main menu) is overwritten.
    pub fn clear_keep_nav(&mut self) {
        // Top strip between icons: x=34..286, y=0..34
        Rectangle::new(Point::new(34, 0), Size::new(252, 34))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        // Everything below icon row: y=34..240
        Rectangle::new(Point::new(0, 34), Size::new(320, 206))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        // Repaint nav icons (overwrites any stale content like coin/battery)
        self.draw_back_button();
    }

    /// Draw settings icon at top-right (34x34 zone) using icon_settings.raw scaled 2:1.
    ///
    /// Unused as of v1.0.3 — camera settings moved to Settings > Camera tab,
    /// no more gear shortcut on ScanQR. Kept around in case the UX brings
    /// back a top-right action button in a future release.
    #[allow(dead_code)]
    pub fn draw_gear_icon(&mut self) {
        use embedded_graphics::prelude::*;
        use embedded_graphics::primitives::{Rectangle, PrimitiveStyle};
        use embedded_graphics::draw_target::DrawTarget;

        // Clear the 34x34 zone
        Rectangle::new(Point::new(286, 0), Size::new(34, 34))
            .into_styled(PrimitiveStyle::with_fill(Rgb565::new(1, 2, 1)))
            .draw(&mut self.display).ok();

        // icon_settings.raw is 56x56 RGB565 LE — scale to 28x28, draw at (289, 3)
        static ICON_RAW: &[u8] = include_bytes!("../../assets/icon_settings.raw");
        let src_w = 56usize;
        let dst_x0 = 289i32;
        let dst_y0 = 3i32;
        let dst_sz = 28usize;

        for dy in 0..dst_sz {
            let sy = dy * 2;
            let area = Rectangle::new(
                Point::new(dst_x0, dst_y0 + dy as i32),
                Size::new(dst_sz as u32, 1),
            );
            let _ = self.display.fill_contiguous(
                &area,
                (0..dst_sz).map(move |dx| {
                    let sx = dx * 2;
                    let off = (sy * src_w + sx) * 2;
                    if off + 1 < ICON_RAW.len() {
                        let lo = ICON_RAW[off];
                        let hi = ICON_RAW[off + 1];
                        Rgb565::from(embedded_graphics::pixelcolor::raw::RawU16::new(
                            u16::from_le_bytes([lo, hi])
                        ))
                    } else {
                        Rgb565::new(1, 2, 1)
                    }
                }),
            );
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BootStatus {
    Verifying,
    Valid,
    Invalid,
    Error,
}
