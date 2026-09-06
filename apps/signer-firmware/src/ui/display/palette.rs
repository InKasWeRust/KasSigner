// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use embedded_graphics::{pixelcolor::Rgb565, prelude::RgbColor};

pub const DISPLAY_H: u32 = 240;

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
pub(crate) const COLOR_HINT: Rgb565 = Rgb565::new(0b01100, 0b011000, 0b01100);
