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

//! ST7796 command tables, MADCTL, init sequence and RGB565 helpers, from
//! esp-bsp `components/lcd/esp_lcd_st7796/esp_lcd_st7796_general.c` (the
//! vendor library is a thin shell around that sequence).
//!
//! This panel needs INVON: without it white shows as black and black as
//! white, which no byte or channel swap can do (all-ones and all-zeros
//! survive them), so a white or black fill tells inversion from a
//! byte-order fault.
//!
//! Pixel bytes go high byte first.

#![allow(missing_docs)] // register offsets and bit tables; see the module header and the datasheet
pub mod cmd {
    pub const SWRESET: u8 = 0x01;
    pub const SLPOUT: u8 = 0x11;
    pub const INVOFF: u8 = 0x20;
    pub const INVON: u8 = 0x21;
    pub const DISPOFF: u8 = 0x28;
    pub const DISPON: u8 = 0x29;
    pub const CASET: u8 = 0x2a;
    pub const RASET: u8 = 0x2b;
    pub const RAMWR: u8 = 0x2c;
    pub const MADCTL: u8 = 0x36;
    pub const COLMOD: u8 = 0x3a;
}

/// MADCTL bits.
pub mod madctl {
    pub const MY: u8 = 0x80;
    pub const MX: u8 = 0x40;
    pub const MV: u8 = 0x20;
    pub const ML: u8 = 0x10;
    pub const BGR: u8 = 0x08;
}

/// Landscape, as the board is held with its camera: 480 wide, 320 tall.
/// With `MV` (axes swapped) set, `MX` flips the vertical: `MV | MX | BGR`
/// shows text upside down. The viewfinder cannot show that mirror (its
/// plane is transposed, itself a mirror) and a mirrored QR code still
/// scans: text is the check. `unit::VIEW_FLIP_Y` flips the viewfinder.
pub const MADCTL_DEFAULT: u8 = madctl::MV | madctl::BGR;
/// 16 bits per pixel, RGB565.
pub const COLMOD_RGB565: u8 = 0x55;

/// Reset timing from `panel_st7796_reset()`: low 10 ms, high 120 ms.
pub const RESET_LOW_MS: u32 = 10;
pub const RESET_HIGH_MS: u32 = 120;
/// SLPOUT settle from `panel_st7796_init()`.
pub const SLPOUT_MS: u32 = 100;

/// One init-sequence entry: command byte and its parameters.
pub struct InitCmd(pub u8, pub &'static [u8]);

/// `vendor_specific_init_default[]`, verbatim.
pub static INIT: &[InitCmd] = &[
    InitCmd(0xf0, &[0xc3]),
    InitCmd(0xf0, &[0x96]),
    InitCmd(0xb4, &[0x01]),
    InitCmd(0xb7, &[0xc6]),
    InitCmd(0xe8, &[0x40, 0x8a, 0x00, 0x00, 0x29, 0x19, 0xa5, 0x33]),
    InitCmd(0xc1, &[0x06]),
    InitCmd(0xc2, &[0xa7]),
    InitCmd(0xc5, &[0x18]),
    InitCmd(
        0xe0,
        &[
            0xf0, 0x09, 0x0b, 0x06, 0x04, 0x15, 0x2f, 0x54, 0x42, 0x3c, 0x17, 0x14, 0x18, 0x1b,
        ],
    ),
    InitCmd(
        0xe1,
        &[
            0xf0, 0x09, 0x0b, 0x06, 0x04, 0x03, 0x2d, 0x43, 0x42, 0x3b, 0x16, 0x14, 0x17, 0x1b,
        ],
    ),
    InitCmd(0xf0, &[0x3c]),
    InitCmd(0xf0, &[0x69]),
];

/// RGB565 helpers.
pub const fn rgb565(r: u8, g: u8, b: u8) -> u16 {
    (((r as u16) & 0xF8) << 8) | (((g as u16) & 0xFC) << 3) | ((b as u16) >> 3)
}

pub mod colour {
    pub const BLACK: u16 = 0x0000;
    pub const WHITE: u16 = 0xFFFF;
    pub const RED: u16 = 0xF800;
    pub const GREEN: u16 = 0x07E0;
    pub const BLUE: u16 = 0x001F;
    pub const YELLOW: u16 = 0xFFE0;
    pub const CYAN: u16 = 0x07FF;
    pub const MAGENTA: u16 = 0xF81F;
}
