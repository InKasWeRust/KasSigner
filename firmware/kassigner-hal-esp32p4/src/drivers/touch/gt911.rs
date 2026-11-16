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

//! GT911, I2C 0x5D or 0x14, 16-bit register addressing. Not fitted to this
//! board; probed for and handled should a panel carry one.

/// I2C address selected by INT low at reset release.
pub const ADDR_PRIMARY: u8 = 0x5D;
/// I2C address selected by INT high at reset release.
pub const ADDR_BACKUP: u8 = 0x14;

#[allow(missing_docs)] // register table
pub mod reg {
    /// Register: 4-byte ASCII product ID ("911").
    pub const PRODUCT_ID: u16 = 0x8140;
    /// b7 = buffer ready, low nibble = touch count. Written 0 after each
    /// read, or the controller stops updating.
    pub const STATUS: u16 = 0x814E;
    /// Point 1: x lo, x hi, y lo, y hi.
    pub const POINT1: u16 = 0x8150;
}

/// First touch point from the 4-byte POINT1 record.
pub fn decode_point(buf: &[u8; 4]) -> super::Point {
    super::Point {
        x: (buf[1] as u16) << 8 | buf[0] as u16,
        y: (buf[3] as u16) << 8 | buf[2] as u16,
    }
}

/// INT level to drive during reset to select a given address.
pub fn int_level_for(addr: u8) -> bool {
    addr == ADDR_BACKUP
}
