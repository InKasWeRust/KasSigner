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

//! FT6336 / FT5x06, I2C 0x38, the part fitted to this board. Single-byte
//! register addressing, unlike the GT911's 16-bit.

/// I2C address. Fixed by the part (FT5x06 family).
pub const ADDR: u8 = 0x38;

#[allow(missing_docs)] // register table
pub mod reg {
    /// Number of active touches, low nibble.
    pub const TD_STATUS: u8 = 0x02;
    /// Point 1: xh, xl, yh, yl. Coordinates are 12 bits; the top two bits
    /// of xh are the event flag.
    pub const P1_XH: u8 = 0x03;
    /// Register: chip ID.
    pub const CHIP_ID: u8 = 0xA3;
    /// Register: vendor ID.
    pub const VENDOR_ID: u8 = 0xA8;
}

/// A report from `TD_STATUS` to `P1_YL`, read in one go: the touch count
/// and point 1 with its event flag. The weight after it, always 0 on this
/// part, is not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Raw {
    /// Touches the controller says are down.
    pub touches: u8,
    /// Point 1's event: 0 pressed, 1 lifted, 2 held, 3 no event.
    pub event: u8,
    /// Point 1's column, in the controller's frame.
    pub x: u16,
    /// Point 1's row, in the controller's frame.
    pub y: u16,
}

/// Decode the five bytes from `TD_STATUS`.
pub fn decode_raw(buf: &[u8; 5]) -> Raw {
    Raw {
        touches: buf[0] & 0x0f,
        event: buf[1] >> 6,
        x: ((u16::from(buf[1]) & 0x0f) << 8) | u16::from(buf[2]),
        y: ((u16::from(buf[3]) & 0x0f) << 8) | u16::from(buf[4]),
    }
}

impl Raw {
    /// Whether the event says a finger is on the point: pressed or held.
    pub const fn event_down(self) -> bool {
        matches!(self.event, 0 | 2)
    }
}
