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

// OV5640 SCCB access and sensor detection.

const OV5640_ADDR: u8 = 0x3C;

// ═══ SCCB register access (16-bit addresses) ═══

pub fn write_reg<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, reg: u16, val: u8) -> bool {
    i2c.write(OV5640_ADDR, &[(reg >> 8) as u8, reg as u8, val]).is_ok()
}

pub fn read_reg<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, reg: u16) -> Option<u8> {
    let mut data = [0u8; 1];
    i2c.write(OV5640_ADDR, &[(reg >> 8) as u8, reg as u8]).ok()?;
    i2c.read(OV5640_ADDR, &mut data).ok()?;
    Some(data[0])
}

// ═══ Detection and initialization ═══

pub fn detect<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) -> bool {
    let id_h = read_reg(i2c, 0x300A).unwrap_or(0);
    let id_l = read_reg(i2c, 0x300B).unwrap_or(0);
    let id = ((id_h as u16) << 8) | id_l as u16;
    if id == 0x5640 {
        crate::log!("   OV5640 detected (ID=0x{:04X})", id);
        true
    } else {
        false
    }
}
