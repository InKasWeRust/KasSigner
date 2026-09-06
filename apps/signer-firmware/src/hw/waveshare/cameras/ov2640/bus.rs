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

// OV2640 SCCB access and bank selection.

const OV2640_ADDR: u8 = 0x30;

// ═══ SCCB register access (8-bit addresses) ═══

pub fn write_reg<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, reg: u8, val: u8) -> bool {
    i2c.write(OV2640_ADDR, &[reg, val]).is_ok()
}

pub fn read_reg<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, reg: u8) -> Option<u8> {
    let mut data = [0u8; 1];
    i2c.write(OV2640_ADDR, &[reg]).ok()?;
    i2c.read(OV2640_ADDR, &mut data).ok()?;
    Some(data[0])
}

/// Select register bank: 0x00 = DSP, 0x01 = Sensor
pub fn select_bank<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, bank: u8) -> bool {
    write_reg(i2c, 0xFF, bank)
}
