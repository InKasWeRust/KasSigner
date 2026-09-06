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

// Optional OV5640 autofocus firmware and commands.

#[cfg(feature = "af")]
use esp_hal::delay::Delay;

#[cfg(feature = "af")]
use super::bus::{read_reg, write_reg};
#[cfg(feature = "af")]
use crate::hw::ov5640_af_fw::OV5640_AF_FW;

// ═══ Autofocus firmware loader ═══
// Gated behind the `af` feature. The Waveshare module currently fitted is
// fixed-focus (no VCM motor), so the 3726-byte MCU blob and its writes are
// compiled out by default. Flip the feature on when an AF-capable module
// is installed.

#[cfg(feature = "af")]
pub(super) fn load_af_firmware<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, delay: &mut Delay) {
    write_reg(i2c, 0x3000, 0x20);
    delay.delay_millis(10);
    for (i, &byte) in OV5640_AF_FW.iter().enumerate() {
        write_reg(i2c, 0x8000u16 + i as u16, byte);
    }
    write_reg(i2c, 0x3022, 0x00); write_reg(i2c, 0x3023, 0x00);
    write_reg(i2c, 0x3024, 0x00); write_reg(i2c, 0x3025, 0x00);
    write_reg(i2c, 0x3026, 0x00); write_reg(i2c, 0x3027, 0x00);
    write_reg(i2c, 0x3028, 0x00); write_reg(i2c, 0x3029, 0xFF);
    write_reg(i2c, 0x3000, 0x00);
    delay.delay_millis(500);
    let af_sta = read_reg(i2c, 0x3029);
    crate::log!("   OV5640 AF firmware: status={:?} (0x70=OK)", af_sta);
    write_reg(i2c, 0x3022, 0x04); write_reg(i2c, 0x3023, 0x01);
    delay.delay_millis(100);
    let af_sta2 = read_reg(i2c, 0x3029);
    crate::log!("   OV5640 AF continuous: status={:?}", af_sta2);
}
