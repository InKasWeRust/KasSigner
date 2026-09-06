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

// OV2640 register diagnostics.

use super::bus::{read_reg, select_bank};

/// Log diagnostic register values.
pub fn log_diagnostics<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) {
    // Sensor bank
    select_bank(i2c, 0x01);
    let pid_h = read_reg(i2c, 0x0A);
    let pid_l = read_reg(i2c, 0x0B);
    let mid_h = read_reg(i2c, 0x1C);
    let mid_l = read_reg(i2c, 0x1D);
    let com7 = read_reg(i2c, 0x12);
    let clkrc = read_reg(i2c, 0x11);
    let reg04 = read_reg(i2c, 0x04);
    crate::log!("   OV2640 sensor: PID={:?}/{:?} MID={:?}/{:?} COM7={:?} CLKRC={:?} REG04={:?}",
        pid_h, pid_l, mid_h, mid_l, com7, clkrc, reg04);

    // DSP bank
    select_bank(i2c, 0x00);
    let image_mode = read_reg(i2c, 0xDA);
    let dvp_sp = read_reg(i2c, 0xD3);
    let ctrl0 = read_reg(i2c, 0xC2);
    let ctrl2 = read_reg(i2c, 0x86);
    let bypass = read_reg(i2c, 0x05);
    let hsize = read_reg(i2c, 0x51);
    let vsize = read_reg(i2c, 0x52);
    let zmow = read_reg(i2c, 0x5A);
    let zmoh = read_reg(i2c, 0x5B);
    crate::log!("   OV2640 DSP: IMG_MODE={:?} DVP_SP={:?} CTRL0={:?} CTRL2={:?} BYPASS={:?}",
        image_mode, dvp_sp, ctrl0, ctrl2, bypass);
    crate::log!("   OV2640 DSP size: HSIZE={:?} VSIZE={:?} ZMOW={:?} ZMOH={:?}",
        hsize, vsize, zmow, zmoh);
}
