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

// OV2640 detection and sensor-mode initialization.

use esp_hal::delay::Delay;
use signer_firmware_core::camera::registers::{id_pair_matches, write_banked};

use super::bus::{read_reg, select_bank, write_reg};
use super::registers::{OV2640_DEFAULT_REGS, OV2640_SVGA_REGS};

pub fn detect<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) -> bool {
    if !select_bank(i2c, 0x01) {
        return false;
    }
    let pid_high = read_reg(i2c, 0x0A).unwrap_or(0);
    let pid_low = read_reg(i2c, 0x0B).unwrap_or(0);
    let detected = id_pair_matches(pid_high, pid_low, 0x26, &[0x41, 0x42]);
    if detected {
        crate::log!("   OV2640 detected (PID=0x{:02X}{:02X})", pid_high, pid_low);
    }
    detected
}

// ═══ Initialization ═══

/// Initialize OV2640 for SVGA 800×600 output.
/// Base mode — used internally before applying 480×480 resize.
/// Follows Espressif esp32-camera driver sequence exactly.
fn init_svga<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, delay: &mut Delay) -> Result<(), &'static str> {
    if !detect(i2c) {
        return Err("OV2640 not detected at 0x30");
    }

    // Software reset (sensor bank)
    select_bank(i2c, 0x01);
    write_reg(i2c, 0x12, 0x80); // COM7 SRST
    delay.delay_millis(100);

    write_banked(
        OV2640_DEFAULT_REGS,
        "OV2640: SCCB write failed (defaults)",
        |register, value, bank| {
            select_bank(i2c, bank);
            write_reg(i2c, register, value)
        },
    )?;
    delay.delay_millis(10);

    // Bypass DSP during mode switch
    select_bank(i2c, 0x00);
    write_reg(i2c, 0x05, 0x01); // R_BYPASS = 1 (bypass DSP)

    write_banked(
        OV2640_SVGA_REGS,
        "OV2640: SCCB write failed (SVGA)",
        |register, value, bank| {
            select_bank(i2c, bank);
            write_reg(i2c, register, value)
        },
    )?;

    // Set clock for ESP32-S3: frequency doubler ON, divider=7
    // CLKRC: bit[7]=1 (2x), bit[5:0]=7 → internal clock = XCLK*2/(7+1) = 20*2/8 = 5MHz sensor clock
    select_bank(i2c, 0x01);
    write_reg(i2c, 0x11, 0x83); // CLKRC: clk_2x=1, clk_div=3 → XCLK*2/4=10MHz

    // DVP speed: auto mode, divider=8
    select_bank(i2c, 0x00);
    write_reg(i2c, 0xD3, 0x84); // R_DVP_SP: auto(bit7) + /4

    // Re-enable DSP
    write_reg(i2c, 0x05, 0x00); // R_BYPASS = 0 (DSP enabled)

    delay.delay_millis(100);

    crate::log!("   OV2640 configured: SVGA 800x600");
    Ok(())
}

/// Initialize OV2640 for 480×480 Y8 output (for PSRAM DMA pipeline).
///
/// Strategy: SVGA 800×600 base mode, then DSP resize/zoom to 480×480.
/// Follows Espressif esp32-camera driver's set_window() sequence.
pub fn init_480<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, delay: &mut Delay) -> Result<(), &'static str> {
    init_svga(i2c, delay)?;

    crate::log!("   OV2640: applying 480x480 Y8 resize...");

    // DSP bank: hold DVP in reset during resize config
    select_bank(i2c, 0x00);
    write_reg(i2c, 0xE0, 0x04); // RESET: hold DVP in reset

    // Enable Y8 output mode: IMAGE_MODE bit[6]=1
    write_reg(i2c, 0xDA, 0x40); // Y8 enable

    // DSP input window — 600×600 square center crop from 800×600 SVGA
    // Gives 1:1 aspect ratio for both standard and wide lens
    {
        write_reg(i2c, 0x51, 0x96); // HSIZE = 150 (600px)
        write_reg(i2c, 0x52, 0x96); // VSIZE = 150 (600px)
        write_reg(i2c, 0x53, 0x19); // XOFFL = 25 (center H)
        write_reg(i2c, 0x54, 0x00); // YOFFL = 0
        write_reg(i2c, 0x55, 0x00); // VHYX
        write_reg(i2c, 0x57, 0x00); // TEST
    }

    // DSP output size (zoom target: 480×480)
    // ZMOW = 480/4 = 120 = 0x78
    // ZMOH = 480/4 = 120 = 0x78
    write_reg(i2c, 0x5A, 0x78); // ZMOW[7:0]
    write_reg(i2c, 0x5B, 0x78); // ZMOH[7:0]
    write_reg(i2c, 0x5C, 0x00); // ZMHH: no extra bits, zoom speed 0

    // CTRL2: DCW + SDE + UV_ADJ + UV_AVG + CMX
    write_reg(i2c, 0x86, 0x3D);

    // CTRL0: YUV422 + YUV_EN
    write_reg(i2c, 0xC2, 0x0C);

    // ── QR scanning defaults (proven on M5Stack LCD decode) ──
    // AEC: low exposure targets for high-contrast QR
    select_bank(i2c, 0x01);
    write_reg(i2c, 0x24, 0x20); // AEW = 0x20
    write_reg(i2c, 0x25, 0x0C); // AEB = 0x0C
    write_reg(i2c, 0x26, 0x10); // VV = linked thresholds
    // AGC ceiling
    let com9 = read_reg(i2c, 0x14).unwrap_or(0x48);
    write_reg(i2c, 0x14, (com9 & 0x1F) | (0x03 << 5)); // AGC idx 3 (from 0x70>>5)

    // SDE: contrast + brightness for QR edge sharpness
    select_bank(i2c, 0x00);
    write_reg(i2c, 0x7C, 0x03); // BPADDR = 3 (contrast center)
    write_reg(i2c, 0x7D, 0x40); // center = 0x40
    write_reg(i2c, 0x7D, 0x8B); // contrast gain = 0x8B
    write_reg(i2c, 0x7C, 0x05); // BPADDR = 5 (brightness)
    write_reg(i2c, 0x7D, 0x08); // brightness = 0x08
    write_reg(i2c, 0x7D, 0x00); // brightness sign = positive
    write_reg(i2c, 0x7C, 0x00); // BPADDR = 0 (enable bitmask LAST)
    write_reg(i2c, 0x7D, 0x04); // enable contrast+brightness
    // Sharpness
    write_reg(i2c, 0x92, 0x01); // manual mode
    write_reg(i2c, 0x93, 0x50); // sharpness = 0x50

    // Release DVP reset — start streaming
    write_reg(i2c, 0xE0, 0x00);

    delay.delay_millis(100);

    crate::log!("   OV2640: 480x480 Y8 configured (SVGA→DSP resize)");
    Ok(())
}
