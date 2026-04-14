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

// hw/camera_ov2640.rs — OV2640 camera driver for Waveshare ESP32-S3-Touch-LCD-2
// 100% Rust, no-std, no-alloc
//
// OV2640 2MP sensor, SCCB (I2C-like) control, DVP 8-bit interface.
// Same FPC connector as OV5640 — hot-swappable via auto-detect at boot.
//
// Key differences from OV5640:
//   - SCCB address: 0x30 (vs OV5640 0x3C)
//   - 8-bit register addresses (vs OV5640 16-bit)
//   - Register bank system: 0xFF selects DSP bank (0x00) or Sensor bank (0x01)
//   - Chip ID: sensor bank 0x0A=0x26, 0x0B=0x41
//   - Output: SVGA 800×600 base, DSP resize to 480×480 Y8 for cam_dma

use esp_hal::delay::Delay;

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

// ═══ Detection ═══

pub fn detect<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) -> bool {
    // Switch to sensor bank to read chip ID
    if !select_bank(i2c, 0x01) { return false; }
    let pid_h = read_reg(i2c, 0x0A).unwrap_or(0);
    let pid_l = read_reg(i2c, 0x0B).unwrap_or(0);
    if pid_h == 0x26 && (pid_l == 0x41 || pid_l == 0x42) {
        crate::log!("   OV2640 detected (PID=0x{:02X}{:02X})", pid_h, pid_l);
        true
    } else {
        false
    }
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

    // Write default_regs (sensor bank init — Espressif defaults)
    for &(reg, val, bank) in OV2640_DEFAULT_REGS {
        select_bank(i2c, bank);
        if !write_reg(i2c, reg, val) {
            return Err("OV2640: SCCB write failed (defaults)");
        }
    }
    delay.delay_millis(10);

    // Bypass DSP during mode switch
    select_bank(i2c, 0x00);
    write_reg(i2c, 0x05, 0x01); // R_BYPASS = 1 (bypass DSP)

    // Write SVGA mode registers
    for &(reg, val, bank) in OV2640_SVGA_REGS {
        select_bank(i2c, bank);
        if !write_reg(i2c, reg, val) {
            return Err("OV2640: SCCB write failed (SVGA)");
        }
    }

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

// ═══ OV2640 default register table (sensor + DSP defaults) ═══
// Format: (register, value, bank) — bank 0x00=DSP, 0x01=Sensor
// Derived from Espressif esp32-camera ov2640_settings.h default_regs.

static OV2640_DEFAULT_REGS: &[(u8, u8, u8)] = &[
    // ── DSP bank defaults ──
    (0x2C, 0xFF, 0x00),
    (0x2E, 0xDF, 0x00),
    // ── Sensor bank defaults ──
    (0x3C, 0x32, 0x01),
    (0x11, 0x00, 0x01), // CLKRC: will be overridden after mode set
    (0x09, 0x02, 0x01), // COM2: output drive 2x
    (0x04, 0xA8, 0x01), // REG04: H-mirror(bit[7]) only for Waveshare landscape
    (0x13, 0xE5, 0x01), // COM8: AEC+AGC+banding
    (0x14, 0x48, 0x01), // COM9: AGC ceiling 8x
    (0x2C, 0x0C, 0x01),
    (0x33, 0x78, 0x01),
    (0x3A, 0x33, 0x01),
    (0x3B, 0xFB, 0x01),
    (0x3E, 0x00, 0x01),
    (0x43, 0x11, 0x01),
    (0x16, 0x10, 0x01),
    (0x39, 0x92, 0x01),
    (0x35, 0xDA, 0x01),
    (0x22, 0x1A, 0x01),
    (0x37, 0xC3, 0x01),
    (0x23, 0x00, 0x01),
    (0x34, 0xC0, 0x01),
    (0x36, 0x1A, 0x01),
    (0x06, 0x88, 0x01),
    (0x07, 0xC0, 0x01),
    (0x0D, 0x87, 0x01),
    (0x0E, 0x41, 0x01),
    (0x4C, 0x00, 0x01),
    (0x48, 0x00, 0x01),
    (0x5B, 0x00, 0x01),
    (0x42, 0x03, 0x01),
    (0x4A, 0x81, 0x01),
    (0x21, 0x99, 0x01),
    (0x24, 0x40, 0x01), // AEW
    (0x25, 0x38, 0x01), // AEB
    (0x26, 0x82, 0x01), // VV
    (0x5C, 0x00, 0x01),
    (0x63, 0x00, 0x01),
    (0x46, 0x22, 0x01),
    (0x0C, 0x3C, 0x01), // COM3
    (0x61, 0x70, 0x01),
    (0x62, 0x80, 0x01),
    (0x7C, 0x05, 0x01),
    (0x20, 0x80, 0x01),
    (0x28, 0x30, 0x01),
    (0x6C, 0x00, 0x01),
    (0x6D, 0x80, 0x01),
    (0x6E, 0x00, 0x01),
    (0x70, 0x02, 0x01),
    (0x71, 0x94, 0x01),
    (0x73, 0xC1, 0x01),
    (0x3D, 0x34, 0x01),
    (0x5A, 0x57, 0x01),
    (0x12, 0x40, 0x01), // COM7: SVGA mode
    (0x17, 0x11, 0x01), // HREFST
    (0x18, 0x43, 0x01), // HREFEND
    (0x19, 0x00, 0x01), // VSTRT
    (0x1A, 0x4B, 0x01), // VEND
    (0x32, 0x09, 0x01), // REG32
    (0x03, 0x0A, 0x01), // COM1
    (0x15, 0x00, 0x01), // COM10
    // ── DSP bank defaults ──
    (0xE5, 0x7F, 0x00),
    (0xF9, 0xC0, 0x00), // MC_BIST
    (0x41, 0x24, 0x00),
    (0xE0, 0x14, 0x00), // RESET: hold DVP+JPEG during init
    (0x76, 0xFF, 0x00),
    (0x33, 0xA0, 0x00),
    (0x42, 0x20, 0x00),
    (0x43, 0x18, 0x00),
    (0x4C, 0x00, 0x00),
    (0x87, 0xD5, 0x00), // CTRL3
    (0x88, 0x3F, 0x00),
    (0xD7, 0x03, 0x00),
    (0xD9, 0x10, 0x00),
    (0xD3, 0x82, 0x00), // R_DVP_SP: auto+/2 (will be overridden)
    (0xC8, 0x08, 0x00),
    (0xC9, 0x80, 0x00),
    // SDE indirect registers (gamma, color)
    (0x7C, 0x00, 0x00),
    (0x7D, 0x00, 0x00),
    (0x7C, 0x03, 0x00),
    (0x7D, 0x48, 0x00),
    (0x7D, 0x48, 0x00),
    (0x7C, 0x08, 0x00),
    (0x7D, 0x20, 0x00),
    (0x7D, 0x10, 0x00),
    (0x7D, 0x0E, 0x00),
    // Gamma
    (0x7C, 0x00, 0x00),
    (0x7D, 0x04, 0x00),
    (0x7D, 0x09, 0x00),
    (0x7D, 0x20, 0x00),
    (0x7D, 0x38, 0x00),
    // Module enables
    (0xC2, 0x0C, 0x00), // CTRL0: YUV422+YUV_EN
    (0xC3, 0xEF, 0x00), // CTRL1: all ISP modules
    (0x86, 0x3D, 0x00), // CTRL2: DCW+SDE+UV_ADJ+UV_AVG+CMX
    // Sensor resolution for DSP (SVGA: 800/8=100, 600/8=75)
    (0xC0, 0x64, 0x00), // HSIZE8 = 100
    (0xC1, 0x4B, 0x00), // VSIZE8 = 75
    (0x8C, 0x00, 0x00), // SIZEL
    // Release resets
    (0xE0, 0x00, 0x00), // RESET: release all
];

// ═══ OV2640 SVGA mode registers ═══
// Applied after defaults, sets sensor windowing and DSP input size for SVGA.
// From Espressif ov2640_settings_to_svga[].

static OV2640_SVGA_REGS: &[(u8, u8, u8)] = &[
    // Sensor bank: SVGA mode + window
    (0x12, 0x40, 0x01), // COM7: SVGA
    (0x03, 0x0A, 0x01), // COM1
    (0x32, 0x09, 0x01), // REG32 (SVGA)
    (0x17, 0x11, 0x01), // HREFST
    (0x18, 0x43, 0x01), // HREFEND
    (0x19, 0x00, 0x01), // VSTRT
    (0x1A, 0x4B, 0x01), // VEND
    (0x37, 0xC0, 0x01),
    (0x4F, 0xCA, 0x01), // BD50
    (0x50, 0xA8, 0x01), // BD60
    (0x5A, 0x23, 0x01),
    (0x6D, 0x00, 0x01),
    (0x3D, 0x38, 0x01),
    (0x39, 0x92, 0x01),
    (0x35, 0xDA, 0x01),
    (0x22, 0x1A, 0x01),
    (0x37, 0xC3, 0x01),
    (0x23, 0x00, 0x01),
    (0x34, 0xC0, 0x01), // ARCOM2
    (0x06, 0x88, 0x01),
    (0x07, 0xC0, 0x01),
    (0x0D, 0x87, 0x01), // COM4
    (0x0E, 0x41, 0x01),
    (0x42, 0x03, 0x01),
    (0x4C, 0x00, 0x01),
    // DSP bank: SVGA resolution + window
    (0xE0, 0x04, 0x00), // RESET: hold DVP
    (0xC0, 0x64, 0x00), // HSIZE8 = 800/8 = 100
    (0xC1, 0x4B, 0x00), // VSIZE8 = 600/8 = 75
    (0x8C, 0x00, 0x00), // SIZEL
    // Image window >= output size
    (0x51, 0xC8, 0x00), // HSIZE = 800/4 = 200
    (0x52, 0x96, 0x00), // VSIZE = 600/4 = 150
    (0x53, 0x00, 0x00), // XOFFL
    (0x54, 0x00, 0x00), // YOFFL
    (0x55, 0x00, 0x00), // VHYX
    (0x57, 0x00, 0x00), // TEST
    (0xE0, 0x00, 0x00), // RESET: release DVP
];
