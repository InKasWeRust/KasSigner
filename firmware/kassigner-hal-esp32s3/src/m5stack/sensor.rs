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

//! The GC0308 camera sensor, over SCCB: at `0x21` on the shared I2C bus,
//! answering `0x9B` from register `0x00`, set up for 320x240 luminance
//! only, one byte a pixel, 76,800 a frame.
//!
//! [`DEFAULTS`] is Espressif's `gc0308_sensor_default_regs` with QR tuning,
//! 240 writes; [`SUBSAMPLE_QVGA`] the 1/2 subsample to 320x240, 17 writes.
//! `tests/m5stack_unit.rs` pins their size, first and last writes and the
//! output format they leave. Every boot runs [`init`] before the DVP
//! peripheral exists and [`reinit`] after; each ends in a full [`load`].
//!
//! # Reset, and no power-down pin
//!
//! The sensor's reset is expander line `P1.0`. Its power-down pin reaches
//! only the connector: expander `P0.4` is `TF_SW`, the card-detect switch,
//! not `CAM_PWDN`. What stops the camera is its rails
//! ([`super::camera::M5Camera`]).
//!
//! # SCCB reads are two transfers
//!
//! The register address is written, the bus stopped, then the byte read:
//! SCCB does not promise a repeated start.

use embedded_hal::i2c::I2c;
use kassigner_hal::camera::Error as CameraError;
use kassigner_hal::timer::Timer;
use kassigner_hal::tune::{Knob, Tune};

use super::pmu;

/// SCCB address, seven bits.
pub const ADDRESS: u8 = 0x21;

/// What register `0x00` holds on page 0.
pub const CHIP_ID: u8 = 0x9B;

/// Page select. `0x00` is page 0, `0x01` page 1, and `0x80` is soft reset.
const REG_PAGE: u8 = 0xFE;
/// Chip ID, page 0.
const REG_CHIP_ID: u8 = 0x00;
/// Output format, page 0. `0x91` is luminance only, the ISP's high eight bits.
const REG_OUTPUT_FORMAT: u8 = 0x24;
/// Output enable, page 0.
const REG_OUTPUT_EN: u8 = 0x25;
/// Sync mode, page 0.
const REG_SYNC_MODE: u8 = 0x26;
/// `CISCTL_MODE2`, page 0.
const REG_MODE2: u8 = 0x15;
/// Crop enable, page 0.
const REG_CROP: u8 = 0x46;
/// Subsample enable, page 1, bit 7.
const REG_SUBSAMPLE_EN: u8 = 0x53;
/// Subsample ratio, page 1.
const REG_SUBSAMPLE_MODE: u8 = 0x54;
/// Second subsample enable, page 1, bit 0.
const REG_SUBSAMPLE_EN2: u8 = 0x55;

/// Luminance only, the ISP's high eight bits.
pub const OUTPUT_Y8: u8 = 0x91;

/// The soft reset write, which needs 20 ms before the next one.
pub const SOFT_RESET: (u8, u8) = (REG_PAGE, 0x80);

/// Espressif's default table with QR tuning. Page 0 unless noted.
pub static DEFAULTS: &[(u8, u8)] = &[
    // Espressif gc0308_sensor_default_regs table
    // from espressif/esp32-camera (sensors/private_include/gc0308_settings.h)
    // Uses subsample mode (Page 1 regs 0x53-0x59) for clean QVGA output.
    (0xfe, 0x80), // Soft reset
    // (delay 20ms inserted by code)
    (0xfe, 0x00), // Select page 0
    // === Espressif default register table — Page 0 ===
    (0xec, 0x20),
    (0x05, 0x00), // ROW_START_H
    (0x06, 0x00), // ROW_START_L
    (0x07, 0x00), // COL_START_H
    (0x08, 0x00), // COL_START_L
    (0x09, 0x01), // WIN_HEIGHT_H  (488 = 0x01E8)
    (0x0a, 0xe8), // WIN_HEIGHT_L
    (0x0b, 0x02), // WIN_WIDTH_H   (648 = 0x0288)
    (0x0c, 0x88), // WIN_WIDTH_L
    (0x0d, 0x02), // VS_ST
    (0x0e, 0x02), // VS_ET
    (0x10, 0x26), // RSH_WIDTH
    (0x11, 0x0d), // TSP_WIDTH
    (0x12, 0x2a), // SAMPLE_HOLD_DELAY
    (0x13, 0x00), // ROW_TAIL_WIDTH
    (0x14, 0x10), // CISCTL_MODE1 (no mirror/flip)
    (0x15, 0x0a), // CISCTL_MODE2: progressive VGA, NO even-skip
    (0x16, 0x05), // CISCTL_MODE3
    (0x17, 0x01), // CISCTL_MODE4
    (0x18, 0x44), // Analog timing
    (0x19, 0x44), // Analog timing
    (0x1a, 0x2a), // ANALOG_MODE1
    (0x1b, 0x00), // ANALOG_MODE2
    (0x1c, 0x49), // HRST_RSG_V18
    (0x1d, 0x9a), // VREF_V25
    (0x1e, 0x61), // ADC_R
    (0x1f, 0x00), // PAD_DRV (<=24MHz, 0x00 is OK per Espressif)
    (0x20, 0x7f), // BLOCK_EN1
    (0x21, 0xfa), // BLOCK_EN2
    (0x22, 0x57), // AAAA_EN: AEC+AGC+AWB enabled
    (0x24, 0x91), // Output format: Y-only, ISP high 8 bits
    (0x25, 0x0f), // Output enable
    (0x26, 0x03), // Sync mode
    (0x28, 0x00), // PCLK_DIV: no division (ESP32-S3 supports up to 40MHz)
    (0x2d, 0x0a),
    (0x2f, 0x01),
    (0x30, 0xf7), // BLK mode
    (0x31, 0x50), // BLK limit
    (0x32, 0x00), // Global offset
    (0x33, 0x28),
    (0x34, 0x2a),
    (0x35, 0x28),
    (0x39, 0x04), // BLK config
    (0x3a, 0x20), // R offset
    (0x3b, 0x20), // G offset
    (0x3c, 0x00), // B offset
    (0x3d, 0x00), // G2 offset
    (0x3e, 0x00),
    (0x3f, 0x00),
    // Pre-gain
    (0x50, 0x14), // GLOBAL_GAIN
    (0x52, 0x41),
    (0x53, 0x80),
    (0x54, 0x80),
    (0x55, 0x80),
    (0x56, 0x80),
    // AWB gains
    (0x5a, 0x56), // AWB_R_GAIN
    (0x5b, 0x40), // AWB_G_GAIN
    (0x5c, 0x4a), // AWB_B_GAIN
    // AEC weights
    (0x8b, 0x20),
    (0x8c, 0x20),
    (0x8d, 0x20),
    (0x8e, 0x14),
    (0x8f, 0x10),
    (0x90, 0x14),
    (0x91, 0x3c),
    (0x92, 0x50),
    // LSC (Lens Shading)
    (0x5d, 0x12),
    (0x5e, 0x1a),
    (0x5f, 0x24),
    // DNDD (Denoise)
    (0x60, 0x07),
    (0x61, 0x15),
    (0x62, 0x08),
    (0x64, 0x03),
    (0x66, 0xe8),
    (0x67, 0x86),
    (0x68, 0x82),
    // ASDE
    (0x69, 0x18),
    (0x6a, 0x0f),
    (0x6b, 0x00),
    (0x6c, 0x5f),
    (0x6d, 0x8f),
    (0x6e, 0x55),
    (0x6f, 0x38),
    (0x70, 0x15),
    (0x71, 0x33),
    // INTPEE (Edge Enhancement) — boosted for sharper QR/BB edges
    (0x72, 0xfe), // stronger edge enhance than 0xdc
    (0x73, 0x00),
    (0x74, 0x02),
    (0x75, 0x3f),
    (0x76, 0x02),
    (0x77, 0x38),
    (0x78, 0x88),
    (0x79, 0x81),
    (0x7a, 0x81),
    (0x7b, 0x22),
    (0x7c, 0xff),
    // Gamma / Color matrix
    (0x93, 0x48),
    (0x94, 0x02),
    (0x95, 0x07),
    (0x96, 0xe0),
    (0x97, 0x40),
    (0x98, 0xf0),
    // Saturation + Contrast
    (0xb1, 0x40), // Cb saturation
    (0xb2, 0x40), // Cr saturation
    (0xb3, 0x50), // Contrast 1.25x (0x40=1.0x) — wider QR black/white gap
    (0xb6, 0xe0),
    // More ISP
    (0xbd, 0x38),
    (0xbe, 0x36),
    // AEC registers
    (0xd0, 0xCB),
    (0xd1, 0x10),
    (0xd2, 0x90),
    (0xd3, 0x38), // AEC target Y (lower than 0x48, for Y-only mode)
    (0xd5, 0xF2),
    (0xd6, 0x16),
    (0xdb, 0x92),
    (0xdc, 0xA5),
    (0xdf, 0x23),
    (0xd9, 0x00),
    (0xda, 0x00),
    (0xe0, 0x09),
    (0xed, 0x04),
    (0xee, 0xa0),
    (0xef, 0x40),
    (0x80, 0x03),
    // Gamma curve
    (0x9F, 0x10),
    (0xA0, 0x20),
    (0xA1, 0x38),
    (0xA2, 0x4e),
    (0xA3, 0x63),
    (0xA4, 0x76),
    (0xA5, 0x87),
    (0xA6, 0xa2),
    (0xA7, 0xb8),
    (0xA8, 0xca),
    (0xA9, 0xd8),
    (0xAA, 0xe3),
    (0xAB, 0xeb),
    (0xAC, 0xf0),
    (0xAD, 0xF8),
    (0xAE, 0xFD),
    (0xAF, 0xFF),
    // Second gamma/Y curve
    (0xc0, 0x00),
    (0xc1, 0x10),
    (0xc2, 0x1c),
    (0xc3, 0x30),
    (0xc4, 0x43),
    (0xc5, 0x54),
    (0xc6, 0x65),
    (0xc7, 0x75),
    (0xc8, 0x93),
    (0xc9, 0xB0),
    (0xca, 0xCB),
    (0xcb, 0xE6),
    (0xcc, 0xFF),
    // Clock / PLL
    (0xf0, 0x02),
    (0xf1, 0x01),
    (0xf2, 0x02),
    (0xf3, 0x30),
    (0xf7, 0x04),
    (0xf8, 0x02),
    (0xf9, 0x9f),
    (0xfa, 0x78),
    // === Page 1: AWB / AEC measure window / misc ===
    (0xfe, 0x01),
    (0x00, 0xf5),
    (0x02, 0x20),
    (0x04, 0x10),
    (0x05, 0x08),
    (0x06, 0x20),
    (0x08, 0x0a),
    (0x0a, 0xa0),
    (0x0b, 0x60),
    (0x0c, 0x08),
    (0x0e, 0x44),
    (0x0f, 0x32),
    (0x10, 0x41),
    (0x11, 0x37),
    (0x12, 0x22),
    (0x13, 0x19),
    (0x14, 0x44),
    (0x15, 0x44),
    (0x16, 0xc2),
    (0x17, 0xA8),
    (0x18, 0x18),
    (0x19, 0x50),
    (0x1a, 0xd8),
    (0x1b, 0xf5),
    (0x70, 0x40),
    (0x71, 0x58),
    (0x72, 0x30),
    (0x73, 0x48),
    (0x74, 0x20),
    (0x75, 0x60),
    (0x77, 0x20),
    (0x78, 0x32),
    (0x30, 0x03),
    (0x31, 0x40),
    (0x32, 0x10),
    (0x33, 0xe0),
    (0x34, 0xe0),
    (0x35, 0x00),
    (0x36, 0x80),
    (0x37, 0x00),
    (0x38, 0x04),
    (0x39, 0x09),
    (0x3a, 0x12),
    (0x3b, 0x1C),
    (0x3c, 0x28),
    (0x3d, 0x31),
    (0x3e, 0x44),
    (0x3f, 0x57),
    (0x40, 0x6C),
    (0x41, 0x81),
    (0x42, 0x94),
    (0x43, 0xA7),
    (0x44, 0xB8),
    (0x45, 0xD6),
    (0x46, 0xEE),
    (0x47, 0x0d),
    (0x62, 0xf7),
    (0x63, 0x68),
    (0x64, 0xd3),
    (0x65, 0xd3),
    (0x66, 0x60),
    // Back to Page 0 for frame timing
    (0xfe, 0x00),
    (0x01, 0x32), // HBLANK
    (0x02, 0x0c), // VBLANK
    (0x0f, 0x01), // VB_HB
    (0xe2, 0x00),
    (0xe3, 0x78),
    (0xe4, 0x00),
    (0xe5, 0xfe),
    (0xe6, 0x01),
    (0xe7, 0xe0),
    (0xe8, 0x01),
    (0xe9, 0xe0),
    (0xea, 0x01),
    (0xeb, 0xe0),
    (0xfe, 0x00),
];

/// The 1/2 subsample for 320x240, applied after [`DEFAULTS`].
///
/// As Espressif's `set_framesize`: the subsample block takes the full VGA
/// image and outputs 320x240 with proper HREF timing.
pub static SUBSAMPLE_QVGA: &[(u8, u8)] = &[
    // Ensure Page 0
    (0xfe, 0x00),
    // Window covers full sensor (subsample block reduces output)
    (0x05, 0x00), // ROW_START_H = 0
    (0x06, 0x00), // ROW_START_L = 0
    (0x07, 0x00), // COL_START_H = 0
    (0x08, 0x00), // COL_START_L = 0
    (0x09, 0x01), // WIN_HEIGHT_H  (488 = 0x01E8)
    (0x0a, 0xe8), // WIN_HEIGHT_L
    (0x0b, 0x02), // WIN_WIDTH_H   (648 = 0x0288)
    (0x0c, 0x88), // WIN_WIDTH_L
    // Disable crop mode — subsample handles size reduction
    (0x46, 0x00),
    // Switch to Page 1 for subsample registers
    (0xfe, 0x01),
    // Subsample mode: 1/2 ratio in both H and V
    (0x54, 0x22), // SUBSAMPLE_MODE
    (0x56, 0x00), // Y subsample config 0
    (0x57, 0x00), // Y subsample config 1
    (0x58, 0x00), // UV subsample config 0
    (0x59, 0x00), // UV subsample config 1
    // Back to Page 0
    (0xfe, 0x00),
];

/// Why the sensor did not come up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Nothing answered with [`CHIP_ID`]. `None` if nothing answered at all.
    NotDetected { id: Option<u8> },
    /// A register write was not acknowledged.
    WriteFailed { reg: u8 },
    /// A register read did not complete.
    ReadFailed { reg: u8 },
    /// The expander would not move the reset line.
    Reset,
}

/// Write one register. `false` if it was not acknowledged.
pub fn write_reg<I: I2c>(i2c: &mut I, reg: u8, val: u8) -> bool {
    i2c.write(ADDRESS, &[reg, val]).is_ok()
}

/// Read one register, as two transfers. `None` if either failed.
pub fn read_reg<I: I2c>(i2c: &mut I, reg: u8) -> Option<u8> {
    let mut buf = [0u8; 1];
    if i2c.write(ADDRESS, &[reg]).is_ok() && i2c.read(ADDRESS, &mut buf).is_ok() {
        return Some(buf[0]);
    }
    None
}

fn write<I: I2c>(i2c: &mut I, reg: u8, val: u8) -> Result<(), Error> {
    if write_reg(i2c, reg, val) {
        Ok(())
    } else {
        Err(Error::WriteFailed { reg })
    }
}

fn read<I: I2c>(i2c: &mut I, reg: u8) -> Result<u8, Error> {
    read_reg(i2c, reg).ok_or(Error::ReadFailed { reg })
}

/// The chip ID, from page 0. The page select is not checked: if it failed,
/// the read that follows fails too, and that is the answer.
pub fn chip_id<I: I2c>(i2c: &mut I) -> Option<u8> {
    let _ = write_reg(i2c, REG_PAGE, 0x00);
    read_reg(i2c, REG_CHIP_ID)
}

/// Whether a GC0308 is answering.
pub fn detect<I: I2c>(i2c: &mut I) -> bool {
    chip_id(i2c) == Some(CHIP_ID)
}

/// Pulse the sensor's reset through the expander.
///
/// # Errors
///
/// `Reset` if the expander did not take the write.
pub fn reset<I: I2c, T: Timer + ?Sized>(i2c: &mut I, timer: &mut T) -> Result<(), Error> {
    pmu::set_output(i2c, pmu::CAM_RST, false).map_err(|_| Error::Reset)?;
    timer.delay_ms(30);
    pmu::set_output(i2c, pmu::CAM_RST, true).map_err(|_| Error::Reset)?;
    timer.delay_ms(30);
    Ok(())
}

/// Write the whole configuration: the defaults, then the subsample. The
/// subsample enable bits are read-modify-write on page 1, and a failed read
/// there is an error, not taken as zero and written.
///
/// # Errors
///
/// `WriteFailed` or `ReadFailed` naming the first register that failed.
pub fn load<I: I2c, T: Timer + ?Sized>(i2c: &mut I, timer: &mut T) -> Result<(), Error> {
    for &(reg, val) in DEFAULTS {
        write(i2c, reg, val)?;
        if (reg, val) == SOFT_RESET {
            timer.delay_ms(20);
        }
    }
    timer.delay_ms(80);

    write(i2c, REG_PAGE, 0x01)?;
    let en = read(i2c, REG_SUBSAMPLE_EN)?;
    write(i2c, REG_SUBSAMPLE_EN, en | 0x80)?;
    let en2 = read(i2c, REG_SUBSAMPLE_EN2)?;
    write(i2c, REG_SUBSAMPLE_EN2, en2 | 0x01)?;
    write(i2c, REG_PAGE, 0x00)?;

    for &(reg, val) in SUBSAMPLE_QVGA {
        write(i2c, reg, val)?;
    }

    // The table ends on page 0, where both of these live.
    write(i2c, REG_OUTPUT_FORMAT, OUTPUT_Y8)?;
    write(i2c, REG_CROP, 0x00)?;

    // What the tables do not write, back to the datasheet's values.
    restore(i2c)?;

    // Let the exposure loop run a few frames.
    timer.delay_ms(100);
    Ok(())
}

/// First bring-up: reset, identify, load.
///
/// # Errors
///
/// `Reset` if the reset line did not move, `NotDetected` if the chip does not
/// answer with its ID, then as [`load`].
pub fn init<I: I2c, T: Timer + ?Sized>(i2c: &mut I, timer: &mut T) -> Result<(), Error> {
    reset(i2c, timer)?;
    // Settle before the first SCCB transfer.
    timer.delay_ms(30);
    match chip_id(i2c) {
        Some(CHIP_ID) => {}
        id => return Err(Error::NotDetected { id }),
    }
    load(i2c, timer)
}

/// Second bring-up, once the DVP peripheral exists: soft reset, identify,
/// load.
///
/// # Errors
///
/// `WriteFailed` if the soft reset or the page select was not acknowledged,
/// `NotDetected` if the chip stops answering, then as [`load`].
pub fn reinit<I: I2c, T: Timer + ?Sized>(i2c: &mut I, timer: &mut T) -> Result<(), Error> {
    write(i2c, SOFT_RESET.0, SOFT_RESET.1)?;
    timer.delay_ms(30);
    write(i2c, REG_PAGE, 0x00)?;
    timer.delay_ms(5);
    match chip_id(i2c) {
        Some(CHIP_ID) => {}
        id => return Err(Error::NotDetected { id }),
    }
    load(i2c, timer)
}

/// What [`DEFAULTS`] does not write and something may change, written at the
/// end of every load at the GC0308 datasheet's reset values.
///
/// The camera runs on [`DEFAULTS`] alone, with Settings' Camera over it.
/// A tuned set on top gave room-light frames more entropy, but it put 2 in
/// `0xD1` bits 3:2, the frames the sensor closes after each exposure change
/// to hide the bad one (the tables write 0), and in bright or changing
/// light the viewfinder froze for up to a second.
///
/// **This is the complete list of what may change at runtime and is not in
/// [`DEFAULTS`]: nothing else puts the sensor back.** The soft reset
/// (`0xFE[7]`) restarts the control logic, but this part keeps its register
/// file (the datasheet promises nothing), and its rail stays up through an
/// ESP32 reset: a value written by hand survives a reset and a reflash.
/// Exposure and pre-gain are the AEC's while it runs; the luma offset may
/// hold a value an earlier tuning screen set.
pub static FACTORY: &[(u8, u8)] = &[
    (REG_PAGE, 0x00), // they all live on page 0
    (0x03, 0x00),     // exposure, bits 11:8
    (0x04, 0x96),     // exposure, bits 7:0
    (0x51, 0x40),     // pre-gain, AEC-controlled while AEC is on
    (0xB5, 0x00),     // luma offset, signed
];

/// Write [`FACTORY`]: `load` ends with it, so a caller needs it only to put
/// those registers back without a full reload.
///
/// # Errors
///
/// `WriteFailed` if a register was not acknowledged.
pub fn restore<I: I2c>(i2c: &mut I) -> Result<(), Error> {
    for &(reg, val) in FACTORY {
        write(i2c, reg, val)?;
    }
    Ok(())
}

// ── Tuning ──────────────────────────────────────────────────────────────────

/// The settings Settings' Camera moves, in its order, and the register
/// behind each, from the GalaxyCore datasheet. [`DEFAULTS`] or [`FACTORY`]
/// writes every one, so a boot puts it back. The luma offset (`0xB5`) is
/// not among them: it measures best at zero, shifts the whole picture and
/// clips, and the exposure does its job.
///
/// Each moves its whole register except two, held to the datasheet's bits:
/// exposure's high part is `0x03[3:0]`, and global gain is six bits.
const TUNED: [(Knob, u8); 7] = [
    // AEC target luminance, what the exposure loop aims at; the screen
    // opens on it.
    (Knob::new("AEC-Y", 0xFF, 8).in_auto().lead(), 0xD3),
    // Exposure bits 11:8 and 7:0, in lines. The loop writes them while it
    // runs: they hold only in MANU.
    (Knob::new("EXPO-H", 0x0F, 1).in_manual(), 0x03),
    (Knob::new("EXPO-L", 0xFF, 8).in_manual(), 0x04),
    // Global gain, 0x10 being 1.0x, and pre-gain; likewise the loop's.
    (Knob::new("GAIN", 0x3F, 2).in_manual(), 0x50),
    (Knob::new("PREGN", 0xFF, 8).in_manual(), 0x51),
    // Luma contrast about the centre at 0xB4, 0x40 being 1.0x, in steps of
    // 4, a grid the tables' 0x50 is on.
    (Knob::new("CONTR", 0xFF, 4), 0xB3),
    // Edge effect, a nibble per edge path: the edges' strength. Not 0x72,
    // which is a mode register.
    (Knob::new("SHARP", 0xFF, 8), 0x77),
];

/// The knobs alone, for [`Tune::knobs`].
static KNOBS: [Knob; 7] = {
    let mut k = [Knob::new("", 0, 0); 7];
    let mut i = 0;
    while i < TUNED.len() {
        k[i] = TUNED[i].0;
        i += 1;
    }
    k
};

/// AEC mode 3; bit 7 is `AEC_en`, the exposure loop's on switch.
const REG_AEC_MODE3: u8 = 0xD2;
/// The switch.
const AEC_EN: u8 = 0x80;

/// The sensor as Settings' Camera moves it, over a handle of its own on the
/// shared bus. The writes land while the camera streams (SCCB is a path
/// separate from the LCD_CAM capture) and take effect on the next frame.
pub struct Tuner<I> {
    i2c: I,
}

impl<I: I2c> Tuner<I> {
    pub fn new(i2c: I) -> Self {
        Self { i2c }
    }

    /// Page 0, where every register here lives.
    fn page0(&mut self) -> Result<(), CameraError> {
        write(&mut self.i2c, REG_PAGE, 0x00).map_err(|_| CameraError::Io)
    }
}

impl<I: I2c> Tune for Tuner<I> {
    fn knobs(&self) -> &'static [Knob] {
        &KNOBS
    }

    fn read(&mut self, out: &mut [u8]) -> Result<(), CameraError> {
        self.page0()?;
        for (o, (_, reg)) in out.iter_mut().zip(TUNED.iter()) {
            *o = read(&mut self.i2c, *reg).map_err(|_| CameraError::Io)?;
        }
        Ok(())
    }

    fn write(&mut self, knob: usize, value: u8) -> Result<(), CameraError> {
        let (k, reg) = TUNED.get(knob).ok_or(CameraError::Io)?;
        self.page0()?;
        write(&mut self.i2c, *reg, value.min(k.max)).map_err(|_| CameraError::Io)
    }

    fn auto(&mut self) -> Option<bool> {
        self.page0().ok()?;
        read(&mut self.i2c, REG_AEC_MODE3)
            .ok()
            .map(|v| v & AEC_EN != 0)
    }

    fn set_auto(&mut self, on: bool) -> Result<(), CameraError> {
        self.page0()?;
        let v = read(&mut self.i2c, REG_AEC_MODE3).map_err(|_| CameraError::Io)?;
        let v = if on { v | AEC_EN } else { v & !AEC_EN };
        write(&mut self.i2c, REG_AEC_MODE3, v).map_err(|_| CameraError::Io)
    }
}

/// Registers worth checking after a load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Readback {
    /// Output format. [`OUTPUT_Y8`].
    pub format: u8,
    /// Output enable. `0x0F`.
    pub output_enable: u8,
    /// Sync mode. `0x03`.
    pub sync: u8,
    /// `CISCTL_MODE2`. `0x0A`.
    pub mode2: u8,
    /// Crop. `0x00`.
    pub crop: u8,
    /// Page 1 subsample enable. Bit 7 set.
    pub subsample_en: u8,
    /// Page 1 subsample ratio. `0x22`.
    pub subsample_mode: u8,
    /// Page 1 second subsample enable. Bit 0 set.
    pub subsample_en2: u8,
}

impl Readback {
    /// Whether these are the values [`load`] leaves.
    pub fn is_loaded(&self) -> bool {
        self.format == OUTPUT_Y8
            && self.output_enable == 0x0F
            && self.sync == 0x03
            && self.mode2 == 0x0A
            && self.crop == 0x00
            && self.subsample_en & 0x80 != 0
            && self.subsample_mode == 0x22
            && self.subsample_en2 & 0x01 != 0
    }
}

/// Read the registers [`load`] sets, and leave the sensor on page 0.
///
/// # Errors
///
/// `ReadFailed` or `WriteFailed` naming the register.
pub fn read_back<I: I2c>(i2c: &mut I) -> Result<Readback, Error> {
    write(i2c, REG_PAGE, 0x00)?;
    let format = read(i2c, REG_OUTPUT_FORMAT)?;
    let output_enable = read(i2c, REG_OUTPUT_EN)?;
    let sync = read(i2c, REG_SYNC_MODE)?;
    let mode2 = read(i2c, REG_MODE2)?;
    let crop = read(i2c, REG_CROP)?;
    write(i2c, REG_PAGE, 0x01)?;
    let subsample_en = read(i2c, REG_SUBSAMPLE_EN)?;
    let subsample_mode = read(i2c, REG_SUBSAMPLE_MODE)?;
    let subsample_en2 = read(i2c, REG_SUBSAMPLE_EN2)?;
    write(i2c, REG_PAGE, 0x00)?;
    Ok(Readback {
        format,
        output_enable,
        sync,
        mode2,
        crop,
        subsample_en,
        subsample_mode,
        subsample_en2,
    })
}
