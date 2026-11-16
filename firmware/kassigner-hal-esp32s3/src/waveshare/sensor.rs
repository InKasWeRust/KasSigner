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

//! The OV5640 sensor: the register tables that put it into 480x480 Y8,
//! tuned by eye on a screen rather than derived from the datasheet. The
//! receiving end, LCD_CAM and the DMA path, is [`super::cam_dma`], and the
//! routing [`crate::gpio_matrix`]. Generic over `embedded_hal::i2c::I2c`.
//!
//! # Autofocus: the lens cannot move on this board
//!
//! The sensor's own MCU and voice coil driver, a 10-bit DAC sinking up to
//! 100 mA at `0x3602` and `0x3603`, answer on the sensor's bus, but the coil's
//! other end is pin 23 of the module's connector, `AF-VCC2.8V` in the module
//! spec, and this board leaves pins 23 and 24 unconnected: the schematic
//! names them `(AF_VDD)Y1` and `(AF_GND)Y0`, the two data lines an 8-bit bus
//! does not use, with no net on either.
//!
//! Measured on the unit: with the AF firmware loaded for the test (`0x3029`
//! reads `0x70`) and exposure and gain locked at `0x3503`, driving the DAC
//! end to end leaves the picture unchanged, so this driver loads none. 2.8 V
//! to pin 23 and ground to pin 24, with the module's R1 and R2 populated,
//! would change that; until then the camera is fixed-focus from around
//! 30 cm.
//!
//! [`Module`], the module fitted, is a runtime choice, not a build feature.

use embedded_hal::i2c::I2c;
use kassigner_hal::camera::Error as CameraError;
use kassigner_hal::timer::Timer;
use kassigner_hal::tune::{Knob, Tune};

use crate::systimer::SysTimer;

/// SCCB address. The sensor answers here and at nothing else.
pub const ADDRESS: u8 = 0x3C;

/// The sensor's product ID, read from `0x300A` and `0x300B`.
pub const PRODUCT_ID: u16 = 0x5640;

/// Which module is fitted.
///
/// The autofocus module is mounted rotated 180 degrees, so its image arrives
/// upside down unless both axes are flipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Module {
    /// Fixed focus. No flip.
    FixedFocus,
    /// Autofocus, mounted rotated. Both axes flipped; no autofocus firmware,
    /// as the lens cannot move on this board (module doc).
    AutoFocus,
}

/// Why the sensor did not come up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Nothing answered at [`ADDRESS`], or it answered with the wrong ID.
    NotDetected { id: u16 },
    /// A register write was not acknowledged.
    WriteFailed { reg: u16 },
}

/// Put the sensor in software standby, or bring it out: `0x3008` bit 6,
/// the OV5640's software power-down, which keeps every register: off camera
/// screens the sensor does not stream. `0x02` is the register's value awake.
pub fn standby<I: I2c>(i2c: &mut I, on: bool) -> bool {
    write_reg(i2c, 0x3008, if on { 0x42 } else { 0x02 })
}

/// Write one sixteen-bit-addressed register.
pub fn write_reg<I: I2c>(i2c: &mut I, reg: u16, val: u8) -> bool {
    i2c.write(ADDRESS, &[(reg >> 8) as u8, reg as u8, val])
        .is_ok()
}

/// Read one sixteen-bit-addressed register.
pub fn read_reg<I: I2c>(i2c: &mut I, reg: u16) -> Option<u8> {
    let mut buf = [0u8; 1];
    i2c.write_read(ADDRESS, &[(reg >> 8) as u8, reg as u8], &mut buf)
        .ok()
        .map(|_| buf[0])
}

/// The product ID the sensor reports.
pub fn product_id<I: I2c>(i2c: &mut I) -> u16 {
    let h = read_reg(i2c, 0x300A).unwrap_or(0);
    let l = read_reg(i2c, 0x300B).unwrap_or(0);
    ((h as u16) << 8) | l as u16
}

/// Whether an OV5640 is present.
pub fn detect<I: I2c>(i2c: &mut I) -> bool {
    product_id(i2c) == PRODUCT_ID
}

/// Bring the sensor up in 480x480 Y8.
///
/// Three tables in order: the baseline, the window and output overrides that
/// make it 480x480, and the close-range tuning for reading a QR code off a lit
/// screen; then [`SCAN_DEFAULTS`] over the tuning.
///
/// # Errors
///
/// `NotDetected` if nothing answers with the right ID, `WriteFailed` naming the
/// first register that was not acknowledged.
pub fn init<I: I2c>(i2c: &mut I, module: Module) -> Result<(), Error> {
    let mut timer = SysTimer;

    let id = product_id(i2c);
    if id != PRODUCT_ID {
        return Err(Error::NotDetected { id });
    }

    for &(reg, val) in INIT_REGS {
        if !write_reg(i2c, reg, val) {
            return Err(Error::WriteFailed { reg });
        }
    }
    timer.delay_ms(300);

    for &(reg, val) in OVERRIDES_480 {
        if !write_reg(i2c, reg, val) {
            return Err(Error::WriteFailed { reg });
        }
    }
    timer.delay_ms(100);

    if module == Module::AutoFocus {
        // The AF module is mounted rotated 180 degrees.
        for &(reg, val) in [(0x3820u16, 0x47u8), (0x3821, 0x06)].iter() {
            if !write_reg(i2c, reg, val) {
                return Err(Error::WriteFailed { reg });
            }
        }
    }

    for &(reg, val) in LCD_QR_TUNING.iter().chain(SCAN_DEFAULTS) {
        if !write_reg(i2c, reg, val) {
            return Err(Error::WriteFailed { reg });
        }
    }
    timer.delay_ms(100);

    Ok(())
}

/// The starting values of the six camera settings, written over
/// [`LCD_QR_TUNING`] at the end of every load: the unit's defaults.
///
/// With these, and the AGC ceiling lowered to about `0x30` on the tuning
/// screen, a version 13 code read off an iPhone, where no set tried with the
/// tables' values did: a phone's screen wants the lower ceiling.
///
/// | register | here | the tables |
/// |---|---|---|
/// | AEC high, `0x3A0F` and `0x3A1B` | `0x58` | `0x60` |
/// | AEC low, `0x3A10` and `0x3A1E` | `0x48` | `0x40` |
/// | contrast, `0x5586` | `0x38` | `0x28` |
/// | brightness, `0x5587` | `0x00` | `0x10` |
/// | AGC ceiling, `0x3A18`/`0x3A19` | `0x00B0` | `0x0078` |
/// | sharpen, `0x5302` | `0x30` | `0x30` |
pub static SCAN_DEFAULTS: &[(u16, u8)] = &[
    (0x3A0F, 0x58),
    (0x3A1B, 0x58),
    (0x3A10, 0x48),
    (0x3A1E, 0x48),
    (0x5586, 0x38),
    (0x5587, 0x00),
    (0x3A18, 0x00),
    (0x3A19, 0xB0),
    (0x5302, 0x30),
];

// ── Tuning ──────────────────────────────────────────────────────────────────

/// The six settings Settings' Camera moves on this unit, in steps of 4.
/// Every register here is written by [`INIT_REGS`], [`LCD_QR_TUNING`] or
/// [`SCAN_DEFAULTS`], so a boot puts it back.
static KNOBS: [Knob; 6] = [
    Knob::new("AEC-H", 0xFF, 4),
    Knob::new("AEC-L", 0xFF, 4),
    Knob::new("Contr", 0xFF, 4),
    Knob::new("Brite", 0xFF, 4),
    Knob::new("AGC", 0xFF, 4).lead(),
    Knob::new("Sharp", 0xFF, 4),
];

/// The AEC's stable window, high and low, each with the pair that shadows
/// it on the way out.
const AEC_HIGH: [u16; 2] = [0x3A0F, 0x3A1B];
const AEC_LOW: [u16; 2] = [0x3A10, 0x3A1E];
/// The SDE's contrast gain, and its brightness magnitude. The brightness
/// sign is `0x5588` bit 3 (OmniVision's application note, 4.9.1), which the
/// tables leave positive and nothing here moves.
const CONTRAST: u16 = 0x5586;
const BRIGHTNESS: u16 = 0x5587;
/// The gain ceiling's low byte; the high one, `0x3A18`, stays zero.
const GAIN_CEILING: u16 = 0x3A19;
/// CIP sharpen, MT offset 1, in the manual mode `LCD_QR_TUNING` sets.
const SHARPEN: u16 = 0x5302;

/// The sensor as Settings' Camera moves it, over the camera's own bus.
///
/// No switch for the exposure loop on this unit.
pub struct Tuner<I> {
    i2c: I,
}

impl<I: I2c> Tuner<I> {
    pub fn new(i2c: I) -> Self {
        Self { i2c }
    }

    fn get(&mut self, reg: u16) -> Result<u8, CameraError> {
        read_reg(&mut self.i2c, reg).ok_or(CameraError::Io)
    }

    fn set(&mut self, regs: &[u16], value: u8) -> Result<(), CameraError> {
        for &reg in regs {
            if !write_reg(&mut self.i2c, reg, value) {
                return Err(CameraError::Io);
            }
        }
        Ok(())
    }
}

impl<I: I2c> Tune for Tuner<I> {
    fn knobs(&self) -> &'static [Knob] {
        &KNOBS
    }

    fn read(&mut self, out: &mut [u8]) -> Result<(), CameraError> {
        let regs = [
            AEC_HIGH[0],
            AEC_LOW[0],
            CONTRAST,
            BRIGHTNESS,
            GAIN_CEILING,
            SHARPEN,
        ];
        for (o, reg) in out.iter_mut().zip(regs) {
            *o = self.get(reg)?;
        }
        Ok(())
    }

    /// The window's low edge is held at or under its high one: the exposure
    /// loop converges only while high is at least low.
    fn write(&mut self, knob: usize, value: u8) -> Result<(), CameraError> {
        match knob {
            0 => {
                self.set(&AEC_HIGH, value)?;
                if self.get(AEC_LOW[0])? > value {
                    self.set(&AEC_LOW, value)?;
                }
                Ok(())
            }
            1 => {
                let high = self.get(AEC_HIGH[0])?;
                self.set(&AEC_LOW, value.min(high))
            }
            2 => self.set(&[CONTRAST], value),
            3 => self.set(&[BRIGHTNESS], value),
            4 => self.set(&[GAIN_CEILING], value),
            5 => self.set(&[SHARPEN], value),
            _ => Err(CameraError::Io),
        }
    }

    fn auto(&mut self) -> Option<bool> {
        None
    }

    fn set_auto(&mut self, _on: bool) -> Result<(), CameraError> {
        Err(CameraError::Io)
    }
}

pub static INIT_REGS: &[(u16, u8)] = &[
    (0x3008, 0x82),
    (0x3008, 0x42),
    (0x3103, 0x13),
    (0x3034, 0x18),
    (0x3035, 0x21),
    (0x3036, 0x18),
    (0x3037, 0x01),
    (0x3108, 0x01),
    (0x3017, 0xFF),
    (0x3018, 0xFF),
    (0x3000, 0x00),
    (0x3002, 0x00),
    (0x3004, 0xFF),
    (0x3006, 0xFF),
    (0x302E, 0x08),
    (0x3820, 0x41),
    (0x3821, 0x00),
    // Center crop: 1280×960 from 2592×1944 (~2× zoom)
    // X start=656(0x0290), X end=1935(0x078F)
    // Y start=492(0x01EC), Y end=1451(0x05AB)
    (0x3800, 0x02),
    (0x3801, 0x90),
    (0x3802, 0x01),
    (0x3803, 0xEC),
    (0x3804, 0x07),
    (0x3805, 0x8F),
    (0x3806, 0x05),
    (0x3807, 0xAB),
    // DVP output: 320×240 (DCW 4× from 1280×960)
    (0x3808, 0x01),
    (0x3809, 0x40),
    (0x380A, 0x00),
    (0x380B, 0xF0),
    (0x380C, 0x07),
    (0x380D, 0x68),
    (0x380E, 0x03),
    (0x380F, 0xD8),
    (0x3810, 0x00),
    (0x3811, 0x00),
    (0x3812, 0x00),
    (0x3813, 0x00),
    (0x3814, 0x11),
    (0x3815, 0x11),
    (0x3630, 0x36),
    (0x3631, 0x0E),
    (0x3632, 0xE2),
    (0x3633, 0x12),
    (0x3621, 0xE0),
    (0x3704, 0xA0),
    (0x3703, 0x5A),
    (0x3715, 0x78),
    (0x3717, 0x01),
    (0x370B, 0x60),
    (0x3705, 0x1A),
    (0x3905, 0x02),
    (0x3906, 0x10),
    (0x3901, 0x0A),
    (0x3731, 0x12),
    (0x3600, 0x08),
    (0x3601, 0x33),
    (0x302D, 0x60),
    (0x3620, 0x52),
    (0x471C, 0x50),
    (0x3A13, 0x43),
    (0x3A18, 0x00),
    (0x3A19, 0xF8),
    (0x3635, 0x13),
    (0x3636, 0x03),
    (0x3634, 0x40),
    (0x3622, 0x01),
    (0x3C01, 0xA4),
    (0x3C04, 0x28),
    (0x3C05, 0x98),
    (0x3C06, 0x00),
    (0x3C07, 0x08),
    (0x3C08, 0x00),
    (0x3C09, 0x1C),
    (0x3C0A, 0x9C),
    (0x3C0B, 0x40),
    (0x3008, 0x02),
    (0x3618, 0x00),
    (0x3612, 0x29),
    (0x3708, 0x64),
    (0x3709, 0x52),
    (0x370C, 0x03),
    (0x4001, 0x02),
    (0x4004, 0x02),
    (0x3000, 0x00),
    (0x3002, 0x1C),
    (0x3004, 0xFF),
    (0x3006, 0xC3),
    (0x4300, 0x10),
    (0x501F, 0x00),
    (0x4740, 0x21),
    (0x5001, 0xA3),
    // DCW 4× downscale: 1280×960 → 320×240
    (0x5600, 0x10),
    (0x5601, 0x22),
    (0x3A02, 0x03),
    (0x3A03, 0xD8),
    (0x3A08, 0x01),
    (0x3A09, 0x3C),
    (0x3A0A, 0x01),
    (0x3A0B, 0x07),
    (0x3A0D, 0x04),
    (0x3A0E, 0x03),
    (0x3A0F, 0x58),
    (0x3A10, 0x48),
    (0x3A11, 0x80),
    (0x3A1B, 0x58),
    (0x3A1E, 0x48),
    (0x3A1F, 0x20),
    (0x5300, 0x08),
    (0x5301, 0x30),
    (0x5302, 0x10),
    (0x5303, 0x00),
    (0x5304, 0x08),
    (0x5305, 0x30),
    (0x5306, 0x10),
    (0x5307, 0x10),
    (0x5308, 0x08), // CIP control; LCD_QR_TUNING writes it again
    (0x5309, 0x08),
    (0x530A, 0x30),
    (0x530B, 0x02),
    (0x5480, 0x01),
    (0x5481, 0x08),
    (0x5482, 0x14),
    (0x5483, 0x28),
    (0x5484, 0x51),
    (0x5485, 0x65),
    (0x5486, 0x71),
    (0x5487, 0x7D),
    (0x5488, 0x87),
    (0x5489, 0x91),
    (0x548A, 0x9A),
    (0x548B, 0xAA),
    (0x548C, 0xB8),
    (0x548D, 0xCD),
    (0x548E, 0xDD),
    (0x548F, 0xEA),
    (0x5490, 0x1D),
    (0x5580, 0x06),
    (0x5583, 0x50),
    (0x5584, 0x10),
    (0x5586, 0x28),
    (0x5585, 0x00),
    (0x5587, 0x10),
    (0x5588, 0x00),
    (0x5688, 0x11),
    (0x5689, 0x11),
    (0x568A, 0x1F),
    (0x568B, 0xF1),
    (0x568C, 0x1F),
    (0x568D, 0xF1),
    (0x568E, 0x11),
    (0x568F, 0x11),
];

pub static OVERRIDES_480: &[(u16, u8)] = &[
    // ── Sensor window: 960×960 center crop ──
    // X start = 816 = 0x0330
    (0x3800, 0x03),
    (0x3801, 0x30),
    // Y start = 492 = 0x01EC
    (0x3802, 0x01),
    (0x3803, 0xEC),
    // X end = 1775 = 0x06EF
    (0x3804, 0x06),
    (0x3805, 0xEF),
    // Y end = 1451 = 0x05AB
    (0x3806, 0x05),
    (0x3807, 0xAB),
    // ── DVP output size: 480×480 ──
    (0x3808, 0x01),
    (0x3809, 0xE0), // DVPHO = 480
    (0x380A, 0x01),
    (0x380B, 0xE0), // DVPVO = 480
    // ── Total pixel timing (HTS/VTS) ──
    // HTS: keep generous for stable PCLK
    (0x380C, 0x07),
    (0x380D, 0x68), // HTS = 1896
    (0x380E, 0x03),
    (0x380F, 0xD8), // VTS = 984
    // ── Offset: 0,0 ──
    (0x3810, 0x00),
    (0x3811, 0x00),
    (0x3812, 0x00),
    (0x3813, 0x00),
    // ── Sub-sampling: none (0x11 = skip 0, step 1) ──
    (0x3814, 0x11),
    (0x3815, 0x11),
    // ── ISP/DCW: 2× downscale (960→480) ──
    // 0x5001: bit7=SDE ON (without it, the Contr and Brite settings' writes
    // to 0x5586/0x5587 land but have no visible effect), bit5=scale,
    // bit1=CMX. AWB(bit0) stays OFF for clean Y8 (the luma plane is
    // unaffected by white balance anyway).
    (0x5001, 0xA2),
    // DCW enable + 2× ratio
    (0x5600, 0x10), // DCW enable
    (0x5601, 0x11), // 2× in both H and V
    // ── Flip/mirror: default orientation; `init` flips for the AF module ──
    (0x3820, 0x41),
    (0x3821, 0x00),
];

pub static LCD_QR_TUNING: &[(u16, u8)] = &[
    // ── AEC/AGC mode: 0x3A00 = 0x78 ──
    // Night mode off (a steady frame rate, not longer integration) and
    // banding on: banding-aware average metering, against LCD backlight
    // flicker.
    (0x3A00, 0x78),
    // ── AEC stable range: 0x3A0F (WPT) / 0x3A10 (BPT) / 0x3A1B / 0x3A1E ──
    // 0x60 to both high limits, 0x40 to both low ones (enter and go out):
    // wider than the init table's 0x58/0x48, against AEC oscillating on pure
    // black-and-white QR patterns. SCAN_DEFAULTS puts 0x58/0x48 back at the
    // end of the load.
    (0x3A0F, 0x60),
    (0x3A10, 0x40),
    (0x3A1B, 0x60),
    (0x3A1E, 0x40),
    // ── AGC ceiling: keep gain moderate to limit noise amplification ──
    // About half the init table's 0x3A18=0x00 / 0x3A19=0xF8, to reduce
    // noise that hurts the decoder's edge detection. SCAN_DEFAULTS writes
    // 0xB0 at the end of the load.
    (0x3A18, 0x00),
    (0x3A19, 0x78),
    // ── ISP master control: 0x5000 ──
    // 0xA7 = 0b1010_0111: bit7=LENC ON (lens shading correction), bit5=raw
    // gamma ON, bit2=BPC ON (black pixel cancellation), bit1=WPC ON (white
    // pixel cancellation), bit0=CIP ON (colour interpolation + edge
    // processing). CIP matters: blurred input needs the sharpening pass, not
    // smoothing.
    (0x5000, 0xA7),
    // ── CIP sharpen: 0x5302 / 0x5308 / 0x5309 / 0x530B ──
    // 0x5302 = sharpen MT offset1: stronger sharpen on mid-frequency edges
    // (the Sharp setting moves it).
    // 0x5308 = 0x40: bit 6, manual edge MT, so 0x5302 applies.
    // 0x5309 = sharpen MT threshold high — aggressive for blur recovery.
    // 0x530B = sharpen TH offset1 — minimum, let auto handle detail.
    (0x5302, 0x30),
    (0x5308, 0x40),
    (0x5309, 0x20),
    (0x530B, 0x08),
    // ── Denoise: 0x5306 / 0x5307 ──
    // Keep denoise moderate — too much kills QR module edges.
    (0x5306, 0x08),
    (0x5307, 0x10),
    // ── Contrast/Brightness SDE: 0x5580 ──
    // bit2=contrast enable, bit1=saturation enable (datasheet SDE CTRL0);
    // the Contr and Brite settings write 0x5586/0x5587.
    (0x5580, 0x06),
];

// ── LCD_CAM ─────────────────────────────────────────────────────────────────
//
// LCD_CAM's `cam_clk` must not be routed to GPIO8: LEDC drives the sensor's
// 20 MHz master clock there, and without it the sensor stops answering on
// SCCB. LCD_CAM's clock enable is `SYSTEM_PERIP_CLK_EN1` bit 8 (TRM register
// 17.5), not bit 0, `PERI_BACKUP`. `cam_dma::init` sets the clocks, end of
// frame on VSYNC and the VSYNC filter.
//
// # The order that works
//
//   1  PWDN low
//   2  LEDC 20 MHz on GPIO8
//   3  30 ms
//   4  `init` over SCCB
//   5  `crate::gpio_matrix::apply`
//   6  `cam_dma::init`
//
// Routing before SCCB appears to work too, but is not the order used.
