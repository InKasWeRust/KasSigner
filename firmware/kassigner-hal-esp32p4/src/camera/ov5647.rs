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

//! OV5647 sensor driver. SCCB shares the board I2C bus on GPIO7/8 with the
//! PMIC, codec and touch.
//!
//! Espressif's mode headers compute entries from IDI_CLOCK_RATE; resolve
//! each one separately. 0x4837 is the MIPI PCLK period behind the sensor's
//! D-PHY timing; 0x3036's value, 0x80, written there in place of 0x28
//! gives a transmitter the receiver cannot lock to.
//!
//!   0x3036 = (IDI_CLOCK_RATE * 8 * 4) / 25000000   = 0x80
//!   0x4837 = 1000000000 / (IDI_CLOCK_RATE / 4)     = 0x28

/// MIPI lane rate, Mbps per lane, of the 480x480 RAW8 2-lane mode: the
/// window X 500..2623, Y 0..1953 binned and subsampled to 1062 by 977,
/// whose middle 480 square the sensor's ISP outputs. Its 240x240 green
/// plane is the M5's, which the decoder was tuned on.
pub const LANE_RATE_MBPS: u32 = 400;
/// Mode width, centred in the 1062 binned columns by the ISP offset
/// (`0x3810`/`0x3811`, 291).
pub const WIDTH: u32 = 480;
/// Mode height, all captured, centred in the 977 binned rows by the ISP
/// offset (`0x3812`/`0x3813`, 248).
pub const HEIGHT: u32 = 480;

/// Chip ID at 0x300A/0x300B.
pub const CHIP_ID: u16 = 0x5647;

/// Espressif's `ov5647_mipi_reset_regs`, which puts the MIPI transmitter in
/// a known state. The sensor leaves software reset with its MIPI pads
/// powered down (0x3016/0x3017/0x3018); the mode table powers them.
pub static RESET_REGS: &[(u16, u8)] = &[
    (0x0100, 0x00), // sleep
    (0x0103, 0x01), // software reset  (then wait ~10 ms)
    (0x4800, 0x01), // CLOCK_LANE_DISABLE -> clock lane to LP-11
];

/// Stream on, from `ov5647_set_stream()`, plus 0x4202 and 0x300d from the
/// Linux ov5647 driver.
pub static STREAM_ON: &[(u16, u8)] = &[
    (0x4800, 0x00),
    (0x4202, 0x00),
    (0x300d, 0x00),
    (0x0100, 0x01),
];

/// Stream off + software standby.
pub static STREAM_OFF: &[(u16, u8)] = &[(0x0100, 0x00), (0x4800, 0x01)];

/// Espressif's `ov5647_mipi_2lane_24Minput_800x640_raw8_50fps`, set for
/// the 480 square that [`LANE_RATE_MBPS`] describes.
pub static MODE_480X480_RAW8: &[(u16, u8)] = &[
    (0x3034, 0x18),
    (0x3035, 0x41),
    (0x3036, 0x80),
    (0x303c, 0x11),
    (0x3106, 0xf5),
    (0x3821, 0x03),
    (0x3820, 0x41),
    (0x3827, 0xec),
    (0x370c, 0x0f),
    (0x3612, 0x59),
    (0x3618, 0x00),
    (0x5000, 0xff),
    (0x583e, 0xf0),
    (0x583f, 0x20),
    (0x5002, 0x41),
    (0x5003, 0x08),
    (0x5a00, 0x08),
    (0x3000, 0x00),
    (0x3001, 0x00),
    (0x3002, 0x00),
    (0x3016, 0x08),
    (0x3017, 0xe0),
    (0x3018, 0x44),
    (0x301c, 0xf8),
    (0x301d, 0xf0),
    (0x3a18, 0x00),
    (0x3a19, 0xf8),
    (0x3c01, 0x80),
    (0x3c00, 0x40),
    (0x3b07, 0x0c),
    (0x380c, 0x7),
    (0x380d, 0x68),
    (0x380e, 0x3),
    (0x380f, 0xd8),
    // Two-to-one subsampling (odd increment 3, even 1) with the 2x2
    // binning in 0x3820/0x3821: each output pixel averages a 2x2 block.
    // Four-to-one skipping, for a wider field, adds visible noise.
    (0x3814, 0x31),
    (0x3815, 0x31),
    (0x3708, 0x64),
    (0x3709, 0x52),
    // The window, 2124 by 1954, binned and subsampled to 1062 by 977. A
    // 1944-square window makes the sensor double every line, so the ISP
    // offsets below, 291 and 248, cut the centred square.
    (0x3800, 0x1),
    (0x3801, 0xf4),
    (0x3802, 0x0),
    (0x3803, 0x0),
    (0x3804, 0xa),
    (0x3805, 0x3f),
    (0x3806, 0x7),
    (0x3807, 0xa1),
    (0x3808, 0x1),
    (0x3809, 0xe0),
    (0x380a, 0x1),
    (0x380b, 0xe0),
    (0x3810, 0x1),
    (0x3811, 0x23),
    (0x3812, 0x0),
    (0x3813, 0xf8),
    (0x3630, 0x2e),
    (0x3632, 0xe2),
    (0x3633, 0x23),
    (0x3634, 0x44),
    (0x3636, 0x06),
    (0x3620, 0x64),
    (0x3621, 0xe0),
    (0x3600, 0x37),
    (0x3704, 0xa0),
    (0x3703, 0x5a),
    (0x3715, 0x78),
    (0x3717, 0x01),
    (0x3731, 0x02),
    (0x370b, 0x60),
    (0x3705, 0x1a),
    (0x3f05, 0x02),
    (0x3f06, 0x10),
    (0x3f01, 0x0a),
    (0x3a08, 0x01),
    (0x3a09, 0x27),
    (0x3a0a, 0x00),
    (0x3a0b, 0xf6),
    (0x3a0d, 0x04),
    (0x3a0e, 0x03),
    (0x3a0f, 0x58),
    (0x3a10, 0x50),
    (0x3a1b, 0x58),
    (0x3a1e, 0x50),
    (0x3a11, 0x60),
    (0x3a1f, 0x28),
    (0x4001, 0x02),
    (0x4004, 0x02),
    (0x4000, 0x09),
    (0x4837, 0x28),
    (0x4050, 0x6e),
    (0x4051, 0x8f),
];

/// Sensor register addresses worth naming.
pub mod reg {
    /// Chip ID high byte; reads 0x56.
    pub const CHIP_ID_HI: u16 = 0x300A;
    /// Chip ID low byte; reads 0x47.
    pub const CHIP_ID_LO: u16 = 0x300B;
    /// 0 = software standby, 1 = streaming.
    pub const MODE_SELECT: u16 = 0x0100;
    /// Write 1 to reset all registers to defaults.
    pub const SOFTWARE_RESET: u16 = 0x0103;
    /// MIPI control: clock-lane gating and LP-11 behaviour between frames.
    pub const MIPI_CTRL00: u16 = 0x4800;
    /// MIPI pad enable; the mode table sets it, or the lanes stay off.
    pub const MIPI_PAD_CTRL: u16 = 0x3018;
    /// AEC/AGC manual enable: b0 AGC manual, b1 AEC manual. 0 = fully auto.
    pub const AEC_MANUAL: u16 = 0x3503;
    /// Exposure, 20 bits across 0x3500..0x3502, in units of 1/16 line.
    pub const EXPOSURE_HI: u16 = 0x3500;
    /// Gain, 10 bits across 0x350a/0x350b. 0x3ff is maximum, about 16x.
    pub const GAIN_HI: u16 = 0x350a;
}

/// SCCB address on the shared bus.
pub const ADDR: u8 = 0x36;

/// What the P4 boots with, after the mode table: every setting the tuning
/// screen moves, at its mode-table or reset value, made explicit as on the
/// other two units.
///
/// | setting | register | value | on the screen |
/// |---|---|---|---|
/// | exposure loop | `0x3503` | `0x00`, on | AUTO |
/// | AEC high | `0x3A0F`, `0x3A1B` | `0x58` | AEC-H `0x58` |
/// | AEC low | `0x3A10`, `0x3A1E` | `0x50` | AEC-L `0x50` |
/// | gain ceiling | `0x3A18`/`0x3A19` | 248 | AGC `0x3E` |
/// | exposure bands, 60 Hz and 50 Hz | `0x3A0D`, `0x3A0E` | 4 and 3 | BANDS 4 of 4 |
/// | metering, the middle four zones | `0x568A` to `0x568D` | weight 1 | CENTER 1 of 15 |
///
/// EXPO and GAIN are the loop's while it runs, so they have no default.
pub static BOOT_DEFAULTS: &[(u16, u8)] = &[
    (0x3503, 0x00),
    (0x3a0f, 0x58),
    (0x3a1b, 0x58),
    (0x3a10, 0x50),
    (0x3a1e, 0x50),
    (0x3a18, 0x00),
    (0x3a19, 0xf8),
    (0x3a0d, 0x04),
    (0x3a0e, 0x03),
    // Every zone at weight 1: the sensor's reset value.
    (0x568a, 0x11),
    (0x568b, 0x11),
    (0x568c, 0x11),
    (0x568d, 0x11),
];
