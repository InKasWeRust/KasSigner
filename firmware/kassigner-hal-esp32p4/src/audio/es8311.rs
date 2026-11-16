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

//! ES8311 mono audio codec, I2C 0x18.
//!
//! Ported from Espressif's `esp-bsp/components/es8311/es8311.c` (deprecated
//! for `esp_codec_dev`, same sequence), whose register names carry the
//! address (`ES8311_SYSTEM_REG0D` is 0x0D). Wiring, with an NS4150B as the
//! power amplifier:
//!
//! ```text
//!   GPIO13 MCLK    GPIO12 BCLK    GPIO10 LRCK
//!   GPIO9  DOUT (to codec)        GPIO11 DIN (from codec)
//!   GPIO53 amp enable -> NS4150B CTRL
//!   I2C 0x18 (CE pin low) for control
//! ```
//!
//! The codec is clocked from the MCLK pin, not SCK: MCLK from SCK forces
//! input and output resolution to match and restricts the rates.

use crate::board::i2c::{self, Bus};

/// CE pin low. CE high would be 0x19.
pub const ADDR: u8 = 0x18;

/// Register addresses.
#[allow(missing_docs)] // register table
pub mod reg {
    pub const RESET: u8 = 0x00;
    pub const CLK_MANAGER_01: u8 = 0x01;
    pub const CLK_MANAGER_02: u8 = 0x02;
    pub const CLK_MANAGER_03: u8 = 0x03;
    pub const CLK_MANAGER_04: u8 = 0x04;
    pub const CLK_MANAGER_05: u8 = 0x05;
    pub const CLK_MANAGER_06: u8 = 0x06;
    pub const CLK_MANAGER_07: u8 = 0x07;
    pub const CLK_MANAGER_08: u8 = 0x08;
    pub const SDPIN: u8 = 0x09;
    pub const SDPOUT: u8 = 0x0A;
    pub const SYSTEM_0D: u8 = 0x0D;
    pub const SYSTEM_0E: u8 = 0x0E;
    pub const SYSTEM_12: u8 = 0x12;
    pub const SYSTEM_13: u8 = 0x13;
    pub const SYSTEM_14: u8 = 0x14;
    pub const ADC_15: u8 = 0x15;
    pub const ADC_16: u8 = 0x16;
    pub const ADC_17: u8 = 0x17;
    pub const ADC_1C: u8 = 0x1C;
    pub const DAC_31: u8 = 0x31;
    pub const DAC_32: u8 = 0x32;
    pub const DAC_37: u8 = 0x37;
    pub const GPIO_44: u8 = 0x44;
    pub const GP_45: u8 = 0x45;
    /// Chip ID registers, read-only. Expect 0x83 / 0x11.
    pub const CHIP_ID1: u8 = 0xFD;
    pub const CHIP_ID2: u8 = 0xFE;
}

/// Sample resolution. The value is the register field, already shifted.
#[derive(Copy, Clone, PartialEq)]
pub enum Resolution {
    /// 16-bit samples.
    Bits16 = 3,
    /// 18-bit samples.
    Bits18 = 2,
    /// 20-bit samples.
    Bits20 = 1,
    /// 24-bit samples.
    Bits24 = 0,
    /// 32-bit samples.
    Bits32 = 4,
}

/// One row of Espressif's `coeff_div[]`.
struct Coeff {
    mclk: u32,
    rate: u32,
    pre_div: u8,
    pre_multi: u8,
    adc_div: u8,
    dac_div: u8,
    fs_mode: u8,
    lrck_h: u8,
    lrck_l: u8,
    bclk_div: u8,
    adc_osr: u8,
    dac_osr: u8,
}

/// Rows of esp-bsp's `coeff_div[]` used on this board, verbatim (the full
/// table has about 100).
static COEFFS: &[Coeff] = &[
    // mclk      rate   pre_div multi adc dac fs lrck_h lrck_l bclk adc_osr dac_osr
    Coeff {
        mclk: 12288000,
        rate: 48000,
        pre_div: 0x01,
        pre_multi: 0x00,
        adc_div: 0x01,
        dac_div: 0x01,
        fs_mode: 0x00,
        lrck_h: 0x00,
        lrck_l: 0xff,
        bclk_div: 0x04,
        adc_osr: 0x10,
        dac_osr: 0x10,
    },
    Coeff {
        mclk: 12288000,
        rate: 32000,
        pre_div: 0x03,
        pre_multi: 0x01,
        adc_div: 0x01,
        dac_div: 0x01,
        fs_mode: 0x00,
        lrck_h: 0x00,
        lrck_l: 0xff,
        bclk_div: 0x04,
        adc_osr: 0x10,
        dac_osr: 0x10,
    },
    Coeff {
        mclk: 12288000,
        rate: 24000,
        pre_div: 0x02,
        pre_multi: 0x00,
        adc_div: 0x01,
        dac_div: 0x01,
        fs_mode: 0x00,
        lrck_h: 0x00,
        lrck_l: 0xff,
        bclk_div: 0x04,
        adc_osr: 0x10,
        dac_osr: 0x10,
    },
    Coeff {
        mclk: 12288000,
        rate: 16000,
        pre_div: 0x03,
        pre_multi: 0x00,
        adc_div: 0x01,
        dac_div: 0x01,
        fs_mode: 0x00,
        lrck_h: 0x00,
        lrck_l: 0xff,
        bclk_div: 0x04,
        adc_osr: 0x10,
        dac_osr: 0x10,
    },
    Coeff {
        mclk: 12288000,
        rate: 8000,
        pre_div: 0x06,
        pre_multi: 0x00,
        adc_div: 0x01,
        dac_div: 0x01,
        fs_mode: 0x00,
        lrck_h: 0x00,
        lrck_l: 0xff,
        bclk_div: 0x04,
        adc_osr: 0x10,
        dac_osr: 0x10,
    },
    // MCLK derived from SCK at 16-bit: mclk = rate * 16 * 2
    Coeff {
        mclk: 1536000,
        rate: 48000,
        pre_div: 0x01,
        pre_multi: 0x03,
        adc_div: 0x01,
        dac_div: 0x01,
        fs_mode: 0x00,
        lrck_h: 0x00,
        lrck_l: 0xff,
        bclk_div: 0x04,
        adc_osr: 0x10,
        dac_osr: 0x10,
    },
];

/// ES8311 codec driver. Stateless: every call takes the bus.
pub struct Es8311;

impl Es8311 {
    fn write(bus: &mut Bus<'_>, r: u8, v: u8) -> bool {
        i2c::write8(bus, ADDR, r, v)
    }

    fn coeff(mclk: u32, rate: u32) -> Option<&'static Coeff> {
        COEFFS.iter().find(|c| c.mclk == mclk && c.rate == rate)
    }

    /// Program the clock dividers for a given MCLK and sample rate.
    fn sample_frequency_config(bus: &mut Bus<'_>, mclk: u32, rate: u32) -> bool {
        let c = match Self::coeff(mclk, rate) {
            Some(c) => c,
            None => return false,
        };

        // reg 0x02: pre_div in [7:5], pre_multi in [4:3], low 3 bits kept.
        let cur = match i2c::read8(bus, ADDR, reg::CLK_MANAGER_02) {
            Some(v) => v,
            None => return false,
        };
        let r02 = (cur & 0x07) | ((c.pre_div - 1) << 5) | (c.pre_multi << 3);
        if !Self::write(bus, reg::CLK_MANAGER_02, r02) {
            return false;
        }

        Self::write(bus, reg::CLK_MANAGER_03, (c.fs_mode << 6) | c.adc_osr)
            && Self::write(bus, reg::CLK_MANAGER_04, c.dac_osr)
            && Self::write(
                bus,
                reg::CLK_MANAGER_05,
                ((c.adc_div - 1) << 4) | (c.dac_div - 1),
            )
            && {
                // reg 0x06: bclk_div in [4:0], top 3 bits kept.
                // Espressif's off-by-one: values under 19 are stored as n-1.
                let cur6 = i2c::read8(bus, ADDR, reg::CLK_MANAGER_06).unwrap_or(0);
                let bd = if c.bclk_div < 19 {
                    c.bclk_div - 1
                } else {
                    c.bclk_div
                };
                Self::write(bus, reg::CLK_MANAGER_06, (cur6 & 0xE0) | bd)
            }
            && {
                let cur7 = i2c::read8(bus, ADDR, reg::CLK_MANAGER_07).unwrap_or(0);
                Self::write(bus, reg::CLK_MANAGER_07, (cur7 & 0xC0) | c.lrck_h)
            }
            && Self::write(bus, reg::CLK_MANAGER_08, c.lrck_l)
    }

    /// Initialise for playback. `mclk` (Hz, on GPIO13) and `rate` must be a
    /// row of `COEFFS`. Sequence from `es8311_init()`: reset, power on,
    /// clocks, format, then the four power-up writes marked "NOT default".
    pub fn init(
        bus: &mut Bus<'_>,
        mclk: u32,
        rate: u32,
        res: Resolution,
        delay: &esp_hal::delay::Delay,
    ) -> Result<(), Error> {
        if !(8000..=96000).contains(&rate) {
            return Err(Error::UnsupportedRate);
        }
        if Self::coeff(mclk, rate).is_none() {
            return Err(Error::UnsupportedRate);
        }

        // Reset to defaults, then power on.
        if !Self::write(bus, reg::RESET, 0x1F) {
            return Err(Error::NotResponding);
        }
        delay.delay_millis(20);
        Self::write(bus, reg::RESET, 0x00);
        Self::write(bus, reg::RESET, 0x80); // power-on

        // reg01 = 0x3F enables all clocks; bit 7 would make SCK the MCLK
        // source.
        if !Self::write(bus, reg::CLK_MANAGER_01, 0x3F) {
            return Err(Error::NotResponding);
        }
        if !Self::sample_frequency_config(bus, mclk, rate) {
            return Err(Error::UnsupportedRate);
        }

        // Format: slave mode (clear bit 6 of reg00), I2S, resolution.
        let r00 = i2c::read8(bus, ADDR, reg::RESET).unwrap_or(0x80);
        Self::write(bus, reg::RESET, r00 & 0xBF);
        let rbits = (res as u8) << 2;
        Self::write(bus, reg::SDPIN, rbits);
        Self::write(bus, reg::SDPOUT, rbits);

        // The four writes Espressif marks "NOT default": without them the
        // codec is configured but silent.
        Self::write(bus, reg::SYSTEM_0D, 0x01); // power up analog
        Self::write(bus, reg::SYSTEM_0E, 0x02); // analog PGA + ADC modulator
        Self::write(bus, reg::SYSTEM_12, 0x00); // power up DAC
        Self::write(bus, reg::SYSTEM_13, 0x10); // enable output to HP drive

        Self::write(bus, reg::ADC_1C, 0x6A); // ADC EQ bypass, DC offset cancel
        Self::write(bus, reg::DAC_37, 0x08); // bypass DAC equaliser

        Ok(())
    }

    /// Set playback volume, 0-100. Register value is `vol * 256 / 100 - 1`.
    pub fn set_volume(bus: &mut Bus<'_>, volume: u8) -> bool {
        let v = volume.min(100);
        let reg32 = if v == 0 {
            0
        } else {
            (((v as u32) * 256 / 100) - 1) as u8
        };
        Self::write(bus, reg::DAC_32, reg32)
    }

    /// Mute or unmute the DAC. Bits 5 and 6 of reg 0x31.
    pub fn set_mute(bus: &mut Bus<'_>, mute: bool) -> bool {
        let cur = match i2c::read8(bus, ADDR, reg::DAC_31) {
            Some(v) => v,
            None => return false,
        };
        let v = if mute { cur | 0x60 } else { cur & !0x60 };
        Self::write(bus, reg::DAC_31, v)
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
/// What went wrong during codec bring-up.
pub enum Error {
    /// No ACK on the I2C bus.
    NotResponding,
    /// The MCLK/rate pair is not in the coefficient table.
    UnsupportedRate,
}
