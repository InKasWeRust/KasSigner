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

// OV5640 baseline and 480x480 initialization workflows.


use esp_hal::delay::Delay;
#[cfg(not(feature = "cam640"))]
use signer_firmware_core::camera::registers::write_pairs;

#[cfg(feature = "af")]
use super::autofocus::load_af_firmware;
use super::bus::{detect, write_reg};
use super::registers::OV5640_INIT_REGS;
#[cfg(not(feature = "cam640"))]
use super::registers::{OV5640_480_OVERRIDES, OV5640_LCD_QR_TUNING};

/// Initialize OV5640 baseline registers (320×240 YUV422 DVP).
/// The 480×480 mode is layered on top via init_480().
pub fn init<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, delay: &mut Delay) -> Result<(), &'static str> {
    if !detect(i2c) {
        return Err("OV5640 not detected at 0x3C");
    }
    for &(reg, val) in OV5640_INIT_REGS {
        if !write_reg(i2c, reg, val) {
            return Err("OV5640: SCCB write failed");
        }
    }
    delay.delay_millis(300);
    crate::log!("   OV5640 configured: baseline registers loaded");

    #[cfg(feature = "af")]
    {
        crate::log!("   OV5640: loading AF firmware (af feature enabled)...");
        load_af_firmware(i2c, delay);
    }
    #[cfg(not(feature = "af"))]
    crate::log!("   OV5640 OK (fixed-focus, no AF)");

    Ok(())
}

/// Initialize OV5640 for 480x480 YUV422 output (for PSRAM DMA pipeline).
///
/// Uses 960x960 center crop from the 2592x1944 sensor array (~2x zoom),
/// then DCW 2x downscale -> 480x480 DVP output. Same PLL and ISP settings
/// as the 320x240 mode.
///
/// 960x960 center crop geometry:
///   X start = (2592-960)/2 = 816 = 0x0330
///   X end   = 816+960-1     = 1775 = 0x06EF
///   Y start = (1944-960)/2 = 492 = 0x01EC
///   Y end   = 492+960-1     = 1451 = 0x05AB
///   Sub-sampling: 0x11 (none - required for clean image)
///   DCW: 2x (960->480)
#[cfg(not(feature = "cam640"))]
pub fn init_480<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, delay: &mut Delay) -> Result<(), &'static str> {
    // First do normal init (sets PLL, analog, ISP, AF firmware)
    init(i2c, delay)?;

    crate::log!("   OV5640: upgrading to 480x480 YUV422...");

    write_pairs(
        OV5640_480_OVERRIDES,
        "OV5640: 480x480 override SCCB write failed",
        |register, value| write_reg(i2c, register, value),
    )?;
    delay.delay_millis(100);

    // OV5640-AF module: flip both axes to compensate for 180-degree
    // physical rotation of the AF module vs the fixed-focus module.
    #[cfg(feature = "ov5640-af")]
    {
        write_reg(i2c, 0x3820, 0x47); // vertical flip ON (bit6 + bit2:1)
        write_reg(i2c, 0x3821, 0x06); // horizontal mirror ON (bit2:1)
        crate::log!("   OV5640-AF: orientation flipped (H+V) for AF module");
    }

    write_pairs(
        OV5640_LCD_QR_TUNING,
        "OV5640: LCD QR tuning SCCB write failed",
        |register, value| write_reg(i2c, register, value),
    )?;
    delay.delay_millis(50);

    crate::log!("   OV5640: 480x480 YUV422 configured (960x960 crop, DCW 2x, LCD QR tuned)");
    Ok(())
}
