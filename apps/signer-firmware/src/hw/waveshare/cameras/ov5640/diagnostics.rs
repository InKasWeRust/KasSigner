// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// OV5640 register diagnostics.

#[cfg(feature = "cam640")]
use esp_hal::delay::Delay;
#[cfg(feature = "cam640")]
use signer_firmware_core::camera::registers::write_pairs;

use super::bus::read_reg;
#[cfg(feature = "cam640")]
use super::bus::write_reg;
#[cfg(feature = "cam640")]
use super::initialization::init;
#[cfg(feature = "cam640")]
use super::registers::{OV5640_640_OVERRIDES, OV5640_LCD_QR_TUNING};

/// Log diagnostic register values (CHIPID, PLL, timing, orientation).
pub fn log_diagnostics<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) {
    let chipid_h = read_reg(i2c, 0x300A);
    let chipid_l = read_reg(i2c, 0x300B);
    let fmt_ctrl = read_reg(i2c, 0x4300);
    let polarity = read_reg(i2c, 0x4740);
    let dvp_ctrl = read_reg(i2c, 0x300E);
    crate::log!("   OV5640 regs: CHIPID={:?}/{:?} FMT={:?} POL={:?} DVP={:?}", chipid_h, chipid_l, fmt_ctrl, polarity, dvp_ctrl);
    let flip_reg = read_reg(i2c, 0x3820);
    let mirror_reg = read_reg(i2c, 0x3821);
    crate::log!("   OV5640 orientation: FLIP(0x3820)={:?} MIRROR(0x3821)={:?}", flip_reg, mirror_reg);
    let pll0 = read_reg(i2c, 0x3034);
    let pll1 = read_reg(i2c, 0x3035);
    let pll2 = read_reg(i2c, 0x3036);
    let pll3 = read_reg(i2c, 0x3037);
    let sclk = read_reg(i2c, 0x3108);
    let sc_ctrl = read_reg(i2c, 0x3103);
    crate::log!("   OV5640 PLL: 0x3034={:?} 0x3035={:?} 0x3036={:?} 0x3037={:?} 0x3108={:?} 0x3103={:?}", pll0, pll1, pll2, pll3, sclk, sc_ctrl);
    let hts_h = read_reg(i2c, 0x380C);
    let hts_l = read_reg(i2c, 0x380D);
    let vts_h = read_reg(i2c, 0x380E);
    let vts_l = read_reg(i2c, 0x380F);
    let dvpho_h = read_reg(i2c, 0x3808);
    let dvpho_l = read_reg(i2c, 0x3809);
    let dvpvo_h = read_reg(i2c, 0x380A);
    let dvpvo_l = read_reg(i2c, 0x380B);
    crate::log!("   OV5640 timing: HTS={:?}/{:?} VTS={:?}/{:?} DVPHO={:?}/{:?} DVPVO={:?}/{:?}", hts_h, hts_l, vts_h, vts_l, dvpho_h, dvpho_l, dvpvo_h, dvpvo_l);
}

/// Initialize the developer-only 640×640 OV5640 diagnostic path.
#[cfg(feature = "cam640")]
pub fn init_hires<I2C: embedded_hal::i2c::I2c>(
    i2c: &mut I2C,
    delay: &mut Delay,
) -> Result<(), &'static str> {
    init(i2c, delay)?;
    crate::log!("   OV5640: diagnostic 640x640 mode");
    write_pairs(
        OV5640_640_OVERRIDES,
        "OV5640: 640x640 override SCCB write failed",
        |register, value| write_reg(i2c, register, value),
    )?;
    delay.delay_millis(100);
    #[cfg(feature = "ov5640-af")]
    {
        let _ = write_reg(i2c, 0x3820, 0x47);
        let _ = write_reg(i2c, 0x3821, 0x06);
    }
    write_pairs(
        OV5640_LCD_QR_TUNING,
        "OV5640: 640x640 LCD tuning write failed",
        |register, value| write_reg(i2c, register, value),
    )?;
    delay.delay_millis(50);
    Ok(())
}
