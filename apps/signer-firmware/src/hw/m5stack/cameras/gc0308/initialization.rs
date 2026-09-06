use esp_hal::delay::Delay;
use signer_firmware_core::camera::registers::{
    write_pairs, write_pairs_with_hook,
};

use super::{
    bus::{sccb_read, sccb_write},
    power::camera_power_on,
    registers::{
        GC0308_CHIP_ID, GC0308_DEFAULTS, GC0308_SUBSAMPLE_QVGA, REG_CHIP_ID,
        REG_OUTPUT_EN, REG_OUTPUT_FORMAT, REG_PAGE_SELECT,
    },
};

const REG_BLOCK_ENABLE_1: u8 = 0x20;
const NOISE_REMOVAL_ENABLE: u8 = 1 << 2;

/// Temporarily expose GC0308 temporal sensor variation for the seed-health capture.
/// The normal QR/viewfinder pipeline keeps ISP denoise enabled; entropy capture
/// disables only the documented noise-removal block and restores the exact prior
/// register value after the eight checked frames.
pub fn begin_entropy_capture<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) -> Option<u8> {
    if !sccb_write(i2c, REG_PAGE_SELECT, 0x00) { return None; }
    let prior = sccb_read(i2c, REG_BLOCK_ENABLE_1)?;
    if !sccb_write(i2c, REG_BLOCK_ENABLE_1, prior & !NOISE_REMOVAL_ENABLE) { return None; }
    Some(prior)
}

pub fn end_entropy_capture<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, prior: u8) -> bool {
    sccb_write(i2c, REG_PAGE_SELECT, 0x00)
        && sccb_write(i2c, REG_BLOCK_ENABLE_1, prior)
}

/// Detect the GC0308 camera on I2C bus.
pub fn detect_gc0308<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) -> bool {
    sccb_write(i2c, REG_PAGE_SELECT, 0x00);
    sccb_read(i2c, REG_CHIP_ID) == Some(GC0308_CHIP_ID)
}

/// Initialize the GC0308 camera for QVGA grayscale output.
pub fn init_gc0308<I2C: embedded_hal::i2c::I2c>(
    i2c: &mut I2C,
    delay: &mut Delay,
) -> Result<(), &'static str> {
    power_camera_after_hal_clock(i2c, delay);
    ensure_detected(i2c, "GC0308 not detected (chip ID != 0x9B)")?;
    write_defaults(i2c, delay, "SCCB write failed during defaults")?;
    configure_initial_qvga(i2c, delay)?;
    log_initial_status(i2c);
    Ok(())
}

fn power_camera_after_hal_clock<I2C: embedded_hal::i2c::I2c>(
    i2c: &mut I2C,
    delay: &mut Delay,
) {
    camera_power_on(i2c, delay);
    // XCLK is already supplied by LCD_CAM::Camera::with_master_clock(GPIO2).
    // Keep only the sensor power/reset settling delay here.
    delay.delay_millis(30);
}

fn ensure_detected<I2C: embedded_hal::i2c::I2c>(
    i2c: &mut I2C,
    error: &'static str,
) -> Result<(), &'static str> {
    detect_gc0308(i2c).then_some(()).ok_or(error)
}

fn write_defaults<I2C: embedded_hal::i2c::I2c>(
    i2c: &mut I2C,
    delay: &mut Delay,
    error: &'static str,
) -> Result<(), &'static str> {
    write_pairs_with_hook(
        GC0308_DEFAULTS,
        error,
        |register, value| sccb_write(i2c, register, value),
        |register, value| {
            if register == 0xfe && value == 0x80 {
                delay.delay_millis(20);
            }
        },
    )?;
    delay.delay_millis(80);
    Ok(())
}

fn configure_initial_qvga<I2C: embedded_hal::i2c::I2c>(
    i2c: &mut I2C,
    delay: &mut Delay,
) -> Result<(), &'static str> {
    configure_qvga_common(i2c)?;
    delay.delay_millis(100);
    Ok(())
}

fn configure_qvga_common<I2C: embedded_hal::i2c::I2c>(
    i2c: &mut I2C,
) -> Result<(), &'static str> {
    sccb_write(i2c, 0xfe, 0x01);
    let subsample = sccb_read(i2c, 0x53).unwrap_or(0x00) | 0x80;
    let subsample_two = sccb_read(i2c, 0x55).unwrap_or(0x00) | 0x01;
    sccb_write(i2c, 0x53, subsample);
    sccb_write(i2c, 0x55, subsample_two);
    sccb_write(i2c, 0xfe, 0x00);
    write_pairs(
        GC0308_SUBSAMPLE_QVGA,
        "SCCB write failed during subsample config",
        |register, value| sccb_write(i2c, register, value),
    )?;
    sccb_write(i2c, 0x46, 0x00);
    Ok(())
}

fn log_initial_status<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) {
    let out_en = sccb_read(i2c, REG_OUTPUT_EN).unwrap_or(0xEE);
    let debug = sccb_read(i2c, 0x2e).unwrap_or(0xEE);
    let format = sccb_read(i2c, REG_OUTPUT_FORMAT).unwrap_or(0xEE);
    let sync = sccb_read(i2c, 0x26).unwrap_or(0xEE);
    let drive = sccb_read(i2c, 0x1f).unwrap_or(0xEE);
    let mode = sccb_read(i2c, 0x15).unwrap_or(0xEE);
    let aec = sccb_read(i2c, 0xd0).unwrap_or(0xEE);
    log!(
        "   GC0308 verify: out_en=0x{:02x} debug=0x{:02x} fmt=0x{:02x} sync=0x{:02x} drv=0x{:02x} mode2=0x{:02x} aec=0x{:02x}",
        out_en, debug, format, sync, drive, mode, aec
    );
    log_subsample_status(i2c, format);
}

fn log_subsample_status<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, format: u8) {
    sccb_write(i2c, 0xfe, 0x01);
    let enabled = sccb_read(i2c, 0x53).unwrap_or(0xff);
    let enabled_two = sccb_read(i2c, 0x55).unwrap_or(0xff);
    let mode = sccb_read(i2c, 0x54).unwrap_or(0xff);
    sccb_write(i2c, 0xfe, 0x00);
    log!(
        "   Subsample: en=0x{:02x}(bit7={}) en2=0x{:02x}(bit0={}) mode=0x{:02x} fmt=0x{:02x}",
        enabled,
        (enabled >> 7) & 1,
        enabled_two,
        enabled_two & 1,
        mode,
        format
    );
}
