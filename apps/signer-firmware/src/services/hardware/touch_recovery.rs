//! Board-specific post-SD touch recovery effect.

#[cfg(feature = "waveshare")]
pub(crate) fn after_sd_scan(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
    let _ = i2c.write(0x15u8, &[0x05, 0x60]);
    let _ = i2c.write(0x15u8, &[0x06, 0x30]);
    let _ = i2c.write(0x15u8, &[0xFE, 0x01]);
}

#[cfg(feature = "m5stack")]
pub(crate) fn after_sd_scan() {}
