use super::registers::GC0308_ADDR;

/// Write a single GC0308 register over SCCB.
pub fn sccb_write<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, reg: u8, value: u8) -> bool {
    i2c.write(GC0308_ADDR, &[reg, value]).is_ok()
}

/// Read a single GC0308 register over SCCB.
pub(super) fn sccb_read<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, reg: u8) -> Option<u8> {
    let mut buffer = [0u8; 1];
    if i2c.write(GC0308_ADDR, &[reg]).is_ok()
        && i2c.read(GC0308_ADDR, &mut buffer).is_ok()
    {
        Some(buffer[0])
    } else {
        None
    }
}

