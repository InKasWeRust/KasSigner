use esp_hal::delay::Delay;

/// Execute the camera PWDN/reset sequence through the AW9523B expander.
pub fn camera_power_on<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, delay: &mut Delay) {
    let mut chip_id = [0u8; 1];
    let aw_ok = i2c.write_read(0x58u8, &[0x10u8], &mut chip_id).is_ok();
    log!("   AW9523B chip_id=0x{:02x} (expect 0x23) ok={}", chip_id[0], aw_ok);

    let mut direction_p0 = [0u8; 1];
    let mut direction_p1 = [0u8; 1];
    let _ = i2c.write_read(0x58u8, &[0x04u8], &mut direction_p0);
    let _ = i2c.write_read(0x58u8, &[0x05u8], &mut direction_p1);
    log!(
        "   Direction P0=0x{:02x} P1=0x{:02x} (expect 0x00=all outputs)",
        direction_p0[0],
        direction_p1[0]
    );

    if direction_p0[0] != 0x00 {
        log!("   FIXING P0 direction → outputs");
        let _ = i2c.write(0x58u8, &[0x12u8, 0xFFu8]);
        let _ = i2c.write(0x58u8, &[0x04u8, 0x00u8]);
    }
    if direction_p1[0] != 0x00 {
        log!("   FIXING P1 direction → outputs");
        let _ = i2c.write(0x58u8, &[0x13u8, 0xFFu8]);
        let _ = i2c.write(0x58u8, &[0x05u8, 0x00u8]);
    }

    let mut p0_value = [0u8; 1];
    let mut p1_value = [0u8; 1];
    let _ = i2c.write_read(0x58u8, &[0x02u8], &mut p0_value);
    let _ = i2c.write_read(0x58u8, &[0x03u8], &mut p1_value);
    let p0 = p0_value[0];
    let p1 = p1_value[0];
    log!(
        "   Before reset: P0=0x{:02x} P1=0x{:02x} (P0.4={} P1.0={})",
        p0,
        p1,
        (p0 >> 4) & 1,
        p1 & 1
    );

    let p0_pwdn_high = p0 | 0x10;
    let _ = i2c.write(0x58u8, &[0x02u8, p0_pwdn_high]);
    delay.delay_millis(10);

    let p1_reset_low = p1 & !0x01;
    let _ = i2c.write(0x58u8, &[0x03u8, p1_reset_low]);
    delay.delay_millis(10);

    let p0_pwdn_low = p0_pwdn_high & !0x10;
    let _ = i2c.write(0x58u8, &[0x02u8, p0_pwdn_low]);
    delay.delay_millis(20);

    let p1_reset_high = p1_reset_low | 0x01;
    let _ = i2c.write(0x58u8, &[0x03u8, p1_reset_high]);
    delay.delay_millis(30);

    let _ = i2c.write_read(0x58u8, &[0x02u8], &mut p0_value);
    let _ = i2c.write_read(0x58u8, &[0x03u8], &mut p1_value);
    log!(
        "   After reset: P0=0x{:02x} P1=0x{:02x} (PWDN={} RST={})",
        p0_value[0],
        p1_value[0],
        (p0_value[0] >> 4) & 1,
        p1_value[0] & 1
    );
}
