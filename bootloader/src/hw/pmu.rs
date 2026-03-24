// hw/pmu.rs — Backlight PWM control for Waveshare ESP32-S3-Touch-LCD-2
//
// LEDC Timer1/Channel1 on GPIO1, configured by esp-hal in main.rs.
// set_brightness() updates duty via direct register writes.

use esp_hal::i2c::master::I2c;

const LEDC_BASE: u32 = 0x6001_9000;
const LEDC_LSCH1_CONF0: u32 = LEDC_BASE + 0x14;
const LEDC_LSCH1_DUTY: u32 = LEDC_BASE + 0x1C;
const LEDC_LSCH1_CONF1: u32 = LEDC_BASE + 0x20;

/// Set backlight brightness 0-255 via LEDC PWM duty on Channel1/GPIO1.
pub fn set_brightness(_i2c: &mut I2c<'_, esp_hal::Blocking>, brightness: u8) {
    unsafe {
        core::ptr::write_volatile(LEDC_LSCH1_DUTY as *mut u32, (brightness as u32) << 4);
        core::ptr::write_volatile(LEDC_LSCH1_CONF1 as *mut u32, 1u32 << 31);
        let conf0 = core::ptr::read_volatile(LEDC_LSCH1_CONF0 as *const u32);
        core::ptr::write_volatile(LEDC_LSCH1_CONF0 as *mut u32, conf0 | (1 << 4));
    }
}
