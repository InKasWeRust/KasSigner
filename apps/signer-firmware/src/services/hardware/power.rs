//! Controller-facing power service. Board-specific PMU/PWM details stay under `hw`.

pub(crate) fn set_brightness(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    value: u8,
) {
    let _ = &mut *i2c;
    crate::hw::pmu::set_brightness!(i2c, value);
}
