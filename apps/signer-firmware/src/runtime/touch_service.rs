//! Sole production transport boundary for touchscreen reads.
//!
//! Workflow/controller code may request a sample from this service, but it may
//! not talk to the board touch driver directly. This keeps contact-gate/wake
//! policy centralized and makes direct transport bypasses mechanically auditable.

use esp_hal::i2c::master::I2c;

#[cfg(feature = "m5stack")]
pub(crate) fn read_checked(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
) -> Result<crate::hw::touch::TouchState, ()> {
    crate::hw::touch::read_touch_checked(i2c)
}

#[cfg(feature = "waveshare")]
pub(crate) fn read_full(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    configured: &mut bool,
) -> (crate::hw::touch::TouchState, crate::hw::touch::HwGesture) {
    crate::hw::touch::read_touch_full(i2c, configured)
}

#[cfg(feature = "waveshare")]
pub(crate) fn read_with_gesture(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
) -> (crate::hw::touch::TouchState, crate::hw::touch::HwGesture) {
    crate::hw::touch::read_touch_with_gesture(i2c)
}
