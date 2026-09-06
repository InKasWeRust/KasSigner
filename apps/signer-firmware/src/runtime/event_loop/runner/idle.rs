//! Idle-time hardware servicing owned by the event-loop runner.

#[cfg(all(feature = "waveshare", not(feature = "workflow-test-auto")))]
pub(crate) fn restage_imu(
    action: crate::hw::touch::TouchAction,
    ad: &crate::runtime::data::AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) {
    if action == crate::hw::touch::TouchAction::None
        && ad.runtime.idle_ticks > 0
        && ad.runtime.idle_ticks % crate::runtime::event_loop::IMU_RESTAGE_TICKS == 0
    {
        let _ = crate::services::entropy::stage_idle_imu(i2c, delay);
    }
}
