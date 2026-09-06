//! CoreS3 IMU/entropy-source initialization phase.

use esp_hal::{Blocking, delay::Delay, i2c::master::I2c};

pub(crate) fn initialize(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) {
    crate::log!("   BOOT PHASE entropy BEGIN");
    crate::log!("   BMI270 IMU init...");
    if crate::services::entropy::initialize_imu(i2c, delay) {
        crate::log!("   BMI270 OK — entropy health ready");
    } else {
        crate::log!("   BMI270 unavailable — new seed creation will fail closed");
    }
    crate::log!("   BOOT PHASE entropy DONE");
}
