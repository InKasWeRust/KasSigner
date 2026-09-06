//! CoreS3 camera sensor and DVP completion phases.

use esp_hal::{Blocking, delay::Delay, i2c::master::I2c, lcd_cam::cam::Camera as DvpCamera};

pub(crate) fn begin_phase() {
    crate::log!("   BOOT PHASE camera BEGIN");
}

pub(crate) fn initialize_sensor(
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
) -> crate::hw::camera::CameraStatus {
    crate::log!("   GC0308 Camera init with HAL LCD_CAM master clock...");
    match crate::hw::camera::init_gc0308(i2c, delay) {
        Ok(()) => {
            crate::log!("   GC0308 OK — HAL owns XCLK/DVP routing");
            crate::hw::camera::CameraStatus::SensorReady
        }
        Err(error) => {
            crate::log!("   GC0308 FAILED: {}", error);
            crate::hw::camera::CameraStatus::Error
        }
    }
}

pub(crate) fn finish_dvp<'a>(camera: DvpCamera<'a>) -> DvpCamera<'a> {
    crate::log!("   LCD_CAM DVP ready — no raw GPIO/IO_MUX override");
    camera
}

pub(crate) fn finish_sensor_status(status: crate::hw::camera::CameraStatus) {
    crate::log!("   Camera status: {:?}", status);
    crate::log!("   BOOT PHASE camera DONE");
}
