//! Waveshare ESP32-S3-Touch-LCD-2 hardware implementation.

pub(crate) mod cameras;
pub(crate) mod display;
pub(crate) mod imu;
pub(crate) mod power;
pub(crate) mod sound;
pub(crate) mod storage;
pub(crate) mod touch;

pub(crate) use cameras::{
    decode_core, dma as cam_dma, ov2640 as camera_ov2640, ov5640 as camera,
    power as camera_power,
};
#[cfg(feature = "af")]
pub(crate) use cameras::af_firmware as ov5640_af_fw;
pub(crate) use power::{battery, pmu};
pub(crate) use imu as entropy_imu;
pub(crate) use storage as sdcard;

pub(crate) const BOARD_NAME: &str = "Waveshare ESP32-S3 Touch LCD 2";
