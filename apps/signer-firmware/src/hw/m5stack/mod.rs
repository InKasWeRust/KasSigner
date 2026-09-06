//! M5Stack CoreS3 / CoreS3 Lite hardware implementation.

pub(crate) mod cameras;
pub(crate) mod display;
pub(crate) mod imu;
pub(crate) mod power;
pub(crate) mod sound;
pub(crate) mod rtc;
pub(crate) mod spi_bus;
pub(crate) mod storage;
pub(crate) mod touch;

pub(crate) use cameras::gc0308 as camera;
pub(crate) use power::{battery, pmu};
pub(crate) use imu as entropy_imu;
pub(crate) use storage as sdcard;

pub(crate) const BOARD_NAME: &str = "M5Stack CoreS3";
