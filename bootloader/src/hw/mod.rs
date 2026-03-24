// hw/ — Hardware drivers for Waveshare ESP32-S3-Touch-LCD-2

pub mod board;
pub mod pmu;
pub mod display;
pub mod icon_data;
pub mod camera;
pub mod touch;
pub mod sound;
pub mod battery;
pub mod sdcard;
pub mod sd_backup;
pub mod lockdown;
#[cfg(feature = "screenshot")]
pub mod screenshot;
