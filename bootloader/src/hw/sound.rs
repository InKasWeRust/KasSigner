// hw/sound.rs — Audio stubs for Waveshare ESP32-S3-Touch-LCD-2
//
// No speaker hardware on this board. All functions are no-ops
// to maintain API compatibility with handlers and UI code.

use esp_hal::delay::Delay;

pub fn set_volume(_vol: u8) {}
pub fn click(_delay: &mut Delay) {}
pub fn beep_error(_delay: &mut Delay) {}
pub fn success(_delay: &mut Delay) {}
pub fn warning(_delay: &mut Delay) {}
pub fn task_done(_delay: &mut Delay) {}
pub fn start_ticking() {}
pub fn stop_ticking() {}
