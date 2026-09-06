//! Waveshare camera PWDN control.
//!
//! GPIO17 is active-high power-down. Keep the raw ESP32-S3 GPIO register
//! knowledge in this board-specific hardware module so runtime/services never
//! duplicate MMIO addresses or polarity assumptions.

const GPIO_OUT_W1TS: *mut u32 = 0x6000_4008usize as *mut u32;
const GPIO_OUT_W1TC: *mut u32 = 0x6000_400Cusize as *mut u32;
const CAMERA_PWDN_MASK: u32 = 1u32 << 17;

/// Deassert PWDN (GPIO17 LOW) so the camera is powered and responsive.
#[inline]
pub(crate) fn wake() {
    // SAFETY: board-specific GPIO write-one-to-clear register; this module owns
    // the Waveshare camera PWDN bit after boot configures GPIO17 as an output.
    unsafe { core::ptr::write_volatile(GPIO_OUT_W1TC, CAMERA_PWDN_MASK) };
}

/// Assert PWDN (GPIO17 HIGH) when the camera is idle.
#[inline]
pub(crate) fn sleep() {
    // SAFETY: board-specific GPIO write-one-to-set register; see `wake`.
    unsafe { core::ptr::write_volatile(GPIO_OUT_W1TS, CAMERA_PWDN_MASK) };
}

/// Power-cycle PWDN while XCLK is already running.
pub(crate) fn pulse_reset(delay: &mut esp_hal::delay::Delay) {
    sleep();
    delay.delay_millis(20);
    wake();
    delay.delay_millis(30);
}
