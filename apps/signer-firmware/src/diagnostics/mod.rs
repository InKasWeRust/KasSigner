//! Developer-only diagnostic capabilities. Never part of production firmware routing.

#![cfg_attr(feature = "hardware-tests", allow(dead_code))]
#![cfg_attr(feature = "workflow-test-auto", allow(dead_code))]
#[cfg(feature = "e12-capture")]
pub(crate) mod e12_capture;
#[cfg(feature = "sentinel-scan")]
pub(crate) mod sentinel_scan;
#[cfg(feature = "wdev-capture")]
pub(crate) mod wdev_capture;
#[cfg(feature = "sha-bench")]
pub(crate) mod sha_bench;
#[cfg(feature = "argon2-bench")]
pub(crate) mod argon2_bench;
#[cfg(all(feature = "imu-dump", feature = "waveshare"))]
pub(crate) mod imu_dump;
#[cfg(feature = "icon-browser")]
pub(crate) mod icon_browser;



pub(crate) fn log_build_profile() {
    log!("KasSigner package {}", env!("CARGO_PKG_VERSION"));
    #[cfg(feature = "workflow-test-auto")]
    log!("   Firmware profile: workflow-e2e auto-run test image");
    #[cfg(all(feature = "workflow-tests", not(feature = "workflow-test-auto")))]
    log!("   Firmware profile: development + on-device E2E menu");
    #[cfg(feature = "hardware-tests")]
    log!("   Firmware profile: hardware-tests HIL image");
    #[cfg(feature = "production")]
    log!("   Firmware profile: production");
    #[cfg(not(any(feature = "workflow-tests", feature = "workflow-test-auto", feature = "hardware-tests", feature = "production")))]
    log!("   Firmware profile: development");
}

// Keep terminal diagnostic divergence behind ordinary `()` call boundaries so
// `-D warnings` does not mark the normal boot path unreachable in diagnostic builds.
#[cfg(feature = "sha-bench")]
pub(crate) fn maybe_run_sha_bench(delay: &mut esp_hal::delay::Delay) {
    sha_bench::run_and_halt(delay);
}
#[cfg(not(feature = "sha-bench"))]
pub(crate) fn maybe_run_sha_bench(_: &mut esp_hal::delay::Delay) {}

#[cfg(feature = "rng-probe")]
pub(crate) fn maybe_finish_rng_probe(delay: &mut esp_hal::delay::Delay) {
    crate::services::entropy::finish_rng_probe(delay);
}
#[cfg(not(feature = "rng-probe"))]
pub(crate) fn maybe_finish_rng_probe(_: &mut esp_hal::delay::Delay) {}

#[cfg(feature = "wdev-capture")]
pub(crate) fn maybe_run_wdev_capture(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) { wdev_capture::run_and_halt(i2c, delay); }
#[cfg(feature = "sentinel-scan")]
pub(crate) fn maybe_run_sentinel_scan(
    ad: &mut crate::runtime::data::AppData,
    delay: &mut esp_hal::delay::Delay,
) {
    sentinel_scan::run_and_halt(ad, delay);
}
#[cfg(not(feature = "sentinel-scan"))]
pub(crate) fn maybe_run_sentinel_scan(
    _: &mut crate::runtime::data::AppData,
    _: &mut esp_hal::delay::Delay,
) {}

#[cfg(feature = "waveshare")]
#[cfg(feature = "imu-dump")]
pub(crate) fn maybe_run_imu_dump(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) {
    imu_dump::run_and_halt(i2c, delay);
}
#[cfg(feature = "waveshare")]
#[cfg(not(feature = "imu-dump"))]
pub(crate) fn maybe_run_imu_dump(
    _: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    _: &mut esp_hal::delay::Delay,
) {}

#[cfg(feature = "icon-browser")]
pub(crate) fn maybe_run_icon_browser<D>(display: &mut D, delay: &mut esp_hal::delay::Delay)
where
    D: embedded_graphics::draw_target::DrawTarget<
        Color = embedded_graphics::pixelcolor::Rgb565,
    >,
{
    icon_browser::draw_and_halt(display, delay);
}
#[cfg(not(feature = "icon-browser"))]
pub(crate) fn maybe_run_icon_browser<D>(_: &mut D, _: &mut esp_hal::delay::Delay)
where
    D: embedded_graphics::draw_target::DrawTarget<
        Color = embedded_graphics::pixelcolor::Rgb565,
    >,
{}
