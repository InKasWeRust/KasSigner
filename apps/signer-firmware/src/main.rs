// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
#![no_std]
#![no_main]
// Firmware lint policy: production code must not hide dead code or unused imports.
// Clippy complexity exceptions are allowed only on the exact item and must carry
// a `LINT-JUSTIFICATION:` comment enforced by check_architecture.py.
#![deny(unused_imports)]
#![warn(dead_code)]
#![warn(unused_variables, unused_assignments, unused_mut)]
#![warn(static_mut_refs)]
// hardware-tests intentionally omits the production event loop. Its root subsystems use
// module-scoped dead-code allowances below; crate-wide diagnostics remain enabled.
// Hardware entry point; platform exclusivity lives in feature_policy.rs.
// ─── Logging macro ────────────────────────────────────────────
// Define before the module tree; silent builds still type-check log arguments.
#[cfg(not(feature = "silent"))]
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{ esp_println::println!($($arg)*) }};
}
#[cfg(feature = "silent")]
#[macro_export]
macro_rules! log {
    () => { () };
    ($($arg:tt)+) => {{
        if false {
            let _ = core::format_args!($($arg)+);
        }
    }};
}
mod feature_policy;
#[cfg(not(feature = "qemu"))]
mod diagnostics;
#[cfg(any(not(feature = "qemu"), feature = "qemu-tests"))]
mod self_test;
#[cfg(not(feature = "qemu"))]
mod boot;
#[cfg(not(feature = "qemu"))]
mod controllers;
#[cfg(not(feature = "qemu"))]
mod crypto;
#[cfg(not(feature = "qemu"))]
mod hw;
#[cfg(feature = "qemu")]
mod qemu;
#[cfg(any(not(feature = "qemu"), feature = "qemu-tests"))]
mod qr;
#[cfg(not(feature = "qemu"))]
mod runtime;
#[cfg(not(feature = "qemu"))]
mod release_policy;
#[cfg(not(feature = "qemu"))]
mod services;
#[cfg(not(feature = "qemu"))]
#[cfg_attr(feature = "workflow-test-auto", allow(dead_code))]
mod ui;
#[cfg(not(feature = "qemu"))]
mod version;
#[cfg(not(feature = "qemu"))]
mod wallet;
use esp_hal::main;
#[cfg(not(feature = "qemu"))]
use esp_hal::{
    clock::CpuClock,
    delay::Delay,
    gpio::{Level, Output, OutputConfig},
    i2c::master::I2c,
    spi::master::{Config as SpiConfig, Spi},
    spi::Mode as SpiMode,
    time::Rate,
};
#[cfg(feature = "waveshare")]
use esp_hal::{gpio::{Input, InputConfig, Pull}, i2c::master::Config as I2cConfig};
#[cfg(feature = "waveshare")]
use esp_hal::ledc::{Ledc, LowSpeed, timer, channel};
#[cfg(feature = "waveshare")]
use esp_hal::ledc::timer::TimerIFace;
#[cfg(feature = "waveshare")]
use esp_hal::ledc::channel::ChannelIFace;
#[cfg(not(feature = "qemu"))]
use esp_hal::lcd_cam::cam::Camera as DvpCamera;
#[cfg(all(feature = "m5stack", any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto")))]
use esp_hal::lcd_cam::{LcdCam, cam::Config as CamConfig};
use esp_backtrace as _;
#[cfg(all(not(feature = "qemu"), any(not(feature = "hardware-tests"), feature = "m5stack")))]
use crate::runtime::data::AppData;
#[cfg(not(feature = "qemu"))]
extern crate alloc;
#[cfg(all(feature = "skip-tests", feature = "silent"))]
compile_error!("skip-tests removes boot known-answer tests and is forbidden in production");
// Non-QEMU builds export the ESP-IDF application descriptor from
// services::verify::anti_rollback so `secure_version` is hardware-enforceable.
// QEMU retains the dependency-provided descriptor because it has no eFuses.
#[cfg(feature = "qemu")]
esp_bootloader_esp_idf::esp_app_desc!();
/// Global flag: redraw sets this to reset QR decoder state on screen change.
/// `AtomicBool` with relaxed ordering is sufficient for this single flag and
/// remains sound if it is touched from an interrupt. It is also
/// clean under the 2024-edition `static_mut_refs` rules.
#[cfg(not(feature = "qemu"))]
#[cfg(feature = "waveshare")]
pub static CORE1_OK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
// Stable crate-root fatal halt path used by runtime/signing.rs.
#[cfg(not(feature = "qemu"))]
pub use runtime::power_state::halt_forever;

#[cfg(feature = "qemu")]
#[main]
fn main() -> ! {
    qemu::run()
}

#[cfg(not(feature = "qemu"))]
#[main]
fn main() -> ! {
    firmware_main()
}

#[cfg(not(feature = "qemu"))]
fn firmware_main() -> ! {
    boot::application::print_banner();

    // ─── ESP32-S3 initialization ─────────────────────────────────
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    #[cfg(not(feature = "hardware-tests"))]
    let (persistent_hmac, persistent_flash) = (peripherals.HMAC, peripherals.FLASH);

    crate::services::memory::psram::initialize_or_halt(&peripherals.PSRAM);
    let mut delay = Delay::new();
    diagnostics::maybe_run_sha_bench(&mut delay);
    #[cfg(feature = "rng-probe")] services::entropy::log_rng_probe("before lockdown");

    #[cfg(feature = "waveshare")]
    boot::waveshare::decode_worker::start!(peripherals);

    // ─── Security: fail closed if radio power-domain lockdown is not verified ───
    boot::security::early_lockdown();
    diagnostics::maybe_finish_rng_probe(&mut delay);
    diagnostics::log_build_profile();
    #[cfg(feature = "workflow-test-auto")] runtime::workflow_tests::run_boot_gate();
    // ─── Hardware self-tests ───────────────────────────────────
    #[cfg(feature = "hardware-tests")]
    let startup_tests_ok = runtime::unit_tests::boot::run_startup_tests(&mut delay);
    #[cfg(not(feature = "hardware-tests"))]
    let _ = runtime::unit_tests::boot::run_startup_tests(&mut delay);
    // Initialize peripherals (PLATFORM-SPECIFIC)
    #[cfg_attr(feature = "workflow-test-auto", allow(unused_variables))]
    #[cfg(feature = "waveshare")]
    let (i2c, cam_i2c, mut boot_display, dvp_camera_opt, cam_dma_buf_opt,
         cam_status, sd_card_type, touch_configured,
         sensor_is_ov2640) = boot::waveshare::initialize!(peripherals, delay);
    // M5Stack workflow/HIL images initialize the same board resources as interactive firmware.
    #[cfg_attr(feature = "hardware-tests", allow(unused_variables))]
    #[cfg(feature = "m5stack")]
    let (i2c, mut boot_display, dvp_camera_opt, cam_dma_buf_opt,
         cam_status, sd_card_type, runtime_audio) = boot::m5stack::initialize!(peripherals, delay);
    #[cfg(feature = "waveshare")] let mut i2c = i2c;
    #[cfg(all(feature = "m5stack", feature = "wdev-capture"))] let mut i2c = i2c;
    #[cfg(all(feature = "m5stack", not(feature = "hardware-tests")))] runtime::core_s3::show_recovery_notice(&mut boot_display, &mut delay);
    #[cfg(feature = "wdev-capture")] diagnostics::maybe_run_wdev_capture(&mut i2c, &mut delay);
    runtime::signing::run_firmware_verify(&mut boot_display, &mut delay); // Verify firmware integrity

    // ─── Security: disable JTAG + USB data after verification ───
    #[cfg(not(any(feature = "hardware-tests", feature = "workflow-test-auto")))]
    boot::security::post_boot_lockdown();
    #[cfg(feature = "hardware-tests")]
    log!("Hardware-test mode: USB/JTAG monitor retained until result marker");

    // Boot into main application
    log!("Wallet storage policy initialized at startup");
    log!("─────────────────────────────────────────");
    #[cfg(all(not(feature = "hardware-tests"), not(feature = "workflow-test-auto")))] let tracker = hw::touch::TouchTracker::new();

    #[cfg(feature = "hardware-tests")]
    let boot_tests_ok = runtime::unit_tests::boot::run_boot_tests();
    #[cfg(all(not(feature = "hardware-tests"), not(feature = "skip-tests")))]
    boot::application::enforce_boot_known_answer_tests();

    #[cfg(all(not(feature = "hardware-tests"), not(feature = "workflow-test-auto")))] let (grid_zones, list_zones, page_up_zone, page_down_zone) = runtime::touch_dispatch::touch_zones();
    #[cfg(any(not(feature = "hardware-tests"), feature = "m5stack"))]
    let ad: &mut AppData = runtime::secret_state::initialize();

    #[cfg(not(feature = "hardware-tests"))]
    diagnostics::maybe_run_sentinel_scan(ad, &mut delay);
    #[cfg(feature = "waveshare")]
    diagnostics::maybe_run_imu_dump(&mut i2c, &mut delay);
    diagnostics::maybe_run_icon_browser(&mut boot_display.display, &mut delay);

    #[cfg(all(feature = "waveshare", not(feature = "hardware-tests")))]
    boot::waveshare::configure_camera_defaults(ad, sensor_is_ov2640);

    #[cfg(all(feature = "m5stack", feature = "hardware-tests"))]
    let signing_tests_ok = runtime::unit_tests::boot::run_signing_pipeline_test(ad);
    #[cfg(all(feature = "m5stack", not(feature = "hardware-tests"), not(feature = "skip-tests")))]
    log!("   Signing pipeline test: host/QA (boot KATs retained)");
    #[cfg(all(feature = "m5stack", not(feature = "hardware-tests"), any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto")))]
    boot::m5stack::kpub_worker::start!(peripherals);
    #[cfg(all(feature = "waveshare", feature = "hardware-tests"))]
    let signing_tests_ok = true;
    // Arm runtime liveness only after bounded boot/KAT/signing work is complete.
    #[cfg(all(feature = "m5stack", not(feature = "hardware-tests"), any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto")))]
    let runtime_watchdog = runtime::core_s3::watchdog_feed!(peripherals.TIMG0);
    #[cfg(all(feature = "m5stack", not(feature = "hardware-tests"), feature = "workflow-test-auto", not(feature = "workflow-runtime-auto")))]
    let runtime_watchdog = || {};
    #[cfg(feature = "hardware-tests")]
    runtime::unit_tests::boot::report_hardware_test_result(
        &mut delay,
        startup_tests_ok,
        boot_tests_ok,
        signing_tests_ok,
    );
    #[cfg(not(feature = "hardware-tests"))]
    log!("   Touch ready — tap menu items to navigate");

    #[cfg(all(feature = "mirror", not(feature = "hardware-tests")))]
    log!("   [MIRROR] Live display mirror active");

    // ─── Main loop ───────────────────────────────────────────────
    // Hardware singleton ownership remains local to the entry point; the
    // loop policy expands from focused runtime modules.
    #[cfg(all(not(feature = "hardware-tests"), feature = "waveshare"))]
    runtime::event_loop::runner::run(
        ad, persistent_hmac, persistent_flash,
        boot_display,
        delay,
        i2c,
        #[cfg(not(feature = "workflow-test-auto"))] cam_i2c,
        #[cfg(not(feature = "workflow-test-auto"))] touch_configured,
        #[cfg(not(feature = "workflow-test-auto"))] sensor_is_ov2640,
        sd_card_type,
        dvp_camera_opt,
        cam_dma_buf_opt,
        cam_status,
        #[cfg(not(feature = "workflow-test-auto"))] tracker,
        #[cfg(not(feature = "workflow-test-auto"))]
        (grid_zones, list_zones, page_up_zone, page_down_zone),
    );

    #[cfg(all(not(feature = "hardware-tests"), feature = "m5stack"))]
    runtime::event_loop::runner::run(
        ad, persistent_hmac, persistent_flash,
        boot_display,
        delay,
        i2c,
        sd_card_type,
        dvp_camera_opt,
        cam_dma_buf_opt,
        cam_status,
        #[cfg(not(feature = "workflow-test-auto"))] tracker,
        runtime_audio, runtime_watchdog,
        #[cfg(not(feature = "workflow-test-auto"))]
        (grid_zones, list_zones, page_up_zone, page_down_zone),
    );
}
