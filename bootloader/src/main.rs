// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

#![allow(dead_code)]
#![allow(unused_imports)]
// [S1] `#![allow(static_mut_refs)]` removed 2026-09-01. It had been silencing
// 17 sites across four files, and the lint was right about all of them.
//
// The six in `hw/cam_dma.rs` were the ones that mattered: `as_ptr()` on a
// `static mut` array forms a shared reference, which asserts the memory is not
// mutated while it lives, and the GDMA engine writes those bounce buffers. The
// rest were claims stronger than the code needed. Two whole groups turned out
// to be dead state from removed filters and were deleted rather than fixed
// ([K13]).
//
// Do not put this back to quieten a new site. Each one is either a false claim
// about memory something else writes, or a `&mut` where a pointer would do.
// The file-local `#[allow]` exists if a single site ever genuinely needs it.
// Clippy Phase A+B cleanup — remaining allows are architectural or intentional
#![allow(clippy::manual_range_contains)]        // explicit range checks in SD filename parsing
#![allow(clippy::collapsible_else_if)]          // else { if } with trailing statements
#![allow(clippy::needless_lifetimes)]           // explicit lifetimes for documentation
#![allow(clippy::unnecessary_mut_passed)]       // mutable ref to DMA methods
#![allow(clippy::needless_range_loop)]          // index-based loops intentional in no_std crypto/DMA
#![allow(clippy::too_many_arguments)]           // handler functions need many params
#![allow(clippy::identity_op)]                  // 0 | HARDENED_BIT for BIP32 path clarity
#![allow(clippy::single_match)]                 // match with one arm often clearer than if-let
#![allow(clippy::nonminimal_bool)]              // expanded bool for readability in crypto
#![allow(clippy::manual_div_ceil)]              // (a + b - 1) / b — .div_ceil() not stable in no_std
#![allow(clippy::unnecessary_min_or_max)]       // explicit min/max for bounds documentation
#![allow(clippy::manual_clamp)]                 // explicit if/else clamp for clarity
#![allow(clippy::manual_find)]                  // manual loop find in no_std
#![allow(clippy::manual_is_multiple_of)]        // x % n == 0 — .is_multiple_of() not stable in no_std
#![allow(clippy::if_same_then_else)]            // platform-specific cfg blocks
#![allow(clippy::manual_memcpy)]                // manual slice copy in unsafe DMA blocks
#![allow(clippy::manual_saturating_arithmetic)] // explicit saturating in crypto
// [S2] 45 allows removed 2026-09-01, and the reason is that they never did
// anything. There is no `#![warn(clippy::pedantic)]`, no nursery, and no
// clippy.toml anywhere in the tree, and CI runs
// `cargo clippy --all-targets -- -D warnings`. So every allow naming a lint
// outside clippy's default groups suppressed a warning that could not fire.
//
// That is worse than harmless. `cast_possible_truncation` sat here with a
// comment reading "ubiquitous u32->u8, usize->u8 in byte manipulation", which
// reads as a considered decision about casts. Nobody had ever seen the
// warnings: turning the lint on with `--force-warn` produced 120, of which 29
// are in key-derivation or consensus code. Those 29 were audited on 2026-09-01
// and every one is sound, but the audit happened because the allow was
// questioned, not because it was there.
//
// The ones below are load-bearing: each suppresses a lint in a default group,
// so deleting one turns CI red. Kept verbatim identical between this file and
// its twin so the shared sources compile under the same lints in both crates.
//
// To revisit the removed set, add `#![warn(clippy::pedantic)]` rather than
// re-adding allows: that makes the suppressions mean something.
//
// FOUR of the removals were WRONG and clippy said so on 2026-09-01:
// `needless_lifetimes`, `unnecessary_mut_passed`, `manual_range_contains`
// and `collapsible_else_if` are default-group lints, not pedantic, so
// their allows were load-bearing. Restored below. The classification
// behind this cleanup was recalled rather than measured, which is why it
// was run against all four configurations before it was trusted.
//
// LIMIT OF THIS METHOD, worth knowing before trusting the survivors: a
// clippy run only exposes an allow whose lint has a violation somewhere
// in the code. An allow for a default-group lint that nothing currently
// violates was removed silently here and will only surface the day
// someone writes code that trips it.
#![allow(clippy::manual_range_patterns)]        // manual range patterns for touch zones
#![allow(clippy::implicit_saturating_sub)]      // manual arithmetic for saturating subtract
#![allow(clippy::manual_pattern_char_comparison)] // explicit case comparison
#![allow(clippy::doc_lazy_continuation)]        // doc comment formatting
// Clippy pedantic — suppressed (intentional in no_std embedded)
#![no_std]
#![no_main]

// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.


// ─── Module-level warning policy ──────────────────────────────
//
// main.rs — KasSigner bootloader entry point
//
// Supports two hardware platforms via Cargo features:
//   --features waveshare  → Waveshare ESP32-S3-Touch-LCD-2
//   --features m5stack    → M5Stack CoreS3 / CoreS3 Lite
//
// Boot sequence: Phase 1 (self-tests) → Phase 2 (peripherals) →
// Phase 3 (firmware verify) → Phase 5 (main loop with touch dispatch).
//
// Peripheral singletons (I2C, SPI, LCD_CAM, I2S) are consumed here
// because esp-hal requires ownership at initialization time.

// ─── Linker note ─────────────────────────────────────────────
// ISR symbols are provided by device.x (from esp32s3 v0.30 rt feature)
// which is INCLUDEd via hal-defaults.x in the esp-hal linker chain.
// DefaultHandler is defined as EspDefaultHandler in hal-defaults.x.
// No manual stubs needed.

// ─── Module tree ─────────────────────────────────────────────
mod crypto;
// The wallet library is kassigner-core (core/). Re-exported as `crate::wallet`
// so every path in the firmware is unchanged.
pub use kassigner_core::wallet;
mod hw;
mod qr;
mod app;
mod ui;
mod features;
mod handlers;
mod version;

use esp_hal::{
    delay::Delay,
    i2c::master::{Config as I2cConfig, I2c},
    spi::master::{Config as SpiConfig, Spi},
    spi::Mode as SpiMode,
    time::Rate,
    clock::CpuClock,
    gpio::{Output, OutputConfig, Level},
    main,
};
#[cfg(feature = "waveshare")]
use esp_hal::gpio::{Input, InputConfig, Pull};
#[cfg(feature = "waveshare")]
use esp_hal::ledc::{Ledc, LowSpeed, timer, channel};
#[cfg(feature = "waveshare")]
use esp_hal::ledc::timer::TimerIFace;
#[cfg(feature = "waveshare")]
use esp_hal::ledc::channel::ChannelIFace;
use esp_hal::lcd_cam::LcdCam;
use esp_hal::lcd_cam::cam::{Camera as DvpCamera, Config as CamConfig};
use esp_backtrace as _;
use crate::app::data::AppData;
use crate::app::input::HandlerGroup;

extern crate alloc;

// ─── Build-time guards against shipping diagnostic features (M-14) ───
//
// Each of these exists to measure or debug something and none belongs in a
// released binary. `production` implies `silent`, so testing `silent` rejects
// both shipping them and building them with the log stubbed out, which is the
// same reasoning as the `imu-dump` guard in hw/imu_ws.rs.
//
// The guards live here rather than beside each feature so that adding a
// diagnostic feature means adding a line to this list, in one visible place.

#[cfg(all(feature = "sentinel-scan", feature = "silent"))]
compile_error!(
    "sentinel-scan compiles a derived PRIVATE KEY into the binary as a search \
     pattern and must never ship. Drop --features sentinel-scan."
);

#[cfg(all(feature = "sha-bench", feature = "silent"))]
compile_error!(
    "sha-bench is a measurement harness no production path calls. Drop \
     --features sha-bench."
);

#[cfg(all(feature = "rng-probe", feature = "silent"))]
compile_error!(
    "rng-probe is a measurement harness for M-13 and reports raw RNG statistics. \
     Drop --features rng-probe."
);

#[cfg(all(feature = "screenshot", feature = "silent"))]
compile_error!(
    "screenshot streams framebuffer contents off the device, including seed \
     and passphrase screens. Drop --features screenshot / mirror."
);

#[cfg(all(feature = "imu-dump", feature = "silent"))]
compile_error!(
    "imu-dump prints raw gyro samples to the serial log, the same physical \
     noise bytes the seed pool is fed from, and is useless with the log \
     stubbed out. Drop --features imu-dump."
);

// skip-tests is not a diagnostic, it is the ABSENCE of one: it removes the
// crypto known-answer tests. P-09 was exactly this feature reaching the
// Dockerfile release stages, so every documented build shipped with the KATs
// unreachable. A release binary that has never verified its own primitives
// against a published vector is the condition H-12 hid in.
#[cfg(all(feature = "skip-tests", feature = "silent"))]
compile_error!(
    "skip-tests removes the crypto known-answer tests. A shipped build must \
     verify its own primitives at boot. Drop --features skip-tests."
);

// icon-browser replaces the normal UI with a developer icon gallery. Harmless
// to secrets, but a released binary that boots into it is not a signer.
#[cfg(all(feature = "icon-browser", feature = "silent"))]
compile_error!(
    "icon-browser replaces the device UI with a developer gallery. Drop \
     --features icon-browser."
);

// verbose-boot is not merely noisy: section 2b of the audit records it dumping
// sighash material over USB (I-04). It is stubbed out by `silent` rather than
// removed, so the combination is a build that thinks it is diagnostic and is
// not.
#[cfg(all(feature = "verbose-boot", feature = "silent"))]
compile_error!(
    "verbose-boot leaks transaction contents over USB and is inert with the \
     log stubbed out. Drop --features verbose-boot."
);

// e12-capture and wdev-capture write RAW noise-source output (the camera bytes
// the seed path hashes, and raw WDEV RNG words) to a removable SD card for
// offline SP 800-90B analysis. Measurement only; a shipped build must not be
// able to do that.
#[cfg(all(feature = "e12-capture", feature = "silent"))]
compile_error!(
    "e12-capture writes the raw camera bytes the seed path hashes to SD. \
     Measurement only. Drop --features e12-capture."
);

#[cfg(all(feature = "wdev-capture", feature = "silent"))]
compile_error!(
    "wdev-capture writes raw hardware RNG output to SD. Measurement only. \
     Drop --features wdev-capture."
);

// ─── Logging macro (available to all modules via `use crate::log`) ───
#[cfg(not(feature = "silent"))]
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { esp_println::println!($($arg)*) };
}
// `{{ }}`, not `{ }`. A macro arm expanding to `{ }` is a block with no value,
// so every `log!(...)` sitting where an expression is required failed with
// "macro expansion ends with an incomplete expression". Rust then declines to
// publish a macro whose definition did not parse, so `#[macro_export]` had no
// effect and every other module reported "cannot find macro `log`", taking with
// it the modules that define FIRMWARE_SIZE, run_boot_tests, handle_menu_touch
// and the rest. 67 errors, one cause.
//
// The arguments are still consumed, so unused-variable warnings do not appear
// and drop order is unchanged.
//
// This is why `--features production` had never built: P-08, confirmed
// 2026-08-02.
#[cfg(feature = "silent")]
#[macro_export]
macro_rules! log {
    // Bare `log!()` with no arguments. There are 15 of them, used as blank
    // lines. `format_args!()` requires at least a format string, so a single
    // catch-all arm cannot serve both cases.
    () => {{ }};
    ($($arg:tt)*) => {{
        // Consume the arguments without formatting them, so that a `log!` in
        // expression position still yields `()` and nothing is left unused.
        let _ = format_args!($($arg)*);
    }};
}

use features::verify::{FirmwareInfo, VerificationResult, FIRMWARE_START_ADDR, FIRMWARE_MAX_SIZE};

/// Main-loop iterations between IMU entropy restagings.
///
/// MEASURED, not estimated. The self-timing heartbeat in crypto::entropy
/// reported 623 ms/stage at 512 ticks on a Waveshare board idling at the
/// menu, so one iteration is 1.22 ms and this fires every ~0.62 s.
///
/// An earlier comment here guessed ~2 ms per iteration and "about one
/// collection per second". The guess was 1.6x off. The value is kept anyway:
/// a 3 ms collection every 623 ms is a 0.48% I2C duty cycle, and a fresher
/// stage is worth more than the saving from halving it.
///
/// Note the heartbeat returned the same 39910 ms on two consecutive boots,
/// to the millisecond. The idle loop is deterministic, which is worth
/// remembering whenever a comment claims loop timing is an entropy source.
#[cfg(feature = "waveshare")]
const IMU_RESTAGE_TICKS: u32 = 512;

// App descriptor — v0.2 macro
esp_bootloader_esp_idf::esp_app_desc!();

/// Global flag: redraw sets this to reset QR decoder state on screen change.
/// AtomicBool (Relaxed): same single instruction on Xtensa as the old
/// `static mut bool`, but sound if ever touched from an interrupt, and
/// clean under the 2024-edition `static_mut_refs` rules.
/// Core 1 rqrr worker is up; camera loop uses the pipelined decode path.
pub static CORE1_OK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub static QR_RESET_FLAG: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Active sensor type on Waveshare (runtime auto-detect).
/// false = OV5640 (default), true = OV2640.
#[cfg(feature = "waveshare")]
///
/// Atomic rather than `static mut`, matching `CORE1_OK` above: written once
/// during camera init and read from five places, so the atomic keeps that
/// sound by construction instead of by an invariant a future edit could
/// break. Free here, a `Relaxed` load is the same instruction as a plain
/// read on Xtensa and no reader is on a hot path, and it removes five
/// `unsafe` blocks.
pub static SENSOR_OV2640: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// ═══════════════════════════════════════════════════════════════════════
//  ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════

// The two hooks kassigner-core needs from the hardware, registered first
// thing in `main`. Nothing in the core crate prints or signs before these.
#[cfg(not(feature = "silent"))]
fn core_log(args: core::fmt::Arguments<'_>) {
    esp_println::println!("{}", args);
}
fn core_entropy(out: &mut [u8]) -> Result<(), ()> {
    crypto::entropy::fill(out).map_err(|_| ())
}

#[main]
fn main() -> ! {
    // kassigner-core hooks. Silent builds register no logger, so the core
    // crate stays exactly as silent as the firmware macro made it.
    #[cfg(not(feature = "silent"))]
    kassigner_core::log::set_logger(core_log);
    kassigner_core::entropy::set_source(core_entropy);

    log!();
    log!("╔════════════════════════════════════╗");
    log!("║      KasSigner Bootloader          ║");
    log!("║   Secure Boot for Kaspa Signer     ║");
    log!("╚════════════════════════════════════╝");
    // Version from the single source of truth (bootloader/Cargo.toml, via
    // version.rs). Always correct, never hand-edited.
    log!("   Firmware v{}", crate::version::STRING);
    log!();

    // ─── ESP32-S3 initialization ─────────────────────────────────
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::psram_allocator!(peripherals.PSRAM, esp_hal::psram);
    log!("   PSRAM: initialized via psram_allocator!");

    // Measurement only, and only under the `sha-bench` feature. Placed
    // here because the SHA peripheral is otherwise unclaimed and this
    // runs before any display or camera setup, so nothing contends with
    // it. Consumes peripherals.SHA, which no other code touches.
    #[cfg(feature = "sha-bench")]
    app::sha_bench::run(peripherals.SHA);

    let mut delay = Delay::new();

    // ─── Core 1: rqrr decode worker (Waveshare) ───
    // The viewfinder halted for every decode while rqrr ran on the main core.
    // Park rqrr on the second LX7 instead; the camera loop hands it jobs and
    // keeps blitting. On any failure the flag stays false and the camera loop
    // uses the original synchronous path.
    #[cfg(feature = "waveshare")]
    {
        use esp_hal::system::{CpuControl, Stack};
        // 48KB: measured need after the rqrr heap-backing fix is ~4KB on a
        // host build; 12x field margin for the Xtensa windowed ABI's register
        // spills. (With rqrr's payload buffers inline on the stack the true
        // need was >96KB, which is what smashed the original 16KB guard.)
        static mut APP_CORE_STACK: Stack<49152> = Stack::new();
        let mut cpu_control = CpuControl::new(peripherals.CPU_CTRL);
        match cpu_control.start_app_core(
            unsafe { &mut *core::ptr::addr_of_mut!(APP_CORE_STACK) },
            || hw::decode_core::core1_main(),
        ) {
            Ok(guard) => {
                core::mem::forget(guard); // parked on drop — keep it running
                CORE1_OK.store(true, core::sync::atomic::Ordering::Relaxed);
                log!("   Core 1: rqrr worker started (48KB stack, heap-backed rqrr)");
            }
            Err(_) => {
                log!("   Core 1: start failed — decode stays on core 0");
            }
        }
        // cpu_control drops normally here: CpuControl has no Drop impl, so
        // nothing happens — only the guard's drop would park the core, and
        // that one is forgotten above.
    }

    // ─── Security: kill radios immediately (Waveshare only — M5Stack has no lockdown yet) ───
    //
    // M-13 probe: `early_lockdown` zeroes the whole of SYSTEM_WIFI_CLK_EN, a
    // shared register, and the concern is that it also gates the clock feeding
    // the WDEV RNG. Measured either side rather than argued about.
    #[cfg(feature = "rng-probe")]
    {
        let (d, o, z, r) = crypto::entropy::probe_wdev(256);
        log!("   [rng-probe] BEFORE lockdown: distinct {}/256  ones {}/8192  zero_words {}  repeats {}  wifi_clk_en 0x{:08X}",
            d, o, z, r, crypto::entropy::read_wifi_clk_en());
    }

    // Both boards as of 2026-08-02. This was Waveshare-only with the note
    // "M5Stack has no lockdown yet", which was never a technical constraint:
    // every register `early_lockdown` touches is SoC-level and identical on
    // both, and M5Stack had exactly the same wireless domain powered on at
    // reset. It was untested, not incompatible.
    hw::lockdown::early_lockdown();

    #[cfg(feature = "rng-probe")]
    {
        // `wifi_clk_en` here is the proof that `early_lockdown` now reaches the
        // right register: everything cleared except bit 15, the RNG's clock.
        // Before the address fix it read 0xFFFCE030 after the lockdown, because
        // the lockdown was writing to a PVT error register instead.
        let (d, o, z, r) = crypto::entropy::probe_wdev(256);
        log!("   [rng-probe] AFTER  lockdown: distinct {}/256  ones {}/8192  zero_words {}  repeats {}  wifi_clk_en 0x{:08X}",
            d, o, z, r, crypto::entropy::read_wifi_clk_en());
    }

    // ─── Stack paint ─────────────────────────────────────────────
    // As early and as shallow as possible: everything below this frame gets
    // painted, so painting from deeper would leave the deep region unmeasured.
    // Must run before the self-tests, which are themselves a deep call chain.
    let (paint_lo, paint_hi) = app::stack_probe::paint();
    app::stack_probe::report_layout(paint_lo, paint_hi);

    // ─── Phase 1: Hardware self-tests ────────────────────────────
    app::boot_test::run_phase1_tests(&mut delay);
    app::stack_probe::report("after phase 1");

    // ═══════════════════════════════════════════════════════════════
    // Phase 2: Initialize peripherals (PLATFORM-SPECIFIC)
    // ═══════════════════════════════════════════════════════════════

    // ─── WAVESHARE PERIPHERAL INIT ───────────────────────────────
    #[cfg(feature = "waveshare")]
    let (mut i2c, mut cam_i2c, mut boot_display, mut dvp_camera_opt, mut cam_dma_buf_opt,
         mut cam_status, mut _bb_card_type, mut touch_configured) = {
        log!("Phase 2: Initializing Display (Waveshare)");
        log!("──────────────────────────────────────────");

        // I2C0 for touch (GPIO48=SDA, GPIO47=SCL)
        let mut i2c = I2c::new(
            peripherals.I2C0,
            I2cConfig::default().with_frequency(Rate::from_khz(400)),
        )
        .expect("I2C0 init failed — hardware fault")
        .with_sda(peripherals.GPIO48)
        .with_scl(peripherals.GPIO47);

        // I2C1 for camera SCCB (GPIO21=SDA, GPIO16=SCL)
        let mut cam_i2c = I2c::new(
            peripherals.I2C1,
            I2cConfig::default().with_frequency(Rate::from_khz(100)),
        )
        .expect("I2C1 init failed — camera SCCB fault")
        .with_sda(peripherals.GPIO21)
        .with_scl(peripherals.GPIO16);

        // Touch INT pin (GPIO46)
        let _touch_int = Input::new(peripherals.GPIO46, InputConfig::default().with_pull(Pull::Up));
        log!("   Touch INT pin (GPIO46) configured");

        // Battery ADC (GPIO5)
        hw::battery::init_battery_adc();
        {
            let batt = hw::battery::read_battery(&mut i2c);
            if let Some(b) = batt {
                log!("   Battery: {}mV {}% {:?}", b.voltage_mv, b.percentage, b.state);
            } else {
                log!("   Battery: read failed");
            }
        }

        // IMU entropy source (QMI8658C, waveshare only).
        //
        // On the shared GPIO47/48 bus alongside the touch controller, NOT the
        // GPIO21/16 camera bus the boot scan above uses. Configured once here
        // rather than at seed time: the part needs 60 ms + 3/ODR after enable
        // before the gyro produces valid data, and a soft reset would cost
        // 1.75 s of system turn-on.
        //
        // Additive only. Failure marks the IMU absent and contributes nothing
        // to the entropy pool; the camera remains the fail-closed gate.
        hw::imu::init(&mut i2c, &mut delay);

        // Gate unused peripheral clocks
        unsafe {
            let clk0 = core::ptr::read_volatile(0x600C_0018u32 as *const u32);
            let gate_bits = (1u32 << 5) | (1u32 << 9) | (1u32 << 10) | (1u32 << 16)
                | (1u32 << 17) | (1u32 << 19) | (1u32 << 20) | (1u32 << 21);
            core::ptr::write_volatile(0x600C_0018u32 as *mut u32, clk0 & !gate_bits);
        }

        // Camera PWDN LOW = active (GPIO17)
        let _cam_pwdn = Output::new(peripherals.GPIO17, Level::Low, OutputConfig::default());
        log!("   Camera PWDN deasserted (GPIO17 LOW)");

        // No audio on Waveshare
        log!("   Audio: not available on this board");

        // SD pre-init
        let mut _bb_card_type = init_sd_card_ws(&mut delay);

        // SPI display (ST7789T3)
        log!("   SPI + ST7789T3 init...");
        let spi = Spi::new(
            peripherals.SPI2,
            SpiConfig::default()
                .with_frequency(Rate::from_mhz(80))
                .with_mode(SpiMode::_0),
        )
        .expect("SPI2 init failed — hardware fault")
        .with_sck(peripherals.GPIO39)
        .with_mosi(peripherals.GPIO38);

        let cs_pin = Output::new(peripherals.GPIO45, Level::High, OutputConfig::default());
        let dc_pin = Output::new(peripherals.GPIO42, Level::Low, OutputConfig::default());
        let reset_pin = Output::new(peripherals.GPIO0, Level::High, OutputConfig::default());

        let boot_display = match hw::display::BootDisplay::new(spi, cs_pin, dc_pin, reset_pin, &mut delay) {
            Ok(d) => { log!("   ST7789T3 display initialized OK — 320x240 color"); d }
            Err(e) => {
                log!("Display init error: {}", e);
                continue_without_display(&mut delay);
            }
        };

        // SDHOST init (post-display)
        _bb_card_type = match hw::sdcard::init_sdhost(&mut delay) {
            Ok(ct) => {
                log!("   SD card initialized: {:?}", ct);
                Some(ct)
            }
            Err(e) => {
                log!("   SD card init failed: {} (continuing without SD)", e);
                None
            }
        };

        // Camera + LEDC XCLK + Backlight
        // NOTE: We do NOT create DvpCamera for Waveshare — cam_dma drives
        // GDMA CH0 + LCD_CAM directly via raw registers for PSRAM DMA.
        // DvpCamera would take ownership of DMA_CH0 and prevent raw access.
        log!("   LCD_CAM + LEDC init (raw GDMA mode)...");
        let mut cam_status = hw::camera::CameraStatus::Error;

        // ── LEDC: XCLK 20MHz on GPIO8 + Backlight PWM on GPIO1 ──
        {
            let mut ledc = Ledc::new(peripherals.LEDC);
            ledc.set_global_slow_clock(esp_hal::ledc::LSGlobalClkSource::APBClk);

            let mut lstimer0 = ledc.timer::<LowSpeed>(timer::Number::Timer0);
            match lstimer0.configure(timer::config::Config {
                duty: timer::config::Duty::Duty2Bit,
                clock_source: timer::LSClockSource::APBClk,
                frequency: Rate::from_mhz(20),
            }) {
                Ok(()) => log!("   LEDC timer: 20MHz, 2-bit duty OK"),
                Err(e) => log!("   LEDC timer FAILED: {:?}", e),
            }

            let mut channel0 = ledc.channel(channel::Number::Channel0, peripherals.GPIO8);
            match channel0.configure(channel::config::Config {
                timer: &lstimer0,
                duty_pct: 50,
                drive_mode: esp_hal::gpio::DriveMode::PushPull,
            }) {
                Ok(()) => log!("   LEDC channel: 50% duty on GPIO8 OK"),
                Err(e) => log!("   LEDC channel FAILED: {:?}", e),
            }
            log!("   LEDC 20MHz XCLK on GPIO8");

            // Backlight PWM
            let mut lstimer1 = ledc.timer::<LowSpeed>(timer::Number::Timer1);
            match lstimer1.configure(timer::config::Config {
                duty: timer::config::Duty::Duty8Bit,
                clock_source: timer::LSClockSource::APBClk,
                frequency: Rate::from_khz(1),
            }) {
                Ok(()) => log!("   LEDC backlight timer: 1kHz, 8-bit OK"),
                Err(e) => log!("   LEDC backlight timer FAILED: {:?}", e),
            }

            let mut bl_channel = ledc.channel(channel::Number::Channel1, peripherals.GPIO1);
            match bl_channel.configure(channel::config::Config {
                timer: &lstimer1,
                duty_pct: 0,
                drive_mode: esp_hal::gpio::DriveMode::PushPull,
            }) {
                Ok(()) => log!("   LEDC backlight channel: GPIO1 OK"),
                Err(e) => log!("   LEDC backlight channel FAILED: {:?}", e),
            }

            hw::pmu::set_brightness(&mut i2c, app::data::DEFAULT_BRIGHTNESS);
            log!("   Backlight ON via PWM (brightness={})", app::data::DEFAULT_BRIGHTNESS);
        }

        // ── XCLK verify REMOVED 2026-08-15 ──
        //
        // It polled GPIO8 through GPIO_IN in a tight loop and counted
        // transitions. XCLK is 20 MHz and each iteration is a volatile read
        // plus a compare, so on a 240 MHz core the sampler ran at the same
        // order as the signal: what it reported was aliasing, not clock
        // health. Measured on Waveshare, same firmware, three boots:
        // 61,539 toggles, then 2, then 3. Nothing about the clock changed
        // between them; only the phase did.
        //
        // The near-zero readings prompted a camera investigation that found
        // nothing wrong: the sensor was detected, configured, streaming full
        // 230,400-byte frames, and decoded a QR. A check that reports a fault
        // on a working device is worse than no check, because it teaches you
        // to ignore the log.
        //
        // The PCLK sampler that followed it went the same way on 2026-08-25:
        // it read 133,331 the day the XCLK one was removed, then 71,430, 12,
        // 1 and 6 on four consecutive boots of one firmware with the camera
        // decoding QR codes on all of them. Same loop, same aliasing.
        //
        // The VSYNC sampler went with it, for two reasons that each suffice.
        // Its 500,000-iteration window is a few milliseconds and a frame is
        // tens of them (HTS 1896 x VTS 984 pixel clocks), so it could only
        // report an edge when the window happened to straddle one. And it
        // ran before `setup_cam_gpio_routing()`, so GPIO6 was not yet an
        // input the matrix would deliver; it read 0 on every boot in every
        // log, camera working each time.
        //
        // XCLK, PCLK and VSYNC are proven by the thing they exist for:
        // `cam_dma` logging full 230,400-byte frames (a frame cannot be
        // delivered without VSYNC framing it) and rqrr decoding from them,
        // both a few lines further down the boot log.
        //
        // The IO_MUX write that used to sit here set bit 9 (input enable) on
        // GPIO8 so the pin could be read at all. It existed only to serve this
        // measurement, so it goes with it and the pin keeps the configuration
        // LEDC gave it.
        //
        // The 30 ms delay stays: it precedes camera bring-up and this is not
        // the change in which to find out whether that timing mattered.
        delay.delay_millis(30);

        // NOTE: Do NOT call enable_lcd_cam_clocks() here — it reassigns GPIO8
        // from LEDC (our XCLK source) to LCD_CAM cam_clk output signal 149.
        // LEDC is already providing 20MHz XCLK on GPIO8. LCD_CAM peripheral
        // clocks (GDMA + LCD_CAM module) are enabled by cam_dma::init().

        // ── I2C1 bus scan ──
        log!("   I2C1 bus scan:");
        {
            let mut found = false;
            for addr in 0x08u8..0x78 {
                let mut probe = [0u8; 1];
                if cam_i2c.read(addr, &mut probe).is_ok() {
                    log!("     Found device at 0x{:02X}", addr);
                    found = true;
                }
            }
            if !found { log!("     No devices found on I2C1"); }
        }

        // ── Camera auto-detect: OV5640 first, OV2640 fallback ──
        log!("   Camera auto-detect...");
        if hw::camera::detect(&mut cam_i2c) {
            log!("   OV5640 found — init {}x{} Y8...", hw::cam_dma::FRAME_W, hw::cam_dma::FRAME_H);
            match hw::camera::init_hires(&mut cam_i2c, &mut delay) {
                Ok(()) => {
                    log!("   OV5640 OK — {}x{} configured", hw::cam_dma::FRAME_W, hw::cam_dma::FRAME_H);
                    cam_status = hw::camera::CameraStatus::SensorReady;
                }
                Err(e) => log!("   OV5640 init FAILED: {}", e),
            }
        } else {
            log!("   OV5640 not found, trying OV2640...");
            match hw::camera_ov2640::init_480(&mut cam_i2c, &mut delay) {
                Ok(()) => {
                    log!("   OV2640 OK — 480x480 Y8 configured");
                    #[cfg(feature = "cam640")]
                    log!("   WARNING: cam640 build expects 640x640 frames — OV2640 outputs 480x480, scanning will NOT work. Rebuild without cam640 for OV2640 modules.");
                    cam_status = hw::camera::CameraStatus::SensorReady;
                    SENSOR_OV2640.store(true, core::sync::atomic::Ordering::Relaxed);
                }
                Err(e) => log!("   OV2640 init FAILED: {}", e),
            }
        }

        // ── PWDN reset + re-init with XCLK running ──
        if cam_status == hw::camera::CameraStatus::SensorReady {
            log!("   Camera PWDN reset (with XCLK running)...");
            unsafe { core::ptr::write_volatile(0x6000_4008u32 as *mut u32, 1u32 << 17); }
            delay.delay_millis(20);
            unsafe { core::ptr::write_volatile(0x6000_400Cu32 as *mut u32, 1u32 << 17); }
            delay.delay_millis(30);

            let is_ov2640 = SENSOR_OV2640.load(core::sync::atomic::Ordering::Relaxed);
            if is_ov2640 {
                match hw::camera_ov2640::init_480(&mut cam_i2c, &mut delay) {
                    Ok(()) => log!("   OV2640 re-init with XCLK (480x480): OK"),
                    Err(e) => log!("   OV2640 re-init with XCLK: {}", e),
                }
                delay.delay_millis(100);
                hw::camera_ov2640::log_diagnostics(&mut cam_i2c);
            } else {
                match hw::camera::init_hires(&mut cam_i2c, &mut delay) {
                    Ok(()) => log!("   OV5640 re-init with XCLK ({}x{}): OK", hw::cam_dma::FRAME_W, hw::cam_dma::FRAME_H),
                    Err(e) => log!("   OV5640 re-init with XCLK: {}", e),
                }
                delay.delay_millis(100);
                hw::camera::log_diagnostics(&mut cam_i2c);
            }

            // PCLK and VSYNC samplers REMOVED 2026-08-25; see the XCLK note
            // above.
        }

        // ── GPIO matrix routing (same as before — manual, not via DvpCamera) ──
        hw::camera::setup_cam_gpio_routing();

        // ── cam_dma: raw GDMA→PSRAM pipeline (replaces DvpCamera + DmaRxBuf) ──
        let dvp_camera_opt: Option<DvpCamera<'_>> = None;
        let cam_dma_buf_opt: Option<esp_hal::dma::DmaRxBuf> = None;

        if cam_status == hw::camera::CameraStatus::SensorReady {
            if hw::cam_dma::init() {
                log!("   cam_dma: PSRAM pipeline ready — {}x{} Y8", hw::cam_dma::FRAME_W, hw::cam_dma::FRAME_H);
                hw::cam_dma::log_status();
            } else {
                log!("   cam_dma: INIT FAILED — falling back to no camera");
                cam_status = hw::camera::CameraStatus::Error;
            }
            delay.delay_millis(150);
        }

        let touch_configured = false;
        (i2c, cam_i2c, boot_display, dvp_camera_opt, cam_dma_buf_opt,
         cam_status, _bb_card_type, touch_configured)
    };

    // ─── M5STACK PERIPHERAL INIT ─────────────────────────────────
    #[cfg(feature = "m5stack")]
    let (mut i2c, mut boot_display, mut dvp_camera_opt, mut cam_dma_buf_opt,
         mut cam_status, mut _bb_card_type) = {
        log!("Phase 2: Initializing Display (CoreS3)");
        log!("──────────────────────────────────────────");

        // I2C0 (shared: PMU, IO expander, touch, camera SCCB)
        let mut i2c = I2c::new(
            peripherals.I2C0,
            I2cConfig::default().with_frequency(Rate::from_khz(400)),
        )
        .expect("I2C0 init failed — hardware fault")
        .with_sda(peripherals.GPIO12)
        .with_scl(peripherals.GPIO11);

        // PMU + IO expander
        init_pmu_m5(&mut i2c, &mut delay);

        // NOTE, recorded so nobody re-proposes it: the AXP2101 VBAT ADC was
        // probed as an entropy candidate and is DEAD. On battery, USB
        // unplugged, 32 samples 20 ms apart: 1 distinct value, spread 0 mV.
        // Almost certainly internally averaged. The first probe was run
        // plugged in and full, where the charger regulates VBAT and pins the
        // reading, and back-to-back so every read returned the same latched
        // conversion; both flaws were fixed and the answer did not change.

        // ES7210 identification. READ ONLY: two register reads, no writes,
        // nothing powered up. Confirms the codec is on the bus and settles the
        // address before any configuration is attempted.
        match hw::mic_m5::probe(&mut i2c) {
            Some(id) => log!(
                "   [mic] ES7210 at 0x{:02X}, id {:02X}{:02X}, ver {:02X}",
                id.addr, id.id1, id.id0, id.version
            ),
            None => log!("   [mic] ES7210 not found on I2C"),
        }

        // I2S audio + speaker
        {
            log!("   I2S1 hardware peripheral init...");
            // TX DMA buffer. 16368 bytes of internal DRAM, which is a lot on a
            // board whose measured margin is 768 bytes (audit 2a), and it
            // holds silence almost all the time: hw/sound_m5.rs treats it as a
            // scratchpad, overwriting it in place with a square wave for a
            // beep and then rewriting silence, with the circular DMA never
            // stopping.
            //
            // REDUCING IT TO 2*4092 WAS TRIED AND KILLED AUDIO COMPLETELY.
            // Not distorted, not clipped: no sound anywhere, clicks included.
            // Reverted. The reason is not understood — the size arithmetic
            // says 8184 bytes is 2046 frames, ~43 ms, ~42 cycles of a 1 kHz
            // tone, which should be ample — so the fault is something other
            // than tone length. Two candidates, neither verified: circular DMA
            // may need more than the two descriptor chunks that size yields,
            // or write_dma_circular may be failing outright and leaving
            // _i2s_tx_ready false, which would also silence the AW88298 since
            // its init requires the I2S clocks to be already running.
            //
            // Do not shrink this again without reading the esp-hal circular
            // DMA implementation first and checking the boot log for
            // "I2S1 circular DMA failed".
            let (_, _, mut tx_buffer, tx_descriptors) = esp_hal::dma_buffers!(0, 4 * 4092);
            use esp_hal::i2s::master::{I2s, Config as I2sConfig2, DataFormat, Channels};

            let i2s_config = I2sConfig2::new_tdm_philips()
                .with_sample_rate(Rate::from_hz(48000))
                .with_data_format(DataFormat::Data16Channel16)
                .with_channels(Channels::STEREO);

            tx_buffer.as_mut_slice().fill(0);
            let mut _i2s_tx_storage: core::mem::MaybeUninit<_> = core::mem::MaybeUninit::uninit();
            let mut _i2s_tx_ready = false;
            let dma_buf_ptr = tx_buffer.as_mut_slice().as_mut_ptr();
            let dma_buf_len = tx_buffer.as_mut_slice().len();

            if let Ok(i2s) = I2s::new(peripherals.I2S1, peripherals.DMA_CH1, i2s_config) {
                _i2s_tx_storage.write(
                    i2s.i2s_tx
                        .with_bclk(peripherals.GPIO34)
                        .with_ws(peripherals.GPIO33)
                        .with_dout(peripherals.GPIO13)
                        .build(tx_descriptors)
                );
                let i2s_tx = unsafe { _i2s_tx_storage.assume_init_mut() };
                match i2s_tx.write_dma_circular(&mut tx_buffer) {
                    Ok(transfer) => { core::mem::forget(transfer); _i2s_tx_ready = true; }
                    Err(_) => log!("   I2S1 circular DMA failed"),
                }
            } else {
                log!("   I2S1 config failed");
            }

            let _ = i2c.write(hw::pmu::AW9523B_ADDR, &[0x02u8, 0x05u8]);
            delay.delay_millis(100);

            log!("   AW88298 Speaker init...");
            let sound_ok = match hw::sound::init_aw88298(&mut i2c, &mut delay) {
                Ok(()) => { log!("   AW88298 OK — speaker enabled"); true }
                Err(e) => { log!("   AW88298 FAILED: {} (no sound)", e); false }
            };
            if sound_ok && _i2s_tx_ready {
                hw::sound::set_volume(18);
                hw::sound::set_dma_buffer(dma_buf_ptr, dma_buf_len);
                hw::sound::boot_tone(&mut delay);
            }
        }

        // SD card (bitbang, before SPI claims GPIOs)
        let _bb_card_type = init_sd_card_m5(&mut i2c, &mut delay);

        // SPI display (ILI9342C)
        log!("   SPI + ILI9342C init...");
        let spi = Spi::new(
            peripherals.SPI2,
            SpiConfig::default()
                .with_frequency(Rate::from_mhz(40))
                .with_mode(SpiMode::_0),
        )
        .expect("SPI2 init failed — hardware fault")
        .with_sck(peripherals.GPIO36)
        .with_mosi(peripherals.GPIO37);

        let cs_pin = Output::new(peripherals.GPIO3, Level::High, OutputConfig::default());
        let dc_pin = Output::new(peripherals.GPIO35, Level::Low, OutputConfig::default());
        let reset_pin = Output::new(peripherals.GPIO14, Level::High, OutputConfig::default());

        let boot_display = match hw::display::BootDisplay::new(spi, cs_pin, dc_pin, reset_pin, &mut delay) {
            Ok(d) => { log!("   ILI9342C display initialized OK — 320x240 color"); d }
            Err(e) => {
                log!("Display init error: {}", e);
                continue_without_display(&mut delay);
            }
        };
        hw::pmu::set_brightness(&mut i2c, app::data::DEFAULT_BRIGHTNESS);

        // Camera (GC0308 + DVP)
        log!("   GC0308 Camera init...");
        let mut cam_status = match hw::camera::init_gc0308(&mut i2c, &mut delay) {
            Ok(()) => { log!("   GC0308 OK"); hw::camera::CameraStatus::SensorReady }
            Err(e) => { log!("   GC0308 FAILED: {}", e); hw::camera::CameraStatus::Error }
        };

        log!("   LCD_CAM DVP init...");
        let cam_config = CamConfig::default().with_frequency(Rate::from_mhz(20));
        hw::camera::enable_lcd_cam_clocks();

        let lcd_cam = LcdCam::new(peripherals.LCD_CAM);
        // QVGA Y-only: 320×240 = 76800 bytes
        let (rx_buffer, rx_descriptors, _, _) = esp_hal::dma_buffers!(76800, 0);
        let cam_dma_buf = esp_hal::dma::DmaRxBuf::new(rx_descriptors, rx_buffer)
            .expect("DMA buffer allocation failed");
        let cam_dma_buf_opt = Some(cam_dma_buf);

        hw::camera::ensure_lcd_clk_enabled();
        let cam_build = DvpCamera::new(lcd_cam.cam, peripherals.DMA_CH0, cam_config);
        let mut dvp_camera_opt: Option<DvpCamera<'_>> = None;

        match cam_build {
            Ok(cam) => {
                let cam = cam
                    .with_master_clock(peripherals.GPIO2)
                    .with_pixel_clock(peripherals.GPIO45)
                    .with_vsync(peripherals.GPIO46)
                    .with_h_enable(peripherals.GPIO38)
                    .with_data0(peripherals.GPIO39)
                    .with_data1(peripherals.GPIO40)
                    .with_data2(peripherals.GPIO41)
                    .with_data3(peripherals.GPIO42)
                    .with_data4(peripherals.GPIO15)
                    .with_data5(peripherals.GPIO16)
                    .with_data6(peripherals.GPIO48)
                    .with_data7(peripherals.GPIO47);

                // Re-init unconditionally.
                //
                // This was gated on verify_xclk_running() > 100, which sampled
                // GPIO2 for an XCLK that does not exist on this board. The
                // GC0308 module supplies its own 20 MHz clock and XCLK is not
                // routed to the SoC (esp-bsp: BSP_CAMERA_GPIO_XCLK =
                // GPIO_NUM_NC; M5Stack pinmap: "System Clock XCLK -1"), so the
                // sampler read 0 on every boot and which branch ran came down
                // to codegen luck rather than hardware state. The re-init is
                // idempotent, so running it always is both correct and stable.
                match hw::camera::reinit_gc0308(&mut i2c, &mut delay) {
                    Ok(()) => log!("   GC0308 re-init OK"),
                    Err(e) => log!("   GC0308 re-init FAILED: {}", e),
                }
                delay.delay_millis(500);

                hw::camera::setup_cam_gpio_routing();
                dvp_camera_opt = Some(cam);
            }
            Err(_) => {
                log!("   LCD_CAM DVP FAILED — config error");
                cam_status = hw::camera::CameraStatus::Error;
            }
        }
        log!();
        if cam_status == hw::camera::CameraStatus::SensorReady {
            hw::camera::configure_cam_vsync_eof();
        }

        (i2c, boot_display, dvp_camera_opt, cam_dma_buf_opt, cam_status, _bb_card_type)
    };

    // ─── Phase 3: Verify firmware integrity ──────────────────────
    app::signing::run_firmware_verify(&mut boot_display, &mut delay);

    // ─── Security: disable JTAG + USB data (both boards) ─────
    //
    // Also un-gated 2026-08-02. In a development build this only clears two
    // bits in USB_SERIAL_JTAG_CONF0; the USB Serial/JTAG peripheral itself is
    // killed only under `production`, so the serial monitor is unaffected here.
    hw::lockdown::post_boot_lockdown();

    // ─── Phase 5: Boot into main application ─────────────────────
    log!("Phase 5: Stateless mode — no PIN, no NVS");
    log!("─────────────────────────────────────────");

    let mut tracker = hw::touch::TouchTracker::new();

    #[cfg(not(feature = "skip-tests"))]
    app::boot_test::run_boot_tests();
    app::stack_probe::report("after boot tests");

    // Crypto KATs are invoked from inside boot_test::run_boot_tests, called
    // just above, so there is no call here. run_boot_tests is gated on
    // `skip-tests` only, not on `silent`, so the KATs run in every build
    // including production (P-09 closed); the guard above makes
    // skip-tests + silent a compile error. In production the log is stubbed,
    // so a failing KAT halts on a dark screen with no message.

    let (grid_zones, list_zones, page_up_zone, page_down_zone) = touch_zones();
    // AppData is ~13 KB after all the PSKT migration additions
    // (IncomingPartialSig[5]×8 = ~4 KB, pubkey_compressed on InputSig[5]×8
    // = ~1.3 KB, signed_qr_buf bumped 1→4 KB in Step 0). Keeping it on
    // the stack blew the main-thread 8 KB ProCpu stack during early boot
    // when rqrr / DMA / cam_tune all want scratch. Box it onto the heap
    // so main's frame only holds a pointer; downstream code reborrows
    // through `ad` unchanged.
    let mut ad_box = alloc::boxed::Box::new(AppData::new());
    // Publish the AppData address for the panic handler. It cannot take
    // &mut AppData: a panic may fire while AppData is already mutably
    // borrowed further up the stack, and forming a second &mut would be UB.
    AD_PTR.store(&*ad_box as *const AppData as usize, core::sync::atomic::Ordering::SeqCst);
    // Address of the chain_cache slot. Registered directly rather than via
    // offset_of!: the field address is fixed for the life of the Box, this
    // needs no per-assignment bookkeeping, and it avoids a macro that
    // requires Rust 1.77.
    AD_CC_SLOT.store(&ad_box.chain_cache as *const _ as usize, core::sync::atomic::Ordering::SeqCst);
    #[allow(unused_mut)]
    let mut ad: &mut AppData = &mut ad_box;

    // Override cam_tune defaults for OV2640 — proven QR decode settings
    #[cfg(feature = "waveshare")]
    if SENSOR_OV2640.load(core::sync::atomic::Ordering::Relaxed) {
        ad.cam_tune_vals = [0x20, 0x0C, 0x8B, 0x08, 0x70, 0x50];
    }

    // M5Stack runs signing pipeline test at boot.
    // NOT waveshare: k256 Schnorr signing needs ~16 KB of stack and the boot
    // frame does not have it. See the note inside run_signing_pipeline_test.
    #[cfg(feature = "m5stack")]
    #[cfg(not(feature = "skip-tests"))]
    run_signing_pipeline_test(ad);

    log!("   Touch ready — tap menu items to navigate");

    #[cfg(feature = "mirror")]
    log!("   [MIRROR] Live display mirror active");

    // ─── Main loop ───────────────────────────────────────────────
    const IDLE_DIM_TICKS: u32 = 15000;
    const IDLE_SLEEP_TICKS: u32 = 50000;
    // Wipe key material this long after the last user interaction.
    //
    // WALL CLOCK, not loop iterations. See IDLE_MARK_TICKS for why an
    // iteration count cannot express a duration in this loop.
    //
    // Expressed in raw 16 MHz SYSTIMER ticks. 240 s = 3,840,000,000 ticks,
    // which fits u32 (max 4,294,967,295).
    //
    // The hard ceiling is the counter wrap. `systimer_ticks` reads only the low
    // 32 bits of the 52-bit SYSTIMER, so it wraps at 4.29e9 / 16e6 = 268.4 s.
    // Do not raise this past that without reading the high word too.
    //
    // MARGIN, 2026-08-02: raised from 180 s to 240 s at the maintainer's
    // request. That cuts the slack from 88 s to 28 s. Still safe, because the
    // check runs on every main-loop pass and nothing blocks the loop for
    // anywhere near 28 s: the longest single operation is a PBKDF2 stretch at
    // about 9 s. If a future operation could block longer than that, widen the
    // counter rather than lowering this back.
    const IDLE_WIPE_S: u32 = 240;
    const IDLE_WIPE_TICKS_16M: u32 = IDLE_WIPE_S * 16_000_000;
    // M5Stack: camera-exit lockout. After leaving a camera screen, any
    // transition back into a camera state within this window is forced back
    // to the main menu. The serial log proved re-entry happens through a
    // NON-tap path (wake_debounce was active and it re-entered anyway), so
    // this gates the state itself, not the input.
    // Both counters live in `ad.touch_guard` since 1.0.7 (see `TouchGuard`
    // in app/data.rs): `debounce` starts at 200 to suppress phantom touches
    // at boot (a press on the blocking logo/verify screens, no touch reads
    // for ~5.5s, otherwise fires into the menu on the first loop read; the
    // coin sits over Scan QR), `exit_lockout` at 0. Moving them into
    // AppData is what lets a camera exit arm them where it happens.
    let mut dim_active: bool = false;
    // Wake-from-sleep needs N consecutive frames of "finger present" to fire.
    // Single-frame noise from ambient light / EMI on the CST816D would
    // otherwise wake the device. 2 frames ≈ 200ms at the sleep-poll rate
    // (100ms per iteration inside the asleep branch).
    #[cfg(feature = "waveshare")]
    let mut wake_confirm_count: u8 = 0;
    #[cfg(feature = "waveshare")]
    const WAKE_CONFIRM_REQUIRED: u8 = 2;

    loop {
        // ─── Mirror: send a few rows per iteration (non-blocking) ──
        #[cfg(feature = "mirror")]
        hw::screenshot::pump_rows();

        // ─── Touch polling (platform-specific API) ───────────────
        #[cfg(feature = "waveshare")]
        let (touch_state, action) = {
            let (ts, gesture) = hw::touch::read_touch_full(&mut i2c, &mut touch_configured);
            let act = tracker.update(ts, gesture);
            (ts, act)
        };
        #[cfg(feature = "m5stack")]
        let (touch_state, action) = {
            let ts = hw::touch::read_touch(&mut i2c);
            let act = tracker.update(ts);
            (ts, act)
        };

        // Ambient touch harvest, BOTH BOARDS. Every contact the UI reports,
        // anywhere in the interface, folds into the stage `fill()` mixes.
        //
        // This is M5Stack's only non-SoC entropy source: `cam_dma` is
        // Waveshare-only and that board has no IMU, so before this its
        // signature nonces rested on SYSTIMER, the eFuse MAC and the WDEV -
        // a counter, a constant and one register.
        //
        // Movement-gated inside `stage_touch`: measured, only 9% of polls
        // during continuous drawing were actual movement, and staging the
        // other 91% would inflate the count while adding nothing.
        if let hw::touch::TouchState::One(p) = touch_state {
            crypto::entropy::stage_touch(p.x, p.y);
        }

        // Touch entropy collection. Confined to its own screen: the canvas is
        // the collection surface, so nothing here fires during menu use and
        // the cadence measured is the one the feature would see.
        //
        // Stage zero settled the clock: a SYSTIMER latch+read costs ~165 ns
        // against a touch interval of 10-100 ms, five orders of magnitude of
        // headroom. What is measured here is the TOUCH CONTROLLER's cadence,
        // which is what decides whether timing carries credit at all.
        //
        // Points are painted incrementally rather than by a full redraw:
        // repainting per event would add tens of milliseconds to every sample
        // and the measured delta would be the redraw, not the finger.
        if matches!(ad.app.state, app::input::AppState::TouchEntropy) {
            if let hw::touch::TouchState::One(p) = touch_state {
                let before = crypto::entropy::touch_probe_count();
                crypto::entropy::touch_probe_record(p.x, p.y);
                let after = crypto::entropy::touch_probe_count();
                if after != before {
                    boot_display.draw_touch_entropy_point(
                        p.x, p.y, after, crypto::entropy::TOUCH_PROBE_MAX);
                    if after >= crypto::entropy::TOUCH_PROBE_MAX {
                        // Report and raw dump are MEASUREMENT ONLY. They need
                        // the stored stream, which a production build does not
                        // keep: events are folded into a running SHA-256 as
                        // they arrive, so the 16 KB of `.bss` the arrays used
                        // to cost exists only under `rng-probe`. The dump is
                        // the seed preimage besides.
                        #[cfg(feature = "rng-probe")]
                        {
                            crypto::entropy::touch_probe_report("canvas");
                            crypto::entropy::touch_probe_dump();
                        }

                        boot_display.draw_saving_screen("Generating seed...");
                        let wc = if ad.word_count == 24 { 24u8 } else { 12u8 };
                        let mut wizard = ui::setup_wizard::SetupWizard::new();
                        wizard.word_count = wc;
                        let mut ent = crypto::entropy::touch_extract_entropy_32();
                        wizard.generate_from_entropy(&ent);
                        for b in ent.iter_mut() {
                            unsafe { core::ptr::write_volatile(b, 0); }
                        }
                        // The capture is the seed preimage: wipe it, do not
                        // merely reset the index.
                        crypto::entropy::touch_probe_zeroize();
                        ad.mnemonic_indices = wizard.mnemonic;
                        ad.word_count = wc;
                        wizard.zeroize();
                        log!("   Touch seed generated ({} words)", wc);
                        ad.pp_input.reset();
                        ad.app.state = app::input::AppState::PassphraseEntry;
                        ad.needs_redraw = true;
                    }
                }
            }
        }

        ad.idle_ticks = ad.idle_ticks.saturating_add(1);

        let is_touch = !matches!(action, hw::touch::TouchAction::None);

        // ─── IMU entropy restaging (Waveshare) ───────────────────
        //
        // crypto::entropy::fill() has no I2C handle and its most important
        // caller, wallet::schnorr, has none anywhere in its call graph. This
        // is the only place in the crate that holds the handle and runs
        // continuously, so this is where MEMS noise enters the staging buffer
        // that fill() mixes.
        //
        // Idle only, so a ~3 ms collection never sits in front of a touch
        // event, and only once every IMU_RESTAGE_TICKS iterations. idle_ticks
        // resets to 0 on interaction, so this fires during quiet periods and
        // stops as soon as the user touches anything.
        #[cfg(feature = "waveshare")]
        if !is_touch && ad.idle_ticks > 0 && ad.idle_ticks % IMU_RESTAGE_TICKS == 0 {
            crypto::entropy::stage_imu(&mut i2c, &mut delay);
        }

        // Camera-exit lockout enforcement: during the window, force any
        // camera-state re-entry back to the menu and log it (this exposes
        // the non-tap path that has been re-arming the viewfinder).
        #[cfg(feature = "m5stack")]
        {
            if ad.touch_guard.exit_lockout > 0 {
                ad.touch_guard.exit_lockout -= 1;
                if ad.app.state.is_scan_camera() {
                    ad.app.go_main_menu();
                    ad.needs_redraw = true;
                }
            }
        }

        // Idle wipe. ABOVE the sleep block deliberately: that block ends in an
        // unconditional `continue`, so anything below it stops running once
        // display_asleep is set, and the whole point of this is to fire after
        // the device has gone to sleep.
        //
        // Without this, key material stays resident in PSRAM for the entire
        // session: seed_mgr slots, acct_key_raw, and the separately allocated
        // chain_cache holding the 65-byte account xprv plus a private key per
        // chain. A warm reset is not a substitute: SRAM and PSRAM retain
        // contents until firmware overwrites them.
        //
        // Fires once, because wipe_secrets clears seed_loaded and only user
        // action can set it again, which resets idle_ticks.
        if systimer_ticks().wrapping_sub(IDLE_MARK_TICKS.load(core::sync::atomic::Ordering::Relaxed))
            >= IDLE_WIPE_TICKS_16M && ad.seed_loaded
        {
            log!("   [SEC] Idle timeout: wiping seed material");
            ad.wipe_secrets();
            ad.app.go_main_menu();
        }

        // Sleep/wake
        if ad.display_asleep {
            // On Waveshare, require multiple consecutive touch samples
            // before waking — rejects single-frame ghost events from
            // ambient light / EMI. Reset counter on any clean sample.
            #[cfg(feature = "waveshare")]
            {
                let raw_touch = !matches!(touch_state, hw::touch::TouchState::NoTouch);
                if raw_touch || is_touch {
                    wake_confirm_count = wake_confirm_count.saturating_add(1);
                } else {
                    wake_confirm_count = 0;
                }
                if wake_confirm_count >= WAKE_CONFIRM_REQUIRED {
                    wake_confirm_count = 0;
                    if handle_wake(ad, &mut i2c, &mut delay, &mut tracker,
                                   touch_state, is_touch) {
                        continue;
                    }
                }
                delay.delay_millis(100);
                continue;
            }
            #[cfg(feature = "m5stack")]
            {
                if handle_wake(ad, &mut i2c, &mut delay, &mut tracker,
                               touch_state, is_touch) {
                    continue;
                }
                delay.delay_millis(100);
                continue;
            }
        }
        #[cfg(feature = "waveshare")]
        { wake_confirm_count = 0; }

        // Dim-first-touch suppression
        if is_touch {
            ad.idle_ticks = 0;
            IDLE_MARK_TICKS.store(systimer_ticks(), core::sync::atomic::Ordering::Relaxed);
            if dim_active {
                hw::pmu::set_brightness(&mut i2c, ad.brightness);
                dim_active = false;
                #[cfg(feature = "m5stack")]
                if !ad.app.state.is_scan_camera() {
                    hw::sound::click(&mut delay);
                }
                tracker = hw::touch::TouchTracker::new();
                ad.touch_guard.debounce = 100;
                continue;
            }
            #[cfg(feature = "m5stack")]
            hw::pmu::set_brightness(&mut i2c, ad.brightness);
        }

        // Idle dimming / sleep
        handle_idle(ad, &mut i2c, &mut dim_active, IDLE_DIM_TICKS, IDLE_SLEEP_TICKS);

        // Extended-bank idle pump: one BIP32 derivation (~110ms) per quiet
        // iteration while resting on the main menu — no camera contention
        // there, and any touch naturally pauses it for the iteration. The
        // full 200+200 bank completes in ~45s of cumulative idle, after
        // which the call is a no-op. Raises input matching and output
        // labeling to depth 200 as pure RAM lookups.
        {
            static mut PUMP_IDLE: u32 = 0;
            unsafe {
                if matches!(action, hw::touch::TouchAction::None)
                    && matches!(ad.app.state, app::input::AppState::MainMenu)
                    && !ad.display_asleep
                {
                    PUMP_IDLE = PUMP_IDLE.saturating_add(1);
                    // ~1-2s of consecutive quiet before any pump work.
                    // Hybrid throttle: while the display is bright, one
                    // ~110ms derivation every 64th tick (~300ms apart)
                    // keeps touch sampling responsive; once dimmed,
                    // full speed, since nobody is interacting. The key
                    // stretch itself runs at seed load now; the pump
                    // only fills banks (its prime branch remains as a
                    // safety net for paths that missed the load prime).
                    if PUMP_IDLE > 400 && (dim_active || PUMP_IDLE % 64 == 0) {
                        app::signing::pump_ext_pubkeys(ad);
                    }
                } else {
                    PUMP_IDLE = 0;
                }
            }
        }

        // ─── Silent duress wipe ──────────────────────────────────
        // Watches raw touch_state, NOT TouchAction::Tap, because Tap fires on
        // RELEASE: by then the finger is up and a hold cannot be measured.
        // Finger down in the logo corner on the main menu starts the timer
        // immediately; lifting or drifting before 4 s does nothing at all,
        // with no prompt shown either way.
        if ad.app.state == app::input::AppState::MainMenu && ad.touch_guard.debounce == 0 {
            if let hw::touch::TouchState::One(pt) = touch_state {
                if pt.x <= 48 && pt.y <= 48 {
                    try_duress_wipe(ad, &mut boot_display, &mut delay, &mut i2c);
                    ad.needs_redraw = true;
                    continue;
                }
            }
        }

        // ─── Touch dispatch ──────────────────────────────────────
        if ad.touch_guard.debounce > 0 {
            ad.touch_guard.debounce -= 1;
        } else if let hw::touch::TouchAction::Tap { x, y } = action {
            let is_back = x <= 48 && y <= 48;
            // Camera scan screens are silent: only the back button
            // clicks. All other taps there are ignored, so no sound.
            let is_scan_cam = ad.app.state.is_scan_camera();
            if !is_scan_cam || is_back {
                hw::sound::click(&mut delay);
            }
            // M5Stack: a back tap on a camera screen exits to a menu whose
            // "Scan QR" card sits under this same position — suppress the
            // lift-bounce so it can't immediately re-enter the scan screen.
            // (Applies from the NEXT iteration; this tap still dispatches.)
            // M5Stack: a back tap on a camera screen is handled COMPLETELY
            // here and consumed. Previously it fell through to the zone
            // handlers, which routed the corner coordinates into another
            // screen first (log: state=99 painted between the tap and the
            // menu) — the "different menus popping". Navigate and stop.
            #[cfg(feature = "m5stack")]
            if is_scan_cam && is_back {
                ad.touch_guard.arm_camera_exit();
                if ad.ms_creating.n > 0 && !ad.ms_creating.active {
                    let mut ki: u8 = 0;
                    for i in 0..ad.ms_creating.n {
                        if ad.ms_creating.slot_empty(i as usize) { ki = i; break; }
                    }
                    ad.app.state = app::input::AppState::MultisigAddKey { key_idx: ki };
                } else if ad.app.state == app::input::AppState::DecryptSecretScan {
                    ad.app.state = app::input::AppState::SingleSigMenu;
                } else {
                    ad.app.go_main_menu();
                }
                ad.needs_redraw = true;
                continue;
            }
            // M5Stack: the main menu's Scan QR card sits under the camera's
            // back-button position, so a corner tap on the menu re-opened the
            // camera — the entire back/viewfinder "ping-pong" (log-proven: the
            // lockout blocked retaps at 44/60/97/131 left; re-entries were
            // retaps landing after the window lapsed). The main menu has no
            // back action, so a corner tap there is a deliberate no-op; the
            // card's body extends well beyond the corner and still works.
            #[cfg(feature = "m5stack")]
            if is_back && ad.app.state == app::input::AppState::MainMenu {
                continue;
            }
            if is_scan_cam && !is_back {
                // Camera scan screens: taps anywhere except the back
                // button must do NOTHING. Never route them to handlers —
                // zone hits there mutate state under the running camera.
                continue;
            }
            let is_home = x >= 268 && y <= 52;

            // Home button — go to main menu
            // Excluded on full-screen QR states (tap = advance/popup, no navigation)
            // and ScanQR (camera screen exits via back button only).
            #[cfg(feature = "waveshare")]
            let home_allowed = is_home && !matches!(ad.app.state,
                app::input::AppState::ScanQR
                | app::input::AppState::ShowQR
                | app::input::AppState::ShowAddressQR
                | app::input::AppState::MultisigShowAddressQR
                | app::input::AppState::ExportKpub
                | app::input::AppState::ExportSeedQR
                | app::input::AppState::ExportCompactSeedQR
            );
            #[cfg(feature = "m5stack")]
            let home_allowed = is_home && !matches!(ad.app.state,
                app::input::AppState::ScanQR
                | app::input::AppState::ShowQR
                | app::input::AppState::ShowAddressQR
                | app::input::AppState::MultisigShowAddressQR
                | app::input::AppState::ExportKpub
                | app::input::AppState::ExportSeedQR
                | app::input::AppState::ExportCompactSeedQR
            );

            if home_allowed {
                use crate::app::input::AppState;
                match ad.app.state {
                    AppState::MainMenu => {}
                    _ => {
                        ad.app.go_main_menu();
                        ad.needs_redraw = true;
                        continue;
                    }
                }
            }

            let result = match ad.app.state.handler_group() {
                HandlerGroup::Menu => handlers::menu::handle_menu_touch(
                    ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &mut dvp_camera_opt, &mut cam_dma_buf_opt,
                    &grid_zones, &list_zones, &page_up_zone, &page_down_zone,
                    x, y, is_back,
                ),
                HandlerGroup::Stego => handlers::stego::handle_stego_touch(
                    ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                    x, y, is_back,
                ),
                HandlerGroup::Sd => handlers::sd::handle_sd_touch(
                    ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                    x, y, is_back,
                ),
                HandlerGroup::Seed => handlers::seed::handle_seed_touch(
                    ad, &mut boot_display, &mut delay, &mut i2c,
                    x, y, is_back,
                ),
                HandlerGroup::Export => handlers::export::handle_export_touch(
                    ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                    x, y, is_back,
                ),
                HandlerGroup::Settings => handlers::settings::handle_settings_touch(
                    ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                    x, y, is_back,
                ),
                HandlerGroup::Tx => handlers::tx::handle_tx_touch(
                    ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &list_zones,
                    x, y, is_back,
                ),
                HandlerGroup::None => None,
            };
            if let Some(r) = result {
                ad.needs_redraw = r;
            }

            // Waveshare: leaving a camera screen by the back button drops the
            // finger straight into the duress-wipe corner.
            //
            // Both are the same 48x48 region at the top left. The duress check
            // above watches RAW `touch_state`, not `Tap`, because a hold has
            // to be measured while the finger is down. So on the iteration
            // after this handler sets `MainMenu`, the finger is still there,
            // the state now matches, and that block fires and `continue`s
            // PAST the redraw at the bottom of the loop. The viewfinder's last
            // frame stays on screen while the menu is live underneath, which
            // reads as a frozen image that a second tap clears.
            //
            // M5Stack never showed it: its camera back tap sets
            // `wake_debounce = 150`, and the duress check requires
            // `wake_debounce == 0`. That was written for the camera/menu
            // ping-pong and covered this by accident, which is why the defect
            // looked board-specific without being board-related.
            //
            // Same primitive and the same value M5Stack already proves: long
            // enough to outlast a lingering contact after release, far shorter
            // than a deliberate second tap. Note this suppresses only the tap
            // dispatch and the duress check; it does NOT skip the redraw,
            // which is the whole point.
            #[cfg(feature = "waveshare")]
            if is_scan_cam && is_back && !ad.app.state.is_scan_camera() {
                ad.touch_guard.arm_camera_exit();
            }

            // Waveshare CST816D: cooldown after tap to suppress ghost double-taps
            // from residual capacitance / ambient light EMI. The controller often
            // reports a spurious Contact→LiftUp sequence within ~100ms of a real tap.
            // Skip during cam-tune — user is actively adjusting, latency matters.
            #[cfg(feature = "waveshare")]
            if !ad.cam_tune_active {
                delay.delay_millis(150);
                // Drain any queued touch event so tracker starts clean
                let (ts, gest) = hw::touch::read_touch_with_gesture(&mut i2c);
                tracker.update(ts, gest);
            }
        }
        // ─── Waveshare: swipe gestures + drag ────────────────────
        #[cfg(feature = "waveshare")]
        {
            if action == hw::touch::TouchAction::SwipeLeft && !ad.cam_tune_active {
                hw::sound::click(&mut delay);
                if matches!(ad.app.state, app::input::AppState::MultisigPickSeed { .. }) {
                    let loaded_count = ad.seed_mgr.slots.iter().filter(|s| !s.is_empty()).count() as u8;
                    if ad.ms_scroll + 3 < loaded_count { ad.ms_scroll += 3; ad.needs_redraw = true; }
                } else {
                    let fake_x = 300u16;
                    let fake_y = 138u16;
                    let result = match ad.app.state.handler_group() {
                        HandlerGroup::Menu => handlers::menu::handle_menu_touch(
                            ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &mut dvp_camera_opt, &mut cam_dma_buf_opt,
                            &grid_zones, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Stego => handlers::stego::handle_stego_touch(
                            ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Export => handlers::export::handle_export_touch(
                            ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Settings => handlers::settings::handle_settings_touch(
                            ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        _ => None,
                    };
                    if let Some(r) = result { ad.needs_redraw = r; }
                }
            } else if action == hw::touch::TouchAction::SwipeRight && !ad.cam_tune_active {
                hw::sound::click(&mut delay);
                if matches!(ad.app.state, app::input::AppState::MultisigPickSeed { .. }) {
                    if ad.ms_scroll >= 3 { ad.ms_scroll -= 3; ad.needs_redraw = true; }
                } else {
                    let fake_x = 20u16;
                    let fake_y = 138u16;
                    let result = match ad.app.state.handler_group() {
                        HandlerGroup::Menu => handlers::menu::handle_menu_touch(
                            ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &mut dvp_camera_opt, &mut cam_dma_buf_opt,
                            &grid_zones, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Stego => handlers::stego::handle_stego_touch(
                            ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Export => handlers::export::handle_export_touch(
                            ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Settings => handlers::settings::handle_settings_touch(
                            ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        _ => None,
                    };
                    if let Some(r) = result { ad.needs_redraw = r; }
                }
            } else if let hw::touch::TouchAction::Drag { x, y, .. } = action {
                // Drag on brightness bar (DisplaySettings)
                if ad.app.state == app::input::AppState::DisplaySettings
                    && (70..=250).contains(&x) && (60..=130).contains(&y)
                {
                    let pct = ((x as u32 - 70) * 255 / 180).min(255) as u8;
                    if pct != ad.brightness {
                        ad.brightness = pct;
                        hw::pmu::set_brightness(&mut i2c, ad.brightness);
                        boot_display.update_brightness_bar(ad.brightness);
                    }
                }
                // Drag on cam-tune slider
                if ad.app.state == app::input::AppState::ScanQR && ad.cam_tune_active && y >= 198 {
                    let p = ad.cam_tune_param as usize;
                    if (52..=268).contains(&x) {
                        let clamped = (x as i32 - 56).max(0).min(208) as u32;
                        ad.cam_tune_vals[p] = ((clamped * 255) / 208) as u8;
                        ad.cam_tune_dirty = true;
                        boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                    }
                }
            }
        }

        // ─── Signing, redraw, camera ─────────────────────────────
        app::signing::handle_signing_step(ad, &mut boot_display, &mut delay);

        // COVB: if camera detected covenant backup, save to SD
        if ad.covb_len > 0
            && !matches!(ad.app.state, app::input::AppState::CovBackupName)
        {
            let n = ad.covb_len;
            // Use filename from sd_file_list[0] (set by keyboard OK), or auto-generate
            let fname = if ad.sd_file_list[0][0] != b' ' && ad.sd_file_list[0][0] != 0 {
                ad.sd_file_list[0]
            } else {
                let hx = b"0123456789ABCDEF";
                let mut f = *b"COV00000COV";
                for i in 0..5usize {
                    if i + 4 < n { f[3 + i] = hx[(ad.signed_qr_buf[4 + i] >> 4) as usize]; }
                }
                f
            };
            boot_display.draw_saving_screen("Saving covenant...");
            match handlers::sd::write_file_to_sd(&mut i2c, &mut delay, &fname, &ad.signed_qr_buf[..n]) {
                Ok(()) => {
                    log!("   COVB saved ({} bytes)", n);
                    boot_display.draw_success_screen("Covenant saved to SD");
                }
                Err(e) => {
                    log!("   COVB save failed: {}", e);
                    boot_display.draw_rejected_screen("SD write failed");
                }
            }
            ad.covb_len = 0;
            ad.sd_file_list[0] = [b' '; 11]; // clear filename
            delay.delay_millis(1500);
            ad.needs_redraw = true;
        }

        // Third lockout enforcement, pre-redraw: the log proved the state
        // flips to a camera screen between the loop-top check and here (armed
        // 300, top check passed, then the camera screen painted with no gate
        // hit). Reverting before the paint closes the last window: during
        // lockout the menu is repainted, never the viewfinder.
        #[cfg(feature = "m5stack")]
        if ad.touch_guard.exit_lockout > 0 && ad.app.state.is_scan_camera() {
            ad.app.go_main_menu();
            ad.needs_redraw = true;
        }
        // Apply this screen's keyboard length cap. Single assignment,
        // board-independent, so a new keyboard screen needs one match arm in
        // AppState::keyboard_max_len() rather than an edit at every state
        // transition that opens it.
        //
        // Placed here, AFTER the handlers, not before them. The handlers are
        // what change ad.app.state, so setting it earlier meant the frame that
        // enters a keyboard screen drew the header with the PREVIOUS screen's
        // cap. Since the header is only painted on a full redraw, it then
        // never corrected: PASSPHRASE showed 0/128 instead of 0/64.
        // SdKsptEncryptPass is the one screen whose cap is not a property of
        // the state alone: it serves both save and load, and the direction
        // lives in kspt_filename. Capping it at 64 unconditionally would make
        // a file written with a longer password unopenable; leaving it at 128
        // unconditionally would let a new one be written.
        let cap = match ad.app.state {
            crate::app::input::AppState::SdKsptEncryptPass => {
                if ad.kspt_is_saving() { 64 } else { 128 }
            }
            _ => ad.app.state.keyboard_max_len(),
        };
        ad.pp_input.max_len = cap;

        if ad.needs_redraw {
            ad.idle_ticks = 0;
            IDLE_MARK_TICKS.store(systimer_ticks(), core::sync::atomic::Ordering::Relaxed);
            ad.needs_redraw = false;
            // Reset sub-menu scroll positions on MainMenu
            if ad.app.state == app::input::AppState::MainMenu {
                ad.tools_menu.scroll = 0;
                ad.export_menu.scroll = 0;
                ad.qr_export_menu.scroll = 0;
                ad.settings_menu.scroll = 0;
                #[cfg(feature = "waveshare")]
                { ad.ms_scroll = 0; }
            }
            ui::redraw::redraw_screen(ad, &mut boot_display, &mut i2c, &_bb_card_type);
            // Mirror mode: request non-blocking frame dump
            #[cfg(feature = "mirror")]
            hw::screenshot::request_frame();
            // Waveshare: read touch after redraw to feed tracker
            #[cfg(feature = "waveshare")]
            {
                let (ts, gest) = hw::touch::read_touch_with_gesture(&mut i2c);
                tracker.update(ts, gest);
            }
        }

        // The stego mode screen used to be auto-skipped, because there was
        // only ever one carrier. There are two now (Descriptor and Picture),
        // so the screen is a real choice and the user makes it.
        ad.stego_auto_scan = false;

        // ─── Camera loop ─────────────────────────────────────────
        // Active on ScanQR (normal decode).
        // On Waveshare, also on CameraSettings (cam-tune only, no decode).
        // Second lockout enforcement, at the camera gate: the immediate
        // re-entries slipped between the loop-top check and this point (state
        // flipped mid-iteration), so the camera restarted before the next
        // iteration's check could catch it. Enforcing here is airtight: no
        // path can start the camera during the lockout window, wherever in
        // the iteration it flipped the state.
        #[cfg(feature = "m5stack")]
        if ad.touch_guard.exit_lockout > 0 && ad.app.state.is_scan_camera() {
            ad.app.go_main_menu();
            ad.needs_redraw = true;
        }

        let camera_active = ad.app.state.is_camera();

        // M5Stack: the camera is HARD-GATED during the post-back lockout —
        // the re-entry travels under a state outside the three-state guard
        // lists (log-proven: pre-redraw gate works but never fires for the
        // immediate re-entries), so guarding state names is a losing game.
        // Gating the call itself is state-independent: during lockout the
        // viewfinder cannot restart, period.
        #[cfg(feature = "m5stack")]
        let camera_allowed = camera_active && ad.touch_guard.exit_lockout == 0;
        #[cfg(feature = "waveshare")]
        let camera_allowed = camera_active;
        if camera_allowed
            && (cam_status == hw::camera::CameraStatus::SensorReady
                || cam_status == hw::camera::CameraStatus::Streaming)
        {
            // Waveshare: PWDN control + cam-tune
            #[cfg(feature = "waveshare")]
            {
                unsafe { core::ptr::write_volatile(0x6000_400Cu32 as *mut u32, 1u32 << 17); }
                if ad.cam_tune_dirty {
                    ad.cam_tune_dirty = false;
                    if SENSOR_OV2640.load(core::sync::atomic::Ordering::Relaxed) {
                        cam_tune_apply_ov2640(&mut cam_i2c, &ad.cam_tune_vals);
                    } else {
                        cam_tune_apply_all(&mut cam_i2c, &ad.cam_tune_vals);
                    }
                }
            }

            handlers::camera_loop::run_camera_cycle(
                ad, &mut boot_display, &mut delay, &mut i2c,
                &mut dvp_camera_opt, &mut cam_status,
                &mut cam_dma_buf_opt, &mut tracker,
            );
            // Waveshare: process taps captured during DMA wait
            #[cfg(feature = "waveshare")]
            {
                if ad.cam_tap_ready {
                    ad.cam_tap_ready = false;
                    let x = ad.cam_tap_x;
                    let y = ad.cam_tap_y;
                    hw::sound::click(&mut delay);
                    let is_back = x <= 48 && y <= 48;
                    // In CameraSettings the camera loop is up but the screen is
                    // a settings screen — route to the settings handler so slider
                    // drags, +/- buttons, and 6 param buttons actually work.
                    // In ScanQR we keep routing to tx.
                    let result = if ad.app.state
                        == app::input::AppState::CameraSettings
                    {
                        handlers::settings::handle_settings_touch(
                            ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones,
                            &page_up_zone, &page_down_zone,
                            x, y, is_back,
                        )
                    } else {
                        handlers::tx::handle_tx_touch(
                            ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones,
                            x, y, is_back,
                        )
                    };
                    if let Some(r) = result { ad.needs_redraw = r; }
                    tracker = hw::touch::TouchTracker::new();
                    // The handlers (tx.rs, settings.rs) set the state directly
                    // on a back tap; this is the exit point for that path, so
                    // the guard is armed here rather than inside them.
                    if !ad.app.state.is_camera() {
                        ad.touch_guard.arm_camera_exit();
                    }
                }
            }

            // Fallback, both boards. Every exit from the camera family is
            // supposed to arm the touch guard where it happens
            // (`AppData::leave_camera` inside `run_camera_cycle`, the
            // dispatch site above, the back-tap sites at the loop top). Why
            // it matters: the main menu's "Scan QR" card sits under the back
            // button, so a lingering back-tap finger (still down, a lift
            // bounce, an immediate retap) re-enters the scan screen, and on
            // Waveshare the duress check `continue`s past the redraw while
            // the CST816D keeps reporting the contact, leaving the menu live
            // under a frozen viewfinder. Until 1.0.7 this block, written once
            // per board with lists that did not agree, was the ONLY place
            // that armed the guard for exits inside the cycle, and the
            // instant-back paths were the exits it missed. Now it arms only
            // when nothing else did, and says so on the serial log, so a new
            // exit path that forgets is loud rather than a frozen screen.
            if !ad.app.state.is_camera() && ad.touch_guard.debounce == 0 {
                log!("   [touch] camera exit to {:?} without leave_camera: arming the guard late",
                    ad.app.state);
                ad.touch_guard.arm_camera_exit();
            }
        }
        // Waveshare: camera PWDN management when not scanning
        #[cfg(feature = "waveshare")]
        {
            if !camera_active && ad.idle_ticks > 150 {
                unsafe { core::ptr::write_volatile(0x6000_4008u32 as *mut u32, 1u32 << 17); }
            }
        }

        app::signing::cycle_signed_qr(ad, &mut boot_display, &mut delay, &mut i2c);
        handlers::export::cycle_kpub_qr(ad, &mut boot_display);
        delay.delay_millis(1);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  PHASE 2 INIT HELPERS
// ═══════════════════════════════════════════════════════════════════════

/// Waveshare: no PMU — power rails always on
#[cfg(feature = "waveshare")]
fn init_pmu_ws(_i2c: &mut I2c<'_, esp_hal::Blocking>, _delay: &mut Delay) {
    log!("   No PMU on this board — power rails always on");
}

/// Waveshare: SD pre-init (power-up clocks before display claims GPIOs)
#[cfg(feature = "waveshare")]
fn init_sd_card_ws(delay: &mut Delay) -> Option<hw::sdcard::SdCardType> {
    log!("   SD pre-init: power-up clocks...");
    hw::sdcard::sd_pre_init();
    delay.delay_millis(10);
    hw::sdcard::sd_power_up_clocks();
    delay.delay_millis(10);
    log!("   SD power-up clocks done");
    None
}

/// M5Stack: AXP2101 PMU + AW9523B IO expander
#[cfg(feature = "m5stack")]
fn init_pmu_m5(i2c: &mut I2c<'_, esp_hal::Blocking>, delay: &mut Delay) {
    log!("   AXP2101 PMU init...");
    match hw::pmu::init_axp2101(i2c, delay) {
        Ok(()) => log!("   AXP2101 OK — DLDO1 enabled (3.3V backlight)"),
        Err(e) => {
            log!("   AXP2101 FAILED: {}", e);
            log!("   Display may not work without backlight power!");
        }
    }
    log!("   AW9523B IO Expander init...");
    match hw::pmu::init_aw9523b(i2c, delay) {
        Ok(()) => log!("   AW9523B OK — LCD and touch reset deasserted"),
        Err(e) => {
            log!("   AW9523B FAILED: {}", e);
            log!("   Display will not initialize without reset release!");
        }
    }
}

/// M5Stack: SD card via bitbang SPI (before hardware SPI claims GPIO36/37)
#[cfg(feature = "m5stack")]
fn init_sd_card_m5(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    delay: &mut Delay,
) -> Option<hw::sdcard::SdCardType> {
    log!("   Pre-SPI SD bitbang test...");
    {
        use hw::pmu::{AXP2101_ADDR, AXP_REG_LDO_EN1};
        const ALDO4_BIT: u8 = 0x08;
        let mut buf = [0u8; 1];
        let _ = i2c.write_read(AXP2101_ADDR, &[AXP_REG_LDO_EN1], &mut buf);
        let ldo_en = buf[0];
        let _ = i2c.write(AXP2101_ADDR, &[AXP_REG_LDO_EN1, ldo_en & !ALDO4_BIT]);
        delay.delay_millis(100);
        let _ = i2c.write(AXP2101_ADDR, &[AXP_REG_LDO_EN1, ldo_en | ALDO4_BIT]);
        delay.delay_millis(250);
    }
    match hw::sdcard::bitbang_init(delay) {
        Ok(ct) => {
            log!("   SD card bitbang init OK: {:?}", ct);
            let mut sector0 = [0u8; 512];
            match hw::sdcard::bb_read_block(ct, 0, &mut sector0) {
                Ok(()) => log!("   MBR: {:02x}{:02x}{:02x}{:02x}..sig={:02x}{:02x} OK",
                    sector0[0], sector0[1], sector0[2], sector0[3],
                    sector0[510], sector0[511]),
                Err(e) => log!("   MBR read failed: {}", e),
            }
            Some(ct)
        }
        Err(e) => {
            log!("   SD card bitbang: {} (continuing without SD)", e);
            None
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  MAIN LOOP HELPERS
// ═══════════════════════════════════════════════════════════════════════

/// Define touch zones for UI navigation.
fn touch_zones() -> (
    [hw::touch::TouchZone; 4], [hw::touch::TouchZone; 4],
    hw::touch::TouchZone, hw::touch::TouchZone,
) {
    (
        // Home grid (2x2)
        [
            hw::touch::TouchZone::new(10,  50,  148, 85),
            hw::touch::TouchZone::new(162, 50,  148, 85),
            hw::touch::TouchZone::new(10,  145, 148, 85),
            hw::touch::TouchZone::new(162, 145, 148, 85),
        ],
        // Sub-menu list (4 items)
        [
            hw::touch::TouchZone::new(40, 44,  240, 46),
            hw::touch::TouchZone::new(40, 90,  240, 46),
            hw::touch::TouchZone::new(40, 136, 240, 46),
            hw::touch::TouchZone::new(40, 182, 240, 46),
        ],
        // Page navigation strips
        hw::touch::TouchZone::new(0,   42, 40, 192),
        hw::touch::TouchZone::new(280, 42, 40, 192),
    )
}

/// M5Stack: signing pipeline self-test at boot
///
/// `#[inline(never)]` is load-bearing. Inlined into `main`, this function's
/// locals become permanent slots in `main`'s frame, which never returns and
/// which no wipe path reaches: `wipe_below_sp` clears only up to
/// `wipe_secrets`'s frame, below `main`'s. The sentinel scan found the account
/// private key derived here sitting at 0x3FCD8D28, above the wipe ceiling,
/// surviving boot cleanup and every duress wipe.
///
/// That instance is harmless, since the mnemonic below is a plaintext constant
/// and its key is public. The mechanism is not: whether a local holding key
/// material lands in a transient frame or a permanent one is otherwise the
/// optimiser's choice. Keeping this out of line puts it below the ceiling where
/// a wipe can reach it, and makes a clean sentinel scan the expected baseline
/// rather than a known exception.
#[cfg(feature = "m5stack")]
#[inline(never)]
fn run_signing_pipeline_test(ad: &mut AppData) {
    let test_words = ["girl", "mad", "pet", "galaxy", "egg", "matter",
                      "matrix", "prison", "refuse", "sense", "ordinary", "nose"];
    for (i, word) in test_words.iter().enumerate() {
        ad.mnemonic_indices[i] = wallet::bip39::word_to_index(word).unwrap_or(0);
    }
    ad.word_count = 12;
    ad.seed_mgr.store(&ad.mnemonic_indices, 12, b"", 0);
    ad.seed_loaded = true;

    // Signing pipeline test — M5Stack only.
    // On waveshare, k256 Schnorr signing overflows the default stack (~16KB needed).
    // The signing itself works fine at runtime (called from handler context with larger stack).
    #[cfg(feature = "m5stack")]
    {
        let ok = app::boot_test::test_signing_pipeline(ad);
        log!("   Signing pipeline test: {}", if ok { "OK" } else { "FAIL" });
    }
    #[cfg(feature = "waveshare")]
    log!("   Signing pipeline test: skipped (waveshare stack limit)");

    // Stage zero for touch-entropy timing credit: measure the cost of a
    // back-to-back SYSTIMER latch+read. The counter resolves at 62.5 ns/tick
    // and `delay_us_systimer` already depends on that, so the open question is
    // the READ cost: if it exceeds the interval being measured, touch deltas
    // come back as multiples of it and look like I2C polling quantization.
    // Runs on both boards, no touch involved, ~256 reads.
    #[cfg(feature = "rng-probe")]
    crypto::entropy::probe_systimer_read_cost();

    // Before the cleanup below, so the sentinel is still where the test left it.
    // Expect hits here: without them the post-wipe scan proves nothing.
    #[cfg(feature = "sentinel-scan")]
    app::stack_probe::scan_sentinel("after signing test");
    // Same point, needle = the BIP39 seed rather than the account key derived
    // from it. Hits here are the control: without them the later scans prove
    // nothing, because a scan that finds nothing everywhere is indistinguishable
    // from a scanner that cannot find anything at all.
    #[cfg(feature = "sentinel-scan")]
    app::stack_probe::scan_seed_needle("after signing test");

    ad.seed_mgr.delete(0);
    ad.seed_loaded = false;
    ad.word_count = 0;
    ad.mnemonic_indices = [0; 24];
    ad.pubkeys_cached = false;

    // After the slot delete and the index clear. Any hit still here is stack
    // residue: the frames that held it have returned, and returning does not
    // erase.
    #[cfg(feature = "sentinel-scan")]
    app::stack_probe::scan_sentinel("after slot delete");
    #[cfg(feature = "sentinel-scan")]
    app::stack_probe::scan_seed_needle("after slot delete");
}

/// Handle wake-from-sleep on touch. Returns true if main loop should `continue`.
fn handle_wake(
    ad: &mut AppData,
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    delay: &mut Delay,
    tracker: &mut hw::touch::TouchTracker,
    touch_state: hw::touch::TouchState,
    is_touch: bool,
) -> bool {
    let raw_touch = !matches!(touch_state, hw::touch::TouchState::NoTouch);
    if !raw_touch && !is_touch { return false; }

    #[cfg(feature = "m5stack")]
    {
        hw::sound::click(delay);
        delay.delay_millis(50);
    }

    hw::pmu::set_brightness(i2c, ad.brightness);

    #[cfg(feature = "m5stack")]
    {
        delay.delay_millis(50);
        hw::pmu::set_brightness(i2c, ad.brightness);
    }

    ad.display_asleep = false;
    ad.needs_redraw = true;
    ad.idle_ticks = 0;
    IDLE_MARK_TICKS.store(systimer_ticks(), core::sync::atomic::Ordering::Relaxed);

    // Wait for finger lift (3 consecutive NoTouch reads)
    let mut no_touch_count: u8 = 0;
    for _ in 0..80 {
        delay.delay_millis(50);
        if matches!(hw::touch::read_touch(i2c), hw::touch::TouchState::NoTouch) {
            no_touch_count += 1;
            if no_touch_count >= 3 { break; }
        } else {
            no_touch_count = 0;
        }
    }
    #[cfg(feature = "waveshare")]
    delay.delay_millis(300);
    #[cfg(feature = "m5stack")]
    delay.delay_millis(500);

    *tracker = hw::touch::TouchTracker::new();
    let _ = hw::touch::read_touch(i2c);
    let _ = hw::touch::read_touch(i2c);
    ad.touch_guard.debounce = 200;
    true
}

/// Handle idle dimming and sleep transitions.
fn handle_idle(
    ad: &mut AppData,
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    dim_active: &mut bool,
    dim_ticks: u32,
    sleep_ticks: u32,
) {
    if ad.idle_ticks == dim_ticks && !ad.display_asleep {
        hw::pmu::set_brightness(i2c, 20);
        *dim_active = true;
    }
    if ad.idle_ticks >= sleep_ticks && !ad.display_asleep {
        #[cfg(feature = "waveshare")]
        hw::pmu::set_brightness(i2c, 0);
        #[cfg(feature = "m5stack")]
        hw::pmu::set_brightness(i2c, 1);
        ad.display_asleep = true;
    }

    // NOTE: the idle wipe is NOT here. This function is called from below the
    // `if ad.display_asleep { ... continue; }` block in the main loop, so it
    // stops being reached the moment the display sleeps, which is exactly when
    // the wipe needs to fire. The check now lives above that block.

}

// ═══════════════════════════════════════════════════════════════════════
//  ERROR HANDLERS
// ═══════════════════════════════════════════════════════════════════════

/// Fatal halt — never returns.
/// Duress wipe action, deliberately out-of-line.
///
/// `#[inline(never)]` is load-bearing, not decoration. Rust sizes a stack frame
/// as the maximum across everything in it, so inlining this into `main` grows
/// main's frame for the entire program, including the iteration that calls
/// `rqrr_decode_inplace`. On M5Stack that decode runs on ProCpu's 8 KB stack
/// (there is no core-1 rqrr worker, `main.rs:219` is waveshare-only), and it
/// was already close enough to the limit that `rqrr_decode_inplace` carries its
/// own `#[inline(never)]`. Having this body inline tipped it: V11 QR decodes
/// that worked began tripping the stack guard.
///
/// The drawing and sound calls are the expensive part; font rendering and
/// framebuffer work carry large frames.
#[inline(never)]
fn try_duress_wipe(
    ad: &mut AppData,
    boot_display: &mut hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
    if handlers::menu::wipe_hold_confirm(boot_display, delay, i2c) {
        ad.wipe_secrets();
        ad.app.go_main_menu();
        boot_display.draw_success_screen("Wiped");
        hw::sound::success(delay);
        delay.delay_millis(1500);
        log!("   [SEC] Duress wipe: key material cleared");
    }
}

/// Raw SYSTIMER low word, 16 MHz ticks. NOT microseconds.
///
/// Deliberately undivided. An earlier version returned `ticks / 16` and the
/// callers did `wrapping_sub` on that, which is WRONG: the raw counter wraps
/// at 2^32, but a divided value only ever reaches 2^32/16 = 268,435,455, so
/// at the hardware wrap it steps from 268,435,455 to 0 and `wrapping_sub`
/// yields ~4.0e9 instead of a small delta. That fires a spurious idle wipe
/// every ~268 s.
///
/// Subtract raw, then divide. Intervals up to 268 s measure correctly.
fn systimer_ticks() -> u32 {
    // `let` binding rather than `unsafe { .. } / 16`: an unsafe block in tail
    // position parses as a statement, so a trailing operator has no left
    // operand.
    unsafe {
        core::ptr::write_volatile(0x6002_3004u32 as *mut u32, 1 << 30);
        for _ in 0..20u32 { core::hint::spin_loop(); }
        core::ptr::read_volatile(0x6002_3044u32 as *const u32)
    }
}

/// `systimer_ticks()` at the last user interaction. Stamped everywhere
/// `idle_ticks` is reset.
///
/// The idle wipe cannot use `idle_ticks`, because a tick is a loop iteration
/// and its period varies by two orders of magnitude:
///
/// | phase                | per tick | why                                  |
/// |----------------------|----------|--------------------------------------|
/// | awake, undimmed      | ~1.2 ms  | measured: 1000 ticks in 1.204 s      |
/// | dimmed, pump running | ~110 ms  | pump_ext_pubkeys drops its 1-in-64   |
/// |                      |          | throttle once dim_active is set      |
/// | asleep               | ~100 ms  | delay_millis(100) in the sleep block |
///
/// So a threshold in ticks means a different wall-clock time depending on
/// what else the loop happens to be doing. Three attempts at a tick-based
/// threshold each failed for that reason. This is wall-clock instead.
static IDLE_MARK_TICKS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Address of the heap-allocated `AppData`, published at boot for the panic
/// handler. Zero until registered.
static AD_PTR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Address of the `chain_cache` field inside that `AppData`. Zero until
/// registered.
static AD_CC_SLOT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Zeroize key material from a panic context, through raw pointers only.
///
/// ORDER MATTERS, same reason as `AppData::wipe_secrets`: `chain_cache` is a
/// separate PSRAM allocation holding the 65-byte account xprv plus a private
/// key per chain, and `AppData` stores only a pointer to it. Wiping the
/// `AppData` block first would destroy the pointer and strand the keys.
///
/// `Option<Box<ChainCache>>` is niche-optimised to a nullable pointer, so the
/// slot can be read directly as `*mut u8`.
///
/// SAFETY: called only from the panic handler, which never returns. No
/// reference to `AppData` is formed, so this is sound even if the panic fired
/// while `AppData` was mutably borrowed.
unsafe fn panic_wipe_appdata() {
    use core::sync::atomic::Ordering;
    let base = AD_PTR.load(Ordering::SeqCst);
    if base == 0 { return; }

    let slot = AD_CC_SLOT.load(Ordering::SeqCst);
    let cc = if slot == 0 { core::ptr::null_mut() }
             else { core::ptr::read_volatile(slot as *const *mut u8) };
    if !cc.is_null() {
        for i in 0..core::mem::size_of::<wallet::bip32::ChainCache>() {
            core::ptr::write_volatile(cc.add(i), 0);
        }
    }

    let p = base as *mut u8;
    let n = core::mem::size_of::<AppData>();
    for i in 0..n { core::ptr::write_volatile(p.add(i), 0); }

    // Read back and confirm. The "second pass (anti-glitch)" in
    // hw/lockdown.rs is a second write with no read and verifies nothing.
    let mut acc: u8 = 0;
    for i in 0..n { acc |= core::ptr::read_volatile(p.add(i)); }
    if acc != 0 {
        for i in 0..n { core::ptr::write_volatile(p.add(i), 0); }
    }
}

/// Panic handler. Wipes first, prints second, then halts.
///
/// Wipe order is deliberate: serial output is slow, and key material would
/// stay resident in PSRAM for its entire duration if the message went first.
///
/// `hw::lockdown::panic_wipe` (the broad SRAM sweep) is deliberately NOT
/// called here. It zeroes SRAM1 through the data-bus alias, which also
/// destroys IRAM and this function's own stack, so a fault mid-sweep would be
/// a double panic.
///
/// The H-01 residual is closed instead by `stack_probe::wipe_below_sp`, which
/// clears only between the guard and this frame. That span is stack by
/// definition, so it cannot reach the IRAM alias and cannot hold anything live.
/// It catches what the targeted wipe cannot: PBKDF2 intermediate state, the
/// 64-byte BIP39 seed from `ensure_session_account_key`, Schnorr scalars, and
/// any `SeedSlot` temporary, all of which sit in returned frames below the
/// current stack pointer.
///
/// ORDER MATTERS. The heap wipe runs first, because it dereferences a pointer
/// and the machinery to do that lives on the stack. Then the stack wipe, which
/// destroys nothing it needs. Then the logging, because serial is slow and
/// nothing should stay live for the length of a message.
///
/// Interrupts are already down here, which is the precondition
/// `wipe_below_sp` requires: an ISR would push a frame into the region being
/// zeroed.
#[panic_handler]
fn kassigner_panic(info: &core::panic::PanicInfo) -> ! {
    unsafe { panic_wipe_appdata(); }
    let wiped = app::stack_probe::wipe_below_sp();
    log!("");
    log!("PANIC: {}", info);
    log!("   Key material wiped, {} B of stack cleared. Halted.", wiped);
    loop { core::hint::spin_loop(); }
}

pub fn halt_forever(delay: &mut Delay) -> ! {
    delay.delay_millis(5000);
    loop { delay.delay_millis(1000); }
}

/// Display-less fallback — verify firmware via serial, then idle.
fn continue_without_display(delay: &mut Delay) -> ! {
    log!();
    log!("No-display mode — serial output only");
    log!();
    let fw = FirmwareInfo::new();
    log!("   Version: {}", fw.version_string().as_str());
    log!("   Address: 0x{:08X}", FIRMWARE_START_ADDR);
    match fw.verify_firmware(FIRMWARE_START_ADDR, FIRMWARE_MAX_SIZE) {
        VerificationResult::Valid => log!("Firmware verified OK"),
        other => {
            log!("CRITICAL: Verification failed: {:?}", other);
            loop { delay.delay_millis(1000); }
        }
    }
    log!("===================================");
    log!("  Boot completed (no display)");
    log!("===================================");
    loop { delay.delay_millis(5000); }
}

/// Waveshare: Apply all 6 cam-tune parameters to OV5640 via I2C1.
///
/// The sliders override a subset of what init_480 sets in OV5640_LCD_QR_TUNING.
/// Everything not written here (ISP master ctrl 0x5000, sharpen thresholds,
/// denoise) stays at the LCD-QR-tuned values from init_480 — previously this
/// function flipped CIP OFF on every slider change, which was correct for
/// sharp paper input but actively hurt blurred close-range LCD input. As of
/// v1.0.3 the slider is additive only: AEC range, contrast, brightness, AGC
/// ceiling, and the final CIP sharpness level.
#[cfg(feature = "waveshare")]
fn cam_tune_apply_all<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, vals: &[u8; 6]) {
    use hw::camera::write_reg;

    // AEC targets: H must be >= L for the control loop to converge.
    // If user drags them inverted, clamp L to H.
    let aec_h = vals[0];
    let aec_l = if vals[1] > vals[0] { vals[0] } else { vals[1] };

    // AEC stable range (enter) and (go out) — keep them paired
    write_reg(i2c, 0x3A0F, aec_h);   // WPT — stable high (enter)
    write_reg(i2c, 0x3A1B, aec_h);   // WPT2 — stable high (go out)
    write_reg(i2c, 0x3A10, aec_l);   // BPT — stable low (enter)
    write_reg(i2c, 0x3A1E, aec_l);   // BPT2 — stable low (go out)

    // SDE (Special Digital Effects) — enable contrast+brightness bits
    let sde = hw::camera::read_reg(i2c, 0x5580).unwrap_or(0x06);
    write_reg(i2c, 0x5580, sde | 0x06);  // bit2 = contrast, bit1 = brightness
    write_reg(i2c, 0x5586, vals[2]);     // contrast
    write_reg(i2c, 0x5585, 0x00);        // brightness sign (0=positive)
    write_reg(i2c, 0x5587, vals[3]);     // brightness magnitude

    // AGC gain ceiling
    write_reg(i2c, 0x3A18, 0x00);
    write_reg(i2c, 0x3A19, vals[4]);

    // CIP sharpness — slider value IGNORED on OV5640.
    //
    // The OV5640's CIP edge-enhancement block (0x5302 with 0x5308[6]=1
    // manual mode) is documented to accept runtime writes, but in practice
    // changing 0x5302 during streaming produces no visible effect on the
    // Y8 output of this module. No production OV5640 driver (Linux, STM,
    // NXP) exposes sharpness as a user-adjustable control — they all set
    // good baseline values at init and leave the CIP block alone.
    //
    // The sharpness slider is kept in the UI for consistency across the
    // OV5640/OV2640/GC0308 camera zoo — the overlay should look the same
    // regardless of which sensor booted. For OV2640 the cam_tune_apply_ov2640
    // path DOES honor the slider. For OV5640 we lock 0x5302 to a fixed good
    // value (0x30, the LCD-QR-tuned baseline) so toggling the slider won't
    // accidentally degrade an already-working image.
    //
    // We still write 0x5308=0x40 each apply to ensure manual MT mode stays
    // asserted (some re-init paths may drop it).
    write_reg(i2c, 0x5308, 0x40);        // manual edge MT mode (bit 6)
    write_reg(i2c, 0x5302, 0x30);        // fixed sharpen (LCD baseline)
    // vals[5] (slider position) intentionally unused on OV5640 — logged
    // below as SHP=xx for diagnostic parity with the other cameras.

    #[cfg(not(feature = "silent"))]
    {
        let avg = hw::camera::read_reg(i2c, 0x56A1).unwrap_or(0);
        log!("[CAM-TUNE] AEC={:02X}/{:02X} CTR={:02X} BRT={:02X} AGC={:02X} SHP={:02X} AVG={:02X}",
            aec_h, aec_l, vals[2], vals[3], vals[4], vals[5], avg);
    }
}

// ═══════════════════════════════════════════════════════════════════
// OV2640 cam_tune — maps the same 6 slider params to OV2640 registers
// ═══════════════════════════════════════════════════════════════════

#[cfg(feature = "waveshare")]
fn cam_tune_apply_ov2640<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, vals: &[u8; 6]) {
    use hw::camera_ov2640::{write_reg, read_reg, select_bank};

    // ── Sensor bank: AEC + AGC ──
    select_bank(i2c, 0x01);

    // AEC targets: AEW / AEB
    let aec_h = vals[0];
    let aec_l = if vals[1] > vals[0] { vals[0] } else { vals[1] };
    write_reg(i2c, 0x24, aec_h); // AEW
    write_reg(i2c, 0x25, aec_l); // AEB
    // VV: fast/slow zone thresholds — link to AEC range
    let vv = ((aec_h >> 1) & 0xF0) | ((aec_l >> 5) & 0x0F);
    write_reg(i2c, 0x26, vv);

    // AGC gain ceiling: COM9 bits[7:5]
    let agc_idx = (vals[4] >> 5) & 0x07;
    let com9 = read_reg(i2c, 0x14).unwrap_or(0x48);
    write_reg(i2c, 0x14, (com9 & 0x1F) | (agc_idx << 5));

    // ── DSP bank: SDE indirect (contrast + brightness) ──
    // Key: write all SDE data FIRST, then enable bitmask LAST.
    // Otherwise each BPADDR=0 write resets other effects.
    select_bank(i2c, 0x00);

    // Contrast: BPADDR=3 = contrast center, BPADDR=4 = contrast gain
    write_reg(i2c, 0x7C, 0x03); // BPADDR = 3
    write_reg(i2c, 0x7D, 0x40); // contrast center = 0x40
    write_reg(i2c, 0x7D, vals[2]); // auto-inc → BPADDR=4: contrast gain

    // Brightness: BPADDR=5 = brightness, BPADDR=6 = brightness sign
    write_reg(i2c, 0x7C, 0x05); // BPADDR = 5
    write_reg(i2c, 0x7D, vals[3]); // brightness value
    write_reg(i2c, 0x7D, 0x00); // auto-inc → BPADDR=6: sign (0=positive)

    // Enable bitmask LAST: bit[2] = contrast+brightness enable
    write_reg(i2c, 0x7C, 0x00); // BPADDR = 0 (SDE control)
    write_reg(i2c, 0x7D, 0x04); // enable contrast+brightness

    // Sharpness: DSP reg 0x92/0x93
    write_reg(i2c, 0x92, 0x01); // manual sharpness mode
    write_reg(i2c, 0x93, vals[5]); // sharpness level

    #[cfg(not(feature = "silent"))]
    {
        select_bank(i2c, 0x01);
        let avg = read_reg(i2c, 0x2F).unwrap_or(0); // YAVG
        log!("[CAM-TUNE-2640] AEC={:02X}/{:02X} CTR={:02X} BRT={:02X} AGC={:02X} SHP={:02X} AVG={:02X}",
            aec_h, aec_l, vals[2], vals[3], vals[4], vals[5], avg);
    }
}

// ═══════════════════════════════════════════════════════════════════
// M5Stack GC0308 cam-tune — maps the 6 slider params to GC0308 registers
// ═══════════════════════════════════════════════════════════════════
//
// Slider → Register mapping (all on Page 0):
//   vals[0] AEC-H    → 0xd3  AEC target Y (0-255, higher = brighter image)
//   vals[1] AEC-L    → 0xd1  AEC gain threshold (auxiliary — GC0308 uses single target)
//   vals[2] Contrast → 0xb3  Contrast gain (0x40 = 1.0x)
//   vals[3] Brite    → 0xb5  Y-offset brightness (two's-complement)
//   vals[4] AGC max  → 0xd2  Max AGC gain ceiling
//   vals[5] Sharp    → 0x72  INTPEE edge enhancement
//
// GC0308 doesn't expose an H/L AEC stable range like OV5640 — a single
// target Y drives the loop. We use vals[1] as a secondary gain threshold
// so both sliders still do something meaningful.

#[cfg(feature = "m5stack")]
#[allow(dead_code)]
fn cam_tune_apply_gc0308<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, vals: &[u8; 6]) {
    use hw::camera::sccb_write;

    // Ensure we're on Page 0 (all relevant regs live here)
    sccb_write(i2c, 0xfe, 0x00);

    // AEC target Y + gain threshold
    sccb_write(i2c, 0xd3, vals[0]);   // AEC target Y
    sccb_write(i2c, 0xd1, vals[1]);   // AEC gain threshold

    // Contrast + brightness
    sccb_write(i2c, 0xb3, vals[2]);   // Contrast gain (0x40 = 1.0x baseline)
    sccb_write(i2c, 0xb5, vals[3]);   // Y-offset brightness (signed)

    // AGC ceiling
    sccb_write(i2c, 0xd2, vals[4]);   // Max AGC gain cap

    // Sharpness / edge enhancement
    sccb_write(i2c, 0x72, vals[5]);   // INTPEE level

    #[cfg(not(feature = "silent"))]
    log!("[CAM-TUNE-GC0308] AEC={:02X} GAIN_THR={:02X} CTR={:02X} BRT={:02X} AGC={:02X} SHP={:02X}",
        vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]);
}

// ═══════════════════════════════════════════════════════════════════
// Panic halt hook — wipe key material before system halts
// ═══════════════════════════════════════════════════════════════════
