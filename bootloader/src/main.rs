#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(static_mut_refs)]
// Clippy Phase A+B cleanup — remaining allows are architectural or intentional
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
#![allow(clippy::bool_comparison)]              // explicit == true/false in some contexts
#![allow(clippy::manual_range_patterns)]        // manual range patterns for touch zones
#![allow(clippy::implicit_saturating_sub)]      // manual arithmetic for saturating subtract
#![allow(clippy::manual_pattern_char_comparison)] // explicit case comparison
#![allow(clippy::manual_ignore_case_cmp)]       // manual ASCII comparison
#![allow(clippy::unnecessary_mut_passed)]       // mutable ref to DMA methods
#![allow(clippy::bool_to_int_with_if)]          // if x { 1 } else { 0 } patterns
#![allow(clippy::collapsible_else_if)]          // else { if } with trailing statements
#![allow(clippy::manual_range_contains)]        // explicit range checks in SD filename parsing
#![allow(clippy::doc_lazy_continuation)]        // doc comment formatting
// Clippy pedantic — suppressed (intentional in no_std embedded)
#![allow(clippy::cast_possible_truncation)]     // ubiquitous u32→u8, usize→u8 in byte manipulation
#![allow(clippy::cast_possible_wrap)]           // u32→i32 in display coordinates
#![allow(clippy::cast_sign_loss)]               // i32→u32 in display/touch coordinates
#![allow(clippy::cast_lossless)]                // u8 as u32 — explicit for clarity in packed structs
#![allow(clippy::items_after_statements)]       // local structs/consts near point of use in handlers
#![allow(clippy::doc_markdown)]                 // technical terms without backticks
#![allow(clippy::wildcard_imports)]             // embedded-graphics prelude pattern
#![allow(clippy::used_underscore_binding)]      // _var used intentionally then read
#![allow(clippy::ptr_as_ptr)]                   // raw pointer casts in DMA/register code
#![allow(clippy::similar_names)]                // pos/prev, bw/bh, x0/x1 etc
#![allow(clippy::unreadable_literal)]           // hex/binary constants (0x6a09e667f3bcc908, 0b01110)
#![allow(clippy::map_unwrap_or)]                // .map().unwrap_or() clearer than map_or in some contexts
#![allow(clippy::explicit_iter_loop)]           // .iter() explicit for clarity in no_std
#![allow(clippy::match_same_arms)]              // platform-specific cfg blocks with identical arms
#![allow(clippy::unnecessary_wraps)]            // consistent Result return in handler chains
#![allow(clippy::ref_option)]                   // &Option<T> in existing function signatures
#![allow(clippy::inline_always)]                // intentional for register read/write hot paths
#![allow(clippy::trivially_copy_pass_by_ref)]   // &u8 in trait-matching signatures
#![allow(clippy::single_char_lifetime_names)]   // standard Rust lifetime naming
#![allow(clippy::struct_excessive_bools)]        // hardware state structs
#![allow(clippy::manual_let_else)]              // explicit if/return pattern
#![allow(clippy::redundant_else)]               // explicit else after return for clarity
#![allow(clippy::if_not_else)]                   // !flag reads fine
#![allow(clippy::single_match_else)]            // match with else arm for clarity
#![allow(clippy::many_single_char_names)]       // x, y, w, h, r in geometry code
#![allow(clippy::borrow_as_ptr)]                // &mut x as *mut in DMA code
#![allow(clippy::manual_midpoint)]              // (a + b) / 2 — .midpoint() not stable in no_std
#![allow(clippy::ref_as_ptr)]                   // &x as *const in register/DMA code
#![allow(clippy::ptr_cast_constness)]           // *mut as *const in DMA
#![allow(clippy::unnecessary_operation)]        // explicit ops for clarity
#![allow(clippy::match_wildcard_for_single_variants)] // _ arm for future-proofing enums
#![allow(clippy::too_many_lines)]               // large embedded handler functions
#![allow(clippy::needless_lifetimes)]           // explicit lifetimes for documentation
#![allow(clippy::unused_self)]                  // trait conformance
#![allow(clippy::enum_glob_use)]                // use Enum::* for variant-heavy matches
#![allow(clippy::doc_link_with_quotes)]         // doc comment formatting
#![allow(clippy::verbose_bit_mask)]             // explicit bit mask for clarity in register code
#![allow(clippy::redundant_closure_for_method_calls)] // .map(|s| s.method()) in handler chains
#![allow(clippy::needless_continue)]            // explicit continue in match arms for clarity
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
mod wallet;
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

// ─── Logging macro (available to all modules via `use crate::log`) ───
#[cfg(not(feature = "silent"))]
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { esp_println::println!($($arg)*) };
}
#[cfg(feature = "silent")]
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { };
}

use features::verify::{FirmwareInfo, VerificationResult, FIRMWARE_START_ADDR, FIRMWARE_MAX_SIZE};

// App descriptor — v0.2 macro
esp_bootloader_esp_idf::esp_app_desc!();

/// Global flag: redraw sets this to reset QR decoder state on screen change.
pub static mut QR_RESET_FLAG: bool = false;

/// Active sensor type on Waveshare (runtime auto-detect).
/// false = OV5640 (default), true = OV2640.
#[cfg(feature = "waveshare")]
pub static mut SENSOR_OV2640: bool = false;

// ═══════════════════════════════════════════════════════════════════════
//  ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════

#[main]
fn main() -> ! {
    log!();
    log!("╔════════════════════════════════════╗");
    log!("║      KasSigner Bootloader v1.0     ║");
    log!("║   Secure Boot for Kaspa Signer     ║");
    log!("╚════════════════════════════════════╝");
    log!();

    // ─── ESP32-S3 initialization ─────────────────────────────────
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::psram_allocator!(peripherals.PSRAM, esp_hal::psram);
    log!("   PSRAM: initialized via psram_allocator!");
    let mut delay = Delay::new();

    // ─── Security: kill radios immediately (Waveshare only — M5Stack has no lockdown yet) ───
    #[cfg(feature = "waveshare")]
    hw::lockdown::early_lockdown();

    // ─── Phase 1: Hardware self-tests ────────────────────────────
    app::boot_test::run_phase1_tests(&mut delay);

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

            hw::pmu::set_brightness(&mut i2c, 102);
            log!("   Backlight ON via PWM (brightness=102)");
        }

        // ── Verify XCLK toggling ──
        unsafe {
            let iomux8 = (0x6000_9000u32 + 0x04 + 8 * 4) as *mut u32;
            let v = core::ptr::read_volatile(iomux8);
            core::ptr::write_volatile(iomux8, v | (1u32 << 9));
        }
        delay.delay_millis(2);
        let mut xclk_tog = 0u32;
        let mut xlast = unsafe {
            (core::ptr::read_volatile(0x6000_403Cu32 as *const u32) >> 8) & 1
        };
        for _ in 0..200_000u32 {
            let x = unsafe {
                (core::ptr::read_volatile(0x6000_403Cu32 as *const u32) >> 8) & 1
            };
            if x != xlast { xclk_tog += 1; xlast = x; }
        }
        log!("   XCLK verify: {} toggles in 200K reads", xclk_tog);
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
            log!("   OV5640 found — init 480x480 Y8...");
            match hw::camera::init_480(&mut cam_i2c, &mut delay) {
                Ok(()) => {
                    log!("   OV5640 OK — 480x480 configured");
                    cam_status = hw::camera::CameraStatus::SensorReady;
                }
                Err(e) => log!("   OV5640 init FAILED: {}", e),
            }
        } else {
            log!("   OV5640 not found, trying OV2640...");
            match hw::camera_ov2640::init_480(&mut cam_i2c, &mut delay) {
                Ok(()) => {
                    log!("   OV2640 OK — 480x480 Y8 configured");
                    cam_status = hw::camera::CameraStatus::SensorReady;
                    unsafe { SENSOR_OV2640 = true; }
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

            let is_ov2640 = unsafe { SENSOR_OV2640 };
            if is_ov2640 {
                match hw::camera_ov2640::init_480(&mut cam_i2c, &mut delay) {
                    Ok(()) => log!("   OV2640 re-init with XCLK (480x480): OK"),
                    Err(e) => log!("   OV2640 re-init with XCLK: {}", e),
                }
                delay.delay_millis(100);
                hw::camera_ov2640::log_diagnostics(&mut cam_i2c);
            } else {
                match hw::camera::init_480(&mut cam_i2c, &mut delay) {
                    Ok(()) => log!("   OV5640 re-init with XCLK (480x480): OK"),
                    Err(e) => log!("   OV5640 re-init with XCLK: {}", e),
                }
                delay.delay_millis(100);
                hw::camera::log_diagnostics(&mut cam_i2c);
            }

            // Verify PCLK
            let mut pclk_tog = 0u32;
            let mut plast = unsafe {
                (core::ptr::read_volatile(0x6000_403Cu32 as *const u32) >> 9) & 1
            };
            for _ in 0..200_000u32 {
                let p = unsafe {
                    (core::ptr::read_volatile(0x6000_403Cu32 as *const u32) >> 9) & 1
                };
                if p != plast { pclk_tog += 1; plast = p; }
            }
            log!("   PCLK(GPIO9) toggles: {}", pclk_tog);

            // Verify VSYNC
            let mut vtog = 0u32;
            let mut vlast = unsafe {
                (core::ptr::read_volatile(0x6000_403Cu32 as *const u32) >> 6) & 1
            };
            for _ in 0..500_000u32 {
                let v = unsafe {
                    (core::ptr::read_volatile(0x6000_403Cu32 as *const u32) >> 6) & 1
                };
                if v != vlast { vtog += 1; vlast = v; }
            }
            log!("   VSYNC(GPIO6) toggles in 500K: {}", vtog);
        }

        // ── GPIO matrix routing (same as before — manual, not via DvpCamera) ──
        hw::camera::setup_cam_gpio_routing();

        // ── cam_dma: raw GDMA→PSRAM pipeline (replaces DvpCamera + DmaRxBuf) ──
        let dvp_camera_opt: Option<DvpCamera<'_>> = None;
        let cam_dma_buf_opt: Option<esp_hal::dma::DmaRxBuf> = None;

        if cam_status == hw::camera::CameraStatus::SensorReady {
            if hw::cam_dma::init() {
                log!("   cam_dma: PSRAM pipeline ready — 480x480 Y8");
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

        // I2S audio + speaker
        {
            log!("   I2S1 hardware peripheral init...");
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
        hw::pmu::set_brightness(&mut i2c, 102);

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

                let xclk_tog = hw::camera::verify_xclk_running();
                if xclk_tog > 100 {
                    match hw::camera::reinit_gc0308(&mut i2c, &mut delay) {
                        Ok(()) => log!("   GC0308 re-init OK with XCLK"),
                        Err(e) => log!("   GC0308 re-init FAILED: {}", e),
                    }
                    delay.delay_millis(500);
                } else {
                    log!("   XCLK not running, skipping re-init");
                }

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

    // ─── Security: disable JTAG + USB data (Waveshare only) ─────
    #[cfg(feature = "waveshare")]
    hw::lockdown::post_boot_lockdown();

    // ─── Phase 5: Boot into main application ─────────────────────
    log!("Phase 5: Stateless mode — no PIN, no NVS");
    log!("─────────────────────────────────────────");

    let mut tracker = hw::touch::TouchTracker::new();

    #[cfg(not(feature = "skip-tests"))]
    app::boot_test::run_boot_tests();

    let (grid_zones, list_zones, page_up_zone, page_down_zone) = touch_zones();
    // AppData is ~13 KB after all the PSKT migration additions
    // (IncomingPartialSig[5]×8 = ~4 KB, pubkey_compressed on InputSig[5]×8
    // = ~1.3 KB, signed_qr_buf bumped 1→4 KB in Step 0). Keeping it on
    // the stack blew the main-thread 8 KB ProCpu stack during early boot
    // when rqrr / DMA / cam_tune all want scratch. Box it onto the heap
    // so main's frame only holds a pointer; downstream code reborrows
    // through `ad` unchanged.
    let mut ad_box = alloc::boxed::Box::new(AppData::new());
    let mut ad: &mut AppData = &mut *ad_box;

    // Override cam_tune defaults for OV2640 — proven QR decode settings
    #[cfg(feature = "waveshare")]
    if unsafe { SENSOR_OV2640 } {
        ad.cam_tune_vals = [0x20, 0x0C, 0x8B, 0x08, 0x70, 0x50];
    }

    // M5Stack runs signing pipeline test at boot
    #[cfg(feature = "m5stack")]
    #[cfg(not(feature = "skip-tests"))]
    run_signing_pipeline_test(&mut ad);

    log!("   Touch ready — tap menu items to navigate");

    #[cfg(feature = "mirror")]
    log!("   [MIRROR] Live display mirror active");

    // ─── Main loop ───────────────────────────────────────────────
    const IDLE_DIM_TICKS: u32 = 36000;
    const IDLE_SLEEP_TICKS: u32 = 72000;
    #[cfg(feature = "waveshare")]
    let mut wake_debounce: u32 = 200; // suppress phantom touches at boot
    #[cfg(feature = "m5stack")]
    let mut wake_debounce: u32 = 0;
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

        ad.idle_ticks = ad.idle_ticks.saturating_add(1);
        let is_touch = !matches!(action, hw::touch::TouchAction::None);

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
                    if handle_wake(&mut ad, &mut i2c, &mut delay, &mut tracker,
                                   &mut wake_debounce, touch_state, is_touch) {
                        continue;
                    }
                }
                delay.delay_millis(100);
                continue;
            }
            #[cfg(feature = "m5stack")]
            {
                if handle_wake(&mut ad, &mut i2c, &mut delay, &mut tracker,
                               &mut wake_debounce, touch_state, is_touch) {
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
            if dim_active {
                hw::pmu::set_brightness(&mut i2c, ad.brightness);
                dim_active = false;
                #[cfg(feature = "m5stack")]
                hw::sound::click(&mut delay);
                tracker = hw::touch::TouchTracker::new();
                wake_debounce = 100;
                continue;
            }
            #[cfg(feature = "m5stack")]
            hw::pmu::set_brightness(&mut i2c, ad.brightness);
        }

        // Idle dimming / sleep
        handle_idle(&mut ad, &mut i2c, &mut dim_active, IDLE_DIM_TICKS, IDLE_SLEEP_TICKS);

        // ─── Touch dispatch ──────────────────────────────────────
        if wake_debounce > 0 {
            wake_debounce -= 1;
        } else if let hw::touch::TouchAction::Tap { x, y } = action {
            hw::sound::click(&mut delay);
            let is_back = x <= 48 && y <= 48;
            let is_home = x >= 268 && y <= 52;

            // Home button — go to main menu
            // Top-right home shortcut excluded on ScanQR for both platforms
            // (Waveshare had gear icon there historically; M5Stack UX parity
            // in v1.0.3 — ScanQR exits via back button only).
            #[cfg(feature = "waveshare")]
            let home_allowed = is_home && ad.app.state != app::input::AppState::ScanQR;
            #[cfg(feature = "m5stack")]
            let home_allowed = is_home && ad.app.state != app::input::AppState::ScanQR;

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
                    &mut ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &mut dvp_camera_opt, &mut cam_dma_buf_opt,
                    &grid_zones, &list_zones, &page_up_zone, &page_down_zone,
                    x, y, is_back,
                ),
                HandlerGroup::Stego => handlers::stego::handle_stego_touch(
                    &mut ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                    x, y, is_back,
                ),
                HandlerGroup::Sd => handlers::sd::handle_sd_touch(
                    &mut ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                    x, y, is_back,
                ),
                HandlerGroup::Seed => handlers::seed::handle_seed_touch(
                    &mut ad, &mut boot_display, &mut delay, &mut i2c,
                    x, y, is_back,
                ),
                HandlerGroup::Export => handlers::export::handle_export_touch(
                    &mut ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                    x, y, is_back,
                ),
                HandlerGroup::Settings => handlers::settings::handle_settings_touch(
                    &mut ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                    x, y, is_back,
                ),
                HandlerGroup::Tx => handlers::tx::handle_tx_touch(
                    &mut ad, &mut boot_display, &mut delay, &mut i2c,
                    &_bb_card_type, &list_zones,
                    x, y, is_back,
                ),
                HandlerGroup::None => None,
            };
            if let Some(r) = result { ad.needs_redraw = r; }

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
                            &mut ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &mut dvp_camera_opt, &mut cam_dma_buf_opt,
                            &grid_zones, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Stego => handlers::stego::handle_stego_touch(
                            &mut ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Export => handlers::export::handle_export_touch(
                            &mut ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Settings => handlers::settings::handle_settings_touch(
                            &mut ad, &mut boot_display, &mut delay, &mut i2c,
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
                            &mut ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &mut dvp_camera_opt, &mut cam_dma_buf_opt,
                            &grid_zones, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Stego => handlers::stego::handle_stego_touch(
                            &mut ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Export => handlers::export::handle_export_touch(
                            &mut ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                            fake_x, fake_y, false,
                        ),
                        HandlerGroup::Settings => handlers::settings::handle_settings_touch(
                            &mut ad, &mut boot_display, &mut delay, &mut i2c,
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
        app::signing::handle_signing_step(&mut ad, &mut boot_display);

        if ad.needs_redraw {
            ad.idle_ticks = 0;
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
            ui::redraw::redraw_screen(&mut ad, &mut boot_display, &mut i2c, &_bb_card_type);
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

        // Auto-trigger: stego JPEG scan
        if ad.stego_auto_scan && ad.app.state == app::input::AppState::StegoModeSelect {
            ad.stego_auto_scan = false;
            let result = handlers::stego::handle_stego_touch(
                &mut ad, &mut boot_display, &mut delay, &mut i2c,
                &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                160, 120, false,
            );
            if let Some(r) = result { ad.needs_redraw = r; }
        }

        // ─── Camera loop ─────────────────────────────────────────
        // Active on ScanQR (normal decode).
        // On Waveshare, also on CameraSettings (cam-tune only, no decode).
        #[cfg(feature = "waveshare")]
        let camera_active = matches!(
            ad.app.state,
            app::input::AppState::ScanQR | app::input::AppState::CameraSettings
        );
        #[cfg(feature = "m5stack")]
        let camera_active = matches!(
            ad.app.state,
            app::input::AppState::ScanQR
        );

        if camera_active
            && (cam_status == hw::camera::CameraStatus::SensorReady
                || cam_status == hw::camera::CameraStatus::Streaming)
        {
            // Waveshare: PWDN control + cam-tune
            #[cfg(feature = "waveshare")]
            {
                unsafe { core::ptr::write_volatile(0x6000_400Cu32 as *mut u32, 1u32 << 17); }
                if ad.cam_tune_dirty {
                    ad.cam_tune_dirty = false;
                    if unsafe { SENSOR_OV2640 } {
                        cam_tune_apply_ov2640(&mut cam_i2c, &ad.cam_tune_vals);
                    } else {
                        cam_tune_apply_all(&mut cam_i2c, &ad.cam_tune_vals);
                    }
                }
            }

            handlers::camera_loop::run_camera_cycle(
                &mut ad, &mut boot_display, &mut delay, &mut i2c,
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
                            &mut ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones,
                            &page_up_zone, &page_down_zone,
                            x, y, is_back,
                        )
                    } else {
                        handlers::tx::handle_tx_touch(
                            &mut ad, &mut boot_display, &mut delay, &mut i2c,
                            &_bb_card_type, &list_zones,
                            x, y, is_back,
                        )
                    };
                    if let Some(r) = result { ad.needs_redraw = r; }
                    tracker = hw::touch::TouchTracker::new();
                }
            }
        }
        // Waveshare: camera PWDN management when not scanning
        #[cfg(feature = "waveshare")]
        {
            if !camera_active && ad.idle_ticks > 150 {
                unsafe { core::ptr::write_volatile(0x6000_4008u32 as *mut u32, 1u32 << 17); }
            }
        }

        app::signing::cycle_signed_qr(&mut ad, &mut boot_display, &mut delay, &mut i2c);
        handlers::export::cycle_kpub_qr(&mut ad, &mut boot_display);
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
#[cfg(feature = "m5stack")]
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

    ad.seed_mgr.delete(0);
    ad.seed_loaded = false;
    ad.word_count = 0;
    ad.mnemonic_indices = [0; 24];
    ad.pubkeys_cached = false;
}

/// Handle wake-from-sleep on touch. Returns true if main loop should `continue`.
fn handle_wake(
    ad: &mut AppData,
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    delay: &mut Delay,
    tracker: &mut hw::touch::TouchTracker,
    wake_debounce: &mut u32,
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
    *wake_debounce = 200;
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
}

// ═══════════════════════════════════════════════════════════════════════
//  ERROR HANDLERS
// ═══════════════════════════════════════════════════════════════════════

/// Fatal halt — never returns.
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
