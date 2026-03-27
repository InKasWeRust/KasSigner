#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(static_mut_refs)]
#![no_std]
#![no_main]

// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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
        log!("   LCD_CAM + DVP init (esp-hal master mode)...");
        let cam_config = CamConfig::default().with_frequency(Rate::from_mhz(20));

        let lcd_cam = LcdCam::new(peripherals.LCD_CAM);
        // QVGA YUV422: 640 bytes/line × 240 lines
        let (rx_buffer, rx_descriptors, _, _) = esp_hal::dma_buffers!(153600, 0);
        let cam_dma_buf = esp_hal::dma::DmaRxBuf::new(rx_descriptors, rx_buffer)
            .expect("DMA buffer allocation failed");
        let cam_dma_buf_opt = Some(cam_dma_buf);

        let cam_build = DvpCamera::new(lcd_cam.cam, peripherals.DMA_CH0, cam_config);
        let mut dvp_camera_opt: Option<DvpCamera<'_>> = None;
        let mut cam_status = hw::camera::CameraStatus::Error;

        match cam_build {
            Ok(cam) => {
                // LEDC: XCLK 20MHz on GPIO8 + Backlight PWM on GPIO1
                log!("   Starting XCLK via esp-hal LEDC...");
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

                // Backlight PWM: Timer1 ~1kHz 8-bit, Channel1 on GPIO1
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

                // Verify XCLK toggling
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

                let cam = cam
                    .with_pixel_clock(peripherals.GPIO9)
                    .with_vsync(peripherals.GPIO6)
                    .with_h_enable(peripherals.GPIO4)
                    .with_data0(peripherals.GPIO12)
                    .with_data1(peripherals.GPIO13)
                    .with_data2(peripherals.GPIO15)
                    .with_data3(peripherals.GPIO11)
                    .with_data4(peripherals.GPIO14)
                    .with_data5(peripherals.GPIO10)
                    .with_data6(peripherals.GPIO7)
                    .with_data7(peripherals.GPIO2);

                delay.delay_millis(30);

                // I2C1 bus scan
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

                log!("   OV5640 SCCB init...");
                match hw::camera::init(&mut cam_i2c, &mut delay) {
                    Ok(()) => {
                        log!("   OV5640 OK — registers configured");
                        cam_status = hw::camera::CameraStatus::SensorReady;
                    }
                    Err(e) => log!("   OV5640 FAILED: {}", e),
                }

                // Reset with XCLK running, then re-init + tune
                if cam_status == hw::camera::CameraStatus::SensorReady {
                    log!("   Camera PWDN reset (with XCLK running)...");
                    unsafe { core::ptr::write_volatile(0x6000_4008u32 as *mut u32, 1u32 << 17); }
                    delay.delay_millis(20);
                    unsafe { core::ptr::write_volatile(0x6000_400Cu32 as *mut u32, 1u32 << 17); }
                    delay.delay_millis(30);

                    match hw::camera::init(&mut cam_i2c, &mut delay) {
                        Ok(()) => log!("   Camera re-init with XCLK: OK"),
                        Err(e) => log!("   Camera re-init with XCLK: {}", e),
                    }
                    delay.delay_millis(100);
                    hw::camera::log_diagnostics(&mut cam_i2c);
                    hw::camera::tune(&mut cam_i2c, &mut delay);

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

                hw::camera::setup_cam_gpio_routing();
                dvp_camera_opt = Some(cam);
            }
            Err(e) => {
                log!("   LCD_CAM DVP FAILED: {:?}", e);
            }
        }
        log!();
        if cam_status == hw::camera::CameraStatus::SensorReady {
            hw::camera::configure_cam_vsync_eof();
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
    let mut ad = AppData::new();

    // M5Stack runs signing pipeline test at boot
    #[cfg(feature = "m5stack")]
    #[cfg(not(feature = "skip-tests"))]
    run_signing_pipeline_test(&mut ad);

    log!("   Touch ready — tap menu items to navigate");

    #[cfg(feature = "screenshot")]
    log!("   [SCREENSHOT] Feature enabled — triple-tap top-right to capture");

    // ─── Main loop ───────────────────────────────────────────────
    const IDLE_DIM_TICKS: u32 = 36000;
    const IDLE_SLEEP_TICKS: u32 = 72000;
    #[cfg(feature = "waveshare")]
    let mut wake_debounce: u32 = 200; // suppress phantom touches at boot
    #[cfg(feature = "m5stack")]
    let mut wake_debounce: u32 = 0;
    let mut dim_active: bool = false;

    loop {
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
            if handle_wake(&mut ad, &mut i2c, &mut delay, &mut tracker,
                           &mut wake_debounce, touch_state, is_touch) {
                continue;
            }
            delay.delay_millis(100);
            continue;
        }

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
            let is_back = x <= 36 && y <= 36;
            let is_home = x >= 268 && y <= 52;

            // Home button — go to main menu
            // Waveshare: skip on ScanQR (gear icon in that zone)
            #[cfg(feature = "waveshare")]
            let home_allowed = is_home && ad.app.state != app::input::AppState::ScanQR;
            #[cfg(feature = "m5stack")]
            let home_allowed = is_home;

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

            #[cfg(feature = "screenshot")]
            {
                if hw::screenshot::check_screenshot_trigger(x, y, ad.idle_ticks) {
                    log!("   Screenshot triggered — dumping to UART...");
                    hw::screenshot::dump_uart();
                    log!("   Screenshot complete.");
                    continue;
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
                    &_bb_card_type, &list_zones,
                    x, y, is_back,
                ),
                HandlerGroup::Seed => handlers::seed::handle_seed_touch(
                    &mut ad, &mut boot_display, &mut delay,
                    x, y, is_back,
                ),
                HandlerGroup::Export => handlers::export::handle_export_touch(
                    &mut ad, &mut boot_display, &mut delay,
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
                            &mut ad, &mut boot_display, &mut delay,
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
                            &mut ad, &mut boot_display, &mut delay,
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
                    && x >= 70 && x <= 250 && y >= 60 && y <= 130
                {
                    let pct = ((x as u32 - 70) * 255 / 180).min(255) as u8;
                    if pct != ad.brightness {
                        ad.brightness = pct;
                        hw::pmu::set_brightness(&mut i2c, ad.brightness);
                        boot_display.update_brightness_bar(ad.brightness);
                    }
                }
                // Drag on cam-tune slider
                if ad.app.state == app::input::AppState::ScanQR && ad.cam_tune_active && y >= 196 {
                    let p = ad.cam_tune_param as usize;
                    if x >= 56 && x <= 264 {
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
            log!("   [DBG] redraw t={} state={:?}", ad.idle_ticks, ad.app.state);
            ui::redraw::redraw_screen(&mut ad, &mut boot_display, &mut i2c, &_bb_card_type);
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
        let camera_active = ad.app.state == app::input::AppState::ScanQR;

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
                    cam_tune_apply_all(&mut cam_i2c, &ad.cam_tune_vals);
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
                    let is_back = x <= 36 && y <= 36;
                    let result = handlers::tx::handle_tx_touch(
                        &mut ad, &mut boot_display, &mut delay, &mut i2c,
                        &_bb_card_type, &list_zones,
                        x, y, is_back,
                    );
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
#[cfg(feature = "waveshare")]
fn cam_tune_apply_all<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, vals: &[u8; 6]) {
    use hw::camera::write_reg;

    write_reg(i2c, 0x3A0F, vals[0]);
    write_reg(i2c, 0x3A1B, vals[0]);
    write_reg(i2c, 0x3A10, vals[1]);
    write_reg(i2c, 0x3A1E, vals[1]);
    write_reg(i2c, 0x5586, vals[2]);
    write_reg(i2c, 0x5587, vals[3]);
    write_reg(i2c, 0x3A18, 0x00);
    write_reg(i2c, 0x3A19, vals[4]);
    write_reg(i2c, 0x5308, vals[5]);

    #[cfg(not(feature = "silent"))]
    log!("[CAM-TUNE] APPLIED: AEC={:02X}/{:02X} CTR={:02X} BRT={:02X} AGC={:02X} SHP={:02X}",
        vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]);
}

// ═══════════════════════════════════════════════════════════════════
// Panic halt hook — wipe key material before system halts
// ═══════════════════════════════════════════════════════════════════
