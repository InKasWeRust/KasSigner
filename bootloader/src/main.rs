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


// ─── Crate-level warning policy ──────────────────────────────
// dead_code: Library modules expose APIs not all called yet.
// unused_imports: Conditional compilation creates unused imports.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(static_mut_refs)]
//
// main.rs — KasSigner bootloader entry point (Waveshare ESP32-S3-Touch-LCD-2)
//
// Boot sequence: Phase 1 (self-tests) → Phase 2 (peripherals) →
// Phase 3 (firmware verify) → Phase 5 (main loop with touch dispatch).
//
// Peripheral singletons (I2C, SPI, LCD_CAM, I2S) are consumed here
// because esp-hal requires ownership at initialization time.

// ─── Linker symbol fixes ─────────────────────────────────────
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
    gpio::{Output, OutputConfig, Input, InputConfig, Pull, Level},
    main,
};
use esp_hal::ledc::{Ledc, LowSpeed, timer, channel};
use esp_hal::ledc::timer::TimerIFace;
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

    // First: set up a small internal DRAM heap so we can allocate before PSRAM
    // The PSRAM allocator extends this with the external memory.
    esp_alloc::psram_allocator!(peripherals.PSRAM, esp_hal::psram);
    log!("   PSRAM: initialized via psram_allocator!");
    let mut delay = Delay::new();

    // ─── Security: kill radios immediately ──────────────────────
    hw::lockdown::early_lockdown();


    // ─── Phase 1: Hardware self-tests ────────────────────────────
    app::boot_test::run_phase1_tests(&mut delay);

    // ─── Phase 2: Initialize peripherals ─────────────────────────
    log!("Phase 2: Initializing Display (Waveshare)");
    log!("──────────────────────────────────────────");

    // Step 2a: I2C bus for touch + IMU (GPIO48=SDA, GPIO47=SCL)
    // Waveshare has separate I2C for camera (GPIO21/16), initialized later
    let mut i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(400)),
    )
    .expect("I2C0 init failed — hardware fault")
    .with_sda(peripherals.GPIO48)
    .with_scl(peripherals.GPIO47);

    // Camera SCCB bus (separate I2C1 on GPIO21=SDA, GPIO16=SCL)
    // OV5640 SCCB: keep at 100kHz — not standard I2C, many modules fail at 400kHz
    let mut cam_i2c = I2c::new(
        peripherals.I2C1,
        I2cConfig::default().with_frequency(Rate::from_khz(100)),
    )
    .expect("I2C1 init failed — camera SCCB fault")
    .with_sda(peripherals.GPIO21)
    .with_scl(peripherals.GPIO16);

    // Step 2b: Direct GPIO init (no PMU on Waveshare)
    // Backlight GPIO1 will be configured by LEDC PWM after display init
    log!("   Backlight will be enabled after display clear via LEDC PWM");

    // Touch INT pin (GPIO46) — active LOW when touch data ready
    let _touch_int = Input::new(peripherals.GPIO46, InputConfig::default().with_pull(Pull::Up));
    log!("   Touch INT pin (GPIO46) configured");

    // Battery ADC init (GPIO5, ADC1_CH4, R19/R20 voltage divider)
    hw::battery::init_battery_adc();
    {
        let batt = hw::battery::read_battery(&mut i2c);
        if let Some(b) = batt {
            log!("   Battery: {}mV {}% {:?}", b.voltage_mv, b.percentage, b.state);
        } else {
            log!("   Battery: read failed");
        }
    }

    // Gate unused peripheral clocks for power savings (~5-15mA)
    // PERIP_CLK_EN0: disable UART1(5), SPI3(16), PCNT(10), RMT(9),
    //   PWM0(17), PWM1(20), TWAI/CAN(19), I2S1(21)
    unsafe {
        let clk0 = core::ptr::read_volatile(0x600C_0018u32 as *const u32);
        let gate_bits = (1u32 << 5) | (1u32 << 9) | (1u32 << 10) | (1u32 << 16)
            | (1u32 << 17) | (1u32 << 19) | (1u32 << 20) | (1u32 << 21);
        core::ptr::write_volatile(0x600C_0018u32 as *mut u32, clk0 & !gate_bits);
    }

    // Camera PWDN LOW = active (GPIO17)
    let _cam_pwdn = Output::new(peripherals.GPIO17, Level::Low, OutputConfig::default());
    log!("   Camera PWDN deasserted (GPIO17 LOW)");

    // Step 2c: No audio hardware on Waveshare (skipped)
    log!("   Audio: not available on this board");

        // Step 2d: SD card pre-init (power-up clocks before display claims GPIOs)
    let mut _bb_card_type = init_sd_card(&mut i2c, &mut delay);

    // Step 2e: SPI display
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

    let mut boot_display = match hw::display::BootDisplay::new(spi, cs_pin, dc_pin, reset_pin, &mut delay) {
        Ok(d) => { log!("   ST7789T3 display initialized OK — 320x240 color"); d }
        Err(e) => {
            log!("Display init error: {}", e);
            continue_without_display(&mut delay);
        }
    };

    // Backlight will be enabled after LEDC PWM setup (inside camera init block)

    // Post-display SDHOST init...
    // 
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
    // Backlight is binary on Waveshare (already set HIGH above)

    // Step 2f: Camera — let esp-hal generate XCLK, then probe SCCB
    // esp-hal's DvpCamera with Config::with_frequency() + with_master_clock()
    // handles all LCD_CAM clock register setup internally.
    log!("   LCD_CAM + DVP init (esp-hal master mode)...");
    let cam_config = CamConfig::default().with_frequency(Rate::from_mhz(20));

    let lcd_cam = LcdCam::new(peripherals.LCD_CAM);
    // QVGA YUV422: 640 bytes/line × 240 lines = 153600 bytes
    // (2 bytes/pixel: YUYV interleaved — Y extracted in camera_loop)
    let (rx_buffer, rx_descriptors, _, _) = esp_hal::dma_buffers!(153600, 0);
    let cam_dma_buf = esp_hal::dma::DmaRxBuf::new(rx_descriptors, rx_buffer)
        .expect("DMA buffer allocation failed");
    let mut cam_dma_buf_opt = Some(cam_dma_buf);

    let cam_build = DvpCamera::new(lcd_cam.cam, peripherals.DMA_CH0, cam_config);
    let mut dvp_camera_opt: Option<DvpCamera<'_>> = None;
    let mut cam_status = hw::camera::CameraStatus::Error;

    match cam_build {
        Ok(cam) => {
            // Start XCLK via esp-hal LEDC FIRST (before DVP pin setup)
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
                duty_pct: 0, // start off — will set brightness after display clear
                drive_mode: esp_hal::gpio::DriveMode::PushPull,
            }) {
                Ok(()) => log!("   LEDC backlight channel: GPIO1 OK"),
                Err(e) => log!("   LEDC backlight channel FAILED: {:?}", e),
            }
            log!("   LEDC backlight PWM on GPIO1");

            // Turn backlight ON now that display is cleared and PWM is ready
            hw::pmu::set_brightness(&mut i2c, 191);
            log!("   Backlight ON via PWM (brightness=191)");

            // Verify XCLK is actually toggling
            unsafe {
                // Enable input on GPIO8 for readback
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
                // No with_master_clock — GPIO8 is used by LEDC
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
                if !found {
                    log!("     No devices found on I2C1");
                }
            }

            log!("   OV5640 SCCB init (pre-XCLK)...");
            match hw::camera::init(&mut cam_i2c, &mut delay) {
                Ok(()) => {
                    log!("   OV5640 OK — registers configured");
                    cam_status = hw::camera::CameraStatus::SensorReady;
                }
                Err(e) => {
                    log!("   OV5640 FAILED: {}", e);
                }
            }

            // XCLK running from LEDC. Reset OV5640 via PWDN toggle so it
            // starts fresh with clock present, then re-init registers.
            if cam_status == hw::camera::CameraStatus::SensorReady {
                log!("   Camera PWDN reset (with XCLK running)...");
                // PWDN HIGH = power down
                unsafe {
                    core::ptr::write_volatile(0x6000_4008u32 as *mut u32, 1u32 << 17); // GPIO17 HIGH
                }
                delay.delay_millis(20);
                // PWDN LOW = power on
                unsafe {
                    core::ptr::write_volatile(0x6000_400Cu32 as *mut u32, 1u32 << 17); // GPIO17 LOW
                }
                delay.delay_millis(30); // Wait for OV5640 to power up with XCLK

                // Re-init OV5640 registers now that XCLK is running
                match hw::camera::init(&mut cam_i2c, &mut delay) {
                    Ok(()) => log!("   Camera re-init with XCLK: OK"),
                    Err(e) => log!("   Camera re-init with XCLK: {}", e),
                }
                delay.delay_millis(100);

                // Diagnostic: register readback
                hw::camera::log_diagnostics(&mut cam_i2c);

                // OV5640 runtime brightness/contrast tuning (uses cam_i2c = I2C1)
                hw::camera::tune(&mut cam_i2c, &mut delay);

                // Check PCLK (GPIO9) toggles — camera should be generating PCLK from its internal PLL
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

                // Also check VSYNC (GPIO6) and HREF (GPIO4)
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
        // Configure VSYNC EOF
        hw::camera::configure_cam_vsync_eof();
        delay.delay_millis(100);
        delay.delay_millis(50);
    }

    // ─── Phase 3: Verify firmware integrity ──────────────────────
    app::signing::run_firmware_verify(&mut boot_display, &mut delay);

    // ─── Security: disable JTAG + USB data ──────────────────────
    hw::lockdown::post_boot_lockdown();

    // ─── Phase 5: Boot into main application ─────────────────────
    log!("Phase 5: Stateless mode — no PIN, no NVS");
    log!("─────────────────────────────────────────");

    let mut tracker = hw::touch::TouchTracker::new();
    let mut touch_configured = false;

    #[cfg(not(feature = "skip-tests"))]
    app::boot_test::run_boot_tests();

    let (grid_zones, list_zones, page_up_zone, page_down_zone) = touch_zones();
    let mut ad = AppData::new();

    log!("   Touch ready — tap menu items to navigate");

    #[cfg(feature = "screenshot")]
    log!("   [SCREENSHOT] Feature enabled — triple-tap top-right to capture");

    // ─── Main loop ───────────────────────────────────────────────
    const IDLE_DIM_TICKS: u32 = 36000;
    const IDLE_SLEEP_TICKS: u32 = 72000;
    let mut wake_debounce: u32 = 200; // suppress phantom touches at boot
    let mut dim_active: bool = false;

    loop {
        // Poll CST816D every loop — INT pin timing unreliable for gating
        let (ts, gesture) = hw::touch::read_touch_full(&mut i2c, &mut touch_configured);
        let action = tracker.update(ts, gesture);
        let touch_state = ts;
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
                tracker = hw::touch::TouchTracker::new();
                wake_debounce = 100;
                continue;
            }
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

            // Home button — go to main menu (skip on ScanQR — gear icon there)
            if is_home && ad.app.state != app::input::AppState::ScanQR {
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

            // Screenshot trigger (disabled — feature not enabled)
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
        } else if action == hw::touch::TouchAction::SwipeLeft && !ad.cam_tune_active {
            // Swipe left = page down (next)
            hw::sound::click(&mut delay);

            // MultisigPickSeed scroll
            if matches!(ad.app.state, app::input::AppState::MultisigPickSeed { .. }) {
                let loaded_count = ad.seed_mgr.slots.iter().filter(|s| !s.is_empty()).count() as u8;
                if ad.ms_scroll + 3 < loaded_count { ad.ms_scroll += 3; ad.needs_redraw = true; }
            } else {
            let fake_x = 300u16; // page_down zone
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
            // Swipe right = page up (previous)
            hw::sound::click(&mut delay);

            // MultisigPickSeed scroll
            if matches!(ad.app.state, app::input::AppState::MultisigPickSeed { .. }) {
                if ad.ms_scroll >= 3 { ad.ms_scroll -= 3; ad.needs_redraw = true; }
            } else {
            let fake_x = 20u16; // page_up zone
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
            // Drag on cam-tune slider (y=196+ matches visual slider area)
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

        // ─── Signing, redraw, camera ─────────────────────────────
        app::signing::handle_signing_step(&mut ad, &mut boot_display);

        if ad.needs_redraw {
            ad.idle_ticks = 0;
            ad.needs_redraw = false;
            // Reset all sub-menu scroll positions when returning to MainMenu
            if ad.app.state == app::input::AppState::MainMenu {
                ad.tools_menu.scroll = 0;
                ad.export_menu.scroll = 0;
                ad.qr_export_menu.scroll = 0;
                ad.settings_menu.scroll = 0;
                ad.ms_scroll = 0;
            }
            log!("   [DBG] redraw t={} state={:?}", ad.idle_ticks, ad.app.state);
            ui::redraw::redraw_screen(&mut ad, &mut boot_display, &mut i2c, &_bb_card_type);
            // Touch read after redraw — feed tracker so taps during redraw aren't lost
            {
                let (ts, gest) = hw::touch::read_touch_with_gesture(&mut i2c);
                tracker.update(ts, gest);
            }
        }

        // Auto-trigger: stego JPEG scan (skips the mode select tap)
        if ad.stego_auto_scan && ad.app.state == app::input::AppState::StegoModeSelect {
            ad.stego_auto_scan = false;
            let result = handlers::stego::handle_stego_touch(
                &mut ad, &mut boot_display, &mut delay, &mut i2c,
                &_bb_card_type, &list_zones, &page_up_zone, &page_down_zone,
                160, 120, false, // fake center tap, not back
            );
            if let Some(r) = result { ad.needs_redraw = r; }
        }

        let camera_active = ad.app.state == app::input::AppState::ScanQR;

        if camera_active
            && (cam_status == hw::camera::CameraStatus::SensorReady
                || cam_status == hw::camera::CameraStatus::Streaming)
        {
            // Camera PWDN LOW = power on
            unsafe { core::ptr::write_volatile(0x6000_400Cu32 as *mut u32, 1u32 << 17); }

            // Apply cam-tune values when changed (or on first stream start)
            if ad.cam_tune_dirty {
                ad.cam_tune_dirty = false;
                cam_tune_apply_all(&mut cam_i2c, &ad.cam_tune_vals);
            }

            handlers::camera_loop::run_camera_cycle(
                &mut ad, &mut boot_display, &mut delay, &mut i2c,
                &mut dvp_camera_opt, &mut cam_status,
                &mut cam_dma_buf_opt, &mut tracker,
            );

            // Process taps captured inside camera_loop during DMA wait
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
                // Reset tracker to prevent main loop from firing the same tap
                tracker = hw::touch::TouchTracker::new();
            }
        } else {
            // Camera PWDN HIGH only after extended absence from ScanQR (saves ~100mA)
            // Keep camera alive briefly for quick back→re-enter cycles
            if ad.idle_ticks > 150 {
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

/// Initialize AXP2101 PMU and AW9523B IO expander.
fn init_pmu(_i2c: &mut I2c<'_, esp_hal::Blocking>, _delay: &mut Delay) {
    // No PMU on Waveshare — power management handled by direct GPIO
    log!("   No PMU on this board — power rails always on");
}

/// Pre-SPI SD card power-up clocks (before hardware SPI claims GPIOs).
/// Does NOT send CMD0 — that would leave the card in a state that
/// the post-display bitbang init can't recover from (no power cycle on Waveshare).
fn init_sd_card(
    _i2c: &mut I2c<'_, esp_hal::Blocking>,
    delay: &mut Delay,
) -> Option<hw::sdcard::SdCardType> {
    log!("   SD pre-init: power-up clocks...");
    hw::sdcard::sd_pre_init();
    delay.delay_millis(10);
    hw::sdcard::sd_power_up_clocks();
    delay.delay_millis(10);
    log!("   SD power-up clocks done");
    None
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

    // Restore backlight
    hw::pmu::set_brightness(i2c, ad.brightness);
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
    delay.delay_millis(300);
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
        // Full sleep: backlight OFF
        hw::pmu::set_brightness(i2c, 0);
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

/// Apply all 6 cam-tune parameters to OV5640 via I2C1 (camera bus).
fn cam_tune_apply_all<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, vals: &[u8; 6]) {
    use hw::camera::write_reg;

    // [0] AEC high target
    write_reg(i2c, 0x3A0F, vals[0]);
    write_reg(i2c, 0x3A1B, vals[0]);
    // [1] AEC low target
    write_reg(i2c, 0x3A10, vals[1]);
    write_reg(i2c, 0x3A1E, vals[1]);
    // [2] Contrast
    write_reg(i2c, 0x5586, vals[2]);
    // [3] Brightness
    write_reg(i2c, 0x5587, vals[3]);
    // [4] AGC ceiling
    write_reg(i2c, 0x3A18, 0x00);
    write_reg(i2c, 0x3A19, vals[4]);
    // [5] Sharpness
    write_reg(i2c, 0x5308, vals[5]);

    #[cfg(not(feature = "silent"))]
    log!("[CAM-TUNE] APPLIED: AEC={:02X}/{:02X} CTR={:02X} BRT={:02X} AGC={:02X} SHP={:02X}",
        vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]);
}

// ═══════════════════════════════════════════════════════════════════
// Panic halt hook — wipe key material before system halts
// ═══════════════════════════════════════════════════════════════════
//
// esp-backtrace prints the backtrace then calls halt().
// We override the weak __halt symbol to wipe SRAM first.
// This ensures seed data is cleared on any panic, stack overflow,
// or assertion failure.

#[export_name = "halt"]
pub fn kassigner_halt() -> ! {
    hw::lockdown::panic_wipe();
    loop {
        // Halted — SRAM is wiped. The watchdog will eventually reset.
        core::hint::spin_loop();
    }
}
