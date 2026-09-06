// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Waveshare platform initialization.
//!
//! The macro preserves the original initialization expression and therefore
//! keeps ESP-HAL singleton ownership and inferred peripheral lifetimes local
//! to the crate entry point.

pub(crate) mod decode_worker;

use esp_hal::delay::Delay;

fn count_gpio_toggles(pin: u32, reads: u32) -> u32 {
    let register = 0x6000_403Cu32 as *const u32;
    let mut toggles = 0u32;
    let mut previous = unsafe { (core::ptr::read_volatile(register) >> pin) & 1 };
    for _ in 0..reads {
        let current = unsafe { (core::ptr::read_volatile(register) >> pin) & 1 };
        if current != previous {
            toggles += 1;
            previous = current;
        }
    }
    toggles
}

pub(crate) fn verify_xclk(delay: &mut Delay) {
    unsafe {
        let iomux8 = (0x6000_9000u32 + 0x04 + 8 * 4) as *mut u32;
        let value = core::ptr::read_volatile(iomux8);
        core::ptr::write_volatile(iomux8, value | (1u32 << 9));
    }
    delay.delay_millis(2);
    let toggles = count_gpio_toggles(8, 200_000);
    crate::log!("   XCLK verify: {} toggles in 200K reads", toggles);
    delay.delay_millis(30);
}

pub(crate) fn log_camera_sync_signals() {
    let pclk_toggles = count_gpio_toggles(9, 200_000);
    crate::log!("   PCLK(GPIO9) toggles: {}", pclk_toggles);
    let vsync_toggles = count_gpio_toggles(6, 500_000);
    crate::log!("   VSYNC(GPIO6) toggles in 500K: {}", vsync_toggles);
}

pub(crate) fn log_i2c_devices<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) {
    crate::log!("   I2C1 bus scan:");
    let mut found = false;
    for address in 0x08u8..0x78 {
        let mut probe = [0u8; 1];
        if i2c.read(address, &mut probe).is_ok() {
            crate::log!("     Found device at 0x{:02X}", address);
            found = true;
        }
    }
    if !found {
        crate::log!("     No devices found on I2C1");
    }
}

pub(crate) fn pre_init_sd_card(delay: &mut Delay) {
    crate::log!("   SD pre-init: power-up clocks...");
    crate::hw::sdcard::sd_pre_init();
    delay.delay_millis(10);
    crate::hw::sdcard::sd_power_up_clocks();
    delay.delay_millis(10);
    crate::log!("   SD power-up clocks done");
}

macro_rules! initialize {
    ($peripherals:ident, $delay:ident) => {{
        log!("Initializing Display (Waveshare)");
        log!("──────────────────────────────────────────");

        // I2C0 for touch (GPIO48=SDA, GPIO47=SCL)
        let mut i2c = I2c::new(
            $peripherals.I2C0,
            I2cConfig::default().with_frequency(Rate::from_khz(400)),
        )
        .expect("I2C0 init failed — hardware fault")
        .with_sda($peripherals.GPIO48)
        .with_scl($peripherals.GPIO47);

        // I2C1 for camera SCCB (GPIO21=SDA, GPIO16=SCL)
        let mut cam_i2c = I2c::new(
            $peripherals.I2C1,
            I2cConfig::default().with_frequency(Rate::from_khz(100)),
        )
        .expect("I2C1 init failed — camera SCCB fault")
        .with_sda($peripherals.GPIO21)
        .with_scl($peripherals.GPIO16);

        // Touch INT pin (GPIO46)
        let _touch_int = Input::new($peripherals.GPIO46, InputConfig::default().with_pull(Pull::Up));
        log!("   Touch INT pin (GPIO46) configured");

        // Battery ADC (GPIO5)
        hw::battery::init_battery_adc();
        {
            let batt = hw::battery::read_battery!(&mut i2c);
            if let Some(b) = batt {
                log!("   Battery: {}mV {}% {:?}", b.voltage_mv, b.percentage, b.state);
            } else {
                log!("   Battery: read failed");
            }
        }

        // QMI8658C is an additive physical source on the shared touch I2C bus.
        // Failure is non-fatal: checked TRNG + camera remain the seed gates.
        let _ = $crate::services::entropy::initialize_imu(&mut i2c, &mut $delay);

        // Gate unused peripheral clocks
        unsafe {
            let clk0 = core::ptr::read_volatile(0x600C_0018u32 as *const u32);
            let gate_bits = (1u32 << 5) | (1u32 << 9) | (1u32 << 10) | (1u32 << 16)
                | (1u32 << 17) | (1u32 << 19) | (1u32 << 20) | (1u32 << 21);
            core::ptr::write_volatile(0x600C_0018u32 as *mut u32, clk0 & !gate_bits);
        }

        // Camera PWDN LOW = active (GPIO17)
        let _cam_pwdn = Output::new($peripherals.GPIO17, Level::Low, OutputConfig::default());
        log!("   Camera PWDN deasserted (GPIO17 LOW)");

        // No audio on Waveshare
        log!("   Audio: not available on this board");

        // SD pre-init
        $crate::boot::waveshare::pre_init_sd_card(&mut $delay);

        // SPI display (ST7789T3)
        log!("   SPI + ST7789T3 init...");
        let spi = Spi::new(
            $peripherals.SPI2,
            SpiConfig::default()
                .with_frequency(Rate::from_mhz(80))
                .with_mode(SpiMode::_0),
        )
        .expect("SPI2 init failed — hardware fault")
        .with_sck($peripherals.GPIO39)
        .with_mosi($peripherals.GPIO38);

        let cs_pin = Output::new($peripherals.GPIO45, Level::High, OutputConfig::default());
        let dc_pin = Output::new($peripherals.GPIO42, Level::Low, OutputConfig::default());
        let reset_pin = Output::new($peripherals.GPIO0, Level::High, OutputConfig::default());

        let boot_display = match hw::display::BootDisplay::new(spi, cs_pin, dc_pin, reset_pin, &mut $delay) {
            Ok(d) => { log!("   ST7789T3 display initialized OK — 320x240 color"); d }
            Err(e) => {
                log!("Display init error: {}", e);
                $crate::runtime::power_state::continue_without_display(&mut $delay);
            }
        };

        // SDHOST init (post-display)
        let sd_card_type = match hw::sdcard::init_sdhost(&mut $delay) {
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
        #[cfg(feature = "cam640")]
        let sensor_is_ov2640 = false;
        #[cfg(not(feature = "cam640"))]
        let mut sensor_is_ov2640 = false;

        // ── LEDC: XCLK 20MHz on GPIO8 + Backlight PWM on GPIO1 ──
        {
            let mut ledc = Ledc::new($peripherals.LEDC);
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

            let mut channel0 = ledc.channel(channel::Number::Channel0, $peripherals.GPIO8);
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

            let mut bl_channel = ledc.channel(channel::Number::Channel1, $peripherals.GPIO1);
            match bl_channel.configure(channel::config::Config {
                timer: &lstimer1,
                duty_pct: 0,
                drive_mode: esp_hal::gpio::DriveMode::PushPull,
            }) {
                Ok(()) => log!("   LEDC backlight channel: GPIO1 OK"),
                Err(e) => log!("   LEDC backlight channel FAILED: {:?}", e),
            }

            hw::pmu::set_brightness!(&mut i2c, 102);
            log!("   Backlight ON via PWM (brightness=102)");
        }

        // ── Verify XCLK toggling ──
        $crate::boot::waveshare::verify_xclk(&mut $delay);

        // NOTE: Do NOT call enable_lcd_cam_clocks() here — it reassigns GPIO8
        // from LEDC (our XCLK source) to LCD_CAM cam_clk output signal 149.
        // LEDC is already providing 20MHz XCLK on GPIO8. LCD_CAM peripheral
        // clocks (GDMA + LCD_CAM module) are enabled by cam_dma::init().

        // ── I2C1 bus scan ──
        $crate::boot::waveshare::log_i2c_devices(&mut cam_i2c);

        // ── Camera auto-detect: OV5640 first, OV2640 fallback ──
        log!("   Camera auto-detect...");
        if hw::camera::detect(&mut cam_i2c) {
            log!("   OV5640 found — init {}x{} Y8...", hw::cam_dma::FRAME_W, hw::cam_dma::FRAME_H);
            #[cfg(feature = "cam640")]
            let ov5640_init = hw::camera::init_hires(&mut cam_i2c, &mut $delay);
            #[cfg(not(feature = "cam640"))]
            let ov5640_init = hw::camera::init_480(&mut cam_i2c, &mut $delay);
            match ov5640_init {
                Ok(()) => {
                    log!("   OV5640 OK — {}x{} configured", hw::cam_dma::FRAME_W, hw::cam_dma::FRAME_H);
                    cam_status = hw::camera::CameraStatus::SensorReady;
                }
                Err(e) => log!("   OV5640 init FAILED: {}", e),
            }
        } else {
            #[cfg(feature = "cam640")]
            log!("   cam640 requires OV5640; OV2640 fallback intentionally disabled");
            #[cfg(not(feature = "cam640"))]
            {
                log!("   OV5640 not found, trying OV2640...");
                match hw::camera_ov2640::init_480(&mut cam_i2c, &mut $delay) {
                    Ok(()) => {
                        log!("   OV2640 OK — 480x480 Y8 configured");
                        cam_status = hw::camera::CameraStatus::SensorReady;
                        sensor_is_ov2640 = true;
                    }
                    Err(e) => log!("   OV2640 init FAILED: {}", e),
                }
            }
        }

        // ── PWDN reset + re-init with XCLK running ──
        if cam_status == hw::camera::CameraStatus::SensorReady {
            log!("   Camera PWDN reset (with XCLK running)...");
            $crate::hw::camera_power::pulse_reset(&mut $delay);

            let is_ov2640 = sensor_is_ov2640;
            if is_ov2640 {
                match hw::camera_ov2640::init_480(&mut cam_i2c, &mut $delay) {
                    Ok(()) => log!("   OV2640 re-init with XCLK (480x480): OK"),
                    Err(e) => log!("   OV2640 re-init with XCLK: {}", e),
                }
                $delay.delay_millis(100);
                hw::camera_ov2640::log_diagnostics(&mut cam_i2c);
            } else {
                #[cfg(feature = "cam640")]
                let ov5640_reinit = hw::camera::init_hires(&mut cam_i2c, &mut $delay);
                #[cfg(not(feature = "cam640"))]
                let ov5640_reinit = hw::camera::init_480(&mut cam_i2c, &mut $delay);
                match ov5640_reinit {
                    Ok(()) => log!("   OV5640 re-init with XCLK ({}x{}): OK", hw::cam_dma::FRAME_W, hw::cam_dma::FRAME_H),
                    Err(e) => log!("   OV5640 re-init with XCLK: {}", e),
                }
                $delay.delay_millis(100);
                hw::camera::log_diagnostics(&mut cam_i2c);
            }

            $crate::boot::waveshare::log_camera_sync_signals();
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
            $delay.delay_millis(150);
        }

        let touch_configured = false;
        (i2c, cam_i2c, boot_display, dvp_camera_opt, cam_dma_buf_opt,
         cam_status, sd_card_type, touch_configured, sensor_is_ov2640)
    }}
}

pub(crate) use initialize;

#[cfg(not(feature = "hardware-tests"))]
pub(crate) fn configure_camera_defaults(
    app: &mut crate::runtime::data::AppData,
    sensor_is_ov2640: bool,
) {
    if sensor_is_ov2640 {
        app.camera.cam_tune_vals = [0x20, 0x0C, 0x8B, 0x08, 0x70, 0x50];
    }
}
