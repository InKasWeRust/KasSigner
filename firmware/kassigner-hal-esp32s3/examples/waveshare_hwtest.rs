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

//! Hardware test for the Waveshare ESP32-S3-Touch-LCD-2, through this crate
//! and not the signing firmware.
//!
//! The same shape as `m5_hwtest`: the unit comes up, each part is exercised
//! through its trait or its module, and every result prints on the serial
//! monitor as `PASS` or `FAIL`. The screen ends green when everything passed
//! and red otherwise.
//!
//! From this crate's directory, with the Xtensa toolchain:
//!
//! ```text
//! cargo +esp ws-hwtest
//! ```
//!
//! The PSRAM mode, octal on this board, is stated in `main`.
//!
//! # The order
//!
//! Core 1 parked in the decode worker, both I2C buses, the battery
//! converter, the IMU, the camera held powered, the card's pre-init, the
//! panel, the card, LEDC for the camera clock and the backlight, then the
//! sensor twice around a power-down pulse, the pin routing and the DMA path.
//! `bring_up` differs: it powers the radio down first and brings the panel
//! up next, before the PSRAM clear, has no battery or card step, and brings
//! the IMU up last, with touch. Both leave the backlight pin alone until
//! LEDC takes it, and blank the panel before the driver's start-up turns the
//! display on (`unit::blank`).
//!
//! # The unit is built here, not by `unit::bring_up`
//!
//! `bring_up` stops at the first part that refuses; this test reports every
//! part and needs what a finished unit does not lend (the bare buses, a
//! transfer abandoned by hand, the sensor brought up twice). Each part is
//! built as `bring_up` builds it: a change there is a change here.
//!
//! # What it asks of a person
//!
//! - Watch the colour bars: red, green and blue, left to right.
//! - Watch the backlight go full, dim, dark, and back.
//! - Touch the screen for eight seconds; a dot appears under the finger.
//! - Show the camera a QR code during the eight-second capture.
//!
//! # The card is written only where the filesystem is not
//!
//! Block 0, the same blocks again as one multi-block read, and the FAT32
//! mount. Then three blocks the filesystem does not use, after the volume or
//! after the MBR, are saved, written with a single-block and a multi-block
//! write, read back, and restored. Nothing the filesystem holds is touched.
//!
//! # The main bus is left stuck twice, on purpose
//!
//! After the IMU's checks, a read from it is started by hand and abandoned
//! with the IMU holding SDA low, the state an interrupted transfer leaves.
//! The first time, the next read goes through the bus as the unit builds it,
//! which must free the line and read the right value. The second time, it
//! goes through esp-hal's driver alone, which must fail rather than return
//! another register's value.
//!
//! # A decoded code prints as its length only
//!
//! It can be a seed.

#![cfg_attr(target_arch = "xtensa", no_std)]
#![cfg_attr(target_arch = "xtensa", no_main)]

/// A host build compiles this and nothing else: the test is for the device.
#[cfg(not(target_arch = "xtensa"))]
fn main() {}

#[cfg(target_arch = "xtensa")]
mod app {
    use core::cell::RefCell;

    use embedded_hal::i2c::I2c as _;
    use embedded_hal_bus::i2c::RefCellDevice;
    use embedded_hal_bus::spi::ExclusiveDevice;
    use esp_backtrace as _;
    use esp_hal::clock::CpuClock;
    use esp_hal::delay::Delay;
    use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
    use esp_hal::i2c::master::{Config as I2cConfig, I2c};
    use esp_hal::ledc::channel::ChannelIFace;
    use esp_hal::ledc::timer::TimerIFace;
    use esp_hal::ledc::{channel, timer, Ledc, LowSpeed};
    use esp_hal::main;
    use esp_hal::spi::master::{Config as SpiConfig, Spi};
    use esp_hal::spi::Mode as SpiMode;
    use esp_hal::system::{CpuControl, Stack};
    use esp_hal::time::Rate;
    use esp_println::{print, println};
    use kassigner_fat32::block::BlockDevice;
    use kassigner_hal::camera::{Camera, Error as CamError, Power};
    use kassigner_hal::decoder::{Attempt, Decoder, Error as DecError, Outcome};
    use kassigner_hal::display::{Backlight, Display, Rect};
    use kassigner_hal::entropy::Entropy;
    use kassigner_hal::input::{Event, State, Touch};
    use kassigner_hal::pins::waveshare as pins;
    use kassigner_hal::timer::Timer;
    use kassigner_hal_esp32s3::entropy::Rng;
    use kassigner_hal_esp32s3::i2c_bus::{line_high, MatrixLines, Recovering};
    use kassigner_hal_esp32s3::panel::Panel;
    use kassigner_hal_esp32s3::systimer::SysTimer;
    use kassigner_hal_esp32s3::waveshare::backlight::WaveshareBacklight;
    use kassigner_hal_esp32s3::waveshare::camera::WaveshareCamera;
    use kassigner_hal_esp32s3::waveshare::decoder::WaveshareDecoder;
    use kassigner_hal_esp32s3::waveshare::storage::WaveshareStorage;
    use kassigner_hal_esp32s3::waveshare::touch::WaveshareTouch;
    use kassigner_hal_esp32s3::waveshare::{
        battery, cam_dma, decode_core, imu, panel, sdhost, sensor, unit,
    };
    use kassigner_hal_esp32s3::{efuse, gpio_matrix};
    use mipidsi::interface::SpiInterface;
    use mipidsi::models::ST7789;
    use mipidsi::Builder;
    use static_cell::StaticCell;

    esp_bootloader_esp_idf::esp_app_desc!();

    // Every `peripherals.GPIOn` below, checked at compile time against the
    // pin map, itself checked against the netlist.
    const _: () = {
        assert!(pins::I2C0[0].gpio == 48 && pins::I2C0[1].gpio == 47 && pins::I2C0[2].gpio == 46);
        assert!(pins::I2C1[0].gpio == 21 && pins::I2C1[1].gpio == 16);
        assert!(pins::SPI2[0].gpio == 39 && pins::SPI2[1].gpio == 38);
        assert!(pins::DISPLAY[0].gpio == 45 && pins::DISPLAY[1].gpio == 42);
        assert!(pins::DISPLAY[2].gpio == 0 && pins::DISPLAY[3].gpio == 1);
        assert!(pins::CAMERA_XCLK.gpio == 8 && pins::CAMERA_PWDN.gpio == 17);
    };

    /// Which OV5640 module is fitted: the autofocus one is mounted turned and
    /// needs both axes flipped. Set this to match the unit.
    const MODULE: sensor::Module = sensor::Module::AutoFocus;

    /// The unit's backlight level, as `unit::DEFAULT_BRIGHTNESS`.
    const DEFAULT_BRIGHTNESS: u8 = 39;

    const BLACK: u16 = 0x0000;
    const WHITE: u16 = 0xFFFF;
    const RED: u16 = 0xF800;
    const GREEN: u16 = 0x07E0;
    const BLUE: u16 = 0x001F;

    /// Core 1's stack, 48 KB, as `unit::CORE1_STACK_BYTES`.
    static mut APP_CORE_STACK: Stack<49152> = Stack::new();

    /// The display interface's batching buffer.
    static SPI_BUF: StaticCell<[u8; panel::SPI_BUFFER_BYTES]> = StaticCell::new();

    /// Pass and fail counts.
    struct Report {
        passed: u32,
        failed: u32,
    }

    impl Report {
        fn check(&mut self, name: &str, ok: bool) {
            if ok {
                self.passed += 1;
                println!("PASS  {}", name);
            } else {
                self.failed += 1;
                println!("FAIL  {}", name);
            }
        }
    }

    /// The value the sensor tables leave in `reg`, if they write it: the last
    /// write wins, in the order `sensor::init` applies them. `SCAN_DEFAULTS`
    /// is left out: it writes none of the registers checked.
    fn loaded_value(reg: u16) -> Option<u8> {
        let mut value = None;
        for &(r, v) in sensor::INIT_REGS.iter().chain(sensor::OVERRIDES_480.iter()) {
            if r == reg {
                value = Some(v);
            }
        }
        if MODULE == sensor::Module::AutoFocus {
            for &(r, v) in [(0x3820u16, 0x47u8), (0x3821, 0x06)].iter() {
                if r == reg {
                    value = Some(v);
                }
            }
        }
        for &(r, v) in sensor::LCD_QR_TUNING {
            if r == reg {
                value = Some(v);
            }
        }
        value
    }

    /// `RTC_IO_TOUCH_PAD5_REG`, GPIO5's RTC pad register, as `battery.rs` has
    /// it: bit 19 `MUX_SEL` routes the pad to the converter, bit 27 `RUE` and
    /// bit 28 `RDE` are its pulls.
    const RTC_IO_TOUCH_PAD5: u32 = 0x6000_8400 + 0x98;

    /// The battery converter's state, for telling a settling reading from a
    /// pad that is not routed.
    fn battery_state(label: &str) {
        // SAFETY: a volatile read of GPIO5's RTC pad register. Read only.
        let pad = unsafe { core::ptr::read_volatile(RTC_IO_TOUCH_PAD5 as *const u32) };
        let (meas, power) = battery::control_state();
        println!(
            "      battery {}: pad {:08X} (MUX_SEL {}, RUE {}, RDE {}), MEAS1_CTRL2 {:08X}, XPD {:08X}, powered {}",
            label,
            pad,
            (pad >> 19) & 1,
            (pad >> 27) & 1,
            (pad >> 28) & 1,
            meas,
            power,
            battery::is_powered()
        );
    }

    /// A luminance byte as neutral RGB565 grey, as in `m5_hwtest`.
    const fn grey(y: u8) -> u16 {
        let v = (y >> 3) as u16;
        (v << 11) | ((v << 1) << 5) | v
    }

    /// The QMI8658's `WHO_AM_I` register and what it holds, datasheet Rev 0.6
    /// Table 20, as `imu.rs` has them.
    const IMU_WHO_AM_I: u8 = 0x00;
    const IMU_WHO_AM_I_VALUE: u8 = 0x05;

    /// Leaving the main bus stuck by hand, through the pins as
    /// `i2c_bus` drives them to free it.
    mod wedge {
        use kassigner_hal::pins::waveshare as pins;
        use kassigner_hal::timer::Timer;
        use kassigner_hal_esp32s3::i2c_bus::{line_high, Lines, MatrixLines};
        use kassigner_hal_esp32s3::systimer::SysTimer;

        pub const SDA: u8 = pins::I2C0[0].gpio;
        pub const SCL: u8 = pins::I2C0[1].gpio;

        /// What [`imu_read`] left.
        pub struct Wedge {
            /// The IMU acknowledged its address.
            pub acked: bool,
            /// The IMU drove a zero, and SCL was stopped there.
            pub driving: bool,
            /// SDA still read low with both pins back on I2C0.
            pub held: bool,
        }

        /// Start a read from the IMU at `address` by hand and abandon it on
        /// a zero bit, the IMU holding SDA low, then give both pins back to
        /// I2C0 as they were.
        ///
        /// The register pointer is the caller's to set first: at `WHO_AM_I`,
        /// 0x05, the first bit the IMU sends is a zero.
        pub fn imu_read(address: u8) -> Wedge {
            let mut lines = MatrixLines::take(SDA, SCL);
            lines.half();

            // START: SDA falls with SCL high.
            lines.set_sda(false);
            lines.half();
            lines.set_scl(false);
            lines.half();

            // The address, read bit set, most significant bit first.
            let byte = (address << 1) | 1;
            for bit in (0..8).rev() {
                lines.set_sda((byte >> bit) & 1 == 1);
                lines.half();
                lines.set_scl(true);
                lines.half();
                lines.set_scl(false);
            }

            // The acknowledge clock, SDA let go: the IMU pulls it low.
            lines.set_sda(true);
            lines.half();
            lines.set_scl(true);
            lines.half();
            let acked = !lines.sda_high();
            lines.set_scl(false);
            lines.half();

            // The IMU now drives its first data bit. Clocked on until it
            // drives a zero, at most a byte, and stopped there with SCL low.
            let mut driving = false;
            if acked {
                for _ in 0..8 {
                    if !lines.sda_high() {
                        driving = true;
                        break;
                    }
                    lines.set_scl(true);
                    lines.half();
                    lines.set_scl(false);
                    lines.half();
                }
            }

            // Dropped: SCL let go and both pins back on I2C0. Nothing clocks
            // the IMU, so it keeps SDA low.
            drop(lines);
            SysTimer.delay_us(5);
            Wedge {
                acked,
                driving,
                held: driving && !line_high(SDA),
            }
        }
    }

    #[main]
    fn main() -> ! {
        let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
        esp_alloc::psram_allocator!(
            peripherals.PSRAM,
            esp_hal::psram,
            esp_hal::psram::PsramConfig {
                // Stated, not probed. This unit's PSRAM is octal.
                mode: esp_hal::psram::PsramMode::OctalSpi,
                ..Default::default()
            }
        );

        let mut delay = Delay::new();
        let mut timer = SysTimer;
        let mut report = Report {
            passed: 0,
            failed: 0,
        };

        println!();
        println!("KasSigner Waveshare ESP32-S3-Touch-LCD-2 hardware test");
        println!("through kassigner-hal-esp32s3, not the signing firmware");
        println!();

        // ── Core 1, parked in the decode worker ──────────────────────────────

        let mut cpu_control = CpuControl::new(peripherals.CPU_CTRL);
        // SAFETY: the only reference ever made to this static.
        let stack = unsafe { &mut *core::ptr::addr_of_mut!(APP_CORE_STACK) };
        let bottom = stack.bottom() as usize;
        // The cross-core interrupt core 0 wakes it with, from its idle wait,
        // bound on core 1 as `unit::bring_up` binds it. Without it the worker
        // sleeps in `WAITI` through every job posted to it.
        let wake =
            esp_hal::interrupt::software::SoftwareInterrupt::<1>::new(peripherals.FROM_CPU_INTR1);
        let core1 = match cpu_control.start_app_core(stack, move || {
            decode_core::bind_wake(wake);
            decode_core::core1_main(bottom)
        }) {
            Ok(guard) => {
                // Parked on drop: kept, as the firmware keeps it.
                core::mem::forget(guard);
                true
            }
            Err(_) => false,
        };
        report.check("core 1 running the decode worker", core1);

        // ── The two buses ────────────────────────────────────────────────────

        // As the unit builds it: the controller's arbitration check on, and
        // wrapped to free a held SDA before every transfer.
        let i2c0 = I2c::new(
            peripherals.I2C0,
            I2cConfig::default()
                .with_frequency(Rate::from_khz(pins::I2C0_KHZ))
                .with_bus_arbitration(true),
        )
        .expect("I2C0")
        .with_sda(peripherals.GPIO48)
        .with_scl(peripherals.GPIO47);
        let bus = RefCell::new(Recovering::new(i2c0, wedge::SDA, wedge::SCL));
        let mut i2c = RefCellDevice::new(&bus);

        let mut cam_i2c = I2c::new(
            peripherals.I2C1,
            I2cConfig::default().with_frequency(Rate::from_khz(pins::I2C1_KHZ)),
        )
        .expect("I2C1")
        .with_sda(peripherals.GPIO21)
        .with_scl(peripherals.GPIO16);

        let _touch_int = Input::new(
            peripherals.GPIO46,
            InputConfig::default().with_pull(Pull::Up),
        );

        print!("      main bus answers at");
        for addr in 0x08u8..0x78 {
            let mut b = [0u8; 1];
            if i2c.read(addr, &mut b).is_ok() {
                print!(" {:02X}", addr);
            }
        }
        println!();

        // ── Battery and IMU, as the firmware brings them up ──────────────────

        battery::init_battery_adc();
        battery_state("after init");
        let cell = battery::read();
        println!("      battery {:?}, raw {:?}", cell, battery::read_raw());
        // The raw value every 100 ms for a second: a converter still settling
        // drifts, a pad that is not routed does not.
        print!("      battery raw over 1 s:");
        for _ in 0..10 {
            delay.delay_millis(100);
            match battery::read_raw() {
                Some(raw) => print!(" {}", raw),
                None => print!(" timeout"),
            }
        }
        println!();
        // The converter answering is all a check can ask of it: this board
        // cannot tell a full cell from none, so a believable value says
        // nothing about a battery being there.
        report.check("battery converter reads", cell.is_ok());

        let imu_ok = imu::init(&mut i2c, &mut timer);
        report.check(
            "QMI8658 found, configured and live",
            imu_ok && imu::present(),
        );
        let mut samples = [0u8; 96];
        let got = imu::collect(&mut i2c, &mut timer, &mut samples);
        println!(
            "      IMU collected {} bytes, distinct per axis {:?}",
            got,
            imu::axis_distinct(&samples[..got])
        );
        report.check(
            "IMU samples look like noise",
            got > 0 && imu::buffer_is_healthy(&samples[..got]),
        );

        // ── The main bus, left stuck, twice ──────────────────────────────────
        //
        // As the module doc says: first through the unit's bus, which frees
        // the line; then through the driver alone, which must refuse.
        let imu_address = pins::I2C0_DEVICES[1].0;
        let enables = MatrixLines::enables_set(wedge::SDA, wedge::SCL);
        // Counted from here: anything the bus freed before the wedge is not
        // this check's.
        let (freed_before, _) = bus.borrow().recoveries();

        let pointer = i2c.write(imu_address, &[IMU_WHO_AM_I]).is_ok();
        let stuck = wedge::imu_read(imu_address);
        println!(
            "      wedged: pointer set {}, IMU acked {}, driving a zero {}, SDA held low on I2C0 {}",
            pointer, stuck.acked, stuck.driving, stuck.held
        );
        let mut b = [0u8; 1];
        let first = i2c
            .write_read(imu_address, &[IMU_WHO_AM_I], &mut b)
            .map(|()| b[0]);
        let (freed, not_freed) = bus.borrow().recoveries();
        let released = line_high(wedge::SDA);
        println!(
            "      through the unit's bus: {:02X?}, freed {} not freed {}, SDA {}, enable bits set {}",
            first,
            freed,
            not_freed,
            if released { "high" } else { "still low" },
            enables
        );
        report.check(
            "a held SDA is freed before the next read",
            enables
                && stuck.held
                && first == Ok(IMU_WHO_AM_I_VALUE)
                && freed == freed_before + 1
                && not_freed == 0
                && released,
        );

        let pointer = i2c.write(imu_address, &[IMU_WHO_AM_I]).is_ok();
        let stuck = wedge::imu_read(imu_address);
        println!(
            "      wedged again: pointer set {}, IMU acked {}, driving a zero {}, SDA held low on I2C0 {}",
            pointer, stuck.acked, stuck.driving, stuck.held
        );
        let bare = bus
            .borrow_mut()
            .inner()
            .write_read(imu_address, &[IMU_WHO_AM_I], &mut b)
            .map(|()| b[0]);
        let after = i2c
            .write_read(imu_address, &[IMU_WHO_AM_I], &mut b)
            .map(|()| b[0]);
        let (freed, not_freed) = bus.borrow().recoveries();
        println!(
            "      through the driver alone: {:02X?}; the next read through the unit's bus: {:02X?}, freed {} not freed {}",
            bare, after, freed, not_freed
        );
        report.check(
            "a read over a held SDA fails instead of returning data",
            stuck.held && bare.is_err() && after == Ok(IMU_WHO_AM_I_VALUE) && not_freed == 0,
        );

        // The camera held powered: PWDN low.
        let mut cam_pwdn = Output::new(peripherals.GPIO17, Level::Low, OutputConfig::default());

        // ── The card's pre-init, before the panel takes the shared pins ──────

        sdhost::sd_pre_init();
        delay.delay_millis(10);
        sdhost::sd_power_up_clocks();
        delay.delay_millis(10);

        // ── The panel ────────────────────────────────────────────────────────

        let spi = Spi::new(
            peripherals.SPI2,
            SpiConfig::default()
                .with_frequency(Rate::from_mhz(80))
                .with_mode(SpiMode::_0),
        )
        .expect("SPI2")
        .with_sck(peripherals.GPIO39)
        .with_mosi(peripherals.GPIO38);
        let cs = Output::new(peripherals.GPIO45, Level::High, OutputConfig::default());
        let dc = Output::new(peripherals.GPIO42, Level::Low, OutputConfig::default());
        let spi_dev = ExclusiveDevice::new_no_delay(spi, cs).expect("SPI device");
        let mut di = SpiInterface::new(spi_dev, dc, SPI_BUF.init([0; panel::SPI_BUFFER_BYTES]));
        // Blanked and written black first, as the unit does: the panel may
        // still show the last picture, perhaps a SeedQR. No reset pin: GPIO0
        // is the BOOT button, and the board does not link it to the panel.
        unit::blank(&mut di, &mut delay);
        let built = Builder::new(ST7789, di)
            .color_order(panel::COLOR_ORDER)
            .invert_colors(panel::INVERSION)
            .display_size(panel::NATIVE.width, panel::NATIVE.height)
            .orientation(panel::orientation())
            .init(&mut delay);
        report.check("ST7789T3 init", built.is_ok());
        let Ok(display) = built else {
            halt(&report);
        };

        // ── The card ─────────────────────────────────────────────────────────

        let card = sdhost::init_sdhost(&mut timer);
        println!("      card at boot {:?}", card);

        // ── LEDC: the camera's 20 MHz clock and the backlight ────────────────

        {
            let mut ledc = Ledc::new(peripherals.LEDC);
            ledc.set_global_slow_clock(esp_hal::ledc::LSGlobalClkSource::APBClk);

            let mut lstimer0 = ledc.timer::<LowSpeed>(timer::Number::Timer0);
            let xclk_timer = lstimer0
                .configure(timer::config::Config {
                    duty: timer::config::Duty::Duty2Bit,
                    clock_source: timer::LSClockSource::APBClk,
                    frequency: Rate::from_mhz(20),
                })
                .is_ok();
            let mut channel0 = ledc.channel(channel::Number::Channel0, peripherals.GPIO8);
            let xclk = channel0
                .configure(channel::config::Config {
                    timer: &lstimer0,
                    duty_pct: 50,
                    drive_mode: esp_hal::gpio::DriveMode::PushPull,
                })
                .is_ok();
            report.check("camera clock, 20 MHz on GPIO8", xclk_timer && xclk);

            let mut lstimer1 = ledc.timer::<LowSpeed>(timer::Number::Timer1);
            let bl_timer = lstimer1
                .configure(timer::config::Config {
                    duty: timer::config::Duty::Duty8Bit,
                    clock_source: timer::LSClockSource::APBClk,
                    frequency: Rate::from_khz(1),
                })
                .is_ok();
            let mut bl_channel = ledc.channel(channel::Number::Channel1, peripherals.GPIO1);
            let bl = bl_channel
                .configure(channel::config::Config {
                    timer: &lstimer1,
                    duty_pct: 0,
                    drive_mode: esp_hal::gpio::DriveMode::PushPull,
                })
                .is_ok();
            report.check("backlight channel on GPIO1", bl_timer && bl);
        }

        let mut lcd = Panel::new(display, WaveshareBacklight, panel::SIZE);
        // Black before the light, as the unit does: the panel may still hold
        // the last screen, perhaps a SeedQR.
        let black = lcd.clear(BLACK).is_ok();
        report.check(
            "panel black, then the backlight at the default level",
            black
                && lcd
                    .set_backlight(Backlight::Level(DEFAULT_BRIGHTNESS))
                    .is_ok(),
        );
        delay.delay_millis(30);

        // ── The sensor, twice around a power-down pulse ──────────────────────

        print!("      camera bus answers at");
        for addr in 0x08u8..0x78 {
            let mut b = [0u8; 1];
            if cam_i2c.read(addr, &mut b).is_ok() {
                print!(" {:02X}", addr);
            }
        }
        println!();

        let id = sensor::product_id(&mut cam_i2c);
        println!(
            "      sensor product id {:04X}, expected {:04X}",
            id,
            sensor::PRODUCT_ID
        );
        let t = timer.now_us();
        let first = sensor::init(&mut cam_i2c, MODULE);
        println!(
            "      sensor first bring-up {:?} in {} ms",
            first,
            timer.since(t) / 1000
        );
        report.check("OV5640 first bring-up", first.is_ok());

        let mut sensor_ok = false;
        if first.is_ok() {
            // PWDN high then low, as the firmware pulses it before the second
            // bring-up.
            cam_pwdn.set_high();
            delay.delay_millis(20);
            cam_pwdn.set_low();
            delay.delay_millis(30);
            let second = sensor::init(&mut cam_i2c, MODULE);
            report.check("OV5640 second bring-up", second.is_ok());
            delay.delay_millis(100);
            sensor_ok = second.is_ok();
        }

        if sensor_ok {
            // Output size, format, and flip/mirror: what the tables leave.
            let mut all = true;
            print!("      sensor registers");
            for reg in [0x3808u16, 0x3809, 0x380A, 0x380B, 0x4300, 0x3820, 0x3821] {
                let Some(want) = loaded_value(reg) else {
                    continue;
                };
                let got = sensor::read_reg(&mut cam_i2c, reg);
                print!(" {:04X}={:02X?}/{:02X}", reg, got, want);
                all &= got == Some(want);
            }
            println!();
            report.check("OV5640 holds the loaded configuration", all);
        }

        gpio_matrix::apply(&pins::CAMERA);

        // ── The panel's own checks ───────────────────────────────────────────

        let w = panel::SIZE.width;
        let h = panel::SIZE.height;
        let third = w / 3;
        let bars = lcd.clear(BLACK).is_ok()
            && lcd.fill(Rect::new(0, 0, third, h), RED).is_ok()
            && lcd.fill(Rect::new(third, 0, third, h), GREEN).is_ok()
            && lcd
                .fill(Rect::new(2 * third, 0, w - 2 * third, h), BLUE)
                .is_ok();
        report.check("colour bars drawn (look: red, green, blue)", bars);
        report.check(
            "a rectangle off the panel is refused",
            lcd.fill(Rect::new(w - 10, 0, 20, 10), WHITE).is_err(),
        );
        delay.delay_millis(1500);

        let full = lcd.set_backlight(Backlight::Level(255)).is_ok();
        delay.delay_millis(800);
        let dim = lcd.set_backlight(Backlight::Level(1)).is_ok();
        delay.delay_millis(800);
        let off = lcd.set_backlight(Backlight::Off).is_ok();
        delay.delay_millis(800);
        let back = lcd
            .set_backlight(Backlight::Level(DEFAULT_BRIGHTNESS))
            .is_ok();
        report.check(
            "backlight full, dim, off and back (look)",
            full && dim && off && back,
        );

        // ── The SoC: RNG and eFuse ───────────────────────────────────────────

        let mut rng = Rng::new();
        rng.start();
        let mut drawn = [0u8; 64];
        report.check(
            "RNG draw passes its health tests",
            rng.fill(&mut drawn).is_ok(),
        );
        // What the unit's start-up verdict counts, run on its own so the code
        // the verdict depends on is the code proven here.
        report.check("start-up generator check passes", rng.health_check());
        // The SAR ADC converting for the generator, read back: a report of
        // what `start` set up, not something the draw depends on.
        report.check("SAR ADC sampling for the generator", rng.adc_sampling());
        println!("      {}", efuse::decode(&efuse::words()).verdict().line());

        // ── Touch ────────────────────────────────────────────────────────────

        let mut touch = WaveshareTouch::new(RefCellDevice::new(&bus));
        let _ = lcd.clear(BLACK);
        println!("      touch the screen for eight seconds");
        let t0 = timer.now_us();
        let mut presses = 0u32;
        let mut read_errors = 0u32;
        while timer.since(t0) < 8_000_000 {
            match touch.read() {
                Ok(State::Idle) => {}
                Ok(state) => {
                    if let Some(p) = state.first() {
                        let x = p.x.min(w - 6);
                        let y = p.y.min(h - 6);
                        let _ = lcd.fill(Rect::new(x, y, 6, 6), WHITE);
                        if p.event == Event::PressDown {
                            presses += 1;
                            println!("      press at ({}, {})", p.x, p.y);
                        }
                    }
                }
                Err(_) => read_errors += 1,
            }
            delay.delay_millis(10);
        }
        println!("      {} presses, {} read errors", presses, read_errors);
        report.check("touch reports presses", presses > 0);

        // ── Camera and decoder ───────────────────────────────────────────────

        let mut cam = if sensor_ok {
            // The power-down pin goes to the camera, as the bring-up hands
            // it over: the power-off check below drives it.
            let cam = WaveshareCamera::new(cam_pwdn);
            report.check("DMA path up, frame buffers in PSRAM", cam.is_some());
            cam_dma::log_status();
            // SAFETY: three volatile reads of LCD_CAM registers, TRM 29.1,
            // 29.11 and 29.12. Reads only.
            let (lcd_clock, cam_ctrl, cam_ctrl1) = unsafe {
                (
                    core::ptr::read_volatile(0x6004_1000 as *const u32),
                    core::ptr::read_volatile(0x6004_1004 as *const u32),
                    core::ptr::read_volatile(0x6004_1008 as *const u32),
                )
            };
            println!(
                "      LCD_CLOCK {:08X}  CAM_CTRL {:08X}  CAM_CTRL1 {:08X}",
                lcd_clock, cam_ctrl, cam_ctrl1
            );
            report.check(
                "LCD_CAM register clock forced on",
                lcd_clock & (1 << 31) != 0,
            );
            report.check("LCD_CAM ends a frame on VSYNC", cam_ctrl & (1 << 8) != 0);
            report.check("LCD_CAM in DE mode", cam_ctrl1 & (1 << 28) == 0);
            delay.delay_millis(150);
            cam
        } else {
            None
        };

        let decoder = WaveshareDecoder::new();
        // `new` allocates nothing, the decode running entirely out of
        // internal SRAM, so this shows only that the decoder was made; the
        // capture below shows the worker answers.
        report.check(
            "decoder ready, no external RAM in its path",
            decoder.is_some(),
        );

        if let (Some(cam), Some(mut dec)) = (cam.as_mut(), decoder) {
            let mut payload = [0u8; 4096];
            let mut line = [0u16; 240];
            println!("      capturing for eight seconds; show it a QR code");
            let _ = lcd.clear(BLACK);
            let t0 = timer.now_us();
            let mut frames = 0u32;
            let mut failures = 0u32;
            let mut submitted = 0u32;
            let mut results = 0u32;
            let mut decoded = 0u32;
            let mut attempt = Attempt::Fast;
            while timer.since(t0) < 8_000_000 {
                // A result from core 1, if one is waiting. Taken first, so the
                // worker is idle again before the next submit.
                match dec.poll(&mut payload) {
                    Ok(Some(Outcome::Found { len })) => {
                        results += 1;
                        decoded += 1;
                        println!("      decoded {} bytes", len);
                        payload.fill(0);
                    }
                    Ok(Some(Outcome::Unreadable)) => {
                        results += 1;
                        attempt = Attempt::Thorough;
                    }
                    Ok(Some(_)) => results += 1,
                    Ok(None) => {}
                    Err(e) => println!("      decode error {:?}", e),
                }

                match cam.frame_within(&timer, 1_000_000) {
                    Ok(frame) => {
                        frames += 1;
                        // The viewfinder: 240x180, every other pixel, with
                        // rows and columns exchanged.
                        for cy in 0..180usize {
                            let col = 60 + cy * 2;
                            for (cx, px) in line.iter_mut().enumerate() {
                                *px = grey(frame[(cx * 2) * cam_dma::BPL + col]);
                            }
                            let _ = lcd.blit(Rect::new(40, 30 + cy as u16, 240, 1), &line);
                        }
                        // The scan loop's policy: fast, and one pass at the
                        // other window after a code is located and unread.
                        match dec.submit(frame, attempt) {
                            Ok(()) => submitted += 1,
                            Err(DecError::Busy) => {}
                            Err(e) => println!("      submit error {:?}", e),
                        }
                        attempt = Attempt::Fast;
                    }
                    Err(e) => {
                        failures += 1;
                        println!("      frame failed: {:?}", e);
                    }
                }
            }
            let secs = timer.since(t0) / 1_000_000;
            println!(
                "      {} frames in {} s, {} failed; {} submitted, {} results, {} decoded, window {}",
                frames,
                secs,
                failures,
                submitted,
                results,
                decoded,
                dec.denom()
            );
            if let Some((ms, side)) = dec.last_cost() {
                println!("      core 1: {ms} ms decode, {side} px side");
            }
            report.check("camera delivers frames", frames > 0 && failures == 0);
            report.check("core 1 returns results", results > 0);

            // A cancel with a job in flight: the loop above left one, and a
            // fresh submit cancelled at once makes another. Each must leave
            // the worker idle rather than finished with nobody to take it.
            dec.cancel();
            let left = decode_core::is_idle();
            let fresh = match cam.frame_within(&timer, 1_000_000) {
                Ok(frame) => {
                    let sent = dec.submit(frame, Attempt::Fast).is_ok();
                    dec.cancel();
                    sent && decode_core::is_idle()
                }
                Err(_) => false,
            };
            report.check("a cancel mid-decode leaves the worker idle", left && fresh);
            // And the worker still works: a job after the cancels comes back.
            let mut back = false;
            if let Ok(frame) = cam.frame_within(&timer, 1_000_000) {
                if dec.submit(frame, Attempt::Fast).is_ok() {
                    let t1 = timer.now_us();
                    while timer.since(t1) < 2_000_000 {
                        if let Ok(Some(_)) = dec.poll(&mut payload) {
                            back = true;
                            break;
                        }
                    }
                }
            }
            payload.fill(0);
            report.check("the worker takes a job after a cancel", back);

            report.check("camera powers off", cam.set_power(Power::Off).is_ok());
            report.check(
                "a powered-down camera refuses a frame",
                matches!(
                    cam.frame_within(&timer, 200_000),
                    Err(CamError::PoweredDown)
                ),
            );
            report.check("camera powers back on", cam.set_power(Power::On).is_ok());
            let t0 = timer.now_us();
            let mut after = 0u32;
            while timer.since(t0) < 2_000_000 {
                if cam.frame_within(&timer, 1_000_000).is_ok() {
                    after += 1;
                }
            }
            println!("      {} frames in the two seconds after power-on", after);
            report.check("camera streams again", after > 0);

            // The frame wipe.
            {
                // Read through the data cache, the S3's only way to PSRAM: it
                // shows the zeros were written, not that PSRAM holds them
                // (that was measured across a reset, `cache.rs`).
                let through_cache = || {
                    let mut n = 0usize;
                    for i in 0..2 {
                        // SAFETY: core 0, and no `poll_done` runs while the
                        // slice lives, so nothing writes the frame under it:
                        // the engine writes only the bounce buffers, and
                        // `poll_done` copies them into a frame. The second
                        // count runs after `clear` has stopped the capture,
                        // `frame_ptr`'s own condition.
                        let f = unsafe {
                            core::slice::from_raw_parts(cam_dma::frame_ptr(i), cam_dma::FRAME_BYTES)
                        };
                        n += f.iter().filter(|&&b| b != 0).count();
                    }
                    n
                };
                let set = through_cache();
                let (bounce_set, _) = cam_dma::bounce_report();
                cam_dma::clear();
                let left = through_cache();
                let (bounce_left, parked) = cam_dma::bounce_report();
                println!(
                    "      {set} bytes set in the frames, {left} left after the wipe, of {} KB",
                    (cam_dma::FRAME_BYTES * 2) / 1024
                );
                report.check("frames wiped", set > 0 && left == 0);
                println!(
                    "      bounce: {bounce_set} bytes set, {bounce_left} left after the wipe, of 8064; engine parked after {parked:?} reads"
                );
                report.check(
                    "bounce buffers wiped",
                    bounce_set > 0 && bounce_left == 0 && parked.is_some(),
                );

                cam_dma::start_capture();
            }
        } else {
            report.check("camera and decoder available", false);
        }

        // ── The card session ─────────────────────────────────────────────────

        let t = timer.now_us();
        let session = sdhost::with_sd_card(&mut i2c, &mut timer, |kind| {
            let mut dev = WaveshareStorage::new(kind).ok_or("no card")?;
            let blocks = dev.blocks();
            let mut first_block = [0u8; 512];
            let single = dev.read(0, &mut first_block).is_ok();
            let mut run = [0u8; 2048];
            let many = dev.read_many(0, &mut run).is_ok() && run[..512] == first_block[..];
            let info = kassigner_fat32::fat32::mount_fat32(&mut dev);
            let wrote = info
                .as_ref()
                .ok()
                .and_then(|i| unused_blocks(blocks, i))
                .map(|first| (first, write_test(&mut dev, first)));
            let mount = info.map(|i| (i.total_sectors, i.sectors_per_cluster));
            Ok((
                kind,
                blocks,
                single,
                many,
                (first_block[510], first_block[511]),
                mount,
                wrote,
            ))
        });
        println!(
            "      card session {:?} in {} ms",
            session,
            timer.since(t) / 1000
        );
        match session {
            Ok((_, _, single, many, _, _, wrote)) => {
                report.check("card block 0 read", single);
                report.check("multi-block read agrees with single", many);
                match wrote {
                    Some((first, (w1, w2, restored))) => {
                        println!("      write test on unused blocks {}..{}", first, first + 3);
                        report.check("single-block write reads back", w1);
                        report.check("multi-block write reads back", w2);
                        report.check("original blocks restored", restored);
                    }
                    None => println!("      no unused blocks on this card: write test skipped"),
                }
            }
            Err(e) => {
                println!("      no card session: {}", e);
                report.check("card session (fails without a card)", false);
            }
        }

        // The display gets its pins back from the card. If this draws, the
        // restore worked.
        let restored =
            lcd.clear(BLACK).is_ok() && lcd.fill(Rect::new(0, h / 2 - 10, w, 20), WHITE).is_ok();
        report.check(
            "display draws after the card session (look: white band)",
            restored,
        );
        delay.delay_millis(1500);

        // ── The battery again, a minute into the run ─────────────────────────

        battery_state("at the end");
        println!("      battery raw at the end: {:?}", battery::read_raw());

        // ── Done ─────────────────────────────────────────────────────────────

        println!();
        println!("{} passed, {} failed", report.passed, report.failed);
        let colour = if report.failed == 0 { GREEN } else { RED };
        let _ = lcd.clear(colour);

        // Keep drawing touches so the unit stays useful on the bench.
        loop {
            if let Ok(State::One(p) | State::Two(p, _)) = touch.read() {
                let _ = lcd.fill(Rect::new(p.x.min(w - 4), p.y.min(h - 4), 4, 4), BLACK);
            }
            delay.delay_millis(10);
        }
    }

    /// Blocks the filesystem does not use: after the FAT32 volume if at least
    /// three fit there, else right after the MBR when the volume starts late
    /// enough to leave room. `None` if neither.
    fn unused_blocks(blocks: u32, info: &kassigner_fat32::fat32::Fat32Info) -> Option<u32> {
        let start = info
            .fat_start_sector
            .checked_sub(info.reserved_sectors as u32)?;
        let end = start.checked_add(info.total_sectors)?;
        if blocks >= end.checked_add(3)? {
            Some(end)
        } else if start >= 4 {
            Some(1)
        } else {
            None
        }
    }

    /// Save three unused blocks, write one with a single-block write and two
    /// with a multi-block write and read them back, then restore all three.
    /// Returns whether each step (single, multi-block, restore) read back
    /// right.
    fn write_test<D: BlockDevice>(dev: &mut D, first: u32) -> (bool, bool, bool) {
        let mut saved = [0u8; 1536];
        if dev.read_many(first, &mut saved).is_err() {
            return (false, false, false);
        }

        let mut one = [0u8; 512];
        for (i, b) in one.iter_mut().enumerate() {
            *b = (i as u8) ^ 0xA5;
        }
        let mut back = [0u8; 512];
        let single =
            dev.write(first, &one).is_ok() && dev.read(first, &mut back).is_ok() && back == one;

        let mut two = [0u8; 1024];
        for (i, b) in two.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7) ^ 0x3C;
        }
        let mut back2 = [0u8; 1024];
        let multi = dev.write_many(first + 1, &two).is_ok()
            && dev.read_many(first + 1, &mut back2).is_ok()
            && back2 == two;

        let mut back3 = [0u8; 1536];
        let restored = dev.write_many(first, &saved).is_ok()
            && dev.read_many(first, &mut back3).is_ok()
            && back3 == saved;

        (single, multi, restored)
    }

    /// Stop, having said why.
    fn halt(report: &Report) -> ! {
        println!("halted: {} passed, {} failed", report.passed, report.failed);
        loop {
            core::hint::spin_loop();
        }
    }

    #[panic_handler]
    fn panic(info: &core::panic::PanicInfo) -> ! {
        println!("PANIC: {}", info);
        loop {
            core::hint::spin_loop();
        }
    }
}
