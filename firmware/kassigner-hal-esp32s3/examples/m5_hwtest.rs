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

//! Hardware test for the M5Stack CoreS3, through this crate, `kassigner-hal`
//! and `kassigner-fat32`, not the signing firmware.
//!
//! Each part is exercised through its trait or its module, and every result
//! printed as `PASS` or `FAIL` on the serial monitor. The screen ends green
//! when everything passed, red otherwise.
//!
//! From this crate's directory, with the Xtensa toolchain:
//!
//! ```text
//! cargo +esp m5-hwtest
//! ```
//!
//! # The unit is built here, not by `unit::bring_up`
//!
//! `bring_up` stops at the first part that refuses, and a finished unit
//! does not lend the bare buses, a transfer to abandon or the sensor to
//! bring up twice; this test reports every part. So each part is built as
//! `bring_up` builds it, in its order: a change there is a change here.
//!
//! # What it asks of a person
//!
//! - Watch the colour bars: red, green and blue, left to right.
//! - Watch the backlight go full, dim, dark, and back.
//! - Touch the screen for eight seconds; a dot appears under each finger.
//! - Point the camera at a QR code during the eight-second capture, for the
//!   decode count to mean something.
//! - Run it once without a card and once with one, for the card-detect level.
//!
//! # The card is written only where the filesystem is not
//!
//! Block 0 is read, then again in a multi-block read, then the FAT32 volume
//! mounted. Three blocks the filesystem does not use, after the volume or
//! the MBR, are saved, written, read back and restored. Nothing the
//! filesystem holds is touched.
//!
//! # Measured, not assumed
//!
//! Frames with a DMA error are counted, the three LCD_CAM registers printed
//! once the capture is configured, and the expander's direction registers
//! read back after the boot sequence.
//!
//! # The bus is left stuck three times, on purpose
//!
//! After the bus scan, three times, a read from the IMU is started by hand
//! and abandoned with the IMU holding SDA low, as an interrupted transfer
//! leaves it. The next read goes through esp-hal's driver alone with the
//! arbitration check off, printed and not judged; then through the bus as
//! the unit builds it, which must free the line and read the right value;
//! then through the driver alone with the check on, which must fail rather
//! than hand back data.

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
    use esp_hal::dma::{DmaLoopBuf, DmaRxBuf};
    use esp_hal::gpio::{Level, Output, OutputConfig};
    use esp_hal::i2c::master::{Config as I2cConfig, I2c};
    use esp_hal::i2s::master::{Channels, DataFormat, I2s, TdmConfig};
    use esp_hal::lcd_cam::cam::{Camera as DvpCamera, CameraTransfer, Config as CamConfig};
    use esp_hal::lcd_cam::LcdCam;
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
    use kassigner_hal::pins::m5stack as pins;
    use kassigner_hal::speaker::{Note, Speaker as _};

    /// What this test plays: plain notes, enough to hear the amplifier work.
    /// The cues are `kassigner-fw`'s, which this crate does not depend on.
    const BOOT: Note = Note::new(800, 6000, 100);
    const CLICK: Note = Note::new(4000, 8000, 30);
    const DECODED: Note = Note::new(2400, 8000, 30);
    const GOOD: Note = Note::new(2000, 6000, 120);
    const BAD: Note = Note::new(300, 10000, 150);
    use kassigner_hal::timer::Timer;
    use kassigner_hal_esp32s3::decode_core;
    use kassigner_hal_esp32s3::efuse;
    use kassigner_hal_esp32s3::entropy::Rng;
    use kassigner_hal_esp32s3::i2c_bus::{line_high, MatrixLines, Recovering};
    use kassigner_hal_esp32s3::m5stack::backlight::M5Backlight;
    use kassigner_hal_esp32s3::m5stack::camera::{self, Capture, M5Camera};
    use kassigner_hal_esp32s3::m5stack::decoder::{self, M5Decoder};
    use kassigner_hal_esp32s3::m5stack::touch::M5Touch;
    use kassigner_hal_esp32s3::m5stack::unit::CORE1_STACK_BYTES;
    use kassigner_hal_esp32s3::m5stack::{battery, panel, pmu, sensor, speaker, storage};
    use kassigner_hal_esp32s3::panel::Panel;
    use kassigner_hal_esp32s3::systimer::SysTimer;
    use mipidsi::interface::SpiInterface;
    use mipidsi::models::ILI9342CRgb565;
    use mipidsi::Builder;
    use static_cell::StaticCell;

    esp_bootloader_esp_idf::esp_app_desc!();

    // The pins below are `peripherals.GPIOn`, which no table can index:
    // these tie each to the netlist-checked map at compile time.
    const _: () = {
        assert!(pins::I2C[0].gpio == 12 && pins::I2C[1].gpio == 11);
        assert!(pins::SPI[0].gpio == 36 && pins::SPI[1].gpio == 37);
        assert!(pins::DISPLAY[0].gpio == 3 && pins::DISPLAY[1].gpio == 35);
        assert!(pins::I2S[0].gpio == 34 && pins::I2S[1].gpio == 33 && pins::I2S[2].gpio == 13);
        assert!(pins::CAMERA[0].gpio == 45 && pins::CAMERA[1].gpio == 46);
        assert!(pins::CAMERA[2].gpio == 38 && pins::CAMERA[3].gpio == 39);
        assert!(pins::CAMERA[4].gpio == 40 && pins::CAMERA[5].gpio == 41);
        assert!(pins::CAMERA[6].gpio == 42 && pins::CAMERA[7].gpio == 15);
        assert!(pins::CAMERA[8].gpio == 16 && pins::CAMERA[9].gpio == 48);
        assert!(pins::CAMERA[10].gpio == 47);
    };

    const BLACK: u16 = 0x0000;
    const WHITE: u16 = 0xFFFF;
    const RED: u16 = 0xF800;
    const GREEN: u16 = 0x07E0;
    const BLUE: u16 = 0x001F;

    /// Core 1's stack, the unit's size: the decode worker parks on it.
    static mut APP_CORE_STACK: Stack<CORE1_STACK_BYTES> = Stack::new();

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

    /// esp-hal's DVP driver behind [`Capture`], one buffer only: the driver
    /// moves the camera and buffer into a transfer and back, so this holds
    /// one or the other.
    struct EspDvp<'d> {
        idle: Option<(DvpCamera<'d>, DmaRxBuf)>,
        busy: Option<CameraTransfer<'d, DmaRxBuf>>,
        /// Frames whose DMA reported an error.
        dma_errors: u32,
    }

    impl Capture for EspDvp<'_> {
        fn clear(&mut self) {
            if let Some(transfer) = self.busy.take() {
                let (_, cam, buf) = transfer.wait();
                self.idle = Some((cam, buf));
            }
            if let Some((_, buf)) = self.idle.as_mut() {
                buf.as_mut_slice().fill(0);
            }
        }

        fn start(&mut self) -> bool {
            if self.busy.is_some() {
                return true;
            }
            let Some((cam, buf)) = self.idle.take() else {
                return false;
            };
            match cam.receive(buf) {
                Ok(transfer) => {
                    self.busy = Some(transfer);
                    true
                }
                Err((_, cam, buf)) => {
                    self.idle = Some((cam, buf));
                    false
                }
            }
        }

        fn is_done(&self) -> bool {
            self.busy.as_ref().is_some_and(|t| t.is_done())
        }

        fn abort(&mut self) {
            if let Some(transfer) = self.busy.take() {
                self.idle = Some(transfer.stop());
            }
        }

        fn finish(&mut self) -> Option<&[u8]> {
            if let Some(transfer) = self.busy.take() {
                let (result, cam, buf) = transfer.wait();
                if result.is_err() {
                    self.dma_errors += 1;
                }
                self.idle = Some((cam, buf));
            }
            self.idle.as_ref().map(|(_, buf)| buf.as_slice())
        }
    }

    /// A luminance byte as neutral RGB565 grey. Green is the five-bit value
    /// doubled, so all three channels move in the same steps: six bits of
    /// green put it up to half a step ahead, a green cast in the dark tones.
    const fn grey(y: u8) -> u16 {
        let v = (y >> 3) as u16;
        (v << 11) | ((v << 1) << 5) | v
    }

    /// The BMI270's addresses, its `CHIP_ID` register and what it holds,
    /// datasheet section 5.2, as `m5stack::imu` has them.
    const IMU_ADDRESSES: [u8; 2] = [0x69, 0x68];
    const IMU_CHIP_ID: u8 = 0x00;
    const IMU_CHIP_ID_VALUE: u8 = 0x24;

    /// Leaving the bus stuck by hand, through the pins as `i2c_bus` drives
    /// them to free it: `waveshare_hwtest`'s, on this unit's pins.
    mod wedge {
        use kassigner_hal::pins::m5stack as pins;
        use kassigner_hal::timer::Timer;
        use kassigner_hal_esp32s3::i2c_bus::{line_high, Lines, MatrixLines};
        use kassigner_hal_esp32s3::systimer::SysTimer;

        pub const SDA: u8 = pins::I2C[0].gpio;
        pub const SCL: u8 = pins::I2C[1].gpio;

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
        /// I2C0. The caller sets the register pointer first: at `CHIP_ID`,
        /// 0x24, the first bit the IMU sends is a zero.
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
                // Stated, not probed: an octal probe takes GPIO 36 and 37,
                // this unit's panel clock and data. The CoreS3 is quad.
                mode: esp_hal::psram::PsramMode::QuadSpi,
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
        println!("KasSigner M5Stack CoreS3 hardware test");
        println!("through kassigner-hal-esp32s3, not the signing firmware");
        println!();

        // ── Core 1, parked in the decode worker ──────────────────────────────

        // As `unit::bring_up` starts it: the M5 decodes on core 1, as the
        // Waveshare does.
        let mut cpu_control = CpuControl::new(peripherals.CPU_CTRL);
        // SAFETY: the only reference ever made to this static.
        let stack = unsafe { &mut *core::ptr::addr_of_mut!(APP_CORE_STACK) };
        let bottom = stack.bottom() as usize;
        // The cross-core interrupt that wakes core 1 from its idle wait,
        // bound there as `unit::bring_up` binds it.
        let wake =
            esp_hal::interrupt::software::SoftwareInterrupt::<1>::new(peripherals.FROM_CPU_INTR1);
        let core1 = match cpu_control.start_app_core(stack, move || {
            decode_core::bind_wake(wake);
            decode_core::core1_main(bottom)
        }) {
            Ok(guard) => {
                // Dropping the guard would park the core, so it is forgotten.
                core::mem::forget(guard);
                true
            }
            Err(_) => false,
        };
        report.check("core 1 running the decode worker", core1);

        // ── The bus, and the parts on it ─────────────────────────────────────

        // As the unit builds it: the controller's arbitration check on, and
        // wrapped to free a held SDA before every transfer.
        let i2c0 = I2c::new(
            peripherals.I2C0,
            I2cConfig::default()
                .with_frequency(Rate::from_khz(400))
                .with_bus_arbitration(true),
        )
        .expect("I2C0")
        .with_sda(peripherals.GPIO12)
        .with_scl(peripherals.GPIO11);
        let bus = RefCell::new(Recovering::new(i2c0, wedge::SDA, wedge::SCL));
        let mut i2c = RefCellDevice::new(&bus);

        report.check(
            "AXP2101 power-up sequence",
            pmu::init_axp2101(&mut i2c, &mut timer).is_ok(),
        );
        report.check(
            "AW9523B power-up sequence",
            pmu::init_aw9523b(&mut i2c, &mut timer).is_ok(),
        );

        let id = pmu::expander_id(&mut i2c);
        println!(
            "      expander id {:02X?}, expected {:02X}",
            id,
            pmu::EXPANDER_ID
        );
        report.check("AW9523B chip id", id.is_ok_and(|v| v == pmu::EXPANDER_ID));

        let dirs = pmu::directions(&mut i2c);
        println!(
            "      directions {:02X?}, expected ({:02X}, {:02X})",
            dirs,
            pmu::CONFIG_P0,
            pmu::CONFIG_P1
        );
        report.check(
            "AW9523B input lines are inputs",
            dirs.is_ok_and(|d| d == (pmu::CONFIG_P0, pmu::CONFIG_P1)),
        );

        // Every rail but the backlight, which the panel lights once black.
        let up = pmu::BOOT_RAILS & !pmu::BACKLIGHT;
        let rails = pmu::rails(&mut i2c);
        println!("      LDO enables {:02X?}, expected {:02X}", rails, up);
        report.check("AXP2101 rails up", rails.is_ok_and(|r| r == up));

        print!("      bus answers at");
        for addr in 0x08u8..0x78 {
            let mut b = [0u8; 1];
            if i2c.read(addr, &mut b).is_ok() {
                print!(" {:02X}", addr);
            }
        }
        println!();

        // The ES7210 identified, read only: two ID registers.
        let mut es7210 = None;
        for addr in 0x40u8..=0x43 {
            let mut id1 = [0u8; 1];
            let mut id0 = [0u8; 1];
            if i2c.write_read(addr, &[0x3D], &mut id1).is_ok()
                && i2c.write_read(addr, &[0x3E], &mut id0).is_ok()
                && id1[0] == 0x72
                && id0[0] == 0x10
            {
                es7210 = Some(addr);
                break;
            }
        }
        println!("      ES7210 at {:02X?}", es7210);
        report.check("ES7210 identifies", es7210.is_some());

        // ── The bus, left stuck, three times ─────────────────────────────────
        //
        // The three reads over a held SDA that the module doc describes.
        let mut b = [0u8; 1];
        let imu_address = IMU_ADDRESSES.into_iter().find(|&a| {
            i2c.write_read(a, &[IMU_CHIP_ID], &mut b).is_ok() && b[0] == IMU_CHIP_ID_VALUE
        });
        let enables = MatrixLines::enables_set(wedge::SDA, wedge::SCL);
        println!(
            "      BMI270 at {:02X?}, enable bits set {}",
            imu_address, enables
        );
        if let Some(imu_address) = imu_address {
            let arbitration = |on: bool| {
                I2cConfig::default()
                    .with_frequency(Rate::from_khz(400))
                    .with_bus_arbitration(on)
            };

            // The check off, and the driver alone.
            let off = bus
                .borrow_mut()
                .inner()
                .apply_config(&arbitration(false))
                .is_ok();
            let pointer = i2c.write(imu_address, &[IMU_CHIP_ID]).is_ok();
            let stuck = wedge::imu_read(imu_address);
            let before = bus
                .borrow_mut()
                .inner()
                .write_read(imu_address, &[IMU_CHIP_ID], &mut b)
                .map(|()| b[0]);
            let on = bus
                .borrow_mut()
                .inner()
                .apply_config(&arbitration(true))
                .is_ok();
            println!(
                "      as it was (check off {}, pointer set {}, SDA held {}): {:02X?}, expected Ok({:02X}); check back on {}",
                off, pointer, stuck.held, before, IMU_CHIP_ID_VALUE, on
            );

            // Through the unit's bus, counted from the wedge on: the
            // pointer's write may itself free what the read above left.
            let pointer = i2c.write(imu_address, &[IMU_CHIP_ID]).is_ok();
            let (freed_before, _) = bus.borrow().recoveries();
            let stuck = wedge::imu_read(imu_address);
            println!(
                "      wedged: pointer set {}, IMU acked {}, driving a zero {}, SDA held low on I2C0 {}",
                pointer, stuck.acked, stuck.driving, stuck.held
            );
            let first = i2c
                .write_read(imu_address, &[IMU_CHIP_ID], &mut b)
                .map(|()| b[0]);
            let (freed, not_freed) = bus.borrow().recoveries();
            let released = line_high(wedge::SDA);
            println!(
                "      through the unit's bus: {:02X?}, freed {} not freed {}, SDA {}",
                first,
                freed,
                not_freed,
                if released { "high" } else { "still low" }
            );
            report.check(
                "a held SDA is freed before the next read",
                enables
                    && on
                    && stuck.held
                    && first == Ok(IMU_CHIP_ID_VALUE)
                    && freed == freed_before + 1
                    && not_freed == 0
                    && released,
            );

            // Through the driver alone, the check on.
            let pointer = i2c.write(imu_address, &[IMU_CHIP_ID]).is_ok();
            let stuck = wedge::imu_read(imu_address);
            println!(
                "      wedged again: pointer set {}, IMU acked {}, driving a zero {}, SDA held low on I2C0 {}",
                pointer, stuck.acked, stuck.driving, stuck.held
            );
            let bare = bus
                .borrow_mut()
                .inner()
                .write_read(imu_address, &[IMU_CHIP_ID], &mut b)
                .map(|()| b[0]);
            let after = i2c
                .write_read(imu_address, &[IMU_CHIP_ID], &mut b)
                .map(|()| b[0]);
            let (freed, not_freed) = bus.borrow().recoveries();
            println!(
                "      through the driver alone: {:02X?}; the next read through the unit's bus: {:02X?}, freed {} not freed {}",
                bare, after, freed, not_freed
            );
            report.check(
                "a read over a held SDA fails instead of returning data",
                stuck.held && bare.is_err() && after == Ok(IMU_CHIP_ID_VALUE) && not_freed == 0,
            );
        } else {
            report.check("a held SDA is freed before the next read", false);
            report.check(
                "a read over a held SDA fails instead of returning data",
                false,
            );
        }

        // ── The speaker: I2S first, then the amplifier ───────────────────────

        // esp-hal's looping DMA buffer: one descriptor that points back to
        // itself, capped at 4095 bytes, so 4092, a 21 ms loop at 48 kHz
        // stereo. The unit plays a four-descriptor ring (`m5stack::ring`).
        let (mut tx_buffer, tx_descriptors) = esp_hal::dma_buffers_impl!(4092, 4092);
        tx_buffer.fill(0);
        let tone_ptr = tx_buffer.as_mut_ptr();
        let tone_len = tx_buffer.len();
        let tx_buffer = DmaLoopBuf::new(tx_descriptors, tx_buffer).expect("I2S loop buffer");
        let i2s_config = TdmConfig::new_tdm_philips()
            .with_sample_rate(Rate::from_hz(speaker::SAMPLE_RATE))
            .with_data_format(DataFormat::Data16Channel16)
            .with_channels(Channels::STEREO);
        let mut i2s_ready = false;
        if let Ok(i2s) = I2s::new(peripherals.I2S1, peripherals.DMA_CH1, i2s_config) {
            let i2s_tx = i2s
                .i2s_tx
                .with_bclk(peripherals.GPIO34)
                .with_ws(peripherals.GPIO33)
                .with_dout(peripherals.GPIO13)
                .build();
            if let Ok(transfer) = i2s_tx.write(tx_buffer) {
                // The stream runs for the life of the program: the transfer
                // is never ended.
                core::mem::forget(transfer);
                i2s_ready = true;
            }
        }
        report.check("I2S circular stream", i2s_ready);

        let amp = speaker::init(&mut i2c, &mut timer);
        println!(
            "      AW88298 {:04X?}, status {:04X?}",
            amp,
            speaker::status(&mut i2c)
        );
        report.check("AW88298 configured", amp.is_ok());

        // SAFETY: the stream's buffer, which nothing else writes from here on.
        // The DMA engine reads it; the speaker writes it.
        let tones: &'static mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(tone_ptr, tone_len) };
        let mut spk = speaker::M5Speaker::new(tones);
        spk.tone(BOOT);
        spk.silence();

        // ── The panel ────────────────────────────────────────────────────────

        let spi = Spi::new(
            peripherals.SPI2,
            SpiConfig::default()
                .with_frequency(Rate::from_mhz(panel::SPI_MHZ))
                .with_mode(SpiMode::_0),
        )
        .expect("SPI2")
        .with_sck(peripherals.GPIO36)
        .with_mosi(peripherals.GPIO37);
        let cs = Output::new(peripherals.GPIO3, Level::High, OutputConfig::default());
        let dc = Output::new(peripherals.GPIO35, Level::Low, OutputConfig::default());
        let spi_dev = ExclusiveDevice::new_no_delay(spi, cs).expect("SPI device");
        let di = SpiInterface::new(spi_dev, dc, SPI_BUF.init([0; panel::SPI_BUFFER_BYTES]));
        let built = Builder::new(ILI9342CRgb565, di)
            .color_order(panel::COLOR_ORDER)
            .invert_colors(panel::INVERSION)
            .orientation(panel::orientation())
            .init(&mut delay);
        report.check("ILI9342C init, no reset pin", built.is_ok());
        let Ok(display) = built else {
            halt(&report);
        };
        let mut lcd = Panel::new(
            display,
            M5Backlight::new(RefCellDevice::new(&bus)),
            panel::SIZE,
        );

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
        let dark = pmu::rails(&mut i2c).map(|r| r & pmu::BACKLIGHT == 0);
        delay.delay_millis(800);
        let back = lcd.set_backlight(Backlight::Level(200)).is_ok();
        let lit = pmu::rails(&mut i2c).map(|r| r & pmu::BACKLIGHT != 0);
        report.check("backlight full and dim", full && dim);
        report.check("backlight off clears DLDO1", off && dark.unwrap_or(false));
        report.check("backlight back on", back && lit.unwrap_or(false));

        // ── The SoC: RNG and eFuse ───────────────────────────────────────────

        let mut rng = Rng::new();
        rng.start();
        let mut drawn = [0u8; 64];
        report.check(
            "RNG draw passes its health tests",
            rng.fill(&mut drawn).is_ok(),
        );
        // What the unit's start-up verdict counts, run on its own so the
        // code the verdict depends on is the code proven here.
        report.check("start-up generator check passes", rng.health_check());
        // The SAR ADC converting for the generator, read back: a report of
        // what `start` set up, not something the draw depends on.
        report.check("SAR ADC sampling for the generator", rng.adc_sampling());
        println!("      {}", efuse::decode(&efuse::words()).verdict().line());

        // ── Battery ──────────────────────────────────────────────────────────

        let cell = battery::read(&mut i2c);
        println!("      battery {:?}", cell);
        report.check("battery read", cell.is_ok());

        // ── Touch ────────────────────────────────────────────────────────────

        let mut touch = M5Touch::new(RefCellDevice::new(&bus));
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
                            spk.tone(CLICK);
                            spk.silence();
                        }
                    }
                }
                Err(_) => read_errors += 1,
            }
            delay.delay_millis(10);
        }
        println!("      {} presses, {} read errors", presses, read_errors);
        report.check("touch reports presses", presses > 0 && read_errors == 0);

        // ── Camera ───────────────────────────────────────────────────────────

        let t = timer.now_us();
        let first = sensor::init(&mut i2c, &mut timer);
        println!(
            "      sensor first bring-up {:?} in {} ms",
            first,
            timer.since(t) / 1000
        );
        report.check("GC0308 first bring-up", first.is_ok());

        let lcd_cam = LcdCam::new(peripherals.LCD_CAM);
        let cam_buf = esp_hal::dma_rx_buffer!(camera::FRAME_BYTES).expect("camera DMA buffer");
        camera::ensure_lcd_clk_enabled();
        let dvp = DvpCamera::new(
            lcd_cam.cam,
            peripherals.DMA_CH0,
            CamConfig::default().with_frequency(Rate::from_mhz(camera::PCLK_MHZ)),
        )
        .expect("DVP configuration")
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

        let second = sensor::reinit(&mut i2c, &mut timer);
        report.check("GC0308 second bring-up", second.is_ok());
        delay.delay_millis(500);
        camera::route_pins();

        let rb = sensor::read_back(&mut i2c);
        println!("      sensor registers {:02X?}", rb);
        report.check(
            "GC0308 holds the loaded configuration",
            rb.is_ok_and(|r| r.is_loaded()),
        );

        let (lcd_clock, cam_ctrl, cam_ctrl1) = camera::lcd_cam_registers();
        println!(
            "      LCD_CLOCK {:08X}  CAM_CTRL {:08X}  CAM_CTRL1 {:08X}",
            lcd_clock, cam_ctrl, cam_ctrl1
        );
        report.check(
            "LCD_CAM register clock forced on",
            lcd_clock & camera::LCD_CAM_CLK_EN != 0,
        );
        report.check(
            "LCD_CAM ends a frame on VSYNC",
            cam_ctrl & camera::CAM_VS_EOF_EN != 0,
        );
        report.check(
            "LCD_CAM in DE mode",
            cam_ctrl1 & camera::CAM_VH_DE_MODE_EN == 0,
        );

        let capture = EspDvp {
            idle: Some((dvp, cam_buf)),
            busy: None,
            dma_errors: 0,
        };
        let mut cam = M5Camera::new(capture, RefCellDevice::new(&bus));

        let Some(mut dec) = M5Decoder::new() else {
            halt(&report);
        };
        let mut payload = [0u8; decoder::MAX_PAYLOAD];

        println!("      capturing for eight seconds; show it a QR code");
        let _ = lcd.clear(BLACK);
        let t0 = timer.now_us();
        let mut frames = 0u32;
        let mut failures = 0u32;
        let mut submitted = 0u32;
        let mut results = 0u32;
        let mut decoded = 0u32;
        let mut line = [0u16; 240];
        while timer.since(t0) < 8_000_000 {
            // A result from core 1, if one is waiting. Taken first, so the
            // worker is idle again before the next submit.
            match dec.poll(&mut payload) {
                Ok(Some(Outcome::Found { len })) => {
                    results += 1;
                    decoded += 1;
                    // The length only: a decoded code can be a seed.
                    println!("      decoded {} bytes", len);
                    payload.fill(0);
                    spk.tone(DECODED);
                    spk.silence();
                }
                Ok(Some(_)) => results += 1,
                Ok(None) => {}
                Err(e) => println!("      decode error {:?}", e),
            }
            match cam.frame_within(&timer, 1_000_000) {
                Ok(frame) => {
                    frames += 1;
                    // The viewfinder: 240x180 from the centre, upright.
                    for cy in 0..180usize {
                        let row = camera::source_row(30 + cy) * camera::FRAME_W + 40;
                        for (cx, px) in line.iter_mut().enumerate() {
                            *px = grey(frame[row + cx]);
                        }
                        let _ = lcd.blit(Rect::new(40, 30 + cy as u16, 240, 1), &line);
                    }
                    match dec.submit(frame, Attempt::Fast) {
                        Ok(()) => submitted += 1,
                        Err(DecError::Busy) => {}
                        Err(e) => println!("      submit error {:?}", e),
                    }
                }
                Err(e) => {
                    failures += 1;
                    println!("      frame failed: {:?}", e);
                }
            }
        }
        let secs = timer.since(t0) / 1_000_000;
        println!(
            "      {} frames in {} s, {} failed, {} with a DMA error; {} submitted, {} results, {} decoded, window {}",
            frames,
            secs,
            failures,
            cam.capture().dma_errors,
            submitted,
            results,
            decoded,
            dec.denom()
        );
        report.check("camera delivers frames", frames > 0 && failures == 0);
        report.check("core 1 returns results", results > 0);

        // A cancel with a job in flight, one the loop may have left and one
        // submitted and cancelled at once: each must leave the worker idle,
        // not finished with nobody to take it.
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
        let rails_off = pmu::rails(&mut i2c).map(|r| r & pmu::CAMERA == 0);
        report.check("camera rails are off", rails_off.unwrap_or(false));
        report.check(
            "a powered-down camera refuses a frame",
            matches!(
                cam.frame_within(&timer, 200_000),
                Err(CamError::PoweredDown)
            ),
        );
        let t = timer.now_us();
        let on = cam.set_power(Power::On);
        println!(
            "      camera back on {:?} in {} ms",
            on,
            timer.since(t) / 1000
        );
        report.check("camera powers back on", on.is_ok());
        let t0 = timer.now_us();
        let mut after = 0u32;
        while timer.since(t0) < 2_000_000 {
            if cam.frame_within(&timer, 1_000_000).is_ok() {
                after += 1;
            }
        }
        println!("      {} frames in the two seconds after power-on", after);
        report.check("camera streams after a power cycle", after > 0);

        // The frame wipe, with the buffer holding what it last captured.
        // Through the capture, which `M5Camera::clear` delegates to: `finish`
        // lends the same buffer while idle, so the counts before and after
        // are of the memory a frame landed in.
        //
        // Not in a scope of its own: the camera's parts stay alive to the end
        // of the test. Dropped here, before the card session, they made the
        // restore check fail.
        let (mut dvp, _cam_i2c) = cam.release();
        let set = dvp
            .finish()
            .map(|f| f.iter().filter(|&&b| b != 0).count())
            .unwrap_or(0);
        dvp.clear();
        let left = dvp
            .finish()
            .map(|f| f.iter().filter(|&&b| b != 0).count())
            .unwrap_or(0);
        println!("      {set} bytes set in the frame, {left} left after the wipe");
        report.check("frame buffer wiped", set > 0 && left == 0);

        // ── Card, read only ──────────────────────────────────────────────────

        let tf = pmu::input(&mut i2c, pmu::TF_SW);
        println!(
            "      TF_SW is {}",
            match tf {
                Ok(true) => "high",
                Ok(false) => "low",
                Err(_) => "unreadable",
            }
        );
        report.check("card-detect line readable", tf.is_ok());

        let t = timer.now_us();
        let session = storage::with_card(&mut i2c, |card| {
            let kind = card.card_type();
            let blocks = card.blocks();
            let mut first_block = [0u8; 512];
            let single = card.read(0, &mut first_block).is_ok();
            let mut run = [0u8; 2048];
            let many = card.read_many(0, &mut run).is_ok() && run[..512] == first_block[..];
            let info = kassigner_fat32::fat32::mount_fat32(card);
            let wrote = info
                .as_ref()
                .ok()
                .and_then(|i| unused_blocks(blocks, i))
                .map(|first| (first, write_test(card, first)));
            let mount = info.map(|i| (i.total_sectors, i.sectors_per_cluster));
            (
                kind,
                blocks,
                single,
                many,
                (first_block[510], first_block[511]),
                mount,
                wrote,
            )
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
                println!("      no card session: {:?}", e);
                report.check("card session (fails without a card)", false);
            }
        }

        // The display gets its bus back from the card: if this draws, the
        // restore worked.
        let restored =
            lcd.clear(BLACK).is_ok() && lcd.fill(Rect::new(0, h / 2 - 10, w, 20), WHITE).is_ok();
        report.check(
            "display draws after the card session (look: white band)",
            restored,
        );
        delay.delay_millis(1500);

        // ── Done ─────────────────────────────────────────────────────────────

        println!();
        println!("{} passed, {} failed", report.passed, report.failed);
        let colour = if report.failed == 0 { GREEN } else { RED };
        let _ = lcd.clear(colour);
        if report.failed == 0 {
            spk.tone(GOOD);
            spk.silence();
        } else {
            spk.tone(BAD);
            spk.silence();
        }

        // Keep drawing touches so the unit stays useful on the bench.
        loop {
            if let Ok(State::One(p) | State::Two(p, _)) = touch.read() {
                let _ = lcd.fill(Rect::new(p.x.min(w - 4), p.y.min(h - 4), 4, 4), BLACK);
            }
            delay.delay_millis(10);
        }
    }

    /// Three blocks the filesystem does not use: after the FAT32 volume if
    /// they fit, else right after the MBR if the volume starts late enough.
    /// `None` if neither.
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
    /// with a multi-block write, then restore all three in one multi-block
    /// write. Returns whether each of those three writes read back right.
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
