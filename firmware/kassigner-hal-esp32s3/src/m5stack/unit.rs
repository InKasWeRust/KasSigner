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

//! The M5Stack CoreS3, brought up in one call: the bus, the power rails, the
//! panel, the generator, the camera, the decoder on core 1, touch, the IMU
//! and the speaker. It returns a [`Unit`], the drivers behind
//! `kassigner-hal`'s traits as `impl Trait`, and [`Checks`], what the
//! bring-up found.
//!
//! The binary sets the allocator, through a function run first on the PSRAM
//! peripheral, and decides what to print. After the first level,
//! [`DEFAULT_BRIGHTNESS`], the backlight level is the caller's.
//!
//! The unit drives six parts on I2C0: the PMU, the expander, the camera
//! sensor, the touch controller, the IMU and the amplifier. The bus is a
//! static, so every device is `'static` and [`Unit::device`] makes more; its
//! cell refuses a second bring-up.

use core::cell::RefCell;

use embedded_hal_bus::i2c::RefCellDevice;
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_hal::delay::Delay;
use esp_hal::dma::aligned::DmaAlignedMut;
use esp_hal::dma::{BurstConfig, DmaRxBuf, ExternalBurstConfig};
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::i2s::master::{Channels, DataFormat, I2s, TdmConfig};
use esp_hal::lcd_cam::cam::{Camera as DvpCamera, Config as CamConfig};
use esp_hal::lcd_cam::LcdCam;
use esp_hal::peripherals::{Peripherals, PSRAM};
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::spi::Mode as SpiMode;
use esp_hal::system::{CpuControl, Stack};
use esp_hal::time::{Duration, Rate};
use esp_hal::timer::timg::TimerGroup;
use esp_hal::timer::PeriodicTimer;
use esp_hal::Blocking;
use mipidsi::interface::SpiInterface;
use mipidsi::models::ILI9342CRgb565;
use mipidsi::Builder;
use static_cell::StaticCell;

use kassigner_hal::battery::{self, Battery, Reading};
use kassigner_hal::camera::Camera;
use kassigner_hal::decoder::Decoder;
use kassigner_hal::display::{Backlight, Display, Rect};
use kassigner_hal::input::Touch;
use kassigner_hal::or_fail;
use kassigner_hal::pins::m5stack as pins;

use super::backlight::M5Backlight;
use super::camera::{self, M5Camera};
use super::decoder::M5Decoder;
use super::dvp::EspDvp;
use super::imu;
use super::ring::{self, DmaRing};
use super::speaker::{self, M5Speaker};
use super::touch::M5Touch;
use super::{panel, pmu, sensor};
use crate::decode_core;
use crate::entropy::Rng;
use crate::i2c_bus::Recovering;
use crate::paint;
use crate::panel::Panel;
use crate::systimer::SysTimer;
use kassigner_hal::drbg::{Drbg, DrbgError};

/// The shared bus. It frees a held SDA before every transfer; see
/// [`crate::i2c_bus`].
pub type Bus = RefCell<Recovering<I2c<'static, Blocking>>>;

/// The backlight level the unit comes up at: 102 of 255, 40%; full is too
/// bright.
pub const DEFAULT_BRIGHTNESS: u8 = 102;

/// One device on it.
pub type Device = RefCellDevice<'static, Recovering<I2c<'static, Blocking>>>;

/// Bytes of stack the decode worker gets on the second core: 24 KB. The
/// same worker on the Waveshare peaked at 16,112, and its flood fill queues
/// on the heap, so the depth does not grow with the picture. The bytes come
/// out of the main stack's room (peak 78,608 of 140,888 on the M5).
pub const CORE1_STACK_BYTES: usize = 24_576;

/// Why the unit could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bus is already up: `bring_up` was called twice.
    AlreadyUp,
    /// A peripheral refused its configuration; the name says which.
    Peripheral(&'static str),
    /// The PMU, which powers the processor, or the I/O expander, which waits
    /// in reset on the PMU's power-good line, would not initialise. The value
    /// names which, and at which register, since the fix differs.
    Pmu(pmu::InitError),
    /// The camera sensor would not initialise.
    Sensor,
    /// The camera's capture would not set up: its DMA buffer or the DVP
    /// interface. Its own variant, so the halt screen can say the camera
    /// failed.
    Camera(&'static str),
    /// The decoder would not come up; it always does. A core 1 that did not
    /// start is [`Checks::core1`].
    Decoder,
    /// The external RAM did not come up, so the heap would be empty, or the
    /// boot's clear did not cover it, so it would hold the last run's bytes.
    Psram,
    /// The generator's cipher failed its known-answer test: a broken build,
    /// not a broken board. A generator that only failed to seed is carried
    /// in [`Unit::rng`] poisoned and reported through [`Checks::rng`].
    Generator(DrbgError),
}

/// A bring-up that failed, [`kassigner_hal::unit::Failed`] with this
/// board's [`Error`]: the panel comes back lit when it was up.
pub type Failed<L> = kassigner_hal::unit::Failed<Error, L>;

/// What the bring-up found out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checks {
    /// Whether the decode worker is running on the second core.
    pub core1: bool,
    /// Whether the generator passed its start-up health tests and seeded the
    /// DRBG.
    pub rng: bool,
    /// Whether the SAR ADC was converting for the generator before it
    /// seeded: the health tests pass on the fast clock alone, so they cannot
    /// tell.
    pub adc: bool,
    /// Whether the gyro is running, so the seed can count it as a source.
    pub imu: bool,
    /// Why it is not, if it is not.
    pub imu_failure: Option<&'static str>,
    /// Microseconds the IMU took to answer after its reset.
    pub imu_reset_wait_us: u32,
    /// Whether the radio's power domain read back isolated and off.
    pub radio_off: bool,
    /// The brown-out detector as the bootloader left it, reported at boot;
    /// its analog reset is part of the verdict.
    pub brownout: crate::brownout::State,
    /// Whether the speaker's stream runs and its amplifier took its set-up;
    /// a unit without sound still signs.
    pub speaker: bool,
}

/// The unit's drivers.
pub struct Unit<L, C, D, T> {
    pub lcd: L,
    pub cam: C,
    pub dec: D,
    pub touch: T,
    /// The DRBG over the chip's tested source; the entropy capture reaches
    /// the raw source through [`Drbg::source`].
    pub rng: Drbg<Rng>,
    pub timer: SysTimer,
    pub delay: Delay,
    /// The speaker, writing its notes into the ring the I2S plays.
    pub speaker: M5Speaker,
    bus: &'static Bus,
    /// Whether core 0's 5 ms alarm runs, so [`Unit::rest`] may sleep.
    rests: bool,
}

impl<L, C, D, T> Unit<L, C, D, T> {
    /// Another device on the shared bus, for the IMU or the expander.
    pub fn device(&self) -> Device {
        RefCellDevice::new(self.bus)
    }

    /// The cell, through the PMU.
    ///
    /// # Errors
    ///
    /// `Io` when the bus transfer fails.
    pub fn battery(&self) -> Result<Reading, battery::Error> {
        super::battery::M5Battery::new(self.device()).read()
    }

    /// Sleep until the next interrupt, the 5 ms alarm at the latest, so the
    /// main loop does not run core 0 flat out on screens without the camera;
    /// without the alarm, return at once, since nothing might wake the core.
    pub fn rest(&self) {
        if self.rests {
            // SAFETY: `WAITI 0` waits, clock-gated, for any interrupt, and
            // changes nothing else; the alarm guarantees one within 5 ms.
            unsafe { core::arch::asm!("waiti 0") };
        }
    }
}

/// Core 0's alarm period.
const REST_MS: u64 = 5;

/// Core 0's alarm, for its handler to clear.
static mut ALARM: Option<PeriodicTimer<'static, Blocking>> = None;

/// The alarm's handler, which only clears the alarm, through esp-hal: the
/// timer group drops the alarm's enable when it fires and esp-hal's clear
/// sets it again. With only the interrupt bit cleared, the alarm rings once
/// and the next rest never wakes.
#[esp_hal::handler]
fn alarm_rang() {
    // SAFETY: set once at bring-up before the interrupt was enabled, and
    // touched only here after that, on core 0.
    unsafe {
        if let Some(alarm) = (*core::ptr::addr_of_mut!(ALARM)).as_mut() {
            alarm.clear_interrupt();
        }
    }
}

static BUS: StaticCell<Bus> = StaticCell::new();
/// The panel's transfer buffer, which keeps the last strip drawn, a
/// SeedQR's maybe. A plain static, so a panic clears it by name; handed out
/// once, since the bus cell refuses a second bring-up.
static mut SPI_BUF: [u8; panel::SPI_BUFFER_BYTES] = [0; panel::SPI_BUFFER_BYTES];
/// Core 1's stack, for the decode worker. A plain static: a cell is
/// initialised from a value, which at this size would be built on the stack
/// first. Handed out once.
static mut APP_CORE_STACK: Stack<CORE1_STACK_BYTES> = Stack::new();

/// What a panic stops besides the stacks, for `stack::wipe_and_halt`, which
/// runs it with both stacks cleared and core 1 parked: the decode worker's
/// image, payload and scratch, which a decode cut short leaves holding a
/// code's picture and bytes; the panel's transfer buffer; the camera,
/// stopped, its two buffers zeroed (mid-scan they hold the last frames) and
/// the PSRAM one written back; and the backlight, off, since the panel keeps
/// the last screen, a SeedQR maybe, and would show it until power-off if
/// lit.
///
/// The backlight is the PMU's DLDO1 rail, written over I2C0 taken afresh,
/// since the unit's driver may be mid-transfer; [`Recovering`] frees a
/// device holding SDA first. It runs last, as the one step that waits on
/// another chip; if it fails the panel stays lit.
pub fn quiesce() {
    decode_core::clear_for_panic();
    // SAFETY: this module's static, `SPI_BUFFER_BYTES` long; the display
    // driver it was lent to never runs again, with the other core parked and
    // this one halting.
    unsafe {
        crate::stack::clear(
            core::ptr::addr_of_mut!(SPI_BUF).cast::<u8>(),
            panel::SPI_BUFFER_BYTES,
        );
    }
    super::dvp::clear_for_panic();
    // SAFETY: I2C0 and its two pins, taken again for one write; the unit is
    // halting, so its driver over them never runs again.
    let (i2c0, sda, scl) = unsafe {
        (
            esp_hal::peripherals::I2C0::steal(),
            esp_hal::peripherals::GPIO12::steal(),
            esp_hal::peripherals::GPIO11::steal(),
        )
    };
    let Ok(i2c) = I2c::new(
        i2c0,
        I2cConfig::default()
            .with_frequency(Rate::from_khz(400))
            .with_bus_arbitration(true),
    ) else {
        return;
    };
    let mut i2c = Recovering::new(
        i2c.with_sda(sda).with_scl(scl),
        pins::I2C[0].gpio,
        pins::I2C[1].gpio,
    );
    let _ = pmu::set_rails(&mut i2c, pmu::BACKLIGHT, false);
}

/// What [`quiesce`] clears besides the decoder's buffers, each named with
/// the bytes set in it, for the panic probe: the panel's transfer buffer,
/// and the camera's two buffers once the camera is up.
#[cfg(feature = "panic-probe")]
pub fn probe_quiesced(mut each: impl FnMut(&'static str, usize)) {
    let at = core::ptr::addr_of!(SPI_BUF) as usize;
    each(
        "panel buffer",
        crate::stack::set_in(at, at + panel::SPI_BUFFER_BYTES),
    );
    let names = ["camera buffer 0", "camera buffer 1"];
    for (name, (at, len)) in names.into_iter().zip(super::dvp::probe_spans()) {
        if at != 0 {
            each(name, crate::stack::set_in(at, at + len));
        }
    }
}

/// Bring the unit up. `heap` makes the external RAM the allocator and
/// returns the bytes it gave; zero (the RAM not up, or not all cleared)
/// stops bring-up with [`Error::Psram`].
///
/// `heap` is a function pointer, not an `impl FnOnce`: generic, this body
/// and its DMA descriptor statics would compile in the calling crate, where
/// the Xtensa backend cannot always place them ("Cannot select
/// XtensaISD::PCREL_WRAPPER TargetConstantPool"). A closure that captures
/// nothing coerces to it.
///
/// # Errors
///
/// [`Error`] in a [`Failed`], with the panel if it was up.
pub fn bring_up(
    p: Peripherals,
    heap: fn(PSRAM<'static>) -> usize,
) -> Result<
    (
        Unit<impl Display, impl Camera, impl Decoder, impl Touch>,
        Checks,
    ),
    Failed<impl Display>,
> {
    // The radio first, off until reset, so every path out, a halt included,
    // leaves it off.
    let radio_off = crate::radio::power_down();

    // ── The bus, and the backlight dark ─────────────────────────────────
    //
    // Before the heap, as nothing here allocates. The backlight is the
    // PMU's DLDO1 rail, which a reset of the chip leaves on, and the panel
    // keeps its last picture through it, perhaps a SeedQR: the rail goes off
    // before the PSRAM clear. A PMU that does not answer yet stops nothing;
    // its boot sequence below leaves the rail off too.
    //
    // Arbitration check on, so a device driving SDA against a transfer ends
    // it with an error, not data; wrapped, so a device holding SDA is freed
    // first. A read of the PMU's rails that came back `Ok` with wrong bits
    // would be written back (`i2c_bus`).
    let i2c0 = I2c::new(
        p.I2C0,
        I2cConfig::default()
            .with_frequency(Rate::from_khz(400))
            .with_bus_arbitration(true),
    )
    .map_err(|_| Error::Peripheral("I2C0"))?
    .with_sda(p.GPIO12)
    .with_scl(p.GPIO11);
    let i2c0 = Recovering::new(i2c0, pins::I2C[0].gpio, pins::I2C[1].gpio);
    let bus: &'static Bus = BUS.try_init(RefCell::new(i2c0)).ok_or(Error::AlreadyUp)?;
    let mut i2c = RefCellDevice::new(bus);
    let _ = pmu::set_rails(&mut i2c, pmu::BACKLIGHT, false);

    // Then the heap, before anything allocates; `p.PSRAM` is taken and the
    // rest wired field by field. The binary states the PSRAM mode: esp-hal
    // 1.2 would otherwise probe, and an octal probe takes GPIO 33 to 37, this
    // board's panel and speaker pins.
    if heap(p.PSRAM) == 0 {
        return Err(Error::Psram.into());
    }

    let mut delay = Delay::new();
    let mut timer = SysTimer;

    // ── The rails and the panel ─────────────────────────────────────────
    pmu::init_axp2101(&mut i2c, &mut timer).map_err(Error::Pmu)?;
    pmu::init_aw9523b(&mut i2c, &mut timer).map_err(Error::Pmu)?;

    let spi = Spi::new(
        p.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(panel::SPI_MHZ))
            .with_mode(SpiMode::_0),
    )
    .map_err(|_| Error::Peripheral("SPI2"))?
    .with_sck(p.GPIO36)
    .with_mosi(p.GPIO37);
    let cs = Output::new(p.GPIO3, Level::High, OutputConfig::default());
    let dc = Output::new(p.GPIO35, Level::Low, OutputConfig::default());
    let spi_dev =
        ExclusiveDevice::new_no_delay(spi, cs).map_err(|_| Error::Peripheral("SPI device"))?;
    // SAFETY: handed out once (the bus cell refused a second bring-up), and
    // only `quiesce`, run once the unit is halting, names it too.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(SPI_BUF) };
    let di = SpiInterface::new(spi_dev, dc, buf);
    let display = Builder::new(ILI9342CRgb565, di)
        .color_order(panel::COLOR_ORDER)
        .invert_colors(panel::INVERSION)
        .orientation(panel::orientation())
        .init(&mut delay)
        .map_err(|_| Error::Peripheral("ILI9342C"))?;
    let mut lcd = Panel::new(
        display,
        M5Backlight::new(RefCellDevice::new(bus)),
        panel::SIZE,
    );
    // Black before any light: a reset clears neither the panel's memory nor
    // its picture, so the backlight comes on only once it is cleared.
    let _ = lcd.clear(0x0000);
    let _ = lcd.set_backlight(Backlight::Level(DEFAULT_BRIGHTNESS));

    // ── The generator ───────────────────────────────────────────────────
    let mut raw = Rng::new();
    raw.start();
    let rng_ok = raw.health_check();
    // Before the DRBG takes the source: whether the ADC is converting, which
    // the health tests cannot see.
    let adc = raw.adc_sampling();
    // The DRBG seeds from a window under the same tests; a failing source
    // yields a poisoned generator, not a missing one, so the unit comes up
    // and the verification screen says what failed.
    let rng = or_fail!(Drbg::new(raw).map_err(Error::Generator), lcd);
    let rng_ok = rng_ok && rng.poisoned().is_none();

    // ── The camera ──────────────────────────────────────────────────────
    //
    // The sensor is loaded twice, around the DVP configuration: the second
    // pass is what makes the first frame arrive.
    or_fail!(
        sensor::init(&mut i2c, &mut timer).map_err(|_| Error::Sensor),
        lcd
    );
    let lcd_cam = LcdCam::new(p.LCD_CAM);
    // The macro builds the descriptors and the buffer, in `DmaAlignedMut`.
    let cam_buf = or_fail!(
        esp_hal::dma_rx_buffer!(camera::FRAME_BYTES).map_err(|_| Error::Camera("DMA buffer")),
        lcd
    );
    // The second, for ping-pong capture (`dvp`), in PSRAM: in internal RAM
    // it would take 75 KB of the main loop's 128 KB of stack headroom.
    // Without it the camera captures one frame at a time. Its wipe writes
    // the zeros back out of the cache (`dvp`'s `clear`).
    let cam_spare = psram_frame();
    camera::ensure_lcd_clk_enabled();
    let dvp = or_fail!(
        DvpCamera::new(
            lcd_cam.cam,
            p.DMA_CH0,
            CamConfig::default().with_frequency(Rate::from_mhz(camera::PCLK_MHZ)),
        )
        .map_err(|_| Error::Camera("DVP")),
        lcd
    )
    .with_pixel_clock(p.GPIO45)
    .with_vsync(p.GPIO46)
    .with_h_enable(p.GPIO38)
    .with_data0(p.GPIO39)
    .with_data1(p.GPIO40)
    .with_data2(p.GPIO41)
    .with_data3(p.GPIO42)
    .with_data4(p.GPIO15)
    .with_data5(p.GPIO16)
    .with_data6(p.GPIO48)
    .with_data7(p.GPIO47);
    or_fail!(
        sensor::reinit(&mut i2c, &mut timer).map_err(|_| Error::Sensor),
        lcd
    );
    delay.delay_millis(500);
    camera::route_pins();
    let dvp = EspDvp::new(dvp, cam_buf);
    let dvp = match cam_spare {
        Some(spare) => dvp.with_spare(spare),
        None => dvp,
    };
    let cam = M5Camera::new(dvp, RefCellDevice::new(bus));

    // ── The decoder: its jobs go to core 1, started last ────────────────
    let dec = or_fail!(M5Decoder::new().ok_or(Error::Decoder), lcd);

    // ── Touch, and the IMU ──────────────────────────────────────────────
    let touch = M5Touch::new(RefCellDevice::new(bus));
    let imu_up = imu::init(&mut i2c, &mut timer);

    // ── The speaker: I2S first, then the amplifier ──────────────────────
    //
    // A 16,368-byte ring the I2S plays until reset, silent until the speaker
    // writes a note into it (`ring`). The amplifier answers only once the
    // I2S clocks run, so it comes after.
    let (mut ring_buffer, ring_descriptors) =
        esp_hal::dma_buffers_impl!(ring::RING_BYTES, ring::RING_CHUNK);
    ring_buffer.fill(0);
    let config = TdmConfig::new_tdm_philips()
        .with_sample_rate(Rate::from_hz(speaker::SAMPLE_RATE))
        .with_data_format(DataFormat::Data16Channel16)
        .with_channels(Channels::STEREO);
    let mut amp = false;
    let mut tones: (*mut u8, usize) = (core::ptr::null_mut(), 0);
    if let (Ok(mut looped), Ok(i2s)) = (
        DmaRing::new(ring_descriptors, ring_buffer),
        I2s::new(p.I2S1, p.DMA_CH1, config),
    ) {
        tones = looped.as_mut_ptr();
        let i2s_tx = i2s
            .i2s_tx
            .with_bclk(p.GPIO34)
            .with_ws(p.GPIO33)
            .with_dout(p.GPIO13)
            .build();
        if let Ok(transfer) = i2s_tx.write(looped) {
            // The ring plays until reset: the transfer is never ended.
            core::mem::forget(transfer);
            amp = speaker::init(&mut i2c, &mut timer).is_ok();
        }
    }
    let speaker = if tones.0.is_null() {
        // No ring: a speaker over a buffer nothing plays.
        static mut SILENT: [u8; 4] = [0; 4];
        // SAFETY: only here, once; the bus cell above refuses a second
        // bring-up.
        M5Speaker::new(unsafe { &mut *core::ptr::addr_of_mut!(SILENT) })
    } else {
        // SAFETY: the ring's buffer, which from here on only the DMA reads
        // and the speaker writes. Made once: the bus cell refuses a second
        // bring-up.
        M5Speaker::new(unsafe { core::slice::from_raw_parts_mut(tones.0, tones.1) })
    };

    // ── Core 0's alarm clock ────────────────────────────────────────────
    //
    // TIMG1's timer 0 fires every 5 ms on core 0, so the main loop can sleep
    // (`Unit::rest`) and still read a tap within milliseconds. Last, so a
    // failed bring-up leaves no interrupt running; held in `ALARM` for its
    // handler until reset.
    let mut alarm = PeriodicTimer::new(TimerGroup::new(p.TIMG1).timer0);
    alarm.set_interrupt_handler(alarm_rang);
    let rests = alarm.start(Duration::from_millis(REST_MS)).is_ok();
    // SAFETY: the one write to `ALARM`, once (the bus cell refuses a second
    // bring-up), before its interrupt is enabled; after it only the handler,
    // on core 0, touches it.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(ALARM);
        *slot = Some(alarm);
        if let (true, Some(alarm)) = (rests, slot.as_mut()) {
            alarm.listen();
        }
    }

    // ── Core 1, parked in the decode worker ─────────────────────────────
    //
    // Last, after everything that can fail, so a bring-up that fails leaves
    // no second core running.
    let mut cpu_control = CpuControl::new(p.CPU_CTRL);
    // SAFETY: the only reference ever made to this static, and only once,
    // since the bus cell refused a second bring-up above.
    let stack = unsafe { &mut *core::ptr::addr_of_mut!(APP_CORE_STACK) };
    // The stack's bottom, for the worker to clear it after each job; both
    // ends, named before core 1 runs on it, for a panic to stop core 1 and
    // clear it.
    let bottom = stack.bottom() as usize;
    crate::stack::core1_started(bottom, stack.top() as usize);
    // Zeroed for the stack probe, which reads the depth as the lowest
    // non-zero word.
    #[cfg(feature = "stack-probe")]
    // SAFETY: core 1's stack, which nothing runs on yet.
    unsafe {
        crate::stack::clear(bottom as *mut u8, stack.top() as usize - bottom)
    };
    // The cross-core interrupt core 0 wakes it with, from its idle wait.
    let wake = esp_hal::interrupt::software::SoftwareInterrupt::<1>::new(p.FROM_CPU_INTR1);
    let core1 = match cpu_control.start_app_core(stack, move || {
        decode_core::bind_wake(wake);
        decode_core::core1_main(bottom)
    }) {
        // The guard parks core 1 on drop: kept.
        Ok(guard) => {
            core::mem::forget(guard);
            true
        }
        Err(_) => false,
    };

    let checks = Checks {
        core1,
        rng: rng_ok,
        adc,
        imu: imu_up,
        imu_failure: imu::failure(),
        imu_reset_wait_us: imu::reset_wait_us(),
        radio_off,
        brownout: crate::brownout::read(),
        speaker: amp,
    };

    Ok((
        Unit {
            lcd,
            cam,
            dec,
            touch,
            rng,
            timer,
            delay,
            speaker,
            bus,
            rests,
        },
        checks,
    ))
}

/// Draw the middle of a frame into `area`: as much of the sensor's 320 by
/// 240 as fits, up to 240 wide, centred on the frame and in the area.
/// Returns where the picture went, for the scan's edge around it. The
/// sensor is mounted so the picture arrives flipped; [`camera::source_row`]
/// undoes that.
///
/// Sent in strips of [`VIEW_STRIP`] rows, one window and one transfer each:
/// a row at a time took 56 ms a pass, where the pixels take about 18 ms at
/// the panel's 40 MHz.
pub fn viewfinder<L: Display>(lcd: &mut L, frame: &[u8], area: Rect) -> Rect {
    let mut strip = [0u16; 240 * VIEW_STRIP];
    let w = usize::from(area.width).min(240).min(camera::FRAME_W);
    let h = usize::from(area.height).min(camera::FRAME_H);
    let (sx, sy) = ((camera::FRAME_W - w) / 2, (camera::FRAME_H - h) / 2);
    let x0 = area.x + (area.width - w as u16) / 2;
    let y0 = area.y + (area.height - h as u16) / 2;
    let mut cy = 0;
    while cy < h {
        let rows = (h - cy).min(VIEW_STRIP);
        for (r, out) in strip[..rows * w].chunks_exact_mut(w).enumerate() {
            let row = camera::source_row(sy + cy + r) * camera::FRAME_W + sx;
            for (cx, px) in out.iter_mut().enumerate() {
                *px = paint::grey(frame[row + cx], cx as u16, (cy + r) as u16);
            }
        }
        let _ = lcd.blit(
            Rect::new(x0, y0 + cy as u16, w as u16, rows as u16),
            &strip[..rows * w],
        );
        cy += rows;
    }
    Rect::new(x0, y0, w as u16, h as u16)
}

/// The camera's second frame buffer, in PSRAM (the heap is PSRAM alone on
/// this unit): `None` if the heap or the DMA refused it. 64-byte aligned and
/// a multiple of 64 long, filled in 64-byte bursts in descriptors of 4,032
/// bytes (63 bursts); esp-hal keeps the cache coherent. Never freed: it
/// lives as long as the camera.
fn psram_frame() -> Option<DmaRxBuf> {
    let layout = core::alloc::Layout::from_size_align(camera::FRAME_BYTES, 64).ok()?;
    // SAFETY: a non-zero layout, so `alloc_zeroed` is sound to call; null is
    // checked below.
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: a fresh, zeroed allocation of exactly this length, owned here
    // and never freed, so a `'static` slice over it is the only reference.
    let frame: &'static mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(ptr, camera::FRAME_BYTES) };
    let buffer = DmaAlignedMut::new(frame).ok()?;
    let descriptors = esp_hal::dma_descriptors_impl!(camera::FRAME_BYTES, 4032);
    let burst = BurstConfig {
        external_memory: ExternalBurstConfig::Size64,
        ..BurstConfig::default()
    };
    DmaRxBuf::new_with_config(descriptors, buffer, burst).ok()
}

/// Rows the viewfinder sends at a time, as the screens are drawn: a 7.5 KB
/// buffer on the stack.
const VIEW_STRIP: usize = 16;

// Ties the bus, panel and camera pins above, written as `peripherals.GPIOn`
// that no table can index, to `kassigner-hal`'s netlist-checked map, at
// compile time.
const _: () = {
    assert!(pins::I2C[0].gpio == 12 && pins::I2C[1].gpio == 11);
    assert!(pins::SPI[0].gpio == 36 && pins::SPI[1].gpio == 37);
    assert!(pins::DISPLAY[0].gpio == 3 && pins::DISPLAY[1].gpio == 35);
    assert!(pins::CAMERA[0].gpio == 45 && pins::CAMERA[1].gpio == 46);
    assert!(pins::CAMERA[2].gpio == 38 && pins::CAMERA[3].gpio == 39);
    assert!(pins::CAMERA[4].gpio == 40 && pins::CAMERA[5].gpio == 41);
    assert!(pins::CAMERA[6].gpio == 42 && pins::CAMERA[7].gpio == 15);
    assert!(pins::CAMERA[8].gpio == 16 && pins::CAMERA[9].gpio == 48);
    assert!(pins::CAMERA[10].gpio == 47);
};
