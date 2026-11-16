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

//! The Waveshare ESP32-S3-Touch-LCD-2, brought up in one call.
//!
//! The same shape as the M5's `unit`, with this board's parts: a second
//! core parked in the decode worker, two buses, an ST7789 with no reset line,
//! a backlight and a camera clock both on LEDC, an OV5640 brought up twice
//! around a power-down pulse, and the camera pins routed by hand through the
//! GPIO matrix. The M5's module says what a bring-up is and is not.
//!
//! # LEDC
//!
//! The camera's 20 MHz clock and the backlight's 1 kHz PWM live as long as
//! the program: they are statics, so the bring-up needs no allocator.
//!
//! # The second core
//!
//! Its stack is a static handed to esp-hal, and the guard esp-hal returns is
//! forgotten, since dropping it parks the core; core 1 stays in the decode
//! worker. A core that will not start is not an error: the unit decodes on
//! this core instead, slower, and [`Checks`] says so.

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};

use embedded_hal_bus::i2c::RefCellDevice;
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_hal::delay::Delay;
use esp_hal::gpio::{DriveMode, Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::ledc::channel::ChannelIFace;
use esp_hal::ledc::timer::TimerIFace;
use esp_hal::ledc::{channel, timer, LSGlobalClkSource, Ledc, LowSpeed};
use esp_hal::peripherals::{Peripherals, PSRAM};
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::spi::Mode as SpiMode;
use esp_hal::system::{CpuControl, Stack};
use esp_hal::time::{Duration, Rate};
use esp_hal::timer::timg::TimerGroup;
use esp_hal::timer::PeriodicTimer;
use esp_hal::Blocking;
use mipidsi::interface::{Interface, SpiInterface};
use mipidsi::models::ST7789;
use mipidsi::Builder;
use static_cell::StaticCell;

use kassigner_hal::camera::Camera;
use kassigner_hal::decoder::Decoder;
use kassigner_hal::display::{Backlight, Display, Rect};
use kassigner_hal::input::Touch;
use kassigner_hal::or_fail;
use kassigner_hal::pins::waveshare as pins;
use kassigner_hal::speaker::Silent;

use super::backlight::WaveshareBacklight;
use super::camera::WaveshareCamera;
use super::decoder::WaveshareDecoder;
use super::sdhost;
use super::touch::WaveshareTouch;
use super::{cam_dma, decode_core, imu, panel, sensor};
use crate::entropy::Rng;
use crate::gpio_matrix;
use crate::i2c_bus::Recovering;
use crate::paint;
use crate::panel::Panel;
use crate::systimer::SysTimer;
use kassigner_hal::drbg::{Drbg, DrbgError};

/// The shared bus: the touch controller and the IMU. It frees a held SDA
/// before every transfer; see [`crate::i2c_bus`].
pub type Bus = RefCell<Recovering<I2c<'static, Blocking>>>;

/// One device on it.
pub type Device = RefCellDevice<'static, Recovering<I2c<'static, Blocking>>>;

/// The camera's own bus.
pub type CameraBus = I2c<'static, Blocking>;

/// Bytes of stack the decode worker gets on the second core.
pub const CORE1_STACK_BYTES: usize = 49_152;

/// The backlight level the unit comes up at.
pub const DEFAULT_BRIGHTNESS: u8 = 39;

/// What a panic stops besides the stacks, for `stack::wipe_and_halt` (both
/// stacks cleared, core 1 parked): the decode worker's image, payload and
/// scratch; the panel's transfer buffer; the camera, stopped, its two PSRAM
/// frames and two bounce buffers zeroed and written back; and the backlight,
/// off, since the panel keeps the last screen, maybe a SeedQR. Any of the
/// buffers may hold a SeedQR's picture. The backlight is LEDC registers,
/// written whatever state the drivers are in; duty zero is dark.
pub fn quiesce() {
    decode_core::clear_for_panic();
    // SAFETY: this module's static, `SPI_BUFFER_BYTES` long; the display
    // driver it was lent to never runs again: the other core is parked and
    // this one is halting.
    unsafe {
        crate::stack::clear(
            core::ptr::addr_of_mut!(SPI_BUF).cast::<u8>(),
            panel::SPI_BUFFER_BYTES,
        );
    }
    cam_dma::clear_for_panic();
    let _ = crate::panel::Backlight::set(&mut WaveshareBacklight, Backlight::Off);
}

/// What [`quiesce`] clears besides the decoder's buffers, each named with
/// the bytes set in it, for the panic probe: the panel's transfer buffer,
/// and the camera's frames and bounce buffers once the camera is up.
#[cfg(feature = "panic-probe")]
pub fn probe_quiesced(mut each: impl FnMut(&'static str, usize)) {
    let at = core::ptr::addr_of!(SPI_BUF) as usize;
    each(
        "panel buffer",
        crate::stack::set_in(at, at + panel::SPI_BUFFER_BYTES),
    );
    let names = [
        "camera frame 0",
        "camera frame 1",
        "bounce buffer A",
        "bounce buffer B",
    ];
    for (name, (at, len)) in names.into_iter().zip(cam_dma::probe_spans()) {
        if at != 0 {
            each(name, crate::stack::set_in(at, at + len));
        }
    }
}

/// Why the unit could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bus is already up: `bring_up` was called twice.
    AlreadyUp,
    /// A peripheral refused its configuration; the name says which.
    Peripheral(&'static str),
    /// The camera sensor would not initialise.
    Sensor,
    /// The camera or the decoder would not take its buffers.
    Camera,
    Decoder,
    /// The external RAM did not come up: no chip found, so the heap would be
    /// empty; or the boot's clear did not cover all of it, so the last run's
    /// bytes would be the heap's.
    Psram,
    /// The generator's cipher failed its known-answer test: a broken build,
    /// not a broken board. One that only failed to seed is carried in
    /// [`Unit::rng`] poisoned and reported through [`Checks::rng`].
    Generator(DrbgError),
}

/// A bring-up that failed, [`kassigner_hal::unit::Failed`] with this
/// board's [`Error`]: on a black screen a camera that does not answer looks
/// like a dead board. The panel comes back lit from the generator on; a
/// failure in the LEDC set-up just before returns it dark.
pub type Failed<L> = kassigner_hal::unit::Failed<Error, L>;

/// What the bring-up found out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checks {
    /// Whether the decode worker is running on the second core.
    pub core1: bool,
    /// Whether the generator passed its health tests on one window at start,
    /// and then seeded the DRBG the flow draws from.
    pub rng: bool,
    /// Whether the SAR ADC was converting for the generator when it seeded
    /// the DRBG. The health tests pass on the fast clock alone, so they
    /// cannot tell a converter left idle.
    pub adc: bool,
    /// The sensor's product id, expected [`sensor::PRODUCT_ID`].
    pub sensor_id: u16,
    /// Whether the gyro is running, so the seed can count it as a source.
    pub imu: bool,
    /// Why it is not, if it is not.
    pub imu_failure: Option<imu::Failure>,
    /// Whether the radio's power domain read back isolated and off.
    pub radio_off: bool,
    /// The brown-out detector as the bootloader left it, shown at boot; its
    /// analog reset is part of the verdict.
    pub brownout: crate::brownout::State,
}

/// The unit's drivers.
pub struct Unit<L, C, D, T> {
    pub lcd: L,
    pub cam: C,
    pub dec: D,
    pub touch: T,
    /// The DRBG over the chip's tested source. The raw source is beneath it,
    /// through [`Drbg::source`], for the entropy capture.
    pub rng: Drbg<Rng>,
    pub timer: SysTimer,
    pub delay: Delay,
    /// The camera's bus, for the autofocus upload and the sensor registers.
    pub cam_i2c: CameraBus,
    /// No speaker on this board, and never one: it plays nothing.
    pub speaker: Silent,
    bus: &'static Bus,
    /// The touch interrupt line, pulled up, owned for the unit's life.
    _touch_int: Input<'static>,
    /// Whether core 0's 5 ms alarm runs, so [`Unit::rest`] may sleep.
    rests: bool,
}

impl<L, C, D, T> Unit<L, C, D, T> {
    /// Another device on the shared bus, for the IMU.
    pub fn device(&self) -> Device {
        RefCellDevice::new(self.bus)
    }

    /// Sleep until the next interrupt, the 5 ms alarm at the latest, between
    /// passes on screens without the camera. Without the alarm it returns at
    /// once: nothing might wake the core.
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

/// The alarm's handler: waking core 0 was the point, so it only clears the
/// alarm, through esp-hal. Clearing the interrupt bit alone is not enough:
/// the timer group drops the alarm's enable when it fires, and esp-hal's
/// clear sets it again for a periodic timer. Otherwise it rings once and the
/// next rest never wakes.
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

/// Set by the first [`bring_up`]: a second is refused before it touches
/// anything, the panel first among them.
static BROUGHT_UP: AtomicBool = AtomicBool::new(false);
static BUS: StaticCell<Bus> = StaticCell::new();
/// The panel's transfer buffer, where the display driver gathers pixels
/// before each write; the last strip drawn, maybe a SeedQR's, stays in it. A
/// plain static, so a panic clears it by name; a second bring-up is refused
/// ([`BROUGHT_UP`]), so it is handed out once.
static mut SPI_BUF: [u8; panel::SPI_BUFFER_BYTES] = [0; panel::SPI_BUFFER_BYTES];
static LEDC: StaticCell<Ledc<'static>> = StaticCell::new();
static XCLK_TIMER: StaticCell<timer::Timer<'static, LowSpeed>> = StaticCell::new();
static XCLK_CHANNEL: StaticCell<channel::Channel<'static, LowSpeed>> = StaticCell::new();
static BACKLIGHT_TIMER: StaticCell<timer::Timer<'static, LowSpeed>> = StaticCell::new();
static BACKLIGHT_CHANNEL: StaticCell<channel::Channel<'static, LowSpeed>> = StaticCell::new();
/// Core 1's stack, which the decode worker parks on. A plain static: it is
/// too large to build as a value.
static mut APP_CORE_STACK: Stack<CORE1_STACK_BYTES> = Stack::new();

/// `SWRESET`: the display off at once, the memory left as it was (ST7789T3
/// 9.1.2), and 5 ms before the next command.
const SWRESET: u8 = 0x01;
const SWRESET_MS: u32 = 5;
/// `CASET`, `RASET`, `RAMWR`: the window, then the memory write. All three
/// are allowed in sleep, where a software reset leaves the panel (9.1.20 to
/// 9.1.22).
const CASET: u8 = 0x2A;
const RASET: u8 = 0x2B;
const RAMWR: u8 = 0x2C;

/// Blank the panel and write its whole memory black, before the driver's
/// start-up turns the display on: a reset of the chip leaves the panel
/// showing its last picture, and neither of the panel's resets clears its
/// memory (9.1.22), so without this the start-up shows that picture again.
///
/// The window is the native 240x320, as a software reset leaves the address
/// mode. Three bytes a pixel cover the memory in the 18-bit format a reset
/// leaves; in the 16-bit one the write wraps and covers it again. Zeros are
/// black once the start-up turns inversion on, as `clear(0x0000)` is. A
/// failed write is not reported here: the driver's start-up, next, reports a
/// panel that does not answer.
pub fn blank<DI: Interface<Word = u8>>(di: &mut DI, delay: &mut Delay) {
    let column_end = (panel::NATIVE.width - 1).to_be_bytes();
    let row_end = (panel::NATIVE.height - 1).to_be_bytes();
    let pixels = u32::from(panel::NATIVE.width) * u32::from(panel::NATIVE.height);
    let _ = di.send_command(SWRESET, &[]);
    delay.delay_millis(SWRESET_MS);
    let _ = di.send_command(CASET, &[0, 0, column_end[0], column_end[1]]);
    let _ = di.send_command(RASET, &[0, 0, row_end[0], row_end[1]]);
    let _ = di.send_command(RAMWR, &[]);
    let _ = di.send_repeated_pixel([0u8; 3], pixels);
}

/// Bring the unit up, with the camera module this unit carries.
///
/// # Errors
///
/// [`Error`] names the part that refused. `heap` makes the external RAM the
/// allocator and returns how many bytes it gave it; zero (the RAM did not
/// come up, or was not all cleared) stops bring-up with [`Error::Psram`].
///
/// `heap` is a function pointer, not an `impl FnOnce`: a generic makes this
/// body part of the calling crate, DMA descriptor statics and all, and the
/// Xtensa backend cannot always place those ("Cannot select
/// XtensaISD::PCREL_WRAPPER TargetConstantPool"). A closure that captures
/// nothing coerces on its own.
pub fn bring_up(
    p: Peripherals,
    module: sensor::Module,
    heap: fn(PSRAM<'static>) -> usize,
) -> Result<
    (
        Unit<impl Display, impl Camera, impl Decoder, impl Touch>,
        Checks,
    ),
    Failed<impl Display>,
> {
    // The radio before anything, off until the next reset: every path out of
    // here, a halt included, leaves it off.
    let radio_off = crate::radio::power_down();

    // One bring-up: a second would take the panel's buffer again.
    if BROUGHT_UP.swap(true, Ordering::AcqRel) {
        return Err(Error::AlreadyUp.into());
    }

    let mut delay = Delay::new();

    // ── The panel, before anything slow ─────────────────────────────────
    //
    // It keeps its memory and its picture through a reset of the chip,
    // perhaps a SeedQR, and nothing resets it: the board does not fit the
    // link (R16) from GPIO0 to its reset, so GPIO0, the BOOT button, is left
    // alone, and the driver sends a software reset, which clears neither.
    // So it is blanked, and its memory written black, before the PSRAM clear
    // and before the driver's start-up turns the display on ([`blank`]). The
    // backlight pin is left alone until LEDC takes it, dark, as v1.0.7 leaves
    // it: undriven, it keeps the backlight off.
    //
    // The card's lines first, set idle with the clocks the SD specification
    // asks for after power-up, while nothing else drives GPIO 38 and 39.
    sdhost::sd_pre_init();
    delay.delay_millis(10);
    sdhost::sd_power_up_clocks();
    delay.delay_millis(10);

    let spi = Spi::new(
        p.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(80))
            .with_mode(SpiMode::_0),
    )
    .map_err(|_| Error::Peripheral("SPI2"))?
    .with_sck(p.GPIO39)
    .with_mosi(p.GPIO38);
    let cs = Output::new(p.GPIO45, Level::High, OutputConfig::default());
    let dc = Output::new(p.GPIO42, Level::Low, OutputConfig::default());
    let spi_dev =
        ExclusiveDevice::new_no_delay(spi, cs).map_err(|_| Error::Peripheral("SPI device"))?;
    // SAFETY: handed out once (a second bring-up was refused above), and
    // nothing else names the buffer but `quiesce`, which runs only once the
    // unit is halting.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(SPI_BUF) };
    let mut di = SpiInterface::new(spi_dev, dc, buf);
    blank(&mut di, &mut delay);
    let display = Builder::new(ST7789, di)
        .color_order(panel::COLOR_ORDER)
        .invert_colors(panel::INVERSION)
        .display_size(panel::NATIVE.width, panel::NATIVE.height)
        .orientation(panel::orientation())
        .init(&mut delay)
        .map_err(|_| Error::Peripheral("ST7789"))?;
    let mut lcd = Panel::new(display, WaveshareBacklight, panel::SIZE);
    // Black through the driver too, before any light.
    let _ = lcd.clear(0x0000);

    // Then the heap, before anything allocates (nothing above does); `heap`
    // takes PSRAM out of `p`. The mode is the binary's to state: esp-hal 1.2
    // would otherwise probe, and an octal probe on the S3 takes GPIO 33 to
    // 37, which one unit's panel is wired to.
    if heap(p.PSRAM) == 0 {
        return Err(Failed {
            error: Error::Psram,
            panel: Some(lcd),
        });
    }

    let timer = SysTimer;

    // ── The main bus ────────────────────────────────────────────────────
    //
    // Arbitration check on, so a device driving SDA against a transfer ends
    // it with an error instead of data; wrapped, so a device left holding SDA
    // is freed before the next transfer (`i2c_bus`).
    let i2c0 = or_fail!(
        I2c::new(
            p.I2C0,
            I2cConfig::default()
                .with_frequency(Rate::from_khz(pins::I2C0_KHZ))
                .with_bus_arbitration(true),
        )
        .map_err(|_| Error::Peripheral("I2C0")),
        lcd
    )
    .with_sda(p.GPIO48)
    .with_scl(p.GPIO47);
    let i2c0 = Recovering::new(i2c0, pins::I2C0[0].gpio, pins::I2C0[1].gpio);
    let bus: &'static Bus = or_fail!(
        BUS.try_init(RefCell::new(i2c0)).ok_or(Error::AlreadyUp),
        lcd
    );

    // ── Core 0's alarm clock ────────────────────────────────────────────
    //
    // TIMG1's timer 0 fires every 5 ms on core 0, so the main loop can sleep
    // on screens without the camera (`Unit::rest`) and still read a tap
    // within a few milliseconds. It runs until reset, held in `ALARM`.
    let mut alarm = PeriodicTimer::new(TimerGroup::new(p.TIMG1).timer0);
    alarm.set_interrupt_handler(alarm_rang);
    let rests = alarm.start(Duration::from_millis(REST_MS)).is_ok();
    // SAFETY: the one write to `ALARM`, before its interrupt is enabled;
    // from here on only the handler, on core 0, touches it.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(ALARM);
        *slot = Some(alarm);
        if let (true, Some(alarm)) = (rests, slot.as_mut()) {
            alarm.listen();
        }
    }

    // ── Core 1, parked in the decode worker ─────────────────────────────
    let mut cpu_control = CpuControl::new(p.CPU_CTRL);
    // SAFETY: the only reference ever made to this static, and only once,
    // since the bus cell refused a second bring-up above.
    let stack = unsafe { &mut *core::ptr::addr_of_mut!(APP_CORE_STACK) };
    // Core 1's stack bounds, named before it runs: the bottom for the worker
    // to clear after each job, both ends for a panic to clear.
    let bottom = stack.bottom() as usize;
    crate::stack::core1_started(bottom, stack.top() as usize);
    // The stack probe reads core 1's depth as its lowest non-zero word: the
    // stack zeroed first, whatever it held before boot.
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
        // Dropping the guard would park the core: forgotten instead.
        Ok(guard) => {
            core::mem::forget(guard);
            true
        }
        Err(_) => false,
    };

    // ── The camera's bus, and the touch interrupt line ──────────────────
    let mut cam_i2c = or_fail!(
        I2c::new(
            p.I2C1,
            I2cConfig::default().with_frequency(Rate::from_khz(pins::I2C1_KHZ)),
        )
        .map_err(|_| Error::Peripheral("I2C1")),
        lcd
    )
    .with_sda(p.GPIO21)
    .with_scl(p.GPIO16);
    let touch_int = Input::new(p.GPIO46, InputConfig::default().with_pull(Pull::Up));

    // ── The card: not here ──────────────────────────────────────────────
    //
    // Nothing at boot needs it, and no card is touched before the generator
    // is checked and the fuses judged. `sdhost::with_sd_card` brings a card
    // up the first time a card job asks, and a boot without a card does not
    // wait for one.

    // ── LEDC: the camera's 20 MHz clock, and the backlight ──────────────
    {
        let ledc = or_fail!(
            LEDC.try_init(Ledc::new(p.LEDC)).ok_or(Error::AlreadyUp),
            lcd
        );
        ledc.set_global_slow_clock(LSGlobalClkSource::APBClk);

        let xclk_timer = or_fail!(
            XCLK_TIMER
                .try_init(ledc.timer::<LowSpeed>(timer::Number::Timer0))
                .ok_or(Error::AlreadyUp),
            lcd
        );
        or_fail!(
            xclk_timer
                .configure(timer::config::Config {
                    duty: timer::config::Duty::Duty2Bit,
                    clock_source: timer::LSClockSource::APBClk,
                    frequency: Rate::from_mhz(20),
                })
                .map_err(|_| Error::Peripheral("XCLK timer")),
            lcd
        );
        let xclk = or_fail!(
            XCLK_CHANNEL
                .try_init(ledc.channel(channel::Number::Channel0, p.GPIO8))
                .ok_or(Error::AlreadyUp),
            lcd
        );
        or_fail!(
            xclk.configure(channel::config::Config {
                timer: &*xclk_timer,
                duty_pct: 50,
                drive_mode: DriveMode::PushPull,
            })
            .map_err(|_| Error::Peripheral("XCLK channel")),
            lcd
        );

        let backlight_timer = or_fail!(
            BACKLIGHT_TIMER
                .try_init(ledc.timer::<LowSpeed>(timer::Number::Timer1))
                .ok_or(Error::AlreadyUp),
            lcd
        );
        or_fail!(
            backlight_timer
                .configure(timer::config::Config {
                    duty: timer::config::Duty::Duty8Bit,
                    clock_source: timer::LSClockSource::APBClk,
                    frequency: Rate::from_khz(1),
                })
                .map_err(|_| Error::Peripheral("backlight timer")),
            lcd
        );
        let backlight = or_fail!(
            BACKLIGHT_CHANNEL
                .try_init(ledc.channel(channel::Number::Channel1, p.GPIO1))
                .ok_or(Error::AlreadyUp),
            lcd
        );
        or_fail!(
            backlight
                .configure(channel::config::Config {
                    timer: &*backlight_timer,
                    duty_pct: 0,
                    drive_mode: DriveMode::PushPull,
                })
                .map_err(|_| Error::Peripheral("backlight channel")),
            lcd
        );
    }
    let _ = lcd.set_backlight(Backlight::Level(DEFAULT_BRIGHTNESS));
    delay.delay_millis(30);

    // ── The generator ───────────────────────────────────────────────────
    let mut raw = Rng::new();
    raw.start();
    let rng_ok = raw.health_check();
    // Read before the DRBG takes the source: whether the ADC the generator
    // draws on is converting, which the health tests cannot see.
    let adc = raw.adc_sampling();
    // The DRBG seeds here, from a window that goes through the same tests;
    // a source that fails them yields a poisoned generator, not a missing
    // one, so the unit still comes up and the verification screen says what
    // failed.
    let rng = or_fail!(Drbg::new(raw).map_err(Error::Generator), lcd);
    let rng_ok = rng_ok && rng.poisoned().is_none();

    // ── The sensor, twice around a power-down pulse, then the pins ──────
    //
    // PWDN held low keeps the camera powered. Without the pulse between the
    // two bring-ups the sensor answers on the bus but never produces a
    // picture: frames arrive and nothing in them decodes.
    let mut cam_pwdn = Output::new(p.GPIO17, Level::Low, OutputConfig::default());
    let sensor_id = sensor::product_id(&mut cam_i2c);
    or_fail!(
        sensor::init(&mut cam_i2c, module).map_err(|_| Error::Sensor),
        lcd
    );
    cam_pwdn.set_high();
    delay.delay_millis(20);
    cam_pwdn.set_low();
    delay.delay_millis(30);
    or_fail!(
        sensor::init(&mut cam_i2c, module).map_err(|_| Error::Sensor),
        lcd
    );
    delay.delay_millis(100);
    gpio_matrix::apply(&pins::CAMERA);
    delay.delay_millis(150);
    // The power-down pin goes to the camera, which drives it: low while it
    // is on, high in standby.
    let cam = or_fail!(WaveshareCamera::new(cam_pwdn).ok_or(Error::Camera), lcd);
    let dec = or_fail!(WaveshareDecoder::new().ok_or(Error::Decoder), lcd);

    // ── Touch, and the IMU ──────────────────────────────────────────────
    let touch = WaveshareTouch::new(RefCellDevice::new(bus));
    let mut sys = SysTimer;
    let imu_up = imu::init(&mut RefCellDevice::new(bus), &mut sys);
    let checks = Checks {
        core1,
        sensor_id,
        rng: rng_ok,
        adc,
        imu: imu_up,
        imu_failure: imu::failure(),
        radio_off,
        brownout: crate::brownout::read(),
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
            cam_i2c,
            speaker: Silent,
            bus,
            _touch_int: touch_int,
            rests,
        },
        checks,
    ))
}

/// Draw the middle of a frame into `area`: every other pixel of the capture,
/// a 240 by 240 picture, as much as fits, centred in the area. Returns where
/// it went, for the scan's edge around it.
///
/// The sensor is mounted turned, so a panel row is a frame column;
/// [`cam_dma::BPL`] is the frame's stride.
pub fn viewfinder<L: Display>(lcd: &mut L, frame: &[u8], area: Rect) -> Rect {
    /// The picture's side, in panel pixels: every other one of 480.
    const SIDE: usize = 240;
    let mut line = [0u16; SIDE];
    let w = usize::from(area.width).min(SIDE);
    let h = usize::from(area.height).min(SIDE);
    let (sx, sy) = ((SIDE - w) / 2, (SIDE - h) / 2);
    let x0 = area.x + (area.width - w as u16) / 2;
    let y0 = area.y + (area.height - h as u16) / 2;
    for cy in 0..h {
        let col = (sy + cy) * 2;
        for (cx, px) in line[..w].iter_mut().enumerate() {
            *px = paint::grey(
                frame[((sx + cx) * 2) * cam_dma::BPL + col],
                cx as u16,
                cy as u16,
            );
        }
        let _ = lcd.blit(Rect::new(x0, y0 + cy as u16, w as u16, 1), &line[..w]);
    }
    Rect::new(x0, y0, w as u16, h as u16)
}

// The pins above, against the map that was checked against the netlist.
const _: () = {
    assert!(pins::I2C0[0].gpio == 48 && pins::I2C0[1].gpio == 47 && pins::I2C0[2].gpio == 46);
    assert!(pins::I2C1[0].gpio == 21 && pins::I2C1[1].gpio == 16);
    assert!(pins::SPI2[0].gpio == 39 && pins::SPI2[1].gpio == 38);
    assert!(pins::DISPLAY[0].gpio == 45 && pins::DISPLAY[1].gpio == 42);
    assert!(pins::DISPLAY[2].gpio == 0 && pins::DISPLAY[3].gpio == 1);
    assert!(pins::CAMERA_XCLK.gpio == 8 && pins::CAMERA_PWDN.gpio == 17);
};
