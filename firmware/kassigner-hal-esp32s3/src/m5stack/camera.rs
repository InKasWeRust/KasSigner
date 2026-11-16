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

//! [`Camera`] for the M5, over esp-hal's DVP capture: one `receive` of
//! `lcd_cam::cam::Camera` into a 76,800-byte DMA buffer a frame, the path
//! proven on this unit. It comes in through [`Capture`], which
//! `dvp::EspDvp` implements on the device, so [`M5Camera`] builds and tests
//! on a host. `is_done()` is polled every 50 µs until the caller's
//! deadline; on expiry the partial frame is stopped and discarded.
//!
//! Every frame arrives bottom row first: [`source_row`] maps it.
//!
//! # Power is the rails
//!
//! `CAM_PWDN` reaches only the connector. The supply is what stops the
//! camera: ALDO3 carries the sensor's 3.3 V and the oscillator that clocks
//! it, BLDO1 and BLDO2 the connector's two other supplies. `Off` switches
//! all three off in one write; `On` switches them on in one write, as the
//! boot sequence does, then brings the sensor up again: without its supply
//! it lost its registers.
//!
//! # LCD_CAM set-up around esp-hal
//!
//! Two raw-register steps: [`ensure_lcd_clk_enabled`], and [`route_pins`]
//! over [`crate::gpio_matrix::apply`] with a table built from the
//! netlist-checked pin map. Nothing else needs writing: `LcdCam::new`
//! enables and resets the peripheral, and esp-hal's default configuration
//! sets `VS_EOF_EN` (bit 8 of `CAM_CTRL`).

use embedded_hal::i2c::I2c;
use kassigner_hal::camera::{Camera, Error, Format, Power};
use kassigner_hal::pins::{m5stack as pins, MatrixRoute};
use kassigner_hal::timer::{Deadline, Timer};

use crate::systimer::SysTimer;

use super::{pmu, sensor};

/// Frame width.
pub const FRAME_W: usize = 320;
/// Frame height.
pub const FRAME_H: usize = 240;
/// Bytes in a frame: one per pixel.
pub const FRAME_BYTES: usize = FRAME_W * FRAME_H;

/// Pixel clock for the capture, in MHz.
pub const PCLK_MHZ: u32 = 20;

/// Poll interval while a frame arrives, in microseconds.
const POLL_US: u32 = 50;

/// How long the rails settle after they come back on, in milliseconds: the
/// boot sequence's wait.
const RAIL_SETTLE_MS: u32 = 50;

/// Which stored row holds upright row `y`. Rows only: the columns are in
/// order.
pub const fn source_row(y: usize) -> usize {
    FRAME_H - 1 - y
}

/// The receiving end: something that captures one frame at a time into its
/// own buffer.
///
/// `dvp::EspDvp` implements this over `esp_hal::lcd_cam::cam::Camera` and
/// its `DmaRxBuf`.
pub trait Capture {
    /// Start capturing one frame. `false` if the capture could not start.
    fn start(&mut self) -> bool;

    /// Whether the frame in flight has finished.
    fn is_done(&self) -> bool;

    /// Stop the frame in flight and discard it.
    fn abort(&mut self);

    /// Zero the buffer frames are captured into. Here because the buffer is
    /// the capture's: [`Capture::finish`] only lends it.
    fn clear(&mut self);

    /// End a finished frame and lend it, once [`Capture::is_done`] returned
    /// true. `None` if there is no frame to lend.
    fn finish(&mut self) -> Option<&[u8]>;
}

/// The M5 camera: the capture, and a handle to the shared I2C bus for the
/// rails and the sensor when it is switched back on.
///
/// The sensor must already be up: the bring-up runs [`sensor::init`],
/// builds the DVP driver, then runs [`sensor::reinit`] and [`route_pins`].
pub struct M5Camera<C, I, T = SysTimer> {
    capture: C,
    i2c: I,
    timer: T,
    power: Power,
    started: bool,
}

impl<C: Capture, I: I2c> M5Camera<C, I, SysTimer> {
    /// Wrap a capture that is ready to run.
    pub fn new(capture: C, i2c: I) -> Self {
        Self::with_timer(capture, i2c, SysTimer)
    }
}

impl<C: Capture, I: I2c, T: Timer> M5Camera<C, I, T> {
    /// Wrap a capture, with the clock the deadline and the waits use: for
    /// tests, which cannot read SYSTIMER.
    pub fn with_timer(capture: C, i2c: I, timer: T) -> Self {
        Self {
            capture,
            i2c,
            timer,
            power: Power::On,
            started: false,
        }
    }

    /// The capture, for what the trait does not carry, such as a diagnostic
    /// count.
    pub fn capture(&self) -> &C {
        &self.capture
    }

    /// Give the capture and the bus handle back.
    pub fn release(self) -> (C, I) {
        (self.capture, self.i2c)
    }
}

impl<C: Capture, I: I2c, T: Timer> Camera for M5Camera<C, I, T> {
    /// The DMA receive buffers, zeroed, through the capture that owns them.
    /// The ping-pong's second is in PSRAM, which keeps its contents through a
    /// reset, so its zeros are written back out of the data cache.
    fn clear(&mut self) {
        self.started = false;
        self.capture.clear();
    }

    fn format(&self) -> Format {
        Format::new(FRAME_W as u16, FRAME_H as u16, 1)
    }

    fn frame(&mut self, deadline: Deadline) -> Result<&[u8], Error> {
        self.frame_idle(deadline, &mut || {})
    }

    /// The wait is a loop of short pauses; `idle` is called once a turn.
    fn frame_idle(&mut self, deadline: Deadline, idle: &mut dyn FnMut()) -> Result<&[u8], Error> {
        self.check()?;

        if !self.started {
            if !self.capture.start() {
                return Err(Error::Io);
            }
            self.started = true;
        }

        loop {
            if self.capture.is_done() {
                self.started = false;
                return match self.capture.finish() {
                    Some(f) if f.len() == FRAME_BYTES => Ok(f),
                    Some(f) => Err(Error::WrongLength {
                        expected: FRAME_BYTES,
                        got: f.len(),
                    }),
                    None => Err(Error::Io),
                };
            }

            if deadline.expired(&self.timer) {
                // A partial frame is no frame: stopped, so the next call
                // starts clean.
                self.capture.abort();
                self.started = false;
                return Err(Error::Timeout);
            }

            idle();
            self.timer.delay_us(POLL_US);
        }
    }

    fn set_power(&mut self, power: Power) -> Result<(), Error> {
        match power {
            Power::Off => {
                if self.started {
                    self.capture.abort();
                    self.started = false;
                }
                pmu::set_rails(&mut self.i2c, pmu::CAMERA, false).map_err(|_| Error::Io)?;
                self.power = Power::Off;
            }
            Power::On => {
                if self.power == Power::On {
                    return Ok(());
                }
                pmu::set_rails(&mut self.i2c, pmu::CAMERA, true).map_err(|_| Error::Io)?;
                self.timer.delay_ms(RAIL_SETTLE_MS);
                sensor::init(&mut self.i2c, &mut self.timer).map_err(|_| Error::Io)?;
                self.power = Power::On;
            }
        }
        Ok(())
    }

    fn power(&self) -> Power {
        self.power
    }
}

// ── LCD_CAM set-up around esp-hal's driver ──────────────────────────────────

/// `LCD_CAM_LCD_CLOCK_REG`, TRM register 29.1.
pub const LCD_CAM_LCD_CLOCK: u32 = 0x6004_1000;
/// `LCD_CAM_CAM_CTRL_REG`, TRM register 29.11. Read for diagnostics only.
pub const LCD_CAM_CAM_CTRL: u32 = 0x6004_1004;
/// `LCD_CAM_CAM_CTRL1_REG`, TRM register 29.12. Read for diagnostics;
/// outside esp-hal's driver, only `dvp::clear_for_panic` writes it, to stop
/// the capture.
pub const LCD_CAM_CAM_CTRL1: u32 = 0x6004_1008;

/// `LCD_CAM_CLK_EN`: force the clock on for every configuration register.
pub const LCD_CAM_CLK_EN: u32 = 1 << 31;
/// `LCD_CAM_CAM_VS_EOF_EN`, bit 8 of `CAM_CTRL`.
pub const CAM_VS_EOF_EN: u32 = 1 << 8;
/// `LCD_CAM_CAM_VH_DE_MODE_EN`, bit 28 of `CAM_CTRL1`.
pub const CAM_VH_DE_MODE_EN: u32 = 1 << 28;

/// Set `LCD_CAM_CLK_EN` if it is clear. Called after `LcdCam::new`, which
/// resets the peripheral and clears the bit, and before the camera driver
/// is built.
pub fn ensure_lcd_clk_enabled() {
    let reg = LCD_CAM_LCD_CLOCK as *mut u32;
    // SAFETY: read-modify-write of `LCD_CAM_LCD_CLOCK_REG` at the address the
    // manual gives. Only bit 31 is added; the unused LCD side's clock fields
    // keep what they hold.
    unsafe {
        let v = core::ptr::read_volatile(reg);
        if v & LCD_CAM_CLK_EN == 0 {
            core::ptr::write_volatile(reg, v | LCD_CAM_CLK_EN);
        }
    }
}

/// The three LCD_CAM registers that describe the capture: `LCD_CLOCK`,
/// `CAM_CTRL` and `CAM_CTRL1`, in that order, for a test binary to print
/// once the driver is built.
pub fn lcd_cam_registers() -> (u32, u32, u32) {
    // SAFETY: three volatile reads of LCD_CAM registers at the addresses the
    // manual gives. Reads only.
    unsafe {
        (
            core::ptr::read_volatile(LCD_CAM_LCD_CLOCK as *const u32),
            core::ptr::read_volatile(LCD_CAM_CAM_CTRL as *const u32),
            core::ptr::read_volatile(LCD_CAM_CAM_CTRL1 as *const u32),
        )
    }
}

/// The camera's pins, as the GPIO matrix routes them: from
/// `kassigner_hal::pins::m5stack::CAMERA`, checked against the netlist, with
/// the manual's signal indices, as the Waveshare map uses them.
///
/// `CAM_H_SYNC` has no pin and is tied to constant zero (`0x3C` in the
/// manual); the capture runs in DE mode, which does not use it.
pub const ROUTES: [MatrixRoute; 12] = [
    MatrixRoute {
        signal: 149,
        name: "CAM_PCLK",
        gpio: Some(pins::CAMERA[0].gpio),
    },
    MatrixRoute {
        signal: 152,
        name: "CAM_V_SYNC",
        gpio: Some(pins::CAMERA[1].gpio),
    },
    MatrixRoute {
        signal: 151,
        name: "CAM_H_SYNC",
        gpio: None,
    },
    MatrixRoute {
        signal: 150,
        name: "CAM_H_ENABLE",
        gpio: Some(pins::CAMERA[2].gpio),
    },
    MatrixRoute {
        signal: 133,
        name: "CAM_DATA_in0",
        gpio: Some(pins::CAMERA[3].gpio),
    },
    MatrixRoute {
        signal: 134,
        name: "CAM_DATA_in1",
        gpio: Some(pins::CAMERA[4].gpio),
    },
    MatrixRoute {
        signal: 135,
        name: "CAM_DATA_in2",
        gpio: Some(pins::CAMERA[5].gpio),
    },
    MatrixRoute {
        signal: 136,
        name: "CAM_DATA_in3",
        gpio: Some(pins::CAMERA[6].gpio),
    },
    MatrixRoute {
        signal: 137,
        name: "CAM_DATA_in4",
        gpio: Some(pins::CAMERA[7].gpio),
    },
    MatrixRoute {
        signal: 138,
        name: "CAM_DATA_in5",
        gpio: Some(pins::CAMERA[8].gpio),
    },
    MatrixRoute {
        signal: 139,
        name: "CAM_DATA_in6",
        gpio: Some(pins::CAMERA[9].gpio),
    },
    MatrixRoute {
        signal: 140,
        name: "CAM_DATA_in7",
        gpio: Some(pins::CAMERA[10].gpio),
    },
];

/// Route the camera's pins to LCD_CAM through the GPIO matrix, after
/// esp-hal has bound the pins and after the sensor's second bring-up. Every
/// pin gets its input buffer and function 1, then every signal its pin.
pub fn route_pins() {
    crate::gpio_matrix::apply(&ROUTES);
}
