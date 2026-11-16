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

//! [`Camera`] over the hand-rolled DMA path.
//!
//! A thin layer: [`super::cam_dma`] does the work; this gives it the trait's
//! shape, enforces the deadline and drives the power-down pin.
//!
//! # The frame is never copied
//!
//! `cam_dma::get_frame()` returns `&'static [u8]` into one of the two PSRAM
//! frames. [`Camera::frame`] hands it straight back, narrowed to `&mut self`,
//! so a caller cannot hold it across the next capture: that writes the other
//! frame, and the one after writes this one.
//!
//! # The deadline
//!
//! The wait polls `cam_dma::poll_done()` against a SYSTIMER deadline, not a
//! count of polls, whose cost moves with the optimiser; on expiry
//! `cam_dma::stop()` halts LCD_CAM and GDMA.
//!
//! # Power
//!
//! Off stops the transfer and drives the power-down pin, `CAM_PWDN` on
//! GPIO 17, high: the OV5640 halts its clock and keeps its registers
//! (datasheet, 2.9). On takes the pin low and waits as the bring-up does
//! after the same edge, and the sensor streams with its settings.

use embedded_hal::digital::OutputPin;
use kassigner_hal::camera::{Camera, Error, Format, Power};
use kassigner_hal::timer::{Deadline, Timer};

use crate::systimer::SysTimer;

use super::cam_dma;

/// How long the sensor is given after its power-down pin goes low, as the
/// bring-up gives it before writing its registers.
const WAKE_US: u32 = 30_000;

/// The Waveshare camera, `P` its power-down pin.
pub struct WaveshareCamera<P> {
    timer: SysTimer,
    power: Power,
    started: bool,
    pwdn: P,
}

impl<P: OutputPin> WaveshareCamera<P> {
    /// Bring the DMA path up: allocate the two PSRAM frame buffers and
    /// configure GDMA and LCD_CAM. `None` if `cam_dma::init` refuses the
    /// buffers, which it does for an address outside external memory
    /// ([`crate::cache::is_external`]).
    ///
    /// The sensor is configured separately, over SCCB. `pwdn` is its
    /// power-down pin, low (sensor on), as the bring-up leaves it.
    pub fn new(pwdn: P) -> Option<Self> {
        if !cam_dma::init() {
            return None;
        }
        Some(Self {
            timer: SysTimer,
            power: Power::On,
            started: false,
            pwdn,
        })
    }
}

impl<P: OutputPin> Camera for WaveshareCamera<P> {
    /// [`cam_dma::clear`]: both frames zeroed and written back from the data
    /// cache, both bounce buffers zeroed once the engine is idle. Measured on
    /// the unit: 460,800 bytes set before, none after, none across a reset.
    /// The capture is left stopped; the next frame request starts it.
    fn clear(&mut self) {
        cam_dma::clear();
    }

    fn format(&self) -> Format {
        // Y8, one byte per pixel, at `cam_dma`'s 480x480.
        Format::new(cam_dma::FRAME_W as u16, cam_dma::FRAME_H as u16, 1)
    }

    /// The wait polls the capture every 50 µs and does nothing else: no
    /// `frame_idle` here, so the trait's default, which never calls its
    /// `idle`, is this unit's.
    ///
    /// Each poll copies out the bounce buffers the engine has filled, and the
    /// engine does not wait for the copies: work between polls, such as a
    /// touch read, can delay a copy past the refill and break the image.
    fn frame(&mut self, deadline: Deadline) -> Result<&[u8], Error> {
        self.check()?;

        // `start_capture` does nothing while the capture runs, so this arms
        // it only the first time and after a `stop`: a timeout, power off or
        // `clear`.
        if !self.started {
            cam_dma::start_capture();
            self.started = true;
        }

        loop {
            if cam_dma::poll_done() {
                self.started = false;
                // The completed buffer. `None` would mean a frame finished
                // with none to read: a fault (`Io`), not a timeout.
                //
                // SAFETY: core 0, and the slice is returned borrowing
                // `&mut self`, so it is gone before the next `frame` can
                // capture over it.
                return unsafe { cam_dma::get_frame() }.ok_or(Error::Io);
            }

            if deadline.expired(&self.timer) {
                // Halts LCD_CAM and GDMA at once, rather than leave the engine
                // filling buffers nobody waits for.
                cam_dma::stop();
                self.started = false;
                return Err(Error::Timeout);
            }

            // Short enough not to hold a frame past its completion, long
            // enough not to saturate the bus the DMA engine uses.
            self.timer.delay_us(50);
        }
    }

    fn set_power(&mut self, power: Power) -> Result<(), Error> {
        if power == self.power {
            return Ok(());
        }
        match power {
            Power::Off => {
                cam_dma::stop();
                self.started = false;
                self.pwdn.set_high().map_err(|_| Error::Io)?;
            }
            Power::On => {
                self.pwdn.set_low().map_err(|_| Error::Io)?;
                self.timer.delay_us(WAKE_US);
            }
        }
        self.power = power;
        Ok(())
    }

    fn power(&self) -> Power {
        self.power
    }
}
