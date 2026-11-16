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

//! The camera.
//!
//! [`Camera::frame`] lends the driver's own buffer rather than filling the
//! caller's. The Waveshare's OV5640 gives 480x480 Y8, 230 KB a frame, and
//! the P4's OV5647 about as much; a copy would add a second buffer and a
//! memcpy per frame to the scan loop. The M5's GC0308 gives 320x240, 77 KB.
//! [`Camera::capture`], built on `frame`, is for a caller that wants its own
//! copy.
//!
//! Every capture takes a deadline: a bare spin on the DMA's `is_done()`
//! freezes the whole unit, touch included, if the sensor stops clocking
//! pixels. The trait offers no unbounded capture.
//!
//! Sensor configuration (register tables, autofocus, SCCB, exposure) is each
//! board's own; a board hands back something that produces frames.
//!
//! [`Camera::set_power`] is one capability with three mechanisms: the
//! Waveshare drives `CAM_PWDN` on a GPIO, the P4 stops its MIPI pipeline,
//! and the M5, whose power-down net reaches only the sensor connector and a
//! resistor, gates its `ALDO3` rail, which feeds both the sensor's 3.3 V and
//! the oscillator that clocks it. After a scan the camera is off, not just
//! unread.

use crate::timer::{Deadline, Timer};

/// What a frame looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    pub width: u16,
    pub height: u16,
    /// Bytes per pixel: one for greyscale, two for RGB565.
    pub bytes_per_pixel: u8,
}

impl Format {
    pub const fn new(width: u16, height: u16, bytes_per_pixel: u8) -> Self {
        Self {
            width,
            height,
            bytes_per_pixel,
        }
    }

    /// Bytes in one frame.
    pub const fn frame_bytes(&self) -> usize {
        self.width as usize * self.height as usize * self.bytes_per_pixel as usize
    }
}

/// Why a capture failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The deadline passed before the frame arrived: usually the sensor
    /// stopped clocking (unpowered, unconfigured, or gone).
    Timeout,
    /// The buffer is not one frame.
    WrongLength { expected: usize, got: usize },
    /// The sensor is powered down: a state the caller set, cured by powering
    /// it on.
    PoweredDown,
    /// The sensor or its bus failed.
    Io,
}

/// Whether the sensor is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Power {
    /// Running and able to produce frames.
    On,
    /// Off. Where the board can, this removes the sensor's supply and clock,
    /// rather than only asserting a power-down pin.
    Off,
}

/// A sensor that produces frames.
pub trait Camera {
    /// The frame format.
    fn format(&self) -> Format;

    /// Wait for a frame and lend it, or give up at `deadline`.
    ///
    /// The slice is the driver's buffer, `format().frame_bytes()` long. It
    /// borrows `&mut self`, so holding a frame while asking for the next does
    /// not compile.
    ///
    /// # Errors
    ///
    /// `PoweredDown` if the sensor is off, `Timeout` if the deadline passes
    /// (no partial frame is lent), `Io` on a transfer failure.
    fn frame(&mut self, deadline: Deadline) -> Result<&[u8], Error>;

    /// Turn the sensor on or off.
    ///
    /// # Errors
    ///
    /// `Io` if the board's mechanism failed, such as the bus write that gates
    /// a PMU rail.
    fn set_power(&mut self, power: Power) -> Result<(), Error>;

    /// Whether the sensor is currently running.
    fn power(&self) -> Power;

    /// Wait for a frame with a timeout in microseconds.
    ///
    /// # Errors
    ///
    /// As [`Camera::frame`].
    fn frame_within<T: Timer + ?Sized>(
        &mut self,
        timer: &T,
        timeout_us: u32,
    ) -> Result<&[u8], Error> {
        self.frame(Deadline::after(timer, timeout_us))
    }

    /// [`Camera::frame`], calling `idle` while the frame is on its way.
    ///
    /// A frame can take up to a hundred milliseconds to arrive; `idle` lets
    /// the caller watch the touch panel meanwhile. The board calls it at most
    /// once per turn of its wait, never where a call could disturb the
    /// frame, and the caller keeps it short. The default never calls it, for
    /// a board whose wait cannot be interrupted.
    ///
    /// # Errors
    ///
    /// As [`Camera::frame`].
    fn frame_idle(&mut self, deadline: Deadline, idle: &mut dyn FnMut()) -> Result<&[u8], Error> {
        let _ = idle;
        self.frame(deadline)
    }

    /// [`Camera::frame_idle`] with a timeout in microseconds.
    ///
    /// # Errors
    ///
    /// As [`Camera::frame`].
    fn frame_within_idle<T: Timer + ?Sized>(
        &mut self,
        timer: &T,
        timeout_us: u32,
        idle: &mut dyn FnMut(),
    ) -> Result<&[u8], Error> {
        self.frame_idle(Deadline::after(timer, timeout_us), idle)
    }

    /// Copy a frame into a caller's buffer: 230 KB on the Waveshare, so
    /// prefer [`Camera::frame`] unless the copy is the point.
    ///
    /// # Errors
    ///
    /// `WrongLength` before anything starts, then as [`Camera::frame`].
    fn capture(&mut self, buf: &mut [u8], deadline: Deadline) -> Result<(), Error> {
        let expected = self.format().frame_bytes();
        if buf.len() != expected {
            return Err(Error::WrongLength {
                expected,
                got: buf.len(),
            });
        }
        let frame = self.frame(deadline)?;
        buf.copy_from_slice(frame);
        Ok(())
    }

    /// Zero the frames this camera holds.
    ///
    /// Called when the camera goes off, as after a SeedQR is read: a frame of
    /// one decodes back to the seed. On the Waveshare the frames are 460 KB
    /// of PSRAM, which keeps its contents through a reset.
    ///
    /// No default, so no board can claim a wipe it never does; a board whose
    /// frames are already gone implements it empty and says so. It may stop
    /// the capture; the next frame request restarts it.
    fn clear(&mut self);

    /// Whether the sensor can produce a frame right now.
    ///
    /// # Errors
    ///
    /// `PoweredDown` if it is off.
    fn check(&self) -> Result<(), Error> {
        if self.power() == Power::Off {
            return Err(Error::PoweredDown);
        }
        Ok(())
    }
}
