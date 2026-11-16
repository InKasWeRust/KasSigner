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

//! The FT6336U touch controller, on the bus the AXP2101 and the AW9523B
//! share.
//!
//! A report is five bytes from `TD_STATUS`: the contact count, then the
//! first point's event and coordinates. A second point, at `0x09`, is read
//! only when the count says there is one. Both axes are turned 180 degrees
//! with the panel ([`rotate`]).
//!
//! Event code 3, "no event", in a report whose count says a finger is
//! there, reads as `PressDown`: a finger the controller sees but names no
//! event for, which the touch tracker counts once it stays. Read as
//! [`State::Idle`], as the Waveshare driver reads it, a finger held still on
//! the M5 ended as soon as it began. That this controller sends code 3 for a
//! held finger is inferred from how the unit behaves, not read out.
//!
//! A point off the panel is dropped, not clamped to the edge: clamped, a
//! raw `x` past 319 becomes `x` 0, which slides a held finger off its
//! button. A first point off the panel reads as [`State::Idle`], which the
//! touch tracker takes as a gap rather than a lift unless it lasts. So does
//! a count above two (the low four bits; the controller tracks two at
//! most): read as two, a garbled byte would be a phantom second touch from
//! stale registers.
//!
//! A bus failure is an error, not "nothing touching"; a controller that
//! does not acknowledge its address is `NotPresent`.

use embedded_hal::i2c::{ErrorKind, I2c};
use kassigner_hal::input::{Error, Event, Point, State, Touch};

use super::panel::SIZE;

/// I2C address. Fixed on this part.
pub const ADDRESS: u8 = 0x38;

/// Contact count, then the first point.
const REG_TD_STATUS: u8 = 0x02;
/// The second point.
const REG_P2_XH: u8 = 0x09;

/// The most contacts the FT6336U tracks.
const MAX_CONTACTS: u8 = 2;

/// Turn a raw report into panel coordinates, both axes flipped, or `None`
/// for a report off the panel.
pub fn rotate(raw_x: u16, raw_y: u16) -> Option<(u16, u16)> {
    if raw_x >= SIZE.width || raw_y >= SIZE.height {
        return None;
    }
    Some((SIZE.width - 1 - raw_x, SIZE.height - 1 - raw_y))
}

/// The event bits. Code 3 reads as `PressDown`: the count, checked before
/// any point is read, says a finger is there (see the module doc).
fn event_of(bits: u8) -> Event {
    match bits {
        1 => Event::LiftUp,
        2 => Event::Contact,
        _ => Event::PressDown,
    }
}

/// One point from its four register bytes; `None` off the panel.
pub fn point(xh: u8, xl: u8, yh: u8, yl: u8) -> Option<Point> {
    let event = event_of((xh >> 6) & 0x03);
    let raw_x = ((xh as u16 & 0x0F) << 8) | xl as u16;
    let raw_y = ((yh as u16 & 0x0F) << 8) | yl as u16;
    let (x, y) = rotate(raw_x, raw_y)?;
    Some(Point { x, y, event })
}

/// A bus error as the trait's.
fn map<E: embedded_hal::i2c::Error>(e: E) -> Error {
    match e.kind() {
        ErrorKind::NoAcknowledge(_) => Error::NotPresent,
        _ => Error::Io,
    }
}

/// The touch panel.
pub struct M5Touch<I> {
    i2c: I,
}

impl<I: I2c> M5Touch<I> {
    /// Take a bus handle. Nothing is written: the controller needs no set-up,
    /// and [`super::pmu::init_aw9523b`] releases its reset.
    pub fn new(i2c: I) -> Self {
        Self { i2c }
    }

    /// Give the bus handle back.
    pub fn release(self) -> I {
        self.i2c
    }
}

impl<I: I2c> Touch for M5Touch<I> {
    fn read(&mut self) -> Result<State, Error> {
        let mut buf = [0u8; 5];
        self.i2c
            .write_read(ADDRESS, &[REG_TD_STATUS], &mut buf)
            .map_err(map)?;

        let count = buf[0] & 0x0F;
        // Nothing touching, or a garbled count (3 to 15): none of it is used,
        // and the next poll reads a fresh one.
        if count == 0 || count > MAX_CONTACTS {
            return Ok(State::Idle);
        }

        let Some(first) = point(buf[1], buf[2], buf[3], buf[4]) else {
            return Ok(State::Idle);
        };

        if count >= 2 {
            // A second point that cannot be read leaves the first standing.
            let mut b2 = [0u8; 4];
            if self.i2c.write_read(ADDRESS, &[REG_P2_XH], &mut b2).is_ok() {
                if let Some(second) = point(b2[0], b2[1], b2[2], b2[3]) {
                    return Ok(State::Two(first, second));
                }
            }
        }

        Ok(State::One(first))
    }

    fn max_contacts(&self) -> u8 {
        MAX_CONTACTS
    }
}
