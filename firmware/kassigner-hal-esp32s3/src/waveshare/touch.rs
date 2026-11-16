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

//! The CST816D touch controller, generic over `embedded_hal::i2c::I2c`, so
//! it builds and checks off target.
//!
//! The controller reports in the panel's native portrait frame, and the
//! display is built rotated 90 degrees, so touch turns too: [`rotate`],
//! checked against [`super::panel::SIZE`].
//!
//! A coordinate is twelve bits, so a report can name a point off the panel.
//! Clamped onto the edge it would look real (measured on this unit: a
//! phantom every few seconds at (319, 175), the clamped right edge), so it
//! is dropped and the read is `Idle`. A phantom on the panel is for
//! `kassigner_fw::touch::Tracker` to refuse.
//!
//! The controller keeps its gesture register across an auto-sleep, so a
//! report with no fingers reads `Idle` and its gesture `Gesture::None`:
//! acting on the stale gesture is phantom activity.
//!
//! A held bus is `crate::i2c_bus`'s to free, before every transfer and for
//! every device on it (`ws-hwtest` checks it with the IMU). The touch
//! driver could not: `GPIO_OUT1` and `GPIO_ENABLE1` do not reach a pin the
//! GPIO matrix routes to I2C0 (TRM register 6.20, `OUT_SEL` and `OEN_SEL`).
//! What stays here is rewriting the controller's settings after
//! [`RECONFIGURE_AFTER`] failed reads in a row, in case it reset.

use embedded_hal::i2c::I2c;
use kassigner_hal::input::{Error, Event, Gesture, Point, State, Touch};

/// I2C address.
pub const ADDRESS: u8 = 0x15;

/// First register of the six-byte report.
const REG_GESTURE_ID: u8 = 0x01;

/// Sensitivity threshold, higher less sensitive: `0x60` cuts ghost clicks
/// under fluorescent light and sunlight flicker.
const REG_SENSITIVITY: (u8, u8) = (0x05, 0x60);
/// Low-power scan range. Higher filters more aggressively before a touch.
const REG_SCAN_RANGE: (u8, u8) = (0x06, 0x30);
/// Keep the controller awake, so it produces no spurious wake events.
const REG_DISABLE_AUTOSLEEP: (u8, u8) = (0xFE, 0x01);

/// Failed reads in a row after which the controller's settings are written
/// again, on the next good read.
pub const RECONFIGURE_AFTER: u8 = 5;

/// Turn a raw report into panel coordinates, or `None` for a report off the
/// panel.
///
/// The reported `y` becomes `x`, and the reported `x` a distance counted up
/// from the bottom.
pub fn rotate(raw_x: u16, raw_y: u16) -> Option<(u16, u16)> {
    let size = super::panel::SIZE;
    if raw_y >= size.width || raw_x >= size.height {
        return None;
    }
    Some((raw_y, size.height - 1 - raw_x))
}

/// The touch panel.
pub struct WaveshareTouch<I> {
    i2c: I,
    /// The controller's registers are set on the first successful read, not
    /// at construction: it may not answer yet when the bus comes up, and a
    /// failed write there would be lost.
    configured: bool,
    consecutive_errors: u8,
}

impl<I: I2c> WaveshareTouch<I> {
    /// Take the bus.
    pub fn new(i2c: I) -> Self {
        Self {
            i2c,
            configured: false,
            consecutive_errors: 0,
        }
    }

    /// Give the bus back.
    pub fn release(self) -> I {
        self.i2c
    }

    /// Write the sensitivity and sleep settings.
    fn configure(&mut self) {
        for (reg, val) in [REG_SENSITIVITY, REG_SCAN_RANGE, REG_DISABLE_AUTOSLEEP] {
            let _ = self.i2c.write(ADDRESS, &[reg, val]);
        }
        self.configured = true;
    }

    /// Read the six-byte report.
    fn read_report(&mut self) -> Result<[u8; 6], Error> {
        let mut buf = [0u8; 6];
        if self
            .i2c
            .write_read(ADDRESS, &[REG_GESTURE_ID], &mut buf)
            .is_err()
        {
            self.consecutive_errors = self.consecutive_errors.saturating_add(1);
            if self.consecutive_errors >= RECONFIGURE_AFTER {
                // The controller may have reset: its settings are written
                // again on the next good read.
                self.configured = false;
            }
            return Err(Error::Io);
        }
        self.consecutive_errors = 0;
        if !self.configured {
            self.configure();
        }
        Ok(buf)
    }
}

/// Decode the gesture byte.
///
/// Codes this trait does not name become [`Gesture::Unknown`] with no
/// payload: the two units' controllers use different codes, so a raw byte
/// means nothing to a portable caller.
fn gesture_of(code: u8) -> Gesture {
    match code {
        0x00 => Gesture::None,
        0x01 => Gesture::SwipeUp,
        0x02 => Gesture::SwipeDown,
        0x03 => Gesture::SwipeLeft,
        0x04 => Gesture::SwipeRight,
        0x05 => Gesture::SingleTap,
        0x0B => Gesture::DoubleTap,
        0x0C => Gesture::LongPress,
        _ => Gesture::Unknown,
    }
}

/// Decode the event bits.
///
/// Three is the controller's "no event", not expected with a finger: it
/// maps to `None`, and the caller reports [`State::Idle`] rather than guess
/// that a finger rests.
fn event_of(bits: u8) -> Option<Event> {
    match bits {
        0 => Some(Event::PressDown),
        1 => Some(Event::LiftUp),
        2 => Some(Event::Contact),
        _ => None,
    }
}

impl<I: I2c> Touch for WaveshareTouch<I> {
    fn read(&mut self) -> Result<State, Error> {
        let buf = self.read_report()?;

        if buf[1] & 0x0F == 0 {
            return Ok(State::Idle);
        }

        let Some(event) = event_of((buf[2] >> 6) & 0x03) else {
            return Ok(State::Idle);
        };

        let raw_x = ((buf[2] as u16 & 0x0F) << 8) | buf[3] as u16;
        let raw_y = ((buf[4] as u16 & 0x0F) << 8) | buf[5] as u16;
        let Some((x, y)) = rotate(raw_x, raw_y) else {
            return Ok(State::Idle);
        };

        Ok(State::One(Point { x, y, event }))
    }

    fn gesture(&mut self) -> Result<Gesture, Error> {
        let buf = self.read_report()?;
        // No fingers means the gesture register is stale: the controller keeps
        // it across an auto-sleep, and acting on it is phantom activity.
        if buf[1] & 0x0F == 0 {
            return Ok(Gesture::None);
        }
        Ok(gesture_of(buf[0]))
    }

    fn max_contacts(&self) -> u8 {
        1
    }
}
