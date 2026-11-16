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

//! Touch input.
//!
//! Only reading the controller (its points and any gesture it computed) is
//! hardware; the tracker above (`kassigner_fw::touch`) is portable.
//!
//! [`Gesture::Unknown`] carries no raw byte: codes differ between
//! controllers, so a portable caller could only use one as a board test. A
//! driver that wants the byte can log it where it still means something.
//!
//! A confirmation should act on a release, not a press, a security property
//! this trait leaves to the caller: on [`Event::PressDown`], a brush or a
//! touch sliding off the confirm button commits a transaction; on
//! [`Event::LiftUp`] inside the same target, a person can still move away.
//! Every board reports both events.

/// What a contact is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A finger has just landed.
    PressDown,
    /// A finger is still down and may have moved.
    Contact,
    /// A finger has just left: what a confirmation acts on (module doc).
    LiftUp,
}

/// Where a contact is, in panel pixels in the display's orientation: a board
/// whose controller reports otherwise converts them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: u16,
    pub y: u16,
    pub event: Event,
}

/// What the panel is reporting. `Two` comes only from a controller that
/// tracks two contacts, never the Waveshare's; a caller wanting one finger
/// reads the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Nothing is touching.
    Idle,
    /// One contact.
    One(Point),
    /// Two contacts.
    Two(Point, Point),
}

impl State {
    /// The first contact, if any.
    pub const fn first(&self) -> Option<Point> {
        match self {
            State::Idle => None,
            State::One(p) | State::Two(p, _) => Some(*p),
        }
    }

    /// Whether anything is touching.
    pub const fn is_touched(&self) -> bool {
        !matches!(self, State::Idle)
    }
}

/// A gesture the controller recognised, among those the controllers share;
/// anything else is [`Gesture::Unknown`] (module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gesture {
    None,
    SwipeUp,
    SwipeDown,
    SwipeLeft,
    SwipeRight,
    SingleTap,
    DoubleTap,
    LongPress,
    /// The controller reported something this trait does not name.
    Unknown,
}

/// Press and lift for a controller read only for where a finger is, as on
/// the P4, so every board reports as the S3 units' controllers do. Each
/// successful read goes through it: the first point after none is
/// [`Event::PressDown`], later ones [`Event::Contact`], and the first read
/// with no finger is [`Event::LiftUp`] at the last point, then
/// [`State::Idle`]. A failed read is not fed in: it is neither a finger nor
/// its absence.
///
/// A tap read only once is a press, then a lift at the same point, which
/// `kassigner_fw::touch::Tracker` confirms as a report that differs from the
/// first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Edges {
    /// Where the finger was at the last read, while one is down.
    last: Option<(u16, u16)>,
}

impl Edges {
    /// No finger down.
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// One successful read: where the finger is, or `None` for none.
    pub fn read(&mut self, at: Option<(u16, u16)>) -> State {
        match (at, self.last) {
            (Some((x, y)), was) => {
                self.last = Some((x, y));
                let event = if was.is_none() {
                    Event::PressDown
                } else {
                    Event::Contact
                };
                State::One(Point { x, y, event })
            }
            (None, Some((x, y))) => {
                self.last = None;
                State::One(Point {
                    x,
                    y,
                    event: Event::LiftUp,
                })
            }
            (None, None) => State::Idle,
        }
    }
}

/// Why a read failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The controller did not answer.
    NotPresent,
    /// The bus failed.
    Io,
}

/// A touch panel.
pub trait Touch {
    /// Read the current contacts.
    ///
    /// # Errors
    ///
    /// `NotPresent` if the controller is absent, `Io` on a bus failure.
    /// Nothing touching is [`State::Idle`], not an error.
    fn read(&mut self) -> Result<State, Error>;

    /// Read the gesture the controller computed. The default,
    /// [`Gesture::None`], is for a controller that computes none; gestures
    /// derived from points are portable code, not here.
    ///
    /// # Errors
    ///
    /// As [`Touch::read`].
    fn gesture(&mut self) -> Result<Gesture, Error> {
        Ok(Gesture::None)
    }

    /// How many contacts this controller can track, one or two, so a caller
    /// can tell one that cannot see a second finger from one that sees none.
    fn max_contacts(&self) -> u8 {
        1
    }
}
