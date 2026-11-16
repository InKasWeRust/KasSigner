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

//! The touch trait, over a fake panel that replays a script of states, and
//! [`Edges`], which makes press and lift events from bare points.

use kassigner_hal::input::{Edges, Error, Event, Gesture, Point, State, Touch};

/// A panel that replays a script.
struct Scripted {
    steps: Vec<Result<State, Error>>,
    at: usize,
    gesture: Gesture,
    contacts: u8,
}

impl Scripted {
    fn new(steps: Vec<Result<State, Error>>) -> Self {
        Self {
            steps,
            at: 0,
            gesture: Gesture::None,
            contacts: 1,
        }
    }
}

impl Touch for Scripted {
    fn read(&mut self) -> Result<State, Error> {
        let s = self.steps.get(self.at).copied().unwrap_or(Ok(State::Idle));
        self.at += 1;
        s
    }
    fn gesture(&mut self) -> Result<Gesture, Error> {
        Ok(self.gesture)
    }
    fn max_contacts(&self) -> u8 {
        self.contacts
    }
}

fn p(x: u16, y: u16, event: Event) -> Point {
    Point { x, y, event }
}

/// Idle is a state, not an error.
#[test]
fn nothing_touching_is_not_a_failure() {
    let mut panel = Scripted::new(vec![Ok(State::Idle)]);
    let s = panel.read().expect("idle reads fine");
    assert_eq!(s, State::Idle);
    assert!(!s.is_touched());
    assert_eq!(s.first(), None);
}

/// A missing controller errors.
#[test]
fn a_missing_controller_errors() {
    let mut panel = Scripted::new(vec![Err(Error::NotPresent)]);
    assert_eq!(panel.read().err(), Some(Error::NotPresent));
}

/// Two contacts come only from a controller that tracks two; `max_contacts`
/// tells a single-point one, like the Waveshare's, from one seeing a single
/// finger.
#[test]
fn two_contacts_depend_on_the_controller() {
    let a = p(10, 10, Event::Contact);
    let b = p(90, 90, Event::Contact);

    let mut single = Scripted::new(vec![Ok(State::One(a))]);
    assert_eq!(single.max_contacts(), 1);
    assert_eq!(single.read().unwrap().first(), Some(a));

    let mut dual = Scripted::new(vec![Ok(State::Two(a, b))]);
    dual.contacts = 2;
    assert_eq!(dual.max_contacts(), 2);
    let s = dual.read().unwrap();
    assert_eq!(
        s.first(),
        Some(a),
        "the first contact is the one a caller wants"
    );
    assert!(s.is_touched());
}

/// `Unknown` carries no chip-specific byte: the codes differ between
/// controllers.
#[test]
fn unknown_gestures_carry_nothing() {
    let mut panel = Scripted::new(vec![]);
    panel.gesture = Gesture::Unknown;
    assert_eq!(panel.gesture().unwrap(), Gesture::Unknown);

    // A controller that computes no gestures says so rather than failing.
    struct Plain;
    impl Touch for Plain {
        fn read(&mut self) -> Result<State, Error> {
            Ok(State::Idle)
        }
    }
    assert_eq!(Plain.gesture().unwrap(), Gesture::None);
    assert_eq!(Plain.max_contacts(), 1);
}

/// Points alone give the S3 units' events: press, contact while it stays,
/// lift where last seen, then idle.
#[test]
fn edges_give_a_press_its_contact_and_its_lift() {
    let mut e = Edges::new();
    let reads = [
        None,
        Some((150, 215)),
        Some((150, 215)),
        Some((152, 216)),
        None,
        None,
    ];
    let got: Vec<State> = reads.iter().map(|&at| e.read(at)).collect();
    assert_eq!(
        got,
        [
            State::Idle,
            State::One(p(150, 215, Event::PressDown)),
            State::One(p(150, 215, Event::Contact)),
            State::One(p(152, 216, Event::Contact)),
            State::One(p(152, 216, Event::LiftUp)),
            State::Idle,
        ]
    );
}

/// A tap read once is a press, then its lift at the same point: two reports
/// that differ, which a tracker confirms a finger by.
#[test]
fn a_tap_read_once_is_a_press_then_its_lift() {
    let mut e = Edges::new();
    assert_eq!(
        e.read(Some((30, 233))),
        State::One(p(30, 233, Event::PressDown))
    );
    assert_eq!(e.read(None), State::One(p(30, 233, Event::LiftUp)));
    assert_eq!(e.read(None), State::Idle);
}

/// A finger back after a lift is a new press, not a contact going on.
#[test]
fn a_finger_back_after_a_lift_presses_again() {
    let mut e = Edges::new();
    e.read(Some((10, 10)));
    e.read(None);
    assert_eq!(
        e.read(Some((11, 12))),
        State::One(p(11, 12, Event::PressDown))
    );
}
