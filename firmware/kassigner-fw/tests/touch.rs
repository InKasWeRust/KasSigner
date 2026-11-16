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

//! Where a touch lands, and which touches count.

use kassigner_fw::touch::{Action, Tracker, Zone, CONFIRM_US, RELEASE_US};
use kassigner_hal::input::{Edges, Event, Point, State};

/// A point, as a controller reports one.
fn p(x: u16, y: u16, event: Event) -> Point {
    Point { x, y, event }
}

/// A zone contains its own edges correctly.
#[test]
fn a_zone_is_half_open() {
    let z = Zone::new(10, 20, 4, 2);
    assert!(z.contains(10, 20), "top left is inside");
    assert!(z.contains(13, 21), "bottom right is inside");
    assert!(!z.contains(14, 21), "one past the right is not");
    assert!(!z.contains(13, 22), "one past the bottom is not");
    assert!(!z.contains(9, 20));
}

/// A zone whose edge overflows contains nothing.
#[test]
fn an_overflowing_zone_contains_nothing() {
    let z = Zone::new(u16::MAX - 1, 0, 4, 4);
    assert!(
        !z.contains(u16::MAX, 1),
        "no wrapping to the left of the screen"
    );
    assert!(!z.contains(0, 0));
}

/// Feed a tracker reads a millisecond apart and collect what it says. An
/// `Idle` is a lift: the panel then reads empty for the release time.
fn follow(reads: &[State]) -> Vec<Action> {
    let mut t = Tracker::new();
    let mut now = 0u64;
    let mut out = Vec::new();
    for &s in reads {
        now += 1_000;
        out.extend(t.read(s, now));
        if s == State::Idle {
            now += RELEASE_US;
            out.extend(t.read(s, now));
        }
    }
    out
}

/// **A read or two with no finger is not a lift.** Empty for less than the
/// release time, then the finger back: one touch, one tap at the end, the
/// hold not cut short.
#[test]
fn an_empty_read_mid_touch_is_not_a_lift() {
    let mut t = Tracker::new();
    let held = State::One(p(200, 200, Event::Contact));
    assert_eq!(t.read(held, 0), Some(Action::Down { x: 200, y: 200 }));
    assert_eq!(t.read(State::Idle, 1_000), None);
    assert_eq!(t.read(State::Idle, 1_000 + RELEASE_US - 1), None, "not yet");
    assert_eq!(t.read(held, 1_000 + RELEASE_US), None, "the same touch");
    assert_eq!(t.read(State::Idle, 50_000), None);
    assert_eq!(
        t.read(State::Idle, 50_000 + RELEASE_US),
        Some(Action::Up { x: 200, y: 200 }),
        "lifted once it stays empty"
    );
}

/// **The Waveshare's phantom is ignored.** One `PressDown` at the same
/// point, read once or for a few reads unchanged, then gone: nothing lit,
/// nothing tapped.
#[test]
fn a_report_that_never_changes_is_not_a_finger() {
    let ghost = State::One(p(319, 175, Event::PressDown));
    assert_eq!(
        follow(&[ghost, State::Idle]),
        [Action::Ignored { x: 319, y: 175 }]
    );
    assert_eq!(
        follow(&[ghost, ghost, ghost, State::Idle]),
        [Action::Ignored { x: 319, y: 175 }]
    );
}

/// **A phantom repeated for less than [`CONFIRM_US`] is still ignored.**
#[test]
fn a_report_shorter_than_the_confirm_time_is_not_a_finger() {
    let mut t = Tracker::new();
    let ghost = State::One(p(319, 175, Event::PressDown));
    let mut now = 0;
    while now < CONFIRM_US {
        assert_eq!(t.read(ghost, now), None, "at {now} us");
        now += 1_000;
    }
    assert_eq!(t.read(State::Idle, now), None);
    assert_eq!(
        t.read(State::Idle, now + RELEASE_US),
        Some(Action::Ignored { x: 319, y: 175 })
    );
}

/// **A finger held still that the controller goes on calling `PressDown`
/// is a finger once it has stayed [`CONFIRM_US`]**: the provisioned M5's
/// quick tap, 17 ms of `PressDown` and nothing else, taps.
#[test]
fn a_still_press_that_stays_is_a_finger() {
    let mut t = Tracker::new();
    let still = State::One(p(150, 215, Event::PressDown));
    assert_eq!(t.read(still, 0), None);
    assert_eq!(t.read(still, CONFIRM_US - 1), None, "not yet");
    assert_eq!(
        t.read(still, CONFIRM_US),
        Some(Action::Down { x: 150, y: 215 })
    );
    assert_eq!(t.read(still, 17_000), None, "said once");
    assert_eq!(t.read(State::Idle, 17_200), None);
    assert_eq!(
        t.read(State::Idle, 17_200 + RELEASE_US),
        Some(Action::Up { x: 150, y: 215 })
    );
}

/// **A tracker trusting first reports takes a single `PressDown` read as a
/// tap**: the M5's, whose quick tap the signer can catch in one read. The
/// default tracker ignores the same read.
#[test]
fn a_trusting_tracker_taps_on_a_single_read() {
    let once = State::One(p(77, 177, Event::PressDown));
    let mut t = Tracker::trusting_first_report();
    assert_eq!(t.read(once, 0), Some(Action::Down { x: 77, y: 177 }));
    assert_eq!(t.read(State::Idle, 20_000), None);
    assert_eq!(
        t.read(State::Idle, 20_000 + RELEASE_US),
        Some(Action::Up { x: 77, y: 177 })
    );
    let mut d = Tracker::new();
    assert_eq!(d.read(once, 0), None);
    assert_eq!(d.read(State::Idle, 20_000), None);
    assert_eq!(
        d.read(State::Idle, 20_000 + RELEASE_US),
        Some(Action::Ignored { x: 77, y: 177 })
    );
}

/// A tap as the M5 and the Waveshare report one: `PressDown`, `Contact` at
/// the next scan, then nothing. Confirmed at the change, lifted where last
/// seen.
#[test]
fn a_press_that_the_controller_follows_is_a_finger() {
    let down = State::One(p(150, 215, Event::PressDown));
    let held = State::One(p(150, 215, Event::Contact));
    assert_eq!(
        follow(&[down, down, held, held, State::Idle]),
        [
            Action::Down { x: 150, y: 215 },
            Action::Up { x: 150, y: 215 }
        ]
    );
}

/// A finger that went down while the loop was drawing is first read in
/// `Contact`, or already lifting: confirmed on that first read.
#[test]
fn a_touch_first_seen_in_contact_is_a_finger() {
    let held = State::One(p(127, 82, Event::Contact));
    assert_eq!(
        follow(&[held, State::Idle]),
        [Action::Down { x: 127, y: 82 }, Action::Up { x: 127, y: 82 }]
    );
    let lifting = State::One(p(30, 233, Event::LiftUp));
    assert_eq!(
        follow(&[lifting, State::Idle]),
        [Action::Down { x: 30, y: 233 }, Action::Up { x: 30, y: 233 }]
    );
}

/// A confirmed finger reports each new point once and lifts from the last;
/// confirming reports where it landed, even if it has moved.
#[test]
fn a_finger_is_followed_where_it_moves() {
    let reads = [
        State::One(p(85, 219, Event::PressDown)),
        State::One(p(80, 219, Event::Contact)),
        State::One(p(80, 219, Event::Contact)),
        State::One(p(67, 219, Event::Contact)),
        State::One(p(67, 219, Event::LiftUp)),
        State::Idle,
        State::Idle,
    ];
    assert_eq!(
        follow(&reads),
        [
            Action::Down { x: 85, y: 219 },
            Action::Moved { x: 67, y: 219 },
            Action::Up { x: 67, y: 219 }
        ]
    );
}

/// Idle with nothing followed says nothing, and a new touch after a lift is
/// a new touch.
#[test]
fn touches_are_separate() {
    let a = State::One(p(10, 10, Event::Contact));
    let b = State::One(p(200, 100, Event::PressDown));
    assert_eq!(
        follow(&[State::Idle, a, State::Idle, State::Idle, b, State::Idle]),
        [
            Action::Down { x: 10, y: 10 },
            Action::Up { x: 10, y: 10 },
            Action::Ignored { x: 200, y: 100 }
        ]
    );
}

/// The P4's reads (where the finger is, or none) turned into presses and
/// lifts by [`Edges`], into the tracker.
fn follow_p4(reads: &[(u64, Option<(u16, u16)>)]) -> Vec<Action> {
    let mut edges = Edges::new();
    let mut t = Tracker::new();
    let mut out = Vec::new();
    for &(now, at) in reads {
        out.extend(t.read(edges.read(at), now));
    }
    out
}

/// **A P4 tap read only once is still a tap**: its press, then its lift on
/// the next read, two reports that differ, confirmed on the second.
#[test]
fn a_p4_tap_read_once_is_a_tap() {
    let release = 2_000 + RELEASE_US;
    assert_eq!(
        follow_p4(&[
            (0, Some((30, 233))),
            (1_000, None),
            (2_000, None),
            (release, None)
        ]),
        [Action::Down { x: 30, y: 233 }, Action::Up { x: 30, y: 233 }]
    );
}

/// **A P4 read with no finger mid-hold is not a lift either**: the lift
/// and press around it stay one touch, one tap at the end.
#[test]
fn a_p4_empty_read_mid_hold_is_not_a_lift() {
    let a = Some((200, 200));
    let release = 6_000 + RELEASE_US;
    assert_eq!(
        follow_p4(&[
            (0, a),
            (1_000, a),
            (2_000, None),
            (3_000, None),
            (4_000, a),
            (5_000, None),
            (6_000, None),
            (release, None),
        ]),
        [
            Action::Down { x: 200, y: 200 },
            Action::Up { x: 200, y: 200 }
        ]
    );
}
