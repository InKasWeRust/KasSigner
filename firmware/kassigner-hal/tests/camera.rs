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

//! The camera and timer traits. The fake sensor can stop clocking, the
//! failure the deadline exists for: a bare spin on "is the frame done"
//! freezes the whole unit, touch included.

use kassigner_hal::camera::{Camera, Error, Format, Power};
use kassigner_hal::timer::{Deadline, Timer};

/// A clock that only moves when told, so a timeout is deterministic.
struct FakeClock {
    us: core::cell::Cell<u64>,
}

impl FakeClock {
    fn new() -> Self {
        Self {
            us: core::cell::Cell::new(0),
        }
    }
    fn advance(&self, us: u64) {
        self.us.set(self.us.get() + us);
    }
}

impl Timer for FakeClock {
    fn now_us(&self) -> u64 {
        self.us.get()
    }
    fn delay_us(&mut self, us: u32) {
        self.advance(us as u64);
    }
}

/// A sensor that produces frames, or stops. Like a real driver it lends its
/// own buffer.
struct FakeCamera<'a> {
    format: Format,
    power: Power,
    /// Microseconds a frame takes. Set beyond any deadline to stall.
    frame_us: u64,
    clock: &'a FakeClock,
    buf: Vec<u8>,
}

impl Camera for FakeCamera<'_> {
    fn clear(&mut self) {
        self.buf.fill(0);
    }

    fn format(&self) -> Format {
        self.format
    }

    fn frame(&mut self, deadline: Deadline) -> Result<&[u8], Error> {
        self.check()?;
        // Poll, as a real driver does.
        let step = 1_000u64;
        let mut waited = 0u64;
        while waited < self.frame_us {
            if deadline.expired(self.clock) {
                return Err(Error::Timeout);
            }
            self.clock.advance(step);
            waited += step;
        }
        for (i, b) in self.buf.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        Ok(&self.buf)
    }

    fn set_power(&mut self, power: Power) -> Result<(), Error> {
        self.power = power;
        Ok(())
    }

    fn power(&self) -> Power {
        self.power
    }
}

fn camera(clock: &FakeClock, frame_us: u64) -> FakeCamera<'_> {
    let format = Format::new(320, 240, 1);
    FakeCamera {
        buf: vec![0u8; format.frame_bytes()],
        format,
        power: Power::On,
        frame_us,
        clock,
    }
}

/// A sensor that stops clocking times out instead of hanging: it never
/// completes a frame, and the call returns.
#[test]
fn a_stalled_sensor_times_out() {
    let clock = FakeClock::new();
    let mut cam = camera(&clock, u64::MAX); // never finishes

    let deadline = Deadline::after(&clock, 50_000);
    assert_eq!(cam.frame(deadline).err(), Some(Error::Timeout));

    // And it gave up near the deadline rather than running away.
    assert!(clock.now_us() >= 50_000);
    assert!(clock.now_us() < 60_000, "it did not overshoot");
}

/// A working sensor returns a frame.
#[test]
fn a_working_sensor_returns_a_frame() {
    let clock = FakeClock::new();
    let mut cam = camera(&clock, 20_000);

    let deadline = Deadline::after(&clock, 100_000);
    let frame = cam.frame(deadline).expect("frame");

    assert_eq!(frame.len(), 320 * 240);
    assert_ne!(frame[..16], [0u8; 16], "the frame has content");
}

/// The copying form refuses a wrong-sized buffer before anything starts.
#[test]
fn the_copying_form_refuses_a_wrong_sized_buffer() {
    let clock = FakeClock::new();
    let mut cam = camera(&clock, 1_000);
    let deadline = Deadline::after(&clock, 100_000);

    let mut short = vec![0u8; 100];
    assert_eq!(
        cam.capture(&mut short, deadline).err(),
        Some(Error::WrongLength {
            expected: 76_800,
            got: 100
        })
    );
    assert_eq!(clock.now_us(), 0, "no time passed, so nothing started");

    // And a correctly sized one holds what the lending form would have lent.
    let mut buf = vec![0u8; 76_800];
    cam.capture(&mut buf, Deadline::after(&clock, 100_000))
        .expect("copy");

    let lent = cam.frame(Deadline::after(&clock, 100_000)).expect("lend");
    assert_eq!(&buf[..], lent, "the copy and the lend agree");
}

/// A powered-down sensor says so at once rather than timing out.
#[test]
fn a_powered_down_sensor_is_distinguishable_from_a_stall() {
    let clock = FakeClock::new();
    let mut cam = camera(&clock, 1_000);

    cam.set_power(Power::Off).expect("power off");
    assert_eq!(cam.power(), Power::Off);

    let deadline = Deadline::after(&clock, 100_000);
    assert_eq!(cam.frame(deadline).err(), Some(Error::PoweredDown));
    assert_eq!(clock.now_us(), 0, "and it did not wait to find out");

    cam.set_power(Power::On).expect("power on");
    assert!(cam.frame(Deadline::after(&clock, 100_000)).is_ok());
}

/// The convenience form is the same call.
#[test]
fn frame_within_is_frame_with_a_deadline() {
    let clock = FakeClock::new();
    let mut cam = camera(&clock, u64::MAX);

    assert_eq!(cam.frame_within(&clock, 10_000).err(), Some(Error::Timeout));
}

/// Frame arithmetic is what it claims.
#[test]
fn frame_sizes_are_consistent() {
    assert_eq!(Format::new(320, 240, 1).frame_bytes(), 76_800);
    assert_eq!(Format::new(320, 240, 2).frame_bytes(), 153_600);
    assert_eq!(Format::new(240, 320, 2).frame_bytes(), 153_600);
}

/// A deadline reports what is left, and stops at zero.
#[test]
fn a_deadline_saturates_rather_than_wrapping() {
    let clock = FakeClock::new();
    let d = Deadline::after(&clock, 1_000);

    assert_eq!(d.remaining_us(&clock), 1_000);
    assert!(!d.expired(&clock));

    clock.advance(400);
    assert_eq!(d.remaining_us(&clock), 600);

    clock.advance(10_000);
    assert!(d.expired(&clock));
    assert_eq!(d.remaining_us(&clock), 0, "not a huge number from wrapping");
}

/// Elapsed time does not go backwards: a clock fault reported as a huge
/// elapsed time would hang whatever waits on a deadline.
#[test]
fn elapsed_time_saturates() {
    let clock = FakeClock::new();
    clock.advance(500);
    assert_eq!(clock.since(200), 300);
    assert_eq!(
        clock.since(9_000),
        0,
        "a future start reads as zero elapsed"
    );
}

/// A millisecond delay is a thousand microseconds.
#[test]
fn delays_add_up() {
    let mut clock = FakeClock::new();
    clock.delay_us(250);
    assert_eq!(clock.now_us(), 250);
    clock.delay_ms(2);
    assert_eq!(clock.now_us(), 2_250);
}
