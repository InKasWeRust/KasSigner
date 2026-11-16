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
//! Where a touch lands, and which touches are a finger. The regions are a
//! screen's, so they are here, not in [`kassigner_hal::input`].
//!
//! # A report is not a finger
//!
//! The Waveshare's controller reports a touch nobody made every few
//! seconds: one `PressDown` at the same point, gone by the next read, which
//! would turn a page or tap a review on its own. Every real touch measured
//! on the three units either updated (`PressDown` becoming `Contact`, or the
//! point moving) or was first seen already in `Contact` or `LiftUp`, having
//! gone down while the loop was busy.
//!
//! So a [`Tracker`] confirms a touch at once only on `Contact` or `LiftUp`,
//! else on the first report that differs, or once it has lasted
//! [`CONFIRM_US`]. Until then it lights and taps nothing, and if it ends
//! unconfirmed it is [`Action::Ignored`]. Which target a confirmed touch
//! landed and lifted on is the screen's to say.
//!
//! # A finger held still can look like a phantom
//!
//! On the provisioned M5 (read out with `ui_probe`) a held finger turns to
//! `Contact` only tens of milliseconds in, and a quick tap is one
//! `PressDown` repeated for 17 ms, then nothing. A phantom is gone by the
//! next read, a fraction of a millisecond, so a report still there after
//! [`CONFIRM_US`] is a finger. But a loop pass on the M5's home grid can
//! outlast 17 ms, catching a quick tap in a single read that no time rule
//! tells from a phantom. Phantoms were never seen on an M5, so its tracker
//! trusts the first report ([`Tracker::trusting_first_report`]); the
//! Waveshare's and the P4's keep the filter.
//!
//! A failed read is neither a finger nor its absence, and is not fed in.
//!
//! # A read with nothing in it is not yet a lift
//!
//! A controller can report no finger for a read or two while one is down,
//! which would break a long hold and make the finger's return a second
//! tap. So a touch ends only once the panel has read empty for
//! [`RELEASE_US`]; a finger back before then is the same touch.

use kassigner_hal::input::{Event, Point, State};

/// A rectangle a touch can fall inside: what a confirmation target is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Zone {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl Zone {
    pub const fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Whether a point is inside. A zone whose edge overflows contains
    /// nothing, rather than wrapping to the screen's other side.
    pub const fn contains(&self, x: u16, y: u16) -> bool {
        match (
            self.x.checked_add(self.width),
            self.y.checked_add(self.height),
        ) {
            (Some(right), Some(bottom)) => x >= self.x && x < right && y >= self.y && y < bottom,
            _ => false,
        }
    }
}

/// What a touch amounts to, as a [`Tracker`] follows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// The touch is confirmed a finger, landed here.
    Down { x: u16, y: u16 },
    /// A confirmed finger moved, to here.
    Moved { x: u16, y: u16 },
    /// A confirmed finger lifted from here, the last point seen.
    Up { x: u16, y: u16 },
    /// A touch ended unconfirmed, reported here.
    Ignored { x: u16, y: u16 },
}

/// How long the panel must read empty before a finger counts as lifted.
pub const RELEASE_US: u64 = 30_000;

/// How long a touch must be reported to count as a finger when nothing in
/// its reports says so: between a phantom's single read and the
/// provisioned M5's 17 ms quick tap.
pub const CONFIRM_US: u64 = 8_000;

/// A touch being followed.
#[derive(Clone, Copy, Debug)]
struct Following {
    first: Point,
    last: Point,
    confirmed: bool,
    /// When it was first reported.
    since: u64,
    /// When the panel started reading empty, while it does.
    empty_since: Option<u64>,
}

/// Follows the panel read by read and says what the touches amount to.
#[derive(Clone, Copy, Debug, Default)]
pub struct Tracker {
    touch: Option<Following>,
    /// A first report is a finger whatever it says.
    trust_first: bool,
}

impl Tracker {
    /// A tracker that confirms a touch only on a change, a `Contact` or
    /// `LiftUp` report, or [`CONFIRM_US`] of the same report.
    pub const fn new() -> Self {
        Self {
            touch: None,
            trust_first: false,
        }
    }

    /// A tracker that takes every first report as a finger: for the M5,
    /// which never produced a phantom and whose quick tap can be a single
    /// `PressDown` read.
    pub const fn trusting_first_report() -> Self {
        Self {
            touch: None,
            trust_first: true,
        }
    }

    /// One successful read of the panel, at `now_us` on the board's clock.
    pub fn read(&mut self, state: State, now_us: u64) -> Option<Action> {
        let Some(p) = state.first() else {
            let t = self.touch.as_mut()?;
            let since = *t.empty_since.get_or_insert(now_us);
            if now_us.saturating_sub(since) < RELEASE_US {
                return None;
            }
            let t = self.touch.take()?;
            return Some(if t.confirmed {
                Action::Up {
                    x: t.last.x,
                    y: t.last.y,
                }
            } else {
                Action::Ignored {
                    x: t.first.x,
                    y: t.first.y,
                }
            });
        };
        let Some(t) = self.touch.as_mut() else {
            // A controller reports `Contact` or `LiftUp` only for a finger it
            // has already followed across a scan.
            let confirmed = self.trust_first || !matches!(p.event, Event::PressDown);
            self.touch = Some(Following {
                first: p,
                last: p,
                confirmed,
                since: now_us,
                empty_since: None,
            });
            return confirmed.then_some(Action::Down { x: p.x, y: p.y });
        };
        // Back before the release: the same touch going on.
        t.empty_since = None;
        if p == t.last {
            // Unchanged: a finger once it has stayed long enough, whatever
            // the controller calls it.
            if !t.confirmed && now_us.saturating_sub(t.since) >= CONFIRM_US {
                t.confirmed = true;
                return Some(Action::Down {
                    x: t.first.x,
                    y: t.first.y,
                });
            }
            return None;
        }
        let moved = (p.x, p.y) != (t.last.x, t.last.y);
        t.last = p;
        if !t.confirmed {
            t.confirmed = true;
            return Some(Action::Down {
                x: t.first.x,
                y: t.first.y,
            });
        }
        moved.then_some(Action::Moved { x: p.x, y: p.y })
    }
}
