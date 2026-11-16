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

//! The loop's input: the timed panel, taps and holds, scan passes, what a
//! sighted code is.

use super::*;

/// A panel that counts the time spent sending to it.
pub(super) struct Timed<'a, L, T> {
    pub(super) lcd: &'a mut L,
    pub(super) timer: &'a T,
    pub(super) panel_us: u64,
}

impl<L: Display, T: Timer> Display for Timed<'_, L, T> {
    fn size(&self) -> kassigner_hal::display::Size {
        self.lcd.size()
    }

    fn blit(&mut self, rect: Rect, pixels: &[u16]) -> Result<(), kassigner_hal::display::Error> {
        let start = self.timer.now_us();
        let r = self.lcd.blit(rect, pixels);
        self.panel_us += self.timer.since(start);
        r
    }

    fn fill(&mut self, rect: Rect, color: u16) -> Result<(), kassigner_hal::display::Error> {
        let start = self.timer.now_us();
        let r = self.lcd.fill(rect, color);
        self.panel_us += self.timer.since(start);
        r
    }

    fn set_backlight(&mut self, level: Backlight) -> Result<(), kassigner_hal::display::Error> {
        self.lcd.set_backlight(level)
    }
}

/// Whether `event` is a tap, kept to say how many reports made it (a
/// phantom still shows). Never where it landed: on a keyboard or the
/// dice pad that spells out what was typed (words, a password, rolls).
pub(super) fn tap_at(event: &Event<'_>, io: &mut Io<'_>, now_us: u64) -> bool {
    match *event {
        // Said after the click starts: a write here would delay it.
        Event::Tap { .. } => {
            let seen = core::mem::take(&mut io.touch_seen);
            let over_ms = now_us.saturating_sub(seen.first_us) / 1000;
            io.tap_said = Some((seen.reports, over_ms, now_us));
            io.deferred_from = None;
            true
        }
        _ => false,
    }
}

/// The panel's reports of a touch up to its tap: how many, since when.
/// A finger gives dozens over a tenth of a second or more, unlike the
/// P4's phantoms. Only reads at the top of the loop count. A report over
/// 100 ms after the last starts a new count.
#[derive(Default)]
pub(super) struct Seen {
    reports: u32,
    first_us: u64,
    last_us: u64,
}

impl Seen {
    pub(super) fn report(&mut self, now_us: u64) {
        if self.reports == 0 || now_us.saturating_sub(self.last_us) > 100_000 {
            self.reports = 0;
            self.first_us = now_us;
        }
        self.reports = self.reports.saturating_add(1);
        self.last_us = now_us;
    }
}

/// A scan's passes, timed: capture, viewfinder and decoder, on average
/// and at worst, said every thirty.
#[derive(Default)]
pub(super) struct Passes {
    n: u32,
    sum: [u64; 3],
    max: [u64; 3],
}

impl Passes {
    pub(super) fn add(&mut self, capture: u64, view: u64, decode: u64) {
        for (i, us) in [capture, view, decode].into_iter().enumerate() {
            self.sum[i] += us;
            self.max[i] = self.max[i].max(us);
        }
        self.n += 1;
        if self.n == 30 {
            let avg = |i: usize| self.sum[i] / 30 / 1000;
            let max = |i: usize| self.max[i] / 1000;
            diag!(
                "scan passes, ms avg/max: capture {}/{}, viewfinder {}/{}, decoder {}/{}",
                avg(0),
                max(0),
                avg(1),
                max(1),
                avg(2),
                max(2)
            );
            // The Waveshare's capture engine keeps a frame only if no
            // bounce buffer was lost: how many it kept.
            #[cfg(feature = "waveshare")]
            {
                let (kept, skipped, fewest) =
                    kassigner_hal_esp32s3::waveshare::cam_dma::take_counts();
                diag!("camera frames: {kept} kept, {skipped} skipped, fewest bytes {fewest}");
            }
            *self = Self::default();
        }
    }
}

/// What a touch the tracker confirmed means to the flow.
pub(super) fn event_of(action: Action) -> Option<Event<'static>> {
    match action {
        Action::Down { x, y } => Some(Event::Press { x, y }),
        Action::Moved { x, y } => Some(Event::Drag { x, y }),
        Action::Up { x, y } => Some(Event::Tap { x, y }),
        Action::Ignored { .. } => None,
    }
}

/// Touch read while a frame is held (every [`TOUCH_POLL_US`]), for the
/// flow once it is let go. Four places hold a press, a move and a lift
/// with one to spare: a move replaces the move before it, and when full
/// a press or a lift lands over a move.
#[derive(Default)]
pub(super) struct Held {
    actions: [Option<Action>; 4],
    n: usize,
}

impl Held {
    fn push(&mut self, action: Action) {
        let last = self.n.checked_sub(1);
        match (action, last.and_then(|i| self.actions[i])) {
            (Action::Moved { .. }, Some(Action::Moved { .. })) => {
                self.actions[self.n - 1] = Some(action);
            }
            _ if self.n < self.actions.len() => {
                self.actions[self.n] = Some(action);
                self.n += 1;
            }
            // Full: a lift or a press still has to land, over a move.
            _ => {
                if let Some(i) = (0..self.n)
                    .rev()
                    .find(|&i| matches!(self.actions[i], Some(Action::Moved { .. })))
                {
                    self.actions.copy_within(i + 1..self.n, i);
                    self.actions[self.n - 1] = Some(action);
                }
            }
        }
    }

    /// Everything held, in order, and nothing left.
    fn take(&mut self) -> impl Iterator<Item = Action> {
        let actions = core::mem::take(&mut self.actions);
        let n = core::mem::take(&mut self.n);
        actions.into_iter().take(n).flatten()
    }
}

/// Hands the flow, in order, all that was held while a frame was on its
/// way: after every wait for a frame, whether one came or not.
pub(super) fn release<L, C, D, T>(
    held: &mut Held,
    unit: &mut unit::Unit<L, C, D, T>,
    flow: &mut Flow<'_, SLOTS>,
    io: &mut Io<'_>,
) where
    L: Display,
    C: Camera,
    D: Decoder,
    T: Touch,
{
    for action in held.take() {
        if let Some(event) = event_of(action) {
            let now_us = unit.timer.now_us();
            io.tapped = tap_at(&event, io, now_us);
            let out = flow.step(event, &mut unit.rng);
            apply(out, unit, flow, io);
        }
    }
}

/// One read of the panel for the tracker, its answer held.
pub(super) fn watch<T: Touch>(touch: &mut T, tracker: &mut Tracker, now_us: u64, held: &mut Held) {
    if let Ok(state) = touch.read() {
        if let Some(action) = tracker.read(state, now_us) {
            held.push(action);
        }
    }
}

/// The frames' and the payload's buffers, just wiped, now wiped in PSRAM
/// too: written back from the cache on the S3s (the P4 writes them
/// uncached).
pub(super) fn settle_scan(io: &Io<'_>) {
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    for region in &io.scan_regions {
        region.write_back();
    }
    #[cfg(feature = "p4")]
    let _ = io;
}

/// The decoder saw a code, read or not: the edge turns green and, if it
/// was red, a tick greets the code. Returns whether it ticked.
pub(super) fn sighted<L, C, D, T>(unit: &mut unit::Unit<L, C, D, T>, io: &mut Io<'_>) -> bool
where
    L: Display,
    C: Camera,
    D: Decoder,
    T: Touch,
{
    let new = io.sighting.saw();
    if new {
        cues::play(&mut unit.speaker, cues::Cue::CodeFound);
    }
    new
}
