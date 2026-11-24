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

//! The touch capture: what the seed's screen reads of a finger, written out
//! raw for measuring. Behind the `touchcap` feature, never in a shipped
//! image.
//!
//! The board crates' captures read the panel in a loop of their own. A seed
//! does not: the loop reads the panel once a pass, between a camera frame,
//! the viewfinder and the IMU, and the time it gives a touch is the time
//! since the pass before. This records that, every read the loop would hand
//! the seed, where the loop hands it over: the position, the time the loop
//! computed, and when.
//!
//! The reads are kept, not handed to the flow, so the touch share never
//! fills and the screen stays up, the camera and the IMU running as in a
//! seed: **a `touchcap` build never makes a seed on that screen.** Nothing
//! is printed until the capture is full, so the console does not slow the
//! loop it measures. Then, between
//!
//! ```text
//! -----BEGIN KASSIGNER TOUCH RAW 2048 2301-----
//! -----END KASSIGNER TOUCH RAW-----
//! ```
//!
//! one read a line, `x y microseconds-the-loop-gave microseconds-at-the-read`
//! (the last one the clock's low 32 bits). The two numbers on the first line
//! are the reads at a new position and all the reads. Every read is there,
//! the ones at an unchanged position too, so the analysis can take the
//! touches as the collector counts them, or with another rule for their
//! time.
//!
//! Leaving the screen ends a capture; coming back starts another.

use alloc::vec::Vec;

use super::*;

/// Reads at a new position a capture collects: the board captures' count.
const MOVED: u32 = 2048;
/// Reads kept at most, a finger held still among them.
const READS_MAX: usize = 8192;

/// One read of the panel, as the loop would hand it to the seed.
#[derive(Clone, Copy)]
struct Read {
    x: u16,
    y: u16,
    /// The time the loop gives the touch: since the last pass with a finger.
    since_us: u32,
    /// The pass's clock, its low 32 bits.
    at_us: u32,
}

/// A capture under way.
pub(super) struct TouchCap {
    reads: Vec<Read>,
    /// Reads at a position other than the one before, as the collector
    /// counts a moving touch.
    moved: u32,
    last: Option<(u16, u16)>,
    done: bool,
}

impl TouchCap {
    /// Empty, its room taken now so no read pays for it.
    pub(super) fn new() -> Self {
        Self {
            reads: Vec::with_capacity(READS_MAX),
            moved: 0,
            last: None,
            done: false,
        }
    }

    /// Keep one read. `true` once, when the capture is full.
    pub(super) fn take(&mut self, x: u16, y: u16, since_us: u32, now_us: u64) -> bool {
        if self.done {
            return false;
        }
        self.reads.push(Read {
            x,
            y,
            since_us,
            at_us: now_us as u32,
        });
        if self.last != Some((x, y)) {
            self.last = Some((x, y));
            self.moved += 1;
            // A sign of life: silence for minutes reads as a dead capture.
            if self.moved.is_multiple_of(MOVED / 8) && self.moved < MOVED {
                out!(
                    "touchcap: {} of {MOVED} moving touches, {} reads",
                    self.moved,
                    self.reads.len()
                );
            }
        }
        self.done = self.moved >= MOVED || self.reads.len() >= READS_MAX;
        self.done
    }

    /// The screen was left: the next capture starts empty.
    pub(super) fn reset(&mut self) {
        if self.done || !self.reads.is_empty() {
            self.reads.clear();
            self.moved = 0;
            self.last = None;
            self.done = false;
        }
    }

    /// Write the capture out. `alive` is called as it goes: a full capture
    /// takes seconds on a UART.
    pub(super) fn dump(&self, alive: &mut dyn FnMut()) {
        out!(
            "-----BEGIN KASSIGNER TOUCH RAW {} {}-----",
            self.moved,
            self.reads.len()
        );
        for (i, r) in self.reads.iter().enumerate() {
            out!("{} {} {} {}", r.x, r.y, r.since_us, r.at_us);
            if i % 256 == 0 {
                alive();
            }
        }
        out!("-----END KASSIGNER TOUCH RAW-----");
        out!(
            "done: {} moving touches in {} reads; leave the screen and come back for another",
            self.moved,
            self.reads.len()
        );
    }
}
