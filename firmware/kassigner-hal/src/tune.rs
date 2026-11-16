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

//! Camera tuning: the settings a tuning screen moves, and how a board moves
//! them.
//!
//! A board names a few registers here, each with a label, a largest value
//! and a step, and reads and writes them by index; which register, and how
//! many bytes, is the board's business, and the screen the flow's. Nothing
//! is saved: bring-up rewrites the board's tables, which hold every setting
//! a tuner reaches, and good values are copied into them by hand.
//!
//! Exposure and gain set by hand hold only while the sensor's exposure loop
//! is off, as it rewrites them every frame; a board that offers them offers
//! the switch too, [`Tune::auto`].

use crate::camera::Error;

/// The most buttons the screen holds, two columns of four, a board's
/// exposure switch included.
pub const MAX_KNOBS: usize = 8;

/// One setting a tuning screen moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Knob {
    /// What the screen calls it, five or six characters.
    pub label: &'static str,
    /// The largest value the register holds; the smallest is zero.
    pub max: u8,
    /// How far minus and plus move it; values sit on the multiples of
    /// `step`, and on `max`.
    pub step: u8,
    /// Shown as a plain number out of `max`, not in hex with a percentage.
    pub count: bool,
    /// Which exposure mode it acts in, on a board with the switch.
    pub acts: Acts,
    /// The setting the screen opens on: the first marked, else the first.
    pub lead: bool,
}

/// When a setting does anything, on a board with an exposure switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acts {
    /// In either mode: contrast, sharpness.
    Always,
    /// Only while the exposure loop runs: its target, its ceilings.
    Auto,
    /// Only while it is off: the exposure and gain it would otherwise set.
    Manual,
}

impl Knob {
    /// A register value, shown in hex.
    pub const fn new(label: &'static str, max: u8, step: u8) -> Self {
        Self {
            label,
            max,
            step,
            count: false,
            acts: Acts::Always,
            lead: false,
        }
    }

    /// Acting only while the exposure loop runs.
    pub const fn in_auto(self) -> Self {
        Self {
            acts: Acts::Auto,
            ..self
        }
    }

    /// Acting only while the exposure loop is off.
    pub const fn in_manual(self) -> Self {
        Self {
            acts: Acts::Manual,
            ..self
        }
    }

    /// The setting the screen opens on.
    pub const fn lead(self) -> Self {
        Self { lead: true, ..self }
    }

    /// Whether it acts with the switch as `auto` says; always on a board
    /// without one (`None`).
    pub const fn acts_in(&self, auto: Option<bool>) -> bool {
        match (self.acts, auto) {
            (Acts::Always, _) | (_, None) => true,
            (Acts::Auto, Some(on)) => on,
            (Acts::Manual, Some(on)) => !on,
        }
    }

    /// A count from 0 to `max`, one at a time, shown as a plain number.
    pub const fn count(label: &'static str, max: u8) -> Self {
        Self {
            label,
            max,
            step: 1,
            count: true,
            acts: Acts::Always,
            lead: false,
        }
    }

    /// The step, never zero.
    const fn stride(&self) -> u16 {
        if self.step == 0 {
            1
        } else {
            self.step as u16
        }
    }

    /// Minus from `now`: the grid point below. A value off the grid lands on
    /// the point just under it, so every grid point stays reachable.
    pub const fn down(&self, now: u8) -> u8 {
        let s = self.stride();
        let v = now as u16;
        let below = if v.is_multiple_of(s) {
            v.saturating_sub(s)
        } else {
            v - v % s
        };
        below as u8
    }

    /// Plus from `now`: the grid point above it, or `max` past the last.
    pub const fn up(&self, now: u8) -> u8 {
        let s = self.stride();
        let above = (now as u16 / s + 1) * s;
        if above > self.max as u16 {
            self.max
        } else {
            above as u8
        }
    }

    /// A value from the track onto the nearest grid point; `max` at the
    /// track's end.
    pub const fn snap(&self, value: u8) -> u8 {
        if value >= self.max {
            return self.max;
        }
        let s = self.stride();
        let near = (value as u16 + s / 2) / s * s;
        if near > self.max as u16 {
            self.max
        } else {
            near as u8
        }
    }
}

/// A board's camera settings.
pub trait Tune {
    /// The settings in screen order: at most [`MAX_KNOBS`], one fewer with
    /// an exposure switch.
    fn knobs(&self) -> &'static [Knob];

    /// Read every setting off the sensor into `out`, one byte per knob.
    ///
    /// # Errors
    ///
    /// `Io` if a read failed; `out` is then partly written.
    fn read(&mut self, out: &mut [u8]) -> Result<(), Error>;

    /// Write setting `knob`.
    ///
    /// # Errors
    ///
    /// `Io` if the write failed or `knob` is not one of [`Tune::knobs`].
    fn write(&mut self, knob: usize, value: u8) -> Result<(), Error>;

    /// Whether the exposure loop is on, read off the sensor; `None` on a
    /// board with no switch.
    fn auto(&mut self) -> Option<bool>;

    /// Turn the exposure loop on or off.
    ///
    /// # Errors
    ///
    /// `Io` if the write failed, or on a board with no switch.
    fn set_auto(&mut self, on: bool) -> Result<(), Error>;
}
