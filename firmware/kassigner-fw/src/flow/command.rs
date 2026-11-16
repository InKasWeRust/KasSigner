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

//! What the flow answers: a command for the board, with the screen.

use super::*;

/// Something the loop must do besides drawing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Bring the camera up and start reporting payloads and progress.
    CameraOn,
    /// Take the camera down.
    CameraOff,
    /// Start reporting seed samples from every source the unit has.
    SamplesOn,
    /// Stop.
    SamplesOff,
    /// Close the console and debug port until the next reset. Issued once,
    /// as a provisioned unit leaves its verification screen: from then on it
    /// may hold a seed, and nothing may leave by that port.
    CloseConsole,
    /// Set the backlight to this level, 1 to 255.
    Backlight(u8),
    /// Set the volume, 0 to 255.
    Volume(u8),
    /// Bring the camera up for the tuning screen, not decoding, and report
    /// its settings as [`Event::Tuned`].
    TuneOn,
    /// Take it down again.
    TuneOff,
    /// Write one camera setting and report them all again.
    Tune { knob: usize, value: u8 },
    /// Turn the exposure loop on or off and report the settings again; the
    /// loop leaves exposure and gain where it had them.
    TuneAuto(bool),
    /// Open a session on the card, run this job in it with [`card::run`],
    /// and report [`Event::Card`]. The loop draws the screen given with it
    /// first: the S3 units cannot draw while the card has the display's pins.
    Card(Job),
    /// Nothing to do but click: the tap was taken, and its work is done and
    /// its screen drawn on the next tick.
    Deferred,
}

/// One step's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    pub screen: Screen,
    pub command: Option<Command>,
}
