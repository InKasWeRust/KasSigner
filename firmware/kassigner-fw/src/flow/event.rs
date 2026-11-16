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

//! What the loop reports, and what a tap lands on.

use super::*;

// ── What the loop reports ───────────────────────────────────────────────────

/// Something that happened, reported by the loop.
#[derive(Clone, Copy, Debug)]
pub enum Event<'e> {
    /// The board is up: the self-test has run and the fuses are read.
    Booted {
        /// The fuse reader's verdict.
        provisioning: Verdict,
        /// Whether the board read its image's hash; if not, the verification
        /// screen shows it red.
        image_read: bool,
        /// Whether every start-up check passed; which checks run is the
        /// board's choice.
        checks_ok: bool,
    },
    /// Time passed; sent every loop pass.
    Tick {
        /// The board's monotonic clock.
        now_us: u64,
    },
    /// A finger lifted from the screen, here.
    Tap { x: u16, y: u16 },
    /// A finger is down, here; a hold is measured from it.
    Press { x: u16, y: u16 },
    /// A finger that is down moved here.
    Drag { x: u16, y: u16 },
    /// A payload reassembled from its frames.
    Payload(&'e [u8]),
    /// A code with no frame header: a SeedQR, or a stray code in view.
    Code(&'e [u8]),
    /// Frames of `Format::Opaque` reassembled, bytes only the screen that
    /// asked can read: Sign Message's text in frames.
    Opaque(&'e [u8]),
    /// Frames received, `have` of `total`, and which: bit `i` of `received`
    /// for frame `i`, the first 64.
    Progress {
        have: usize,
        total: usize,
        received: u64,
    },
    /// The scanner read a code that could be a v1.0.7 set's last frame or a
    /// 24-word compact SeedQR ([`crate::scan::Step::LastFrameOrSeed`]); sent
    /// at each read. Read alone for [`SEED_HINT_US`], it is taken for the
    /// seed, and the scan screen says how else to load it.
    LastFrameOrSeed,
    /// A camera sample for the seed: the delta between two frames.
    CameraSample(&'e [u8]),
    /// An IMU sample for the seed.
    ImuSample(&'e [u8]),
    /// The finger moved, for the seed.
    TouchMoved { x: u16, y: u16, since_us: u32 },
    /// The camera's settings read off the sensor, one per knob, and the
    /// exposure loop's switch if any: sent as the tuning screen opens and
    /// after every change, so it shows the sensor's values.
    Tuned {
        values: &'e [u8],
        auto: Option<bool>,
    },
    /// How a [`Command::Card`] job went.
    Card(Outcome),
    /// The camera is on but its frames have failed long enough for the
    /// binary to call it lost (a loose connector, a stopped sensor). Every
    /// screen using it is refused: the scanners, the tuning screen and the
    /// seed's sampling, which would otherwise wait forever.
    CameraLost,
    /// The screen just given did not reach the panel: the panel or its bus
    /// failed partway. Sent at once, before anything else is stepped. On a
    /// review page or CONFIRM SEND? the review is refused
    /// ([`Refusal::NotDrawn`]) and the page not counted seen, rather than
    /// left live behind a panel that does not show it; elsewhere, ignored.
    NotDrawn,
}

/// What a tap lifting at `(x, y)` lands on through `target`, if the finger
/// went down on the same target at `pressed_at`. Slid onto or off a target,
/// or with no press seen, it lands on nothing: on the unit every lift
/// follows a press.
pub(super) fn tapped<T: PartialEq>(
    pressed_at: Option<(u16, u16)>,
    (x, y): (u16, u16),
    target: impl Fn(u16, u16) -> Option<T>,
) -> Option<T> {
    let (px, py) = pressed_at?;
    let at = target(x, y)?;
    (target(px, py)? == at).then_some(at)
}
