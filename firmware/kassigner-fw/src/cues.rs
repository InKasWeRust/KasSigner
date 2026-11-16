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

//! What the device plays, and when: tones, each with its own loudness.
//! Design rather than hardware, so every board with a speaker plays the
//! same; [`kassigner_hal::speaker`] holds only what a board does with a
//! note. A rest, a note at zero hertz, is the error beep's pause.

use kassigner_hal::speaker::{Note, Speaker};

use crate::flow::Screen;

/// The repeating tick: this note, then silence, until stopped.
pub const TICK: Note = Note::new(2000, 5000, 15);

/// An event the device marks with a sound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cue {
    /// A touch was taken.
    Click,
    /// A code came into view, or a frame of one in several was taken.
    CodeFound,
    /// A scan read what it was after.
    CodeDecoded,
    /// Something failed.
    Error,
    /// The device started.
    Boot,
    /// A task finished well.
    Success,
    /// A destructive action is next.
    Warning,
}

const CLICK: &[Note] = &[Note::new(4000, 8000, 30)];
const CODE_FOUND: &[Note] = &[Note::new(2000, 4000, 15)];
const CODE_DECODED: &[Note] = &[Note::new(2400, 8000, 30), Note::new(3600, 8000, 30)];
const ERROR: &[Note] = &[
    Note::new(300, 10000, 150),
    Note::rest(50),
    Note::new(300, 10000, 150),
];
const BOOT: &[Note] = &[
    Note::new(800, 6000, 100),
    Note::new(1200, 6000, 100),
    Note::new(1600, 6000, 150),
];
const SUCCESS: &[Note] = &[
    Note::new(1200, 6000, 80),
    Note::new(1600, 6000, 80),
    Note::new(2000, 6000, 120),
];
const WARNING: &[Note] = &[Note::new(1200, 8000, 120), Note::new(600, 8000, 200)];

impl Cue {
    /// What the cue sounds like.
    pub const fn notes(self) -> &'static [Note] {
        match self {
            Cue::Click => CLICK,
            Cue::CodeFound => CODE_FOUND,
            Cue::CodeDecoded => CODE_DECODED,
            Cue::Error => ERROR,
            Cue::Boot => BOOT,
            Cue::Success => SUCCESS,
            Cue::Warning => WARNING,
        }
    }
}

/// Play a cue on a speaker, and end silent.
pub fn play(speaker: &mut (impl Speaker + ?Sized), cue: Cue) {
    speaker.play(cue.notes());
}

/// Start a cue and return once it plays on its own; [`finish`] ends it. For
/// the click, heard while the screen the tap asked for is drawn.
pub fn start(speaker: &mut (impl Speaker + ?Sized), cue: Cue) {
    speaker.start(cue.notes());
}

/// End a cue [`start`] began.
pub fn finish(speaker: &mut (impl Speaker + ?Sized)) {
    speaker.finish();
}

/// The cue a step of the flow earns, from the screens before and after it,
/// whether a tap made it, and whether it gave a command.
///
/// A halt warns; a refusal is an error; a reply after signing and a seed
/// opened succeed; an SD card job that worked succeeds and one that failed
/// is an error; the home screen's first appearance after the checks chimes.
/// A frame of a code in several ticks as it is taken, and a scan that read
/// what it was after chirps as its screen gives way; the tick for a code
/// coming into view is the binary's ([`crate::ui::camera::Sighting`]).
///
/// Every tap that did something clicks first ([`clicks`]); this is the
/// step's other sound, played once its screen is drawn, or the click itself
/// when it has none.
pub fn for_step(before: &Screen, after: &Screen, tapped: bool, commanded: bool) -> Option<Cue> {
    match (before, after) {
        (Screen::Halted(_), Screen::Halted(_)) => None,
        (_, Screen::Halted(_)) => Some(Cue::Warning),
        (Screen::Refused(_), Screen::Refused(_)) => None,
        (_, Screen::Refused(_)) => Some(Cue::Error),
        // Signed: SIGNING gives way to SIGNED TX QR. Other steps among the
        // reply's screens click or are silent (a frame the clock turned, a
        // save's result giving way).
        (Screen::Signing, Screen::ReplyFormat) => Some(Cue::Success),
        // A message signed: SIGNING gives way to the signature.
        (Screen::MessageSigning, Screen::MessageResult { .. }) => Some(Cue::Success),
        // Wiped by Home's logo held: a job done well.
        (Screen::Wiped, Screen::Wiped) => None,
        (_, Screen::Wiped) => Some(Cue::Success),
        // A frame of a code in several taken: a tick, each one.
        (
            Screen::Scanning {
                have: a, total: t, ..
            },
            Screen::Scanning {
                have: b, total: u, ..
            },
        )
        | (
            Screen::MessageScan {
                have: a, total: t, ..
            },
            Screen::MessageScan {
                have: b, total: u, ..
            },
        )
        | (
            Screen::BackupScan {
                have: a, total: t, ..
            },
            Screen::BackupScan {
                have: b, total: u, ..
            },
        ) if *b > 0 && (a, t) != (b, u) => Some(Cue::CodeFound),
        (Screen::Scanning { .. }, Screen::Scanning { .. })
        | (Screen::MessageScan { .. }, Screen::MessageScan { .. })
        | (Screen::BackupScan { .. }, Screen::BackupScan { .. }) => None,
        // The backup check: failed is the error, passed a success.
        (Screen::CheckFailed { .. }, Screen::CheckFailed { .. }) => None,
        (_, Screen::CheckFailed { .. }) => Some(Cue::Error),
        (Screen::BackupChecked, Screen::BackupChecked) => None,
        (_, Screen::BackupChecked) => Some(Cue::Success),
        // A scan read, its screen giving way to what it read: the chirp. A
        // refusal of what it read is the error, above; Back's tap is a
        // click; Home untouched is the idle wipe, silent.
        (Screen::Scanning { .. } | Screen::MessageScan { .. }, after)
            if !tapped && *after != Screen::Home =>
        {
            Some(Cue::CodeDecoded)
        }
        (Screen::Opening { .. }, Screen::Opening { .. }) => None,
        (Screen::Opening { .. }, _) => Some(Cue::Success),
        (Screen::Verified(_), Screen::Home) => Some(Cue::Boot),
        (Screen::CardDone { .. }, Screen::CardDone { .. }) => None,
        // An empty card is said, not sounded.
        (
            _,
            Screen::CardDone {
                outcome: crate::card::Outcome::Listed { .. },
                ..
            },
        ) => None,
        (_, Screen::CardDone { outcome, .. }) => Some(if outcome.ok() {
            Cue::Success
        } else {
            Cue::Error
        }),
        // Rolls refused as not dice, said with the error.
        (Screen::DiceRefused, Screen::DiceRefused) => None,
        (_, Screen::DiceRefused) => Some(Cue::Error),
        // Uneven rolls are warned of, not refused.
        (Screen::DiceUneven, Screen::DiceUneven) => None,
        (_, Screen::DiceUneven) => Some(Cue::Warning),
        // A phrase that failed its checksum: the error, as a refusal.
        (Screen::Words { invalid: true, .. }, Screen::Words { invalid: true, .. }) => None,
        (_, Screen::Words { invalid: true, .. }) => Some(Cue::Error),
        _ if clicks(before, after, tapped, commanded) => Some(Cue::Click),
        _ => None,
    }
}

/// Whether a step clicks: a tap that did something, a screen changed or a
/// command given, whatever other sound the step earns.
pub fn clicks(before: &Screen, after: &Screen, tapped: bool, commanded: bool) -> bool {
    tapped && (commanded || before != after)
}

/// Start the tick on a speaker.
pub fn start_ticking(speaker: &mut (impl Speaker + ?Sized)) {
    speaker.start_ticking(TICK);
}
