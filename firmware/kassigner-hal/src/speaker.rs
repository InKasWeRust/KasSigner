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

//! Sound: what the device plays, and how a board plays it.
//!
//! A board plays a note, goes silent, sets a volume, and repeats a note as a
//! tick. Which notes make each cue lives in `kassigner_fw::cues`, so every
//! board sounds the same; a board without audio uses [`Silent`].
//!
//! [`Speaker::tone`] blocks until the note has played. Nothing here fails: a
//! flow signing a transaction should not stop because a beep did not play,
//! so a board reports failure at its audio set-up, as the M5's amplifier
//! init does.

/// One note: a tone at `hz`, at `level`, for `ms`. `level` is the peak on a
/// sixteen-bit scale, before the volume. Zero hertz is a rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub hz: u16,
    pub level: u16,
    pub ms: u16,
}

impl Note {
    pub const fn new(hz: u16, level: u16, ms: u16) -> Self {
        Self { hz, level, ms }
    }

    /// Silence for `ms`.
    pub const fn rest(ms: u16) -> Self {
        Self {
            hz: 0,
            level: 0,
            ms,
        }
    }
}

/// A board's speaker.
pub trait Speaker {
    /// Play `note`, returning once it has played. It may keep sounding until
    /// the next call.
    fn tone(&mut self, note: Note);

    /// Stop sounding, now.
    fn silence(&mut self);

    /// Set the volume, 0 to 255.
    fn set_volume(&mut self, volume: u8);

    /// Start `note` repeating, that note then silence, until
    /// [`Speaker::stop_ticking`]. Returns at once.
    fn start_ticking(&mut self, note: Note);

    /// Stop the tick.
    fn stop_ticking(&mut self);

    /// Play `notes` in turn, returning once the last has played, and end
    /// silent. A board that can stream a sequence with no gap between notes
    /// does so here.
    fn play(&mut self, notes: &[Note]) {
        for &note in notes {
            self.tone(note);
        }
        self.silence();
    }

    /// Start `notes` and return once they play on by themselves, for a sound
    /// that must not hold up what follows (a click under a redraw);
    /// [`Speaker::finish`] ends them. The default, for a board that cannot
    /// play in the background, plays them to the end here.
    fn start(&mut self, notes: &[Note]) {
        self.play(notes);
    }

    /// End what [`Speaker::start`] began, once it has played. The default
    /// has nothing to end.
    fn finish(&mut self) {}
}

/// A speaker that plays nothing, for a board without one.
#[derive(Clone, Copy, Debug, Default)]
pub struct Silent;

impl Speaker for Silent {
    fn tone(&mut self, _note: Note) {}
    fn silence(&mut self) {}
    fn set_volume(&mut self, _volume: u8) {}
    fn start_ticking(&mut self, _note: Note) {}
    fn stop_ticking(&mut self) {}
}

// ── Samples ─────────────────────────────────────────────────────────────────

/// One cycle of a sine wave, 64 samples, full scale, precomputed so no
/// floating point runs on a device.
const SINE: [i16; 64] = [
    0, 3212, 6393, 9512, 12539, 15446, 18204, 20787, 23170, 25329, 27245, 28898, 30273, 31356,
    32137, 32609, 32767, 32609, 32137, 31356, 30273, 28898, 27245, 25329, 23170, 20787, 18204,
    15446, 12539, 9512, 6393, 3212, 0, -3212, -6393, -9512, -12539, -15446, -18204, -20787, -23170,
    -25329, -27245, -28898, -30273, -31356, -32137, -32609, -32767, -32609, -32137, -31356, -30273,
    -28898, -27245, -25329, -23170, -20787, -18204, -15446, -12539, -9512, -6393, -3212,
];

/// How loud a sequence's samples are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loudness {
    /// Each note's own level, scaled by a volume out of 255, for a board
    /// whose volume is in the samples.
    Level { volume: u8 },
    /// One peak for every note: the P4, whose volume is the codec's.
    Fixed(i16),
}

/// A sequence's samples as the P4 streams them: [`wave`], 16-bit little
/// endian, the same in both slots of each stereo frame, a buffer at a time.
/// (The M5 writes [`wave`] into its own ring.) Sent once, not looped, a
/// stream starts and ends each sound where its samples do.
///
/// Each note starts its wave at zero and fades in and out over [`FADE_MS`]:
/// a note cut off mid-cycle steps from wherever the wave was to silence, a
/// click the speaker plays at full force. A low note steps furthest, its
/// slow wave being far from zero for longest.
pub struct Pcm<'a> {
    notes: &'a [Note],
    at: usize,
    left: usize,
    /// Frames in the note being made.
    total: usize,
    rate: u32,
    phase: u32,
    loudness: Loudness,
}

/// How long each note takes to rise from silence and fall back to it.
pub const FADE_MS: u32 = 3;

/// Below this, a note also carries its third and fifth harmonics at a third
/// and a fifth of its height, a square wave's first terms without its
/// edges. A small speaker gives back little of a pure low sine: on the M5 a
/// 300 Hz sine played far quieter than a 4 kHz click, and harmonics at 900
/// and 1500 Hz carry it.
pub const RICH_BELOW_HZ: u16 = 1000;

/// A full cycle of a phase: the table's 64 points, `1 << 16` apart.
pub const CYCLE: u32 = 64 << 16;

/// The sine at `phase`, a full cycle being [`CYCLE`], read between the
/// table's 64 points by the phase's next eight bits.
fn sine_at(phase: u32) -> i32 {
    let i = ((phase >> 16) & 0x3F) as usize;
    let (a, b) = (i32::from(SINE[i]), i32::from(SINE[(i + 1) & 0x3F]));
    let t = ((phase >> 8) & 0xFF) as i32;
    a + (((b - a) * t) >> 8)
}

/// The wave every note is played with, at `phase` (a full cycle is
/// [`CYCLE`]), at full height (32,767): a sine, and under [`RICH_BELOW_HZ`]
/// the sine with its third and fifth harmonics. The P4 plays it through
/// [`Pcm`], the M5 from the ring its I2S plays round.
///
/// Not a square wave: its edges carry harmonics past half the sample rate,
/// which fold back as tones that are not the note's, and its halves are
/// uneven when a period is not a whole number of frames; the M5 played both
/// as distortion. The sine is read between the table's points, or a low
/// note is a staircase (160 frames a cycle at 300 Hz on 64 steps) heard as
/// grit. A phase that has gone round a whole number of cycles reads as
/// zero does.
pub fn wave(hz: u16, phase: u32) -> i32 {
    if hz < RICH_BELOW_HZ {
        // The three terms peak at 14/15 of full height, so 15/14 brings
        // them back to it.
        let sum = sine_at(phase)
            + sine_at(phase.wrapping_mul(3)) / 3
            + sine_at(phase.wrapping_mul(5)) / 5;
        (sum * 15 / 14).clamp(-32767, 32767)
    } else {
        sine_at(phase)
    }
}

impl<'a> Pcm<'a> {
    /// `notes` at `rate` frames a second, starting at a zero crossing.
    pub fn new(notes: &'a [Note], rate: u32, loudness: Loudness) -> Self {
        let mut p = Self {
            notes,
            at: 0,
            left: 0,
            total: 0,
            rate,
            phase: 0,
            loudness,
        };
        p.left = p.frames_of(0);
        p.total = p.left;
        p.skip_empty();
        p
    }

    fn frames_of(&self, i: usize) -> usize {
        self.notes
            .get(i)
            .map_or(0, |n| (self.rate / 1000) as usize * usize::from(n.ms))
    }

    /// On to the next note with frames, its sine starting at zero.
    fn skip_empty(&mut self) {
        while self.left == 0 && self.at < self.notes.len() {
            self.at += 1;
            self.left = self.frames_of(self.at);
            self.total = self.left;
            self.phase = 0;
        }
    }

    /// The fade on the frame about to be made, out of 256: rising over the
    /// note's first [`FADE_MS`], falling over its last, at most half the
    /// note each way.
    fn fade(&self) -> i32 {
        let ramp = ((self.rate * FADE_MS / 1000) as usize)
            .min(self.total / 2)
            .max(1);
        let done = self.total - self.left;
        let edge = done.min(self.left - 1).min(ramp);
        (edge * 256 / ramp) as i32
    }

    /// Frames still to make.
    pub fn frames_left(&self) -> usize {
        self.left
            + (self.at + 1..self.notes.len())
                .map(|i| self.frames_of(i))
                .sum::<usize>()
    }

    /// Whether every frame has been made.
    pub fn done(&self) -> bool {
        self.at >= self.notes.len()
    }

    /// Fill whole frames of `out`, four bytes each, returning the bytes
    /// written.
    pub fn fill(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n + 4 <= out.len() && !self.done() {
            let note = self.notes[self.at];
            let peak = match self.loudness {
                Loudness::Level { volume } => {
                    (i32::from(note.level.min(i16::MAX as u16)) * i32::from(volume) / 255) as i16
                }
                Loudness::Fixed(peak) => peak,
            };
            let v = if note.hz == 0 {
                0
            } else {
                ((((wave(note.hz, self.phase) * i32::from(peak)) >> 15) * self.fade()) >> 8) as i16
            };
            // A full cycle is 64 << 16. The step is 32-bit throughout:
            // `hz * 65536` fits a `u32` for any `u16` hz.
            self.phase = self
                .phase
                .wrapping_add((u32::from(note.hz) * 65536 / self.rate) * 64);
            let b = v.to_le_bytes();
            out[n..n + 4].copy_from_slice(&[b[0], b[1], b[0], b[1]]);
            n += 4;
            self.left -= 1;
            self.skip_empty();
        }
        n
    }
}
