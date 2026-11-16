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

//! What a board is asked to do with a note.
//!
//! Which notes make which cue is `kassigner-fw`'s, and tested there.

use kassigner_hal::speaker::{wave, Loudness, Note, Pcm, Silent, Speaker, CYCLE, RICH_BELOW_HZ};

/// What a board was asked to do.
#[derive(Debug, PartialEq)]
enum Call {
    Tone(Note),
    Silence,
    Tick(Note),
    Stop,
    Volume(u8),
}

#[derive(Default)]
struct Recorder(Vec<Call>);

impl Speaker for Recorder {
    fn tone(&mut self, note: Note) {
        self.0.push(Call::Tone(note));
    }
    fn silence(&mut self) {
        self.0.push(Call::Silence);
    }
    fn set_volume(&mut self, volume: u8) {
        self.0.push(Call::Volume(volume));
    }
    fn start_ticking(&mut self, note: Note) {
        self.0.push(Call::Tick(note));
    }
    fn stop_ticking(&mut self) {
        self.0.push(Call::Stop);
    }
}

/// **A note is hertz, loudness and milliseconds, and a rest is silence with a
/// duration.**
#[test]
fn a_rest_is_a_note_at_zero_hertz() {
    assert_eq!(Note::rest(50), Note::new(0, 0, 50));
    let n = Note::new(4000, 8000, 30);
    assert_eq!((n.hz, n.level, n.ms), (4000, 8000, 30));
}

/// **Every call reaches the board, and a board without a speaker takes them
/// all.**
#[test]
fn silent_takes_every_call() {
    fn feedback(s: &mut dyn Speaker) {
        s.set_volume(200);
        s.tone(Note::new(1000, 5000, 10));
        s.silence();
        s.start_ticking(Note::new(2000, 5000, 15));
        s.stop_ticking();
    }
    feedback(&mut Silent);

    let mut r = Recorder::default();
    feedback(&mut r);
    assert_eq!(
        r.0,
        vec![
            Call::Volume(200),
            Call::Tone(Note::new(1000, 5000, 10)),
            Call::Silence,
            Call::Tick(Note::new(2000, 5000, 15)),
            Call::Stop,
        ]
    );
}

/// **A sequence's samples are exactly its frames, in any size of piece:**
/// every note's length at the rate, rests and empty notes included, whole
/// frames only, both slots the same.
#[test]
fn pcm_makes_every_frame_once() {
    let click = [Note::new(4000, 8000, 30)];
    let boot = [
        Note::new(800, 6000, 100),
        Note::new(1200, 6000, 100),
        Note::new(1600, 6000, 150),
    ];
    let error = [
        Note::new(300, 10000, 150),
        Note::rest(50),
        Note::new(300, 10000, 150),
    ];
    let empty = [Note::new(1000, 5000, 0), Note::new(2000, 5000, 10)];
    for (notes, frames) in [
        (&click[..], 1440),
        (&boot[..], 16800),
        (&error[..], 16800),
        (&empty[..], 480),
        (&[][..], 0),
    ] {
        for piece in [8192usize, 1024, 6] {
            let mut pcm = Pcm::new(notes, 48_000, Loudness::Fixed(16384));
            assert_eq!(pcm.frames_left(), frames);
            let mut buf = vec![0u8; piece];
            let mut total = 0;
            let mut guard = 0;
            while !pcm.done() {
                let n = pcm.fill(&mut buf);
                assert_eq!(n % 4, 0);
                assert!(buf[..n].chunks(4).all(|f| f[0..2] == f[2..4]), "both slots");
                total += n;
                guard += 1;
                assert!(guard < 100_000);
            }
            assert_eq!(total, frames * 4, "{frames} frames in pieces of {piece}");
            assert_eq!(pcm.frames_left(), 0);
        }
    }
}

/// **Loudness: a fixed peak, or each note's level times the volume.** A
/// rest is silent either way.
#[test]
fn pcm_loudness() {
    let peak = |notes: &[Note], loudness| {
        let mut pcm = Pcm::new(notes, 48_000, loudness);
        let mut buf = vec![0u8; 4 * 480];
        let n = pcm.fill(&mut buf);
        buf[..n]
            .chunks(4)
            .map(|f| i16::from_le_bytes([f[0], f[1]]).unsigned_abs())
            .max()
            .unwrap_or(0)
    };
    let note = [Note::new(1000, 8000, 10)];
    assert!((16000..=16384).contains(&peak(&note, Loudness::Fixed(16384))));
    let scaled = u16::try_from(8000 * 128 / 255).unwrap();
    assert!((scaled - 60..=scaled).contains(&peak(&note, Loudness::Level { volume: 128 })));
    assert_eq!(peak(&note, Loudness::Level { volume: 0 }), 0);
    assert_eq!(peak(&[Note::rest(10)], Loudness::Fixed(16384)), 0);
}

/// **Every note starts and ends at silence:** no sample steps further than
/// the wave itself moves, at a rest, between notes, or at the ends.
#[test]
fn pcm_notes_fade_at_their_edges() {
    let error = [
        Note::new(300, 10000, 150),
        Note::rest(50),
        Note::new(300, 10000, 150),
    ];
    let mut pcm = Pcm::new(&error, 48_000, Loudness::Fixed(16384));
    let mut buf = vec![0u8; 4 * 16800];
    let n = pcm.fill(&mut buf);
    let s: Vec<i32> = buf[..n]
        .chunks(4)
        .map(|f| i32::from(i16::from_le_bytes([f[0], f[1]])))
        .collect();
    assert_eq!(s.len(), 16800);
    // With its harmonics a 300 Hz wave moves at most three times as fast as
    // the sine alone, 2 pi 300 / 48000 of the peak a frame, times 15/14:
    // about 2,070. Nothing may jump further.
    let steepest = s.windows(2).map(|w| (w[1] - w[0]).abs()).max().unwrap();
    assert!(steepest <= 2_100, "a step of {steepest}");
    // The edges themselves: first and last frame of each note near zero.
    for at in [0, 7199, 9600, 16799] {
        assert!(s[at].abs() <= 200, "frame {at} is {}", s[at]);
    }
    // And the middle of a note is still at full height.
    let middle = s[1000..6000].iter().map(|v| v.abs()).max().unwrap();
    assert!(middle >= 16000, "peak {middle}");
}

/// **The wave both speakers play:** from the boundary up the sine, exact at
/// its quarters; below, with its third and fifth harmonics, within full
/// height and zero at the start. A phase that has gone round a whole number
/// of cycles reads as zero does, so the M5 can loop a buffer of whole cycles
/// without a jump.
#[test]
fn the_wave_is_a_sine_with_harmonics_below_the_boundary() {
    let quarters: Vec<i32> = (0..4).map(|q| wave(RICH_BELOW_HZ, q * CYCLE / 4)).collect();
    assert_eq!(quarters, [0, 32767, 0, -32767]);

    let low = RICH_BELOW_HZ - 1;
    assert_eq!(wave(low, 0), 0);
    let peak = (0..CYCLE)
        .step_by(1 << 10)
        .map(|p| wave(low, p).abs())
        .max()
        .unwrap();
    assert!((32_000..=32_767).contains(&peak), "{peak}");
    assert_ne!(
        wave(low, CYCLE / 8),
        wave(RICH_BELOW_HZ, CYCLE / 8),
        "the harmonics are there"
    );

    for p in [0, 12_345, CYCLE / 3, CYCLE - 1] {
        assert_eq!(wave(300, p + 7 * CYCLE), wave(300, p));
        assert_eq!(wave(4000, p + 7 * CYCLE), wave(4000, p));
    }
}
