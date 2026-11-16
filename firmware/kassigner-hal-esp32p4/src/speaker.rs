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

//! The speaker: the ES8311 codec and the NS4150B amplifier, behind
//! `kassigner-hal`'s `Speaker`, for the device's cues (`kassigner_fw::cues`).
//! Sequences go out through `audio::player` over I2S0, the tick through
//! `audio::ring`, which sounds while the processor is busy; a sound started
//! meanwhile stops the tick.
//!
//! The amplifier is switched on after the codec is set up, so the codec's
//! set-up noise never reaches the speaker, and then stays on.

use esp_hal::dma::DmaTxStreamBuf;
use esp_hal::gpio::Output;
use kassigner_hal::speaker::{Note, Speaker};

use crate::audio::es8311::Es8311;
use crate::audio::player::{Player, Playing, Ringing, AMPLITUDE, SAMPLE_RATE};
use crate::audio::ring::DmaRing;
use crate::cam::SharedBus;

/// The volume the unit starts at, on the 0 to 255 scale: 50%.
pub const DEFAULT_VOLUME: u8 = 128;

/// The speaker. Without a player (the codec or I2S would not set up) it
/// plays nothing, and the unit still signs.
pub struct P4Speaker {
    player: Option<Player<'static>>,
    stream: Option<DmaTxStreamBuf>,
    /// A sequence [`Speaker::start`] began, until [`Speaker::finish`].
    playing: Option<Playing<'static>>,
    /// The tick's ring, and while it plays, its transfer.
    ring: Option<DmaRing>,
    ticking: Option<Ringing<'static>>,
    bus: &'static SharedBus,
    /// The amplifier's enable, held so it stays driven.
    _amp: Output<'static>,
}

impl P4Speaker {
    /// Over a player, its stream buffer, the tick's ring, the codec's bus
    /// and the amplifier's enable. Set the codec up and the amplifier on
    /// first.
    pub fn new(
        player: Option<Player<'static>>,
        stream: DmaTxStreamBuf,
        ring: Option<DmaRing>,
        bus: &'static SharedBus,
        amp: Output<'static>,
    ) -> Self {
        Self {
            player,
            stream: Some(stream),
            playing: None,
            ring,
            ticking: None,
            bus,
            _amp: amp,
        }
    }

    /// Whether it can play.
    pub fn plays(&self) -> bool {
        self.player.is_some()
    }
}

impl Speaker for P4Speaker {
    fn tone(&mut self, note: Note) {
        self.play(&[note]);
    }

    /// Nothing sounds between sequences: each one's transfer ends with it.
    fn silence(&mut self) {}

    /// The codec's volume runs 0 to 100.
    fn set_volume(&mut self, volume: u8) {
        let percent = (u32::from(volume) * 100 / 255) as u8;
        let _ = Es8311::set_volume(&mut self.bus.borrow_mut(), percent);
    }

    /// The note, then silence, played round and round, about twelve times
    /// a second, until [`Speaker::stop_ticking`], even while the CPU is busy.
    fn start_ticking(&mut self, note: Note) {
        if self.ticking.is_some() {
            return;
        }
        self.finish();
        let (Some(player), Some(mut ring)) = (self.player.as_mut(), self.ring.take()) else {
            return;
        };
        fill_tick(ring.buffer_mut(), note);
        match player.start_ring(ring) {
            Ok(ringing) => self.ticking = Some(ringing),
            Err(ring) => self.ring = Some(ring),
        }
    }

    fn stop_ticking(&mut self) {
        if let (Some(player), Some(ringing)) = (self.player.as_mut(), self.ticking.take()) {
            self.ring = Some(player.stop_ring(ringing));
        }
    }

    /// The notes as one stream, played through.
    fn play(&mut self, notes: &[Note]) {
        self.start(notes);
        self.finish();
    }

    /// The notes as one stream, returning once they are all in it: at once
    /// for a click, which plays from the buffer while the caller draws.
    fn start(&mut self, notes: &[Note]) {
        self.stop_ticking();
        self.finish();
        let (Some(player), Some(stream)) = (self.player.as_mut(), self.stream.take()) else {
            return;
        };
        match player.begin(notes, stream) {
            Ok(playing) => self.playing = Some(playing),
            Err((_, stream)) => self.stream = stream,
        }
    }

    /// Let the stream play out and stop it.
    fn finish(&mut self) {
        if let (Some(player), Some(playing)) = (self.player.as_mut(), self.playing.take()) {
            self.stream = Some(player.end(playing));
        }
    }
}

/// The tick in `buf`: `note`'s whole cycles that fit its milliseconds, from
/// zero, then silence; stereo, sixteen bits, little endian. Its peak is
/// `AMPLITUDE` times the note's level over 10,000, the loudest cue's.
fn fill_tick(buf: &mut [u8], note: Note) {
    use kassigner_hal::speaker::{wave, CYCLE};
    buf.fill(0);
    let hz = u64::from(note.hz);
    if hz == 0 || hz * 2 > u64::from(SAMPLE_RATE) {
        return;
    }
    let cycles = hz * u64::from(note.ms) / 1000;
    let frames = (cycles * u64::from(SAMPLE_RATE) / hz).min((buf.len() / 4) as u64);
    let height = AMPLITUDE * i32::from(note.level.min(10_000)) / 10_000;
    for f in 0..frames {
        let phase = ((f * cycles * u64::from(CYCLE)) / frames.max(1)) as u32;
        let v = ((wave(note.hz, phase) * height) >> 15) as i16;
        let b = v.to_le_bytes();
        let o = f as usize * 4;
        buf[o..o + 4].copy_from_slice(&[b[0], b[1], b[0], b[1]]);
    }
}
