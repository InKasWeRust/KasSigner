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

//! The AW88298 amplifier and the tones played through it.
//!
//! [`M5Speaker`] implements [`kassigner_hal::speaker::Speaker`]: what each
//! cue sounds like is the HAL's; this module makes the notes sound.
//!
//! # How sound works on this board
//!
//! I2S1 plays a DMA ring forever (`ring`), zeros as silence. Nothing starts
//! or stops, so nothing pops: only what is written changes. [`M5Speaker`]
//! takes the buffer esp-hal's I2S and DMA read. A tone is a fill then
//! silence, and anything that blocks between the two leaves it playing:
//! `silence` is for a caller about to do something long.
//!
//! The wave is the HAL's [`kassigner_hal::speaker::wave`], as on the P4: a
//! sine with its third and fifth harmonics under 1 kHz. A square wave
//! distorts: its harmonics run past half the sample rate and fold back as
//! tones that are not the note's.
//!
//! # The amplifier's set-up
//!
//! [`INIT`] is what M5Unified writes in `_speaker_enabled_cb_cores3` for
//! 48 kHz. The amplifier answers only once the I2S clocks run, so [`init`]
//! comes after the stream starts; a write it does not acknowledge is an
//! error.
//!
//! # The buffer is read by DMA
//!
//! Nothing in Rust reads a fill before silence overwrites it, so a compiler
//! may drop it as dead. A compiler fence after each fill prevents that, at
//! no run-time cost.
//!
//! Zero hertz has no wave: [`fill_tone`] fills silence.

use core::sync::atomic::{compiler_fence, Ordering};

use embedded_hal::i2c::I2c;
use kassigner_hal::speaker::{wave, Note, Speaker, CYCLE};
use kassigner_hal::timer::Timer;

use crate::systimer::SysTimer;

use super::pmu;

/// I2C address.
pub const ADDRESS: u8 = 0x36;

/// Sample rate the stream runs at and [`INIT`] configures.
pub const SAMPLE_RATE: u32 = 48_000;

/// The volume the unit starts at, on the 0 to 255 scale: 8%, which the
/// Audio screen shows as 8.
pub const DEFAULT_VOLUME: u8 = 21;

/// What the whole volume scale spans: 255 is half a note's level, which
/// gives the low end twice the steps. The speaker and its amplifier are loud
/// for their size: 5% of full height is still too loud.
pub const VOLUME_FULL: i32 = 510;

/// Chip ID.
const REG_ID: u8 = 0x00;
/// System status.
const REG_SYSST: u8 = 0x01;
/// System control.
const REG_SYSCTRL: u8 = 0x04;

/// The amplifier's configuration, in order, sixteen bits a register: boost
/// off; I2S on and the amplifier powered; no AGC and no mute; 48 kHz with a
/// 32-bit frame; volume.
pub const INIT: [(u8, u16); 5] = [
    (0x61, 0x0673),
    (REG_SYSCTRL, 0x4040),
    (0x05, 0x0008),
    (0x06, 0x14C8),
    (0x0C, 0x0064),
];

/// Wait after the reset line is released, before the first transfer.
const RESET_RELEASE_MS: u32 = 100;
/// Wait after the configuration.
const SETTLE_MS: u32 = 50;

/// Why the amplifier did not come up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The expander would not release the amplifier's reset.
    Reset,
    /// Nothing answered at [`ADDRESS`].
    NotFound,
    /// A configuration write was not acknowledged.
    WriteFailed { reg: u8 },
}

fn write_reg<I: I2c>(i2c: &mut I, reg: u8, val: u16) -> Result<(), I::Error> {
    i2c.write(ADDRESS, &[reg, (val >> 8) as u8, val as u8])
}

/// Read one sixteen-bit register.
///
/// # Errors
///
/// The bus error, if the read failed.
pub fn read_reg<I: I2c>(i2c: &mut I, reg: u8) -> Result<u16, I::Error> {
    let mut buf = [0u8; 2];
    i2c.write_read(ADDRESS, &[reg], &mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// Release the amplifier's reset, identify it and configure it; the I2S
/// stream must already be running.
///
/// Returns the chip ID, reported rather than checked: the value read on the
/// units at hand is not confirmed across board revisions, and a wrong
/// constant would silence working hardware.
///
/// # Errors
///
/// `Reset`, `NotFound`, or `WriteFailed` naming the register.
pub fn init<I: I2c, T: Timer + ?Sized>(i2c: &mut I, timer: &mut T) -> Result<u16, Error> {
    pmu::set_output(i2c, pmu::AW_RST, true).map_err(|_| Error::Reset)?;
    timer.delay_ms(RESET_RELEASE_MS);

    let id = read_reg(i2c, REG_ID).map_err(|_| Error::NotFound)?;
    for &(reg, val) in &INIT {
        write_reg(i2c, reg, val).map_err(|_| Error::WriteFailed { reg })?;
    }
    timer.delay_ms(SETTLE_MS);
    Ok(id)
}

/// The status and control registers, for a caller that wants to print them.
///
/// # Errors
///
/// The bus error, if either read failed.
pub fn status<I: I2c>(i2c: &mut I) -> Result<(u16, u16), I::Error> {
    Ok((read_reg(i2c, REG_SYSST)?, read_reg(i2c, REG_SYSCTRL)?))
}

/// Fill `buf` with the note's wave at `amplitude`: stereo, sixteen bits,
/// little endian.
///
/// The buffer holds a whole number of cycles, the nearest to `freq_hz`: a
/// loop that ended mid-cycle would tick every time round. The pitch moves
/// by at most half a cycle a loop, under 6 Hz for the ring. Zero hertz fills
/// silence; above half the sample rate the buffer is left as it was.
pub fn fill_tone(buf: &mut [u8], freq_hz: u16, amplitude: i16) {
    if freq_hz == 0 {
        buf.fill(0);
        return;
    }
    let total = (buf.len() / 4) as u64;
    let rate = u64::from(SAMPLE_RATE);
    let cycles = ((u64::from(freq_hz) * total * 2 + rate) / (2 * rate)).max(1);
    if cycles * 2 > total {
        return;
    }
    // `cycles` whole cycles over `total` frames: a whole step a frame, the
    // remainder carried, so the frame after the last is the first again. No
    // division a frame: a note's ramp fills the whole ring several times.
    let span = cycles * u64::from(CYCLE);
    let (step, rem) = ((span / total) as u32, span % total);
    let (mut phase, mut carry) = (0u32, 0u64);
    for f in 0..total as usize {
        let v = ((wave(freq_hz, phase) * i32::from(amplitude)) >> 15) as i16;
        let b = v.to_le_bytes();
        buf[f * 4..f * 4 + 4].copy_from_slice(&[b[0], b[1], b[0], b[1]]);
        phase = phase.wrapping_add(step);
        carry += rem;
        if carry >= total {
            carry -= total;
            phase = phase.wrapping_add(1);
        }
    }
}

/// Milliseconds, and steps, a note takes to rise to its height and to fall
/// from it: three steps of a quarter each.
pub const RAMP_STEPS: u32 = 3;

/// The speaker: the buffer the I2S stream plays, and a volume.
pub struct M5Speaker<T = SysTimer> {
    buf: &'static mut [u8],
    volume: u8,
    timer: T,
}

impl M5Speaker<SysTimer> {
    /// Take the stream's buffer. It is silenced here.
    pub fn new(buf: &'static mut [u8]) -> Self {
        Self::with_timer(buf, SysTimer)
    }
}

impl<T: Timer> M5Speaker<T> {
    /// Take the stream's buffer, with the clock the tones are timed by: for
    /// tests, which cannot read SYSTIMER.
    pub fn with_timer(buf: &'static mut [u8], timer: T) -> Self {
        let mut s = Self {
            buf,
            volume: DEFAULT_VOLUME,
            timer,
        };
        s.silence();
        s
    }

    /// The volume.
    pub fn volume(&self) -> u8 {
        self.volume
    }

    /// What the stream is playing, for a test.
    pub fn buffer(&self) -> &[u8] {
        self.buf
    }

    /// The clock the tones are timed by, for a test.
    pub fn timer(&self) -> &T {
        &self.timer
    }

    /// A level scaled by the volume.
    fn scaled(&self, level: u16) -> i16 {
        let level = i32::from(level.min(i16::MAX as u16));
        (level * i32::from(self.volume) / VOLUME_FULL) as i16
    }

    /// Wait until `ms` milliseconds after `start`, if that is still ahead.
    fn until(&mut self, start: u64, ms: u32) {
        let left = (start + u64::from(ms) * 1000).saturating_sub(self.timer.now_us());
        if left > 0 {
            self.timer.delay_us(left as u32);
        }
    }
}

impl<T: Timer> Speaker for M5Speaker<T> {
    /// Fill the stream with the note and wait it out, leaving it playing.
    ///
    /// A note long enough rises over its first [`RAMP_STEPS`] milliseconds
    /// and falls over its last, a quarter of its height a millisecond, the
    /// whole ring rewritten each step: a wave switched straight on gives high
    /// notes a hard, slightly broken attack.
    ///
    /// Each step waits until its own time after the note began, so a fill's
    /// time comes out of the wait and the note takes exactly its
    /// milliseconds.
    fn tone(&mut self, note: Note) {
        let start = self.timer.now_us();
        let full = self.scaled(note.level);
        let ms = u32::from(note.ms);
        if note.hz == 0 || ms < 2 * RAMP_STEPS + 2 {
            fill_tone(self.buf, note.hz, full);
            compiler_fence(Ordering::SeqCst);
            self.until(start, ms);
            return;
        }
        let height = |k: u32| (i32::from(full) * k as i32 / (RAMP_STEPS as i32 + 1)) as i16;
        for k in 1..=RAMP_STEPS {
            fill_tone(self.buf, note.hz, height(k));
            compiler_fence(Ordering::SeqCst);
            self.until(start, k);
        }
        fill_tone(self.buf, note.hz, full);
        compiler_fence(Ordering::SeqCst);
        self.until(start, ms - RAMP_STEPS);
        for k in (1..=RAMP_STEPS).rev() {
            fill_tone(self.buf, note.hz, height(k));
            compiler_fence(Ordering::SeqCst);
            self.until(start, ms - k + 1);
        }
    }

    fn silence(&mut self) {
        self.buf.fill(0);
        compiler_fence(Ordering::SeqCst);
    }

    fn set_volume(&mut self, volume: u8) {
        self.volume = volume;
    }

    /// The note at the start of the buffer and silence after it, so the stream
    /// plays tick, pause, tick until overwritten. The tick is as many whole
    /// cycles as fit the note's milliseconds: it starts and ends at zero, so
    /// neither edge steps.
    fn start_ticking(&mut self, note: Note) {
        self.buf.fill(0);
        if note.hz == 0 || u32::from(note.hz) * 2 > SAMPLE_RATE {
            compiler_fence(Ordering::SeqCst);
            return;
        }
        let total_frames = self.buf.len() / 4;
        let cycles = u32::from(note.hz) * u32::from(note.ms) / 1000;
        let click_frames = (cycles * SAMPLE_RATE / u32::from(note.hz)) as usize;
        let click_bytes = click_frames.min(total_frames) * 4;
        let amplitude = self.scaled(note.level);
        fill_tone(&mut self.buf[..click_bytes], note.hz, amplitude);
        compiler_fence(Ordering::SeqCst);
    }

    fn stop_ticking(&mut self) {
        self.silence();
    }
}
