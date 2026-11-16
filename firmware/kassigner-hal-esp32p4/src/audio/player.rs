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

//! I2S playback for the ES8311.
//!
//! A sequence goes out as one `DmaTxStreamBuf` transfer kept running while
//! samples are pushed in. Separate transfers let the I2S FIFO empty between
//! them: 512-frame chunks put a gap every 10.6 ms, a 94 Hz rasp.
//!
//! esp-hal hardcodes I2S clock source 2 (EXTERNAL) for the P4, where
//! ESP-IDF uses 0 (XTAL) below revision 3.0; without the fix in
//! `esp-hal-fork/fork.sh`, `I2s::new()` spins forever in `update_tx()`.
//!
//! TDM Philips, 16-bit, stereo frames: the ES8311 is mono, but an I2S frame
//! has two slots, so each sample goes into both (true mono would halve the
//! rate and drop the pitch an octave).
//!
//! ```text
//!   GPIO13 MCLK    GPIO12 BCLK    GPIO10 WS/LRCK    GPIO9 DOUT
//! ```

use esp_hal::{
    dma::DmaTxStreamBuf,
    gpio::interconnect::PeripheralOutput,
    i2s::master::{Channels, DataFormat, I2s, I2sTx, I2sTxDmaTransfer, TdmConfig},
    time::{Instant, Rate},
    Blocking,
};
use kassigner_hal::speaker::{Loudness, Note, Pcm};

use super::ring::DmaRing;

/// Must pair with the supplied MCLK in `es8311`'s coefficient table.
pub const SAMPLE_RATE: u32 = 48_000;

/// Stream buffer size: 8 KB, about 43 ms of stereo 16-bit audio at 48 kHz.
/// A click fits whole, so `Player::begin` returns at once; a longer
/// sequence's refills, pushed in a tight loop, stay far ahead of the DMA.
pub const STREAM_BYTES: usize = 8_192;

/// The stream buffer's descriptor size: `DmaTxStreamBuf::new` refuses fewer
/// than four, and the default 4095 bytes gives an 8 KB buffer three.
pub const STREAM_CHUNK: usize = 2_048;

const _: () = assert!(STREAM_BYTES / STREAM_CHUNK >= 4);

/// Peak amplitude out of 32767: -6 dBFS, since full scale into a small
/// class-D amp clips. Loudness is the codec's volume register.
pub const AMPLITUDE: i32 = 16384;

/// Frames generated per refill pass.
const BATCH: usize = 256;

/// A sequence playing, from [`Player::begin`] until [`Player::end`].
pub struct Playing<'d> {
    transfer: I2sTxDmaTransfer<'d, Blocking, DmaTxStreamBuf>,
    started: Instant,
    /// How long the sequence and its tail take to go out, from `started`.
    lasts_us: u64,
}

/// Silence after every sequence, so the stream stops on a zero after the
/// last note: 256 frames, 5.3 ms.
pub const TAIL_BYTES: usize = BATCH * 4;
const TAIL_US: u64 = (BATCH as u64 * 1_000_000) / SAMPLE_RATE as u64 + 1_000;

/// Tone player over I2S TX DMA. See module docs for the clock caveat.
pub struct Player<'d> {
    tx: Option<I2sTx<'d, Blocking>>,
}

impl<'d> Player<'d> {
    /// Claim the I2S and its DMA channel and set up TX on these pins.
    /// Nothing plays until [`Player::begin`].
    pub fn new<I>(
        i2s: I,
        channel: impl esp_hal::i2s::master::I2sMasterDmaChannel<'d, I>,
        mclk: impl PeripheralOutput<'d>,
        bclk: impl PeripheralOutput<'d>,
        ws: impl PeripheralOutput<'d>,
        dout: impl PeripheralOutput<'d>,
    ) -> Result<Self, esp_hal::i2s::master::ConfigError>
    where
        I: esp_hal::i2s::master::Instance + 'd,
    {
        let i2s = I2s::new(
            i2s,
            channel,
            TdmConfig::new_tdm_philips()
                .with_sample_rate(Rate::from_hz(SAMPLE_RATE))
                .with_data_format(DataFormat::Data16Channel16)
                .with_channels(Channels::STEREO),
        )?
        .with_mclk(mclk);

        let tx = i2s
            .i2s_tx
            .with_bclk(bclk)
            .with_ws(ws)
            .with_dout(dout)
            .build();

        Ok(Self { tx: Some(tx) })
    }

    /// Play a sequence as ONE continuous DMA transfer, returning once it has
    /// played: [`Player::begin`] then [`Player::end`].
    pub fn play(
        &mut self,
        seq: &[Note],
        buf: DmaTxStreamBuf,
    ) -> (Result<(), Error>, Option<DmaTxStreamBuf>) {
        match self.begin(seq, buf) {
            Ok(playing) => (Ok(()), Some(self.end(playing))),
            Err((e, buf)) => (Err(e), buf),
        }
    }

    /// Start a sequence and return once all of it is in the stream: at once
    /// for one that fits the buffer, such as a click, which then plays while
    /// the caller goes on. [`Player::end`] finishes it.
    ///
    /// The buffer is filled before the transfer starts, so only that goes
    /// out (a stream started unfilled first plays all the buffer last held),
    /// and remade each time, since it counts what was filled. The sequence
    /// ends in [`TAIL_BYTES`] of silence, after which the DMA stops by
    /// itself. A sequence longer than the buffer is pushed into the running
    /// stream as room frees up.
    ///
    /// On an error the buffer comes back if it can: `None` means it was lost
    /// in the remaking, and the player plays nothing more.
    pub fn begin(
        &mut self,
        seq: &[Note],
        buf: DmaTxStreamBuf,
    ) -> Result<Playing<'d>, (Error, Option<DmaTxStreamBuf>)> {
        let Some(tx) = self.tx.take() else {
            return Err((Error::Dma, Some(buf)));
        };
        let (descriptors, buffer) = buf.split();
        let Ok(mut buf) = DmaTxStreamBuf::new(descriptors, buffer) else {
            self.tx = Some(tx);
            return Err((Error::Dma, None));
        };

        // One peak for every note; loudness is the codec's volume.
        let mut synth = Pcm::new(seq, SAMPLE_RATE, Loudness::Fixed(AMPLITUDE as i16));
        let lasts_us = synth.frames_left() as u64 * 1_000_000 / u64::from(SAMPLE_RATE) + TAIL_US;
        buf.push_with(|out| synth.fill(out));
        if synth.done() {
            // All of it fitted: the tail, at least the two descriptors' worth
            // a stream must start with.
            buf.push_with(|out| {
                let n = TAIL_BYTES.max(2 * STREAM_CHUNK).min(out.len()) & !3;
                out[..n].fill(0);
                n
            });
        }

        let mut transfer = match tx.write(buf) {
            Ok(t) => t,
            Err((_e, tx_back, buf_back)) => {
                self.tx = Some(tx_back);
                return Err((Error::Dma, Some(buf_back)));
            }
        };
        let started = Instant::now();

        // What did not fit, and then the tail, as room frees up.
        let mut frame = [0u8; BATCH * 4];
        let mut tail = if synth.done() { 0 } else { TAIL_BYTES };
        while !synth.done() || tail > 0 {
            let want = if synth.done() {
                let n = tail.min(frame.len());
                frame[..n].fill(0);
                tail -= n;
                n
            } else {
                synth.fill(&mut frame)
            };
            let mut pushed = 0usize;
            let mut spins = 0u32;
            while pushed < want {
                let got = transfer.push(&frame[pushed..want]);
                pushed += got;
                if got == 0 {
                    spins += 1;
                    if spins > 200_000 {
                        let (tx_back, buf_back) = transfer.stop();
                        self.tx = Some(tx_back);
                        return Err((Error::Dma, Some(buf_back)));
                    }
                } else {
                    spins = 0;
                }
            }
        }
        Ok(Playing {
            transfer,
            started,
            lasts_us,
        })
    }

    /// Let what [`Player::begin`] started finish, stop the stream, and hand
    /// back its buffer; at once if the sequence is already over.
    pub fn end(&mut self, playing: Playing<'d>) -> DmaTxStreamBuf {
        while playing.started.elapsed().as_micros() < playing.lasts_us {}
        // stop() returns (tx, buf), with no Result as wait() has.
        let (tx_back, buf_back) = playing.transfer.stop();
        self.tx = Some(tx_back);
        buf_back
    }
}

/// The tick's ring playing, from [`Player::start_ring`] until
/// [`Player::stop_ring`].
pub struct Ringing<'d> {
    transfer: I2sTxDmaTransfer<'d, Blocking, DmaRing>,
}

impl<'d> Player<'d> {
    /// Play `ring` round and round until [`Player::stop_ring`]; it has the
    /// I2S meanwhile.
    ///
    /// # Errors
    ///
    /// The ring back, if the I2S is busy or the transfer would not start.
    pub fn start_ring(&mut self, ring: DmaRing) -> Result<Ringing<'d>, DmaRing> {
        let Some(tx) = self.tx.take() else {
            return Err(ring);
        };
        match tx.write(ring) {
            Ok(transfer) => Ok(Ringing { transfer }),
            Err((_e, tx_back, ring_back)) => {
                self.tx = Some(tx_back);
                Err(ring_back)
            }
        }
    }

    /// Stop the ring and give it back.
    pub fn stop_ring(&mut self, ringing: Ringing<'d>) -> DmaRing {
        let (tx_back, ring_back) = ringing.transfer.stop();
        self.tx = Some(tx_back);
        ring_back
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
/// Why playback could not start.
pub enum Error {
    /// DMA buffer or channel setup failed.
    Dma,
}
