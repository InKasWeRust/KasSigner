// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! CoreS3 AW88298 I2S speaker facade.
//!
//! UI/domain code only queues sound cues. The event loop owns the sole I2S TX
//! object and services queued cues through [`RuntimeAudio`]. No HAL driver is
//! stored behind a raw pointer and no controller can reborrow I2S unsafely.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use esp_hal::{
    Blocking,
    delay::Delay,
    i2c::master::I2c,
    i2s::master::I2sTx,
    time::{Duration, Instant},
};
use signer_firmware_core::presentation::audio::{
    boot_chime_bytes, fill_stereo_boot_chime_chunk, fill_stereo_square_wave,
};

const AW88298_ADDR: u8 = 0x36;
const SAMPLE_RATE: u32 = 48_000;
const SOUND_DMA_BYTES: usize = 4 * 4092;
const BYTES_PER_STEREO_FRAME: usize = 4;
const MAX_FEEDBACK_TONE_MS: u16 = 32;
const TRAILING_SILENCE_MS: u16 = 4;
const SOUND_DMA_TIMEOUT: Duration = Duration::from_millis(140);

pub(crate) type SoundTx = I2sTx<'static, Blocking>;
pub(crate) type SoundBuffer = [u8; SOUND_DMA_BYTES];

const CUE_NONE: u8 = 0;
const CUE_CLICK: u8 = 1;
const CUE_QR_FOUND: u8 = 2;
const CUE_QR_DECODED: u8 = 3;
const CUE_ERROR: u8 = 4;
const CUE_SUCCESS: u8 = 5;
const CUE_WARNING: u8 = 6;
const CUE_TASK_DONE: u8 = 7;
const CUE_TICK: u8 = 8;

static PENDING_CUE: AtomicU8 = AtomicU8::new(CUE_NONE);
static CUES_SUSPENDED: AtomicBool = AtomicBool::new(false);
static VOLUME: AtomicU8 = AtomicU8::new(64);

/// Sole runtime owner of the CoreS3 I2S TX driver and DMA work buffer.
///
/// This value stays in the event-loop stack. Controllers can request cues, but
/// cannot access or alias the HAL driver.
pub(crate) struct RuntimeAudio {
    tx: SoundTx,
    buffer: &'static mut SoundBuffer,
    healthy: bool,
}

impl RuntimeAudio {
    pub(crate) fn new(tx: SoundTx, buffer: &'static mut SoundBuffer) -> Self {
        buffer.fill(0);
        Self { tx, buffer, healthy: true }
    }

    /// Play the fixed 350 ms startup chirp as one continuous circular-DMA
    /// stream. Refill occurs only through esp-hal's safe circular-transfer API;
    /// application code never aliases or mutates a DMA-borrowed buffer.
    pub(crate) fn play_boot_chime(&mut self) -> bool {
        let initial_frames = self.buffer.len() / BYTES_PER_STEREO_FRAME;
        fill_stereo_boot_chime_chunk(self.buffer, SAMPLE_RATE, 0);
        let words: &[u8] = &self.buffer[..];
        let Ok(mut transfer) = self.tx.write_dma_circular(&words) else { return false; };
        stream_boot_chime(&mut transfer, initial_frames)
    }

    /// Service at most one queued cue. Keeping this bounded prevents a burst of
    /// domain notifications from monopolizing the UI loop.
    pub(crate) fn service_pending(&mut self) {
        if CUES_SUSPENDED.load(Ordering::Acquire) {
            PENDING_CUE.store(CUE_NONE, Ordering::Release);
            return;
        }
        if !self.healthy {
            PENDING_CUE.store(CUE_NONE, Ordering::Release);
            return;
        }
        let code = PENDING_CUE.swap(CUE_NONE, Ordering::AcqRel);
        let Some(player) = player_for(code) else { return; };
        log!("   AUDIO CoreS3 cue {} BEGIN", code);
        let played = player(self);
        log!("   AUDIO CoreS3 cue {} DONE ok={}", code, played);
        if !played {
            self.healthy = false;
            PENDING_CUE.store(CUE_NONE, Ordering::Release);
            log!("   AW88298 runtime audio disabled after bounded I2S write failure");
        }
    }

    fn play_pattern(&mut self, tones: &[(u16, i16, u16)]) -> bool {
        self.play_fill(|buffer| fill_pattern(buffer, tones))
    }

    fn play_fill(&mut self, fill: impl FnOnce(&mut SoundBuffer) -> usize) -> bool {
        let used = fill(self.buffer).min(self.buffer.len()) & !3usize;
        if used == 0 { return false; }
        let words: &[u8] = &self.buffer[..used];
        let Ok(transfer) = self.tx.write_dma_circular(&words) else { return false; };
        play_bounded_dma(transfer, used)
    }
}

type CuePlayer = fn(&mut RuntimeAudio) -> bool;

fn player_for(code: u8) -> Option<CuePlayer> {
    let index = code.checked_sub(1)? as usize;
    CUE_PLAYERS.get(index).copied()
}

const CUE_PLAYERS: [CuePlayer; 8] = [
    play_click,
    play_qr_found,
    play_qr_decoded,
    play_error,
    play_success,
    play_warning,
    play_task_done,
    play_tick,
];

fn play_click(audio: &mut RuntimeAudio) -> bool {
    audio.play_pattern(&[(1800, scaled_amplitude(7000), 8)])
}

fn play_qr_found(audio: &mut RuntimeAudio) -> bool {
    audio.play_pattern(&[(2000, scaled_amplitude(5000), 15)])
}

fn play_qr_decoded(audio: &mut RuntimeAudio) -> bool {
    let amplitude = scaled_amplitude(8000);
    audio.play_pattern(&[(2400, amplitude, 24), (3600, amplitude, 24)])
}

fn play_error(audio: &mut RuntimeAudio) -> bool {
    let amplitude = scaled_amplitude(10000);
    audio.play_pattern(&[(300, amplitude, 32), (300, amplitude, 32)])
}

fn play_success(audio: &mut RuntimeAudio) -> bool {
    let amplitude = scaled_amplitude(6000);
    audio.play_pattern(&[(1200, amplitude, 20), (1600, amplitude, 20), (2000, amplitude, 28)])
}

fn play_warning(audio: &mut RuntimeAudio) -> bool {
    let amplitude = scaled_amplitude(8000);
    audio.play_pattern(&[(1200, amplitude, 28), (600, amplitude, 32)])
}

fn play_task_done(audio: &mut RuntimeAudio) -> bool {
    audio.play_pattern(&[(1400, scaled_amplitude(6000), 28)])
}

fn play_tick(audio: &mut RuntimeAudio) -> bool {
    audio.play_pattern(&[(2000, scaled_amplitude(5000), 12)])
}

fn stream_boot_chime(
    transfer: &mut esp_hal::dma::DmaTransferTxCircular<'_, SoundTx>,
    initial_frames: usize,
) -> bool {
    let total_bytes = boot_chime_bytes(SAMPLE_RATE);
    let mut consumed_bytes = 0usize;
    let mut source_frame = initial_frames;
    let started = Instant::now();
    while consumed_bytes < total_bytes {
        if started.elapsed() >= Duration::from_millis(500) {
            return false;
        }
        let Ok(pushed) = transfer.push_with(|chunk| {
            let writable = chunk.len() & !(BYTES_PER_STEREO_FRAME - 1);
            fill_stereo_boot_chime_chunk(&mut chunk[..writable], SAMPLE_RATE, source_frame);
            writable
        }) else {
            return false;
        };
        if pushed == 0 {
            core::hint::spin_loop();
            continue;
        }
        consumed_bytes = consumed_bytes.saturating_add(pushed);
        source_frame = source_frame.saturating_add(pushed / BYTES_PER_STEREO_FRAME);
    }
    true
}

fn playback_duration(used: usize) -> Duration {
    const BYTES_PER_MS: usize = (SAMPLE_RATE as usize * BYTES_PER_STEREO_FRAME) / 1_000;
    let millis = used.saturating_add(BYTES_PER_MS - 1) / BYTES_PER_MS;
    Duration::from_millis(millis.max(1) as u64)
}

fn play_bounded_dma(
    transfer: esp_hal::dma::DmaTransferTxCircular<'_, SoundTx>,
    used: usize,
) -> bool {
    let play_for = playback_duration(used);
    let started = Instant::now();
    loop {
        let elapsed = started.elapsed();
        if elapsed >= play_for { return transfer.stop().is_ok(); }
        if elapsed >= SOUND_DMA_TIMEOUT {
            let _ = transfer.stop();
            return false;
        }
        core::hint::spin_loop();
    }
}

pub fn set_volume(vol: u8) {
    VOLUME.store(vol, Ordering::Release);
}

fn scaled_amplitude(base: i16) -> i16 {
    let vol = VOLUME.load(Ordering::Acquire) as i32;
    ((base as i32) * vol / 255) as i16
}

fn aw_write(i2c: &mut I2c<'_, Blocking>, reg: u8, val: u16) -> bool {
    i2c.write(AW88298_ADDR, &[reg, (val >> 8) as u8, (val & 0xFF) as u8]).is_ok()
}

#[cfg(not(feature = "silent"))]
fn aw_read(i2c: &mut I2c<'_, Blocking>, reg: u8) -> u16 {
    let mut buf = [0u8; 2];
    if i2c.write_read(AW88298_ADDR, &[reg], &mut buf).is_ok() {
        ((buf[0] as u16) << 8) | buf[1] as u16
    } else {
        0
    }
}

/// Initialize AW88298 speaker amplifier while I2S clocks are already running.
pub fn init_aw88298(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> Result<(), &'static str> {
    let mut buf = [0u8; 2];
    if i2c.write_read(AW88298_ADDR, &[0x00], &mut buf).is_err() {
        return Err("AW88298 not found on I2C");
    }
    #[cfg(not(feature = "silent"))]
    {
        let chip_id = ((buf[0] as u16) << 8) | buf[1] as u16;
        log!("   AW88298 chip ID: {:#06X}", chip_id);
    }

    aw_write(i2c, 0x61, 0x0673);
    aw_write(i2c, 0x04, 0x4040);
    aw_write(i2c, 0x05, 0x0008);
    aw_write(i2c, 0x06, 0x14C8);
    aw_write(i2c, 0x0C, 0x0064);
    delay.delay_millis(50);

    #[cfg(not(feature = "silent"))]
    {
        let sysst = aw_read(i2c, 0x01);
        let sysctrl = aw_read(i2c, 0x04);
        log!("   AW88298 SYSST={:#06X} SYSCTRL={:#06X}", sysst, sysctrl);
    }
    Ok(())
}

pub fn fill_tone_buf(buf: &mut [u8], freq_hz: u16, amplitude: i16) {
    fill_stereo_square_wave(buf, SAMPLE_RATE, freq_hz, amplitude);
}

fn bytes_for_ms(duration_ms: u16) -> usize {
    (SAMPLE_RATE as usize * BYTES_PER_STEREO_FRAME * duration_ms as usize) / 1000
}

fn fill_pattern(buffer: &mut SoundBuffer, tones: &[(u16, i16, u16)]) -> usize {
    buffer.fill(0);
    let silence_bytes = bytes_for_ms(TRAILING_SILENCE_MS) & !3usize;
    let mut offset = 0usize;
    for &(frequency, amplitude, duration_ms) in tones {
        let tone_bytes = bytes_for_ms(duration_ms.min(MAX_FEEDBACK_TONE_MS)) & !3usize;
        let end = offset.saturating_add(tone_bytes).min(buffer.len()) & !3usize;
        if end <= offset { break; }
        fill_tone_buf(&mut buffer[offset..end], frequency, amplitude);
        offset = end.saturating_add(silence_bytes).min(buffer.len()) & !3usize;
    }
    offset
}

fn request(cue: u8) {
    if CUES_SUSPENDED.load(Ordering::Acquire) { return; }
    PENDING_CUE.store(cue, Ordering::Release);
}

/// Drop any queued cue before entering a credential KDF interval. The event
/// loop never starts speaker DMA while a foreground-exclusive credential
/// operation is active, so submit feedback cannot overlap memory-hard work.
pub fn discard_pending() { PENDING_CUE.store(CUE_NONE, Ordering::Release); }

/// Suspend all runtime cues across a foreground-exclusive credential interval.
/// This is deliberately independent of AppData so the I2S owner never needs to
/// inspect mutable presentation state while servicing the hardware queue.
pub fn suspend_runtime_cues() {
    CUES_SUSPENDED.store(true, Ordering::Release);
    discard_pending();
}

/// Resume runtime cues only after the credential driver reaches a terminal or
/// cancelled state. Cues requested while suspended are intentionally dropped.
pub fn resume_runtime_cues() {
    // The operation engine may ask to resume on ordinary non-credential frames.
    // Do not clear a legitimate queued UI cue (notably PIN/password key clicks)
    // unless we are actually leaving a suspended credential interval.
    if CUES_SUSPENDED.swap(false, Ordering::AcqRel) {
        discard_pending();
    }
}

/// UI/domain sound APIs only enqueue cues; they never touch I2S/GPIO/DMA.
pub fn click() { request(CUE_CLICK); }
pub fn qr_found() { request(CUE_QR_FOUND); }
pub fn qr_decoded() { request(CUE_QR_DECODED); }
pub fn beep_error() { request(CUE_ERROR); }
pub fn success() { request(CUE_SUCCESS); }
pub fn warning() { request(CUE_WARNING); }
pub fn task_done() { request(CUE_TASK_DONE); }
pub fn start_ticking() { request(CUE_TICK); }
pub fn stop_ticking() {}
