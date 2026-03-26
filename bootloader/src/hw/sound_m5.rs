// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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


// hw/sound.rs — AW88298 speaker driver and audio feedback
// KasSigner — Sound module (CoreS3 AW88298 I2S speaker)
// ═══════════════════════════════════════════════════════════════
//
// Audio architecture:
//   ESP32-S3 I2S1 → circular DMA → AW88298 amp → 1W speaker
//
// The DMA runs in circular mode with descriptors pointing to a
// static buffer in main's stack. Writing audio data to the buffer
// is immediately picked up by the I2S peripheral — no DMA restart
// needed. Writing zeros = silence.
//
// Init sequence matches M5Unified exactly (SYSCTRL=0x4040).

#![allow(dead_code)]
#[cfg(not(feature = "silent"))]

use crate::log;
use esp_hal::delay::Delay;
use esp_hal::i2c::master::I2c;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

const AW88298_ADDR: u8 = 0x36;
const SAMPLE_RATE: u32 = 48000;

/// Global DMA buffer pointer — set once by main after I2S init
static DMA_BUF: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static DMA_LEN: AtomicUsize = AtomicUsize::new(0);
/// Global volume level (0-255, default ~200)
static VOLUME: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(18);

/// Register the DMA buffer so click()/beep() can write to it
pub fn set_dma_buffer(ptr: *mut u8, len: usize) {
    DMA_BUF.store(ptr, Ordering::Release);
    DMA_LEN.store(len, Ordering::Release);
}

/// Set global volume level (0-255)
pub fn set_volume(vol: u8) {
    VOLUME.store(vol, Ordering::Release);
}

/// Get amplitude scaled by volume. Base amplitude is scaled by volume/255.
fn scaled_amplitude(base: i16) -> i16 {
    let vol = VOLUME.load(Ordering::Acquire) as i32;
    ((base as i32) * vol / 255) as i16
}

fn aw_write(i2c: &mut I2c<'_, esp_hal::Blocking>, reg: u8, val: u16) -> bool {
    i2c.write(AW88298_ADDR, &[reg, (val >> 8) as u8, (val & 0xFF) as u8]).is_ok()
}

#[allow(dead_code)]
fn aw_read(i2c: &mut I2c<'_, esp_hal::Blocking>, reg: u8) -> u16 {
    let mut buf = [0u8; 2];
    if i2c.write_read(AW88298_ADDR, &[reg], &mut buf).is_ok() {
        ((buf[0] as u16) << 8) | buf[1] as u16
    } else { 0 }
}

/// Initialize AW88298 speaker amplifier
/// Must be called AFTER I2S1 DMA is started (clocks must be running)
pub fn init_aw88298(i2c: &mut I2c<'_, esp_hal::Blocking>, delay: &mut Delay) -> Result<(), &'static str> {
    let mut buf = [0u8; 2];
    if i2c.write_read(AW88298_ADDR, &[0x00], &mut buf).is_err() {
        return Err("AW88298 not found on I2C");
    }
    let chip_id = ((buf[0] as u16) << 8) | buf[1] as u16;
    #[cfg(not(feature = "silent"))]
    log!("   AW88298 chip ID: {:#06X}", chip_id);

    // Match M5Unified init exactly
    // Source: M5Unified/src/M5Unified.cpp _speaker_enabled_cb_core2
    aw_write(i2c, 0x61, 0x0673);   // Boost mode disabled
    aw_write(i2c, 0x04, 0x4040);   // SYSCTRL: I2SEN + IPLL, AMPPD=0 PWDN=0
    aw_write(i2c, 0x05, 0x0008);   // SYSCTRL2: no AGC, no mute
    aw_write(i2c, 0x06, 0x14C8);   // I2SCTRL: 48kHz, BCK=32bit
    aw_write(i2c, 0x0C, 0x0064);   // Volume

    delay.delay_millis(50);

    #[cfg(not(feature = "silent"))] {
        let sysst = aw_read(i2c, 0x01);
        let sysctrl = aw_read(i2c, 0x04);
        log!("   AW88298 SYSST={:#06X} SYSCTRL={:#06X}", sysst, sysctrl);
    }

    Ok(())
}

/// Fill a buffer slice with a square wave tone (stereo 16-bit, little-endian)
pub fn fill_tone_buf(buf: &mut [u8], freq_hz: u16, amplitude: i16) {
    let period = (SAMPLE_RATE / freq_hz as u32) as usize;
    if period == 0 { return; }
    let half = period / 2;
    let total = buf.len() / 4; // stereo 16-bit = 4 bytes per frame
    let mut idx = 0usize;
    for f in 0..total {
        let val: i16 = if idx < half { amplitude } else { -amplitude };
        let b = val.to_le_bytes();
        let o = f * 4;
        buf[o] = b[0]; buf[o+1] = b[1];   // left
        buf[o+2] = b[0]; buf[o+3] = b[1];  // right
        idx += 1;
        if idx >= period { idx = 0; }
    }
}

/// Write silence to the DMA buffer
fn write_silence() {
    let ptr = DMA_BUF.load(Ordering::Acquire);
    let len = DMA_LEN.load(Ordering::Acquire);
    if ptr.is_null() || len == 0 { return; }
    unsafe {
        core::slice::from_raw_parts_mut(ptr, len).fill(0);
    }
}

/// Write a tone to the DMA buffer
fn write_tone(freq_hz: u16, amplitude: i16) {
    let ptr = DMA_BUF.load(Ordering::Acquire);
    let len = DMA_LEN.load(Ordering::Acquire);
    if ptr.is_null() || len == 0 { return; }
    unsafe {
        let buf = core::slice::from_raw_parts_mut(ptr, len);
        fill_tone_buf(buf, freq_hz, amplitude);
    }
}

/// Play a short click sound (~30ms)
pub fn click(delay: &mut Delay) {
    write_tone(4000, scaled_amplitude(8000));
    delay.delay_millis(30);
    write_silence();
}

/// Short soft tick when QR finders are detected (~15ms)
pub fn qr_found(delay: &mut Delay) {
    write_tone(2000, scaled_amplitude(4000));
    delay.delay_millis(15);
    write_silence();
}

/// Success chirp when QR is fully decoded (~60ms, rising)
pub fn qr_decoded(delay: &mut Delay) {
    write_tone(2400, scaled_amplitude(8000));
    delay.delay_millis(30);
    write_tone(3600, scaled_amplitude(8000));
    delay.delay_millis(30);
    write_silence();
}
/// Play an error buzz (~300ms, double beep)
pub fn beep_error(delay: &mut Delay) {
    write_tone(300, scaled_amplitude(10000));
    delay.delay_millis(150);
    write_silence();
    delay.delay_millis(50);
    write_tone(300, scaled_amplitude(10000));
    delay.delay_millis(150);
    write_silence();
}

/// Play boot jingle (ascending 3-note)
pub fn boot_tone(delay: &mut Delay) {
    write_tone(800, scaled_amplitude(6000));
    delay.delay_millis(100);
    write_tone(1200, scaled_amplitude(6000));
    delay.delay_millis(100);
    write_tone(1600, scaled_amplitude(6000));
    delay.delay_millis(150);
    write_silence();
}

/// Success jingle — like boot_tone but brighter (ascending 3-note, higher pitch)
/// Use for: seed activated, stego export done, SD test passed, format complete
pub fn success(delay: &mut Delay) {
    write_tone(1200, scaled_amplitude(6000));
    delay.delay_millis(80);
    write_tone(1600, scaled_amplitude(6000));
    delay.delay_millis(80);
    write_tone(2000, scaled_amplitude(6000));
    delay.delay_millis(120);
    write_silence();
}

/// Warning/destructive action sound — descending 2-note
/// Use for: seed deleted, data wiped
pub fn warning(delay: &mut Delay) {
    write_tone(1200, scaled_amplitude(8000));
    delay.delay_millis(120);
    write_tone(600, scaled_amplitude(8000));
    delay.delay_millis(200);
    write_silence();
}

/// Short task-complete chirp — single mid-tone
/// Use for: SD format done, file saved, backup created
pub fn task_done(delay: &mut Delay) {
    write_tone(1400, scaled_amplitude(6000));
    delay.delay_millis(150);
    write_silence();
}

/// Start a soft rhythmic tick that loops autonomously via DMA circular buffer.
/// One gentle click per ~85ms buffer loop (~12 per second, sounds like a clock).
/// I2S1 DMA is independent from SPI2, so it plays while SD bitbang runs.
pub fn start_ticking() {
    let ptr = DMA_BUF.load(Ordering::Acquire);
    let len = DMA_LEN.load(Ordering::Acquire);
    if ptr.is_null() || len == 0 { return; }

    let amp = scaled_amplitude(5000); // audible
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
    let total_frames = len / 4;

    buf.fill(0); // silence

    // Click: 15ms = 720 frames at 48kHz — short but audible
    let click_frames = 720usize;
    let freq_period = (48000u32 / 2000) as usize; // 2000 Hz — clean tick

    for f in 0..click_frames.min(total_frames) {
        let phase = f % freq_period;
        let val: i16 = if phase < freq_period / 2 { amp } else { -amp };
        let b = val.to_le_bytes();
        let o = f * 4;
        buf[o] = b[0]; buf[o+1] = b[1];
        buf[o+2] = b[0]; buf[o+3] = b[1];
    }
    // Remaining ~70ms is silence — DMA loops: click...silence...click...silence
}

/// Stop the tick-tock sound (write silence to DMA buffer)
pub fn stop_ticking() {
    write_silence();
}
