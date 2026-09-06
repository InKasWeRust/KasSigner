//! Pure stereo sample generation used by board audio adapters.

const BYTES_PER_STEREO_FRAME: usize = 4;

// Deterministic CoreS3 startup chirp. These constants intentionally mirror the
// original waveform specification while remaining independent of HAL/DMA ownership.
pub const BOOT_CHIME_VOLUME: u8 = 18;
pub const BOOT_CHIME_BASE_AMPLITUDE: i16 = 6_000;
pub const BOOT_CHIME_AMPLITUDE: i16 = 423; // 6000 * 18 / 255 (integer scaling)
pub const BOOT_CHIME_SEGMENTS: [(u16, usize); 3] = [(800, 100), (1_200, 100), (1_600, 150)];
pub const BOOT_CHIME_DURATION_MS: usize = 350;

pub fn boot_chime_frames(sample_rate: u32) -> usize {
    (sample_rate as usize * BOOT_CHIME_DURATION_MS) / 1_000
}

pub fn boot_chime_bytes(sample_rate: u32) -> usize {
    boot_chime_frames(sample_rate).saturating_mul(BYTES_PER_STEREO_FRAME)
}

/// Fill a slice of the startup stream beginning at an absolute stereo-frame
/// position. Frames after the 350 ms chirp are silence. This makes the waveform
/// deterministic even when a board adapter refills circular DMA in chunks.
pub fn fill_stereo_boot_chime_chunk(output: &mut [u8], sample_rate: u32, start_frame: usize) {
    output.fill(0);
    let total_frames = boot_chime_frames(sample_rate);
    for local_frame in 0..output.len() / BYTES_PER_STEREO_FRAME {
        let absolute_frame = start_frame.saturating_add(local_frame);
        if absolute_frame >= total_frames {
            break;
        }
        let Some((frequency, segment_frame)) = boot_segment_frame(sample_rate, absolute_frame)
        else {
            break;
        };
        let Some(period) = sample_period(sample_rate, frequency) else {
            continue;
        };
        let half = period / 2;
        let phase = segment_frame % period;
        let sample = if phase < half {
            BOOT_CHIME_AMPLITUDE
        } else {
            -BOOT_CHIME_AMPLITUDE
        };
        write_stereo_sample(output, local_frame, sample);
    }
}

pub fn fill_stereo_boot_chime(output: &mut [u8], sample_rate: u32) -> usize {
    let writable = boot_chime_bytes(sample_rate).min(output.len()) & !(BYTES_PER_STEREO_FRAME - 1);
    fill_stereo_boot_chime_chunk(&mut output[..writable], sample_rate, 0);
    writable
}

fn boot_segment_frame(sample_rate: u32, absolute_frame: usize) -> Option<(u16, usize)> {
    let mut segment_start = 0usize;
    for (frequency, duration_ms) in BOOT_CHIME_SEGMENTS {
        let segment_frames = (sample_rate as usize * duration_ms) / 1_000;
        let segment_end = segment_start.saturating_add(segment_frames);
        if absolute_frame < segment_end {
            return Some((frequency, absolute_frame - segment_start));
        }
        segment_start = segment_end;
    }
    None
}

pub fn fill_stereo_square_wave(
    output: &mut [u8],
    sample_rate: u32,
    frequency_hz: u16,
    amplitude: i16,
) {
    let Some(period) = sample_period(sample_rate, frequency_hz) else {
        return;
    };
    let half = period / 2;
    for frame in 0..output.len() / BYTES_PER_STEREO_FRAME {
        let phase = frame % period;
        write_stereo_sample(
            output,
            frame,
            if phase < half {
                amplitude
            } else {
                amplitude.wrapping_neg()
            },
        );
    }
}

pub fn fill_stereo_tick(
    output: &mut [u8],
    sample_rate: u32,
    frequency_hz: u16,
    amplitude: i16,
    click_frames: usize,
) {
    output.fill(0);
    let Some(period) = sample_period(sample_rate, frequency_hz) else {
        return;
    };
    let half = period / 2;
    let available_frames = output.len() / BYTES_PER_STEREO_FRAME;
    for frame in 0..click_frames.min(available_frames) {
        let phase = frame % period;
        write_stereo_sample(
            output,
            frame,
            if phase < half {
                amplitude
            } else {
                amplitude.wrapping_neg()
            },
        );
    }
}

fn sample_period(sample_rate: u32, frequency_hz: u16) -> Option<usize> {
    let frequency = u32::from(frequency_hz);
    if frequency == 0 {
        return None;
    }
    usize::try_from(sample_rate / frequency)
        .ok()
        .filter(|period| *period != 0)
}

fn write_stereo_sample(output: &mut [u8], frame: usize, value: i16) {
    let bytes = value.to_le_bytes();
    let offset = frame * BYTES_PER_STEREO_FRAME;
    output[offset] = bytes[0];
    output[offset + 1] = bytes[1];
    output[offset + 2] = bytes[0];
    output[offset + 3] = bytes[1];
}
