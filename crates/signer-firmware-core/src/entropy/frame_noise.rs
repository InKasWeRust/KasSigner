//! Temporal camera-noise liveness measurement.
//!
//! The camera contributes entropy only when consecutive captures demonstrate
//! per-pixel temporal movement. Static scene content is never credited as fresh
//! entropy. The thresholds intentionally retain the original hardware-tested
//! floor until SP 800-90B characterization data is available.

pub const NOISE_SAMPLES: usize = 256;
pub const MIN_CHANGED_FOR_ENTROPY: u32 = (NOISE_SAMPLES / 16) as u32;
pub const MIN_AC_FOR_ENTROPY_X100: u32 = 20;
pub const MIN_CAPTURED_FRAMES: u8 = 6;
pub const MIN_LIVE_DELTAS: u8 = 5;
pub const MAX_CONSECUTIVE_STALE_DELTAS: u8 = 1;
pub const MAX_CAMERA_HEALTH_WINDOWS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameNoise {
    pub sampled: u32,
    pub changed: u32,
    pub mad_x100: u32,
    pub distinct: u32,
    pub mean_shift_x100: i32,
    pub ac_x100: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CameraEntropyReport {
    pub frames_captured: u8,
    pub deltas_observed: u8,
    pub live_deltas: u8,
    pub max_consecutive_stale_deltas: u8,
}

impl CameraEntropyReport {
    #[must_use]
    pub const fn healthy(self) -> bool {
        self.frames_captured >= MIN_CAPTURED_FRAMES
            && self.live_deltas >= MIN_LIVE_DELTAS
            && self.max_consecutive_stale_deltas <= MAX_CONSECUTIVE_STALE_DELTAS
    }
}

#[must_use]
pub const fn should_retry_camera_window(window_index: u8, report: CameraEntropyReport) -> bool {
    !report.healthy() && window_index + 1 < MAX_CAMERA_HEALTH_WINDOWS
}

pub struct CameraEntropyTracker {
    previous: [u8; NOISE_SAMPLES],
    baseline_valid: bool,
    frames_captured: u8,
    deltas_observed: u8,
    live_deltas: u8,
    stale_run: u8,
    max_stale_run: u8,
}

impl CameraEntropyTracker {
    pub const fn new() -> Self {
        Self {
            previous: [0; NOISE_SAMPLES],
            baseline_valid: false,
            frames_captured: 0,
            deltas_observed: 0,
            live_deltas: 0,
            stale_run: 0,
            max_stale_run: 0,
        }
    }

    pub fn observe(&mut self, pixels: &[u8]) -> Option<FrameNoise> {
        if pixels.len() < NOISE_SAMPLES {
            return None;
        }
        self.frames_captured = self.frames_captured.saturating_add(1);
        let stride = pixels.len() / NOISE_SAMPLES;
        let had_baseline = self.baseline_valid;
        let mut seen = [0u8; 32];
        let mut distinct = 0u32;
        let mut changed = 0u32;
        let mut absdiff = 0u32;
        let mut signdiff = 0i32;

        for index in 0..NOISE_SAMPLES {
            let current = pixels[index * stride];
            let seen_index = usize::from(current / 8);
            let bit_index = usize::from(current % 8);
            let bit = [1u8, 2, 4, 8, 16, 32, 64, 128][bit_index];
            if seen[seen_index] & bit == 0 {
                seen[seen_index] |= bit;
                distinct += 1;
            }
            if had_baseline {
                let previous = self.previous[index];
                changed += u32::from(previous != current);
                let delta = i32::from(current) - i32::from(previous);
                absdiff += delta.unsigned_abs();
                signdiff += delta;
            }
            self.previous[index] = current;
        }
        self.baseline_valid = true;
        if !had_baseline {
            return None;
        }

        let mad_x100 = absdiff * 100 / NOISE_SAMPLES as u32;
        let mean_shift_x100 = signdiff * 100 / NOISE_SAMPLES as i32;
        let noise = FrameNoise {
            sampled: NOISE_SAMPLES as u32,
            changed,
            mad_x100,
            distinct,
            mean_shift_x100,
            ac_x100: mad_x100.saturating_sub(mean_shift_x100.unsigned_abs()),
        };
        self.record_delta(is_live(&noise));
        Some(noise)
    }

    fn record_delta(&mut self, live: bool) {
        self.deltas_observed = self.deltas_observed.saturating_add(1);
        if live {
            self.live_deltas = self.live_deltas.saturating_add(1);
            self.stale_run = 0;
        } else {
            self.stale_run = self.stale_run.saturating_add(1);
            self.max_stale_run = self.max_stale_run.max(self.stale_run);
        }
    }

    #[must_use]
    pub const fn report(&self) -> CameraEntropyReport {
        CameraEntropyReport {
            frames_captured: self.frames_captured,
            deltas_observed: self.deltas_observed,
            live_deltas: self.live_deltas,
            max_consecutive_stale_deltas: self.max_stale_run,
        }
    }
}

impl Default for CameraEntropyTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub const fn is_live(noise: &FrameNoise) -> bool {
    noise.changed >= MIN_CHANGED_FOR_ENTROPY && noise.ac_x100 >= MIN_AC_FOR_ENTROPY_X100
}
