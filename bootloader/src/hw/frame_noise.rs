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

// hw/frame_noise.rs — Camera entropy measurement, both platforms
//
// WHY THIS IS SHARED AND NOT IN cam_dma.rs
//
// It started in cam_dma.rs, which is Waveshare-only. The result was that the
// seed-path entropy gate got a real liveness check on Waveshare and kept the
// original defect on M5Stack: `got_entropy` was set because
// `get_entropy_bytes()` returned Some, i.e. because a pointer was non-null,
// and nothing verified the pixels varied. A camera handing back a frozen or
// unwritten buffer satisfied it completely. Audit finding E-07, fixed on one
// platform and silently open on the other, which is worse than open on both
// because the asymmetry is invisible.
//
// The measurement has no dependency on how the frame arrived. It takes a byte
// slice. So it lives here, both platforms call it, and the gate means the same
// thing on both.
//
// WHAT IS ACTUALLY BEING MEASURED
//
// Not the image. A device sitting on a table photographs the same scene at
// every seed generation, so spatial content is a CONSTANT across generations
// and contributes nothing. The entropy is entirely in the temporal delta:
// shot noise, read noise, dark current.
//
// This is why "distinct values in this frame" is the wrong metric on its own.
// A fixed photograph scores beautifully and carries no entropy across
// generations. Distinct is kept only as a secondary check for a region that is
// constant or was never written; `changed` is the number that decides.
//
// MEASURED ON HARDWARE (Waveshare, OV5640, 8064-byte partial captures):
//
//   M5Stack GC0308, dark room                 0/1024 changed, MAD 0.00 LSB
//   lens covered, sensor cold from PWDN    451/1024 changed, MAD 2.44 LSB
//   lens covered, AGC wound to 0xF8        841/1024 changed, MAD 4.02 LSB
//   ambient light                      928-992/1024 changed, MAD 13.0-58.8
//   pointed at a light source             1017/1024 changed, MAD 90.87 LSB
//
// The GC0308 dark-room row is the real floor and it is ZERO: bit-identical
// frames, black-level clamping flooring the image to a constant and clipping
// the read noise away. This is SENSOR-DEPENDENT. The OV5640 covered-and-cold
// row still moves 44% of its bytes; the GC0308 in the dark moves none.
//
// MIN_CHANGED_FOR_ENTROPY is set from the OV5640 floor, and the GC0308 dark
// case fails it outright rather than by any threshold judgement, which is
// correct: a frozen buffer carries nothing.

/// Bytes compared per frame.
///
/// Sampled with a stride across the whole supplied buffer rather than the
/// first kilobyte of it, so a partial capture, a letterboxed frame or a dead
/// region at one end cannot flatter the result.
///
/// REDUCED 1024 -> 256. This buffer is `static mut` in `.bss`, and 1 KB of it
/// went onto a platform that audit section 2a documents as having no SRAM
/// margin to spare — that section is a 57.6 KB static blowing the M5Stack
/// budget. An M5Stack build subsequently died on a stack guard violation at
/// Phase 5 with only trivial functional changes in the delta, which is what a
/// marginal memory condition being tipped looks like rather than a new bug.
///
/// 256 stride-sampled bytes is ample. The statistics that matter are ratios —
/// fraction of bytes changed, mean absolute difference, AC component — and
/// none of them need a kilobyte. Distinct still has the full 0..255 range to
/// work in. Measured values from a 1024-sample run reproduce at 256 within
/// their own run-to-run spread.
const NOISE_SAMPLES: usize = 256;

static mut NOISE_SNAP: [u8; NOISE_SAMPLES] = [0; NOISE_SAMPLES];
static mut NOISE_SNAP_VALID: bool = false;

/// Minimum bytes-changed-per-frame, out of NOISE_SAMPLES, for the camera to
/// count as a live entropy source.
///
/// EXPRESSED AS A RATIO, not an absolute, so changing NOISE_SAMPLES cannot
/// silently move the gate. NOISE_SAMPLES/16 is 6.25%: 64 of 1024, 16 of 256.
///
/// Worst case measured on hardware is 451 of 1024, i.e. 44%, with the lens
/// fully covered and the sensor cold from PWDN before AGC winds up. A static
/// buffer reads 0. 6.25% sits a seventh of the way to the measured floor and
/// two orders of magnitude above a dead one, which is the margin a threshold
/// that can refuse to generate a seed needs to have.
///
/// RAISED 1/16 -> 3/25 (6.25% -> 12%) from the E-12 measurements tabulated at
/// `MIN_DISTINCT_FOR_ENTROPY`. 30 of 256 sits 2.3x below the lowest per-delta
/// `changed` on any run that assessed above 256 bits, and rejects none of the
/// eight. The old 6.25% also rejects none of them; the increase buys margin
/// against a colder sensor or another unit landing between the two, at the
/// cost of a retry rather than a seed.
pub const MIN_CHANGED_FOR_ENTROPY: u32 = (NOISE_SAMPLES * 3 / 25) as u32;

/// Minimum AC component, scaled by 100, for a frame delta to count.
///
/// AC = MAD - |mean shift|. It is the part of the inter-frame difference that
/// is NOT the whole image moving together, i.e. the part that is per-pixel.
///
/// THIS REPLACED A `distinct` THRESHOLD, WHICH WAS WRONG. Measured on M5Stack
/// with the lens covered:
///
///   494/1024 changed, MAD 2.37, distinct 1     (mean shift not yet measured)
///   172/1024 changed, MAD 5.78, distinct 1, mean shift 0
///
/// The first reading was diagnosed as a flat frame stepping level, and a
/// distinct >= 4 rule was added to catch it. The second reading, taken once
/// mean shift existed, refutes that: shift 0 against MAD 5.78 means the changes
/// cancel, so they are independent per-pixel movements, not a common offset.
/// The frame is spatially flat and temporally noisy, and the entropy is
/// temporal. Gating on spatial diversity refused a source carrying several
/// hundred bits per delta, and on M5Stack, which has no second source, that
/// meant refusing to generate a seed in a dark room.
///
/// `distinct` is also redundant as a gate: an unwritten buffer fails on
/// `changed`, and a stepping constant fails here. It stays reported, not
/// gated.
///
/// LOWERED 0.5 -> 0.2 after the first AC data existed. Measured on M5Stack,
/// AC averaged over 7 deltas:
///
///   0.25   near-static frame, 97/1024 changed   REFUSED at 0.5
///   1.29   dim, MAD 21.11 of which ~19.8 was DC level-step (AEC hunting)
///   7.87   room light
///   11.20  room light
///
/// The refused run had 97 bytes moving ~2.6 LSB each. Discounted to one bit
/// per changed byte that is ~97 bits per delta and ~680 across seven, which
/// clears 256 by the same arithmetic used to call this source sufficient in
/// the first place. Refusing it was over-conservative, and on M5Stack, which
/// has no second source, a false refusal means the user cannot generate a seed
/// at all.
///
/// 0.2 still rejects a static or unwritten buffer, which reads ~0.
///
/// THIS NUMBER IS A STOPGAP AND SHOULD BE TREATED AS ONE. It is set from four
/// observations and a judgement about where a gap looks thin, not from a
/// min-entropy estimate. Audit E-12: capture raw frames, run NIST SP 800-90B
/// offline, set every threshold in this subsystem from data. Until then this
/// separates "some independent per-pixel movement" from "none", which is the
/// only distinction it can honestly make.
pub const MIN_AC_FOR_ENTROPY: u32 = 20;

pub struct FrameNoise {
    /// Bytes compared.
    pub sampled: u32,
    /// Bytes differing from the previous frame. THE number that matters: near
    /// zero means the buffer is not being refreshed and the camera is
    /// contributing nothing while appearing to.
    pub changed: u32,
    /// Mean absolute inter-frame difference, scaled by 100 to stay integral.
    /// Healthy sensor noise on a static scene is roughly 1 to 3 LSB.
    pub mad_x100: u32,
    /// Distinct byte values in the current sample. Detects a constant or
    /// unwritten region. REPORTED, NOT GATED: it measures spatial diversity
    /// within one frame, while the entropy is temporal, and gating on it
    /// refused a flat-but-noisy frame that was contributing properly.
    pub distinct: u32,
    /// SIGNED mean inter-frame difference, scaled by 100. The DC component.
    ///
    /// This is what separates the two ways a frame can change:
    ///
    ///   per-pixel noise    mad_x100 >> |mean_shift_x100|   (changes cancel)
    ///   global level step  mad_x100 == |mean_shift_x100|   (changes align)
    ///
    /// A frame whose MAD is entirely explained by its mean shift moved as one
    /// object and contributed nothing per pixel.
    pub mean_shift_x100: i32,
    /// MAD minus |mean shift|, floored at 0. The per-pixel part, and the
    /// figure the gate actually uses.
    pub ac_x100: u32,
}

/// Forget the previous frame, so the next `measure` establishes a fresh
/// baseline instead of differencing against a frame from minutes ago.
///
/// Call once before a capture loop.
pub fn reset_baseline() {
    unsafe {
        NOISE_SNAP_VALID = false;
    }
}

/// Compare `pixels` against the frame supplied on the previous call.
///
/// Returns None on the first call after a reset (baseline established, no
/// delta yet) and None if the buffer is too small to sample.
pub fn measure(pixels: &[u8]) -> Option<FrameNoise> {
    if pixels.len() < NOISE_SAMPLES {
        return None;
    }
    let stride = pixels.len() / NOISE_SAMPLES;

    let mut seen = [0u32; 8];
    let mut distinct = 0u32;
    let mut changed = 0u32;
    let mut absdiff = 0u32;
    let mut signdiff = 0i32;

    unsafe {
        let had_baseline = NOISE_SNAP_VALID;
        for i in 0..NOISE_SAMPLES {
            let b = pixels[i * stride];
            let w = (b >> 5) as usize;
            let bit = 1u32 << (b & 0x1F);
            if seen[w] & bit == 0 {
                seen[w] |= bit;
                distinct += 1;
            }
            if had_baseline {
                let prev = NOISE_SNAP[i];
                if prev != b {
                    changed += 1;
                }
                let d = b as i32 - prev as i32;
                absdiff += d.unsigned_abs();
                signdiff += d;
            }
            NOISE_SNAP[i] = b;
        }
        NOISE_SNAP_VALID = true;
        if !had_baseline {
            return None;
        }
    }

    let mad_x100 = absdiff * 100 / NOISE_SAMPLES as u32;
    let mean_shift_x100 = signdiff * 100 / NOISE_SAMPLES as i32;

    Some(FrameNoise {
        sampled: NOISE_SAMPLES as u32,
        changed,
        mad_x100,
        distinct,
        mean_shift_x100,
        ac_x100: mad_x100.saturating_sub(mean_shift_x100.unsigned_abs()),
    })
}

/// Minimum distinct sample values, of NOISE_SAMPLES, for one delta to count.
///
/// MEASURED (E-12, eight captures, NIST SP 800-90B `ea_non_iid`, all ten
/// estimators over the frame-delta stream):
///
///   run                       bits   x256    min changed   min distinct
///   static, grey subject, dim    0   ZERO              0              1
///   static, dim                645    2.5             69             36
///   static                     830    3.2            118             54
///   moving, slight           2,547    9.9             80             51
///   moving                  12,976   50.7            113             54
///   moving                  13,557   53.0             84             41
///   static, bright          24,813   96.9            142            104
///   moving, bright          28,342  110.7            133             83
///
/// The zero-entropy capture is separated from every other run by BOTH
/// `changed` (0 vs >=69) and `distinct` (1 vs >=36). Any threshold between
/// those bounds gives identical results on all eight, so these are margins
/// over a floor rather than calibrated values: 30 and 10 sit 2.3x and 3.6x
/// below the lowest passing observation. The region between the zero run and
/// the next-worst was not sampled, so this catches a dead sensor and does not
/// certify 256 bits.
/// PER BOARD, because the two capture paths sample different populations.
///
/// `measure` takes 256 stride samples from whatever buffer it is handed:
///
/// ```text
///   M5Stack    DvpCamera, 76,800 B per frame  ->  stride 300, spread across
///              the whole 320x240 image
///   Waveshare  cam_dma, 8,064 B per read      ->  stride 31, a narrow band
///              of one 480x480 frame
/// ```
///
/// `changed` is comparative and survives that difference: measured 235 to 247
/// of 256 on healthy Waveshare captures, seven times its own floor. `distinct`
/// counts values within one sample set, and a short smooth slice shows fewer
/// of them even from a perfectly live sensor. Three healthy Waveshare runs
/// measured `distinct min` of 8, 9 and 22.
///
/// The M5Stack value of 10 was derived from eight E-12 captures on that board
/// (zero-entropy run: `distinct 1`; lowest passing run: 36). **No equivalent
/// Waveshare dataset exists.** 5 is a bare liveness floor, not a calibration:
/// it clears the lowest observed healthy value by 1.6x and still refuses a
/// slice where nearly every sample is identical. The real number wants an
/// E-12 run on Waveshare, including a lens-covered control.
///
/// A Waveshare capture that fails this still has the IMU behind it
/// (`cam_ok || imu_ok`), which is why the looser floor is tolerable there and
/// would not be on M5Stack, where the camera is the only source.
#[cfg(feature = "waveshare")]
pub const MIN_DISTINCT_FOR_ENTROPY: u32 = 5;
#[cfg(feature = "m5stack")]
pub const MIN_DISTINCT_FOR_ENTROPY: u32 = 10;

/// Verdict on ONE frame delta.
///
/// PER DELTA, NOT AVERAGED. The zero-entropy capture above had four of seven
/// deltas frozen (`changed` 0, `distinct` 1, bit-identical frames) and its
/// MEAN still cleared every threshold, because three live deltas at the head
/// carried the dead tail. A mean cannot see a sensor that stops.
///
/// AC IS NOT PART OF THIS. `ac_x100` is `MAD - |shift|`, which is not the AC
/// component: half the pixels moving 0 and half moving +32 gives MAD 16,
/// shift 16, AC 0, while every pixel carried an independent bit. Measured, a
/// run assessing at 830 bits had `min AC` of 0.01, so any AC threshold above
/// that rejects a good capture; and the single richest delta in the whole
/// set (4.09 bits/byte by MCV) scored AC 0.06. It is kept in `FrameNoise`
/// for the log line, where it is informative, and out of the gate, where it
/// inverts.
pub fn is_live(n: &FrameNoise) -> bool {
    n.changed >= MIN_CHANGED_FOR_ENTROPY && n.distinct >= MIN_DISTINCT_FOR_ENTROPY
}
