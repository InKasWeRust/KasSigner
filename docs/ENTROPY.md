<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# Entropy: what was measured, and what is only checked

Every random value KasSigner produces comes from one of five physical sources.
This document records, per source, two different things and keeps them apart:

- **Measured against a standard**: raw output captured to SD, taken off the
  device, and run through NIST SP 800-90B `ea_non_iid` (all ten estimators).
  These are the only numbers that say how much entropy a source carries.
- **Health-checked at runtime**: what the firmware tests every time it uses the
  source, on the device, before it trusts the output. These are liveness
  checks. They catch a dead, stuck or frozen source; they do not measure
  entropy, and a plain counter can pass some of them.

A source can be well measured and lightly checked, or heavily checked and never
measured. The table says which is which. Nothing here is a certification.

## Where each source is used

| Source | Used for | Board |
|---|---|---|
| Camera | Seed generation (camera mode); staged for the pool when a QR scan has powered it | both |
| Touch | Seed generation (touch mode); staged for the pool from the main loop | both |
| IMU (gyro) | Mixed into camera-mode seed generation | Waveshare |
| Dice | Seed generation (dice mode), manual entry, no measurement applies | both |
| Hardware RNG (WDEV) | `fill()`: signing nonces, ECIES ephemeral keys, backup salts and nonces. Never a seed source | both |

Seed generation and `fill()` are separate paths. The hardware RNG does not
contribute to seeds; the camera, touch and IMU do not run when `fill()` needs a
nonce mid-operation, so their contribution to the pool is whatever was staged
while they happened to be running.

## Measured against a standard

All runs: NIST SP 800-90B `ea_non_iid`, all ten estimators, on files captured
by the `e12-capture` (camera) and `wdev-capture` (RNG) measurement builds or by
the touch probe log. Figures are the estimator minimum unless stated.

### Hardware RNG (WDEV_RND)

Two chips, one session each, 250,000 32-bit words (8,000,000 bits) per read
spacing, five spacings from 0 to 1,024 spin-loops between reads.

| Board | Date | Spacing | MCV min-entropy per byte | Shannon per byte | Serial correlation |
|---|---|---|---|---|---|
| M5Stack CoreS3 Lite | 2026-08-14 | 0 | 7.892 | 7.99983 | +0.0017 |
| | | 16 | 7.869 | 7.99979 | +0.0001 |
| | | 64 | 7.873 | 7.99981 | -0.0002 |
| | | 256 | 7.880 | 7.99983 | +0.0032 |
| | | 1024 | 7.878 | 7.99981 | +0.0029 |
| Waveshare ESP32-S3-Touch-LCD-2 | 2026-08-15 | 0 | 7.869 | 7.99982 | +0.0000 |
| | | 16 | 7.863 | 7.99981 | +0.0026 |
| | | 64 | 7.879 | 7.99979 | -0.0031 |
| | | 256 | 7.875 | 7.99983 | +0.0040 |
| | | 1024 | 7.876 | 7.99982 | -0.0037 |

Byte chi-square 234 to 295 against 255 expected; unique-word fraction matches
the birthday bound for 250,000 draws from 2^32; gzip and xz both fractionally
above 1.0. Mean MCV min-entropy 7.878 (M5Stack) against 7.872 (Waveshare), a
gap of 0.006 bits, inside estimator noise. Read spacing makes no difference on
either board.

What this establishes: no defect detectable at 2,000,000 samples per condition
on two independent devices, and the figure is per-design, not per-device. What
it does not: MCV is one estimator and usually the most generous; two chips, one
temperature, one voltage. The raw files are kept so the full battery can be
re-run without recapturing.

### Camera, M5Stack (seed path)

M5Stack CoreS3 Lite, eight captures of eight frames each, the frame-delta
stream the seed path hashes.

| Conditions | Min-entropy, bits per capture | Times 256 |
|---|---|---|
| Static, grey subject, dim | 0 | 0 |
| Static, dim | 645 | 2.5 |
| Static | 830 | 3.2 |
| Moving, slight | 2,547 | 9.9 |
| Moving | 12,976 | 50.7 |
| Moving | 13,557 | 53.0 |
| Static, bright | 24,813 | 96.9 |
| Moving, bright | 28,342 | 110.7 |

The zero run is what the runtime check exists to catch: a static grey subject
in dim light produced eight near-identical frames and no entropy at all, while
the sensor looked busy. Every other run cleared 256 bits, the worst by 2.5
times. The region between zero and 645 was not sampled; the runtime thresholds
sit in that gap as margins over a floor, not as calibrated values.

### Camera, Waveshare (seed path)

Waveshare ESP32-S3-Touch-LCD-2 with OV5640-AF, 2026-08-18, two captures of
eight 8,064-byte reads each (this board's capture path samples a narrow band
of one 480x480 frame, not the whole image, so the figures do not compare
one-to-one with M5Stack). Same tool, same rule: minimum over all estimators of
H_original and 8 x H_bitstring on the frame-delta stream.

| Conditions | Min-entropy, bits per byte | Bits per capture | Times 256 | Runtime verdict |
|---|---|---|---|---|
| Lens hole covered (case LEDs still lit), camera fixed | 0.361 | 20,391 | 80 | DEGRADED (distinct min 3, 4/7 deltas live) |
| Moving, good light | 2.165 | 122,196 | 477 | live |

Two conditions, and they are the two ends of what this hardware can produce.
The lower one is the darkest state reachable on a Waveshare in its case: the
case's own red and blue indicator LEDs light the sensor even with the lens hole
covered, so a fully dark capture does not exist on this board and the M5Stack
zero control has no equivalent here. The runtime check still flagged that
darkest capture DEGRADED, so on this board the floor of 5 sits above the lowest
capture the hardware can produce; conservative, and on Waveshare a degraded
camera does not refuse the seed on its own, the IMU carries it (see the runtime
table).

### Touch (seed path)

M5Stack CoreS3 Lite, two runs, position and inter-event timing measured as
separate channels.

| Run | Coordinates, bits per event | Timing, bits per event |
|---|---|---|
| 27 s of scribbling | 3.89 | 0.22 |
| 122 s of slow, straight, predictable motion | 0.08 | 0.76 |

The two channels anti-correlate: fast motion makes position rich and timing
regular, slow motion the reverse. Taking the larger single channel of the worse
run as the conservative bound (one hand drives both), 2,048 events yield 1,558
bits against a 256-bit target. A finger held still, or tapping one point,
records nothing at all, so the bar never fills and no seed is produced.

## Health-checked at runtime, not measured against a standard

| Source | Check | Threshold | Fails how |
|---|---|---|---|
| Hardware RNG, every `fill()` | 32-word window: repeats, distinct words, ones balance, stuck bit positions, monotonic run | repeats 0, distinct 32/32, ones in 256..768 of 1,024, stuck 0/32, not monotonic | `fill()` zeroes the caller's buffer and returns `SourceDegraded`; signing, ECIES and SD salt/nonce generation all refuse |
| Camera, every seed capture | Per-delta changed and distinct counts over 256 stride samples; every delta must pass | changed 30 of 256 on both boards; distinct 10 (M5Stack), 5 (Waveshare) | M5Stack: capture refused with "Need more light". Waveshare: camera marked DEGRADED and not counted as a healthy source, the IMU carries the seed; refused only if the IMU fails too |
| IMU, boot and every seed capture | Distinct sample values per axis over the collected buffer | 60 % distinct on every axis (healthy axis about 94 %) | Axis excluded from the mix; a frozen part is reported |
| Touch, every seed capture | Unchanged coordinates are not recorded | none needed | The bar does not fill; no seed |

Three boots on M5Stack (2026-08-14) gave `fill()` windows of ones 483, 516 and
506 of 1,024, repeats 0, distinct 32/32, stuck 0/32, not monotonic.

The IMU has boot and capture readings only. Its noise floor is understood from
the datasheet and observation (on a still device the low byte of each 16-bit
reading is inside the noise), but no SP 800-90B run has been made on the gyro
stream. It is the one source without a measured figure.

## Reproducing

Camera and RNG captures use measurement-only build features (`e12-capture`,
`wdev-capture`) that write raw source output to the SD card and are a compile
error together with `production`. Analysis was done off-device with the NIST
`SP800-90B_EntropyAssessment` tools. Raw capture files are retained by the
project.
