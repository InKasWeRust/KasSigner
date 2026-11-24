<!--
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
-->

# Entropy: what was measured, and what is only checked

Where a KasSigner's randomness comes from, how much of it each source was
measured to carry, and what the unit checks every time it uses one.

Two things are kept apart here, because they are not the same:

- **Measured**: raw output written off the unit, with no hashing or mixing,
  and estimated on a computer. Only these numbers say how much entropy a
  source carries.
- **Checked**: what the firmware tests on the unit before it trusts a
  sample. These are liveness checks. They catch a source that is dead, stuck
  or frozen; they do not measure entropy.

Nothing here is a certification. The gaps are listed at the end.

## Two kinds of randomness

| What | Made from | Used for |
|---|---|---|
| A new seed | The camera, the touch screen and the motion sensor, hashed together, with the chip's generator mixed in and counted as nothing | The seed words |
| A dice seed | The rolls you type, and nothing else | The seed words |
| The generator | The chip's hardware random number source, through a ChaCha20 generator | Signature randomness, backup salts and nonces, the random bytes of a hidden backup, the backup check's draws |

A seed never rests on the chip's generator: nobody can inspect that silicon.
The generator never rests on the camera or a finger: it has to work with
nobody there.

## How a seed is made

Every sample goes into one SHA-256, each framed by its source's name and its
length, and the seed is the first 16 or 32 bytes of the digest
([`crates/kassigner-crypto/src/seed.rs`](../crates/kassigner-crypto/src/seed.rs)).
A hash of many inputs is at least as unpredictable as its best input, so a
bad source cannot weaken a good one.

The count below adds the sources' credits. That treats them as independent
of one another, which is assumed and not measured: moving the unit reaches
the camera and the motion sensor together, and a finger on the screen shakes
the unit a little.

The unit counts what it was fed
([`firmware/kassigner-fw/src/seed.rs`](../firmware/kassigner-fw/src/seed.rs)):

- A seed needs **256 credited bits**, for twelve words as for twenty-four.
- **Every source the unit has must give its own share.** No source is
  credited past its share, so the fastest one cannot carry the others.
- A source producing nothing stops the seed. It is not carried by the rest.
- The generator's draw goes in last and is credited **zero**. If the
  generator fails its own tests, no seed is made.

| Unit | Sources | Share each |
|---|---|---|
| M5Stack CoreS3 | Camera, touch, motion sensor (BMI270) | 86 bits |
| Waveshare ESP32-S3-Touch-LCD-2 | Camera, touch, motion sensor (QMI8658) | 86 bits |
| Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 | Camera, touch | 128 bits |

An S3 unit whose motion sensor does not answer at boot asks the other two
for 128 bits each.

## What each source is credited, against what was measured

The credit is what the unit counts. The measured figure is the worst one
found for that source, over every condition tried. All numbers are in
[`firmware/kassigner-fw/src/limits.rs`](../firmware/kassigner-fw/src/limits.rs).

| Source | Credit | Worst measured, M5Stack | Worst measured, Waveshare S3 | P4 |
|---|---|---|---|---|
| Camera | 1 bit per 160 bytes (0.006 a byte) | 0.013 a byte | 0.310 a byte | 0.78 a byte |
| Motion sensor | 1 bit per 2 bytes (0.5 a byte) | 2.40 a byte | 2.21 a byte | has none |
| Touch | 1 bit per 2 moving touches (0.5 a touch) | 5.00 a touch | 3.69 a touch | 4.67 a touch |
| Generator | nothing | 7.18 a byte | 6.95 a byte | 7.27 a byte |

So the thinnest margin is the M5's camera with a bright bulb in view, about
twice the credit. Every other pair is four times or more.

The touch figure is the timing of a touch, which is the jitter of the unit's
own loop and not the person; what the finger itself adds is under
[Touch](#touch), and for a slow hand on the M5 it is less than the credit.

The camera's one rate is set by the M5, the weakest camera, and applied to
all three units.

## The measurements

Taken in September and October 2026 on this tree, with the capture builds
described under [Reproducing](#reproducing); the touch figures and the P4's
camera in November 2026, after the release. Unless a section says
otherwise the tool is NIST's SP 800-90B `ea_non_iid`, the figure is the
lowest of its estimators, and the unit is bits per byte.

### Camera

What is measured is not the picture. A unit on a table sees the same scene
every time, so the sample is the change of each sampled byte between two
consecutive frames, the bytes spread across the whole sensor. A seed takes
512 such bytes per pass; a capture takes 8,192 per pass, 262,144 in all.

| Condition | M5Stack (GC0308) | Waveshare S3 (OV5640) | P4 (OV5647) |
|---|---|---|---|
| Room light, still | 0.212 | 1.331 | 1.576 |
| Moving | not run | 1.096 | not run |
| Bright bulb in view | 0.013 | 0.883 | 1.095 |
| Lens covered | 0.000 | 0.310 | 0.781 |

- Bright light is the weak case on all three: where the picture saturates, bytes
  stop changing, and the tool counts those runs as predictable.
- Moving the unit does not help. Motion is structure, and structure is
  predictable. Holding still in ordinary light measured best.
- The M5 with its lens covered gives nothing at all, while the sensor looks
  busy. The liveness check exists for that capture, and refuses it.
- The Waveshare's sensor settings were changed after these runs, and the
  runs were not repeated. Its worst figure is fifty times the credit.
- The P4 with its lens covered still carries the sensor's noise (two runs,
  0.781 and 0.786), but so faintly that a seed's 512-byte sample shows 8 to
  13 distinct values, under the 16 the liveness check asks for. The check
  refuses it: a P4 makes no seed in the dark.
- A capture writes each frame's bytes out before it takes the next, so its
  frames are further apart than a seed's, about a second and a half on the
  P4 against a tenth of a second. Sensor noise does not depend on the wait;
  slow changes in the light do, so the lit figures may read higher than a
  seed sees. The covered-lens figure is the one the wait cannot flatter.

### Motion sensor

The low byte of each gyro axis, three interleaved: at rest the low byte
holds the sensor's own noise. Each unit was captured flat on a table and
then moving in a hand: 262,144 bytes a capture on the Waveshare, 32,768 on
the M5.

| Unit | Still | In a hand | Worst |
|---|---|---|---|
| Waveshare S3 (QMI8658) | 5.54 | 2.21 | 2.21 |
| M5Stack (BMI270, ±250 degrees a second, normal filter) | 6.33 / 6.25 / 6.19 | 2.69 / 2.86 / 2.40 | 2.40 |

The M5's row is three runs at one setting. Its figures are the lowest of
the estimators computed for each capture, not the full NIST suite. A
hand-held capture varies by about half a bit from run to run, because the
motion is different every time.

### Touch

Measured inside the signer itself, on the screen that makes a seed, so the
events are the ones a seed is fed. The unit reads the panel once in each
pass of its main loop. One event is where the finger is and the microseconds
since the pass before, counted only when the finger is somewhere new. Each
run is 2,048 such events; position and timing were estimated apart, in bits
per event.

| Unit | Hand | Timing | Position, across | Position, down |
|---|---|---|---|---|
| M5Stack | Slow | 5.46 | 0.19 | 0.29 |
| M5Stack | Moderate | 5.09 | 1.23 | 1.21 |
| M5Stack | Very fast | 5.00 | 4.85 | 3.73 |
| Waveshare S3 | Slow | 3.69 | 1.11 | 0.93 |
| Waveshare S3 | Moderate | 4.14 | 1.76 | 3.11 |
| Waveshare S3 | Very fast | 4.17 | 4.73 | 2.58 |
| P4 | Slow | 4.84 | 2.29 | 0.34 |
| P4 | Moderate | 5.20 | 1.09 | 4.70 |
| P4 | Very fast | 4.67 | 5.38 | 4.27 |

- **The timing is the unit, not the person.** On the seed screen a pass
  takes a steady 100 ms on the M5, 125 ms on the Waveshare and 113 ms on the
  P4, each a little different from the last. The figure is that jitter in
  the microsecond count. It is real and it is in every event, but a finger
  does not make it.
- **The position is the person, and it follows the hand.** At one read a
  pass, a slow finger takes small steps that repeat; a fast one lands
  somewhere new every time. One hand drives both directions, so the two
  position columns are not added.
- **A slow hand on the M5 gives less position than the credit**, 0.2 to 0.3
  of a bit against half a bit. The timing carries that case. On the other
  two units, and at any faster hand, position alone is over the credit.
- The time a seed is fed is the time since the last pass with a finger on
  the screen, moved or not. Measured the other way, since the last event
  that counted, the timing figures are the same within half a bit, in
  either direction, on every unit.

2,048 events is far fewer samples than the tool is designed for, so these
are rough figures.

v1.1.0 was released on touch figures from a capture that read the panel in
a tight loop and timed only changes of position (2.80 an event on the M5,
1.08 on the Waveshare, none on the P4). A seed is not fed that way, so those
figures were replaced by the ones above.

### Generator

| Unit | Source | Capture | Bits per byte |
|---|---|---|---|
| M5Stack | ESP32-S3 hardware generator | 262,144 bytes | 7.18 |
| Waveshare S3 | ESP32-S3 hardware generator | 262,144 bytes | 6.95 |
| P4, chip revision 1.3 | SAR ADC noise, read 56 µs apart | 1,048,576 bytes for the second run | 7.27, then 7.31 |

- On the same tool, 200 KB of a computer's own random bytes measures 7.06,
  so the two S3 figures are at the tool's ceiling for a capture that size.
  They were taken before the firmware started the S3's SAR ADC as a second
  feed for its generator, and not repeated after.
- The P4 at this chip revision has no dedicated generator block: its only
  source is ADC noise, which the firmware starts itself. It was assessed
  twice, with an earlier start-up sequence (7.269) and with Espressif's
  (7.31). Its health-test cutoffs are computed from the lower figure.
- v1.0.x measured the S3's generator on the same two boards with a larger
  sample; that is in the
  [`v1.0.x` branch's document](https://github.com/InKasWeRust/KasSigner/blob/v1.0.x/docs/ENTROPY.md).

## What the unit checks every time

| Source | Check | If it fails |
|---|---|---|
| Camera sample | At least 256 bytes, at least 16 distinct values, at least one byte in eight changed, and not the same as any of the eight samples before | Not absorbed, not credited |
| Motion sample | At least 48 bytes; on each of the three axes, 60% of the values tested are distinct; not the same as any of the eight samples before | Not absorbed, not credited |
| Touch | The finger moved since the last event | Not counted |
| S3 generator, every 32 words drawn | No word repeated, all distinct, no bit position stuck, not a counter, set bits within 30% to 70% | The draw is zeroed and refused |
| P4 generator, every byte | SP 800-90B's two continuous tests: the same byte 4 times in a row, or a window's first byte 16 times in 512 | The generator refuses until the unit restarts |

On every unit the flow draws from a ChaCha20 generator seeded from the
tested source: 64 raw bytes through SHA-256, a fresh seed at least every
4,096 bytes, and each block's key replaced as soon as it is used
([`firmware/kassigner-hal/src/drbg/generator.rs`](../firmware/kassigner-hal/src/drbg/generator.rs)).
A source that fails its tests poisons it, and whatever needed the randomness
is refused: a signature, a backup, a seed.

While a seed is being made, the screen asks for whatever the source still
short needs: a finger moved, the camera moved, the unit moved.

## What this does not establish

- **The sources are counted as independent**, which is assumed, as said
  under [How a seed is made](#how-a-seed-is-made).
- **Touch timing is the unit's own jitter.** It is measured and it is real,
  but it is one clock against another inside the unit, not a person.
- **The camera captures take their frames further apart than a seed does**,
  as said under [Camera](#camera).
- **The checks are not measurements.** A source that is alive and weak
  passes them. What stands against that is the credit, set under the worst
  figure measured, and the rule that every source gives its share.
- **The repeat check looks eight samples back.** It compares a sample with
  the last eight from the same source, which catches a source taking turns
  between a few buffers, but not a longer cycle.
- **One unit of each kind**, in ordinary room conditions. No sweep of
  temperature or supply voltage was made.
- **Touch and the M5's motion sensor rest on small captures**, as said
  above.

## Dice

A person who trusts none of this hardware uses Dice Seed. The seed is
SHA-256 over the digits as typed, so it can be checked with any other tool.
The unit asks for 99 rolls for twelve words and 198 for twenty-four. A fair
roll carries 2.585 bits, so 99 rolls carry 255.9.

It refuses rolls that were plainly never rolled (a face almost never seen,
the same face ten times in a row) and warns when a face is seen in under 8%
of the rolls.

## Reproducing

The capture builds write a source out raw, as hex between markers, so a
capture can be cut out of a terminal log:

```text
-----BEGIN KASSIGNER CAPTURE cam 8192 32-----
-----END KASSIGNER CAPTURE-----
```

They are behind the `capture` feature and never in a release image.

| Unit | From | Cargo aliases |
|---|---|---|
| M5Stack | `firmware/kassigner-hal-esp32s3` | `m5-capture-cam`, `m5-capture-rng`, `m5-capture-touch`, `m5-capture-imu` |
| Waveshare S3 | `firmware/kassigner-hal-esp32s3` | `ws-capture-cam`, `ws-capture-rng`, `ws-capture-touch`, `ws-capture-imu` |
| P4 | `firmware/kassigner-hal-esp32p4` | `p4-entropy` |

The touch runs used a `touchcap` build of `kassigner-signer`, and the P4's
camera a `p4_capture` example of `kassigner-hal-esp32p4`. Both were written
after the `v1.1.0` tag: they are in this tree, not in v1.1.0's.

One condition per run. The analysis is done on a computer with
[NIST's SP 800-90B tools](https://github.com/usnistgov/SP800-90B_EntropyAssessment),
`ea_non_iid` at 8 bits per sample.
