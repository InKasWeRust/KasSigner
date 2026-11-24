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

//! Making a seed, with sources that are dead, stuck, frozen or fine.
//!
//! Each gate answers a failure seen or measured: a generator reading zero,
//! a camera returning one value in the dark, an IMU axis alive at boot and
//! frozen by seed time, a finger held still. None of them counts, and what
//! does is credited at the device's figures and no more.

use kassigner_crypto::seed::Words;
use kassigner_fw::limits;
use kassigner_fw::seed::{
    self, Collector, Encoding, Error, ReadError, Source, Verdict, REPEAT_WINDOW,
};
use kassigner_hal::entropy::{self, Entropy};

/// A source that works.
struct Live(u32);

impl Entropy for Live {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), entropy::Error> {
        for b in out.iter_mut() {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (self.0 >> 24) as u8;
        }
        Ok(())
    }
}

/// A source that is dead.
struct Dead;

impl Entropy for Dead {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), entropy::Error> {
        out.fill(0);
        Err(entropy::Error::Unhealthy)
    }
}

/// Bytes that look like a live sensor.
fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    Live(seed).fill(&mut out).unwrap();
    out
}

fn words(m: &kassigner_crypto::bip39::Mnemonic) -> Vec<u16> {
    (0..m.len()).map(|i| m.index(i).unwrap()).collect()
}

/// Camera bytes worth `bits` at the credited rate.
fn camera_bytes(bits: u32) -> usize {
    (bits * limits::CAMERA_BYTES_PER_BIT) as usize
}

/// A collector with no source required, for checking one source at a time.
fn open_collector() -> Collector {
    Collector::new(&[])
}

/// Fill a source's share with credited samples, for tests about another one.
fn fill_camera(c: &mut Collector, from: u32) {
    let mut seed = from;
    while c.credited_from(Source::Camera) < c.share() {
        c.absorb_camera(&noise(seed, 2048));
        seed += 1;
    }
}

/// The generator is absorbed and credited nothing; a dead one refuses.
#[test]
fn the_generator_counts_for_nothing_and_a_dead_one_refuses() {
    let mut c = open_collector();
    let mut scratch = [0xAAu8; 64];
    c.absorb_generator(&mut Live(1), &mut scratch).unwrap();
    assert_eq!(c.credited(), 0);
    assert_eq!(scratch, [0u8; 64], "the draw is wiped");

    let mut c = open_collector();
    assert_eq!(
        c.absorb_generator(&mut Dead, &mut scratch),
        Err(entropy::Error::Unhealthy)
    );
    assert_eq!(c.credited(), 0);
}

/// The generator still changes the seed, so it is insurance even at zero.
#[test]
fn the_generator_still_changes_the_seed() {
    let chunk = noise(7, camera_bytes(limits::SEED_MIN_BITS));
    let mut a = open_collector();
    a.absorb_generator(&mut Live(1), &mut [0u8; 32]).unwrap();
    a.absorb_camera(&chunk);
    let mut b = open_collector();
    b.absorb_generator(&mut Live(2), &mut [0u8; 32]).unwrap();
    b.absorb_camera(&chunk);
    assert_ne!(
        words(&a.finish(Words::Twelve).unwrap()),
        words(&b.finish(Words::Twelve).unwrap())
    );
}

/// A camera chunk is credited at the device's figure, once.
#[test]
fn a_live_camera_chunk_is_credited_once() {
    let mut c = open_collector();
    let chunk = noise(3, camera_bytes(128));
    assert_eq!(
        c.absorb_camera(&chunk),
        Verdict::Credited {
            bits: 128,
            total: 128
        }
    );
    assert_eq!(c.share(), limits::SEED_MIN_BITS, "no source required here");
    assert_eq!(c.absorb_camera(&chunk), Verdict::Repeat);
    assert_eq!(c.credited(), 128);
    assert_eq!(c.credited_from(Source::Camera), 128);
    assert_eq!(c.remaining(), 128);
    assert!(!c.is_enough());
    assert_eq!(c.absorb_camera(&noise(4, camera_bytes(128))).bits(), 128);
    assert!(c.is_enough());
    assert_eq!(c.remaining(), 0);
}

/// A camera whose two buffers stop being written gives samples that take
/// turns, X-Y then Y-X: each differs from the one before, and each is
/// refused as a repeat of the one before that.
#[test]
fn a_camera_taking_turns_is_refused() {
    let mut c = open_collector();
    let x_less_y = noise(5, camera_bytes(32));
    let y_less_x: Vec<u8> = x_less_y.iter().map(|b| b.wrapping_neg()).collect();
    assert_eq!(c.absorb_camera(&x_less_y).bits(), 32);
    assert_eq!(c.absorb_camera(&y_less_x).bits(), 32);
    for _ in 0..4 {
        assert_eq!(c.absorb_camera(&x_less_y), Verdict::Repeat);
        assert_eq!(c.absorb_camera(&y_less_x), Verdict::Repeat);
    }
    assert_eq!(c.credited_from(Source::Camera), 64);
}

/// A sample is held against the last `REPEAT_WINDOW` from its source: one
/// that many back is a repeat, one further back is credited again.
#[test]
fn the_repeat_check_looks_a_window_back() {
    let mut c = open_collector();
    let samples: Vec<Vec<u8>> = (0..=REPEAT_WINDOW as u32)
        .map(|i| noise(100 + i, camera_bytes(8)))
        .collect();
    for s in &samples[..REPEAT_WINDOW] {
        assert_eq!(c.absorb_camera(s).bits(), 8);
    }
    assert_eq!(
        c.absorb_camera(&samples[0]),
        Verdict::Repeat,
        "a window back"
    );
    assert_eq!(c.absorb_camera(&samples[REPEAT_WINDOW]).bits(), 8);
    assert_eq!(c.absorb_camera(&samples[0]).bits(), 8, "past the window");
}

/// Dice look one roll back only: a die has six faces, so a caller adding a
/// roll at a time keeps every roll but one equal to the roll just before.
#[test]
fn dice_look_one_roll_back() {
    let mut c = open_collector();
    for roll in [b"1", b"2", b"1", b"2"] {
        assert_eq!(
            c.absorb_dice(roll).unwrap().bits(),
            limits::DICE_BITS_PER_ROLL
        );
    }
    assert_eq!(c.absorb_dice(b"2"), Ok(Verdict::Repeat));
    assert_eq!(c.credited(), 4 * limits::DICE_BITS_PER_ROLL);
}

/// What the camera gate refuses: a short chunk, a dark sensor, one value.
#[test]
fn a_dead_camera_is_not_credited() {
    let mut c = open_collector();
    assert_eq!(
        c.absorb_camera(&noise(1, limits::CAMERA_SAMPLE_MIN - 1)),
        Verdict::Short {
            len: limits::CAMERA_SAMPLE_MIN - 1,
            min: limits::CAMERA_SAMPLE_MIN
        }
    );
    // The M5 in the dark: one value throughout.
    assert_eq!(c.absorb_camera(&[0u8; 4096]), Verdict::Dead);
    // Tuned, in the dark: a few non-zero bytes (81 in 256 KB), scaled.
    let mut dark = vec![0u8; 4096];
    for (i, b) in dark.iter_mut().enumerate().take(64) {
        *b = (i % 32) as u8 + 1;
    }
    assert_eq!(c.absorb_camera(&dark), Verdict::Dead);
    // Plenty of change, but two values only: a counter, not a sensor.
    let two: Vec<u8> = (0..4096u32).map(|i| (i % 2) as u8 + 1).collect();
    assert_eq!(c.absorb_camera(&two), Verdict::Dead);
    assert_eq!(c.credited(), 0);

    // Like a covered Waveshare lens (44% of bytes changed, many values):
    // alive.
    let mut covered = noise(9, 4096);
    for b in covered.iter_mut().skip(1).step_by(2) {
        *b = 0;
    }
    assert!(matches!(
        c.absorb_camera(&covered),
        Verdict::Credited { .. }
    ));
}

/// An IMU chunk with one frozen axis is dead, tried on each axis.
#[test]
fn one_frozen_axis_fails_the_whole_buffer() {
    let live = noise(5, 3 * 64);
    let mut c = open_collector();
    assert_eq!(
        c.absorb_imu(&live),
        Verdict::Credited {
            bits: (3 * 64) / limits::IMU_BYTES_PER_BIT,
            total: 96
        }
    );
    for axis in 0..3 {
        let mut frozen = live.clone();
        for b in frozen.iter_mut().skip(axis).step_by(3) {
            *b = 0x42;
        }
        assert_eq!(c.absorb_imu(&frozen), Verdict::Dead, "axis {axis}");
    }
    assert_eq!(
        c.absorb_imu(&live[..limits::IMU_SAMPLE_MIN - 1]),
        Verdict::Short {
            len: limits::IMU_SAMPLE_MIN - 1,
            min: limits::IMU_SAMPLE_MIN
        }
    );
    assert_eq!(c.credited(), 96);
}

/// A finger held still counts nothing; a moving one earns a bit every
/// `TOUCH_EVENTS_PER_BIT` touches.
#[test]
fn touch_credits_movement_only() {
    let mut c = open_collector();
    assert_eq!(c.absorb_touch(10, 10, 9000).bits(), 0);
    assert_eq!(c.absorb_touch(10, 10, 9100), Verdict::Still);
    assert_eq!(c.absorb_touch(11, 10, 9200).bits(), 1);
    let per = limits::TOUCH_EVENTS_PER_BIT as usize;
    let mut earned = 1;
    for i in 0..(2 * per * 100) {
        earned += c.absorb_touch(20 + i as u16, 30, 9000 + i as u32).bits();
    }
    assert_eq!(earned, 201);
    assert_eq!(c.credited(), 201);
}

/// Dice in a mixed seed: two bits a roll, and a bad face refuses the lot.
#[test]
fn dice_in_the_mix() {
    let mut c = open_collector();
    assert_eq!(
        c.absorb_dice(b"1234561").unwrap(),
        Verdict::Credited {
            bits: 7 * limits::DICE_BITS_PER_ROLL,
            total: 14
        }
    );
    assert_eq!(
        c.absorb_dice(b"12345670"),
        Err(Error::BadRoll { position: 6 })
    );
    assert_eq!(c.absorb_dice(b""), Ok(Verdict::Short { len: 0, min: 1 }));
    assert_eq!(c.credited(), 14);
}

/// Nothing under 256 bits becomes a seed; at 256 it does, at either length.
#[test]
fn finish_needs_the_minimum() {
    let mut c = open_collector();
    c.absorb_camera(&noise(1, camera_bytes(limits::SEED_MIN_BITS - 1)));
    assert_eq!(
        c.finish(Words::Twelve).err(),
        Some(Error::NotEnough {
            have: 255,
            need: limits::SEED_MIN_BITS
        })
    );
    let mut c = open_collector();
    c.absorb_camera(&noise(1, camera_bytes(limits::SEED_MIN_BITS)));
    let m = c.finish(Words::Twelve).unwrap();
    assert_eq!(m.len(), 12);
    let mut c = open_collector();
    c.absorb_camera(&noise(1, camera_bytes(limits::SEED_MIN_BITS)));
    let m = c.finish(Words::TwentyFour).unwrap();
    assert_eq!(m.len(), 24);
}

/// Every source the unit has must reach its share: a total is not enough.
#[test]
fn every_source_must_reach_its_share() {
    // The M5's pair: 256 between two is 128 each.
    let mut c = Collector::new(&[Source::Camera, Source::Touch]);
    assert_eq!(c.share(), 128);

    // A chunk worth four times the whole requirement, credited its share
    // and no more.
    c.absorb_camera(&noise(1, camera_bytes(4 * limits::SEED_MIN_BITS)));
    assert_eq!(c.credited(), 128);
    assert_eq!(c.credited_from(Source::Camera), 128);
    assert!(!c.is_enough(), "one source cannot finish it");
    assert_eq!(c.short(), Some(Source::Touch));
    assert_eq!(
        c.finish(Words::Twelve).err(),
        Some(Error::SourceShort {
            source: Source::Touch,
            have: 0,
            need: 128
        })
    );

    // 128 bits take 256 moving touches; then it is a seed.
    let mut c = Collector::new(&[Source::Camera, Source::Touch]);
    c.absorb_camera(&noise(1, camera_bytes(4 * limits::SEED_MIN_BITS)));
    for i in 0..(2 * 200) {
        c.absorb_touch(i as u16, 7, 900 + i as u32);
    }
    assert_eq!(
        c.credited_from(Source::Touch),
        128,
        "touch stops at its share"
    );
    assert_eq!(c.credited(), 256, "and so does the total");
    assert_eq!(c.short(), None);
    assert!(c.is_enough());
    assert_eq!(c.finish(Words::TwentyFour).unwrap().len(), 24);
}

/// A dead source stops the seed rather than being carried by the others.
#[test]
fn a_dead_source_stops_the_seed() {
    let mut c = Collector::new(&[Source::Camera, Source::Touch]);
    for _ in 0..40 {
        // The M5 in the dark.
        assert_eq!(c.absorb_camera(&[0u8; 4096]), Verdict::Dead);
    }
    for i in 0..4096 {
        c.absorb_touch(i as u16, 11, 900 + i as u32);
    }
    assert_eq!(
        c.credited_from(Source::Touch),
        128,
        "touch filled its share"
    );
    assert_eq!(c.credited(), 128, "and the camera credited nothing");
    assert_eq!(c.short(), Some(Source::Camera));
    assert!(!c.is_enough());
}

/// Three sources split the requirement three ways, and the IMU is only
/// required on a unit that has one.
#[test]
fn the_share_follows_the_sources_the_unit_has() {
    let three = Collector::new(&[Source::Camera, Source::Imu, Source::Touch]);
    assert_eq!(three.share(), 86);

    // The same board with the IMU absent asks the other two for more each.
    let two = Collector::new(&[Source::Camera, Source::Touch]);
    assert_eq!(two.share(), 128);

    // The generator is never a share: it is credited nothing.
    let with_rng = Collector::new(&[Source::Generator, Source::Camera, Source::Touch]);
    assert_eq!(with_rng.share(), 128);
    let mut c = with_rng;
    c.absorb_generator(&mut Live(3), &mut [0u8; 32]).unwrap();
    fill_camera(&mut c, 20);
    for i in 0..(2 * 128) {
        c.absorb_touch(i as u16, 3, 800 + i as u32);
    }
    assert_eq!(c.short(), None);
    assert!(c.finish(Words::Twelve).is_ok());

    // A source listed twice is one source.
    assert_eq!(
        Collector::new(&[Source::Camera, Source::Camera]).share(),
        256
    );
}

/// The same inputs make the same seed; a different input, a different one.
#[test]
fn the_seed_is_a_function_of_what_went_in() {
    fn make(cam: u32, touch_x: u16) -> Vec<u16> {
        let mut c = open_collector();
        c.absorb_camera(&noise(cam, camera_bytes(limits::SEED_MIN_BITS)));
        c.absorb_touch(touch_x, 5, 1234);
        words(&c.finish(Words::TwentyFour).unwrap())
    }
    assert_eq!(make(1, 10), make(1, 10));
    assert_ne!(make(1, 10), make(2, 10));
    assert_ne!(make(1, 10), make(1, 11));
}

/// A decoded payload is a standard SeedQR, a compact one, or neither.
#[test]
fn read_qr_tells_the_encodings_apart() {
    let standard = b"000000000000000000000000000000000000000000000003";
    let (m, e) = seed::read_qr(standard).unwrap();
    assert_eq!(e, Encoding::Standard);
    assert_eq!(m.len(), 12);
    assert_eq!(m.word(11), Some("about"));

    let (m, e) = seed::read_qr(&[0u8; 16]).unwrap();
    assert_eq!(e, Encoding::Compact);
    assert_eq!(m.word(11), Some("about"));

    let (m, e) = seed::read_qr(&[0u8; 32]).unwrap();
    assert_eq!(e, Encoding::Compact);
    assert_eq!(m.len(), 24);
    assert_eq!(m.word(23), Some("art"));

    let mut long = [b'0'; 96];
    long[95] = b'1';
    // Whatever the checksum says, it is a standard shape and level 2 judges it.
    match seed::read_qr(&long) {
        Ok((m, Encoding::Standard)) => assert_eq!(m.len(), 24),
        Err(ReadError::Slot(_)) => {}
        other => panic!("{other:?}"),
    }

    assert_eq!(seed::read_qr(b"0000").err(), Some(ReadError::NotSeedQr));
    assert_eq!(seed::read_qr(&[b'x'; 48]).err(), Some(ReadError::NotSeedQr));
    assert_eq!(seed::read_qr(&[0u8; 20]).err(), Some(ReadError::NotSeedQr));
    assert_eq!(seed::read_qr(&[0u8; 48]).err(), Some(ReadError::NotSeedQr));
    let mut wrong = *standard;
    wrong[47] = b'4';
    assert!(matches!(seed::read_qr(&wrong), Err(ReadError::Slot(_))));
    // A transaction frame: our magic byte and not a seed.
    assert_eq!(seed::read_qr(&[0x1B; 48]).err(), Some(ReadError::NotSeedQr));
}

/// Both encodings draw, and a drawn code reads back as the same words.
#[test]
fn seedqr_draws_and_reads_back() {
    use kassigner_crypto::slot::{to_compact_seedqr, to_seedqr, SEEDQR_MAX};

    for len in [16usize, 32] {
        let m = kassigner_crypto::bip39::from_entropy(&noise(11, len)).unwrap();
        let s = seed::standard_qr(&m).unwrap();
        let c = seed::compact_qr(&m).unwrap();
        assert!(s.size >= 21);
        assert!(c.size >= 21);
        // The standard code carries more, so it is never the smaller.
        assert!(s.size >= c.size);

        let mut digits = [0u8; SEEDQR_MAX];
        let n = to_seedqr(&m, &mut digits);
        let (back, _) = seed::read_qr(&digits[..n]).unwrap();
        assert_eq!(words(&back), words(&m));
        let mut bytes = [0u8; 32];
        let n = to_compact_seedqr(&m, &mut bytes);
        let (back, _) = seed::read_qr(&bytes[..n]).unwrap();
        assert_eq!(words(&back), words(&m));
    }
}

/// Credit stops at a source's share, and the bytes keep going in: the count
/// a screen shows says what is missing, not how far a fast source overshot.
#[test]
fn credit_stops_at_the_share_but_absorbing_does_not() {
    let sources = [Source::Camera, Source::Imu, Source::Touch];
    let mut c = Collector::new(&sources);
    assert_eq!(c.share(), 86);

    // 384 bytes is 192 credited bits, more than twice the share.
    assert_eq!(c.absorb_imu(&noise(2, 384)).bits(), 86);
    for i in 0..20 {
        assert_eq!(c.absorb_imu(&noise(10 + i, 384)).bits(), 0, "sample {i}");
    }
    assert_eq!(c.credited_from(Source::Imu), 86);
    assert_eq!(c.credited(), 86);

    // The uncredited samples still went into the pool: a collector fed only
    // the first makes a different seed.
    let mut quiet = Collector::new(&sources);
    quiet.absorb_imu(&noise(2, 384));
    for col in [&mut c, &mut quiet] {
        fill_camera(col, 60);
        for i in 0..(2 * 86) {
            col.absorb_touch(i as u16, 9, 700 + i as u32);
        }
        assert!(col.is_enough());
    }
    assert_ne!(
        words(&c.finish(Words::Twelve).unwrap()),
        words(&quiet.finish(Words::Twelve).unwrap()),
        "the uncredited samples still changed the seed"
    );
}

/// A large IMU chunk is not dead by arithmetic: 60% of 512 samples an axis
/// distinct would be 307 values of the 256 a byte holds.
#[test]
fn a_large_imu_chunk_is_not_dead_by_arithmetic() {
    let mut c = Collector::new(&[]);
    for len in [192usize, 384, 1536, 3072] {
        assert!(
            matches!(
                c.absorb_imu(&noise(len as u32, len)),
                Verdict::Credited { .. }
            ),
            "{len} bytes read as dead"
        );
    }
    // A frozen axis is still caught at any size.
    for len in [192usize, 1536] {
        let mut frozen = noise(7, len);
        for b in frozen.iter_mut().skip(1).step_by(3) {
            *b = 0x11;
        }
        assert_eq!(c.absorb_imu(&frozen), Verdict::Dead, "{len} bytes");
    }
}
