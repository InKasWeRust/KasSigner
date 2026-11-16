// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Codes out and in, through the unit's own frames, encoder and decoder.

use kassigner_protocol::frame::{Format, FrameError};
use kassigner_protocol::profile::Profile;
use kassigner_qr::{Decoder, Scratch};
use kassigner_sdk::transport::{
    Codes, Progress, Reader, ReaderBuffers, TransportError, CODE_MAX, FRAME_BUF, MIN_VERSION,
    PERIOD_UP_TO_V7_MS, PERIOD_V8_V9_MS, PREFERRED_FRAMES,
};

const P: Profile = Profile::ESP32S3;

/// A KSPT-looking payload of `len` bytes: the magic, then a run.
fn payload(len: usize) -> Vec<u8> {
    let mut v = b"KSPT\x06\x00".to_vec();
    v.extend((6..len).map(|i| (i * 7 % 251) as u8));
    v.truncate(len);
    v
}

/// Every code of `payload` under `codes`, as bytes.
fn frames(codes: &Codes, payload: &[u8]) -> Vec<Vec<u8>> {
    (0..codes.frames)
        .map(|i| {
            let mut buf = [0u8; FRAME_BUF];
            let n = codes
                .bytes(Format::Kspt, payload, i, &mut buf)
                .expect("a frame");
            buf[..n].to_vec()
        })
        .collect()
}

struct Room {
    payload: Vec<u8>,
    seen: Vec<bool>,
    sizes: Vec<u8>,
    bare: Vec<u8>,
}

impl Room {
    fn new() -> Self {
        Room {
            payload: vec![0; P.max_reassembled],
            seen: vec![false; P.max_frames],
            sizes: vec![0; P.max_frames],
            bare: vec![0; CODE_MAX],
        }
    }
    fn buffers(&mut self) -> ReaderBuffers<'_> {
        ReaderBuffers {
            payload: &mut self.payload,
            seen: &mut self.seen,
            sizes: &mut self.sizes,
            bare: &mut self.bare,
        }
    }
    fn reader(&mut self) -> Reader<'_> {
        Reader::new(self.buffers(), 225)
    }
}

/// Codes cycle at 600 ms up to version 7 and 850 ms at 8 and 9, over every
/// length the profile takes, each version met.
#[test]
fn the_period_follows_the_version() {
    assert_eq!((PERIOD_UP_TO_V7_MS, PERIOD_V8_V9_MS), (600, 850));
    let mut met = [false; 10];
    for len in 1..=P.max_reassembled {
        let Ok(plan) = Codes::plan(len, &P) else {
            break;
        };
        let want = if plan.version <= 7 { 600 } else { 850 };
        assert_eq!(
            plan.period_ms(),
            want,
            "{len} bytes, version {}",
            plan.version
        );
        met[usize::from(plan.version)] = true;
    }
    assert!(met[6] && met[7] && met[8] && met[9], "{met:?}");
}

/// The plan: bare up to a version-6 code's 134 bytes, then the smallest version
/// from 6 in five frames or fewer, then version 9, within the profile; no frame
/// is drawn above the plan's version.
#[test]
fn the_plan_follows_the_rule() {
    let bare = Codes::plan(134, &P).unwrap();
    assert!(bare.bare);
    assert_eq!((bare.frames, bare.version), (1, MIN_VERSION));
    // Version-6 frames, though a denser code would hold them: 169 and 232 are a
    // card's backup line without and with a recovery wallet.
    for len in [135, 169, 230, 232] {
        let two = Codes::plan(len, &P).unwrap();
        assert_eq!(
            (two.bare, two.frames, two.version),
            (false, 2, MIN_VERSION),
            "{len}"
        );
    }
    let small = Codes::plan(300, &P).unwrap();
    assert_eq!(
        (small.bare, small.frames, small.version),
        (false, 3, MIN_VERSION)
    );
    assert_eq!(small.bytes_per_frame, 134 - 5);
    let five = Codes::plan(1000, &P).unwrap();
    assert_eq!(
        (five.frames, five.version, five.bytes_per_frame),
        (5, 9, 225)
    );
    let many = Codes::plan(2000, &P).unwrap();
    assert_eq!((many.frames, many.version), (9, 9));
    assert!(many.frames > PREFERRED_FRAMES);
    for (len, plan) in [(300, small), (1000, five), (2000, many)] {
        let p = payload(len);
        for i in 0..plan.frames {
            let side = plan.code(Format::Kspt, &p, i).unwrap().size;
            assert!(
                side <= 17 + 4 * plan.version,
                "{len}: frame {i} lighter or at its version"
            );
        }
    }
    // 300 bytes in three frames: 106-byte codes, version 5, not padded up.
    assert_eq!(
        small.code(Format::Kspt, &payload(300), 0).unwrap().size,
        17 + 4 * 5
    );
    assert_eq!(Codes::plan(0, &P), Err(TransportError::Empty));
    assert!(matches!(
        Codes::plan(P.max_reassembled + 1, &P),
        Err(TransportError::TooManyFrames { .. })
    ));
    let last = Codes::plan(64 * 225 - 3, &P).unwrap();
    assert_eq!(last.frames, 64);
    assert!(matches!(
        Codes::plan(64 * 225 - 2, &P),
        Err(TransportError::TooManyFrames { frames: 65, .. })
    ));
    assert_eq!(
        five.bytes(Format::Kspt, &payload(1000), 5, &mut [0u8; FRAME_BUF]),
        Err(TransportError::NoSuchFrame {
            index: 5,
            frames: 5
        })
    );
}

/// Frames out, frames in, in any order with repeats, make the payload; a bare
/// code, from one.
#[test]
fn frames_round_trip_through_the_reader() {
    for len in [200usize, 300, 1000, 2000, 5000] {
        let p = payload(len);
        let codes = Codes::plan(len, &P).unwrap();
        let fs = frames(&codes, &p);
        let mut room = Room::new();
        let mut reader = room.reader();
        // Last first, then every one twice, as a camera round a cycle.
        let order: Vec<usize> = (0..fs.len()).rev().chain(0..fs.len()).collect();
        let mut whole = None;
        for (k, &i) in order.iter().enumerate() {
            let got = reader.take(&fs[i], P.max_frames).unwrap();
            match got {
                Progress::Whole(n) => {
                    assert_eq!(n, len);
                    whole.get_or_insert(k);
                }
                Progress::Partial { have, need } => {
                    assert!(have < need && need == fs.len(), "{len}: {have}/{need}");
                    assert!(whole.is_none());
                }
                Progress::Nothing => assert!(whole.is_some() || k > 0, "a repeat"),
                Progress::NotAReply => panic!("a frame"),
            }
        }
        assert_eq!(
            whole,
            Some(fs.len() - 1),
            "{len}: whole after the last new frame"
        );
        assert_eq!(reader.format(), Some(Format::Kspt));
        let mut out = vec![0u8; len];
        assert_eq!(reader.collect(&mut out), Ok(len));
        assert_eq!(out, p);
        assert_eq!(
            reader.collect(&mut vec![0u8; len - 1]),
            Err(TransportError::TooLong { needed: len })
        );
    }
    let p = payload(134);
    let codes = Codes::plan(134, &P).unwrap();
    let fs = frames(&codes, &p);
    assert_eq!(fs, vec![p.clone()], "a bare code is the payload");
    let mut room = Room::new();
    let mut reader = room.reader();
    assert_eq!(reader.take(&fs[0], P.max_frames), Ok(Progress::Whole(134)));
    assert_eq!(reader.format(), Some(Format::Kspt));
    let mut out = vec![0u8; 134];
    assert_eq!(reader.collect(&mut out), Ok(134));
    assert_eq!(out, p);
    assert_eq!(reader.take(b"hello", P.max_frames), Ok(Progress::NotAReply));
}

/// A reader suspended after every code, then resumed over the same room, reads
/// a framed reply and a bare one.
#[test]
fn a_reader_suspended_per_code_reads_the_same() {
    let p = payload(2000);
    let fs = frames(&Codes::plan(2000, &P).unwrap(), &p);
    let mut room = Room::new();
    let mut state = room.reader().suspend();
    let order: Vec<usize> = (0..fs.len()).rev().collect();
    for (k, &i) in order.iter().enumerate() {
        let mut reader = Reader::resume(room.buffers(), state);
        let got = reader.take(&fs[i], P.max_frames).unwrap();
        if k + 1 == fs.len() {
            assert_eq!(got, Progress::Whole(2000));
        } else {
            assert_eq!(
                got,
                Progress::Partial {
                    have: k + 1,
                    need: fs.len()
                }
            );
        }
        state = reader.suspend();
    }
    let reader = Reader::resume(room.buffers(), state);
    let mut out = vec![0u8; 2000];
    assert_eq!(reader.collect(&mut out), Ok(2000));
    assert_eq!(out, p);
    let state = reader.suspend();

    let bare = payload(150);
    let mut reader = Reader::resume(room.buffers(), state);
    assert_eq!(reader.take(&bare, P.max_frames), Ok(Progress::Whole(150)));
    let state = reader.suspend();
    let reader = Reader::resume(room.buffers(), state);
    let mut out = vec![0u8; 150];
    assert_eq!(reader.collect(&mut out), Ok(150));
    assert_eq!(out, bare);
}

/// A state over buffers it does not fit starts over: a bare reply longer than
/// `bare` is dropped.
#[test]
fn a_reader_state_over_buffers_it_does_not_fit_starts_over() {
    let bare = payload(150);
    let mut room = Room::new();
    let state = {
        let mut reader = room.reader();
        assert_eq!(reader.take(&bare, P.max_frames), Ok(Progress::Whole(150)));
        reader.suspend()
    };
    let mut short = Room::new();
    short.bare = vec![0; 100];
    let mut reader = Reader::resume(short.buffers(), state);
    assert_eq!(reader.format(), None);
    assert!(reader.collect(&mut [0u8; 150]).is_err());
    assert_eq!(
        reader.take(&bare[..100], P.max_frames),
        Ok(Progress::Whole(100))
    );
}

/// The reader says which frames are in, out of order, over every frame a
/// profile allows; after a set is dropped for another, only the new one's;
/// after a reset or a bare reply, none.
#[test]
fn the_reader_says_which_frames_are_in() {
    let len = (1..=P.max_reassembled)
        .rev()
        .find(|&l| Codes::plan(l, &P).is_ok_and(|c| c.frames == P.max_frames))
        .expect("a reply in every frame the profile allows");
    let p = payload(len);
    let codes = Codes::plan(len, &P).unwrap();
    let fs = frames(&codes, &p);
    let mut room = Room::new();
    let mut reader = room.reader();
    assert_eq!(reader.received(), 0);
    let n = fs.len();
    let order: Vec<usize> = (0..n).map(|k| k * 37 % n).chain([5, 5, 40, 0]).collect();
    let mut held = 0u64;
    for &i in &order {
        reader.take(&fs[i], P.max_frames).unwrap();
        held |= 1 << i;
        assert_eq!(reader.received(), held, "after frame {i}");
    }
    assert_eq!(reader.received(), u64::MAX, "all 64 once whole");

    let a = payload(1000);
    let mut b = payload(1000);
    b[500] ^= 0xFF;
    let plan = Codes::plan(1000, &P).unwrap();
    let (fa, fb) = (frames(&plan, &a), frames(&plan, &b));
    reader.reset();
    assert_eq!(reader.received(), 0, "a reset forgets them");
    reader.take(&fa[0], P.max_frames).unwrap();
    reader.take(&fa[3], P.max_frames).unwrap();
    assert_eq!(reader.received(), 0b1001);
    reader.take(&fb[1], P.max_frames).unwrap();
    assert_eq!(reader.received(), 0b10, "only the new set's frame");
    assert_eq!(
        reader.take(&payload(150), P.max_frames),
        Ok(Progress::Whole(150))
    );
    assert_eq!(reader.received(), 0, "a bare reply has no frames");
}

/// Two transmissions never make one reply: a second request's frames replace
/// the first's.
#[test]
fn two_transmissions_never_mix() {
    let a = payload(1000);
    let mut b = payload(1000);
    b[500] ^= 0xFF;
    let codes = Codes::plan(1000, &P).unwrap();
    let fa = frames(&codes, &a);
    let fb = frames(&codes, &b);
    let mut room = Room::new();
    let mut reader = room.reader();
    assert!(matches!(
        reader.take(&fa[0], P.max_frames),
        Ok(Progress::Partial { have: 1, .. })
    ));
    assert!(matches!(
        reader.take(&fa[1], P.max_frames),
        Ok(Progress::Partial { have: 2, .. })
    ));
    // The screen moved to b: its frame names another payload, and the set
    // starts over.
    assert!(matches!(
        reader.take(&fb[2], P.max_frames),
        Ok(Progress::Partial { have: 1, .. })
    ));
    for f in [&fb[0], &fb[1], &fb[3]] {
        reader.take(f, P.max_frames).unwrap();
    }
    assert_eq!(reader.take(&fb[4], P.max_frames), Ok(Progress::Whole(1000)));
    let mut out = vec![0u8; 1000];
    reader.collect(&mut out).unwrap();
    assert_eq!(out, b);
    assert_eq!(
        reader.take(&[0x1B, 0x77, 0, 1, 0, 0, 0, 0, 1], P.max_frames),
        Err(TransportError::Frame(FrameError::UnknownFormat(0x77)))
    );
}

/// A new transmission's first frame is progress even when the set it replaces
/// held one frame, the same count: the reader says the set started over.
#[test]
fn a_new_transmission_replacing_one_frame_is_progress() {
    let a = payload(1000);
    let mut b = payload(1000);
    b[500] ^= 0xFF;
    let codes = Codes::plan(1000, &P).unwrap();
    let fa = frames(&codes, &a);
    let fb = frames(&codes, &b);
    let mut room = Room::new();
    let mut reader = room.reader();
    assert!(matches!(
        reader.take(&fa[0], P.max_frames),
        Ok(Progress::Partial { have: 1, .. })
    ));
    assert!(matches!(
        reader.take(&fb[3], P.max_frames),
        Ok(Progress::Partial { have: 1, .. })
    ));
    assert_eq!(reader.received(), 1 << 3, "only the new set's frame");
    assert_eq!(reader.take(&fb[3], P.max_frames), Ok(Progress::Nothing));
}

fn rasterize(qr: &kassigner_qr::QrMatrix, scale: usize, quiet: usize) -> (usize, Vec<u8>) {
    let n = qr.size as usize;
    let side = (n + quiet * 2) * scale;
    let mut px = vec![0xFFu8; side * side];
    for y in 0..n {
        for x in 0..n {
            if qr.get(x as u8, y as u8) {
                for dy in 0..scale {
                    for dx in 0..scale {
                        px[((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx] = 0x00;
                    }
                }
            }
        }
    }
    (side, px)
}

/// Every code decodes back to its frame with the unit's decoder, at the
/// planned version or below, and the frames read make the payload.
#[test]
fn every_code_decodes_with_the_units_decoder() {
    for len in [200usize, 300, 1000] {
        let p = payload(len);
        let codes = Codes::plan(len, &P).unwrap();
        let fs = frames(&codes, &p);
        let mut room = Room::new();
        let mut reader = room.reader();
        for (i, frame) in fs.iter().enumerate() {
            let qr = codes.code(Format::Kspt, &p, i).expect("a code");
            assert!(
                qr.size <= 17 + 4 * codes.version,
                "{len}: version past the plan"
            );
            let (side, mut px) = rasterize(&qr, 4, 4);
            let mut out = [0u8; 512];
            let mut scratch = Scratch::new();
            let mut dec = Decoder::new(&mut scratch);
            let got = dec
                .decode(side, side, 8, &mut px, &mut out)
                .expect("decodes");
            assert_eq!(&out[..got.len], &frame[..], "{len}: frame {i}");
            reader.take(&out[..got.len], P.max_frames).unwrap();
        }
        let mut out = vec![0u8; len];
        assert_eq!(reader.collect(&mut out), Ok(len));
        assert_eq!(out, p);
    }
}
