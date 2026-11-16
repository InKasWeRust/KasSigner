// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multi-frame transport.
//!
//! Frames as a camera catches them: out of order, repeated, interleaved with
//! another transmission, or built by hand past what `parse` lets through.

use kassigner_protocol::frame::{
    digest, frames_needed, parse, payload_capacity, sha256, write, write_split, Format, Frame,
    FrameError, Named, Reassembler, FIRST_HEADER_LEN, HEADER_LEN, MAGIC,
};
use kassigner_protocol::profile::Profile;

const P: Profile = Profile::ESP32S3;

/// Buffers a device would supply, sized from the profile.
struct Bufs {
    buf: [u8; 64 * 200],
    seen: [bool; 64],
    sizes: [u8; 64],
}

impl Bufs {
    fn new() -> Self {
        Self {
            buf: [0u8; 64 * 200],
            seen: [false; 64],
            sizes: [0u8; 64],
        }
    }
    fn reassembler(&mut self) -> Reassembler<'_> {
        Reassembler::new(&mut self.buf, &mut self.seen, &mut self.sizes, 200)
    }
}

/// Split a payload into frames the way a sender would.
fn split(payload: &[u8], per: usize) -> Vec<Vec<u8>> {
    split_as(Format::Kspt, payload, per)
}

fn split_as(format: Format, payload: &[u8], per: usize) -> Vec<Vec<u8>> {
    split_naming(format, payload, per, digest(payload))
}

/// As [`split_as`], naming `named` as the digest: `per` bytes a frame,
/// greedily.
fn split_naming(format: Format, payload: &[u8], per: usize, named: [u8; 4]) -> Vec<Vec<u8>> {
    let total = payload.len().div_ceil(per) as u8;
    payload
        .chunks(per)
        .enumerate()
        .map(|(i, chunk)| {
            let mut out = vec![0u8; FIRST_HEADER_LEN + chunk.len()];
            let n = write(format, i as u8, total, named, chunk, &mut out).expect("write");
            out.truncate(n);
            out
        })
        .collect()
}

/// Any arrival order reassembles: forward, reversed, rotated.
#[test]
fn any_arrival_order_reassembles() {
    let payload: Vec<u8> = (0..1000).map(|i| (i * 7 + 3) as u8).collect();
    let frames = split(&payload, 200);
    assert_eq!(frames.len(), 5);

    let orders: [Vec<usize>; 3] = [
        (0..5).collect(),
        (0..5).rev().collect(),
        vec![3, 4, 0, 1, 2],
    ];

    for order in orders {
        let mut b = Bufs::new();
        let mut r = b.reassembler();
        for &i in &order {
            let f = parse(&frames[i], P.max_frames).expect("parse");
            r.push(&f).expect("push");
        }
        assert!(r.is_complete(), "order {order:?} did not complete");
        let mut out = vec![0u8; payload.len()];
        let n = r.collect(&mut out).expect("collect");
        assert_eq!(
            &out[..n],
            &payload[..],
            "order {order:?} changed the payload"
        );
    }
}

/// A repeated frame is ignored, not an error: a looping display shows each
/// many times.
#[test]
fn repeated_frames_are_ignored() {
    let payload: Vec<u8> = (0..500).map(|i| i as u8).collect();
    let frames = split(&payload, 200);

    let mut b = Bufs::new();
    let mut r = b.reassembler();
    for _ in 0..4 {
        for f in &frames {
            let f = parse(f, P.max_frames).expect("parse");
            r.push(&f).expect("push");
        }
    }
    assert!(r.is_complete());
    let mut out = vec![0u8; payload.len()];
    assert_eq!(r.collect(&mut out).unwrap(), payload.len());
    assert_eq!(&out[..], &payload[..]);
}

/// Progress and the frames received are known before completion.
#[test]
fn progress_reports_what_has_arrived() {
    let payload: Vec<u8> = (0..1000).map(|i| i as u8).collect();
    let frames = split(&payload, 200);

    let mut b = Bufs::new();
    let mut r = b.reassembler();
    assert_eq!(r.progress(), (0, 0), "nothing known before the first frame");
    assert_eq!(r.received(), 0);

    let mut bits = 0u64;
    for (k, i) in [3usize, 0, 4, 1, 2].into_iter().enumerate() {
        let f = parse(&frames[i], P.max_frames).expect("parse");
        r.push(&f).expect("push");
        bits |= 1 << i;
        assert_eq!(r.progress(), (k + 1, 5));
        assert_eq!(r.received(), bits);
    }
    r.reset();
    assert_eq!(r.received(), 0, "a reset forgets them");
}

/// The whole SHA-256 is SHA-256 (FIPS 180-2's "abc" vector) and the frames'
/// digest its start; the firmware checks a request against it between
/// review and signing.
#[test]
fn the_whole_digest_is_sha256_and_the_frames_digest_its_start() {
    let abc = sha256(b"abc");
    let want: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(abc, want);
    assert_eq!(digest(b"abc")[..], abc[..4]);
}

/// A slot whose offset does not fit an address is refused, not a panic: at
/// half the address space frame 2's offset overflows and frame 1's is past
/// the buffer, both `TooLarge`; frame 0 is still taken.
#[test]
fn a_slot_past_what_an_address_holds_is_refused() {
    let mut buf = [0u8; 600];
    let mut seen = [false; 3];
    let mut sizes = [0u8; 3];
    let slot = usize::MAX / 2 + 1;
    let mut r = Reassembler::new(&mut buf, &mut seen, &mut sizes, slot);
    for index in [2u8, 1] {
        let frame = Frame {
            format: Format::Kspt,
            index,
            total: 3,
            named: None,
            fragment: &[1, 2, 3],
        };
        assert_eq!(r.push(&frame), Err(FrameError::TooLarge), "frame {index}");
    }
    assert_eq!(r.progress(), (0, 0), "nothing was adopted");
    let first = Frame {
        format: Format::Kspt,
        index: 0,
        total: 3,
        named: None,
        fragment: &[1, 2, 3],
    };
    assert_eq!(r.push(&first), Ok(()), "frame 0 is at offset 0");
    assert_eq!(r.progress(), (1, 3));
}

/// More frames than there are slots is refused and leaves nothing behind:
/// `total` is bounded by `parse`'s `max_frames`, the arrays by the buffers,
/// and nothing makes them agree.
#[test]
fn a_stream_longer_than_the_buffers_is_refused() {
    // Four slots, against a sender splitting into ten frames.
    let mut buf = [0u8; 4 * 200];
    let mut seen = [false; 4];
    let mut sizes = [0u8; 4];
    let mut r = Reassembler::new(&mut buf, &mut seen, &mut sizes, 200);

    let payload: Vec<u8> = (0..2000).map(|i| i as u8).collect();
    let frames = split(&payload, 200);
    let f = parse(&frames[0], P.max_frames).expect("parse");
    assert_eq!(f.total, 10);
    assert_eq!(
        r.push(&f),
        Err(FrameError::TooManyFrames {
            total: 10,
            limit: 4
        })
    );

    // Nothing was recorded: the readers stay inside the arrays.
    assert_eq!(r.progress(), (0, 0), "the stream was not adopted");
    assert!(!r.is_complete());
    assert_eq!(r.payload_len(), 0);
    assert!(r.collect(&mut [0u8; 2000]).is_err());

    // Built by hand: the count is refused, not the index.
    let forged = Frame {
        format: Format::Kspt,
        index: 0,
        total: 200,
        named: None,
        fragment: &[1, 2, 3],
    };
    assert_eq!(
        r.push(&forged),
        Err(FrameError::TooManyFrames {
            total: 200,
            limit: 4
        })
    );
    assert_eq!(r.progress(), (0, 0));

    // A stream that fits is still accepted.
    let short = split(&payload[..600], 200);
    for raw in &short {
        let f = parse(raw, P.max_frames).expect("parse");
        r.push(&f).expect("push");
    }
    assert!(r.is_complete());
    let mut out = [0u8; 600];
    assert_eq!(r.collect(&mut out).expect("collect"), 600);
    assert_eq!(&out[..], &payload[..600]);
}

/// A frame outside its own set is refused by `push` as by `parse`: stored,
/// it would only inflate `progress`, which a scan loop compares to spot a
/// duplicate.
#[test]
fn a_frame_outside_its_own_set_is_refused() {
    let payload: Vec<u8> = (0..1000).map(|i| i as u8).collect();
    let frames = split(&payload, 200);

    let mut b = Bufs::new();
    let mut r = b.reassembler();
    for raw in &frames[..4] {
        let f = parse(raw, P.max_frames).expect("parse");
        r.push(&f).expect("push");
    }
    assert_eq!(r.progress(), (4, 5));

    // Index 40 of 5: inside the 64 slots, outside the set.
    let stray = Frame {
        format: Format::Kspt,
        index: 40,
        total: 5,
        named: Some(Named::Tag(digest(&payload)[0])),
        fragment: &[9, 9, 9],
    };
    assert_eq!(
        r.push(&stray),
        Err(FrameError::BadIndex {
            index: 40,
            total: 5
        })
    );
    assert_eq!(r.progress(), (4, 5), "a refused frame is not counted");

    // A total of zero names no set at all.
    let empty = Frame {
        format: Format::Kspt,
        index: 0,
        total: 0,
        named: Some(Named::Digest(digest(&payload))),
        fragment: &[1],
    };
    assert!(matches!(
        r.push(&empty),
        Err(FrameError::BadIndex { .. } | FrameError::StreamChanged)
    ));

    // The real last frame completes it.
    let f = parse(&frames[4], P.max_frames).expect("parse");
    r.push(&f).expect("push");
    assert!(r.is_complete());
    let mut out = [0u8; 1000];
    assert_eq!(r.collect(&mut out).expect("collect"), 1000);
    assert_eq!(&out[..], &payload[..]);
}

/// A frame from another transmission is refused, not mixed in: two codes
/// are in view while a screen switches.
#[test]
fn a_frame_from_another_transmission_is_refused() {
    let a: Vec<u8> = (0..500).map(|i| i as u8).collect();
    let b_payload: Vec<u8> = (0..900).map(|i| (i * 3) as u8).collect();
    let fa = split(&a, 200);
    let fb = split(&b_payload, 200);
    assert_ne!(fa.len(), fb.len(), "the two must differ in frame count");

    let mut bufs = Bufs::new();
    let mut r = bufs.reassembler();
    r.push(&parse(&fa[0], P.max_frames).unwrap())
        .expect("first");
    let intruder = parse(&fb[0], P.max_frames).unwrap();
    assert_eq!(r.push(&intruder), Err(FrameError::StreamChanged));

    // After a reset the second transmission is taken.
    r.reset();
    for f in &fb {
        r.push(&parse(f, P.max_frames).unwrap())
            .expect("after reset");
    }
    assert!(r.is_complete());
}

/// Malformed frames are refused, each for its own reason.
#[test]
fn malformed_frames_are_refused() {
    assert_eq!(parse(&[MAGIC, 1], P.max_frames), Err(FrameError::TooShort));

    let k = Format::Kspt as u8;
    let d = [7, 7, 7, 7];
    // total = 0.
    assert_eq!(
        parse(&[MAGIC, k, 0, 0, d[0], d[1], d[2], d[3]], P.max_frames),
        Err(FrameError::BadIndex { index: 0, total: 0 })
    );
    // index not below total.
    assert_eq!(
        parse(&[MAGIC, k, 3, 3, d[0]], P.max_frames),
        Err(FrameError::BadIndex { index: 3, total: 3 })
    );
    // more frames than the profile allows.
    assert_eq!(
        parse(&[MAGIC, k, 0, 200, d[0], d[1], d[2], d[3]], P.max_frames),
        Err(FrameError::TooManyFrames {
            total: 200,
            limit: 64
        })
    );
    // a format byte nobody defines.
    assert_eq!(
        parse(&[MAGIC, 0x42, 0, 1, d[0], d[1], d[2], d[3]], P.max_frames),
        Err(FrameError::UnknownFormat(0x42))
    );
    // Frame 0 short of the whole digest: its header is eight bytes.
    assert_eq!(
        parse(&[MAGIC, k, 0, 2, d[0], d[1], d[2]], P.max_frames),
        Err(FrameError::TooShort)
    );
    // Any other frame's is five; one that is only a header carries nothing.
    assert_eq!(
        parse(&[MAGIC, k, 1, 2, d[0]], P.max_frames).map(|f| f.fragment.len()),
        Ok(0)
    );
}

/// Frames of the earlier five-byte header, its fifth byte the fragment's
/// length, are never collected: that byte reads as the tag and frame 0's
/// first bytes as the digest, so two lengths are two transmissions, and one
/// length completes as a set that is not the payload named.
#[test]
fn the_frames_before_the_digest_are_never_collected() {
    let old = |index: u8, total: u8, fragment: &[u8]| {
        let mut f = vec![
            MAGIC,
            Format::Kspt as u8,
            index,
            total,
            fragment.len() as u8,
        ];
        f.extend_from_slice(fragment);
        f
    };
    let payload: Vec<u8> = (0..252).map(|i| (i * 11) as u8).collect();
    let mut b = Bufs::new();
    let mut r = b.reassembler();

    // 231 bytes as 116 and 115, as the earlier split sent them.
    r.push(&parse(&old(0, 2, &payload[..116]), P.max_frames).unwrap())
        .expect("frame 0");
    assert_eq!(
        r.push(&parse(&old(1, 2, &payload[116..231]), P.max_frames).unwrap()),
        Err(FrameError::StreamChanged)
    );

    // 252 bytes as 126 and 126.
    r.reset();
    for (i, part) in payload.chunks(126).enumerate() {
        r.push(&parse(&old(i as u8, 2, part), P.max_frames).unwrap())
            .expect("push");
    }
    assert!(r.is_complete());
    assert_eq!(r.collect(&mut [0u8; 252]), Err(FrameError::DigestMismatch));

    // One frame.
    r.reset();
    r.push(&parse(&old(0, 1, &payload[..100]), P.max_frames).unwrap())
        .expect("push");
    assert!(r.is_complete());
    assert_eq!(r.collect(&mut [0u8; 100]), Err(FrameError::DigestMismatch));
}

/// A single-frame payload needs no special case.
#[test]
fn one_frame_is_not_a_special_case() {
    let payload = b"KSPT";
    let frames = split(payload, 200);
    assert_eq!(frames.len(), 1);

    let mut b = Bufs::new();
    let mut r = b.reassembler();
    r.push(&parse(&frames[0], P.max_frames).unwrap()).unwrap();
    assert!(r.is_complete());
    let mut out = [0u8; 8];
    let n = r.collect(&mut out).unwrap();
    assert_eq!(&out[..n], payload);
}

/// Frame counts follow the payload, frame 0 three bytes short, with no
/// off-by-one.
#[test]
fn frames_needed_is_exact_at_boundaries() {
    assert_eq!(frames_needed(0, 200), 0);
    assert_eq!(frames_needed(1, 200), 1);
    assert_eq!(frames_needed(197, 200), 1);
    assert_eq!(frames_needed(198, 200), 2);
    assert_eq!(frames_needed(397, 200), 2);
    assert_eq!(frames_needed(398, 200), 3);
    assert_eq!(payload_capacity(0, 200), 0);
    assert_eq!(payload_capacity(1, 200), 197);
    assert_eq!(payload_capacity(64, 225), 14_397);
}

/// What `frames_needed` plans, `write_split` fits: for every length up to
/// four frames at 225 bytes a frame (version 9) and 48 (version 3), each
/// frame fits and carries something, all codes but the last match, and
/// [`payload_capacity`] is the most the count holds.
#[test]
fn the_planned_frames_fit_their_codes() {
    for per in [225usize, 48] {
        for len in 1..=4 * per {
            let payload: Vec<u8> = (0..len).map(|i| (i * 13) as u8).collect();
            let total = frames_needed(len, per);
            assert!(len <= payload_capacity(total, per), "{len} in {total}");
            assert!(len > payload_capacity(total - 1, per), "{len} in fewer");
            let mut codes = Vec::new();
            let mut whole = Vec::new();
            for i in 0..total {
                let mut buf = vec![0u8; HEADER_LEN + per];
                let n = write_split(Format::Kspt, &payload, i as u8, total as u8, &mut buf)
                    .expect("the frame fits its code");
                let f = parse(&buf[..n], P.max_frames).expect("parse");
                assert!(!f.fragment.is_empty(), "{len}: frame {i} carries nothing");
                whole.extend_from_slice(f.fragment);
                codes.push(n);
            }
            assert_eq!(whole, payload, "{len} at {per}");
            let first = codes[0];
            assert!(
                codes[..total - 1].iter().all(|&c| c == first) && codes[total - 1] <= first,
                "{len} at {per}: {codes:?}"
            );
        }
    }
}

/// A fragment past 255 bytes is refused, whatever the slot: a reader
/// records the length in a byte, and the boards' slot is 256.
#[test]
fn a_fragment_past_a_byte_is_refused() {
    let mut buf = vec![0u8; 2 * 300];
    let mut seen = [false; 2];
    let mut sizes = [0u8; 2];
    let mut r = Reassembler::new(&mut buf, &mut seen, &mut sizes, 300);
    let long = [0x55u8; 256];
    let f = Frame {
        format: Format::Kspt,
        index: 1,
        total: 2,
        named: Some(Named::Tag(1)),
        fragment: &long,
    };
    assert_eq!(r.push(&f), Err(FrameError::TooLarge));
    assert_eq!(r.progress().0, 0, "nothing was stored");
    assert_eq!(
        write(Format::Kspt, 1, 2, [1; 4], &long, &mut [0u8; 300]),
        Err(FrameError::TooLarge),
        "nor written"
    );
}

/// A first frame refused for its size leaves no transmission behind, so
/// the next one, even an unnamed v1.0.7 set, is read.
#[test]
fn a_first_frame_refused_for_its_size_holds_nothing() {
    let mut b = Bufs::new();
    let mut r = b.reassembler();
    let long = [0x55u8; 201];
    let refused = Frame {
        format: Format::Kspt,
        index: 0,
        total: 3,
        named: None,
        fragment: &long,
    };
    assert_eq!(r.push(&refused), Err(FrameError::TooLarge));
    assert_eq!(r.progress(), (0, 0), "no transmission held");
    let short = [0x66u8; 50];
    let next = Frame {
        format: Format::Kspt,
        index: 0,
        total: 2,
        named: None,
        fragment: &short,
    };
    assert_eq!(r.push(&next), Ok(()), "the next transmission is read");
    assert_eq!(r.progress(), (1, 2));
}

/// An incomplete set yields no payload: collected early, a truncated
/// transaction could still parse.
#[test]
fn an_incomplete_set_yields_nothing() {
    let payload: Vec<u8> = (0..1000).map(|i| i as u8).collect();
    let frames = split(&payload, 200);

    let mut b = Bufs::new();
    let mut r = b.reassembler();
    for f in frames.iter().take(4) {
        r.push(&parse(f, P.max_frames).unwrap()).unwrap();
    }
    assert!(!r.is_complete());
    let mut out = vec![0u8; payload.len()];
    assert_eq!(r.collect(&mut out), Err(FrameError::TooShort));
}

/// A payload too large for the caller's buffer is refused before a byte is
/// copied.
#[test]
fn a_payload_too_large_to_collect_leaves_nothing() {
    let payload: Vec<u8> = (0..1000).map(|i| (i % 251) as u8 + 1).collect();
    let frames = split(&payload, 200);

    let mut b = Bufs::new();
    let mut r = b.reassembler();
    for f in &frames {
        r.push(&parse(f, P.max_frames).unwrap()).unwrap();
    }
    assert!(r.is_complete());
    let mut out = vec![0u8; payload.len() - 1];
    assert_eq!(r.collect(&mut out), Err(FrameError::TooLarge));
    assert!(out.iter().all(|&b| b == 0), "nothing of the payload");

    let mut out = vec![0u8; payload.len()];
    assert_eq!(
        r.collect(&mut out),
        Ok(payload.len()),
        "and it fits exactly"
    );
    assert_eq!(out, payload);
}

/// Round trip through `write` and `parse`.
#[test]
fn write_and_parse_round_trip() {
    let frag: Vec<u8> = (0..200).map(|i| (i * 5) as u8).collect();
    let named = [0xDE, 0xAD, 0xBE, 0xEF];
    let mut buf = [0u8; 256];
    let n = write(Format::Pskb, 7, 20, named, &frag, &mut buf).unwrap();
    assert_eq!(n, HEADER_LEN + frag.len());
    assert_eq!(buf[0], MAGIC);

    let f: Frame<'_> = parse(&buf[..n], P.max_frames).unwrap();
    assert_eq!(f.format, Format::Pskb);
    assert_eq!(f.index, 7);
    assert_eq!(f.total, 20);
    assert_eq!(f.named, Some(Named::Tag(0xDE)), "the digest's first byte");
    assert_eq!(f.fragment, &frag[..]);

    // Frame 0 carries the whole digest, three bytes more of header.
    let n = write(Format::Pskb, 0, 20, named, &frag, &mut buf).unwrap();
    assert_eq!(n, FIRST_HEADER_LEN + frag.len());
    let f = parse(&buf[..n], P.max_frames).unwrap();
    assert_eq!(f.index, 0);
    assert_eq!(f.named, Some(Named::Digest(named)));
    assert_eq!(f.fragment, &frag[..]);

    // write refuses what parse would refuse.
    assert_eq!(
        write(Format::Kspt, 5, 5, named, &frag, &mut buf),
        Err(FrameError::BadIndex { index: 5, total: 5 })
    );
}

/// `write_split` splits evenly and reassembles: 297 bytes in two frames go
/// as 147 and 150, both codes 155 bytes, not 222 and 75, a dense code and a
/// sparse one for a reader to refocus between.
#[test]
fn a_split_is_even_and_reassembles() {
    let payload: Vec<u8> = (0..297).map(|i| (i * 7) as u8).collect();
    let mut b = Bufs::new();
    let mut r = b.reassembler();
    let mut sizes = Vec::new();
    let mut codes = Vec::new();
    for i in 0..2 {
        let mut buf = [0u8; HEADER_LEN + 225];
        let n = write_split(Format::Kspt, &payload, i, 2, &mut buf).expect("write_split");
        let f = parse(&buf[..n], P.max_frames).expect("parse");
        assert_eq!((f.index, f.total), (i, 2));
        sizes.push(f.fragment.len());
        codes.push(n);
        r.push(&f).expect("push");
    }
    assert_eq!(sizes, [147, 150]);
    assert_eq!(codes, [155, 155]);
    let mut out = vec![0u8; payload.len()];
    let n = r.collect(&mut out).expect("collect");
    assert_eq!(&out[..n], &payload[..]);

    // Refused: an index past the set, an empty set or payload, a frame the
    // split leaves empty (13 bytes in 5 frames are 1, 4, 4, 4; 5 bytes in 4
    // leave frame 0 none).
    let mut buf = [0u8; 64];
    assert_eq!(
        write_split(Format::Kspt, &payload, 2, 2, &mut buf),
        Err(FrameError::BadIndex { index: 2, total: 2 })
    );
    assert_eq!(
        write_split(Format::Kspt, &payload, 0, 0, &mut buf),
        Err(FrameError::BadIndex { index: 0, total: 0 })
    );
    assert_eq!(
        write_split(Format::Kspt, &[], 0, 1, &mut buf),
        Err(FrameError::BadIndex { index: 0, total: 1 })
    );
    assert_eq!(
        write_split(Format::Kspt, &payload[..13], 4, 5, &mut buf),
        Err(FrameError::BadIndex { index: 4, total: 5 })
    );
    assert_eq!(
        write_split(Format::Kspt, &payload[..5], 0, 4, &mut buf),
        Err(FrameError::BadIndex { index: 0, total: 4 })
    );
}

/// Only the magic makes a frame: bare hex such as `"02ab..."` would read by
/// shape alone as frame 48 of 50.
#[test]
fn bare_text_is_not_mistaken_for_a_frame() {
    // A hex ciphertext, and other text a camera may catch.
    let hex_ciphertext = b"02ab3f9c11de4477a0b1c2d3e4f5061728394a5b6c7d8e9f00112233445566778899";
    assert_eq!(
        parse(hex_ciphertext, P.max_frames),
        Err(FrameError::NotAFrame)
    );

    for text in [
        &b"kpub2LmT7bF9xQeR4vN8sW1jK6hY3dC5gA0pZuXoI9tE2rM7nB4wS8fV1cH6yD3kJ"[..],
        &b"1AbCdEfGhIjKlMnOpQrStUvWxYz23456789"[..],
        &b"abandon abandon abandon abandon abandon about"[..],
        &b"KSPT\x01\x00some transaction bytes here"[..],
        &b"PSKB7b226964223a2231"[..],
    ] {
        assert_eq!(
            parse(text, P.max_frames),
            Err(FrameError::NotAFrame),
            "{text:?}"
        );
    }
}

/// The format is known from the first frame caught, whatever its index.
#[test]
fn the_format_is_known_before_frame_zero() {
    let payload: Vec<u8> = (0..900).map(|i| i as u8).collect();
    let frames = split_as(Format::Pskb, &payload, 200);

    let mut b = Bufs::new();
    let mut r = b.reassembler();
    assert_eq!(r.format(), None, "nothing known before the first frame");

    // Catch the last frame first.
    let last = parse(frames.last().unwrap(), P.max_frames).unwrap();
    r.push(&last).unwrap();
    assert_eq!(
        r.format(),
        Some(Format::Pskb),
        "the format arrived with the frame"
    );
    assert!(!r.is_complete());
}

/// Two transmissions of the same length but different formats are not
/// mixed: a KSPT and a PSKB of one transaction are close in size.
#[test]
fn a_different_format_at_the_same_length_is_refused() {
    let payload: Vec<u8> = (0..500).map(|i| i as u8).collect();
    let a = split_as(Format::Kspt, &payload, 200);
    let b_frames = split_as(Format::Pskb, &payload, 200);
    assert_eq!(a.len(), b_frames.len(), "the two must be the same length");

    let mut bufs = Bufs::new();
    let mut r = bufs.reassembler();
    r.push(&parse(&a[0], P.max_frames).unwrap()).expect("first");
    assert_eq!(
        r.push(&parse(&b_frames[0], P.max_frames).unwrap()),
        Err(FrameError::StreamChanged)
    );
}

/// Every defined format round-trips through write and parse.
#[test]
fn every_format_round_trips() {
    for f in [
        Format::Kspt,
        Format::Pskb,
        Format::Kpub,
        Format::Descriptor,
        Format::Container,
        Format::Opaque,
    ] {
        let mut out = [0u8; 32];
        let n = write(f, 0, 1, digest(b"body"), b"body", &mut out).unwrap();
        assert_eq!(parse(&out[..n], P.max_frames).unwrap().format, f);
    }
}

/// A reset wipes the fragments and their lengths: what a camera reads can
/// be a seed.
#[test]
fn a_reset_wipes_the_payload() {
    let payload: Vec<u8> = (0..600).map(|i| (i % 251) as u8 + 1).collect();
    let frames = split(&payload, 200);

    let mut b = Bufs::new();
    {
        let mut r = b.reassembler();
        for raw in &frames {
            let f = parse(raw, P.max_frames).expect("parse");
            r.push(&f).expect("push");
        }
        assert!(r.is_complete());
        let mut out = [0u8; 600];
        assert_eq!(r.collect(&mut out).expect("collect"), 600);
        assert_eq!(&out[..], &payload[..]);

        r.reset();
        assert_eq!(r.progress(), (0, 0));
        assert!(!r.is_complete());
        // Suspended, not dropped: the drop would wipe the buffers too, so
        // what is checked below is the reset's work alone.
        r.suspend();
    }

    // The payload has no zero bytes, so any survivor would show.
    assert!(
        b.buf.iter().all(|&x| x == 0),
        "the fragments are still in the buffer"
    );
    assert!(b.sizes.iter().all(|&x| x == 0), "and their lengths");

    // The buffers then serve another payload.
    let mut out2 = [0u8; 400];
    {
        let mut r = b.reassembler();
        let second: Vec<u8> = (0..400).map(|i| (i % 97) as u8 + 100).collect();
        for raw in &split(&second, 200) {
            let f = parse(raw, P.max_frames).expect("parse");
            r.push(&f).expect("push");
        }
        assert!(r.is_complete());
        assert_eq!(r.collect(&mut out2).expect("collect"), 400);
    }
}

/// A reassembler wipes the buffer when dropped, however the borrow ends.
#[test]
fn a_reassembler_wipes_itself_when_it_goes() {
    let payload: Vec<u8> = (0..600).map(|i| (i % 251) as u8 + 1).collect();
    let mut b = Bufs::new();
    let mut out = [0u8; 600];
    {
        let mut r = b.reassembler();
        for raw in &split(&payload, 200) {
            let f = parse(raw, P.max_frames).expect("parse");
            r.push(&f).expect("push");
        }
        assert_eq!(r.collect(&mut out).expect("collect"), 600);
        // No reset, no cancel: the borrow simply ends.
    }
    assert!(
        b.buf.iter().all(|&x| x == 0),
        "the fragments outlived the reassembler"
    );
    assert!(b.sizes.iter().all(|&x| x == 0), "and their lengths");
    // What the caller copied out is its own, and untouched.
    assert_eq!(&out[..], &payload[..]);
}

/// A reassembler suspended and resumed per frame, as a binding owning the
/// buffers uses it, works as one: the fragments stay, stream and digest
/// travel in the state, and another transmission's frame is refused.
#[test]
fn a_suspended_reassembler_resumes_over_its_buffers() {
    let payload: Vec<u8> = (0..1000).map(|i| (i * 7 + 3) as u8).collect();
    let frames = split(&payload, 200);
    let other = split(&(0..1000).map(|i| (i * 3) as u8).collect::<Vec<u8>>(), 200);
    let mut b = Bufs::new();
    let mut state = b.reassembler().suspend();
    assert!(b.buf.iter().all(|&x| x == 0));
    for (k, i) in [3usize, 4, 0, 1].into_iter().enumerate() {
        let mut r = Reassembler::resume(&mut b.buf, &mut b.seen, &mut b.sizes, state);
        r.push(&parse(&frames[i], P.max_frames).unwrap())
            .expect("push");
        assert_eq!(r.progress(), (k + 1, 5));
        assert_eq!(r.format(), Some(Format::Kspt));
        state = r.suspend();
        assert!(
            b.seen.iter().filter(|s| **s).count() == k + 1,
            "the seen bits stay"
        );
        assert!(b.buf.iter().any(|&x| x != 0), "the fragments stay");
    }
    {
        let mut r = Reassembler::resume(&mut b.buf, &mut b.seen, &mut b.sizes, state);
        assert_eq!(
            r.push(&parse(&other[2], P.max_frames).unwrap()),
            Err(FrameError::StreamChanged)
        );
        state = r.suspend();
    }
    let mut r = Reassembler::resume(&mut b.buf, &mut b.seen, &mut b.sizes, state);
    r.push(&parse(&frames[2], P.max_frames).unwrap())
        .expect("push");
    assert!(r.is_complete() && r.digest_matches());
    let mut out = vec![0u8; 1000];
    assert_eq!(r.collect(&mut out).unwrap(), 1000);
    assert_eq!(out, payload);
}

/// A state resumed over buffers it does not fit is cleared, as by a reset,
/// and the transmission scanned again completes.
#[test]
fn a_state_over_buffers_it_does_not_fit_starts_over() {
    let payload: Vec<u8> = (0..1000).map(|i| (i * 5 + 1) as u8).collect();
    let frames = split(&payload, 200);
    let mut b = Bufs::new();
    let state = {
        let mut r = b.reassembler();
        for f in &frames[..3] {
            r.push(&parse(f, P.max_frames).unwrap()).expect("push");
        }
        r.suspend()
    };
    let fresh = Bufs::new().reassembler().suspend();

    let check = |r: &mut Reassembler<'_>| {
        assert_eq!(r.progress(), (0, 0));
        assert!(!r.is_complete() && !r.digest_matches());
        assert_eq!(r.payload_len(), 0);
        assert_eq!(r.collect(&mut [0u8; 1000]), Err(FrameError::TooShort));
    };

    // Arrays shorter than the five frames the state expects.
    let (mut buf, mut seen, mut sizes) = (vec![1u8; 64 * 200], [true; 4], [200u8; 4]);
    check(&mut Reassembler::resume(
        &mut buf, &mut seen, &mut sizes, state,
    ));
    assert!(buf.iter().all(|&x| x == 0) && seen.iter().all(|s| !s));

    // A buffer that cannot hold the fragments the seen bits name.
    let (mut buf, mut seen, mut sizes) = (vec![1u8; 300], [true; 64], [200u8; 64]);
    check(&mut Reassembler::resume(
        &mut buf, &mut seen, &mut sizes, state,
    ));

    // A seen bit past the count, and one with no stream at all, each with
    // a length past its slot.
    for (st, i) in [(state, 9usize), (fresh, 0)] {
        let (mut buf, mut seen, mut sizes) = (vec![1u8; 64 * 200], [false; 64], [0u8; 64]);
        seen[i] = true;
        sizes[i] = 255;
        let mut r = Reassembler::resume(&mut buf, &mut seen, &mut sizes, st);
        check(&mut r);
        // Scanned again through the cleared buffers, it is the payload.
        for f in &frames {
            r.push(&parse(f, P.max_frames).unwrap()).expect("push");
        }
        let mut out = vec![0u8; 1000];
        assert_eq!(r.collect(&mut out), Ok(1000));
        assert_eq!(out, payload);
    }

    // The buffers it came from still resume it.
    let r = Reassembler::resume(&mut b.buf, &mut b.seen, &mut b.sizes, state);
    assert_eq!(r.progress(), (3, 5));
}

/// Two payloads of one format and length are two transmissions, the case
/// the digest is for: a screen switching to the transaction with another
/// amount must not yield frame 0 of one and frame 1 of the other.
#[test]
fn the_same_size_with_another_payload_is_another_transmission() {
    let a: Vec<u8> = (0..400).map(|i| (i * 7) as u8).collect();
    let mut b_payload = a.clone();
    b_payload[300] ^= 1; // an amount in the second frame
    let fa = split(&a, 200);
    let fb = split(&b_payload, 200);
    assert_eq!((fa.len(), fb.len()), (2, 2));
    // The first frames differ only in the digest they name.
    let named = HEADER_LEN - 1..FIRST_HEADER_LEN;
    assert_eq!(fa[0][..named.start], fb[0][..named.start]);
    assert_eq!(fa[0][named.end..], fb[0][named.end..]);
    assert_ne!(fa[0][named.clone()], fb[0][named]);

    let mut bufs = Bufs::new();
    let mut r = bufs.reassembler();
    r.push(&parse(&fa[0], P.max_frames).unwrap())
        .expect("first");
    assert_eq!(
        r.push(&parse(&fb[1], P.max_frames).unwrap()),
        Err(FrameError::StreamChanged),
        "the second's frame is not taken into the first"
    );
    assert!(!r.is_complete());
}

/// A switch whose tag matches by chance, one in 256, completes a set that
/// is neither payload and is not collected; a frame 0 naming another digest
/// is another transmission, even at an index already held.
#[test]
fn a_tag_matching_by_chance_is_caught() {
    let a: Vec<u8> = (0..400).map(|i| (i * 7) as u8).collect();
    // Another amount in the second frame, one whose digest shares A's tag.
    let other = (0u16..=u16::MAX)
        .find_map(|x| {
            let mut b = a.clone();
            b[300..302].copy_from_slice(&x.to_be_bytes());
            (b != a && digest(&b)[0] == digest(&a)[0]).then_some(b)
        })
        .expect("one in 256 shares it");
    assert_ne!(digest(&a), digest(&other));
    let fa = split(&a, 200);
    let fb = split(&other, 200);

    // A's frame 0 and B's frame 1: one tag, and a set that is neither.
    let mut bufs = Bufs::new();
    let mut r = bufs.reassembler();
    r.push(&parse(&fa[0], P.max_frames).unwrap())
        .expect("A's frame 0");
    r.push(&parse(&fb[1], P.max_frames).unwrap())
        .expect("B's frame 1, the same tag");
    assert!(r.is_complete());
    assert!(!r.digest_matches());
    assert_eq!(r.collect(&mut [0u8; 400]), Err(FrameError::DigestMismatch));

    // B's frame 0 after A's: another digest, though index 0 is held.
    assert_eq!(
        r.push(&parse(&fb[0], P.max_frames).unwrap()),
        Err(FrameError::StreamChanged)
    );
}

/// A set naming a tag and no digest, as a frame 0 built by hand can, is
/// never collected: with nothing to check it against, it is not trusted.
#[test]
fn a_set_with_no_digest_to_check_is_not_collected() {
    let payload = b"two halves";
    let tag = digest(payload)[0];
    let mut b = Bufs::new();
    let mut r = b.reassembler();
    for (i, part) in payload.chunks(5).enumerate() {
        r.push(&Frame {
            format: Format::Kspt,
            index: i as u8,
            total: 2,
            named: Some(Named::Tag(tag)),
            fragment: part,
        })
        .expect("push");
    }
    assert!(r.is_complete());
    assert!(!r.digest_matches());
    assert_eq!(r.collect(&mut [0u8; 10]), Err(FrameError::DigestMismatch));
}

/// A set whose fragments do not hash to frame 0's digest is never
/// collected.
#[test]
fn a_set_that_is_not_its_payload_is_not_collected() {
    let payload: Vec<u8> = (0..500).map(|i| (i * 3) as u8).collect();
    let frames = split_naming(Format::Kspt, &payload, 200, digest(b"another payload"));

    let mut b = Bufs::new();
    let mut r = b.reassembler();
    for raw in &frames {
        r.push(&parse(raw, P.max_frames).unwrap()).expect("push");
    }
    assert!(r.is_complete());
    assert!(!r.digest_matches());
    let mut out = vec![0u8; payload.len()];
    assert_eq!(r.collect(&mut out), Err(FrameError::DigestMismatch));
    assert!(out.iter().all(|&x| x == 0), "nothing was copied out");

    // The same frames naming their own payload's digest are collected.
    r.reset();
    for raw in &split(&payload, 200) {
        r.push(&parse(raw, P.max_frames).unwrap()).expect("push");
    }
    assert!(r.digest_matches());
    assert_eq!(r.collect(&mut out), Ok(payload.len()));
    assert_eq!(out, payload);
}

/// A frame held that comes back changed is a conflict, as a sender never
/// changes one: this is how two v1.0.7 transmissions of one frame count,
/// which name no digest, show they are mixing. The same frame again is a
/// repeat. Named frames are held to the same rule.
#[test]
fn a_frame_held_that_comes_back_changed_is_a_conflict() {
    let old = |index, fragment| Frame {
        format: Format::Kspt,
        index,
        total: 3,
        named: None,
        fragment,
    };
    let mut bufs = Bufs::new();
    let mut r = bufs.reassembler();
    r.push(&old(0, b"KSPT first")).expect("frame 0");
    r.push(&old(1, b"one's second")).expect("frame 1");
    r.push(&old(1, b"one's second")).expect("the same again");
    assert_eq!(r.progress(), (2, 3));
    assert_eq!(
        r.push(&old(1, b"two's second")),
        Err(FrameError::Conflict),
        "the other code's frame 1"
    );
    assert_eq!(
        r.push(&old(1, b"one's")),
        Err(FrameError::Conflict),
        "shorter"
    );
    assert_eq!(r.progress(), (2, 3), "nothing taken");
    r.push(&old(2, b"one's third")).expect("frame 2");
    let mut out = [0u8; 64];
    let n = r.collect(&mut out).expect("collect");
    assert_eq!(&out[..n], b"KSPT firstone's secondone's third");

    // Named frames: the same tag, another fragment.
    let a: Vec<u8> = (0..500).map(|i| i as u8).collect();
    let fa = split(&a, 200);
    let mut bufs = Bufs::new();
    let mut r = bufs.reassembler();
    let f1 = parse(&fa[1], P.max_frames).unwrap();
    r.push(&f1).expect("frame 1");
    let changed = Frame {
        fragment: &[0u8; 10],
        ..f1
    };
    assert_eq!(r.push(&changed), Err(FrameError::Conflict));
    r.push(&f1).expect("the same again");
}
