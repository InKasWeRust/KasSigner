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

//! Reassembling a transmission without a camera: [`Scan::offer`] decides by
//! bytes alone.
//!
//! The refusals matter most: halves of two transactions reassemble into
//! neither, which a person would then be asked to sign.

use kassigner_fw::scan::{Scan, Step};
use kassigner_protocol::frame::{digest, write, Format};

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::unhex;

/// One transmission, as frames.
fn frames(format: Format, payload: &[u8], per_frame: usize) -> Vec<Vec<u8>> {
    frames_naming(format, payload, per_frame, digest(payload))
}

/// As [`frames`], every frame naming `named` as the payload's digest.
fn frames_naming(format: Format, payload: &[u8], per_frame: usize, named: [u8; 4]) -> Vec<Vec<u8>> {
    let total = payload.len().div_ceil(per_frame);
    (0..total)
        .map(|i| {
            let start = i * per_frame;
            let end = (start + per_frame).min(payload.len());
            let mut out = vec![0u8; per_frame + 16];
            let n = write(
                format,
                i as u8,
                total as u8,
                named,
                &payload[start..end],
                &mut out,
            )
            .expect("write frame");
            out.truncate(n);
            out
        })
        .collect()
}

fn scan_buffers(slots: usize, slot: usize) -> (Vec<u8>, Vec<bool>, Vec<u8>) {
    (
        vec![0u8; slots * slot],
        vec![false; slots],
        vec![0u8; slots],
    )
}

/// A whole transmission reassembles to what went in.
#[test]
fn a_transmission_reassembles() {
    let payload: Vec<u8> = (0..300).map(|i| (i * 7 % 251) as u8).collect();
    let fs = frames(Format::Kspt, &payload, 64);
    assert!(fs.len() > 1, "this needs more than one frame to be a test");

    let (mut buf, mut seen, mut sizes) = scan_buffers(16, 64);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 64);

    for (i, f) in fs.iter().enumerate() {
        let step = scan.offer(f).expect("offer");
        if i + 1 == fs.len() {
            assert!(matches!(
                step,
                Step::Complete {
                    format: Format::Kspt,
                    ..
                }
            ));
        } else {
            assert!(matches!(step, Step::Accepted { .. }), "frame {i}: {step:?}");
        }
    }

    assert!(scan.is_complete());
    assert_eq!(scan.payload_len(), payload.len());

    let mut out = vec![0u8; scan.payload_len()];
    let n = scan.collect(&mut out).expect("collect");
    assert_eq!(&out[..n], &payload[..]);
}

/// Frames arriving in any order, some twice, as from a camera waved at a
/// cycling display, reassemble the same.
#[test]
fn order_does_not_matter() {
    let payload: Vec<u8> = (0..200).map(|i| i as u8).collect();
    let fs = frames(Format::Pskb, &payload, 40);

    let (mut buf, mut seen, mut sizes) = scan_buffers(16, 40);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 40);

    // Backwards, with a repeat in the middle.
    let mut order: Vec<usize> = (0..fs.len()).rev().collect();
    order.insert(2, order[1]);

    for i in order {
        scan.offer(&fs[i]).expect("offer");
    }

    assert!(scan.is_complete());
    let mut out = vec![0u8; scan.payload_len()];
    scan.collect(&mut out).expect("collect");
    assert_eq!(out, payload);
}

/// A code not ours is recognised, not misread as a frame: the `0x1B` header
/// byte begins no text payload, where a shape test can read a hex string as
/// frame 48 of 50.
#[test]
fn a_code_that_is_not_ours_is_rejected() {
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 64);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 64);

    for other in [
        &b"https://example.com/pay?amount=1"[..],
        &b"WIFI:S:somenetwork;T:WPA;P:hunter2;;"[..],
        // Hex that a heuristic reads as a frame header.
        &b"02ab7f3c9e10445566778899aabbccddeeff00112233445566778899aabbccdd"[..],
        &b""[..],
        &[0x20u8, 0x01, 0x00, 0x02, 0x04][..],
    ] {
        assert_eq!(
            scan.offer(other).expect("offer"),
            Step::NotOurs,
            "{other:?}"
        );
    }

    assert_eq!(
        scan.progress(),
        (0, 0),
        "and none of it started a transmission"
    );
}

/// A frame of another transmission starts it and is never mixed in: the sending
/// screen changed, and halves of two transactions reassemble into neither.
#[test]
fn a_frame_from_another_transmission_starts_it() {
    let a: Vec<u8> = (0..120).map(|i| i as u8).collect();
    let b: Vec<u8> = (0..200).map(|i| (255 - i) as u8).collect();

    let fa = frames(Format::Kspt, &a, 40);
    let fb = frames(Format::Kspt, &b, 40);
    assert_ne!(fa.len(), fb.len());

    let (mut buf, mut seen, mut sizes) = scan_buffers(16, 40);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 40);

    scan.offer(&fa[0]).expect("first");
    assert_eq!(scan.progress(), (1, fa.len()));

    // A frame from the other transmission: it starts over, with it.
    assert!(matches!(
        scan.offer(&fb[1]).expect("offer"),
        Step::Accepted { have: 1, .. }
    ));
    assert_eq!(scan.progress(), (1, fb.len()));

    // A different format starts over too.
    let fc = frames(Format::Descriptor, &a, 40);
    assert!(matches!(
        scan.offer(&fc[0]).expect("offer"),
        Step::Accepted { have: 1, .. }
    ));
    assert_eq!(scan.format(), Some(Format::Descriptor));

    // And what completes is the last transmission whole.
    let mut last = Step::NoCode;
    for f in &fb {
        last = scan.offer(f).expect("offer");
    }
    assert!(matches!(last, Step::Complete { .. }), "{last:?}");
    let mut out = vec![0u8; scan.payload_len()];
    scan.collect(&mut out).expect("collect");
    assert_eq!(out, b);
}

/// Two transactions of the same size are never joined: one frame from each, the
/// same transaction rebuilt with another amount, would complete a set of one's
/// inputs and the other's outputs. The second's frame starts it over.
#[test]
fn two_transactions_of_the_same_size_are_never_joined() {
    let a: Vec<u8> = (0..120).map(|i| (i * 7) as u8).collect();
    let mut b = a.clone();
    b[100] ^= 1; // an amount, in the last frame
    let fa = frames(Format::Kspt, &a, 60);
    let fb = frames(Format::Kspt, &b, 60);
    assert_eq!((fa.len(), fb.len()), (2, 2));

    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 60);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 60);
    scan.offer(&fa[0]).expect("first's frame 0");
    assert!(
        matches!(
            scan.offer(&fb[1]).expect("second's frame 1"),
            Step::Accepted { have: 1, .. }
        ),
        "not a completed set"
    );
    let last = scan.offer(&fb[0]).expect("second's frame 0");
    assert!(matches!(last, Step::Complete { .. }), "{last:?}");
    let mut out = vec![0u8; scan.payload_len()];
    scan.collect(&mut out).expect("collect");
    assert_eq!(out, b, "the second, whole");
}

/// **A switch whose tag matches by chance is dropped when its set completes:**
/// one switch in 256 shares the digest's first byte and joins the set; frame
/// 0's whole digest then refuses the set and the scan starts over. A frame 0
/// naming another digest starts over at once.
#[test]
fn a_switch_whose_tag_matches_is_dropped_when_it_completes() {
    let a: Vec<u8> = (0..120).map(|i| (i * 7) as u8).collect();
    let b = (0u16..=u16::MAX)
        .find_map(|x| {
            let mut b = a.clone();
            b[100..102].copy_from_slice(&x.to_be_bytes());
            (b != a && digest(&b)[0] == digest(&a)[0]).then_some(b)
        })
        .expect("one in 256 shares it");
    let fa = frames(Format::Kspt, &a, 60);
    let fb = frames(Format::Kspt, &b, 60);

    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 60);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 60);
    scan.offer(&fa[0]).expect("first's frame 0");
    assert_eq!(
        scan.offer(&fb[1]).expect("second's frame 1"),
        Step::Mismatched
    );
    assert_eq!(scan.progress(), (0, 0), "nothing kept");
    let mut last = Step::NoCode;
    for f in &fb {
        last = scan.offer(f).expect("offer");
    }
    assert!(matches!(last, Step::Complete { .. }), "{last:?}");
    let mut out = vec![0u8; scan.payload_len()];
    scan.collect(&mut out).expect("collect");
    assert_eq!(out, b, "the second, whole");

    // Frame 0 of the first while the second's is held: started at once.
    scan.reset();
    scan.offer(&fb[0]).expect("second's frame 0");
    assert!(matches!(
        scan.offer(&fa[0]).expect("first's frame 0"),
        Step::Accepted { have: 1, .. }
    ));
    let last = scan.offer(&fa[1]).expect("first's frame 1");
    assert!(matches!(last, Step::Complete { .. }), "{last:?}");
}

/// **A set that is not the payload it named is dropped whole**, whether its
/// frames are two transmissions' or damaged, and the scan goes on.
#[test]
fn a_set_that_is_not_its_payload_is_dropped() {
    let payload: Vec<u8> = (0..120).map(|i| (i * 5) as u8).collect();
    let bad = frames_naming(Format::Kspt, &payload, 40, digest(b"something else"));

    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 40);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 40);
    let mut last = Step::NoCode;
    for f in &bad {
        last = scan.offer(f).expect("offer");
    }
    assert_eq!(last, Step::Mismatched);
    assert_eq!(scan.progress(), (0, 0), "nothing kept");
    assert!(!scan.is_complete());

    // The same payload's own frames still read.
    for f in &frames(Format::Kspt, &payload, 40) {
        last = scan.offer(f).expect("offer");
    }
    assert!(matches!(last, Step::Complete { .. }), "{last:?}");
}

/// A repeated frame is reported as one, and changes nothing.
#[test]
fn a_repeat_is_a_repeat() {
    let payload: Vec<u8> = (0..120).map(|i| i as u8).collect();
    let fs = frames(Format::Kspt, &payload, 40);

    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 40);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 40);

    assert!(matches!(
        scan.offer(&fs[0]).unwrap(),
        Step::Accepted { have: 1, .. }
    ));
    assert_eq!(scan.offer(&fs[0]).unwrap(), Step::Duplicate);
    assert_eq!(scan.progress().0, 1);
}

/// A reset throws away a partial transmission, as when the camera moves to
/// another screen, so the next one reads.
#[test]
fn a_reset_starts_over() {
    let a: Vec<u8> = (0..120).map(|i| i as u8).collect();
    let b: Vec<u8> = (0..200).map(|i| (255 - i) as u8).collect();
    let fa = frames(Format::Kspt, &a, 40);
    let fb = frames(Format::Kspt, &b, 40);

    let (mut buf, mut seen, mut sizes) = scan_buffers(16, 40);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 40);

    scan.offer(&fa[0]).expect("first");
    assert_eq!(scan.progress().0, 1);

    scan.reset();
    assert_eq!(scan.progress(), (0, 0));
    assert!(scan.format().is_none());

    // The other transmission is accepted: nothing is left to disagree with.
    for f in &fb {
        scan.offer(f).expect("offer");
    }
    assert!(scan.is_complete());
    let mut out = vec![0u8; scan.payload_len()];
    scan.collect(&mut out).expect("collect");
    assert_eq!(out, b);
}

/// Collecting into a short buffer says how much is needed, not only that it
/// is too small.
#[test]
fn a_short_collect_buffer_reports_the_size() {
    let payload: Vec<u8> = (0..120).map(|i| i as u8).collect();
    let fs = frames(Format::Kspt, &payload, 40);

    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 40);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 40);
    for f in &fs {
        scan.offer(f).expect("offer");
    }

    let mut small = vec![0u8; 10];
    match scan.collect(&mut small) {
        Err(kassigner_fw::scan::Error::TooLarge { needed }) => {
            assert_eq!(needed, payload.len())
        }
        other => panic!("{other:?}"),
    }
}

/// Progress, what a person watches while scanning, is known from the first
/// frame; before it, zero of zero.
#[test]
fn progress_is_visible_throughout() {
    let payload: Vec<u8> = (0..250).map(|i| i as u8).collect();
    let fs = frames(Format::Kspt, &payload, 50);

    let (mut buf, mut seen, mut sizes) = scan_buffers(16, 50);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 50);

    assert_eq!(scan.progress(), (0, 0), "nothing is known yet");
    assert!(scan.format().is_none());

    for (i, f) in fs.iter().enumerate() {
        scan.offer(f).expect("offer");
        let (have, need) = scan.progress();
        assert_eq!(have, i + 1);
        assert_eq!(need, fs.len(), "the total is known from the first frame");
    }
    assert_eq!(scan.format(), Some(Format::Kspt));
}

/// A transmission too large for this device says so, not `NotOurs`, which would
/// look like a wifi code: a sender's frame limit is its own, so this happens
/// with nothing wrong.
#[test]
fn a_transmission_larger_than_this_device_is_named() {
    // Four slots, against a sender splitting into ten.
    let (mut buf, mut seen, mut sizes) = scan_buffers(4, 64);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 64);

    let payload: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
    let fs = frames(Format::Kspt, &payload, 64);
    assert_eq!(fs.len(), 10, "ten frames against four slots");

    assert_eq!(
        scan.offer(&fs[0]).expect("offer"),
        Step::TooLong {
            total: 10,
            limit: 4
        },
        "ours, and too big, which is not the same as not ours"
    );
    assert_eq!(scan.progress(), (0, 0), "and it started nothing");

    // A foreign code still reads as foreign.
    assert_eq!(
        scan.offer(b"https://example.com").expect("offer"),
        Step::NotOurs
    );

    // And a transmission that does fit still works on the same scan.
    let short: Vec<u8> = (0..120).map(|i| (i % 97) as u8).collect();
    let fits = frames(Format::Kspt, &short, 64);
    assert!(fits.len() <= 4);
    let mut last = Step::NoCode;
    for f in &fits {
        last = scan.offer(f).expect("offer");
    }
    assert!(matches!(last, Step::Complete { .. }), "{last:?}");
}

/// A compact SeedQR is never taken for a frame header: its 16 or 32 random
/// bytes read as an over-long v1.0.7 header about once in 550, or an
/// over-long `0x1B` header once in 23,000, and a seed refused as too long
/// could not be loaded. A `0x1B` frame of another length naming too many is
/// still too long.
#[test]
fn a_compact_seedqr_is_not_a_frame_header() {
    let (mut buf, mut seen, mut sizes) = scan_buffers(64, 64);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 64);

    // v1.0.7's shape: index below total, total over 64, the length byte
    // exactly what follows it.
    let mut old_12 = [0x5Au8; 16];
    old_12[..3].copy_from_slice(&[0x10, 0xC8, 13]);
    let mut old_24 = [0xA5u8; 32];
    old_24[..3].copy_from_slice(&[0x10, 0xC8, 29]);
    // The `0x1B` framing's: the magic, a format, index below total, total
    // over 64.
    let mut new_12 = [0x33u8; 16];
    new_12[..4].copy_from_slice(&[0x1B, Format::Kspt as u8, 0, 200]);
    let mut new_24 = [0x33u8; 32];
    new_24[..4].copy_from_slice(&[0x1B, Format::Opaque as u8, 3, 100]);
    for code in [&old_12[..], &old_24, &new_12, &new_24] {
        assert_eq!(
            scan.offer(code).expect("offer"),
            Step::NotOurs,
            "{code:02x?}"
        );
    }
    assert_eq!(scan.progress(), (0, 0), "and it started nothing");

    let mut other = [0x33u8; 40];
    other[..4].copy_from_slice(&[0x1B, Format::Kspt as u8, 0, 200]);
    assert_eq!(
        scan.offer(&other).expect("offer"),
        Step::TooLong {
            total: 200,
            limit: 64
        }
    );
}

// ── What v1.0.7 read ────────────────────────────────────────────────────────

/// A request split the way a v1.0.7 companion splits it: `index`, `total`,
/// `frag_len`, then the fragment, with nothing to mark it as a frame.
fn legacy_frames(payload: &[u8], per_frame: usize) -> Vec<Vec<u8>> {
    let total = payload.len().div_ceil(per_frame);
    (0..total)
        .map(|i| {
            let fragment = &payload[i * per_frame..((i + 1) * per_frame).min(payload.len())];
            let mut out = vec![i as u8, total as u8, fragment.len() as u8];
            out.extend_from_slice(fragment);
            out
        })
        .collect()
}

/// A KSPT-shaped payload: the tag, then bytes.
fn tagged(tag: &[u8; 4], len: usize) -> Vec<u8> {
    let mut p = tag.to_vec();
    p.extend((0..len - 4).map(|i| (i * 13 % 251) as u8));
    p
}

/// **An old-framed request reassembles, once its frame zero has named it.**
#[test]
fn an_old_framed_request_reassembles() {
    let payload = tagged(b"KSPT", 700);
    let fs = legacy_frames(&payload, 230);
    assert!(fs.len() > 2);
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 230);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 230);

    // A later frame before frame zero: nothing says what it belongs to, so
    // it is dropped and the scan waits.
    assert_eq!(
        scan.offer(&fs[1]).expect("offer"),
        Step::BeforeFrameZero {
            index: 1,
            total: fs.len() as u8
        }
    );
    assert_eq!(scan.progress(), (0, 0));

    // Frame zero, then the rest in any order.
    assert!(matches!(
        scan.offer(&fs[0]).expect("frame zero"),
        Step::Accepted { .. }
    ));
    let mut last = Step::NoCode;
    for f in fs[1..].iter().rev() {
        last = scan.offer(f).expect("offer");
    }
    assert_eq!(
        last,
        Step::Complete {
            format: kassigner_protocol::frame::Format::Kspt,
            len: payload.len()
        }
    );
    let mut out = vec![0u8; payload.len()];
    let n = scan.collect(&mut out).expect("collect");
    assert_eq!(&out[..n], &payload[..]);
}

/// Old frames shown in a cycle are read from wherever the camera comes in: a
/// frame before frame zero is dropped, not `NotOurs`, on which the flow ends
/// the scan, and taken next time round.
#[test]
fn old_frames_in_a_cycle_are_read_from_wherever_it_is() {
    let payload = tagged(b"PSKB", 1100);
    let fs = legacy_frames(&payload, 230);
    let n = fs.len();
    assert_eq!(n, 5);
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 230);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 230);

    // The camera comes in at frame 2 and the sender goes round twice.
    let mut steps = Vec::new();
    for k in 0..2 * n {
        let step = scan.offer(&fs[(2 + k) % n]).expect("offer");
        steps.push(step);
        if matches!(step, Step::Complete { .. }) {
            break;
        }
    }
    assert_eq!(
        &steps[..3],
        &[2u8, 3, 4].map(|index| Step::BeforeFrameZero {
            index,
            total: n as u8
        }),
        "the frames before frame zero, dropped"
    );
    assert!(!steps.contains(&Step::NotOurs), "and none ended the scan");
    assert_eq!(
        steps.last(),
        Some(&Step::Complete {
            format: kassigner_protocol::frame::Format::Pskb,
            len: payload.len()
        }),
        "complete the next time round"
    );
    let mut out = vec![0u8; payload.len()];
    let got = scan.collect(&mut out).expect("collect");
    assert_eq!(&out[..got], &payload[..]);

    // A seed's length is still a seed's, whatever its bytes say: a code of
    // 16 bytes shaped as frame 3 of 6 goes to the flow.
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 230);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 230);
    let mut seed = vec![3u8, 6, 13];
    seed.extend_from_slice(&[0x5A; 13]);
    assert_eq!(scan.offer(&seed).expect("offer"), Step::NotOurs);
}

/// Two v1.0.7 codes in view are never joined once a frame comes round: their
/// frames name nothing, so the other code's frame enters the set, but the first
/// frame number that comes round again, changed, shows the mix and the set is
/// dropped. A mix that completes first is left to the parser and the review.
#[test]
fn two_old_codes_in_view_are_never_joined() {
    let a = tagged(b"KSPT", 700);
    let mut b = b"KSPT".to_vec();
    b.extend((0..696).map(|i| (i * 17 % 253) as u8));
    let (fa, fb) = (legacy_frames(&a, 230), legacy_frames(&b, 230));
    assert_eq!((fa.len(), fb.len()), (4, 4), "the same frame count");
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 230);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 230);

    // One's frames 0 and 1, then the other's frame 1.
    assert!(matches!(
        scan.offer(&fa[0]).expect("offer"),
        Step::Accepted { .. }
    ));
    assert!(matches!(
        scan.offer(&fa[1]).expect("offer"),
        Step::Accepted { .. }
    ));
    assert_eq!(scan.offer(&fb[1]).expect("offer"), Step::Mismatched);
    assert_eq!(scan.progress(), (0, 0), "nothing kept");

    // The other left in view, from its frame 2: read whole.
    let mut last = Step::NoCode;
    for k in 0..8 {
        last = scan.offer(&fb[(2 + k) % 4]).expect("offer");
        if matches!(last, Step::Complete { .. }) {
            break;
        }
    }
    assert!(matches!(last, Step::Complete { .. }), "{last:?}");
    let mut out = vec![0u8; b.len()];
    let n = scan.collect(&mut out).expect("collect");
    assert_eq!(&out[..n], &b[..]);

    // Frame 0 of each, in turn: dropped at the second.
    scan.reset();
    scan.offer(&fa[0]).expect("offer");
    assert_eq!(scan.offer(&fb[0]).expect("offer"), Step::Mismatched);

    // The same frame again is a repeat.
    scan.offer(&fa[0]).expect("offer");
    assert_eq!(scan.offer(&fa[0]).expect("offer"), Step::Duplicate);

    // What cannot be told: one frame 0, the other's frames 1 to 3, none
    // seen twice. A set of neither, left to the parser and the review.
    scan.reset();
    for f in [&fa[0], &fb[1], &fb[2]] {
        scan.offer(f).expect("offer");
    }
    assert!(matches!(
        scan.offer(&fb[3]).expect("offer"),
        Step::Complete { .. }
    ));
    let mut out = vec![0u8; a.len()];
    let n = scan.collect(&mut out).expect("collect");
    assert!(out[..n] != a[..] && out[..n] != b[..]);
}

/// **A request that fits one code arrives bare, and is the payload.**
#[test]
fn a_bare_request_is_whole() {
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 64);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 64);
    for tag in [b"KSPT", b"PSKB"] {
        assert_eq!(scan.offer(&tagged(tag, 180)).expect("offer"), Step::Whole);
    }
    assert_eq!(scan.progress(), (0, 0), "and nothing was assembled");
}

/// **An old frame zero must carry a request's tag.**
///
/// Without it, three bytes that happen to agree with the length would start
/// a transmission that never completes: the failure the `0x1B` magic ended.
#[test]
fn an_old_frame_zero_without_a_tag_is_not_ours() {
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 64);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 64);
    let fs = legacy_frames(&tagged(b"XXXX", 100), 50);
    assert_eq!(scan.offer(&fs[0]).expect("offer"), Step::NotOurs);
    assert_eq!(scan.progress(), (0, 0));
}

/// **The two framings never mix.**
///
/// Same format and the same total is exactly the case a total check alone
/// would let through.
#[test]
fn old_and_new_frames_do_not_mix() {
    let payload = tagged(b"KSPT", 150);
    let old = legacy_frames(&payload, 50);
    let new = frames(kassigner_protocol::frame::Format::Kspt, &payload, 50);
    assert_eq!(old.len(), new.len());

    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 64);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 64);
    assert!(matches!(
        scan.offer(&old[0]).expect("old"),
        Step::Accepted { .. }
    ));
    assert_eq!(scan.offer(&new[1]).expect("new"), Step::WrongTransmission);

    scan.reset();
    assert!(matches!(
        scan.offer(&new[0]).expect("new"),
        Step::Accepted { .. }
    ));
    assert_eq!(scan.offer(&old[1]).expect("old"), Step::WrongTransmission);
}

/// A kpub's raw form as a v1.0.7 unit sent it: the marker, then a real
/// kpub's 78-byte body (rusty-kaspa's first cosigner kpub).
fn kpub_raw() -> Vec<u8> {
    use kassigner_kaspa::base58::{decode_check, decoded_max};
    let text = "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
    let mut raw = [0u8; decoded_max(111)];
    let n = decode_check(text.as_bytes(), &mut raw).unwrap();
    let mut out = vec![0x01];
    out.extend_from_slice(&raw[..n]);
    out
}

/// A kpub in v1.0.7's two frames reassembles to its raw form: frame zero names
/// it by the marker and a kpub's version, as a request's names it by its tag.
/// The marker without a kpub's version is not ours.
#[test]
fn a_kpub_in_old_frames_reassembles() {
    use kassigner_protocol::frame::Format;
    let payload = kpub_raw();
    assert_eq!(payload.len(), 79);
    let fs = legacy_frames(&payload, 40);
    assert_eq!(
        (fs.len(), fs[0].len(), fs[1].len()),
        (2, 43, 42),
        "v1.0.7's two codes"
    );
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 64);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 64);
    assert!(matches!(
        scan.offer(&fs[0]).expect("frame zero"),
        Step::Accepted { .. }
    ));
    assert_eq!(
        scan.offer(&fs[1]).expect("frame one"),
        Step::Complete {
            format: Format::Kpub,
            len: 79
        }
    );
    let mut out = vec![0u8; 79];
    let n = scan.collect(&mut out).expect("collect");
    assert_eq!(&out[..n], &payload[..]);
    assert!(kassigner_fw::kpub::read(&out[..n]).is_some(), "a kpub");

    let mut wrong = payload.clone();
    wrong[1] ^= 0xFF;
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 64);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 64);
    assert_eq!(
        scan.offer(&legacy_frames(&wrong, 40)[0]).expect("offer"),
        Step::NotOurs
    );
}

/// A kpub in `0x1B` frames reassembles to the same raw form.
#[test]
fn a_kpub_in_new_frames_reassembles() {
    use kassigner_protocol::frame::Format;
    let payload = kpub_raw();
    let fs = frames(Format::Kpub, &payload, 40);
    assert_eq!(fs.len(), 2);
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 64);
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 64);
    scan.offer(&fs[1]).expect("frame one first");
    assert_eq!(
        scan.offer(&fs[0]).expect("frame zero"),
        Step::Complete {
            format: Format::Kpub,
            len: 79
        }
    );
    let mut out = vec![0u8; 79];
    let n = scan.collect(&mut out).expect("collect");
    assert_eq!(&out[..n], &payload[..]);
}

/// Which codes go on to more frames, in both framings: the camera loop asks
/// before offering, and one frame of several keeps it reading where a lone code
/// ends the scan.
#[test]
fn a_frame_of_several_goes_on_in_either_framing() {
    let (mut buf, mut seen, mut sizes) = scan_buffers(8, 230);
    let scan = Scan::new(&mut buf, &mut seen, &mut sizes, 230);
    let payload = tagged(b"KSPT", 700);

    for f in frames(Format::Kspt, &payload, 230) {
        assert!(scan.of_several(&f), "a frame of a new set");
    }
    for f in legacy_frames(&payload, 230) {
        assert!(
            scan.of_several(&f),
            "a frame of an old set, frame zero or not"
        );
    }

    let lone = frames(Format::Kspt, &tagged(b"KSPT", 100), 230);
    assert_eq!(lone.len(), 1);
    assert!(!scan.of_several(&lone[0]), "a set of one");
    assert!(!scan.of_several(&tagged(b"PSKB", 180)), "a bare request");
    assert!(!scan.of_several(b"https://example.com"), "not ours");
    assert!(!scan.of_several(&[0x11; 16]), "a compact seed");

    let too_many = frames(Format::Kspt, &tagged(b"KSPT", 9 * 50), 50);
    assert!(!scan.of_several(&too_many[0]), "more than this scan holds");
    let old_too_many = legacy_frames(&tagged(b"KSPT", 9 * 50), 50);
    assert!(
        !scan.of_several(&old_too_many[0]),
        "more old frames than it holds"
    );
}

// ── The v1.0.7 corpus ─────────────────────────────────────────────────────
//
// The codes kassigner.org 1.0.7 and a v1.0.7 unit show, as their generators
// drew them (`spec/vectors/v107`; its `MANIFEST.md` says how): one code in hex
// a line, in display order. Each set is read by a scan the units' size, 64
// frames of 256 bytes.

/// A corpus file, built into the test.
macro_rules! corpus {
    ($path:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/v107/",
            $path
        ))
    };
}

/// A set of codes as the corpus keeps it.
fn codes(text: &[u8]) -> Vec<Vec<u8>> {
    core::str::from_utf8(text)
        .expect("text")
        .lines()
        .map(unhex)
        .collect()
}

/// A scan the size the units build: `CAPACITY.bytes_per_frame` and the
/// profile's `max_frames`.
fn unit_scan() -> (Vec<u8>, Vec<bool>, Vec<u8>) {
    scan_buffers(64, 256)
}

/// Read a set the way a camera meets it, coming in at frame `from` of a
/// sender going round: what the scan said last, and what it assembled.
fn read_from(set: &[Vec<u8>], from: usize) -> (Step, Vec<u8>) {
    let (mut buf, mut seen, mut sizes) = unit_scan();
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 256);
    let n = set.len();
    let mut last = Step::NoCode;
    for k in 0..2 * n {
        last = scan.offer(&set[(from + k) % n]).expect("offer");
        if matches!(last, Step::Complete { .. } | Step::Whole | Step::NotOurs) {
            break;
        }
    }
    let mut out = vec![0u8; 64 * 256];
    let got = match last {
        Step::Complete { .. } => scan.collect(&mut out).expect("collect"),
        _ => 0,
    };
    out.truncate(got);
    (last, out)
}

/// A set read from every frame a camera can come in at is `payload`, as
/// one code bare or as frames reassembled.
fn reads_as(name: &str, set: &[Vec<u8>], payload: &[u8], format: Format) {
    if set.len() == 1 {
        let (step, _) = read_from(set, 0);
        assert_eq!(step, Step::Whole, "{name}: one bare code");
        assert_eq!(set[0], payload, "{name}: and it is the payload");
        return;
    }
    for from in 0..set.len() {
        let (step, got) = read_from(set, from);
        assert_eq!(
            step,
            Step::Complete {
                format,
                len: payload.len()
            },
            "{name}: from frame {from} of {}",
            set.len()
        );
        assert!(got == payload, "{name}: from frame {from}, the payload");
    }
}

/// A kassigner.org 1.0.7 request: its name, its codes, its payload and what it
/// is.
macro_rules! request {
    ($name:literal, $format:expr) => {
        (
            $name,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../spec/vectors/v107/site/",
                $name,
                ".frames"
            )) as &[u8],
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../spec/vectors/v107/site/",
                $name,
                ".bin"
            )) as &[u8],
            $format,
        )
    };
}

/// A v1.0.7 unit's reply at one density: `fast`, 227 bytes a frame (its phone
/// and kassigner.org choice, and KasSigner's Fast), or `safe`, 40 (KasSigner's
/// Safe). The KasSigner choice is offered only for a multisig reply or a
/// transaction loaded back from the card.
macro_rules! reply {
    ($name:literal, $density:literal, $format:expr) => {
        (
            concat!($name, " at ", $density),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../spec/vectors/v107/device/",
                $name,
                ".",
                $density,
                ".frames"
            )) as &[u8],
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../spec/vectors/v107/device/",
                $name,
                ".bin"
            )) as &[u8],
            $format,
        )
    };
}

/// **Every request kassigner.org 1.0.7 shows is read,** bare or in frames, and
/// from wherever its cycle is when the camera comes in.
#[test]
fn every_kassigner_org_request_of_1_0_7_is_read() {
    let sets = [
        request!("kspt_send_1in", Format::Kspt),
        request!("kspt_send_3in", Format::Kspt),
        request!("kspt_compound", Format::Kspt),
        request!("kspt_consolidate", Format::Kspt),
        request!("kspt_multisig", Format::Kspt),
        request!("kspt2_relay_send", Format::Kspt),
        request!("kspt2_relay_multisig", Format::Kspt),
        request!("kspt2_relay_multisig_3in", Format::Kspt),
        request!("kspt2_relay_covenant", Format::Kspt),
        request!("pskb_send", Format::Pskb),
        request!("pskb_send_utxos", Format::Pskb),
        request!("pskb_compound", Format::Pskb),
        request!("pskb_multisig", Format::Pskb),
        request!("pskb_multisig_3in", Format::Pskb),
        request!("pskb_covenant_genesis", Format::Pskb),
    ];
    for (name, frames, payload, format) in sets {
        reads_as(name, &codes(frames), payload, format);
    }
}

/// **Every reply a v1.0.7 unit shows is read,** at each density it offers and
/// from wherever its cycle is: what a cosigner on this version scans from one
/// on that. Single-signature replies' Safe sets are those loaded back from the
/// card; a bundle, needing more than 64 frames at Safe, has none.
///
/// At Safe a set's last frame can take two shapes nothing else here does:
///
/// - Padded: a fragment under 20 bytes is zero-padded to 20, its length byte
///   unchanged; the 2-of-3's reply signed by both, 1,179 bytes in 30 frames,
///   ends on one of 19.
/// - A seed's length: a 29-byte fragment makes a 32-byte frame, a 24-word
///   compact SeedQR's length; `kspt_consolidate`'s reply from the card, 561
///   bytes in 15 frames, ends on one.
#[test]
fn every_reply_a_1_0_7_unit_shows_is_read() {
    let sets = [
        reply!("kspt_send_1in.reply", "fast", Format::Kspt),
        reply!("kspt_send_1in.reply", "safe", Format::Kspt),
        reply!("kspt_send_3in.reply", "fast", Format::Kspt),
        reply!("kspt_send_3in.reply", "safe", Format::Kspt),
        reply!("kspt_consolidate.reply", "fast", Format::Kspt),
        reply!("kspt_consolidate.reply", "safe", Format::Kspt),
        reply!("kspt2_relay_multisig.reply", "fast", Format::Kspt),
        reply!("kspt2_relay_multisig.reply", "safe", Format::Kspt),
        reply!("kspt2_relay_multisig.reply.abandon24", "fast", Format::Kspt),
        reply!("kspt2_relay_multisig.reply.abandon24", "safe", Format::Kspt),
        reply!("kspt2_relay_multisig_3in.reply", "fast", Format::Kspt),
        reply!("kspt2_relay_multisig_3in.reply", "safe", Format::Kspt),
        reply!(
            "kspt2_relay_multisig_3in.reply.abandon24",
            "fast",
            Format::Kspt
        ),
        reply!(
            "kspt2_relay_multisig_3in.reply.abandon24",
            "safe",
            Format::Kspt
        ),
        reply!("pskb_send.reply", "fast", Format::Pskb),
        reply!("pskb_send_utxos.reply", "fast", Format::Pskb),
        reply!("pskb_compound.reply", "fast", Format::Pskb),
        reply!("pskb_covenant_genesis.reply", "fast", Format::Pskb),
        reply!("pskb_multisig.reply", "fast", Format::Pskb),
        reply!("pskb_multisig.reply.abandon24", "fast", Format::Pskb),
    ];
    for (name, frames, payload, format) in sets {
        reads_as(name, &codes(frames), payload, format);
    }
}

/// **A kpub a v1.0.7 unit shows is read** in both its forms, as the same key:
/// one code, its text, handed to the flow as a code that is not a frame; and
/// two frames, the raw form, reassembled.
#[test]
fn a_kpub_a_1_0_7_unit_shows_is_read() {
    let sets: [(&[u8], &[u8], &str); 2] = [
        (
            corpus!("device/abandon12.kpub44.one.frames"),
            corpus!("device/abandon12.kpub44.two.frames"),
            "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8",
        ),
        (
            corpus!("device/abandon12.kpub45.one.frames"),
            corpus!("device/abandon12.kpub45.two.frames"),
            "kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14",
        ),
    ];
    for (one, two, text) in sets {
        let key = kassigner_fw::kpub::read(text.as_bytes()).expect("the kpub");

        let one = codes(one);
        assert_eq!(one.len(), 1);
        assert_eq!(read_from(&one, 0).0, Step::NotOurs, "the text is no frame");
        assert_eq!(one[0], text.as_bytes(), "and is the kpub's text");
        assert_eq!(kassigner_fw::kpub::read(&one[0]), Some(key));

        let two = codes(two);
        assert_eq!(two.len(), 2);
        for from in 0..2 {
            let (step, raw) = read_from(&two, from);
            assert_eq!(
                step,
                Step::Complete {
                    format: Format::Kpub,
                    len: kassigner_fw::kpub::RAW_LEN
                },
                "from frame {from}"
            );
            assert_eq!(
                kassigner_fw::kpub::read(&raw),
                Some(key),
                "from frame {from}"
            );
        }
    }
}

/// **A SeedQR v1.0.7 shows goes to the flow untouched,** standard or
/// compact: no frame in either.
#[test]
fn a_seedqr_of_1_0_7_is_no_frame() {
    let seeds: [&[u8]; 6] = [
        corpus!("seedqr/abandon12.standard"),
        corpus!("seedqr/abandon12.compact"),
        corpus!("seedqr/abandon24.standard"),
        corpus!("seedqr/abandon24.compact"),
        corpus!("seedqr/zoo12.standard"),
        corpus!("seedqr/zoo12.compact"),
    ];
    for seed in seeds {
        let (mut buf, mut seen, mut sizes) = unit_scan();
        let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 256);
        assert_eq!(scan.offer(seed).expect("offer"), Step::NotOurs);
        assert_eq!(scan.progress(), (0, 0));
        assert!(!scan.of_several(seed));
    }
}

/// The held last frame is named, and taken once its set begins:
/// `kspt_consolidate`'s Safe reply ends on a 32-byte frame, held and named
/// before frame zero so the flow can tell a seed that never loads. A compact
/// SeedQR of that shape is held the same way; of any other shape, it goes to
/// the flow.
#[test]
fn a_last_frame_of_a_seeds_length_is_held_and_named() {
    let set = codes(corpus!("device/kspt_consolidate.reply.safe.frames"));
    let last = set.last().expect("a set");
    assert_eq!((last.len(), last[0], last[1]), (32, 14, 15));

    let (mut buf, mut seen, mut sizes) = unit_scan();
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 256);
    assert_eq!(
        scan.offer(last).expect("offer"),
        Step::LastFrameOrSeed { total: 15 }
    );
    assert_eq!(scan.progress(), (0, 0), "held, not stored");
    assert!(matches!(
        scan.offer(&set[0]).expect("frame zero"),
        Step::Accepted { .. }
    ));
    assert!(matches!(
        scan.offer(last).expect("again"),
        Step::Accepted { .. }
    ));

    let mut seed = [0x5Au8; 32];
    seed[..3].copy_from_slice(&[6, 7, 29]);
    let (mut buf, mut seen, mut sizes) = unit_scan();
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 256);
    assert_eq!(
        scan.offer(&seed).expect("offer"),
        Step::LastFrameOrSeed { total: 7 }
    );
    seed[0] = 5;
    assert_eq!(scan.offer(&seed).expect("offer"), Step::NotOurs);
}

// ── Any codes ───────────────────────────────────────────────────────────────

#[path = "../../../testkit/mutate.rs"]
mod mutate;

/// Codes as the camera hands them over, each a length byte and that many bytes,
/// through a unit's scan under the mutation loop in `testkit/mutate.rs`: it must
/// return on any codes, and collect whatever it says is complete.
fn any_codes(data: &[u8]) {
    let (mut buf, mut seen, mut sizes) = unit_scan();
    let mut scan = Scan::new(&mut buf, &mut seen, &mut sizes, 256);
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let n = usize::from(len).min(tail.len());
        let code = &tail[..n];
        let _ = scan.of_several(code);
        if scan.offer(code).is_ok() {
            let _ = scan.progress();
            let _ = scan.received();
            if scan.is_complete() {
                let mut out = vec![0u8; scan.payload_len()];
                scan.collect(&mut out).expect("a complete scan collects");
                scan.reset();
            }
        }
        rest = &tail[n..];
    }
}

/// Codes one after another, as [`any_codes`] reads them.
fn as_codes(codes: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in codes {
        out.push(c.len() as u8);
        out.extend_from_slice(c);
    }
    out
}

/// This version's frames and v1.0.7's, a SeedQR's digits among them, and
/// v1.0.7's recorded codes.
#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn any_codes_scan() {
    let mut seeds = Vec::new();
    for len in [10, 300, 900] {
        let payload = tagged(b"KSPT", len);
        seeds.push(as_codes(&frames(Format::Kspt, &payload, 200)));
        seeds.push(as_codes(&frames(Format::Opaque, &payload, 64)));
        seeds.push(as_codes(&legacy_frames(&payload, 230)));
    }
    seeds.push(as_codes(&[
        b"0123456789012345678901234567890123456789".to_vec()
    ]));
    for set in [
        &corpus!("site/kspt_send_1in.frames")[..],
        corpus!("site/pskb_multisig.frames"),
        corpus!("device/kspt_send_3in.reply.fast.frames"),
        corpus!("device/abandon12.kpub45.two.frames"),
    ] {
        seeds.push(as_codes(&codes(set)));
    }
    mutate::run("scan", 3000, seeds, any_codes);
}
