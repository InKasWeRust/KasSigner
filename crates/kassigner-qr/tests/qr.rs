// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! QR conformance.
//!
//! No module-by-module comparison with a reference encoder: two correct
//! encoders can choose different masks, and a mask flips every data module,
//! so that would measure mask agreement, not conformance. Compared instead:
//! the mask-independent parts, and whether an independent decoder reads
//! back what we encoded.

use kassigner_qr::{
    byte_capacity, encode, encode_at, encode_numeric, numeric_capacity, select_version,
    select_version_numeric, DecodeError, Decoder, QrError, QrMatrix, Scratch, MAX_SIDE,
    MAX_VERSION,
};

/// Does the decoder work at all, on a matrix we did not produce?
///
/// Named to sort first. If this fails, the decoder wrapper or the rasterizer
/// below is at fault; if it passes and a round trip fails, the encoder is.
#[test]
fn aa_decoder_reads_a_reference_matrix() {
    use qrcode::{EcLevel, QrCode, Version};

    let payload = b"kassigner-qr reference";
    let code = QrCode::with_version(payload, Version::Normal(2), EcLevel::L).expect("reference");
    let n = code.width();
    let colors = code.to_colors();

    let (w, h, mut pixels) = rasterize_fn(n, 6, 6, |x, y| colors[y * n + x] == qrcode::Color::Dark);

    let mut out = [0u8; 256];
    let mut scratch = Scratch::new();
    let mut dec = Decoder::new(&mut scratch);
    let got = dec
        .decode(w, h, 8, &mut pixels, &mut out)
        .unwrap_or_else(|e| panic!("decoder failed on a REFERENCE matrix: {e:?}"));
    assert_eq!(&out[..got.len], payload);
}

/// Our matrix decodes back to the bytes we put in, read by an independent
/// implementation: the encoder's conformance test.
#[test]
fn encoder_output_decodes_to_the_same_bytes() {
    for payload in [
        &b"kaspa:qr0"[..],
        &b"KSPT\x03\x00"[..],
        &[0xFFu8; 40][..],
        &[0x00u8; 17][..],
        &b"0123456789012345678901234567890123456789012345678901234567890123456789"[..],
    ] {
        let qr = encode(payload).expect("encode");
        let (w, h, mut pixels) = rasterize(&qr, 6, 6);

        let mut out = [0u8; 512];
        let mut scratch = Scratch::new();
        let mut dec = Decoder::new(&mut scratch);
        let got = dec
            .decode(w, h, 8, &mut pixels, &mut out)
            .unwrap_or_else(|e| {
                panic!("our matrix did not decode: {e:?}, {} bytes", payload.len())
            });

        assert_eq!(&out[..got.len], payload, "round trip changed the payload");
        assert_eq!(got.grids, 1, "expected exactly one grid");
    }
}

/// A code drawn at a version larger than its data needs reads back the
/// same, at every version from the smallest that holds the data to 9, each
/// at its version's side. Data a version cannot hold, and a version outside
/// 1 to 9, are refused.
#[test]
fn a_code_at_a_given_version_decodes_to_the_same_bytes() {
    for payload in [&b"kaspa:qr0"[..], &[0x5Au8; 117][..], &[0xA5u8; 230][..]] {
        let smallest = select_version(payload.len()).unwrap();
        for v in smallest..=MAX_VERSION {
            let qr = encode_at(payload, v).expect("encode");
            assert_eq!(qr.size, 17 + 4 * v, "version {v}");
            let (w, h, mut pixels) = rasterize(&qr, 6, 6);
            let mut out = [0u8; 512];
            let mut scratch = Scratch::new();
            let got = Decoder::new(&mut scratch)
                .decode(w, h, 8, &mut pixels, &mut out)
                .unwrap_or_else(|e| panic!("version {v} did not decode: {e:?}"));
            assert_eq!(&out[..got.len], payload, "version {v}");
        }
        assert_eq!(encode(payload).unwrap().size, 17 + 4 * smallest);
        if smallest > 1 {
            assert_eq!(
                encode_at(payload, smallest - 1).err(),
                Some(QrError::DataTooLong),
                "one version short"
            );
        }
    }
    for v in [0, MAX_VERSION + 1] {
        assert_eq!(encode_at(b"x", v).err(), Some(QrError::DataTooLong), "{v}");
    }
}

/// Numeric mode, likewise by round trip, at lengths that leave each
/// remainder: three digits pack into ten bits, one or two left over into a
/// shorter tail.
#[test]
fn numeric_encoder_output_decodes_to_the_same_digits() {
    for len in [1usize, 2, 3, 4, 5, 41, 76, 77] {
        let digits: Vec<u8> = (0..len).map(|i| b'0' + (i % 10) as u8).collect();
        let qr = encode_numeric(&digits).expect("encode");
        let (w, h, mut pixels) = rasterize(&qr, 6, 6);

        let mut out = [0u8; 256];
        let mut scratch = Scratch::new();
        let mut dec = Decoder::new(&mut scratch);
        let got = dec
            .decode(w, h, 8, &mut pixels, &mut out)
            .unwrap_or_else(|e| panic!("{len} digits did not decode: {e:?}"));
        assert_eq!(&out[..got.len], &digits[..], "{len} digits changed");
    }
}

/// Numeric mode refuses a byte that is not a digit, just below '0' and just
/// above '9' among them.
#[test]
fn numeric_mode_refuses_what_is_not_a_digit() {
    // Compares the error rather than the Result: QrMatrix derives nothing.
    for digits in [&b"12/4"[..], b"12:4", b" 1", b"9a"] {
        assert_eq!(
            encode_numeric(digits).err(),
            Some(QrError::NotNumeric),
            "{digits:?}"
        );
    }
}

/// The mask-independent structure matches a reference encoder: size, the
/// three finder patterns and the timing patterns, which agree whatever mask
/// either encoder chose.
#[test]
fn function_patterns_match_a_reference_implementation() {
    use qrcode::{EcLevel, QrCode, Version};

    for v in 1..=MAX_VERSION {
        let cap = byte_capacity(v).expect("in range");
        let data: Vec<u8> = (0..cap).map(|i| (i * 31 + 7) as u8).collect();

        let ours = encode(&data).expect("we encode");
        let theirs = QrCode::with_version(&data, Version::Normal(v as i16), EcLevel::L)
            .expect("reference encodes");
        let n = theirs.width();
        let colors = theirs.to_colors();
        assert_eq!(ours.size as usize, n, "size, version {v}");

        let ref_dark = |x: usize, y: usize| colors[y * n + x] == qrcode::Color::Dark;

        // The three finder patterns, 7 by 7 at each corner but the fourth.
        for &(ox, oy) in &[(0usize, 0usize), (n - 7, 0), (0, n - 7)] {
            for dy in 0..7 {
                for dx in 0..7 {
                    assert_eq!(
                        ours.get((ox + dx) as u8, (oy + dy) as u8),
                        ref_dark(ox + dx, oy + dy),
                        "version {v}, finder at ({ox},{oy}), module ({dx},{dy})"
                    );
                }
            }
        }

        // Timing patterns: row 6 and column 6, between the finders.
        for i in 8..n - 8 {
            assert_eq!(
                ours.get(i as u8, 6),
                ref_dark(i, 6),
                "version {v}, timing row at {i}"
            );
            assert_eq!(
                ours.get(6, i as u8),
                ref_dark(6, i),
                "version {v}, timing col at {i}"
            );
        }
    }
}

/// An empty frame reports nothing found rather than something wrong.
#[test]
fn a_blank_frame_is_not_found() {
    let mut pixels = vec![0xFFu8; 128 * 128];
    let mut out = [0u8; 64];
    let mut scratch = Scratch::new();
    let mut dec = Decoder::new(&mut scratch);
    assert_eq!(
        dec.decode(128, 128, 8, &mut pixels, &mut out),
        Err(DecodeError::NotFound)
    );
}

/// A payload larger than the caller's buffer is reported, not truncated: a
/// truncated one could show part of a transaction as the whole.
#[test]
fn an_oversized_payload_is_refused_not_truncated() {
    let payload = [0x41u8; 60];
    let qr = encode(&payload).expect("encode");
    let (w, h, mut pixels) = rasterize(&qr, 6, 6);

    let mut small = [0u8; 16];
    let mut scratch = Scratch::new();
    let mut dec = Decoder::new(&mut scratch);
    assert_eq!(
        dec.decode(w, h, 8, &mut pixels, &mut small),
        Err(DecodeError::BufferTooSmall)
    );
}

/// A decode leaves its scratch wiped, however it ends: for a SeedQR the
/// corrected bytes are the seed, and a board keeps its scratch as long as it
/// runs. Four endings through one scratch: a clean read; a mirrored one,
/// where the first attempt fails and the second reads it; a payload too long
/// for the buffer; and a code damaged past correction.
#[test]
fn a_decode_leaves_its_scratch_wiped() {
    let payload = b"0148111120480003091510291234";
    let qr = encode(payload).expect("encode");
    let n = qr.size as usize;

    let mut scratch = Scratch::new();
    let mut read = |(w, h, mut pixels): (usize, usize, Vec<u8>), out: &mut [u8]| {
        let mut dec = Decoder::new(&mut scratch);
        let got = dec.decode(w, h, 8, &mut pixels, out);
        (got, scratch.is_clear())
    };
    let mut out = [0u8; 64];

    let (got, clear) = read(rasterize(&qr, 6, 6), &mut out);
    assert_eq!(&out[..got.expect("a clean code decodes").len], payload);
    assert!(clear, "scratch left dirty by a clean read");

    let mirrored = rasterize_fn(n, 6, 6, |x, y| qr.get(y as u8, x as u8));
    let (got, clear) = read(mirrored, &mut out);
    assert_eq!(&out[..got.expect("a mirrored code decodes").len], payload);
    assert!(clear, "scratch left dirty by a mirrored read");

    let (got, clear) = read(rasterize(&qr, 6, 6), &mut [0u8; 4]);
    assert_eq!(got, Err(DecodeError::BufferTooSmall));
    assert!(clear, "scratch left dirty by an overflow");

    // A band of rows inverted, clear of the finders, the format bits and the
    // timing column: the code is found and read, and does not correct.
    let band = 9..n - 9;
    let damaged = rasterize_fn(n, 6, 6, |x, y| {
        qr.get(x as u8, y as u8) ^ (band.contains(&y) && x != 6)
    });
    let (got, clear) = read(damaged, &mut out);
    assert_eq!(got, Err(DecodeError::Unreadable));
    assert!(clear, "scratch left dirty by a failed correction");
}

/// A decode that fails part-way leaves nothing in the buffer. A numeric
/// segment, as in a SeedQR, then FNC1's mode indicator, which the vendored
/// decoder does not read: it writes the digits, fails, and they are wiped.
/// With a good code below in the same frame, the good one is read and
/// nothing of the bad one stays past its length.
#[test]
fn a_failed_decode_leaves_nothing_in_the_buffer() {
    use qrcode::bits::Bits;
    use qrcode::{Color, EcLevel, QrCode, Version};

    let digits = b"0148111120480003091510291234";
    let mut bits = Bits::new(Version::Normal(2));
    bits.push_numeric_data(digits).unwrap();
    bits.push_fnc1_first_position().unwrap();
    bits.push_terminator(EcLevel::L).unwrap();
    let bad = QrCode::with_bits(bits, EcLevel::L).unwrap();
    let good = QrCode::with_version(b"42", Version::Normal(1), EcLevel::L).unwrap();

    // Codes stacked in one frame, top to bottom, 4 pixels a module, each
    // with a quiet zone of 4 modules.
    let frame = |codes: &[&QrCode]| {
        let (scale, quiet) = (4, 4);
        let side = codes.iter().map(|c| c.width()).max().unwrap() + 2 * quiet;
        let (w, h) = (side * scale, side * scale * codes.len());
        let mut px = vec![0xFFu8; w * h];
        for (i, code) in codes.iter().enumerate() {
            let (n, colors) = (code.width(), code.to_colors());
            for y in 0..n {
                for x in 0..n {
                    if colors[y * n + x] == Color::Dark {
                        for dy in 0..scale {
                            let row = (i * side + quiet + y) * scale + dy;
                            let at = row * w + (quiet + x) * scale;
                            px[at..at + scale].fill(0);
                        }
                    }
                }
            }
        }
        (w, h, px)
    };

    let mut scratch = Scratch::new();
    let (w, h, mut pixels) = frame(&[&bad]);
    let mut out = [0u8; 64];
    let mut dec = Decoder::new(&mut scratch);
    assert_eq!(
        dec.decode(w, h, 8, &mut pixels, &mut out),
        Err(DecodeError::Unreadable)
    );
    assert_eq!(out, [0u8; 64], "the digits read before the failure");

    let (w, h, mut pixels) = frame(&[&bad, &good]);
    let got = dec
        .decode(w, h, 8, &mut pixels, &mut out)
        .expect("the good code is read");
    assert_eq!(got.grids, 2, "both codes found");
    assert_eq!(&out[..got.len], b"42");
    assert_eq!(&out[got.len..], &[0u8; 62][..], "the bad code's tail");
}

/// Capacity limits agree between the tables and the encoder.
#[test]
fn capacity_tables_agree_with_the_encoder() {
    for v in 1..=MAX_VERSION {
        let cap = byte_capacity(v).unwrap();
        assert_eq!(select_version(cap), Some(v), "byte capacity at version {v}");
        let num = numeric_capacity(v).unwrap();
        assert_eq!(
            select_version_numeric(num),
            Some(v),
            "numeric at version {v}"
        );
    }

    let biggest = byte_capacity(MAX_VERSION).unwrap();
    assert_eq!(select_version(biggest + 1), None);
    // Compares the error rather than the Result: QrMatrix derives nothing.
    assert_eq!(
        encode(&vec![0u8; biggest + 1]).err(),
        Some(QrError::DataTooLong)
    );
}

/// A code reads at every module width from two pixels up: every version,
/// drawn at every side from two to six pixels a module, each module as wide
/// as its share of the side rounds to, as a panel draws it and a camera
/// samples it, so some modules are a pixel wider than the rest.
///
/// At some sides a finder pattern's centre gets the wide modules and its
/// four one-module runs the narrow (2, 2, 8, 2, 2 at 2.4 pixels a module),
/// past the finder check's 1:1:3:1:1 tolerance on every row. [`finders_pass`]
/// finds those sides, which are skipped and must all be under 2.5 pixels a
/// module.
#[test]
fn a_code_reads_at_every_module_width() {
    let mut scratch = Scratch::new();
    let (mut missed, mut skipped) = (Vec::new(), Vec::new());
    for version in 1..=MAX_VERSION {
        let len = byte_capacity(version).unwrap();
        // The version's full byte capacity, so `encode` picks this version.
        let data: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
        let qr = encode(&data).unwrap();
        let n = usize::from(qr.size);
        assert_eq!(n, 17 + 4 * usize::from(version));
        for side in 2 * n..=6 * n {
            let per = side as f64 / n as f64;
            if !finders_pass(n, side) {
                skipped.push(format!("v{version} {side} px ({per:.2} a module)"));
                assert!(
                    per < 2.5,
                    "v{version} {side} px: finders refused at {per:.2} a module"
                );
                continue;
            }
            // Four modules of white, and the code's modules spread over
            // `side` pixels as the panel spreads them.
            let quiet = (4 * side).div_ceil(n);
            let w = side + 2 * quiet;
            let mut px = vec![0xFFu8; w * w];
            for y in 0..side {
                for x in 0..side {
                    if qr.get((x * n / side) as u8, (y * n / side) as u8) {
                        px[(y + quiet) * w + x + quiet] = 0;
                    }
                }
            }
            let mut d = Decoder::new(&mut scratch);
            let mut out = [0u8; 256];
            match d.decode(w, w, 8, &mut px, &mut out) {
                Ok(got) if out[..got.len] == data[..] => {}
                other => missed.push(format!(
                    "v{version} {side} px ({per:.2} a module): {other:?}"
                )),
            }
        }
    }
    assert!(
        missed.is_empty(),
        "{} missed, {} skipped as past the finder check:\n{}",
        missed.len(),
        skipped.len(),
        missed.join("\n")
    );
}

/// Whether the decoder's finder check (`rqrr`'s `detect.rs`) passes the
/// top-left and top-right finder patterns of a code drawn `side` pixels
/// across: each run within three quarters of a module of its expected width,
/// a module being the mean of the four one-module runs. The bottom-left
/// pattern's runs across are the top-left's.
fn finders_pass(n: usize, side: usize) -> bool {
    let mut widths = vec![0usize; n];
    for x in 0..side {
        widths[x * n / side] += 1;
    }
    [0, n - 7].iter().all(|&first| {
        let m = &widths[first..first + 7];
        let runs = [m[0], m[1], m[2] + m[3] + m[4], m[5], m[6]];
        let sum = runs[0] + runs[1] + runs[3] + runs[4];
        runs.iter()
            .zip([1, 1, 3, 1, 1])
            .all(|(&run, check)| (16 * run).abs_diff(4 * check * sum) <= 3 * sum)
    })
}

/// Render a matrix into a grayscale frame as a camera would see it:
/// `scale` pixels per module, `quiet` modules of white border.
fn rasterize(qr: &QrMatrix, scale: usize, quiet: usize) -> (usize, usize, Vec<u8>) {
    rasterize_fn(qr.size as usize, scale, quiet, |x, y| {
        qr.get(x as u8, y as u8)
    })
}

fn rasterize_fn<F: Fn(usize, usize) -> bool>(
    n: usize,
    scale: usize,
    quiet: usize,
    dark: F,
) -> (usize, usize, Vec<u8>) {
    let side = (n + quiet * 2) * scale;
    let mut px = vec![0xFFu8; side * side];
    for y in 0..n {
        for x in 0..n {
            if dark(x, y) {
                for dy in 0..scale {
                    for dx in 0..scale {
                        px[((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx] = 0x00;
                    }
                }
            }
        }
    }
    (side, side, px)
}

/// A matrix wipes its modules. Its `Drop` runs its `zeroize`, which is what
/// is checked: reading a dropped matrix would take `unsafe` and read a value
/// Rust calls gone. A copy spilled elsewhere is outside any test (see the
/// crate header).
#[test]
fn a_matrix_wipes_itself() {
    use zeroize::Zeroize;
    let payload = b"0148111120480003091510291234";
    let mut qr = encode(payload).expect("encode");
    let mut dark = 0usize;
    for y in 0..qr.size {
        for x in 0..qr.size {
            if qr.get(x, y) {
                dark += 1;
            }
        }
    }
    assert!(dark > 0, "a code has dark modules before it is wiped");

    qr.zeroize();
    let mut after = 0usize;
    for y in 0..qr.size {
        for x in 0..qr.size {
            if qr.get(x, y) {
                after += 1;
            }
        }
    }
    assert_eq!(after, 0, "every module is cleared");
}

/// Two decoders at once, in two scratches, share nothing: four threads
/// decode side by side, two hundred times between them, every read right
/// and every scratch left wiped.
#[test]
fn two_decoders_at_once_share_nothing() {
    let payloads: Vec<Vec<u8>> = (0..4u8)
        .map(|t| format!("kassigner-qr thread {t}, side by side").into_bytes())
        .collect();
    std::thread::scope(|threads| {
        for payload in &payloads {
            threads.spawn(move || {
                let qr = encode(payload).expect("encode");
                let mut scratch = Box::new(Scratch::new());
                for _ in 0..50 {
                    let (w, h, mut pixels) = rasterize(&qr, 4, 4);
                    let mut out = [0u8; 128];
                    let got = Decoder::new(&mut scratch)
                        .decode(w, h, 8, &mut pixels, &mut out)
                        .expect("decodes beside the others");
                    assert_eq!(&out[..got.len], &payload[..]);
                    assert!(scratch.is_clear(), "left wiped");
                }
            });
        }
    });
}

/// A frame of impossible sides is refused, not a panic: zero, past
/// `MAX_SIDE`, or more pixels than the buffer holds.
#[test]
fn a_frame_of_impossible_sides_is_refused() {
    let mut scratch = Scratch::new();
    let mut d = Decoder::new(&mut scratch);
    let mut pixels = vec![255u8; 64 * 64];
    let mut out = [0u8; 64];
    for (w, h) in [
        (0, 64),
        (64, 0),
        (65, 64),
        (64, 65),
        (MAX_SIDE + 1, 1),
        (1, MAX_SIDE + 1),
    ] {
        assert_eq!(
            d.decode(w, h, 8, &mut pixels, &mut out).err(),
            Some(DecodeError::BadFrame),
            "{w} by {h}"
        );
    }
    assert_eq!(
        d.decode(64, 64, 8, &mut pixels, &mut out).err(),
        Some(DecodeError::NotFound),
        "the frame itself is fine"
    );
}

/// Outside the matrix is light: a column past the right edge is not the
/// next row's first module.
#[test]
fn outside_the_matrix_is_light() {
    let m = encode(b"KasSigner").expect("encode");
    let s = m.size;
    // The top-left finder's corner is dark; past each edge is not.
    assert!(m.get(0, 0));
    assert!(m.get(0, 1), "the finder's left column");
    assert!(
        !m.get(s, 0),
        "past the right edge, not row 1's first module"
    );
    assert!(!m.get(0, s));
    assert!(!m.get(u8::MAX, u8::MAX));
}

// ── Any picture ─────────────────────────────────────────────────────────────

#[path = "../../../testkit/mutate.rs"]
mod mutate;

/// A square frame of as many pixels as `data` fills, through the decoder,
/// fuzzed (`testkit/mutate.rs`): it returns on any picture and leaves its
/// scratch zeroed, however it ends.
fn pictures(data: &[u8]) {
    let side = data.len().isqrt();
    let mut pixels = data[..side * side].to_vec();
    let mut out = [0u8; 4096];
    let mut scratch = Scratch::new();
    let _ = Decoder::new(&mut scratch).decode(side, side, 8, &mut pixels, &mut out);
    assert!(scratch.is_clear(), "a decode that left its scratch written");
}

/// Codes of several versions and modes, drawn two pixels a module, and a
/// blank frame.
#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_camera_frame_any_pixels() {
    let mut seeds: Vec<Vec<u8>> = [
        &b"kaspa:qr0"[..],
        &b"KSPT\x03\x00\x01\x02"[..],
        &[0x1B; 60][..],
        &[0x5A; 100][..],
    ]
    .iter()
    .map(|payload| rasterize(&encode(payload).unwrap(), 2, 4).2)
    .collect();
    seeds.push(
        rasterize(
            &encode_numeric(b"0123456789012345678901234567890123456789").unwrap(),
            2,
            4,
        )
        .2,
    );
    seeds.push(vec![0xFF; 60 * 60]);
    mutate::run("camera frame", 300, seeds, pictures);
}
