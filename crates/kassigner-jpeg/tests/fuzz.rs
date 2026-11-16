// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A photo from a card, fuzzed (`testkit/mutate.rs`): segments, EXIF and scan
//! read without a panic or a hang, and a rewrite reads back the same
//! coefficients (not bytes: a damaged scan can re-encode differently).

#[path = "../../../testkit/mutate.rs"]
mod mutate;

use kassigner_jpeg::exif::Tiff;
use kassigner_jpeg::scan::{self, Tables, Visit, BLOCK};
use kassigner_jpeg::segment;

/// The most blocks a frame may declare: the steganography carrier's.
const MAX_BLOCKS: u32 = 1_200_000;

/// Changes nothing.
struct Keep;
impl Visit for Keep {
    fn block(&mut self, _: u32, _: &mut [i16; BLOCK]) {}
}

/// Changes nothing; FNV-1a over each block's index and coefficients.
struct Sum(u64);
impl Visit for Sum {
    fn block(&mut self, index: u32, c: &mut [i16; BLOCK]) {
        let bytes = index
            .to_le_bytes()
            .into_iter()
            .chain(c.iter().flat_map(|v| v.to_le_bytes()));
        for b in bytes {
            self.0 = (self.0 ^ u64::from(b)).wrapping_mul(0x100_0000_01B3);
        }
    }
}

/// The sum of `file`'s scan, `None` if it does not read.
fn coefficients(file: &[u8]) -> Option<u64> {
    let mut tables = Tables::EMPTY;
    let frame = scan::parse(file, MAX_BLOCKS, &mut tables).ok()?;
    let mut sum = Sum(0xCBF2_9CE4_8422_2325);
    scan::read(file, &frame, &mut sum).ok()?;
    Some(sum.0)
}

fn photos(file: &[u8]) {
    for s in segment::segments(file) {
        let _ = s.payload(file);
    }
    let _ = segment::dimensions(file);
    let _ = segment::scan_start(file);
    if let Some(app1) = segment::exif_app1(file) {
        if let Some(tiff) = Tiff::of_app1(app1.payload(file)) {
            let mut ifd = tiff.ifd0();
            for _ in 0..4 {
                let Some(at) = ifd else { break };
                for e in tiff.entries(at).take(256) {
                    let _ = tiff.value(&e);
                    let _ = tiff.field_u32(&e);
                    let _ = e.value_len();
                }
                ifd = tiff.next_ifd(at).map(|n| n as usize);
            }
            let _ = tiff.user_comment();
            let _ = tiff.ascii(0x010E);
        }
        let mut out = vec![0u8; file.len() + 64];
        let _ = segment::replace_exif(file, &[0xFF, 0xE1, 0, 2], &mut out);
    }
    let mut tables = Tables::EMPTY;
    let Ok(frame) = scan::parse(file, MAX_BLOCKS, &mut tables) else {
        return;
    };
    let mut out = vec![0u8; 2 * file.len() + 64];
    let Ok(n) = scan::rewrite(file, &frame, &mut Keep, &mut out) else {
        return;
    };
    // Only for a file with its end marker: one without is written back
    // without it.
    if file.ends_with(&[0xFF, segment::EOI]) {
        if let Some(read) = coefficients(file) {
            assert_eq!(
                coefficients(&out[..n]),
                Some(read),
                "a rewrite that does not read back"
            );
        }
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_photo_any_bytes() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    let seeds = names
        .into_iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    mutate::run("photo", 3000, seeds, photos);
}
