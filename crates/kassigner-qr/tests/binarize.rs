// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The vendored decoder's binarizer gives, bit for bit, the answers recorded
//! from its version with raw-pointer row loops and a `static mut`
//! accumulator. Frames from a fixed seed (noise, a gradient, a checkerboard,
//! black-and-white specks) at the units' 240 by 240, an odd size, the widest
//! row the binarizer takes, and an odd size either side of 240, each at
//! every `denom` the units use.

/// A frame's thresholded pixels: FNV-1a, 64 bits.
fn fnv(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// xorshift64, the frames' source.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// A `w` by `h` frame of `kind`: noise, a gradient, a checkerboard, specks.
fn frame(r: &mut Rng, w: usize, h: usize, kind: u64) -> Vec<u8> {
    let mut f = vec![0u8; w * h];
    for y in 0..h {
        for x in 0..w {
            f[y * w + x] = match kind {
                0 => r.next() as u8,
                1 => ((x * 255 / w) as u8).wrapping_add((r.next() % 32) as u8),
                2 => {
                    if ((x / 7) + (y / 5)).is_multiple_of(2) {
                        20 + (r.next() % 40) as u8
                    } else {
                        200 + (r.next() % 55) as u8
                    }
                }
                _ => {
                    if r.next().is_multiple_of(3) {
                        0
                    } else {
                        255
                    }
                }
            };
        }
    }
    f
}

/// Width, height, kind, `denom`, and the old binarizer's answer.
const ANSWERS: [(usize, usize, u64, usize, u64); 64] = [
    (240, 240, 0, 8, 0xc71e92ff02ceccf5),
    (240, 240, 0, 4, 0x0216974f6f3e76d4),
    (240, 240, 0, 3, 0x0216974f6f3e76d4),
    (240, 240, 0, 2, 0xe96b12b6506c36d9),
    (240, 240, 1, 8, 0x16440d4fff22015a),
    (240, 240, 1, 4, 0x4218bb42aaa93c05),
    (240, 240, 1, 3, 0x4218bb42aaa93c05),
    (240, 240, 1, 2, 0x60e37bd984161274),
    (240, 240, 2, 8, 0x2ce1a8e41f31f8c5),
    (240, 240, 2, 4, 0x2ce1a8e41f31f8c5),
    (240, 240, 2, 3, 0x2ce1a8e41f31f8c5),
    (240, 240, 2, 2, 0x5041e3b77108a9cf),
    (240, 240, 3, 8, 0x240e2a5a5dcee4d8),
    (240, 240, 3, 4, 0x240e2a5a5dcee4d8),
    (240, 240, 3, 3, 0x240e2a5a5dcee4d8),
    (240, 240, 3, 2, 0x240e2a5a5dcee4d8),
    (97, 61, 0, 8, 0x1a169e557a79a581),
    (97, 61, 0, 4, 0x968f11c03f25171e),
    (97, 61, 0, 3, 0x087644ebc3929bc8),
    (97, 61, 0, 2, 0x087644ebc3929bc8),
    (97, 61, 1, 8, 0xe109dd02364bda2b),
    (97, 61, 1, 4, 0x903cb7900811556b),
    (97, 61, 1, 3, 0x3a635b2748ea682f),
    (97, 61, 1, 2, 0x3a635b2748ea682f),
    (97, 61, 2, 8, 0xdaa7a783f142ee7d),
    (97, 61, 2, 4, 0xdaa7a783f142ee7d),
    (97, 61, 2, 3, 0xdaa7a783f142ee7d),
    (97, 61, 2, 2, 0xdaa7a783f142ee7d),
    (97, 61, 3, 8, 0x35863da31ff87dcb),
    (97, 61, 3, 4, 0x35863da31ff87dcb),
    (97, 61, 3, 3, 0x35863da31ff87dcb),
    (97, 61, 3, 2, 0x35863da31ff87dcb),
    (1024, 3, 0, 8, 0x45b70e9279d583f8),
    (1024, 3, 0, 4, 0x4560e1442d4c5b6f),
    (1024, 3, 0, 3, 0x4560e1442d4c5b6f),
    (1024, 3, 0, 2, 0x2c9db4825a7db430),
    (1024, 3, 1, 8, 0x2bd41ad8495befaa),
    (1024, 3, 1, 4, 0x7f0c4b7f162ad8fe),
    (1024, 3, 1, 3, 0x7f0c4b7f162ad8fe),
    (1024, 3, 1, 2, 0xcf70eea127e9860b),
    (1024, 3, 2, 8, 0xc9a2e6a43845c0f0),
    (1024, 3, 2, 4, 0xc9a2e6a43845c0f0),
    (1024, 3, 2, 3, 0xc9a2e6a43845c0f0),
    (1024, 3, 2, 2, 0x556dbc632903dc32),
    (1024, 3, 3, 8, 0xfc7d6241e26a7a55),
    (1024, 3, 3, 4, 0xfc7d6241e26a7a55),
    (1024, 3, 3, 3, 0xfc7d6241e26a7a55),
    (1024, 3, 3, 2, 0xfc7d6241e26a7a55),
    (239, 241, 0, 8, 0x7a79a6e7010943f4),
    (239, 241, 0, 4, 0xbb85485578f4b726),
    (239, 241, 0, 3, 0xbb85485578f4b726),
    (239, 241, 0, 2, 0x45dafaa53e8b690e),
    (239, 241, 1, 8, 0x2b78fff8adb749ad),
    (239, 241, 1, 4, 0x86bf97391ac79f4a),
    (239, 241, 1, 3, 0x86bf97391ac79f4a),
    (239, 241, 1, 2, 0x86d7344550f59a45),
    (239, 241, 2, 8, 0xc2e9f3277755f111),
    (239, 241, 2, 4, 0xc2e9f3277755f111),
    (239, 241, 2, 3, 0xc2e9f3277755f111),
    (239, 241, 2, 2, 0x02b64539748cfaa8),
    (239, 241, 3, 8, 0xccff434a97285bed),
    (239, 241, 3, 4, 0xccff434a97285bed),
    (239, 241, 3, 3, 0xccff434a97285bed),
    (239, 241, 3, 2, 0xccff434a97285bed),
];

#[test]
fn the_binarizer_gives_what_it_gave_before() {
    let mut r = Rng(0x2545_F491_4F6C_DD1D);
    let mut answers = ANSWERS.iter();
    let mut scratch = Box::new(rqrr::Scratch::new());
    for (w, h) in [(240, 240), (97, 61), (1024, 3), (239, 241)] {
        for kind in 0..4 {
            let f = frame(&mut r, w, h, kind);
            for denom in [8, 4, 3, 2] {
                let &(aw, ah, ak, ad, want) = answers.next().unwrap();
                assert_eq!((aw, ah, ak, ad), (w, h, kind, denom));
                let mut px = f.clone();
                // Thresholded in place; the prepared image is not needed.
                rqrr::PreparedImage::prepare_borrowed_with_denom(w, h, denom, &mut px);
                assert_eq!(fnv(&px), want, "{w}x{h}, kind {kind}, denom {denom}");
                // And with the accumulator in a scratch, as the boards
                // prepare: the same bits, the scratch left wiped.
                let mut px = f.clone();
                rqrr::PreparedImage::prepare_borrowed_in(w, h, denom, &mut px, &mut scratch);
                assert_eq!(
                    fnv(&px),
                    want,
                    "{w}x{h}, kind {kind}, denom {denom}, in a scratch"
                );
                assert!(scratch.is_clear());
            }
        }
    }
    assert!(answers.next().is_none());
}
