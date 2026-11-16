// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The decoder is fed what a camera could show it, and must answer rather
//! than panic: a panic on a unit wipes memory and halts, so a frame the
//! decoder cannot handle costs a reboot. Inputs come from fixed seeds, so a
//! failure names the seed that replays it; inputs found to panic are kept
//! below as cases of their own.
//!
//! `KQR_ROBUST_ITERS` sets the count, 600 by default, for a longer search.

use std::panic::{catch_unwind, AssertUnwindSafe};

use kassigner_qr::decode::{Decoder, Scratch};
use kassigner_qr::encode::encode;

/// A small deterministic generator: the inputs are reproducible from a seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below((hi - lo + 1) as u64) as usize
    }
}

/// One generated frame.
struct Frame {
    w: usize,
    h: usize,
    px: Vec<u8>,
}

fn noise(r: &mut Rng) -> Frame {
    let (w, h) = (r.range(1, 320), r.range(1, 320));
    let px = (0..w * h).map(|_| r.next() as u8).collect();
    Frame { w, h, px }
}

/// A finder pattern, the 7x7 ring a detector looks for, at `scale`.
fn finder(f: &mut Frame, x0: usize, y0: usize, scale: usize) {
    for y in 0..7 * scale {
        for x in 0..7 * scale {
            let (mx, my) = (x / scale, y / scale);
            let ring = mx == 0 || my == 0 || mx == 6 || my == 6;
            let core = (2..=4).contains(&mx) && (2..=4).contains(&my);
            let (px, py) = (x0 + x, y0 + y);
            if px < f.w && py < f.h {
                f.px[py * f.w + px] = if ring || core { 0 } else { 0xFF };
            }
        }
    }
}

/// One to six finder patterns scattered on a plain or noisy field, lined up
/// badly, overlapping or at a frame's edge: shapes no real code makes, for
/// grid identification to cope with.
fn finders(r: &mut Rng) -> Frame {
    let (w, h) = (r.range(24, 320), r.range(24, 320));
    let mut f = Frame {
        w,
        h,
        px: if r.below(2) == 0 {
            vec![0xFF; w * h]
        } else {
            (0..w * h).map(|_| r.next() as u8).collect()
        },
    };
    for _ in 0..r.range(1, 6) {
        let s = r.range(1, 6);
        let (x, y) = (
            r.range(0, w.saturating_sub(1)),
            r.range(0, h.saturating_sub(1)),
        );
        finder(&mut f, x, y, s);
    }
    f
}

/// A real code, rendered and then damaged: flipped pixels, painted blocks,
/// a crop, or a smear.
fn damaged(r: &mut Rng) -> Frame {
    let len = r.range(1, 120);
    let data: Vec<u8> = (0..len).map(|_| r.next() as u8).collect();
    let qr = encode(&data).expect("encodes");
    let n = qr.size as usize;
    let scale = r.range(1, 5);
    let quiet = r.range(0, 4);
    let side = (n + 2 * quiet) * scale;
    let mut f = Frame {
        w: side,
        h: side,
        px: vec![0xFF; side * side],
    };
    for y in 0..n {
        for x in 0..n {
            if qr.get(x as u8, y as u8) {
                for dy in 0..scale {
                    for dx in 0..scale {
                        f.px[((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx] = 0;
                    }
                }
            }
        }
    }
    match r.below(4) {
        0 => {
            let flips = r.range(1, side * side / 4);
            for _ in 0..flips {
                let i = r.below((side * side) as u64) as usize;
                f.px[i] ^= 0xFF;
            }
        }
        1 => {
            for _ in 0..r.range(1, 8) {
                let (bw, bh) = (r.range(1, side / 2 + 1), r.range(1, side / 2 + 1));
                let (x0, y0) = (r.range(0, side - 1), r.range(0, side - 1));
                let v = if r.below(2) == 0 { 0 } else { 0xFF };
                for y in y0..(y0 + bh).min(side) {
                    for x in x0..(x0 + bw).min(side) {
                        f.px[y * side + x] = v;
                    }
                }
            }
        }
        2 => {
            // A crop: a window of the code, down to a sliver.
            let (cw, ch) = (r.range(1, side), r.range(1, side));
            let (x0, y0) = (r.range(0, side - cw), r.range(0, side - ch));
            let mut px = Vec::with_capacity(cw * ch);
            for y in y0..y0 + ch {
                px.extend_from_slice(&f.px[y * side + x0..y * side + x0 + cw]);
            }
            f = Frame { w: cw, h: ch, px };
        }
        _ => {
            // A smear: each row shifted by a growing amount, a crude shear.
            let k = r.range(1, 4);
            let mut px = vec![0xFF; side * side];
            for y in 0..side {
                let s = (y * k / 8).min(side);
                px[y * side + s..(y + 1) * side]
                    .copy_from_slice(&f.px[y * side..(y + 1) * side - s]);
            }
            f.px = px;
        }
    }
    f
}

/// A real code with its finder and timing patterns kept and other modules
/// flipped at random: past the grid, the format and version bits, the error
/// correction and the segments have to cope. Some frames keep the format
/// bits too; others flip them as well.
fn structured(r: &mut Rng) -> Frame {
    let len = r.range(1, 200);
    let data: Vec<u8> = (0..len).map(|_| r.next() as u8).collect();
    let qr = encode(&data).expect("encodes");
    let n = qr.size as usize;
    let keep_format = r.below(2) == 0;
    // From one module in 400 (a nearly good code, deep into the error
    // correction) to one in three.
    let flip_one_in = [3u64, 8, 40, 400][r.below(4) as usize];
    let fixed = |x: usize, y: usize| {
        let finder = (x < 9 && (y < 9 || y >= n - 8)) || (x >= n - 8 && y < 9);
        let timing = x == 6 || y == 6;
        finder || timing
    };
    let format =
        |x: usize, y: usize| (y == 8 && (x < 9 || x >= n - 8)) || (x == 8 && (y < 9 || y >= n - 7));
    let scale = r.range(2, 4);
    let quiet = 4;
    let side = (n + 2 * quiet) * scale;
    let mut f = Frame {
        w: side,
        h: side,
        px: vec![0xFF; side * side],
    };
    for y in 0..n {
        for x in 0..n {
            let mut dark = qr.get(x as u8, y as u8);
            let may_change = !fixed(x, y) || (!keep_format && format(x, y));
            if may_change && r.below(flip_one_in) == 0 {
                dark = !dark;
            }
            if dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        f.px[((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx] = 0;
                    }
                }
            }
        }
    }
    f
}

/// Three finder patterns on a white 240x240 field, turned by `degrees`,
/// `scale` pixels a module, their corners `spacing` modules apart, shifted
/// `shift` pixels off centre. At a spacing a little over seven the rings
/// almost touch, with no edge between them where a timing pattern would be.
fn turned_finders(degrees: f32, scale: f32, spacing: f32, shift: f32) -> Frame {
    let (w, h) = (240usize, 240usize);
    let (sin, cos) = degrees.to_radians().sin_cos();
    let (cx, cy) = (120.0 + shift, 120.0 + shift * 0.37);
    let corners = [(0.0, 0.0), (spacing, 0.0), (0.0, spacing)];
    let mut px = vec![0xFF; w * h];
    for y in 0..h {
        for x in 0..w {
            let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
            let u = (cos * dx + sin * dy) / scale + 3.5;
            let v = (-sin * dx + cos * dy) / scale + 3.5;
            for (cu, cv) in corners {
                let (mu, mv) = (u - cu, v - cv);
                if !((0.0..7.0).contains(&mu) && (0.0..7.0).contains(&mv)) {
                    continue;
                }
                let (mx, my) = (mu as i32, mv as i32);
                let ring = mx == 0 || my == 0 || mx == 6 || my == 6;
                let core = (2..=4).contains(&mx) && (2..=4).contains(&my);
                if ring || core {
                    px[y * w + x] = 0;
                }
            }
        }
    }
    Frame { w, h, px }
}

/// Decode `f`, returning the panic message if the decoder panicked.
fn try_decode(f: &Frame, denom: usize) -> Option<String> {
    let mut px = f.px.clone();
    let mut out = [0u8; 3000];
    let mut scratch = Scratch::new();
    let r = catch_unwind(AssertUnwindSafe(|| {
        let mut d = Decoder::new(&mut scratch);
        let _ = d.decode(f.w, f.h, denom, &mut px, &mut out);
    }));
    r.err().map(|e| {
        e.downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| e.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "a panic with no message".into())
    })
}

/// No generated frame makes the decoder panic.
#[test]
fn no_frame_makes_the_decoder_panic() {
    let iters: u64 = std::env::var("KQR_ROBUST_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for seed in 1..=iters {
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let kind = r.below(4);
        let f = match kind {
            0 => noise(&mut r),
            1 => finders(&mut r),
            2 => damaged(&mut r),
            _ => structured(&mut r),
        };
        let denom = [2usize, 4, 8, 16][r.below(4) as usize];
        if let Some(msg) = try_decode(&f, denom) {
            failures.push(format!(
                "seed {seed} kind {kind} {}x{} denom {denom}: {msg}",
                f.w, f.h
            ));
        }
    }
    std::panic::set_hook(prev);
    assert!(
        failures.is_empty(),
        "{} panics:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Turned finders whose rings almost touch: an answer, not a panic.
///
/// Upstream's timing scan panics on each case at every threshold below, on
/// `assert!(scan >= 1)`: no edge between the finders, so no timing pattern.
/// One case per scale, from a sweep of 0 to 90 degrees at 2 to 5 pixels a
/// module.
#[test]
fn turned_finders_that_almost_touch() {
    // (degrees, pixels a module, spacing in modules, shift in pixels)
    const CASES: [(f32, f32, f32, f32); 6] = [
        (42.7, 2.0, 7.62, 0.75),
        (30.1, 2.5, 7.35, 0.0),
        (30.1, 3.0, 7.29, 0.0),
        (35.7, 3.5, 7.23, 0.0),
        (25.9, 4.0, 7.23, 0.0),
        (18.9, 5.0, 7.2, 0.75),
    ];
    let mut failures = Vec::new();
    for (degrees, scale, spacing, shift) in CASES {
        let f = turned_finders(degrees, scale, spacing, shift);
        for denom in [2usize, 4, 8] {
            if let Some(msg) = try_decode(&f, denom) {
                failures.push(format!(
                    "{degrees} degrees, {scale} px, spacing {spacing}, shift {shift}, \
                     denom {denom}: {msg}"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} panics:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
