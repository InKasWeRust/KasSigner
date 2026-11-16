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

//! The M5 decoder, with a real code: encoded by `kassigner-qr`, painted into
//! a frame bottom row first, as this camera delivers it, and decoded.
//!
//! Reading it does not prove the orientation: the vendored decoder retries a
//! grid it could not read with rows and columns swapped, so a mirror image
//! reads too, as the decode test shows. The orientation is checked pixel by
//! pixel on what [`decoder::prepare`] produces.
//!
//! Every decode is in one test function: the core-1 worker's one job slot
//! and image are shared, and tests in one binary run in parallel. On a host
//! the worker runs a job in the submit that posts it, so a result is ready
//! when `submit` returns; on the device it is ready a decode later.

#![cfg(all(feature = "m5stack", feature = "decode"))]

use kassigner_hal::decoder::{Attempt, Decoder, Error, Outcome};
use kassigner_hal_esp32s3::decode_core;
use kassigner_hal_esp32s3::m5stack::camera::{source_row, FRAME_BYTES, FRAME_H, FRAME_W};
use kassigner_hal_esp32s3::m5stack::decoder::{self, M5Decoder};

/// Paint `data` as a QR code, upright, into a frame stored the way the
/// camera stores it.
fn frame_with(data: &[u8]) -> Vec<u8> {
    let qr = kassigner_qr::encode(data).expect("encodes");
    let side = qr.size as usize;
    let scale = 5usize;
    let span = side * scale;
    let x0 = (FRAME_W - span) / 2;
    let y0 = (FRAME_H - span) / 2;

    let mut frame = vec![0xF0u8; FRAME_BYTES];
    for y in 0..FRAME_H {
        for x in 0..FRAME_W {
            let inside = (x0..x0 + span).contains(&x) && (y0..y0 + span).contains(&y);
            let dark = inside && qr.get(((x - x0) / scale) as u8, ((y - y0) / scale) as u8);
            if dark {
                // Upright row `y` is stored at `source_row(y)`.
                frame[source_row(y) * FRAME_W + x] = 0x10;
            }
        }
    }
    frame
}

/// What the decoder sees is the scene upright, and its centre square.
#[test]
fn prepare_turns_the_frame_upright_and_crops_the_centre() {
    // A scene whose every pixel says where it is.
    let scene = |x: usize, y: usize| (x * 7 + y * 13) as u8;
    let mut frame = vec![0u8; FRAME_BYTES];
    for y in 0..FRAME_H {
        for x in 0..FRAME_W {
            frame[source_row(y) * FRAME_W + x] = scene(x, y);
        }
    }
    let mut image = vec![0u8; decoder::IMAGE_BYTES];
    decoder::prepare(&frame, &mut image);
    for y in 0..decoder::SIDE {
        for x in 0..decoder::SIDE {
            assert_eq!(
                image[y * decoder::SIDE + x],
                scene(x + decoder::CROP_X, y),
                "({x}, {y})"
            );
        }
    }
    assert_eq!(decoder::CROP_X, 40, "the crop's left edge");
}

#[test]
fn the_decoder_reads_a_code_through_the_cameras_orientation() {
    let mut dec = M5Decoder::new().expect("always");
    assert!(dec.is_asynchronous(), "core 1 decodes");
    assert!(!dec.is_ready(), "nothing submitted");

    // A real code, read.
    let message = b"KasSigner M5 port";
    let frame = frame_with(message);
    dec.submit(&frame, Attempt::Fast).unwrap();
    assert!(
        dec.is_ready(),
        "on a host the worker runs the job in the submit"
    );
    let mut out = [0u8; 64];
    assert_eq!(
        dec.poll(&mut out),
        Ok(Some(Outcome::Found { len: message.len() }))
    );
    assert_eq!(&out[..message.len()], message);
    assert_eq!(dec.poll(&mut out), Ok(None), "taken once");
    assert!(decode_core::is_idle(), "taking it frees the worker");

    // Stored upright, not as this camera delivers it, the code is a mirror
    // image to the decoder, and reads anyway: hence orientation is checked
    // on `prepare`, not by decoding.
    let mut upright = vec![0u8; FRAME_BYTES];
    for y in 0..FRAME_H {
        let src = source_row(y) * FRAME_W;
        upright[y * FRAME_W..(y + 1) * FRAME_W].copy_from_slice(&frame[src..src + FRAME_W]);
    }
    dec.submit(&upright, Attempt::Fast).unwrap();
    assert_eq!(
        dec.poll(&mut out),
        Ok(Some(Outcome::Found { len: message.len() }))
    );

    // A frame of the wrong size.
    assert_eq!(
        dec.submit(&frame[..1000], Attempt::Fast),
        Err(Error::WrongLength {
            expected: FRAME_BYTES,
            got: 1000
        })
    );

    // An outcome not yet taken is not overwritten.
    dec.submit(&frame, Attempt::Thorough).unwrap();
    assert_eq!(dec.submit(&frame, Attempt::Fast), Err(Error::Busy));

    // A buffer too small for the payload: an error, and the outcome is gone.
    let mut small = [0u8; 4];
    assert_eq!(
        dec.poll(&mut small),
        Err(Error::WrongLength {
            expected: message.len(),
            got: 4
        })
    );
    assert!(!dec.is_ready());
    assert!(decode_core::is_idle());
    assert_eq!(small, [0; 4], "nothing copied into a buffer too small");

    // The thorough pass, at the other window, read the code, so that window
    // is kept.
    assert_eq!(dec.denom(), decoder::DENOM_WIDE);

    // A thorough pass that reads nothing changes no window.
    let blank = vec![0x80u8; FRAME_BYTES];
    dec.submit(&blank, Attempt::Thorough).unwrap();
    assert_eq!(dec.poll(&mut out), Ok(Some(Outcome::NotFound)));
    assert_eq!(dec.denom(), decoder::DENOM_WIDE);

    // The window: two misses and it switches, two more and it switches back.
    dec.cancel();
    let start = dec.denom();
    let other = if start == decoder::DENOM_NARROW {
        decoder::DENOM_WIDE
    } else {
        decoder::DENOM_NARROW
    };
    for expected in [start, other, other, start] {
        dec.submit(&blank, Attempt::Fast).unwrap();
        assert_eq!(dec.poll(&mut out), Ok(Some(Outcome::NotFound)));
        assert_eq!(dec.denom(), expected);
    }

    // `cancel` drops an outcome not taken, and leaves the worker idle.
    dec.submit(&frame, Attempt::Fast).unwrap();
    dec.cancel();
    assert_eq!(dec.poll(&mut out), Ok(None));
    assert!(decode_core::is_idle());

    // A job of a scan abandoned since is wiped, never copied out.
    let fill = |image: &mut [u8]| decoder::prepare(&frame, image);
    assert!(decode_core::fill_image(decoder::IMAGE_BYTES, fill));
    assert!(decode_core::submit(
        decoder::SIDE,
        decoder::SIDE,
        decoder::DENOM_NARROW,
        decode_core::KIND_FAST
    ));
    decode_core::bump_generation();
    let mut stale = [0xAAu8; 64];
    let (o, copied) = decode_core::take_results(&mut stale).expect("finished");
    assert_eq!(o.outcome, Outcome::Found { len: message.len() });
    assert!(!copied);
    assert!(
        stale.iter().all(|&b| b == 0xAA),
        "nothing of it in the buffer"
    );

    // A finished job no decoder waits for, as a cancel that gave up leaves
    // it: the next submit wipes it and is accepted, not refused `Busy`.
    let mut dec = M5Decoder::new().expect("always");
    assert!(decode_core::fill_image(decoder::IMAGE_BYTES, fill));
    assert!(decode_core::submit(
        decoder::SIDE,
        decoder::SIDE,
        decoder::DENOM_NARROW,
        decode_core::KIND_FAST
    ));
    assert!(!decode_core::is_idle(), "finished, and nobody's");
    dec.submit(&blank, Attempt::Fast).unwrap();
    assert_eq!(
        dec.poll(&mut out),
        Ok(Some(Outcome::NotFound)),
        "the answer to its own frame, not the code left behind"
    );

    // The image is lent for the call, and only while the worker is idle.
    dec.submit(&blank, Attempt::Fast).unwrap();
    assert!(!decode_core::fill_image(1, |_| unreachable!(
        "lent while busy"
    )));
    let _ = dec.poll(&mut out);
    assert!(decode_core::fill_image(1, |image| {
        assert!(
            !decode_core::fill_image(1, |_| unreachable!("lent twice")),
            "not inside a fill"
        );
        image[0] = 0;
    }));
}
