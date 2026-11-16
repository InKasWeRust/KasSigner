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

//! Writing a source out raw, for measuring it somewhere else.
//!
//! Behind the `capture` feature, never in a shipped image. The output is the
//! sensor's bytes, with no hashing or mixing: a hash makes any source look
//! perfect. It is hex between markers, so a capture can be cut out of a
//! terminal log:
//!
//! ```text
//! -----BEGIN KASSIGNER CAPTURE cam 8192 32-----
//! -----END KASSIGNER CAPTURE-----
//! ```
//!
//! The routines are generic over the HAL traits, so one copy serves both S3
//! units; an example per unit brings its board up and calls in. The IMU is
//! the exception: the boards carry different parts, and `imu` uses the
//! driver its features name.
//!
//! The bytes go to a [`Write`] the caller passes: the library depends on no
//! console (`esp-println` is a dev-dependency only, and `log!` expands to
//! nothing).

use core::fmt::Write;

use embedded_hal::i2c::I2c;

use kassigner_hal::camera::Camera;
#[cfg(feature = "decode")]
use kassigner_hal::decoder::{Attempt, Decoder, Outcome};
#[cfg(feature = "decode")]
use kassigner_hal::display::{Backlight, Display, Rect};
use kassigner_hal::entropy::Entropy;
use kassigner_hal::input::Touch;
use kassigner_hal::timer::Timer;

use crate::systimer::SysTimer;

/// How many touch events a capture collects.
pub const TOUCH_EVENTS: u32 = 2048;

/// Bytes of raw source per chunk. With [`CHUNKS`], a quarter of the million
/// samples an estimator wants: enough to tell a live source from a dead one,
/// in about a minute over the wire.
pub const CHUNK: usize = 8192;
/// Chunks per capture. See [`CHUNK`].
pub const CHUNKS: u32 = 32;

/// Bytes per IMU chunk: smaller than [`CHUNK`], since the gyro is read over
/// I2C, three bytes a sample.
pub const IMU_CHUNK: usize = 1024;
/// Chunks per IMU capture. See [`IMU_CHUNK`].
pub const IMU_CHUNKS: u32 = 32;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Which source [`raw`] writes out: an argument, not a feature, since which
/// source a build measures is the example's choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The change between consecutive camera frames.
    Camera,
    /// The generator's own output, through the health-checked path.
    Rng,
}

impl Source {
    /// The word that names it in the markers.
    pub const fn tag(self) -> &'static str {
        match self {
            Source::Camera => "cam",
            Source::Rng => "rng",
        }
    }
}

/// Print `bytes` as hex, 64 per line.
fn hex_lines<W: Write>(out: &mut W, bytes: &[u8]) {
    for row in bytes.chunks(64) {
        let mut line = [0u8; 128];
        for (i, b) in row.iter().enumerate() {
            line[i * 2] = HEX[(b >> 4) as usize];
            line[i * 2 + 1] = HEX[(b & 0x0F) as usize];
        }
        let _ = writeln!(
            out,
            "{}",
            core::str::from_utf8(&line[..row.len() * 2]).unwrap_or("")
        );
    }
}

/// Raw touch events, one a line: `x y microseconds-since-the-last`.
///
/// Position and timing stay apart so an estimator can take either: they
/// anti-correlate (fast motion makes position rich and timing regular, slow
/// motion the reverse). An unchanged coordinate, a finger held still,
/// records nothing.
pub fn touch<D, T, W>(touch: &mut D, timer: &T, out: &mut W) -> !
where
    D: Touch,
    T: Timer + ?Sized,
    W: Write,
{
    let _ = writeln!(
        out,
        "capture: touch, {} events; scribble on the screen",
        TOUCH_EVENTS
    );
    let _ = writeln!(out, "-----BEGIN KASSIGNER TOUCH {}-----", TOUCH_EVENTS);
    let start = timer.now_us();
    let mut last = start;
    let mut seen = 0u32;
    let mut prev = (u16::MAX, u16::MAX);
    while seen < TOUCH_EVENTS {
        let Ok(state) = touch.read() else {
            continue;
        };
        let Some(p) = state.first() else {
            continue;
        };
        if (p.x, p.y) == prev {
            continue;
        }
        prev = (p.x, p.y);
        let now = timer.now_us();
        let _ = writeln!(out, "{} {} {}", p.x, p.y, now - last);
        last = now;
        seen += 1;
    }
    let _ = writeln!(out, "-----END KASSIGNER TOUCH-----");
    let _ = writeln!(
        out,
        "done: {} events in {} ms",
        TOUCH_EVENTS,
        timer.since(start) / 1000
    );
    loop {
        core::hint::spin_loop();
    }
}

/// Write raw source bytes for offline analysis.
///
/// For the camera, the change of each sampled byte between consecutive
/// frames, not the picture: a unit on a table sees the same scene at every
/// seed generation. For the generator, its output through `fill`, health
/// check included.
pub fn raw<C, E, T, W>(cam: &mut C, rng: &mut E, timer: &T, source: Source, out: &mut W) -> !
where
    C: Camera,
    E: Entropy + ?Sized,
    T: Timer + ?Sized,
    W: Write,
{
    let tag = source.tag();
    let _ = writeln!(
        out,
        "capture: {}, {} chunks of {} bytes, raw hex between markers",
        tag, CHUNKS, CHUNK
    );
    let _ = writeln!(
        out,
        "redirect this whole log to a file; the analyser cuts it out\n"
    );

    let mut prev = alloc::vec![0u8; CHUNK];
    let mut cur = alloc::vec![0u8; CHUNK];
    let mut have_prev = false;

    let _ = writeln!(
        out,
        "-----BEGIN KASSIGNER CAPTURE {} {} {}-----",
        tag, CHUNK, CHUNKS
    );
    let mut done = 0u32;
    while done < CHUNKS {
        if source == Source::Rng {
            if rng.fill(&mut cur).is_err() {
                let _ = writeln!(out, "(generator refused a draw: unhealthy)");
                continue;
            }
        } else {
            let Ok(frame) = cam.frame_within(timer, 1_000_000) else {
                continue;
            };
            // One byte in every few, so a chunk spans the whole sensor.
            let stride = frame.len() / CHUNK;
            for (i, b) in cur.iter_mut().enumerate() {
                *b = frame[i * stride];
            }
            if !have_prev {
                prev.copy_from_slice(&cur);
                have_prev = true;
                continue;
            }
            // The delta; this frame becomes the next one's reference.
            for i in 0..CHUNK {
                let d = cur[i].wrapping_sub(prev[i]);
                prev[i] = cur[i];
                cur[i] = d;
            }
        }

        hex_lines(out, &cur);
        done += 1;
        if done.is_multiple_of(4) {
            let _ = writeln!(out, "(chunk {} of {})", done, CHUNKS);
        }
    }
    let _ = writeln!(out, "-----END KASSIGNER CAPTURE-----");
    let _ = writeln!(out, "done: {} bytes of {}", CHUNK * CHUNKS as usize, tag);
    loop {
        core::hint::spin_loop();
    }
}

/// Raw IMU bytes, for measuring what a board's gyro is worth.
///
/// The exact stream a seed mixes: the low byte of each gyro axis, three
/// interleaved, as the driver's `collect` writes them. On a still unit the
/// low byte holds the noise and the high byte is near-constant.
///
/// Run it twice, flat on a table and moving in a hand. The Waveshare's
/// QMI8658 gave 5.54 bits a byte still and 2.21 moving: a still MEMS gyro's
/// low bits are thermal noise, and motion adds a large correlated signal an
/// estimator reads as structure. Needs a board feature, since the part and
/// its driver are the board's; [`touch`] and [`raw`] need none.
#[cfg(any(feature = "m5stack", feature = "waveshare"))]
pub fn imu<I, T, W>(i2c: &mut I, timer: &T, out: &mut W) -> !
where
    I: I2c,
    T: Timer + ?Sized,
    W: Write,
{
    #[cfg(feature = "m5stack")]
    use crate::m5stack::imu as part;
    #[cfg(all(feature = "waveshare", not(feature = "m5stack")))]
    use crate::waveshare::imu as part;

    let mut sys = SysTimer;

    // Who answers on the bus: the driver gives up quietly and its log lines
    // print nowhere, so this tells a silent part from a failed configuration.
    let _ = write!(out, "main bus answers at");
    for addr in 0x08u8..0x78 {
        let mut b = [0u8; 1];
        if i2c.read(addr, &mut b).is_ok() {
            let _ = write!(out, " {:02X}", addr);
        }
    }
    let _ = writeln!(out);

    // 200 ms, for a part still coming out of reset.
    let started = timer.now_us();
    while timer.since(started) < 200_000 {
        core::hint::spin_loop();
    }

    if !part::init(i2c, &mut sys) {
        let _ = writeln!(out, "the IMU did not start: {:?}", part::failure());
        loop {
            core::hint::spin_loop();
        }
    }
    let _ = writeln!(out, "the IMU answered and took its configuration");
    let _ = writeln!(
        out,
        "capture: imu, {} chunks of {} bytes, raw hex between markers",
        IMU_CHUNKS, IMU_CHUNK
    );
    let mut buf = alloc::vec![0u8; IMU_CHUNK];
    let _ = writeln!(
        out,
        "-----BEGIN KASSIGNER CAPTURE imu {} {}-----",
        IMU_CHUNK, IMU_CHUNKS
    );
    for done in 1..=IMU_CHUNKS {
        let n = part::collect(i2c, &mut sys, &mut buf);
        if n == 0 {
            let _ = writeln!(out, "(the IMU contributed nothing)");
            continue;
        }
        hex_lines(out, &buf[..n]);
        if done.is_multiple_of(4) {
            let _ = writeln!(out, "(chunk {} of {})", done, IMU_CHUNKS);
        }
    }
    let _ = writeln!(out, "-----END KASSIGNER CAPTURE-----");
    loop {
        core::hint::spin_loop();
    }
}

/// Quiet zone above and below a code, in pixels, that the version sweep
/// tries: the default, a thin one, none. Smaller gives bigger modules and a
/// thinner quiet zone.
#[cfg(feature = "decode")]
pub const SWEEP_MARGINS: &[u16] = &[10, 4, 0];

/// How long the sweep holds each code, in microseconds.
#[cfg(feature = "decode")]
pub const SWEEP_HOLD_US: u64 = 4_000_000;

#[cfg(feature = "decode")]
const BLACK: u16 = 0x0000;
#[cfg(feature = "decode")]
const WHITE: u16 = 0xFFFF;

/// Show a ladder of QR versions, reading all the while.
///
/// One half of a two-unit measurement of what a panel can show and a camera
/// read. Each code starts with its version, margin and brightness, so any
/// reader (the other unit, a phone, a browser) names what it read. This unit
/// reads too, measuring both directions in one run.
///
/// `bright` is the backlight while showing. The right level differs by
/// board, distance and pair of units: too bright saturates the sensor
/// photographing it and reflects off the code that sensor reads, too dim
/// leaves nothing to detect.
#[cfg(feature = "decode")]
pub fn qr_show<C, D, L, T, W>(
    cam: &mut C,
    dec: &mut D,
    lcd: &mut L,
    timer: &T,
    payload: &mut [u8],
    bright: u8,
    out: &mut W,
) -> !
where
    C: Camera,
    D: Decoder,
    L: Display,
    T: Timer + ?Sized,
    W: Write,
{
    let size = lcd.size();
    let _ = lcd.set_backlight(Backlight::Level(bright));
    let _ = writeln!(
        out,
        "sweep: panel {}x{} at brightness {}, v1 to v9 at margins {:?}, {} ms each",
        size.width,
        size.height,
        bright,
        SWEEP_MARGINS,
        SWEEP_HOLD_US / 1000
    );
    let mut data = [0u8; 256];
    loop {
        for &margin in SWEEP_MARGINS {
            for version in 1..=9u8 {
                let Some(capacity) = kassigner_qr::byte_capacity(version) else {
                    continue;
                };
                // Version, margin and brightness first, then filler.
                let n = capacity.min(data.len());
                for (i, b) in data[..n].iter_mut().enumerate() {
                    *b = match i {
                        0 => b'V',
                        1 => b'0' + version / 10,
                        2 => b'0' + version % 10,
                        3 => b' ',
                        4 => b'M',
                        5 => b'0' + (margin / 10) as u8,
                        6 => b'0' + (margin % 10) as u8,
                        7 => b' ',
                        8 => b'B',
                        9 => b'0' + bright / 100,
                        10 => b'0' + (bright / 10) % 10,
                        11 => b'0' + bright % 10,
                        12 => b' ',
                        _ => b'a' + (i % 26) as u8,
                    };
                }
                let Ok(code) = kassigner_qr::encode(&data[..n]) else {
                    let _ = writeln!(out, "  v{}: this encoder will not make one", version);
                    continue;
                };
                let short = size.width.min(size.height);
                let target = short.saturating_sub(margin * 2);
                let _ = writeln!(
                    out,
                    "  showing v{} at margin {}: {} bytes, {} modules, {} px wide",
                    version, margin, n, code.size, target
                );
                draw_code(lcd, &code, margin);

                // Hold it, reading all the while.
                let start = timer.now_us();
                while timer.since(start) < SWEEP_HOLD_US {
                    if let Ok(Some(Outcome::Found { len })) = dec.poll(payload) {
                        let head = &payload[..len.min(13)];
                        let _ = writeln!(
                            out,
                            "    read {} bytes, starts {:?}",
                            len,
                            core::str::from_utf8(head).unwrap_or("??")
                        );
                        payload.fill(0);
                    }
                    if let Ok(frame) = cam.frame_within(timer, 200_000) {
                        let _ = dec.submit(frame, Attempt::Thorough);
                    }
                }
            }
        }
    }
}

/// Draw a code centred. `margin` is the quiet zone above and below; the
/// white runs on to the panel's left and right edges.
#[cfg(feature = "decode")]
fn draw_code<L: Display>(lcd: &mut L, code: &kassigner_qr::QrMatrix, margin: u16) {
    let size = lcd.size();
    let short = size.width.min(size.height);
    let target = short.saturating_sub(margin * 2).max(u16::from(code.size));
    let x0 = (size.width - target) / 2;
    let y0 = (size.height - target) / 2;
    let side = u32::from(code.size);

    let _ = lcd.clear(WHITE);
    let mut line = [WHITE; 320];
    let row = &mut line[..usize::from(target)];
    for py in 0..target {
        // Which module row this pixel row falls in.
        let my = (u32::from(py) * side / u32::from(target)) as u8;
        for (px, slot) in row.iter_mut().enumerate() {
            let mx = (px as u32 * side / u32::from(target)) as u8;
            *slot = if code.get(mx, my) { BLACK } else { WHITE };
        }
        let _ = lcd.blit(Rect::new(x0, y0 + py, target, 1), row);
    }
}

/// A byte of luminance as a dithered RGB565 pixel: the viewfinder's own,
/// [`crate::paint::grey`].
pub use crate::paint::grey;
