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

//! The camera screens: scanning, and making a seed.
//!
//! The board paints its viewfinder every frame into a box the screen names.
//! The counter at the top right, the line and the dots sit outside it,
//! redrawn as they change, so the picture is never covered. A scan's box is
//! a square at the left ([`scan_viewfinder`]) that never moves or changes
//! size while frames come in, with the set's [`dots`] or the scan's line
//! beside it ([`side_area`]). A seed's box ([`viewfinder`]) is wider and
//! shorter, leaving its foot for a line saying what the seed still needs:
//! nobody aims at anything while a seed is made.
//!
//! Only the back button leaves; any other touch does nothing on a scan and
//! feeds a seed being made. A scan's picture has an edge: red while no code
//! is in view, flashing green while one is ([`Sighting`], [`edges`]).

use super::band::Band;
use super::chrome::{corner, header, place_back, Nav};
use super::color::{rgb565, HINT, ORANGE, TEAL};
use super::scale::{Kit, Scale};
use crate::seed::Source;
use crate::touch::Zone;

/// The scan screen's title.
pub const SCAN: &str = "SCAN QR";
/// The seed screen's.
pub const NEW_SEED: &str = "NEW SEED";
/// Sign Message's text scanner's.
pub const SCAN_TEXT: &str = "SCAN TEXT";
/// The backup check's, for the copy of a code shown.
pub const CHECK_BACKUP: &str = "CHECK BACKUP";

/// Where the back button counts.
pub const fn back(scale: Scale) -> Zone {
    corner(scale, Nav::Back)
}

/// The box a seed's viewfinder is painted in: under the rule, above the
/// line.
pub const fn viewfinder(scale: Scale) -> Zone {
    scale.zone(40, 56, 240, 156)
}

/// The box a scan's viewfinder is painted in: a square at the left. On the
/// S3 units, the middle of what a full-width box shows, at the same scale;
/// on the P4, its whole picture, 231 by 240.
pub const fn scan_viewfinder(scale: Scale) -> Zone {
    scale.zone(SQUARE_X, SQUARE_Y, SQUARE, SQUARE)
}

/// The scan's square: its left edge, top and side, in design pixels.
const SQUARE_X: i32 = 12;
const SQUARE_Y: i32 = 56;
const SQUARE: i32 = 180;

/// Beside a scan's square: where its dots go, or its line. Clear of the
/// square's edge and of the counter above it.
pub const fn side_area(scale: Scale) -> Zone {
    scale.zone(SIDE_X, SQUARE_Y, SIDE_W, 184)
}

/// The side's left edge and width, and the middle its dots and line are
/// centred on: level with the square's.
const SIDE_X: i32 = 196;
const SIDE_W: i32 = 120;
const SIDE_MIDDLE: (i32, i32) = (SIDE_X + SIDE_W / 2, SQUARE_Y + SQUARE / 2);

/// Where the line that says what to do goes: the box's foot.
pub const fn note_area(scale: Scale) -> Zone {
    scale.zone(40, 212, 240, 24)
}

/// Where the counter goes: the top right corner, clear of the title.
pub const fn counter_area(scale: Scale) -> Zone {
    scale.zone(220, 4, 98, 36)
}

/// The screen around the viewfinder, with the line under it if there is
/// one.
pub fn chrome(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    title: &str,
    count: &str,
    note: Option<&str>,
) {
    place_back(band, scale);
    header(band, scale, kit, title);
    counter(band, scale, kit, count);
    if let Some(text) = note {
        self::note(band, scale, kit, text);
    }
}

/// The counter alone, right-aligned in its corner.
pub fn counter(band: &mut Band<'_>, scale: Scale, kit: &Kit, text: &str) {
    let x = scale.x(316) - kit.title.width(text);
    band.text(kit.title, x, scale.y(30), TEAL, text);
}

/// The line alone.
pub fn note(band: &mut Band<'_>, scale: Scale, kit: &Kit, text: &str) {
    band.text_centered(kit.body, scale.x(160), scale.y(229), ORANGE, text);
}

/// The most frames a scan's dots show, the profile's most: a dot a frame.
pub const DOTS_MAX: usize = 64;
/// Dots in a row, and rows in a batch: two rows of five are the ten frames
/// kassigner.org shows a unit at a time.
pub const DOTS_PER_ROW: usize = 5;
pub const ROWS_PER_BATCH: usize = 2;

/// A set's dots in design pixels, by the rows it needs: the dot, the step
/// across and down, and the gap after each batch.
const fn dot_sizes(rows: usize) -> (i32, i32, i32, i32) {
    if rows <= 4 {
        (12, 18, 18, 10)
    } else if rows <= 8 {
        (10, 16, 14, 8)
    } else {
        (8, 14, 10, 8)
    }
}

/// A scan's dots: one per frame, so a missing frame shows which it is,
/// teal once read. The block is centred beside the square, a short last row
/// starting at its left edge so a column is the same place in every row.
/// Bit `i` of `received` is frame `i`.
pub fn dots(band: &mut Band<'_>, scale: Scale, total: usize, received: u64) {
    let total = total.min(DOTS_MAX);
    if total == 0 {
        return;
    }
    let rows = total.div_ceil(DOTS_PER_ROW);
    let (dot, across, down, gap) = dot_sizes(rows);
    let cols = total.min(DOTS_PER_ROW) as i32;
    let batches = rows.div_ceil(ROWS_PER_BATCH) as i32;
    let width = (cols - 1) * across + dot;
    let height = (rows as i32 - 1) * down + (batches - 1) * gap + dot;
    let (cx, cy) = SIDE_MIDDLE;
    let (left, top) = (cx - width / 2, cy - height / 2);
    for k in 0..total {
        let (r, col) = (k / DOTS_PER_ROW, (k % DOTS_PER_ROW) as i32);
        let batch = (r / ROWS_PER_BATCH) as i32;
        let color = if received & (1u64 << k) != 0 {
            TEAL
        } else {
            HINT
        };
        band.disc(
            scale.x(left + col * across),
            scale.y(top + r as i32 * down + batch * gap),
            scale.len(dot),
            color,
        );
    }
}

/// A scan's line beside its square, wrapped at words onto up to four lines,
/// centred on the square's middle.
pub fn side_note(band: &mut Band<'_>, scale: Scale, kit: &Kit, text: &str) {
    let font = kit.body;
    let room = scale.len(SIDE_W - 8);
    let mut lines: [&str; 4] = [""; 4];
    let mut n = 0;
    let mut rest = text.trim();
    while !rest.is_empty() && n < lines.len() {
        // The longest run of whole words that fits; a word longer than the
        // side goes on a line of its own.
        let mut end = rest.len();
        while font.width(&rest[..end]) > room {
            match rest[..end].rfind(' ') {
                Some(space) if space > 0 => end = space,
                _ => break,
            }
        }
        lines[n] = &rest[..end];
        n += 1;
        rest = rest[end..].trim_start();
    }
    let step = i32::from(font.ascent) + i32::from(font.descent) + scale.len(4);
    let (cx, cy) = SIDE_MIDDLE;
    let first = scale.y(cy) - (n as i32 * step) / 2 + i32::from(font.ascent);
    for (i, line) in lines[..n].iter().enumerate() {
        band.text_centered(font, scale.x(cx), first + i as i32 * step, ORANGE, line);
    }
}

/// What a scan shows beside its square: its line when it has one, else
/// its dots.
pub fn scan_side(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    line: Option<&str>,
    (total, received): (usize, u64),
) {
    match line {
        Some(text) => side_note(band, scale, kit, text),
        None => dots(band, scale, total, received),
    }
}

/// A scan's counter: frames read of how many, or nothing before the first.
pub fn scan_counter(have: usize, total: usize, out: &mut [u8; 16]) -> &str {
    if total == 0 {
        return "";
    }
    let n = Part::Number(have).write(out, 0);
    let n = Part::Text("/").write(out, n);
    let n = Part::Number(total).write(out, n);
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// A seed's counter: the bits credited so far.
pub fn seed_counter(credited: u32, out: &mut [u8; 16]) -> &str {
    let bits = usize::try_from(credited).unwrap_or(usize::MAX);
    let n = Part::Number(bits).write(out, 0);
    let n = Part::Text(" bits").write(out, n);
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// The scan's line for a code shaped as the last frame of a v1.0.7 set and
/// read alone for a while: about one 24-word compact SeedQR in 266,000 has
/// that shape and never loads, and these two forms of the same seed do.
pub const SEED_HINT: &str = "Use the Standard SeedQR or words";

/// What a seed being made asks: whatever source it still needs.
pub const fn seed_hint(short: Option<Source>) -> &'static str {
    match short {
        Some(Source::Touch) => "Move a finger on the screen",
        Some(Source::Camera) => "Move the camera around",
        Some(Source::Imu) => "Move the unit",
        Some(Source::Dice) => "Roll the dice",
        Some(Source::Generator) | None => "Almost there",
    }
}

/// The scan's edge while no code is in view.
pub const SEARCHING: u16 = rgb565(24, 6, 0);
/// The scan's edge while a code is in view, bright and dim in turn.
pub const IN_VIEW: [u16; 2] = [rgb565(0, 63, 0), rgb565(0, 42, 0)];
/// Frames the green lasts after the decoder last saw a code. The decoder
/// answers about one frame in one or two drawn, so a code held in view
/// stays green, and one taken away turns red in about a second.
pub const HELD_FRAMES: u8 = 10;
/// The edge's width in design pixels.
pub const EDGE: i32 = 2;

/// Whether a code has been in view lately, for the scan's edge: told of
/// each code found ([`Sighting::saw`]), asked for the colour once a frame
/// ([`Sighting::edge`]). The tick that greets a code sounds when the edge
/// turns green, so a code found on and off ticks once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sighting {
    /// Frames of green left.
    held: u8,
    /// The next green is the dim one.
    dim: bool,
}

impl Sighting {
    /// Red: nothing seen.
    pub const fn new() -> Self {
        Self {
            held: 0,
            dim: false,
        }
    }

    /// The decoder found a code in a frame, read or not. Returns whether it
    /// just came into view, the edge red until now: the tick's moment.
    pub fn saw(&mut self) -> bool {
        let new = self.held == 0;
        self.held = HELD_FRAMES;
        new
    }

    /// The edge's colour for the frame being drawn.
    pub fn edge(&mut self) -> u16 {
        if self.held == 0 {
            return SEARCHING;
        }
        self.held -= 1;
        let color = IN_VIEW[usize::from(self.dim)];
        self.dim = !self.dim;
        color
    }

    /// A scan begins or ends: red again, and the next code ticks.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Where the scan's edge goes around `picture`, [`EDGE`] wide: top, left,
/// right, foot. Outside the picture at the top and sides, where nothing
/// paints over it; on the picture's last rows at the foot, painted last in
/// each frame, so the edge drawn on them just after does not flicker.
pub fn edges(scale: Scale, picture: Zone) -> [Zone; 4] {
    let w = scale.len(EDGE).max(1) as u16;
    let (x, y, width, height) = (picture.x, picture.y, picture.width, picture.height);
    let left = x.saturating_sub(w);
    [
        Zone::new(left, y.saturating_sub(w), x + width + w - left, w),
        Zone::new(left, y, x - left, height),
        Zone::new(x + width, y, w, height),
        Zone::new(x, y + height - w.min(height), width, w.min(height)),
    ]
}

/// A piece of a counter, or of any line with a number in it.
pub(crate) enum Part<'a> {
    Number(usize),
    Text(&'a str),
}

impl Part<'_> {
    /// Write this at `at` in `out`, as much as fits, and return the end.
    pub(crate) fn write(&self, out: &mut [u8], at: usize) -> usize {
        let mut digits = [0u8; 20];
        let bytes: &[u8] = match self {
            Part::Text(t) => t.as_bytes(),
            Part::Number(v) => {
                let (mut v, mut i) = (*v, digits.len());
                loop {
                    i -= 1;
                    digits[i] = b'0' + (v % 10) as u8;
                    v /= 10;
                    if v == 0 {
                        break;
                    }
                }
                &digits[i..]
            }
        };
        let n = bytes.len().min(out.len() - at);
        out[at..at + n].copy_from_slice(&bytes[..n]);
        at + n
    }
}
