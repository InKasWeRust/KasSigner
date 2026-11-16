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

//! The display trait, over a fake framebuffer a test can draw on and read
//! pixels from. [`off_is_not_the_dimmest_level`] guards a difference between
//! the real boards.

use kassigner_hal::display::{Backlight, Display, Error, Rect, Size};

/// A panel in RAM.
struct Fake {
    size: Size,
    pixels: Vec<u16>,
    backlight: Backlight,
    /// Draws that reached the "panel", so a refused one is seen to send
    /// nothing.
    writes: usize,
}

impl Fake {
    fn new(w: u16, h: u16) -> Self {
        let size = Size::new(w, h);
        Self {
            pixels: vec![0; size.pixels()],
            size,
            backlight: Backlight::Off,
            writes: 0,
        }
    }

    fn at(&self, x: u16, y: u16) -> u16 {
        self.pixels[y as usize * self.size.width as usize + x as usize]
    }
}

impl Display for Fake {
    fn size(&self) -> Size {
        self.size
    }

    fn blit(&mut self, rect: Rect, pixels: &[u16]) -> Result<(), Error> {
        self.check(rect, Some(pixels))?;
        self.writes += 1;
        for row in 0..rect.height {
            for col in 0..rect.width {
                let dst =
                    (rect.y + row) as usize * self.size.width as usize + (rect.x + col) as usize;
                self.pixels[dst] = pixels[row as usize * rect.width as usize + col as usize];
            }
        }
        Ok(())
    }

    fn fill(&mut self, rect: Rect, color: u16) -> Result<(), Error> {
        self.check(rect, None)?;
        self.writes += 1;
        for row in 0..rect.height {
            for col in 0..rect.width {
                let dst =
                    (rect.y + row) as usize * self.size.width as usize + (rect.x + col) as usize;
                self.pixels[dst] = color;
            }
        }
        Ok(())
    }

    fn set_backlight(&mut self, level: Backlight) -> Result<(), Error> {
        self.backlight = level;
        Ok(())
    }
}

/// A blit lands where it was asked to and nowhere else.
#[test]
fn a_blit_lands_in_its_rectangle() {
    let mut d = Fake::new(16, 8);
    let rect = Rect::new(2, 1, 3, 2);
    let px = [0xF800u16, 0x07E0, 0x001F, 0xFFFF, 0x0000, 0x1234];

    d.blit(rect, &px).expect("blit");

    assert_eq!(d.at(2, 1), 0xF800);
    assert_eq!(d.at(4, 1), 0x001F);
    assert_eq!(d.at(2, 2), 0xFFFF);
    assert_eq!(d.at(4, 2), 0x1234);

    // Outside the rectangle is untouched.
    assert_eq!(d.at(1, 1), 0);
    assert_eq!(d.at(5, 1), 0);
    assert_eq!(d.at(2, 0), 0);
    assert_eq!(d.at(2, 3), 0);
}

/// Clear covers the whole panel.
#[test]
fn clear_covers_everything() {
    let mut d = Fake::new(8, 4);
    d.clear(0xABCD).expect("clear");
    for y in 0..4 {
        for x in 0..8 {
            assert_eq!(d.at(x, y), 0xABCD, "({x},{y})");
        }
    }
}

/// A rectangle off the panel is refused before anything is sent.
#[test]
fn an_out_of_bounds_rectangle_sends_nothing() {
    let mut d = Fake::new(16, 8);
    let before = d.writes;

    let rect = Rect::new(14, 0, 4, 1);
    let px = [0u16; 4];
    assert_eq!(
        d.blit(rect, &px).err(),
        Some(Error::OutOfBounds {
            rect,
            size: Size::new(16, 8)
        })
    );
    assert_eq!(d.writes, before, "nothing reached the panel");

    // The rectangle that exactly reaches the edge is fine.
    assert!(d.blit(Rect::new(12, 0, 4, 1), &px).is_ok());
}

/// A rectangle whose edge overflows is out of bounds, not wrapped.
#[test]
fn an_overflowing_rectangle_is_out_of_bounds() {
    let d = Fake::new(16, 8);
    let rect = Rect::new(u16::MAX, 0, 2, 1);
    assert!(!rect.fits(d.size()));
    assert!(d.check(rect, None).is_err());
}

/// A buffer that does not match the rectangle is refused before any pixel
/// is written.
#[test]
fn a_mismatched_buffer_sends_nothing() {
    let mut d = Fake::new(16, 8);
    let before = d.writes;
    let rect = Rect::new(0, 0, 4, 2);

    let short = [0u16; 7];
    assert_eq!(
        d.blit(rect, &short).err(),
        Some(Error::WrongLength {
            expected: 8,
            got: 7
        })
    );

    let long = [0u16; 9];
    assert_eq!(
        d.blit(rect, &long).err(),
        Some(Error::WrongLength {
            expected: 8,
            got: 9
        })
    );

    assert_eq!(d.writes, before, "neither reached the panel");
}

/// Off is not the dimmest level. On the Waveshare duty zero is dark; on the
/// M5 the lowest DLDO1 code, `0x11` (2.2 V), is dim but lit, and level 0 maps
/// to it. The enum makes each board handle `Off` as its own case, on the M5
/// by disabling the rail: on a unit that shows seed words, an idle timeout
/// must not mean dark on one board and readable on another.
#[test]
fn off_is_not_the_dimmest_level() {
    assert_ne!(Backlight::Off, Backlight::Level(1));
    assert!(!Backlight::Off.is_lit());
    assert!(Backlight::Level(1).is_lit());

    // Zero means off only through the named constructor.
    assert_eq!(Backlight::from_u8(0), Backlight::Off);
    assert_eq!(Backlight::from_u8(1), Backlight::Level(1));
    assert_eq!(Backlight::from_u8(255), Backlight::Level(255));
}

/// The backlight is set, and read back as what was asked for.
#[test]
fn the_backlight_takes_what_it_is_given() {
    let mut d = Fake::new(8, 4);

    d.set_backlight(Backlight::Level(200)).expect("set");
    assert_eq!(d.backlight, Backlight::Level(200));

    d.set_backlight(Backlight::Off).expect("off");
    assert_eq!(d.backlight, Backlight::Off);
    assert!(!d.backlight.is_lit());
}

/// Geometry arithmetic is what it claims.
#[test]
fn geometry_is_consistent() {
    let size = Size::new(320, 240);
    assert_eq!(size.pixels(), 76_800);

    let full = Rect::new(0, 0, 320, 240);
    assert!(full.fits(size));
    assert_eq!(full.pixels(), size.pixels());

    assert!(!Rect::new(0, 0, 321, 240).fits(size));
    assert!(!Rect::new(1, 0, 320, 240).fits(size));
    assert!(Rect::new(319, 239, 1, 1).fits(size));
}
