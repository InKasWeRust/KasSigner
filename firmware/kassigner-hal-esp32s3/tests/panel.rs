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

//! The adapter against a fake panel: `mipidsi` is generic over its
//! interface, so the test supplies one that records.
//!
//! The refusals matter most: `set_pixels` does no bounds checking, so in
//! each the adapter is the only thing in the way.

use kassigner_hal::display::{Backlight as Level, Display, Error, Rect, Size};
use kassigner_hal_esp32s3::panel::{Backlight, Panel};
use mipidsi::interface::Interface;

/// What the fake interface saw.
#[derive(Default)]
struct Log {
    commands: Vec<(u8, Vec<u8>)>,
    pixels: usize,
    repeats: usize,
}

/// An interface that records.
struct Recorder {
    log: std::rc::Rc<core::cell::RefCell<Log>>,
}

impl Interface for Recorder {
    type Word = u8;
    type Error = ();

    fn send_command(&mut self, command: u8, args: &[u8]) -> Result<(), ()> {
        self.log
            .borrow_mut()
            .commands
            .push((command, args.to_vec()));
        Ok(())
    }

    fn send_pixels<const N: usize>(
        &mut self,
        pixels: impl IntoIterator<Item = [u8; N]>,
    ) -> Result<(), ()> {
        self.log.borrow_mut().pixels += pixels.into_iter().count();
        Ok(())
    }

    fn send_repeated_pixel<const N: usize>(
        &mut self,
        _pixel: [u8; N],
        count: u32,
    ) -> Result<(), ()> {
        self.log.borrow_mut().repeats += count as usize;
        Ok(())
    }
}

/// A backlight that records.
struct FakeBacklight {
    level: Level,
    fail: bool,
}

impl Backlight for FakeBacklight {
    fn set(&mut self, level: Level) -> Result<(), Error> {
        if self.fail {
            return Err(Error::Io);
        }
        self.level = level;
        Ok(())
    }
}

type Fake = Panel<Recorder, mipidsi::models::ILI9341Rgb565, mipidsi::NoResetPin, FakeBacklight>;

/// A panel over the recording interface.
fn panel(w: u16, h: u16) -> (Fake, std::rc::Rc<core::cell::RefCell<Log>>) {
    let log = std::rc::Rc::new(core::cell::RefCell::new(Log::default()));
    let di = Recorder {
        log: std::rc::Rc::clone(&log),
    };
    let display = mipidsi::Builder::new(mipidsi::models::ILI9341Rgb565, di)
        .init(&mut FakeDelay)
        .expect("init");
    let bl = FakeBacklight {
        level: Level::Off,
        fail: false,
    };
    (Panel::new(display, bl, Size::new(w, h)), log)
}

struct FakeDelay;
impl embedded_hal::delay::DelayNs for FakeDelay {
    fn delay_ns(&mut self, _ns: u32) {}
}

/// A blit reaches the driver.
#[test]
fn a_blit_reaches_the_panel() {
    let (mut p, log) = panel(64, 32);
    let before = log.borrow().pixels;

    let rect = Rect::new(4, 2, 8, 4);
    let px = vec![0xF800u16; rect.pixels()];
    p.blit(rect, &px).expect("blit");

    assert_eq!(log.borrow().pixels - before, 32, "eight by four pixels");
}

/// A rectangle off the panel is refused before the driver sees it.
#[test]
fn an_out_of_bounds_rectangle_never_reaches_the_driver() {
    let (mut p, log) = panel(64, 32);
    let before = log.borrow().pixels;

    let rect = Rect::new(60, 0, 8, 1);
    let px = vec![0u16; 8];
    assert_eq!(
        p.blit(rect, &px).err(),
        Some(Error::OutOfBounds {
            rect,
            size: Size::new(64, 32)
        })
    );
    assert_eq!(log.borrow().pixels, before, "nothing was written");

    // One that exactly reaches the edge is fine.
    assert!(p.blit(Rect::new(56, 0, 8, 1), &px).is_ok());
}

/// A buffer that does not match the rectangle is refused.
#[test]
fn a_mismatched_buffer_never_reaches_the_driver() {
    let (mut p, log) = panel(64, 32);
    let before = log.borrow().pixels;
    let rect = Rect::new(0, 0, 4, 4);

    assert_eq!(
        p.blit(rect, &[0u16; 15]).err(),
        Some(Error::WrongLength {
            expected: 16,
            got: 15
        })
    );
    assert_eq!(
        p.blit(rect, &[0u16; 17]).err(),
        Some(Error::WrongLength {
            expected: 16,
            got: 17
        })
    );
    assert_eq!(log.borrow().pixels, before);
}

/// An empty rectangle draws no pixels and is not an error.
#[test]
fn an_empty_rectangle_writes_nothing() {
    let (mut p, log) = panel(64, 32);
    let before = (log.borrow().pixels, log.borrow().repeats);

    assert!(p.blit(Rect::new(10, 10, 0, 4), &[]).is_ok());
    assert!(p.blit(Rect::new(10, 10, 4, 0), &[]).is_ok());
    assert!(p.fill(Rect::new(10, 10, 0, 0), 0xFFFF).is_ok());

    assert_eq!(
        (log.borrow().pixels, log.borrow().repeats),
        before,
        "nothing drawn"
    );
}

/// Clear covers the whole panel.
#[test]
fn clear_covers_the_panel() {
    let (mut p, log) = panel(16, 8);
    let before = log.borrow().pixels + log.borrow().repeats;

    p.clear(0x001F).expect("clear");

    let drawn = log.borrow().pixels + log.borrow().repeats - before;
    assert_eq!(drawn, 16 * 8);
}

/// The backlight is passed through, and its failure is reported.
#[test]
fn the_backlight_is_the_boards_business() {
    let (mut p, _log) = panel(16, 8);

    p.set_backlight(Level::Level(180)).expect("set");
    p.set_backlight(Level::Off).expect("off");

    // A backlight that is a bus write can fail; the adapter reports it.
    let log = std::rc::Rc::new(core::cell::RefCell::new(Log::default()));
    let di = Recorder { log };
    let display = mipidsi::Builder::new(mipidsi::models::ILI9341Rgb565, di)
        .init(&mut FakeDelay)
        .expect("init");
    let mut failing = Panel::new(
        display,
        FakeBacklight {
            level: Level::Off,
            fail: true,
        },
        Size::new(16, 8),
    );
    assert_eq!(
        failing.set_backlight(Level::Level(1)).err(),
        Some(Error::Io)
    );
}

/// The panel's size is what it was built with.
#[test]
fn the_size_is_fixed_at_construction() {
    let (p, _) = panel(240, 320);
    assert_eq!(p.size(), Size::new(240, 320));
    assert_eq!(p.size().pixels(), 76_800);
}
