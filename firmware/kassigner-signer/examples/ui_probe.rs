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

//! The brand screens on a unit: how they look, how long they take to draw,
//! and what memory drawing them uses.
//!
//! ```text
//! cargo +esp195 m5-ui
//! cargo +esp195 ws-ui
//! cargo +esp195 p4-ui
//! ```
//!
//! The logo screen, then the home grid. Seeds, Tools and Settings open their
//! screens, with working back, home and page buttons; the seeds screen shows
//! `ui::seeds::SAMPLE`'s rows, a tap on one making it the one in use. Other
//! targets only say on the console what they would do; the home grid's
//! header shows the logo screen again. A target lights under a finger and
//! is tapped when the finger lifts on it; a touch
//! `kassigner_fw::touch::Tracker` never confirms is "ignored".
//!
//! # What it prints
//!
//! The band's size, on the main stack, and the stack the renderer adds below
//! it; the time of each full screen and each redraw of a lit target; the
//! heap (PSRAM) in use before and after drawing, which should match, as the
//! band renderer takes none. Then a line per touch, tap or not:
//!
//! ```text
//! touch 96 ms: 212 reads, 9 changes, 0 bus errors; down PressDown (291, 12), up LiftUp (293, 14); began 1840 ms after a draw
//! ```
//!
//! How long the finger was down; the panel reads meanwhile and how many
//! changed (how often the controller updated); read failures since the last
//! line; the first and last report with their events; and how long after
//! the last draw the touch began. A real tap and a phantom one differ here.

#![cfg_attr(any(target_arch = "xtensa", target_arch = "riscv32"), no_std)]
#![cfg_attr(any(target_arch = "xtensa", target_arch = "riscv32"), no_main)]
#![forbid(unsafe_code)]

#[cfg(any(
    all(feature = "m5stack", feature = "waveshare"),
    all(feature = "m5stack", feature = "p4"),
    all(feature = "waveshare", feature = "p4")
))]
compile_error!("pick one unit: --features m5stack, --features waveshare or --features p4");

#[cfg(all(
    any(target_arch = "xtensa", target_arch = "riscv32"),
    not(any(feature = "m5stack", feature = "waveshare", feature = "p4"))
))]
compile_error!("the probe needs a unit: --features m5stack, waveshare or p4");

/// A host build compiles this and nothing else: the probe is for a unit.
#[cfg(not(any(target_arch = "xtensa", target_arch = "riscv32")))]
fn main() {}

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
#[path = "../src/heap.rs"]
mod heap;

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
mod common;

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
mod device {
    use esp_hal::clock::CpuClock;
    use esp_hal::main;
    use esp_println::println;

    use kassigner_fw::touch::{Action, Tracker, Zone};
    use kassigner_fw::ui::band::{render, Band};
    use kassigner_fw::ui::brand;
    use kassigner_fw::ui::chrome::Nav;
    use kassigner_fw::ui::color::BACKGROUND;
    use kassigner_fw::ui::menu::{self, Menu};
    use kassigner_fw::ui::scale::{Kit, Scale};
    use kassigner_fw::ui::seeds::{self, Seed};
    use kassigner_fw::wipe::Mark;
    use kassigner_hal::display::{Display, Rect};
    use kassigner_hal::input::{Point, Touch};
    use kassigner_hal::timer::Timer;

    use crate::common::UNIT;

    // ── The board-dependent lines ────────────────────────────────────────
    #[cfg(feature = "p4")]
    use kassigner_hal_esp32p4::{stack, unit};
    #[cfg(feature = "m5stack")]
    use kassigner_hal_esp32s3::m5stack::unit;
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    use kassigner_hal_esp32s3::stack;
    #[cfg(feature = "waveshare")]
    use kassigner_hal_esp32s3::waveshare::unit;

    esp_bootloader_esp_idf::esp_app_desc!();

    /// The panel's width and the fonts and icons cut for it (320 by 240 on
    /// the S3 units, 480 by 320 on the P4), fixed at build time so the other
    /// set's tables stay out of the image.
    #[cfg(feature = "p4")]
    const WIDTH: usize = 480;
    #[cfg(feature = "p4")]
    static KIT: &Kit = &kassigner_fw::ui::scale::LARGE;
    #[cfg(not(feature = "p4"))]
    const WIDTH: usize = 320;
    #[cfg(not(feature = "p4"))]
    static KIT: &Kit = &kassigner_fw::ui::scale::SMALL;

    /// The settings this unit has: every one on the M5Stack and the P4, and
    /// all but Audio on the Waveshare, which has no speaker.
    #[cfg(any(feature = "m5stack", feature = "p4"))]
    static SETTINGS: &Menu = &menu::SETTINGS;
    #[cfg(feature = "waveshare")]
    static SETTINGS: &Menu = &menu::SETTINGS_NO_AUDIO;

    /// Rows a band holds.
    const BAND_ROWS: usize = 16;

    /// The version, as the logo screen shows it.
    const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

    /// How long the logo screen stays, in milliseconds.
    const LOGO_MS: u32 = 2_500;

    #[main]
    fn main() -> ! {
        let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
        println!("KasSigner UI probe, {UNIT}");
        let anchor = Mark::here();

        // The board up and the heap made as the firmware does, through
        // `heap.rs`.

        #[cfg(feature = "waveshare")]
        let up = unit::bring_up(
            peripherals,
            kassigner_hal_esp32s3::waveshare::sensor::Module::AutoFocus,
            super::heap::make,
        );
        #[cfg(not(feature = "waveshare"))]
        let up = unit::bring_up(peripherals, super::heap::make);
        let (mut unit, _checks) = match up {
            Ok(up) => up,
            Err(e) => {
                println!("HALT: the board did not come up: {e:?}");
                loop {
                    core::hint::spin_loop();
                }
            }
        };

        let size = unit.lcd.size();
        let scale = Scale::for_panel(size);
        let whole = Rect::new(0, 0, size.width, size.height);
        let mut band = [BACKGROUND; WIDTH * BAND_ROWS];
        let (bottom, top) = stack::core0();
        println!(
            "panel {}x{}; band {} rows, {} bytes, on the main stack {:#x}..{:#x}",
            size.width,
            size.height,
            BAND_ROWS,
            core::mem::size_of_val(&band),
            bottom,
            top
        );

        let heap_before = esp_alloc::HEAP.used();
        let mut deepest = anchor.addr();

        // ── The logo screen, then the home grid ──────────────────────────
        let started = unit.timer.now_us();
        let drawn = render(&mut unit.lcd, whole, BACKGROUND, &mut band, |b| {
            deepest = deepest.min(Mark::here().addr());
            brand::logo(b, scale, KIT, VERSION, UNIT);
        });
        println!("logo screen: {} us ({drawn:?})", unit.timer.since(started));
        unit.timer.delay_ms(LOGO_MS);

        let mut rows = seeds::SAMPLE;
        let mut screen = Screen::Home;
        let started = unit.timer.now_us();
        let drawn = render(&mut unit.lcd, whole, BACKGROUND, &mut band, |b| {
            deepest = deepest.min(Mark::here().addr());
            paint(b, scale, screen, &rows, None);
        });
        println!("home grid: {} us ({drawn:?})", unit.timer.since(started));
        let mut drawn_at = unit.timer.now_us();

        println!(
            "heap (PSRAM) in use: {} bytes before drawing, {} after",
            heap_before,
            esp_alloc::HEAP.used()
        );
        println!(
            "stack the renderer adds below main's frame: {} bytes (the band is in main's frame)",
            anchor.addr() - deepest
        );
        println!("tap around; the home grid's header shows the logo screen again");

        // ── Touch ────────────────────────────────────────────────────────
        //
        // Each good read goes to the tracker, which says when a touch is a
        // finger, where it moves and where it lifts; the trace beside it is
        // only for the console. The M5's controller has not been seen to
        // report a touch nobody made, and its quick tap can arrive as one
        // `PressDown` read, so first reports are trusted there; the
        // Waveshare and the P4 report phantom touches and keep the filter.
        let mut tracker = if cfg!(feature = "m5stack") {
            Tracker::trusting_first_report()
        } else {
            Tracker::new()
        };
        let mut touch: Option<Trace> = None;
        let mut errors = 0u32;
        // `landed`: what the finger landed on, if anything; `lit`: the same
        // target while the finger is still over it, drawn lit.
        let mut landed: Option<Hit> = None;
        let mut lit: Option<Hit> = None;
        // What the screen shows lit, so a redraw happens only on a change.
        let mut shown: Option<Hit> = None;
        loop {
            let Ok(state) = unit.touch.read() else {
                errors += 1;
                continue;
            };
            // The console's line, when a touch ends.
            let now = unit.timer.now_us();
            if let Some(p) = state.first() {
                if touch.is_none() {
                    touch = Some(Trace::new(p, now, drawn_at, errors));
                    errors = 0;
                }
                if let Some(t) = touch.as_mut() {
                    t.read(p, now);
                }
            } else if let Some(t) = touch.take() {
                t.say();
            }

            let Some(action) = tracker.read(state, now) else {
                continue;
            };
            match action {
                Action::Down { x, y } => {
                    landed = hit(scale, screen, &rows, x, y);
                    lit = landed;
                }
                Action::Moved { x, y } => {
                    lit = landed.filter(|&h| {
                        zone(scale, screen, &rows, h).is_some_and(|z| z.contains(x, y))
                    });
                }
                Action::Ignored { x, y } => {
                    println!("ignored: a touch never confirmed, at ({x}, {y})");
                    continue;
                }
                Action::Up { .. } => {
                    let tapped = lit.take().and(landed.take());
                    shown = None;
                    let Some(h) = tapped else {
                        continue;
                    };
                    let (next, logo) = act(screen, h, &mut rows);
                    if logo {
                        let _ = render(&mut unit.lcd, whole, BACKGROUND, &mut band, |b| {
                            brand::logo(b, scale, KIT, VERSION, UNIT)
                        });
                        unit.timer.delay_ms(LOGO_MS);
                    }
                    // The same screen too: the light goes out and a change of
                    // seed shows.
                    screen = next;
                    let started = unit.timer.now_us();
                    let drawn = render(&mut unit.lcd, whole, BACKGROUND, &mut band, |b| {
                        paint(b, scale, screen, &rows, None)
                    });
                    drawn_at = unit.timer.now_us();
                    println!(
                        "{}: {} us ({drawn:?})",
                        name(screen),
                        unit.timer.since(started)
                    );
                    continue;
                }
            }

            // Down or Moved: redraw what landed if its light changed.
            if lit != shown {
                shown = lit;
                if let Some(z) = landed.and_then(|h| zone(scale, screen, &rows, h)) {
                    let started = unit.timer.now_us();
                    let area = Rect::new(z.x, z.y, z.width, z.height);
                    let drawn = render(&mut unit.lcd, area, BACKGROUND, &mut band, |b| {
                        paint(b, scale, screen, &rows, lit)
                    });
                    drawn_at = unit.timer.now_us();
                    println!(
                        "{:?} {}: {} us ({drawn:?})",
                        landed,
                        if lit.is_some() { "lit" } else { "released" },
                        unit.timer.since(started)
                    );
                }
            }
        }
    }

    /// One touch, as the console reports it.
    struct Trace {
        /// When the first report with a finger in it was read.
        began_us: u64,
        /// How long after the last draw finished that was.
        after_draw_us: u64,
        /// When the last one was.
        last_us: u64,
        /// Reads that found a finger, and how many differed from the one
        /// before.
        reads: u32,
        changes: u32,
        /// Read failures since the last touch's line.
        errors: u32,
        first: Point,
        last: Point,
    }

    impl Trace {
        fn new(p: Point, now_us: u64, drawn_at_us: u64, errors: u32) -> Self {
            Self {
                began_us: now_us,
                after_draw_us: now_us.saturating_sub(drawn_at_us),
                last_us: now_us,
                reads: 0,
                changes: 0,
                errors,
                first: p,
                last: p,
            }
        }

        /// Another read with a finger in it.
        fn read(&mut self, p: Point, now_us: u64) {
            if self.reads > 0 && p != self.last {
                self.changes += 1;
            }
            self.reads += 1;
            self.last = p;
            self.last_us = now_us;
        }

        /// The console line.
        fn say(&self) {
            println!(
                "touch {} ms: {} reads, {} changes, {} bus errors; down {:?} ({}, {}), up {:?} ({}, {}); began {} ms after a draw",
                (self.last_us - self.began_us) / 1000,
                self.reads,
                self.changes,
                self.errors,
                self.first.event,
                self.first.x,
                self.first.y,
                self.last.event,
                self.last.x,
                self.last.y,
                self.after_draw_us / 1000
            );
        }
    }

    /// Where the probe is.
    #[derive(Clone, Copy)]
    enum Screen {
        Home,
        Seeds { page: usize },
        Menu { menu: &'static Menu, page: usize },
    }

    /// A screen's name, for the console.
    fn name(screen: Screen) -> &'static str {
        match screen {
            Screen::Home => "home grid",
            Screen::Seeds { .. } => "seeds",
            Screen::Menu { menu, .. } => menu.title,
        }
    }

    /// Something tappable, on whichever screen is up.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Hit {
        Home(brand::Target),
        Seeds(seeds::Target),
        Menu(menu::Target),
    }

    /// What is under a point.
    fn hit(scale: Scale, screen: Screen, rows: &[Seed], x: u16, y: u16) -> Option<Hit> {
        let cap = seeds::SAMPLE_CAPACITY;
        match screen {
            Screen::Home => brand::target(scale, x, y).map(Hit::Home),
            Screen::Seeds { page } => seeds::target(scale, rows, cap, page, x, y).map(Hit::Seeds),
            Screen::Menu { menu, page } => menu::target(scale, menu, page, x, y).map(Hit::Menu),
        }
    }

    /// Where a target is, from the screen's own function.
    fn zone(scale: Scale, screen: Screen, rows: &[Seed], h: Hit) -> Option<Zone> {
        let cap = seeds::SAMPLE_CAPACITY;
        match (screen, h) {
            (Screen::Home, Hit::Home(t)) => Some(brand::zone(scale, t)),
            (Screen::Seeds { page }, Hit::Seeds(t)) => seeds::zone(scale, rows, cap, page, t),
            (Screen::Menu { menu, page }, Hit::Menu(t)) => menu::zone(scale, menu, page, t),
            _ => None,
        }
    }

    /// Draw the screen that is up, with `lit` lit.
    fn paint(band: &mut Band<'_>, scale: Scale, screen: Screen, rows: &[Seed], lit: Option<Hit>) {
        let cap = seeds::SAMPLE_CAPACITY;
        match screen {
            Screen::Home => {
                let lit = lit.and_then(|h| if let Hit::Home(t) = h { Some(t) } else { None });
                brand::home(band, scale, KIT, lit, None);
            }
            Screen::Seeds { page } => {
                let lit = lit.and_then(|h| if let Hit::Seeds(t) = h { Some(t) } else { None });
                seeds::draw(band, scale, KIT, rows, cap, page, lit);
            }
            Screen::Menu { menu, page } => {
                let lit = lit.and_then(|h| if let Hit::Menu(t) = h { Some(t) } else { None });
                menu::draw(band, scale, KIT, menu, page, lit);
            }
        }
    }

    /// What a tap does: the screen after it, and whether the logo screen
    /// shows first.
    fn act(screen: Screen, h: Hit, rows: &mut [Seed]) -> (Screen, bool) {
        match (screen, h) {
            (Screen::Home, Hit::Home(brand::Target::Header)) => (Screen::Home, true),
            (Screen::Home, Hit::Home(brand::Target::Card(i))) => match i {
                1 => (Screen::Seeds { page: 0 }, false),
                2 => (
                    Screen::Menu {
                        menu: &menu::TOOLS,
                        page: 0,
                    },
                    false,
                ),
                3 => (
                    Screen::Menu {
                        menu: SETTINGS,
                        page: 0,
                    },
                    false,
                ),
                _ => {
                    println!("{}: nothing behind it yet", brand::LABELS[i]);
                    (screen, false)
                }
            },
            (Screen::Menu { menu, page }, Hit::Menu(t)) => match t {
                menu::Target::Nav(Nav::PageUp) => (
                    Screen::Menu {
                        menu,
                        page: page - 1,
                    },
                    false,
                ),
                menu::Target::Nav(Nav::PageDown) => (
                    Screen::Menu {
                        menu,
                        page: page + 1,
                    },
                    false,
                ),
                menu::Target::Nav(_) => (Screen::Home, false),
                menu::Target::Item(i) => {
                    println!(
                        "{}: {}, nothing behind it yet",
                        menu.title, menu.items[i].label
                    );
                    (screen, false)
                }
            },
            (Screen::Seeds { page }, Hit::Seeds(t)) => {
                let at = |slot: usize| page * 3 + slot;
                match t {
                    seeds::Target::Nav(Nav::PageUp) => (Screen::Seeds { page: page - 1 }, false),
                    seeds::Target::Nav(Nav::PageDown) => (Screen::Seeds { page: page + 1 }, false),
                    seeds::Target::Nav(_) => (Screen::Home, false),
                    seeds::Target::Address | seeds::Target::Export => {
                        println!("{t:?}: nothing behind it yet");
                        (screen, false)
                    }
                    seeds::Target::Row(slot) if at(slot) < rows.len() => {
                        for (i, s) in rows.iter_mut().enumerate() {
                            s.active = i == at(slot);
                        }
                        (screen, false)
                    }
                    seeds::Target::Row(_) => {
                        println!("+: would add a seed");
                        (screen, false)
                    }
                    seeds::Target::Delete(slot) => {
                        println!("delete: would ask to delete sample row {}", at(slot));
                        (screen, false)
                    }
                }
            }
            _ => (screen, false),
        }
    }
}
