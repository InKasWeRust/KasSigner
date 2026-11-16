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

//! The drawing itself: the gauge, blending, bands, corners, codes, text, the
//! scale, pages and the preview pictures.

use super::*;

/// Home shows a battery only when a reading says what a cell holds: nothing
/// for a failed or implausible read, or for 100% where full and absent read
/// the same; the empty outline when no cell is fitted.
#[test]
fn the_gauge_shows_only_what_a_reading_knows() {
    use kassigner_hal::battery::{BatteryStatus, ChargeState, Error, Reading};
    let cell = |present, percentage, state| {
        Ok(Reading::Battery(BatteryStatus {
            present,
            voltage_mv: 3900,
            percentage,
            state,
        }))
    };
    assert_eq!(
        brand::Gauge::of(cell(Some(true), 72, ChargeState::Discharging)),
        Some(gauge(72, false))
    );
    assert_eq!(
        brand::Gauge::of(cell(Some(true), 100, ChargeState::Charging)),
        Some(gauge(100, true))
    );
    assert_eq!(
        brand::Gauge::of(cell(Some(false), 0, ChargeState::Unknown)),
        Some(brand::Gauge::Empty),
        "no cell fitted"
    );
    assert_eq!(
        brand::Gauge::of(cell(None, 100, ChargeState::Unknown)),
        None,
        "full, or no cell"
    );
    assert_eq!(
        brand::Gauge::of(cell(None, 64, ChargeState::Unknown)),
        Some(gauge(64, false))
    );
    assert_eq!(brand::Gauge::of(Ok(Reading::Implausible { raw: 12 })), None);
    assert_eq!(brand::Gauge::of(Err(Error::Io)), None);
}

/// A level one point from the one shown leaves it shown, so Home's figure
/// does not flick on a cell's few millivolts of wander. Two points or more,
/// the charger starting or stopping, the cell fitted or removed, or a failed
/// read change it.
#[test]
fn the_gauge_holds_a_point_of_wander() {
    use brand::Gauge;
    let after = Gauge::after;
    assert_eq!(
        after(Some(gauge(72, false)), Some(gauge(71, false))),
        Some(gauge(72, false))
    );
    assert_eq!(
        after(Some(gauge(72, false)), Some(gauge(73, false))),
        Some(gauge(72, false))
    );
    assert_eq!(
        after(Some(gauge(72, false)), Some(gauge(70, false))),
        Some(gauge(70, false))
    );
    assert_eq!(
        after(Some(gauge(72, false)), Some(gauge(72, true))),
        Some(gauge(72, true))
    );
    assert_eq!(
        after(Some(gauge(72, false)), Some(Gauge::Empty)),
        Some(Gauge::Empty)
    );
    assert_eq!(
        after(Some(Gauge::Empty), Some(gauge(40, false))),
        Some(gauge(40, false))
    );
    assert_eq!(after(Some(gauge(72, false)), None), None);
    assert_eq!(after(None, Some(gauge(72, false))), Some(gauge(72, false)));
}

/// Redrawing only the battery's zone turns Home with one battery into Home
/// with another, pixel for pixel, on both panels: the zone holds nothing
/// else of Home.
#[test]
fn the_gauge_is_redrawn_in_its_zone_alone() {
    let batteries = [
        None,
        Some(brand::Gauge::Empty),
        Some(gauge(8, false)),
        Some(gauge(22, false)),
        Some(gauge(100, true)),
        Some(gauge(100, false)),
    ];
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let z = brand::gauge_zone(scale);
        let area = Rect::new(z.x, z.y, z.width, z.height);
        let drawn = |battery: Option<brand::Gauge>| {
            let mut panel = Panel::new(size.width, size.height);
            let mut buf = vec![0u16; usize::from(size.width) * 8];
            let at = whole(&panel);
            render(&mut panel, at, BACKGROUND, &mut buf, |b| {
                brand::home(b, scale, kit, None, battery)
            })
            .unwrap();
            panel
        };
        let bare = drawn(None);
        for y in z.y..z.y + z.height {
            for x in z.x..z.x + z.width {
                assert_eq!(bare.at(x, y), BACKGROUND, "Home itself at ({x}, {y})");
            }
        }
        for from in batteries {
            for to in batteries {
                let mut panel = drawn(from);
                let mut buf = vec![0u16; usize::from(size.width) * 8];
                render(&mut panel, area, BACKGROUND, &mut buf, |b| {
                    brand::home(b, scale, kit, None, to)
                })
                .unwrap();
                assert!(
                    panel.px == drawn(to).px,
                    "{size:?}: {from:?} redrawn as {to:?}"
                );
            }
        }
    }
}

#[test]
fn blend_keeps_its_ends() {
    let (bg, fg) = (rgb565(3, 10, 20), rgb565(30, 50, 1));
    assert_eq!(blend(bg, fg, 0), bg);
    assert_eq!(blend(bg, fg, 255), fg);
    assert_eq!(blend(0x0000, 0xFFFF, 128), rgb565(16, 32, 16));
}

#[test]
fn every_pixel_of_the_area_is_written_once() {
    let mut panel = Panel::new(320, 240);
    let area = Rect::new(10, 20, 100, 50);
    // Seven rows a band: fifty rows need eight bands, the last one short.
    let mut buf = [0u16; 700];
    render(&mut panel, area, 0x0F0F, &mut buf, |_| {}).unwrap();
    for y in 0..240u16 {
        for x in 0..320u16 {
            let inside =
                x >= area.x && x < area.x + area.width && y >= area.y && y < area.y + area.height;
            let i = usize::from(y) * 320 + usize::from(x);
            assert_eq!(panel.writes[i], u32::from(inside), "({x}, {y})");
        }
    }
    assert_eq!(panel.at(10, 20), 0x0F0F);
}

#[test]
fn render_refuses_what_does_not_fit() {
    let mut panel = Panel::new(320, 240);
    let mut buf = [0u16; 99];
    let err = render(&mut panel, Rect::new(0, 0, 100, 10), 0, &mut buf, |_| {});
    assert_eq!(
        err,
        Err(Error::WrongLength {
            expected: 100,
            got: 99
        })
    );
    let mut buf = [0u16; 320];
    let err = render(&mut panel, Rect::new(300, 0, 30, 10), 0, &mut buf, |_| {});
    assert!(matches!(err, Err(Error::OutOfBounds { .. })));
    assert!(panel.writes.iter().all(|&n| n == 0));
}

/// A screen drawn a row at a time is the screen drawn whole: nothing a
/// painter does depends on where the band boundaries fall.
#[test]
fn bands_do_not_show() {
    for size in SIZES {
        for (name, paint) in screens(size) {
            let mut one = Panel::new(size.width, size.height);
            let mut buf = vec![0u16; usize::from(size.width)];
            let area = whole(&one);
            render(&mut one, area, BACKGROUND, &mut buf, |b| paint(b)).unwrap();

            let mut all = Panel::new(size.width, size.height);
            let mut buf = vec![0u16; size.pixels()];
            let area = whole(&all);
            render(&mut all, area, BACKGROUND, &mut buf, |b| paint(b)).unwrap();
            assert!(one.px == all.px, "{name} at {size:?}");
        }
    }
}

#[test]
fn rounded_corners_are_smoothed() {
    let mut panel = Panel::new(40, 40);
    let mut buf = [0u16; 40 * 40];
    let area = whole(&panel);
    render(&mut panel, area, 0x0000, &mut buf, |b| {
        b.rounded(0, 0, 40, 40, 10, 0xFFFF)
    })
    .unwrap();
    assert_eq!(panel.at(0, 0), 0x0000, "the corner itself is outside");
    assert_eq!(panel.at(20, 20), 0xFFFF, "the middle is inside");
    assert_eq!(
        panel.at(10, 0),
        0xFFFF,
        "the top edge past the corner is inside"
    );
    let edge = panel.at(1, 5);
    assert!(
        edge != 0x0000 && edge != 0xFFFF,
        "a pixel on the curve is part covered: {edge:#06x}"
    );
}

/// A box with no width or height draws nothing and does not panic, even at
/// -2 or less, where clamping the radius to half the shorter side would.
#[test]
fn a_box_with_no_room_draws_nothing() {
    let mut panel = Panel::new(40, 40);
    let mut buf = [0u16; 40 * 40];
    let area = whole(&panel);
    render(&mut panel, area, 0x0000, &mut buf, |b| {
        for (w, h) in [(-2, 10), (10, -2), (-40, -40), (0, 10), (10, 0)] {
            b.rounded(10, 10, w, h, 4, 0xFFFF);
        }
    })
    .unwrap();
    assert!(panel.px.iter().all(|&p| p == 0x0000), "nothing drawn");
}

/// A code wider than 320 pixels is painted in row pieces of 320 with every
/// module in place, checked module by module since the camera's decoder
/// does not take modules this large.
#[test]
fn a_code_is_painted_on_a_larger_panel() {
    use kassigner_fw::paint::{self, BLACK, WHITE};
    let code = kassigner_qr::encode::encode(b"kassigner, a code wider than one row piece").unwrap();
    let (w, h) = (800usize, 600usize);
    let mut panel = Panel::new(w as u16, h as u16);
    paint::draw_code(&mut panel, &code, 10);

    // The white square, then the square the dark modules span inside it,
    // which is the code's own: finder patterns fill three of its corners.
    let bbox = |pick: &dyn Fn(usize, usize) -> bool| {
        let (mut x0, mut y0, mut x1, mut y1) = (w, h, 0, 0);
        for y in 0..h {
            for x in 0..w {
                if pick(x, y) {
                    (x0, y0, x1, y1) = (x0.min(x), y0.min(y), x1.max(x + 1), y1.max(y + 1));
                }
            }
        }
        (x0, y0, x1, y1)
    };
    let white = bbox(&|x, y| panel.px[y * w + x] == WHITE);
    let (x0, y0, x1, y1) = bbox(&|x, y| {
        (white.0..white.2).contains(&x)
            && (white.1..white.3).contains(&y)
            && panel.px[y * w + x] == BLACK
    });
    let side = x1 - x0;
    assert_eq!(side, y1 - y0, "a square code");
    assert!(side > 320, "wider than one piece: {side}");
    let n = usize::from(code.size);
    for my in 0..n {
        for mx in 0..n {
            let x = x0 + (2 * mx + 1) * side / (2 * n);
            let y = y0 + (2 * my + 1) * side / (2 * n);
            let want = if code.get(mx as u8, my as u8) {
                BLACK
            } else {
                WHITE
            };
            assert_eq!(
                panel.px[y * w + x],
                want,
                "module ({mx}, {my}) at ({x}, {y})"
            );
        }
    }
}

#[test]
fn text_is_drawn_and_measured() {
    let font = SMALL.body;
    let mut panel = Panel::new(320, 40);
    let mut buf = [0u16; 320 * 40];
    let mut moved = 0;
    let area = whole(&panel);
    render(&mut panel, area, 0x0000, &mut buf, |b| {
        moved = b.text(font, 10, 25, TEXT, "Kaspa")
    })
    .unwrap();
    assert_eq!(moved, font.width("Kaspa"));
    assert!(panel.px.contains(&TEXT), "some pixels fully covered");
    assert!(
        panel.px.iter().any(|&p| p != TEXT && p != 0),
        "and some edges"
    );
    // Anything but printable ASCII is a filled block in the text's colour,
    // as wide as a digit and as tall as a capital, not a `?`, which a text
    // can hold. One block a character, whatever its length in UTF-8.
    for c in ["é", "\u{7f}", "\u{1F600}", "\t"] {
        assert_eq!(font.width(c), font.width("0"), "{c:?}");
    }
    let g = font.glyph('\u{7f}');
    let capital = font.glyph('H');
    assert_eq!((g.top, g.height), (capital.top, capital.height));
    let mut panel = Panel::new(320, 40);
    let area = whole(&panel);
    render(&mut panel, area, 0x0000, &mut buf, |b| {
        b.text(font, 10, 25, ACCENT, "\u{7f}");
    })
    .unwrap();
    let (left, top) = (10 + i32::from(g.left), 25 - i32::from(g.top));
    for y in 0..40i32 {
        for x in 0..320i32 {
            let inside = (left..left + i32::from(g.width)).contains(&x)
                && (top..top + i32::from(g.height)).contains(&y);
            let want = if inside { ACCENT } else { 0x0000 };
            assert_eq!(panel.px[(y * 320 + x) as usize], want, "({x}, {y})");
        }
    }
}

#[test]
fn the_scale_fits_the_design() {
    let s = Scale::for_panel(Size::new(320, 240));
    assert_eq!((s.x(0), s.y(0), s.len(320), s.len(240)), (0, 0, 320, 240));
    // 480 by 320 is height-bound: four thirds, and 26 columns each side.
    let s = Scale::for_panel(Size::new(480, 320));
    assert_eq!((s.len(240), s.len(320), s.y(0)), (320, 427, 0));
    assert_eq!(s.x(0), 26);
}

#[test]
fn pages_are_counted_as_drawn() {
    assert_eq!(menu::pages(&menu::TOOLS), 1);
    assert_eq!(menu::pages(&menu::SETTINGS), 2);
    assert_eq!(menu::pages(&menu::SETTINGS_NO_AUDIO), 1);
    // A setting's screen goes back to the page its row is on.
    assert_eq!(menu::page_of(&menu::SETTINGS, menu::Setting::About), 1);
    assert_eq!(menu::page_of(&menu::SETTINGS, menu::Setting::SdCard), 0);
    assert_eq!(
        menu::page_of(&menu::SETTINGS_NO_AUDIO, menu::Setting::About),
        0
    );
    assert_eq!(menu::pages(&menu::SEED_TOOLS), 2);
    // Every seed and one `+`, three to a page.
    assert_eq!(seeds::pages(&SEEDS, CAPACITY), 2);
    assert_eq!(seeds::pages(&SEEDS[..2], CAPACITY), 1);
    assert_eq!(seeds::pages(&SEEDS[..3], CAPACITY), 2);
    // Full: no `+`.
    assert_eq!(seeds::pages(&SEEDS[..3], 3), 1);
    assert_eq!(seeds::pages(&[], CAPACITY), 1);
}

/// A level's percentage, and a tap on the bar's ends.
#[test]
fn a_level_reads_as_a_percentage() {
    let mut buf = [0u8; 4];
    assert_eq!(settings::percent(0, &mut buf), "0%");
    assert_eq!(settings::percent(25, &mut buf), "9%");
    assert_eq!(settings::percent(128, &mut buf), "50%");
    assert_eq!(settings::percent(255, &mut buf), "100%");
    assert_eq!(settings::percent_of(0x0F, 0x0F, &mut buf), "100%");
    assert_eq!(settings::percent_of(0x20, 0x3F, &mut buf), "50%");
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let track = camtune::zone(scale, 7, true, camtune::Target::Track).unwrap();
        assert_eq!(
            camtune::value_at(scale, 0x3F, track.x + track.width - 1),
            0x3F
        );
        assert_eq!(camtune::value_at(scale, 0x3F, 0), 0);
    }
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let bar = settings::zone(scale, settings::Target::Bar).unwrap();
        assert_eq!(settings::level_at(scale, bar.x), 0, "{size:?}");
        assert_eq!(
            settings::level_at(scale, bar.x + bar.width - 1),
            255,
            "{size:?}"
        );
        // Only the bar and the percentage change with the level.
        let area = settings::level_area(scale);
        assert!(Rect::new(area.x, area.y, area.width, area.height).fits(size));
    }
}

/// With `UI_PREVIEW` set, every brand screen as a picture.
#[test]
fn previews() {
    let Some(dir) = std::env::var_os("UI_PREVIEW") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    for size in SIZES {
        for (name, paint) in screens(size) {
            let mut panel = Panel::new(size.width, size.height);
            let mut buf = vec![0u16; usize::from(size.width) * 16];
            let area = whole(&panel);
            render(&mut panel, area, BACKGROUND, &mut buf, |b| paint(b)).unwrap();
            let mut ppm = format!("P6 {} {} 255\n", size.width, size.height).into_bytes();
            for p in &panel.px {
                let (r, g, b) = ((p >> 11) & 0x1F, (p >> 5) & 0x3F, p & 0x1F);
                ppm.extend([
                    (r * 255 / 31) as u8,
                    (g * 255 / 63) as u8,
                    (b * 255 / 31) as u8,
                ]);
            }
            let file = dir.join(format!("{name}_{}x{}.ppm", size.width, size.height));
            std::fs::write(file, ppm).unwrap();
        }
    }
}

/// Every screen at the P4's size draws the same with the stretched-picture
/// store as without, and drawn again the store makes nothing new.
#[test]
fn stretched_pictures_are_kept_and_the_same() {
    use kassigner_fw::ui::band::{render_with, Stretched};
    let size = Size::new(480, 320);
    let store: &'static mut [u16] = Box::leak(vec![0u16; 160_000].into_boxed_slice());
    let mut kept = Stretched::new(store);
    for (name, paint) in screens(size) {
        let mut plain = Panel::new(size.width, size.height);
        let mut cached = Panel::new(size.width, size.height);
        let mut buf = vec![0u16; usize::from(size.width) * 16];
        let area = whole(&plain);
        render(&mut plain, area, BACKGROUND, &mut buf, |b| paint(b)).unwrap();
        render_with(
            &mut cached,
            area,
            BACKGROUND,
            &mut buf,
            Some(&mut kept),
            |b| paint(b),
        )
        .unwrap();
        assert!(plain.px == cached.px, "{name} differs with the store");
        let before = kept.kept();
        render_with(
            &mut cached,
            area,
            BACKGROUND,
            &mut buf,
            Some(&mut kept),
            |b| paint(b),
        )
        .unwrap();
        assert_eq!(kept.kept(), before, "{name} made something twice");
        assert!(plain.px == cached.px, "{name} differs drawn again");
    }
    let (pictures, pixels) = kept.kept();
    println!("kept {pictures} pictures, {pixels} pixels");
    assert!(pictures > 0);
}

/// Every version's code, centred or at the left, has three and a half
/// modules of white each side and modules of four pixels or more, and reads
/// back with the camera's decoder. ISO 18004's four would shrink a version
/// 9's modules to 3.92 pixels on a 240-pixel panel, which the decoder misses.
#[test]
fn every_code_has_three_and_a_half_modules_of_white_around_it() {
    use kassigner_fw::paint::{self, BLACK, WHITE};
    use kassigner_qr::capacity::{byte_capacity, MAX_VERSION};
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let margin = u16::try_from(scale.len(10)).unwrap();
        let (w, h) = (usize::from(size.width), usize::from(size.height));
        for version in 1..=MAX_VERSION {
            // Lower case, so the encoder takes bytes and the version is
            // the one whose capacity this fills.
            let len = byte_capacity(version).unwrap();
            let data: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
            let code = kassigner_qr::encode::encode(&data).unwrap();
            let n = i64::from(code.size);
            assert_eq!(n, 17 + 4 * i64::from(version), "version {version}");
            for left in [false, true] {
                let mut panel = Panel::new(size.width, size.height);
                if left {
                    paint::draw_code_left(&mut panel, &code, margin);
                } else {
                    paint::draw_code(&mut panel, &code, margin);
                }
                let what = format!("version {version}, left {left}, {size:?}");
                // The white square, then the dark modules inside it.
                let bbox = |pick: &dyn Fn(usize, usize) -> bool| {
                    let (mut x0, mut y0, mut x1, mut y1) = (w, h, 0, 0);
                    for y in 0..h {
                        for x in 0..w {
                            if pick(x, y) {
                                (x0, y0, x1, y1) =
                                    (x0.min(x), y0.min(y), x1.max(x + 1), y1.max(y + 1));
                            }
                        }
                    }
                    (x0 as i64, y0 as i64, x1 as i64, y1 as i64)
                };
                let white = bbox(&|x, y| panel.px[y * w + x] == WHITE);
                let inside = |x: usize, y: usize| {
                    (white.0..white.2).contains(&(x as i64))
                        && (white.1..white.3).contains(&(y as i64))
                };
                let dark = bbox(&|x, y| inside(x, y) && panel.px[y * w + x] == BLACK);
                let side = dark.2 - dark.0;
                assert_eq!(side, dark.3 - dark.1, "{what}: a square code");
                let quiet = [
                    dark.0 - white.0,
                    white.2 - dark.2,
                    dark.1 - white.1,
                    white.3 - dark.3,
                ];
                assert!(
                    side >= 4 * n,
                    "{what}: modules under four pixels, {side} px a side"
                );
                for q in quiet {
                    assert!(
                        2 * q * n >= 7 * side,
                        "{what}: {q} px of white beside a code {side} px a side, {:.2} modules",
                        (q * n) as f64 / side as f64
                    );
                }
                // Read back off the panel as drawn.
                let mut gray: Vec<u8> = panel
                    .px
                    .iter()
                    .map(|&p| if p == WHITE { 255 } else { 0 })
                    .collect();
                let mut scratch = kassigner_qr::Scratch::new();
                let mut decoder = kassigner_qr::Decoder::new(&mut scratch);
                let mut out = [0u8; 512];
                let got = decoder
                    .decode(w, h, 8, &mut gray, &mut out)
                    .unwrap_or_else(|e| panic!("{what}: does not read back: {e:?}"));
                assert_eq!(&out[..got.len], &data[..], "{what}: reads back");
            }
        }
    }
}
