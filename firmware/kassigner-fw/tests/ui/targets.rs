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

//! Touch targets: each where it is drawn, and apart from the others.

use super::*;

#[test]
fn every_target_is_where_it_is_drawn_and_apart() {
    for size in SIZES {
        let scale = Scale::for_panel(size);

        let home: Vec<_> = (0..4)
            .map(brand::Target::Card)
            .chain([brand::Target::Header, brand::Target::Logo])
            .map(|t| (t, brand::zone(scale, t)))
            .collect();
        check(size, &home, |x, y| brand::target(scale, x, y), |_, _| false);

        let add_key = kassigner_fw::ui::multisig::add_key(1, 3);
        for m in [
            &menu::TOOLS,
            &menu::SEED_TOOLS,
            &menu::MULTISIG,
            &add_key,
            &menu::SETTINGS,
            &menu::SETTINGS_NO_AUDIO,
        ] {
            for page in 0..menu::pages(m) {
                let navs = [Nav::Back, Nav::Home, Nav::PageUp, Nav::PageDown];
                let zones: Vec<_> = navs
                    .map(menu::Target::Nav)
                    .into_iter()
                    .chain((0..m.items.len()).map(menu::Target::Item))
                    .filter_map(|t| menu::zone(scale, m, page, t).map(|z| (t, z)))
                    .collect();
                check(
                    size,
                    &zones,
                    |x, y| menu::target(scale, m, page, x, y),
                    |_, _| false,
                );
            }
        }

        let levels = [
            settings::Target::Nav(Nav::Back),
            settings::Target::Nav(Nav::Home),
            settings::Target::Minus,
            settings::Target::Plus,
            settings::Target::Bar,
        ];
        let zones: Vec<_> = levels
            .into_iter()
            .filter_map(|t| settings::zone(scale, t).map(|z| (t, z)))
            .collect();
        assert_eq!(zones.len(), 5, "a level screen has its five targets");
        check(
            size,
            &zones,
            |x, y| settings::target(scale, x, y),
            |_, _| false,
        );

        for (knobs, auto) in [(7, true), (8, false), (6, false), (5, false), (1, true)] {
            let zones: Vec<_> = [
                camtune::Target::Exit,
                camtune::Target::Auto,
                camtune::Target::Minus,
                camtune::Target::Plus,
                camtune::Target::Track,
            ]
            .into_iter()
            .chain((0..8).map(camtune::Target::Knob))
            .filter_map(|t| camtune::zone(scale, knobs, auto, t).map(|z| (t, z)))
            .collect();
            assert_eq!(zones.len(), 4 + usize::from(auto) + knobs, "{knobs} {auto}");
            check(
                size,
                &zones,
                |x, y| camtune::target(scale, knobs, auto, x, y),
                |_, _| false,
            );
            // Nothing that counts lies on the picture.
            let view = camtune::viewfinder(scale);
            for (t, z) in &zones {
                assert!(!overlap(z, &view), "{t:?} on the viewfinder at {size:?}");
            }
        }
        let view = camtune::viewfinder(scale);
        for z in [camtune::panel_area(scale), camtune::slider_area(scale)] {
            assert!(
                !overlap(&z, &view),
                "redrawn over the viewfinder at {size:?}"
            );
        }

        let own = [
            backup::Target::Nav(Nav::Back),
            backup::Target::Nav(Nav::Home),
            backup::Target::Import,
            backup::Target::Export,
        ];
        let zones: Vec<_> = own
            .into_iter()
            .map(|t| (t, backup::zone(scale, t).expect("on the screen")))
            .collect();
        check(
            size,
            &zones,
            |x, y| backup::target(scale, x, y),
            |_, _| false,
        );
        // SELECT BACKUP with six: two pages, the arrows where there is a
        // page to go to.
        for page in 0..2 {
            let picks: Vec<_> = [Nav::Back, Nav::Home, Nav::PageUp, Nav::PageDown]
                .map(backup::Pick::Nav)
                .into_iter()
                .chain((0..6).map(backup::Pick::Row))
                .chain((0..6).map(backup::Pick::Trash))
                .filter_map(|p| backup::pick_zone(scale, 6, page, p).map(|z| (p, z)))
                .collect();
            assert_eq!(
                picks.len(),
                2 + 1 + if page == 0 { 8 } else { 4 },
                "page {page}"
            );
            // A row's trash is inside the row, and wins there.
            let inside = |a: backup::Pick, b: backup::Pick| matches!((a, b), (backup::Pick::Row(i), backup::Pick::Trash(j)) if i == j);
            check(
                size,
                &picks,
                |x, y| backup::pick(scale, 6, page, x, y),
                inside,
            );
        }
        let warn = [
            backup::Target::Nav(Nav::Back),
            backup::Target::Nav(Nav::Home),
            backup::Target::Understand,
        ];
        let zones: Vec<_> = warn
            .into_iter()
            .map(|t| (t, backup::zone(scale, t).expect("on the screen")))
            .collect();
        check(
            size,
            &zones,
            |x, y| backup::warning_target(scale, x, y),
            |_, _| false,
        );

        for page in 0..keyboard::PAGES {
            let targets: Vec<_> = [
                keyboard::Target::Nav(Nav::Back),
                keyboard::Target::Nav(Nav::Home),
            ]
            .into_iter()
            .chain(keyboard::keys(page).map(keyboard::Target::Key))
            .collect();
            assert_eq!(targets.len(), 2 + 26 + 6, "page {page}: its keys");
            let zones: Vec<_> = targets
                .into_iter()
                .map(|t| (t, keyboard::zone(scale, page, t).expect("on the page")))
                .collect();
            check(
                size,
                &zones,
                |x, y| keyboard::target(scale, page, keyboard::Mode::Text { full: false }, x, y),
                |_, _| false,
            );
        }
        // Every printable character but space is a key on one page, and
        // space is its own key.
        for c in 0x21..=0x7Eu8 {
            assert!(
                (0..keyboard::PAGES).any(|p| keyboard::zone(
                    scale,
                    p,
                    keyboard::Target::Key(keyboard::Key::Char(c))
                )
                .is_some()),
                "{:?} has no key",
                c as char
            );
        }

        let sd = [
            sd_card::Target::Nav(Nav::Back),
            sd_card::Target::Nav(Nav::Home),
            sd_card::Target::Format,
            sd_card::Target::Test,
        ];
        let zones: Vec<_> = sd
            .into_iter()
            .filter_map(|t| sd_card::zone(scale, t).map(|z| (t, z)))
            .collect();
        assert_eq!(zones.len(), 4, "the SD Card screen has its four targets");
        let present = card::Status::Present(Kind::SdV1);
        check(
            size,
            &zones,
            |x, y| sd_card::target(scale, present, x, y),
            |_, _| false,
        );
        // Without a card the buttons are not there.
        for status in [card::Status::Absent, card::Status::Checking] {
            for t in [sd_card::Target::Format, sd_card::Target::Test] {
                let z = sd_card::zone(scale, t).unwrap();
                let (cx, cy) = (z.x + z.width / 2, z.y + z.height / 2);
                assert_eq!(
                    sd_card::target(scale, status, cx, cy),
                    None,
                    "{t:?} {status:?}"
                );
            }
        }

        let answers = [
            dialog::Target::Nav(Nav::Back),
            dialog::Target::Nav(Nav::Home),
            dialog::Target::Cancel,
            dialog::Target::Accept,
        ];
        let zones: Vec<_> = answers
            .into_iter()
            .filter_map(|t| dialog::zone(scale, t).map(|z| (t, z)))
            .collect();
        assert_eq!(zones.len(), 4, "a dialog has its four targets");
        check(
            size,
            &zones,
            |x, y| dialog::target(scale, x, y),
            |_, _| false,
        );

        for list in [&SEEDS[..], &[]] {
            for page in 0..seeds::pages(list, CAPACITY) {
                let navs = [Nav::Back, Nav::Home, Nav::PageUp, Nav::PageDown];
                let zones: Vec<_> = navs
                    .map(seeds::Target::Nav)
                    .into_iter()
                    .chain([seeds::Target::Address, seeds::Target::Export])
                    .chain((0..3).map(seeds::Target::Row))
                    .chain((0..3).map(seeds::Target::Delete))
                    .filter_map(|t| seeds::zone(scale, list, CAPACITY, page, t).map(|z| (t, z)))
                    .collect();
                let nested = |a: seeds::Target, b: seeds::Target| matches!((a, b), (seeds::Target::Delete(i), seeds::Target::Row(j)) if i == j);
                // A row's middle is its own; its delete button is at the end.
                check(
                    size,
                    &zones,
                    |x, y| seeds::target(scale, list, CAPACITY, page, x, y),
                    nested,
                );
            }
        }
    }
}

/// The Address screen's and the keypad's targets count where drawn and
/// apart on both panels, for a seed at index 0 and past it and a raw key.
#[test]
fn the_address_screen_and_keypad_targets_are_apart() {
    use kassigner_fw::ui::{address, keypad};
    for size in [Size::new(320, 240), Size::new(480, 320)] {
        let scale = Scale::for_panel(size);
        for (single, first) in [(false, true), (false, false), (true, true)] {
            let zones: Vec<_> = [
                address::Target::Nav(Nav::Back),
                address::Target::Nav(Nav::Home),
                address::Target::Address,
                address::Target::Chain,
                address::Target::Before,
                address::Target::Index,
                address::Target::After,
            ]
            .into_iter()
            .filter_map(|t| address::zone(scale, single, first, t).map(|z| (t, z)))
            .collect();
            let expect = if single {
                3
            } else if first {
                6
            } else {
                7
            };
            assert_eq!(zones.len(), expect, "{size:?} {single} {first}");
            check(
                size,
                &zones,
                |x, y| address::target(scale, single, first, x, y),
                |_, _| false,
            );
        }
        let keys = [
            keypad::Key::Digit(1),
            keypad::Key::Digit(5),
            keypad::Key::Digit(9),
            keypad::Key::Digit(0),
            keypad::Key::Clear,
            keypad::Key::Go,
        ];
        let zones: Vec<_> = [
            keypad::Target::Nav(Nav::Back),
            keypad::Target::Nav(Nav::Home),
        ]
        .into_iter()
        .chain(keys.map(keypad::Target::Key))
        .map(|t| (t, keypad::zone(scale, t).unwrap()))
        .collect();
        check(
            size,
            &zones,
            |x, y| keypad::target(scale, x, y),
            |_, _| false,
        );
    }
}

/// The dice and BIP85 screens' targets count where drawn and apart on both
/// panels; UNDO only with a roll to take back, "-" only past index 0.
#[test]
fn the_dice_and_bip85_targets_are_apart() {
    use kassigner_fw::ui::{bip85, dice};
    for size in [Size::new(320, 240), Size::new(480, 320)] {
        let scale = Scale::for_panel(size);
        for rolled in [0usize, 5] {
            let zones: Vec<_> = [
                dice::Target::Nav(Nav::Back),
                dice::Target::Nav(Nav::Home),
                dice::Target::Undo,
            ]
            .into_iter()
            .chain((1..=6).map(dice::Target::Face))
            .filter_map(|t| dice::zone(scale, rolled, t).map(|z| (t, z)))
            .collect();
            assert_eq!(zones.len(), if rolled > 0 { 9 } else { 8 }, "{size:?}");
            check(
                size,
                &zones,
                |x, y| dice::target(scale, rolled, x, y),
                |_, _| false,
            );
        }
        for first in [true, false] {
            let zones: Vec<_> = [
                bip85::Target::Nav(Nav::Back),
                bip85::Target::Nav(Nav::Home),
                bip85::Target::Minus,
                bip85::Target::Index,
                bip85::Target::Plus,
                bip85::Target::Derive,
            ]
            .into_iter()
            .filter_map(|t| bip85::zone(scale, first, t).map(|z| (t, z)))
            .collect();
            assert_eq!(zones.len(), if first { 5 } else { 6 });
            check(
                size,
                &zones,
                |x, y| bip85::target(scale, first, x, y),
                |_, _| false,
            );
        }
    }
}

/// CREATE MULTISIG's targets count where drawn and apart on both panels,
/// each "-" and "+" always a target, as each is always drawn lit.
#[test]
fn the_create_multisig_targets_are_apart() {
    use kassigner_fw::ui::multisig::{target, zone, Row, Target};
    for size in [Size::new(320, 240), Size::new(480, 320)] {
        let scale = Scale::for_panel(size);
        let zones: Vec<_> = [
            Target::Nav(Nav::Back),
            Target::Nav(Nav::Home),
            Target::Minus(Row::Required),
            Target::Plus(Row::Required),
            Target::Minus(Row::Total),
            Target::Plus(Row::Total),
            Target::Next,
        ]
        .into_iter()
        .filter_map(|t| zone(scale, t).map(|z| (t, z)))
        .collect();
        assert_eq!(zones.len(), 7, "{size:?}");
        check(size, &zones, |x, y| target(scale, x, y), |_, _| false);
    }
}

/// SELECT SEED's targets count where drawn and apart on both panels: a row
/// for each seed on the page, an arrow only with a page behind it.
#[test]
fn the_select_seed_targets_are_apart() {
    use seeds::{pick_target, pick_zone, Pick};
    for size in SIZES {
        let scale = Scale::for_panel(size);
        for (seeds, page, live) in [(1, 0, 3), (3, 0, 5), (5, 0, 6), (5, 1, 5), (6, 1, 6)] {
            let zones: Vec<_> = [Nav::Back, Nav::Home, Nav::PageUp, Nav::PageDown]
                .map(Pick::Nav)
                .into_iter()
                .chain((0..seeds::ROWS).map(Pick::Row))
                .filter_map(|t| pick_zone(scale, seeds, page, t).map(|z| (t, z)))
                .collect();
            assert_eq!(zones.len(), live, "{seeds} seeds, page {page}, at {size:?}");
            check(
                size,
                &zones,
                |x, y| pick_target(scale, seeds, page, x, y),
                |_, _| false,
            );
        }
    }
}

/// A group's address screen's targets count where drawn and apart on both
/// panels, "<" only past index 0, and its line fits at its widest between
/// "-" and "+".
#[test]
fn the_group_address_targets_are_apart() {
    use kassigner_fw::ui::address::{group_target, group_zone, Target};
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        for first in [true, false] {
            let zones: Vec<_> = [
                Target::Nav(Nav::Back),
                Target::Nav(Nav::Home),
                Target::CosignerBefore,
                Target::CosignerAfter,
                Target::Address,
                Target::Chain,
                Target::Before,
                Target::Index,
                Target::After,
            ]
            .into_iter()
            .filter_map(|t| group_zone(scale, first, t).map(|z| (t, z)))
            .collect();
            assert_eq!(zones.len(), if first { 8 } else { 9 }, "{size:?}");
            check(
                size,
                &zones,
                |x, y| group_target(scale, first, x, y),
                |_, _| false,
            );
        }
        let w = kit.body.width("5-of-5, cosigner 4");
        assert!(w <= scale.len(152), "the line is {w} wide at {size:?}");

        // A tap past either side of "-", "+", "<" or ">", or 20 below, is
        // still that button, not the address's code; the line between "-"
        // and "+" does nothing; "<" not at index 0.
        let at = |first, x: i32, y: i32| {
            group_target(scale, first, scale.x(x) as u16, scale.y(y) as u16)
        };
        for (x, y) in [(64, 60), (46, 48), (110, 60), (64, 94)] {
            assert_eq!(
                at(false, x, y),
                Some(Target::CosignerBefore),
                "{x},{y} {size:?}"
            );
            assert_eq!(
                at(false, 320 - x, y),
                Some(Target::CosignerAfter),
                "{x},{y} {size:?}"
            );
        }
        assert_eq!(at(false, 160, 60), None, "the line {size:?}");
        assert_eq!(at(false, 160, 80), None, "under the line {size:?}");
        for (x, y) in [(160, 100), (64, 100), (160, 160)] {
            assert_eq!(at(false, x, y), Some(Target::Address), "{x},{y} {size:?}");
        }
        for (x, y) in [(35, 225), (40, 180), (85, 230)] {
            assert_eq!(at(false, x, y), Some(Target::Before), "{x},{y} {size:?}");
            assert_eq!(at(true, x, y), None, "{x},{y} at #0 {size:?}");
            assert_eq!(
                at(false, 320 - x, y),
                Some(Target::After),
                "{x},{y} {size:?}"
            );
        }
        assert_eq!(at(false, 160, 190), Some(Target::Chain), "{size:?}");
    }
}

/// The grid view's strips count where drawn and apart from Back and Home,
/// on both panels.
#[test]
fn the_grid_view_strips_are_apart() {
    use kassigner_fw::ui::seedqr::{target, zone, Target};
    for size in [Size::new(320, 240), Size::new(480, 320)] {
        let scale = Scale::for_panel(size);
        let zones: Vec<_> = [
            Target::Nav(Nav::Back),
            Target::Nav(Nav::Home),
            Target::Left,
            Target::Right,
            Target::Up,
            Target::Down,
        ]
        .into_iter()
        .map(|t| (t, zone(scale, t).unwrap()))
        .collect();
        check(size, &zones, |x, y| target(scale, x, y), |_, _| false);
    }
}

/// KPUB EXPORT QR's two cards count where drawn and apart from Back and
/// Home, on both panels.
#[test]
fn the_kpub_cards_are_apart() {
    use kassigner_fw::ui::kpub::{target, zone, Target};
    for size in [Size::new(320, 240), Size::new(480, 320)] {
        let scale = Scale::for_panel(size);
        let zones: Vec<_> = [
            Target::Nav(Nav::Back),
            Target::Nav(Nav::Home),
            Target::Wallet,
            Target::KasSigner,
        ]
        .into_iter()
        .map(|t| (t, zone(scale, t).unwrap()))
        .collect();
        check(size, &zones, |x, y| target(scale, x, y), |_, _| false);
    }
}

/// Each camera tuning button, one to eight of them, counts its whole lit
/// edge and at most four design pixels past it on both panels, so a tap
/// picks the button it lands on.
#[test]
fn the_tuning_buttons_count_where_they_are_drawn() {
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let w = usize::from(size.width);
        let (left, right) = (scale.x(198), i32::from(size.width));
        let (top, foot) = (scale.y(36), scale.y(180));
        // Four design pixels, and one for rounding.
        let reach = scale.len(4) + 1;
        let counts = (1..=8)
            .map(|k| (k, false))
            .chain((1..=7).map(|k| (k, true)));
        for (knobs, auto) in counts {
            for i in 0..knobs {
                let tuning = camtune::Tuning {
                    knobs: &EIGHT[..knobs],
                    picked: 0,
                    value: 0,
                    auto: auto.then_some(true),
                };
                let lit = camtune::Target::Knob(i);
                let mut panel = Panel::new(size.width, size.height);
                let mut buf = vec![0u16; w * 16];
                let area = whole(&panel);
                render(&mut panel, area, BACKGROUND, &mut buf, |b| {
                    camtune::draw(b, scale, kit, &tuning, Some(lit))
                })
                .unwrap();
                let what = format!("button {i} of {knobs}, switch {auto}, {size:?}");
                let (mut x0, mut y0, mut x1, mut y1) = (i32::MAX, i32::MAX, i32::MIN, i32::MIN);
                for y in top..foot {
                    for x in left..right {
                        if panel.px[y as usize * w + x as usize] != ACCENT {
                            continue;
                        }
                        assert_eq!(
                            camtune::target(scale, knobs, auto, x as u16, y as u16),
                            Some(lit),
                            "({x}, {y}) on the edge of {what}"
                        );
                        (x0, y0, x1, y1) = (x0.min(x), y0.min(y), x1.max(x), y1.max(y));
                    }
                }
                assert!(x0 <= x1, "{what} drawn lit");
                let z = camtune::zone(scale, knobs, auto, lit).expect("a setting's button");
                let (zx, zy) = (i32::from(z.x), i32::from(z.y));
                let (zr, zf) = (zx + i32::from(z.width), zy + i32::from(z.height));
                assert!(
                    zx >= x0 - reach && zy >= y0 - reach && zr <= x1 + 1 + reach && zf <= y1 + 1 + reach,
                    "{what}: counts over ({zx}, {zy})..({zr}, {zf}), drawn over ({x0}, {y0})..({}, {})",
                    x1 + 1,
                    y1 + 1
                );
            }
        }
    }
}

/// Save to SD is on the left of every dialog that offers it, so it is in
/// the same place everywhere.
#[test]
fn save_to_sd_is_on_the_left_everywhere() {
    use kassigner_fw::ui::dialog;
    for d in [
        dialog::kpub_exported(),
        dialog::signed_tx(),
        dialog::message_exported(),
        dialog::address_exported(),
        dialog::seed_exported(),
        dialog::kpub_scanned(),
    ] {
        assert_eq!(d.cancel, "Save to SD", "{}", d.title);
        assert_ne!(d.accept, "Save to SD", "{}", d.title);
    }
}

/// "<" and ">" count over at least twice their drawn button, for room to
/// tap, clear of the index and the switch; "<" counts for nothing at index
/// 0.
#[test]
fn the_arrows_count_past_their_buttons() {
    use kassigner_fw::ui::address::{zone, Target};
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let z = |t| zone(scale, false, false, t).unwrap();
        let (index, chain) = (z(Target::Index), z(Target::Chain));
        for (name, arrow, drawn) in [
            ("<", z(Target::Before), scale.zone(10, 210, 50, 28)),
            (">", z(Target::After), scale.zone(260, 210, 50, 28)),
        ] {
            assert!(
                arrow.x <= drawn.x
                    && arrow.y <= drawn.y
                    && arrow.x + arrow.width >= drawn.x + drawn.width
                    && arrow.y + arrow.height >= drawn.y + drawn.height,
                "{name} holds its button at {size:?}"
            );
            assert!(
                u32::from(arrow.width) * u32::from(arrow.height)
                    >= 2 * u32::from(drawn.width) * u32::from(drawn.height),
                "{name} at least twice its button at {size:?}"
            );
            assert!(!overlap(&arrow, &index), "{name} and the index");
            assert!(!overlap(&arrow, &chain), "{name} and the switch");
            let r = Rect::new(arrow.x, arrow.y, arrow.width, arrow.height);
            assert!(r.fits(size), "{name} on the panel at {size:?}");
        }
        assert_eq!(zone(scale, false, true, Target::Before), None);
    }
}
