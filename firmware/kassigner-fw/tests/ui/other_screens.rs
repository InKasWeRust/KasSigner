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

//! The other screens: the scan's square and edge, the viewfinder, the
//! keyboards, the files list, Sign Message, stego and the backup check.

use super::*;

/// A scan's dots, one a frame up to 64, lie beside its square on both
/// panels: five a row, two rows a batch with a wider step between batches,
/// gray until read and teal once read.
#[test]
fn a_scan_s_dots_lie_beside_its_square() {
    use kassigner_fw::ui::color::{HINT, ORANGE, TEAL};
    // The dots drawn alone.
    let draw = |size: Size, total: usize, received: u64| {
        let scale = Scale::for_panel(size);
        let mut panel = Panel::new(size.width, size.height);
        let mut buf = vec![0u16; usize::from(size.width) * 16];
        let area = whole(&panel);
        render(&mut panel, area, BACKGROUND, &mut buf, |b| {
            camera::dots(b, scale, total, received)
        })
        .unwrap();
        panel
    };
    let solid = |p: u16| p == TEAL || p == ORANGE || p == HINT;
    // Dot centres, row by row: each band of rows holding solid pixels is a
    // row of dots, its middle row's runs the dots, with that row's y.
    let dots = |panel: &Panel| {
        let (w, h) = (panel.size.width, panel.size.height);
        let mut rows: Vec<(u16, Vec<(u16, u16)>)> = Vec::new();
        let mut band: Option<(u16, u16)> = None;
        let runs = |y: u16| {
            let mut runs = Vec::new();
            let mut x = 0;
            while x < w {
                if solid(panel.at(x, y)) {
                    let from = x;
                    while x < w && solid(panel.at(x, y)) {
                        x += 1;
                    }
                    let mid = from + (x - from) / 2;
                    runs.push((mid, panel.at(mid, y)));
                }
                x += 1;
            }
            runs
        };
        for y in 0..=h {
            let any = y < h && (0..w).any(|x| solid(panel.at(x, y)));
            match (any, band) {
                (true, None) => band = Some((y, y)),
                (true, Some((top, _))) => band = Some((top, y)),
                (false, Some((top, bottom))) => {
                    let mid = top + (bottom - top) / 2;
                    rows.push((mid, runs(mid)));
                    band = None;
                }
                (false, None) => {}
            }
        }
        rows
    };

    for size in SIZES {
        let scale = Scale::for_panel(size);
        let side = camera::side_area(scale);
        let square = camera::scan_viewfinder(scale);
        let edges = camera::edges(scale, square);
        for total in 1..=64usize {
            let panel = draw(size, total, u64::MAX);
            for y in 0..size.height {
                for x in 0..size.width {
                    if panel.at(x, y) != BACKGROUND {
                        assert!(side.contains(x, y), "{total} at ({x}, {y}) on {size:?}");
                        assert!(!square.contains(x, y), "{total} over the square");
                        assert!(
                            !edges.iter().any(|e| e.contains(x, y)),
                            "{total} over the edge"
                        );
                    }
                }
            }
            let rows = dots(&panel);
            let lens: Vec<usize> = rows.iter().map(|(_, r)| r.len()).collect();
            let mut want = vec![5; total / 5];
            if total % 5 != 0 {
                want.push(total % 5);
            }
            assert_eq!(lens, want, "{total} frames on {size:?}");
            assert!(
                rows.iter().all(|(_, r)| r[0].0 == rows[0].1[0].0),
                "rows start together at {total} on {size:?}"
            );
            // Inside a batch one step down; from one batch to the next, more.
            let ys: Vec<u16> = rows.iter().map(|(y, _)| *y).collect();
            for (k, pair) in ys.windows(2).enumerate() {
                let step = pair[1] - pair[0];
                let inside = ys[1] - ys[0];
                if k % 2 == 0 {
                    assert!(step.abs_diff(inside) <= 1, "{total}: row {k} to {}", k + 1);
                } else {
                    assert!(step > inside + 2, "{total}: batch gap after row {k}");
                }
            }
        }
        assert!(dots(&draw(size, 0, u64::MAX)).is_empty(), "nothing yet");
        let unread: usize = dots(&draw(size, 21, 0)).iter().map(|(_, r)| r.len()).sum();
        assert_eq!(unread, 21, "unread, still drawn");
    }

    let size = SIZES[0];
    let colors = |total: usize, received: u64| -> Vec<u16> {
        dots(&draw(size, total, received))
            .into_iter()
            .flat_map(|(_, r)| r.into_iter().map(|(_, c)| c))
            .collect()
    };
    assert_eq!(colors(3, 0b101), [TEAL, HINT, TEAL]);
    // 40 frames: one dot each, the first 32 read.
    let c = colors(40, (1u64 << 32) - 1);
    assert_eq!(c.len(), 40);
    assert!(c[..32].iter().all(|&p| p == TEAL), "read");
    assert!(c[32..].iter().all(|&p| p == HINT), "not read yet");
    // Frame 33 read alone: its own dot, the third of the seventh row.
    let c = colors(40, 1u64 << 32);
    assert_eq!(c[32], TEAL);
    assert!(c.iter().enumerate().all(|(i, &p)| i == 32 || p == HINT));
    for total in 1..=64usize {
        for received in [0, u64::MAX, 0x5555_5555_5555_5555] {
            assert!(
                !colors(total, received).contains(&ORANGE),
                "no orange at {total}"
            );
        }
    }
}

/// A scan's line is wrapped a word at a time, in orange, inside the side
/// beside its square, on both panels.
#[test]
fn a_scan_s_line_fits_beside_its_square() {
    use kassigner_fw::ui::color::ORANGE;
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let kit = kit(size);
        let mut panel = Panel::new(size.width, size.height);
        let mut buf = vec![0u16; usize::from(size.width) * 16];
        let area = whole(&panel);
        render(&mut panel, area, BACKGROUND, &mut buf, |b| {
            camera::side_note(b, scale, kit, camera::SEED_HINT)
        })
        .unwrap();
        let side = camera::side_area(scale);
        let mut drawn = 0;
        let mut rows = std::collections::BTreeSet::new();
        for y in 0..size.height {
            for x in 0..size.width {
                let p = panel.at(x, y);
                if p != BACKGROUND {
                    assert!(side.contains(x, y), "({x}, {y}) on {size:?}");
                    drawn += 1;
                    if p == ORANGE {
                        rows.insert(y);
                    }
                }
            }
        }
        assert!(drawn > 0, "drawn on {size:?}");
        // More than one line: the side is narrower than the line.
        let lines = rows
            .iter()
            .zip(rows.iter().skip(1))
            .filter(|(a, b)| **b > **a + 1)
            .count()
            + 1;
        assert!(lines >= 2, "{lines} lines on {size:?}");
    }
}

/// The camera screens' counter, line and side lie outside the viewfinder,
/// so redrawing them never covers the picture, and clear the back button
/// and the rule; a scan's viewfinder is square.
#[test]
fn the_viewfinder_is_never_drawn_over() {
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let rule = scale.y(40);
        let square = camera::scan_viewfinder(scale);
        assert_eq!(square.width, square.height, "a square at {size:?}");
        for (view, scan) in [
            (camera::viewfinder(scale), false),
            (camera::scan_viewfinder(scale), true),
        ] {
            let r = Rect::new(view.x, view.y, view.width, view.height);
            assert!(r.fits(size), "the viewfinder at {size:?}");
            let mut others = vec![
                ("counter", camera::counter_area(scale)),
                ("back", camera::back(scale)),
            ];
            if scan {
                others.push(("side", camera::side_area(scale)));
            } else {
                others.push(("line", camera::note_area(scale)));
            }
            for (name, z) in others {
                assert!(!overlap(&z, &view), "{name} and the viewfinder at {size:?}");
                let r = Rect::new(z.x, z.y, z.width, z.height);
                assert!(r.fits(size), "{name} at {size:?}");
            }
            assert!(i32::from(view.y) > rule, "under the rule at {size:?}");
        }
        assert!(!overlap(&camera::counter_area(scale), &camera::back(scale)));
    }
}

/// A file name's keyboard types only letters and digits, eight at most;
/// Delete, the arrows, the page key and OK always act.
#[test]
fn a_file_name_keyboard_takes_only_what_a_name_can_hold() {
    use keyboard::{Key, Mode, Target};
    let scale = Scale::for_panel(Size::new(320, 240));
    let at = |page: u8, key: Key| {
        let z = keyboard::zone(scale, page, Target::Key(key)).unwrap();
        (z.x + z.width / 2, z.y + z.height / 2)
    };
    let hit = |mode: Mode, page: u8, key: Key| {
        let (x, y) = at(page, key);
        keyboard::target(scale, page, mode, x, y)
    };
    let open = Mode::Name { full: false };
    let full = Mode::Name { full: true };
    assert_eq!(
        hit(open, 0, Key::Char(b'a')),
        Some(Target::Key(Key::Char(b'a')))
    );
    assert_eq!(
        hit(open, 2, Key::Char(b'7')),
        Some(Target::Key(Key::Char(b'7')))
    );
    assert_eq!(hit(open, 2, Key::Char(b'!')), None, "a symbol");
    assert_eq!(hit(open, 0, Key::Space), None, "space");
    assert_eq!(hit(full, 0, Key::Char(b'a')), None, "full");
    for key in [Key::Delete, Key::Left, Key::Right, Key::Page, Key::Ok] {
        assert_eq!(hit(full, 0, key), Some(Target::Key(key)), "{key:?}");
    }
    assert_eq!(
        hit(Mode::Text { full: false }, 2, Key::Char(b'!')),
        Some(Target::Key(Key::Char(b'!')))
    );
    let mut out = [0u8; 8];
    assert_eq!(
        keyboard::Note::Count { used: 6, of: 8 }.shown(&mut out).0,
        "6/8"
    );
}

/// The trash counts from 8 pixels left of its button to the row's end, so
/// a tap just beside it, as at (276, 74), deletes rather than restores.
#[test]
fn the_trash_counts_to_its_row_end() {
    use backup::{pick, Pick};
    let scale = Scale::for_panel(Size::new(320, 240));
    assert_eq!(pick(scale, 1, 0, 276, 74), Some(Pick::Trash(0)), "the miss");
    assert_eq!(
        pick(scale, 1, 0, 230, 46),
        Some(Pick::Trash(0)),
        "its top left"
    );
    assert_eq!(
        pick(scale, 1, 0, 277, 89),
        Some(Pick::Trash(0)),
        "its bottom right"
    );
    assert_eq!(
        pick(scale, 1, 0, 120, 67),
        Some(Pick::Row(0)),
        "the name restores"
    );
    assert_eq!(pick(scale, 1, 0, 300, 74), None, "the margin");
}

/// The word keyboard's targets, suggestions included, count where drawn and
/// apart on both panels; only lower-case letters type, and the arrows, OK
/// and the suggestions act only when the mode allows.
#[test]
fn the_word_keyboard_is_a_compact_grid() {
    use keyboard::{Key, Mode, Target};
    for size in [Size::new(320, 240), Size::new(480, 320)] {
        let scale = Scale::for_panel(size);
        let mode = Mode::Word {
            back: true,
            on: true,
            take: true,
            chips: 3,
        };
        let zones: Vec<_> = [Target::Nav(Nav::Back), Target::Nav(Nav::Home)]
            .into_iter()
            .chain((0..3).map(Target::Chip))
            .chain(keyboard::keys(0).map(Target::Key))
            .filter(|&t| match t {
                Target::Key(k) => mode.takes(k),
                _ => true,
            })
            .map(|t| (t, keyboard::zone_in(scale, 0, mode, t).expect("drawn")))
            .collect();
        assert_eq!(zones.len(), 2 + 3 + 26 + 4, "{size:?}");
        check(
            size,
            &zones,
            |x, y| keyboard::target(scale, 0, mode, x, y),
            |_, _| false,
        );

        let center = |t: Target| {
            let z = keyboard::zone_in(scale, 0, mode, t).unwrap();
            (z.x + z.width / 2, z.y + z.height / 2)
        };
        let (x, y) = center(Target::Key(Key::Space));
        assert_eq!(keyboard::target(scale, 0, mode, x, y), None, "space");
        let (x, y) = center(Target::Key(Key::Page));
        assert_eq!(keyboard::target(scale, 0, mode, x, y), None, "page");
        let shut = Mode::Word {
            back: false,
            on: false,
            take: false,
            chips: 0,
        };
        for key in [Key::Left, Key::Right, Key::Ok] {
            let (x, y) = center(Target::Key(key));
            assert_eq!(keyboard::target(scale, 0, shut, x, y), None, "{key:?}");
        }
        let (x, y) = center(Target::Chip(0));
        assert_eq!(
            keyboard::target(scale, 0, shut, x, y),
            None,
            "no chips shown"
        );
    }
}

/// A full SELECT BACKUP, 16 pages, drawn without its note, leaves blank
/// where the widest "+N more files" note, `+65535 more files`, would go, so
/// the two never meet.
#[test]
fn the_more_files_note_clears_the_page_indicator() {
    let names = full_list();
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let kit = kit(size);
        let mut panel = Panel::new(size.width, size.height);
        let mut buf = vec![0u16; usize::from(size.width) * 16];
        let area = whole(&panel);
        render(&mut panel, area, BACKGROUND, &mut buf, |b| {
            backup::list(b, scale, kit, "SELECT BACKUP", (0, &names), 0)
        })
        .unwrap();
        let note = "+65535 more files";
        let (left, right) = (scale.x(6), scale.x(6) + kit.hint.width(note));
        let base = scale.y(236);
        let (top, foot) = (
            base - i32::from(kit.hint.ascent),
            (base + i32::from(kit.hint.descent)).min(i32::from(size.height)),
        );
        let w = usize::from(size.width);
        for y in top..foot {
            for x in left..right {
                assert_eq!(
                    panel.px[y as usize * w + x as usize],
                    BACKGROUND,
                    "drawn at ({x}, {y}) under the note, {size:?}"
                );
            }
        }
    }
}

/// The scan's edge frames its picture, top and sides outside it and the
/// foot on its last rows, clear of the rule, the back button, the counter
/// and the line or side; its sides meet, two design pixels wide, for a full
/// picture (the S3 units) or a smaller centred one (the P4).
#[test]
fn the_scan_s_edge_frames_its_picture() {
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let rule = scale.y(40);
        let w = scale.len(camera::EDGE) as u16;
        for (view, line) in [
            (camera::scan_viewfinder(scale), false),
            (camera::viewfinder(scale), true),
        ] {
            let beside = if line {
                camera::note_area(scale)
            } else {
                camera::side_area(scale)
            };
            let small = Zone::new(
                view.x + (view.width - 232.min(view.width)) / 2,
                view.y + (view.height - 152.min(view.height)) / 2,
                232.min(view.width),
                152.min(view.height),
            );
            for picture in [view, small] {
                let [top, left, right, foot] = camera::edges(scale, picture);
                for (name, edge) in [
                    ("top", top),
                    ("left", left),
                    ("right", right),
                    ("foot", foot),
                ] {
                    let r = Rect::new(edge.x, edge.y, edge.width, edge.height);
                    assert!(r.fits(size), "{name} at {size:?}");
                    assert!(
                        i32::from(edge.y) > rule,
                        "{name} under the rule at {size:?}"
                    );
                    for (other, z) in [
                        ("counter", camera::counter_area(scale)),
                        ("back", camera::back(scale)),
                    ] {
                        assert!(!overlap(&edge, &z), "{name} and {other} at {size:?}");
                    }
                    assert!(!overlap(&edge, &beside), "{name} and the line or side");
                }
                for (name, edge) in [("top", top), ("left", left), ("right", right)] {
                    assert!(!overlap(&edge, &picture), "{name} outside the picture");
                }
                assert_eq!(
                    (top.height, left.width, right.width, foot.height),
                    (w, w, w, w)
                );
                assert_eq!(
                    (foot.x, foot.width, foot.y + foot.height),
                    (picture.x, picture.width, picture.y + picture.height),
                    "the foot on the picture's last rows"
                );
                assert_eq!((top.x, top.x + top.width), (left.x, right.x + right.width));
                assert_eq!(top.y + top.height, picture.y);
                assert_eq!((left.y, left.height), (picture.y, picture.height));
                assert_eq!((right.y, right.height), (picture.y, picture.height));
            }
        }
    }
    assert_eq!(Scale::for_panel(SIZES[0]).len(camera::EDGE), 2);
}

/// The edge is red until the decoder finds a code, read or not, then bright
/// and dim green in turn for ten frames, held while the code stays in view,
/// with one tick as it turns green. A scan begun or ended starts red.
#[test]
fn a_code_in_view_turns_the_edge_green() {
    use camera::{Sighting, HELD_FRAMES, IN_VIEW, SEARCHING};
    let mut s = Sighting::new();
    assert_eq!(s.edge(), SEARCHING);
    assert_eq!(s.edge(), SEARCHING);
    assert!(s.saw(), "the tick");
    assert_eq!(s.edge(), IN_VIEW[0]);
    assert_eq!(s.edge(), IN_VIEW[1]);
    assert!(!s.saw(), "found again while green: no tick");
    for i in 0..HELD_FRAMES {
        assert_eq!(s.edge(), IN_VIEW[usize::from(i % 2 == 1)], "frame {i}");
    }
    assert_eq!(s.edge(), SEARCHING, "taken away");
    assert!(s.saw(), "back in view: the tick again");
    assert_ne!(s.edge(), SEARCHING);
    s.reset();
    assert_eq!(s, Sighting::new());
    assert_eq!(s.edge(), SEARCHING);
    assert!(s.saw());
    assert_eq!(rgb565(24, 6, 0), SEARCHING);
    assert_eq!(IN_VIEW, [rgb565(0, 63, 0), rgb565(0, 42, 0)]);
    assert_eq!(HELD_FRAMES, 10);
}

/// SIGN shows no teal until the message's last page has been shown, so it
/// never looks live while a tap on it does nothing.
#[test]
fn sign_is_dimmed_until_the_message_is_read() {
    use kassigner_fw::ui::address::{draw_message, message_pages, zone, Target};
    use kassigner_fw::ui::color::TEAL;
    let text = "Kaspa ".repeat(40);
    let pages = message_pages(&text);
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let button = zone(scale, false, true, Target::Index).unwrap();
        let teal = |live: bool| {
            let mut panel = Panel::new(size.width, size.height);
            let mut buf = vec![0u16; usize::from(size.width) * 16];
            let area = whole(&panel);
            render(&mut panel, area, BACKGROUND, &mut buf, |b| {
                draw_message(b, scale, kit, &text, (0, pages), (false, live))
            })
            .unwrap();
            (button.y..button.y + button.height)
                .flat_map(|y| (button.x..button.x + button.width).map(move |x| (x, y)))
                .filter(|&(x, y)| panel.at(x, y) == TEAL)
                .count()
        };
        assert_eq!(teal(false), 0, "dimmed at {size:?}");
        assert!(teal(true) > 0, "lit at {size:?}");
    }
}

/// STEGANOGRAPHY's targets count where drawn and apart on both panels, and
/// every line it draws fits, the preview wrapping a 64-character descriptor
/// without loss.
#[test]
fn the_stego_targets_are_apart_and_its_texts_fit() {
    use kassigner_fw::ui::stego::{lines, preview, target, zone, Target};
    use kassigner_protocol::stego::Carrier;
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let zones: Vec<_> = [Target::Nav(Nav::Back), Target::Nav(Nav::Home)]
            .into_iter()
            .chain((0..3).map(Target::Carrier))
            .filter_map(|t| zone(scale, t).map(|z| (t, z)))
            .collect();
        assert_eq!(zones.len(), 5, "{size:?}");
        check(size, &zones, |x, y| target(scale, x, y), |_, _| false);
        assert!(zone(scale, Target::Carrier(3)).is_none());
        // Each card's two lines inside it: the name in the title font,
        // where it hides the backup in the body's.
        let inner = scale.len(232 - 24);
        for c in Carrier::ALL {
            assert!(
                kit.title.width(c.label()) <= inner,
                "{} at {size:?}",
                c.label()
            );
            assert!(
                kit.body.width(c.description()) <= inner,
                "{} at {size:?}",
                c.description()
            );
        }
        let card_h = i32::from(zone(scale, Target::Carrier(0)).unwrap().height);
        let two = i32::from(kit.title.ascent)
            + scale.len(kassigner_fw::ui::stego::CARD_GAP)
            + i32::from(kit.body.ascent);
        assert!(
            two + scale.len(8) <= card_h,
            "{two} in {card_h} at {size:?}"
        );
        // The last card ends above the panel's foot.
        let last = zone(scale, Target::Carrier(2)).unwrap();
        assert!(i32::from(last.y + last.height) <= i32::from(size.height));
        for text in [
            "Rocky",
            "Rocky at the beach, summer 2024",
            "Me at the age of twenty with my family on the hill by the lake",
            &"a".repeat(64),
            &"ab ".repeat(21),
        ] {
            let d = preview(text);
            let joined: String = lines(text).concat();
            assert_eq!(
                joined.replace(' ', ""),
                text.replace(' ', ""),
                "{text:?} wraps without loss"
            );
            for (line, _) in d.lines {
                assert!(
                    kit.body.width(line) <= scale.len(300),
                    "{line:?} at {size:?}"
                );
            }
        }
        assert_eq!(preview("Rocky").lines[3].0, "This caption is the password");
        // ADD HINT?, HIDE BACKUP? and the hint menu's rows fit.
        for (line, _) in kassigner_fw::ui::stego::add_hint().lines {
            assert!(
                kit.body.width(line) <= scale.len(300),
                "{line:?} at {size:?}"
            );
        }
        // A camera's name whole on a dialog's line; the longest the card
        // holds, cut in the middle to the line.
        use kassigner_fw::ui::stego::{photo_line, PHOTO_LINE};
        let mut shown = [0u8; PHOTO_LINE];
        let photo = photo_line(kit, scale, "IMG_20241014_153022.jpg", &mut shown);
        assert_eq!(photo, "IMG_20241014_153022.jpg");
        let longest = format!("{}.jpg", "Holiday photo ".repeat(6).trim_end());
        let mut cut = [0u8; PHOTO_LINE];
        let cut = photo_line(kit, scale, &longest, &mut cut);
        assert!(cut.contains("...") && cut.ends_with(".jpg"), "{cut}");
        assert!(kit.body.width(cut) <= scale.len(300), "{cut} at {size:?}");
        let long = "a".repeat(64);
        for hint in [true, false] {
            let d = kassigner_fw::ui::stego::confirm(photo, Carrier::Both, &long, hint);
            for (line, _) in d.lines {
                assert!(
                    kit.body.width(line) <= scale.len(300),
                    "{line:?} at {size:?}"
                );
            }
        }
        // RECOVERY HINT: its targets apart, its rows' texts inside the row.
        use kassigner_fw::ui::stego::{hint_target, hint_zone, HintTarget, HINTS, HINT_ROWS};
        let zones: Vec<_> = [HintTarget::Nav(Nav::Back), HintTarget::Nav(Nav::Home)]
            .into_iter()
            .chain((0..HINT_ROWS).map(HintTarget::Row))
            .filter_map(|t| hint_zone(scale, t).map(|z| (t, z)))
            .collect();
        assert_eq!(zones.len(), 6, "{size:?}");
        check(size, &zones, |x, y| hint_target(scale, x, y), |_, _| false);
        for hint in HINTS.iter().chain(["Custom hint"].iter()) {
            assert!(
                kit.body.width(hint) <= scale.len(232 - 50),
                "{hint} at {size:?}"
            );
        }
        for (line, _) in kassigner_fw::ui::stego::done("IMG_2041.JPG", Carrier::Both).lines {
            assert!(
                kit.body.width(line) <= scale.len(300),
                "{line:?} at {size:?}"
            );
        }
        for (line, _) in [
            refusal::NOT_A_JPEG,
            refusal::PROGRESSIVE_JPEG,
            refusal::PHOTO_TOO_SMALL,
            refusal::PHOTO_TOO_LARGE,
            refusal::PHOTO_DAMAGED,
            refusal::EXIF_FAILED,
            refusal::VERIFY_FAILED,
            refusal::NO_BACKUP,
            refusal::WRONG_DESCRIPTOR,
            refusal::UNKNOWN_FORMAT,
        ] {
            assert!(
                kit.body.width(line) <= scale.len(300),
                "{line:?} at {size:?}"
            );
        }
        // Stego Import's ERROR screens: the first line in the title font.
        for (first, second) in [
            refusal::NO_BACKUP,
            refusal::WRONG_DESCRIPTOR,
            refusal::UNKNOWN_FORMAT,
        ] {
            assert!(
                kit.title.width(first) <= scale.len(300),
                "{first:?} at {size:?}"
            );
            assert!(
                kit.body.width(second) <= scale.len(300),
                "{second:?} at {size:?}"
            );
        }
        assert!(kit.body.width(loading::EMBEDDING.1) <= scale.len(300));
        assert!(kit.body.width(loading::READING.1) <= scale.len(300));
        // LOAD SEED? and RECOVERY HINT: every line inside the dialog, the
        // longest hint a unit seals included.
        for carrier in Carrier::ALL {
            for (words, two) in [(12, false), (24, true)] {
                let d = kassigner_fw::ui::stego::found(words, carrier, two);
                for (line, _) in d.lines {
                    assert!(
                        kit.body.width(line) <= scale.len(300),
                        "{line:?} at {size:?}"
                    );
                }
            }
        }
        let found = kassigner_fw::ui::stego::found(24, Carrier::Picture, false);
        assert_eq!(
            (found.lines[0].0, found.lines[1].0, found.lines[2].0),
            ("24-word seed found.", "In the photo itself", "")
        );
        assert_eq!(found.cancel, "CANCEL");
        let two = kassigner_fw::ui::stego::found(12, Carrier::Picture, true);
        assert_eq!(
            (two.lines[2].0, two.cancel),
            ("The photo holds two backups", "OTHER")
        );
        for hint in HINTS
            .iter()
            .copied()
            .chain(["x".repeat(64).as_str(), "ab ".repeat(21).as_str()])
        {
            let d = kassigner_fw::ui::stego::hint_shown(hint);
            let shown: String = d.lines.iter().map(|(l, _)| *l).collect();
            assert!(
                shown.replace(' ', "").contains(&hint.replace(' ', "")),
                "{hint:?} shown whole"
            );
            for (line, _) in d.lines {
                assert!(
                    kit.body.width(line) <= scale.len(300),
                    "{line:?} at {size:?}"
                );
            }
        }
        assert_eq!(
            kassigner_fw::ui::stego::hint_shown("Name of my loved one?").lines[3].0,
            "Its answer is your 25th word"
        );
        // OVERWRITE?: the longest 8.3 name and its lines inside the dialog.
        for (line, _) in kassigner_fw::ui::stego::overwrite("IMG_2041.JPG").lines {
            assert!(
                kit.body.width(line) <= scale.len(300),
                "{line:?} at {size:?}"
            );
        }
    }
}

/// The backup check's screens fit, every list word on a CHECK card, and its
/// targets count where drawn and apart on both panels; a seed with no
/// backup offers no Address.
#[test]
fn the_backup_check_fits_and_its_targets_are_apart() {
    use kassigner_crypto::wordlist::WORDLIST;
    use word_ui::{check_target, check_zone, CheckTarget};
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let room = scale.len(300);
        let card = check_zone(scale, CheckTarget::Choice(0)).unwrap();
        for w in WORDLIST {
            assert!(
                kit.title.width(w) + scale.len(12) <= i32::from(card.width),
                "{w:?} at {size:?}"
            );
        }
        for qr in [false, true] {
            for (line, _) in dialog::backup_check(qr).lines {
                assert!(kit.body.width(line) <= room, "{line:?} at {size:?}");
            }
        }
        let mut t = [0u8; 24];
        let title = word_ui::title(&mut t, "CHECK", 2, 3);
        assert!(
            kit.header.width(title) <= scale.len(200),
            "{title} at {size:?}"
        );
        assert!(kit.hint.width("Tap the word your copy has there.") <= room);
        assert!(kit.title.width(word_ui::CHECKED) <= room);
        assert!(
            kit.title.width(seeds::NO_BACKUP) + scale.len(8) + scale.len(6) <= scale.len(130),
            "NO BACKUP before the kind at {size:?}"
        );

        let zones: Vec<_> = [CheckTarget::Nav(Nav::Back), CheckTarget::Nav(Nav::Home)]
            .into_iter()
            .chain((0..word_ui::CHOICES).map(CheckTarget::Choice))
            .filter_map(|t| check_zone(scale, t).map(|z| (t, z)))
            .collect();
        assert_eq!(zones.len(), 2 + word_ui::CHOICES);
        check(size, &zones, |x, y| check_target(scale, x, y), |_, _| false);

        let rows = unbacked_seeds();
        assert!(seeds::address_dimmed(&rows));
        assert!(seeds::zone(scale, &rows, CAPACITY, 0, seeds::Target::Address).is_none());
        assert!(!seeds::address_dimmed(&SEEDS));
    }
}
