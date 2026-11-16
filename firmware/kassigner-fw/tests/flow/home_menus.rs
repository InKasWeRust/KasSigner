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

//! Home, the menus and Settings: Display, Audio, camera tuning, About, SD
//! Card, and Export's way back.

use super::*;

/// The menus: Tools, Seed Tools under it, back out, and Settings.
#[test]
fn the_menus_are_walked_by_taps() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(card(2), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Tools,
            page: 0
        }
    );
    f.step(item(&menu::TOOLS, 0), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedTools,
            page: 0
        }
    );
    // Seed Tools has two pages.
    let down = menu::zone(
        SCALE,
        &menu::SEED_TOOLS,
        0,
        menu::Target::Nav(Nav::PageDown),
    );
    f.step(tap_in(down.expect("a second page")), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedTools,
            page: 1
        }
    );
    f.step(tap_in(chrome::corner(SCALE, Nav::Back)), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Tools,
            page: 0
        },
        "back from Seed Tools is Tools"
    );
    f.step(tap_in(chrome::corner(SCALE, Nav::Back)), &mut Live);
    assert_eq!(f.state(), State::Home);
    f.step(card(3), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Settings,
            page: 0
        }
    );
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
}

/// A setting acts in its mode: the loop's target only while it runs, the
/// exposure only while it is off, contrast either way; with no switch,
/// everything acts.
#[test]
fn a_setting_acts_in_its_mode() {
    let (target, exposure, contrast) = (KNOBS[0], KNOBS[1], KNOBS[5]);
    assert!(target.acts_in(Some(true)) && !target.acts_in(Some(false)));
    assert!(!exposure.acts_in(Some(true)) && exposure.acts_in(Some(false)));
    assert!(contrast.acts_in(Some(true)) && contrast.acts_in(Some(false)));
    assert!(target.acts_in(None) && exposure.acts_in(None));
    // The screen opens on the lead setting, here the first.
    assert_eq!(KNOBS.iter().position(|k| k.lead), Some(0));
}

/// A tap on the tuning screen's target.
fn on_tune(t: camtune::Target) -> Event<'static> {
    tap_in(camtune::zone(SCALE, KNOBS.len(), true, t).expect("on the tuning screen"))
}

/// Camera: the camera comes up without decoding and shows what the sensor
/// reports; the buttons pick a knob, minus, plus and the track move it in
/// its range, the switch asks to be flipped, and EXIT stops the camera and
/// returns to Settings.
#[test]
fn camera_tunes_the_sensor() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(card(3), &mut Live);
    let out = f.step(item(&menu::SETTINGS, 2), &mut Live);
    assert_eq!(out.command, Some(Command::TuneOn));
    assert_eq!(f.state(), State::CameraTune { knob: 0 }, "the lead setting");

    let read = [0x58, 0x00, 0x96, 0x14, 0x40, 0x44, 0x38];
    let out = f.step(
        Event::Tuned {
            values: &read,
            auto: Some(true),
        },
        &mut Live,
    );
    assert_eq!(
        out.screen,
        Screen::CameraTune {
            knob: 0,
            value: 0x58,
            auto: Some(true)
        }
    );
    let out = f.step(on_tune(camtune::Target::Plus), &mut Live);
    assert_eq!(
        out.command,
        Some(Command::Tune {
            knob: 0,
            value: 0x60
        })
    );

    // EXPO-H holds four bits: plus stops at 0x0F.
    f.step(on_tune(camtune::Target::Knob(1)), &mut Live);
    assert_eq!(f.state(), State::CameraTune { knob: 1 });
    for _ in 0..20 {
        f.step(on_tune(camtune::Target::Plus), &mut Live);
    }
    let out = f.step(on_tune(camtune::Target::Plus), &mut Live);
    assert_eq!(out.command, None, "at its top");
    assert_eq!(
        out.screen,
        Screen::CameraTune {
            knob: 1,
            value: 0x0F,
            auto: Some(true)
        }
    );

    // Values snap to the step's grid: EXPO-L at 0x96, off its grid of 8,
    // goes up to 0x98 and down to 0x90.
    f.step(on_tune(camtune::Target::Knob(2)), &mut Live);
    let out = f.step(on_tune(camtune::Target::Plus), &mut Live);
    assert_eq!(
        out.command,
        Some(Command::Tune {
            knob: 2,
            value: 0x98
        })
    );
    let out = f.step(on_tune(camtune::Target::Minus), &mut Live);
    assert_eq!(
        out.command,
        Some(Command::Tune {
            knob: 2,
            value: 0x90
        })
    );
    for k in KNOBS {
        for v in 0..=u8::MAX {
            let s = k.snap(v);
            assert!(
                s == k.max || s.is_multiple_of(k.step),
                "{} {v} -> {s}",
                k.label
            );
            assert!(s <= k.max);
            let (d, u) = (k.down(v), k.up(v));
            assert!(
                d == 0 || d.is_multiple_of(k.step),
                "{} down {v} -> {d}",
                k.label
            );
            assert!(
                u == k.max || u.is_multiple_of(k.step),
                "{} up {v} -> {u}",
                k.label
            );
        }
    }

    // A press at the track's right end sets the top, a drag to its left
    // end the bottom.
    f.step(on_tune(camtune::Target::Knob(3)), &mut Live);
    let track = camtune::zone(SCALE, KNOBS.len(), true, camtune::Target::Track).unwrap();
    let out = f.step(
        Event::Press {
            x: track.x + track.width - 1,
            y: track.y + 5,
        },
        &mut Live,
    );
    assert_eq!(
        out.command,
        Some(Command::Tune {
            knob: 3,
            value: 0x3F
        })
    );
    let out = f.step(
        Event::Drag {
            x: 0,
            y: track.y + 5,
        },
        &mut Live,
    );
    assert_eq!(out.command, None, "past the track is not on it");
    let out = f.step(
        Event::Drag {
            x: track.x,
            y: track.y + 5,
        },
        &mut Live,
    );
    assert_eq!(out.command, Some(Command::Tune { knob: 3, value: 0 }));

    let out = f.step(on_tune(camtune::Target::Auto), &mut Live);
    assert_eq!(out.command, Some(Command::TuneAuto(false)));

    let out = f.step(on_tune(camtune::Target::Exit), &mut Live);
    assert_eq!(out.command, Some(Command::TuneOff));
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Settings,
            page: 0
        }
    );
}

/// A tap on a level screen's target.
fn on_level(t: settings::Target) -> Event<'static> {
    tap_in(settings::zone(SCALE, t).expect("on a level screen"))
}

/// Display: plus and minus step the backlight and tell the board, the bar
/// sets it where tapped, never below the floor; back returns to Settings.
#[test]
fn display_sets_the_backlight() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(card(3), &mut Live);
    let out = f.step(item(&menu::SETTINGS, 0), &mut Live);
    assert_eq!(f.state(), State::Display);
    assert_eq!(out.screen, Screen::Display { level: 128 });

    let out = f.step(on_level(settings::Target::Plus), &mut Live);
    assert_eq!(out.command, Some(Command::Backlight(153)));
    assert_eq!(out.screen, Screen::Display { level: 153 });

    // The bar's left end is the floor, not dark.
    let bar = settings::zone(SCALE, settings::Target::Bar).expect("a bar");
    let out = f.step(
        Event::Tap {
            x: bar.x,
            y: bar.y + 1,
        },
        &mut Live,
    );
    assert_eq!(out.command, Some(Command::Backlight(BACKLIGHT_FLOOR)));
    let out = f.step(on_level(settings::Target::Minus), &mut Live);
    assert_eq!(out.command, None, "already at the floor");
    assert_eq!(
        out.screen,
        Screen::Display {
            level: BACKLIGHT_FLOOR
        }
    );

    // The bar's right end is full.
    let right = bar.x + bar.width - 1;
    let out = f.step(
        Event::Tap {
            x: right,
            y: bar.y + 1,
        },
        &mut Live,
    );
    assert_eq!(out.command, Some(Command::Backlight(255)));

    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Settings,
            page: 0
        }
    );
    // What was set stays set.
    let out = f.step(item(&menu::SETTINGS, 0), &mut Live);
    assert_eq!(out.screen, Screen::Display { level: 255 });
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
}

/// Audio: the volume moves by the same rules, down to silent.
#[test]
fn audio_sets_the_volume() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(card(3), &mut Live);
    f.step(item(&menu::SETTINGS, 1), &mut Live);
    assert_eq!(f.state(), State::Audio);
    let out = f.step(on_level(settings::Target::Plus), &mut Live);
    assert_eq!(out.command, Some(Command::Volume(43)));
    f.step(on_level(settings::Target::Minus), &mut Live);
    let out = f.step(on_level(settings::Target::Minus), &mut Live);
    assert_eq!(out.command, Some(Command::Volume(0)), "silent is allowed");
    assert_eq!(out.screen, Screen::Audio { level: 0 });
}

/// About is the verification screen with what boot found; a tap anywhere
/// returns to its row's Settings page.
#[test]
fn about_goes_back_on_a_tap() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(card(3), &mut Live);
    let down = menu::zone(SCALE, &menu::SETTINGS, 0, menu::Target::Nav(Nav::PageDown));
    f.step(tap_in(down.expect("a second page")), &mut Live);
    let out = f.step(item(&menu::SETTINGS, 4), &mut Live);
    assert_eq!(out.screen, Screen::About(CLEAN));
    f.step(Event::Tap { x: 160, y: 120 }, &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Settings,
            page: 1
        }
    );
}

/// A tap on the SD Card screen's target, with a card in the slot.
fn on_sd(t: sd_card::Target) -> Event<'static> {
    tap_in(sd_card::zone(SCALE, t).expect("on the SD Card screen"))
}

/// Export goes back where it was opened from, the seeds screen (also after
/// a submenu) or Import / Export.
#[test]
fn export_goes_back_where_it_came_from() {
    use kassigner_fw::ui::backup;
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    let rows: Vec<_> = (0..f.seed_count()).filter_map(|i| f.seed(i)).collect();
    f.step(
        tap_in(seeds::zone(SCALE, &rows, 6, 0, seeds::Target::Export).unwrap()),
        &mut Live,
    );
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Export,
            page: 0
        }
    );
    f.step(item(&menu::EXPORT, 0), &mut Live);
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Export,
            page: 0
        }
    );
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::Seeds { page: 0 }, "from the seeds screen");

    f.step(home_button(), &mut Live);
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(backup::zone(SCALE, backup::Target::Export).unwrap()),
        &mut Live,
    );
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::ImportExport, "from Import / Export");
}

/// SD Card: opening probes the slot; buttons only with a card; Test comes
/// back after five seconds; Format asks, is held as a seed's delete is, and
/// comes back after three; a card pulled mid-job shows as absent.
#[test]
fn sd_card_checks_tests_and_formats() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(card(3), &mut Live);

    // Opening probes.
    let out = f.step(item(&menu::SETTINGS, 3), &mut Live);
    assert_eq!(
        out.screen,
        Screen::Card {
            status: card::Status::Checking
        }
    );
    assert_eq!(out.command, Some(Command::Card(Job::Probe)));

    // Nothing there: no buttons.
    let out = f.step(Event::Card(Outcome::Absent), &mut Live);
    assert_eq!(
        out.screen,
        Screen::Card {
            status: card::Status::Absent
        }
    );
    let out = f.step(on_sd(sd_card::Target::Test), &mut Live);
    assert_eq!(out.command, None, "no Test without a card");
    assert_eq!(f.state(), State::Card);

    // Back to Settings, and in again with a card.
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Settings,
            page: 0
        }
    );
    f.step(item(&menu::SETTINGS, 3), &mut Live);
    let present = Screen::Card {
        status: card::Status::Present(Kind::SdV2High),
    };
    let out = f.step(Event::Card(Outcome::Present(Kind::SdV2High)), &mut Live);
    assert_eq!(out.screen, present);

    // Test: runs, shows the result, and comes back after five seconds.
    let t = 1_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    let out = f.step(on_sd(sd_card::Target::Test), &mut Live);
    assert_eq!(out.screen, Screen::CardBusy(Job::Test));
    assert_eq!(out.command, Some(Command::Card(Job::Test)));
    let tested = Outcome::Tested {
        bytes: 34,
        files: 2,
    };
    let out = f.step(Event::Card(tested), &mut Live);
    assert_eq!(
        out.screen,
        Screen::CardDone {
            job: Job::Test,
            outcome: tested
        }
    );
    f.step(on_sd(sd_card::Target::Format), &mut Live);
    assert!(
        matches!(f.state(), State::CardDone { .. }),
        "a tap does not cut it short"
    );
    f.step(
        Event::Tick {
            now_us: t + card_done_us(Job::Test, tested) - 1,
        },
        &mut Live,
    );
    assert!(matches!(f.state(), State::CardDone { .. }));
    let out = f.step(
        Event::Tick {
            now_us: t + card_done_us(Job::Test, tested),
        },
        &mut Live,
    );
    assert_eq!(out.screen, present);

    // Format asks first; Cancel keeps the card.
    let out = f.step(on_sd(sd_card::Target::Format), &mut Live);
    assert_eq!(out.screen, Screen::CardFormat { hold: None });
    f.step(answer(dialog::Target::Cancel), &mut Live);
    assert_eq!(f.state(), State::Card);

    // Armed, lifted before the time: not formatted.
    let Event::Tap { x, y } = answer(dialog::Target::Accept) else {
        unreachable!()
    };
    f.step(on_sd(sd_card::Target::Format), &mut Live);
    let out = f.step(answer(dialog::Target::Accept), &mut Live);
    assert_eq!(out.screen, Screen::CardFormat { hold: Some(0) });
    assert_eq!(out.command, None);
    let t = 20_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    f.step(Event::Press { x, y }, &mut Live);
    f.step(
        Event::Tick {
            now_us: t + HOLD_US / 2,
        },
        &mut Live,
    );
    let out = f.step(answer(dialog::Target::Accept), &mut Live);
    assert_eq!(out.command, None);
    assert_eq!(f.state(), State::Card, "released at half the time");

    // Held for the time: formatted.
    f.step(on_sd(sd_card::Target::Format), &mut Live);
    f.step(answer(dialog::Target::Accept), &mut Live);
    let t = 40_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    f.step(Event::Press { x, y }, &mut Live);
    let out = f.step(
        Event::Tick {
            now_us: t + HOLD_US / 2,
        },
        &mut Live,
    );
    assert_eq!(out.screen, Screen::CardFormat { hold: Some(50) });
    let out = f.step(
        Event::Tick {
            now_us: t + HOLD_US,
        },
        &mut Live,
    );
    assert_eq!(out.screen, Screen::CardBusy(Job::Format));
    assert_eq!(out.command, Some(Command::Card(Job::Format)));
    let out = f.step(Event::Card(Outcome::Formatted), &mut Live);
    assert_eq!(
        out.screen,
        Screen::CardDone {
            job: Job::Format,
            outcome: Outcome::Formatted
        }
    );
    let out = f.step(
        Event::Tick {
            now_us: t + HOLD_US + card_done_us(Job::Format, Outcome::Formatted),
        },
        &mut Live,
    );
    assert_eq!(out.screen, present);
    assert_eq!(card_done_us(Job::Format, Outcome::Formatted), 3_000_000);
    assert_eq!(card_done_us(Job::Test, tested), 5_000_000);
    // A failed job shows as long as any error.
    let failed = Outcome::Failed(card::Error::Backup("Wrong password or damaged file"));
    assert_eq!(card_done_us(Job::Format, failed), ERROR_US);
    assert_eq!(card_done_us(Job::Write, failed), ERROR_US);
    assert_eq!(card_done_us(Job::Test, failed), ERROR_US);
    assert_eq!(card_done_us(Job::Write, Outcome::Absent), ERROR_US);
    assert_eq!(REFUSED_US, ERROR_US);
    assert_eq!(ERROR_US, 5_000_000);

    // A card pulled mid-test shows as absent.
    f.step(on_sd(sd_card::Target::Test), &mut Live);
    f.step(Event::Card(Outcome::Absent), &mut Live);
    let out = f.step(
        Event::Tick {
            now_us: t + 60_000_000,
        },
        &mut Live,
    );
    assert_eq!(
        out.screen,
        Screen::Card {
            status: card::Status::Absent
        }
    );

    // Home from the screen and from the question.
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
}
