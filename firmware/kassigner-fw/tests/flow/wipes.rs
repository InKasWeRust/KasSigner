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

//! The two wipes: Home's logo held, and four minutes untouched.

use super::*;

// ── The two wipes ──────────────────────────────────────────────────────────

/// A finger on Home's logo, down at `t`.
fn logo_down<const N: usize>(f: &mut Flow<'_, N>, t: u64) {
    f.step(Event::Tick { now_us: t }, &mut Live);
    let z = brand::zone(SCALE, brand::Target::Logo);
    f.step(
        Event::Press {
            x: z.x + z.width / 2,
            y: z.y + z.height / 2,
        },
        &mut Live,
    );
}

/// Home's logo held six seconds wipes every slot and the wallet in use,
/// silently while held; then WIPED, with the success sound, then Home. The
/// lift that ends the hold taps nothing.
#[test]
fn home_s_logo_held_six_seconds_wipes_everything() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    let t = 10_000_000;
    logo_down(&mut f, t);
    let out = f.step(
        Event::Tick {
            now_us: t + WIPE_HOLD_US - 1,
        },
        &mut Live,
    );
    assert_eq!(out.screen, Screen::Home, "nothing shown while held");
    assert_eq!(f.seed_count(), 1);
    let out = f.step(
        Event::Tick {
            now_us: t + WIPE_HOLD_US,
        },
        &mut Live,
    );
    assert_eq!(out.screen, Screen::Wiped);
    assert_eq!(
        kassigner_fw::cues::for_step(&Screen::Home, &out.screen, false, false),
        Some(kassigner_fw::cues::Cue::Success)
    );
    assert_eq!(f.seed_count(), 0, "every slot");
    assert_eq!(f.fingerprint(), None, "no wallet in use");
    let z = brand::zone(SCALE, brand::Target::Logo);
    f.step(
        Event::Tap {
            x: z.x + z.width / 2,
            y: z.y + z.height / 2,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Wiped, "the lift taps nothing");
    f.step(
        Event::Tick {
            now_us: t + WIPE_HOLD_US + WIPED_US - 1,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Wiped);
    f.step(
        Event::Tick {
            now_us: t + WIPE_HOLD_US + WIPED_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home);
    // A request now has no seed to be signed with.
    f.step(scan(), &mut Live);
    let req = ours();
    deliver(&mut f, &req);
    assert_eq!(f.state(), State::Refused(Refusal::NoWallet));
}

/// A hold lifted early or slid off the logo wipes nothing.
#[test]
fn a_logo_hold_cut_short_wipes_nothing() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    let z = brand::zone(SCALE, brand::Target::Logo);
    let (x, y) = (z.x + z.width / 2, z.y + z.height / 2);

    let t = 10_000_000;
    logo_down(&mut f, t);
    f.step(
        Event::Tick {
            now_us: t + WIPE_HOLD_US / 2,
        },
        &mut Live,
    );
    f.step(Event::Tap { x, y }, &mut Live);
    f.step(
        Event::Tick {
            now_us: t + 2 * WIPE_HOLD_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home, "lifted early");
    assert_eq!(f.seed_count(), 1);

    let t = t + 3 * WIPE_HOLD_US;
    logo_down(&mut f, t);
    let card = brand::zone(SCALE, brand::Target::Card(1));
    f.step(
        Event::Drag {
            x: card.x + card.width / 2,
            y: card.y + card.height / 2,
        },
        &mut Live,
    );
    f.step(
        Event::Tick {
            now_us: t + 2 * WIPE_HOLD_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home, "slid off");
    assert_eq!(f.seed_count(), 1);
}

/// Four minutes untouched with a seed held wipes everything and goes home,
/// silently: a touch restarts the count, a camera left on is stopped, and
/// with nothing held nothing happens.
#[test]
fn four_minutes_untouched_wipes_everything() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    let t = 10_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    // A tap on the header does nothing but is a touch.
    let header = brand::zone(SCALE, brand::Target::Header);
    f.step(tap_in(header), &mut Live);
    f.step(
        Event::Tick {
            now_us: t + IDLE_WIPE_US - 1,
        },
        &mut Live,
    );
    assert_eq!(f.seed_count(), 1);
    // Scanning, the camera on, untouched since.
    let out = f.step(scan(), &mut Live);
    assert_eq!(out.command, Some(Command::CameraOn));
    // The tap on Scan was a touch: four minutes from it.
    let at = t + IDLE_WIPE_US - 1;
    let out = f.step(
        Event::Tick {
            now_us: at + IDLE_WIPE_US - 1,
        },
        &mut Live,
    );
    assert_eq!(out.command, None);
    assert_eq!(f.state(), State::Scanning);
    let out = f.step(
        Event::Tick {
            now_us: at + IDLE_WIPE_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home);
    assert_eq!(out.screen, Screen::Home);
    assert_eq!(out.command, Some(Command::CameraOff));
    assert_eq!(f.seed_count(), 0);
    assert_eq!(f.fingerprint(), None);

    // Nothing held: a menu left untouched stays.
    f.step(card(3), &mut Live);
    let settings = f.state();
    f.step(
        Event::Tick {
            now_us: at + 3 * IDLE_WIPE_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), settings);
}

/// The idle wipe lets a running job finish: a seed still opening when four
/// minutes pass opens, then is wiped on the tick after.
#[test]
fn the_idle_wipe_lets_a_seed_open_first() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    f.step(Event::Code(&seedqr()), &mut Live);
    f.touch(answer(dialog::Target::Accept));
    f.step(no_passphrase(), &mut Live);
    assert!(matches!(f.state(), State::Opening { .. }));
    let late = VERIFIED_US + IDLE_WIPE_US;
    let mut ticks = 0;
    while matches!(f.state(), State::Opening { .. }) {
        f.step(Event::Tick { now_us: late }, &mut Live);
        ticks += 1;
        assert!(ticks <= OPEN_STEPS + 1, "it opens");
    }
    assert!(matches!(f.state(), State::Seeds { .. }), "opened");
    assert_eq!(f.seed_count(), 1);
    f.step(Event::Tick { now_us: late + 1 }, &mut Live);
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.seed_count(), 0);
}

/// The idle wipe takes what is typed with no seed held: a raw key half
/// typed and left four minutes is gone, the unit home.
#[test]
fn the_idle_wipe_takes_a_key_typed_with_no_seed() {
    let hex = private_hex(&wallet(), Path::receive(5));
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    let t = 10_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    raw_key_keyboard(&mut f);
    type_hex(&mut f, &hex[..20]);
    assert_eq!(f.state(), State::RawKey);
    assert_eq!(f.seed_count(), 0);

    f.step(
        Event::Tick {
            now_us: t + IDLE_WIPE_US - 1,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::RawKey);
    assert_eq!(f.typed().0, &hex[..20]);
    let out = f.step(
        Event::Tick {
            now_us: t + IDLE_WIPE_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home);
    assert_eq!(out.screen, Screen::Home);
    assert_eq!(f.typed().0, "");
}
