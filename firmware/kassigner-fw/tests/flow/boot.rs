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

//! Boot: the start-up checks, the fuses' verdict, and the verification screen.

use super::*;

/// A booted event with this verdict, every check passed.
fn boot_with(provisioning: Verdict, image_read: bool) -> Event<'static> {
    Event::Booted {
        provisioning,
        image_read,
        checks_ok: true,
    }
}

/// Only download mode open, as the provisioned Waveshare reads.
const DOWNLOAD_OPEN: Holes = Holes {
    key_slot: false,
    jtag: false,
    download: true,
};

// ── Boot ────────────────────────────────────────────────────────────────────

/// The red screen: a failed start-up check, and nothing leaves it.
#[test]
fn a_failed_check_halts_and_stays_halted() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = flow(&mut m, &[]);
    assert_eq!(f.state(), State::Boot);
    assert_eq!(
        f.step(Event::Tick { now_us: 1 }, &mut Live).screen,
        Screen::Booting
    );
    let out = f.step(
        Event::Booted {
            provisioning: Verdict::Provisioned,
            image_read: true,
            checks_ok: false,
        },
        &mut Live,
    );
    let halted = State::Halted(Halt::SelfTest);
    assert_eq!(f.state(), halted);
    assert_eq!(out.screen, Screen::Halted(Halt::SelfTest));
    assert_eq!(out.command, None);
    let digits = seedqr();
    for e in [
        RIGHT,
        LEFT,
        Event::Tick { now_us: 1 << 40 },
        Event::Payload(&digits),
        Event::Code(&digits),
        GOOD,
    ] {
        let out = f.step(e, &mut Live);
        assert_eq!(f.state(), halted, "{e:?} left the red screen");
        assert_eq!(out.command, None);
    }
}

/// The fuses never halt the unit: every verdict ends on the verification
/// screen. Only a failed check halts.
#[test]
fn the_fuses_never_halt() {
    let all = Holes {
        key_slot: true,
        jtag: true,
        download: true,
    };
    for verdict in [
        Verdict::Blank,
        Verdict::Provisioned,
        Verdict::Holes(DOWNLOAD_OPEN),
        Verdict::Holes(all),
    ] {
        for image_read in [true, false] {
            let mut m = Memory::new();
            let mut f: Flow<'_, 1> = flow(&mut m, &[]);
            let out = f.step(boot_with(verdict, image_read), &mut Live);
            let check = brand::Check {
                verdict,
                image_read,
            };
            assert_eq!(f.state(), State::Verified(check), "{check:?}");
            assert_eq!(out.screen, Screen::Verified(check));
            assert_eq!(out.command, None);

            let mut m = Memory::new();
            let mut f: Flow<'_, 1> = flow(&mut m, &[]);
            f.step(
                Event::Booted {
                    provisioning: verdict,
                    image_read,
                    checks_ok: false,
                },
                &mut Live,
            );
            assert_eq!(f.state(), State::Halted(Halt::SelfTest), "{check:?}");
        }
    }
}

/// The verification screen holds for its time, then the home grid.
#[test]
fn a_provisioned_unit_verifies_and_rests_on_the_home_grid() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = flow(&mut m, &[]);
    f.step(Event::Tick { now_us: 500 }, &mut Live);
    let out = f.step(GOOD, &mut Live);
    assert_eq!(out.screen, Screen::Verified(CLEAN));
    f.step(
        Event::Tick {
            now_us: 500 + VERIFIED_US - 1,
        },
        &mut Live,
    );
    assert_eq!(
        f.state(),
        State::Verified(CLEAN),
        "held for less than its time"
    );
    let out = f.step(
        Event::Tick {
            now_us: 500 + VERIFIED_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home);
    assert_eq!(out.screen, Screen::Home);
    assert_eq!(f.fingerprint(), None);
    assert_eq!(
        out.command,
        Some(Command::CloseConsole),
        "a provisioned unit goes quiet as it leaves verification"
    );
    // Once: the next tick asks nothing of the port.
    let out = f.step(
        Event::Tick {
            now_us: 501 + VERIFIED_US,
        },
        &mut Live,
    );
    assert_eq!(out.command, None);
}

/// The screen stays 3 seconds.
#[test]
fn the_verification_screen_stays_three_seconds() {
    assert_eq!(VERIFIED_US, 3_000_000);
}

/// A blank unit runs, timed like a provisioned one, and keeps its console.
#[test]
fn a_blank_unit_runs_and_keeps_its_console() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = flow(&mut m, &[]);
    f.step(Event::Tick { now_us: 500 }, &mut Live);
    f.step(boot_with(Verdict::Blank, true), &mut Live);
    let blank = brand::Check {
        verdict: Verdict::Blank,
        image_read: true,
    };
    assert!(!blank.red() && !blank.clean());
    assert_eq!(f.state(), State::Verified(blank));
    f.step(
        Event::Tick {
            now_us: 500 + VERIFIED_US - 1,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Verified(blank));
    let out = f.step(
        Event::Tick {
            now_us: 500 + VERIFIED_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home, "it runs");
    assert_eq!(out.command, None, "and keeps its console");
}

/// A hole open is red, and red waits for a tap, not time, a press or a
/// drag. The tap goes home, closing a provisioned unit's console.
#[test]
fn a_hole_waits_for_a_tap_and_then_closes_the_console() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = flow(&mut m, &[]);
    f.step(boot_with(Verdict::Holes(DOWNLOAD_OPEN), true), &mut Live);
    let holed = brand::Check {
        verdict: Verdict::Holes(DOWNLOAD_OPEN),
        image_read: true,
    };
    assert!(holed.red() && !holed.clean());
    for e in [
        Event::Tick { now_us: 1 << 40 },
        Event::Press { x: 160, y: 120 },
        Event::Drag { x: 170, y: 120 },
        Event::Tick { now_us: 1 << 41 },
    ] {
        let out = f.step(e, &mut Live);
        assert_eq!(f.state(), State::Verified(holed), "{e:?} passed it");
        assert_eq!(out.command, None);
    }
    let out = f.step(Event::Tap { x: 160, y: 120 }, &mut Live);
    assert_eq!(f.state(), State::Home);
    assert_eq!(out.command, Some(Command::CloseConsole));
}

/// A hash not read is red too: a provisioned unit waits for a tap and
/// closes its console; a blank one waits and keeps it.
#[test]
fn an_unread_hash_waits_for_a_tap() {
    for (verdict, closes) in [(Verdict::Provisioned, true), (Verdict::Blank, false)] {
        let mut m = Memory::new();
        let mut f: Flow<'_, 1> = flow(&mut m, &[]);
        f.step(boot_with(verdict, false), &mut Live);
        let check = brand::Check {
            verdict,
            image_read: false,
        };
        assert!(check.red() && !check.clean());
        f.step(Event::Tick { now_us: 1 << 40 }, &mut Live);
        assert_eq!(f.state(), State::Verified(check), "time does not pass it");
        let out = f.step(Event::Tap { x: 160, y: 120 }, &mut Live);
        assert_eq!(f.state(), State::Home);
        assert_eq!(out.command, closes.then_some(Command::CloseConsole));
    }
}
