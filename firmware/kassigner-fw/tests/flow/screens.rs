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

//! What every screen shares: secrets marked, a lost camera, and what the
//! console prints.

use super::*;

/// A screen that draws a secret says so, and only those do: the loop
/// scrubs the stack after one, since the band it was composed in and the
/// encoder's scratch keep it. A file name, message, address, kpub or count
/// is no secret and costs no scrub.
#[test]
fn secret_screens_say_so() {
    use kassigner_fw::flow::{CountFor, Typing, WordsFor};
    use kassigner_fw::text::Typed;
    let field = Typed::<64>::new().field();
    let keyboard = |typing| Screen::Keyboard {
        typing,
        page: 0,
        field,
    };
    let secret = [
        Screen::ShowWords { pos: 0, of: 12 },
        Screen::Words {
            action: WordsFor::Import,
            pos: 0,
            of: 12,
            filled: 0,
            field,
            invalid: false,
        },
        Screen::LastWord {
            of: 12,
            choices: 128,
            at: Hidden(0),
        },
        Screen::SeedQr { compact: true },
        Screen::SeedQrGrid {
            compact: false,
            x: 0,
            y: 0,
        },
        Screen::PlainQr,
        Screen::PlainFrames {
            frame: 0,
            frames: 3,
        },
        Screen::Kprv { master: true },
        Screen::KprvQr { master: false },
        Screen::PrivateKey {
            change: false,
            index: 0,
            single: false,
        },
        Screen::PrivateKeyQr {
            change: true,
            index: 3,
        },
        keyboard(Typing::Passphrase),
        keyboard(Typing::PassphraseAgain),
        keyboard(Typing::Password),
        keyboard(Typing::PasswordAgain),
        keyboard(Typing::DeletePassword),
        keyboard(Typing::OverwritePassword),
        keyboard(Typing::RawKey),
    ];
    for s in secret {
        assert!(s.shows_secret(), "{s:?}");
    }
    let public = [
        keyboard(Typing::FileName),
        keyboard(Typing::KpubFileName),
        keyboard(Typing::SigFileName),
        keyboard(Typing::Message),
        Screen::Home,
        Screen::Address {
            change: false,
            index: 0,
            single: false,
        },
        Screen::AddressQr {
            change: false,
            index: 0,
        },
        Screen::KpubQr {
            frame: 0,
            frames: 2,
        },
        Screen::MessageFrames {
            frame: 0,
            frames: 1,
        },
        Screen::PlainFormat,
        Screen::PlainMode,
        Screen::Loading { words: 12 },
        Screen::Dice {
            rolled: 3,
            target: 99,
        },
        Screen::WordCount {
            action: CountFor::Dice,
        },
    ];
    for s in public {
        assert!(!s.shows_secret(), "{s:?}");
    }
}

/// A camera lost while on refuses whatever uses it: the home scanner, Sign
/// Message's, the tuning screen and the seed's sampling each take it down,
/// say why, then go home; elsewhere nothing changes. The seed's samples go
/// too: the next seed starts from nothing.
#[test]
fn a_lost_camera_ends_every_screen_using_it() {
    // A clock that only moves forward, past each refusal's time.
    let clock = std::cell::Cell::new(VERIFIED_US);
    let lost = |f: &mut Flow<'_, 6>, off: Command| {
        let out = f.step(Event::CameraLost, &mut Live);
        assert_eq!(out.command, Some(off), "{:?}", f.state());
        assert_eq!(f.state(), State::Refused(Refusal::NoCamera));
        assert_eq!(out.screen, Screen::Refused(Refusal::NoCamera));
        clock.set(clock.get() + 2 * REFUSED_US);
        f.step(
            Event::Tick {
                now_us: clock.get(),
            },
            &mut Live,
        );
        assert_eq!(f.state(), State::Home, "the refusal times out home");
    };

    // The home scanner, and home, where nothing is on.
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    let out = f.step(Event::CameraLost, &mut Live);
    assert_eq!((f.state(), out.command), (State::Home, None));
    assert_eq!(f.step(scan(), &mut Live).command, Some(Command::CameraOn));
    lost(&mut f, Command::CameraOff);

    // The tuning screen.
    f.step(card(3), &mut Live);
    let out = f.step(item(&menu::SETTINGS, 2), &mut Live);
    assert_eq!(out.command, Some(Command::TuneOn));
    lost(&mut f, Command::TuneOff);

    // Sign Message's scanner.
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut mem);
    let out = sign_message(&mut f, 2);
    assert_eq!(out.command, Some(Command::CameraOn));
    assert_eq!(f.state(), State::MessageScan);
    lost(&mut f, Command::CameraOff);

    // The seed's sampling, part way through.
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[Source::Camera, Source::Touch]);
    assert_eq!(new_seed(&mut f, &mut Live), Some(Command::SamplesOn));
    for salt in 0..4 {
        let s = camera_sample(salt);
        f.step(Event::CameraSample(&s), &mut Live);
    }
    let now = Event::Tick {
        now_us: clock.get(),
    };
    let Screen::Generating { credited, .. } = f.step(now, &mut Live).screen else {
        panic!("generating");
    };
    assert!(credited > 0, "the camera's samples were counted");
    lost(&mut f, Command::SamplesOff);
    assert_eq!(new_seed(&mut f, &mut Live), Some(Command::SamplesOn));
    let now = Event::Tick {
        now_us: clock.get(),
    };
    let Screen::Generating { credited, .. } = f.step(now, &mut Live).screen else {
        panic!("generating again");
    };
    assert_eq!(credited, 0, "nothing gathered before the loss was kept");
}

/// A screen written to the console leaves out the index: a bench unit's
/// console prints every screen, and must not print the address and BIP85
/// keypads' digits or the BIP85 child's index.
#[test]
fn a_screen_printed_leaves_out_the_index() {
    let screens = [
        Screen::AddressIndex {
            typed: Hidden(*b"73915"),
            len: 5,
        },
        Screen::Bip85Index {
            typed: Hidden(*b"73915"),
            len: 5,
        },
        Screen::Bip85 {
            words: 24,
            index: Hidden(73_915),
        },
    ];
    for screen in screens {
        let said = format!("{screen:?}");
        assert!(said.contains("Hidden(..)"), "{said}");
        for leak in ["73915", "73_915", "55, 51", "73915u32"] {
            assert!(!said.contains(leak), "{said}");
        }
    }
}
