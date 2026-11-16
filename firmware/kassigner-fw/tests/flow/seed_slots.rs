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

//! Seeds and their slots: loaded, generated, put in use, deleted, and the
//! passphrase.

use super::*;

/// A tap on the seeds screen, on page 0.
fn on_seeds(f: &Flow<'_, 6>, t: seeds::Target) -> Event<'static> {
    let rows: Vec<_> = (0..f.seed_count()).filter_map(|i| f.seed(i)).collect();
    tap_in(seeds::zone(SCALE, &rows, 6, 0, t).expect("on the seeds screen"))
}

/// A generator that has died.
struct Dead;

impl Entropy for Dead {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), entropy::Error> {
        Err(entropy::Error::Unhealthy)
    }
}

/// A second seed, for the tests that hold two.
fn other_seedqr() -> Vec<u8> {
    let m = bip39::from_entropy(&[9u8; 16]).unwrap();
    let mut out = [0u8; slot::SEEDQR_MAX];
    let n = slot::to_seedqr(&m, &mut out);
    out[..n].to_vec()
}

// ── Seed ────────────────────────────────────────────────────────────────────

/// A scanned SeedQR is stored only once Load is tapped, then is the seed in
/// use.
#[test]
fn a_seedqr_is_loaded_only_on_load() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    let digits = seedqr();
    f.step(Event::Code(&digits), &mut Live);
    assert_eq!(f.state(), State::Loading);
    assert_eq!(f.seed_count(), 0, "nothing stored while asking");
    assert_eq!(f.fingerprint(), None);

    f.touch(answer(dialog::Target::Accept));
    assert_eq!(
        f.seed_count(),
        0,
        "nothing stored while the passphrase is asked"
    );
    let out = f.step(no_passphrase(), &mut Live);
    assert_eq!(
        out.screen,
        Screen::Opening {
            done: 0,
            total: OPEN_STEPS
        },
        "stored, and being opened where the screen can show it"
    );
    assert_eq!(f.seed_count(), 1);
    opened(&mut f);
    assert_eq!(f.state(), State::Seeds { page: 0 });
    let row = f.seed(0).expect("a row");
    assert_eq!(row.fingerprint, wallet().fingerprint());
    assert_eq!(row.kind, seeds::Kind::Words12);
    assert!(row.active && !row.passphrase);
}

/// Cancelling a read SeedQR stores nothing and drops the words.
#[test]
fn a_seedqr_can_be_refused() {
    for t in [dialog::Target::Cancel, dialog::Target::Nav(Nav::Back)] {
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        f.step(scan(), &mut Live);
        let digits = seedqr();
        f.step(Event::Code(&digits), &mut Live);
        f.touch(answer(t));
        assert_eq!(f.state(), State::Home, "{t:?}");
        assert_eq!(f.seed_count(), 0);
        // The words went with the question: Load has nothing to load.
        assert_eq!(
            f.step(Event::Tick { now_us: 1 }, &mut Live).screen,
            Screen::Home
        );
    }
}

/// Something neither a request nor a SeedQR is refused, then Home.
#[test]
fn a_code_that_is_not_a_seedqr_is_refused() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    let out = f.step(Event::Code(b"hello"), &mut Live);
    assert_eq!(f.state(), State::Refused(Refusal::NotRecognised));
    assert_eq!(out.command, Some(Command::CameraOff));
    f.step(Event::Tick { now_us: 1 << 40 }, &mut Live);
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.fingerprint(), None);
}

/// Seed words are a seed: twelve or twenty-four list words, any case,
/// spaced or on lines (as a Plain Words QR holds them), in one code or in
/// frames, bring LOAD SEED?. List words that are not a phrase are refused,
/// never shown; fewer than twelve are refused as other text.
#[test]
fn the_main_scanner_reads_seed_words() {
    let phrase = |m: &bip39::Mnemonic| {
        (0..m.len())
            .map(|i| m.word(i).unwrap())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let twelve = phrase(&bip39::from_entropy(&[9u8; 16]).unwrap());
    let twenty_four = phrase(&bip39::from_entropy(&[7u8; 32]).unwrap());
    let shouted = twelve.to_uppercase().replace(' ', "\n");
    for (text, words) in [(&twelve, 12), (&twenty_four, 24), (&shouted, 12)] {
        let mut m = Memory::new();
        let mut f: Flow<'_, 1> = booted(&mut m, &[]);
        f.step(scan(), &mut Live);
        let out = f.step(Event::Code(text.as_bytes()), &mut Live);
        assert_eq!(f.state(), State::Loading, "{text}");
        assert_eq!(out.screen, Screen::Loading { words });
        assert_eq!(out.command, Some(Command::CameraOff));
        assert_eq!(f.seed_count(), 0, "nothing stored while asking");
    }
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    f.step(Event::Opaque(twelve.as_bytes()), &mut Live);
    assert_eq!(f.state(), State::Loading, "in frames");

    // A bad checksum, a word too many: refused.
    let mut words: Vec<&str> = twelve.split(' ').collect();
    words.swap(0, 1);
    let swapped = words.join(" ");
    let thirteen = format!("{twelve} abandon");
    for text in [&swapped, &thirteen] {
        if bip39::from_words(text.split(' ')).is_ok() {
            continue;
        }
        let mut m = Memory::new();
        let mut f: Flow<'_, 1> = booted(&mut m, &[]);
        f.step(scan(), &mut Live);
        f.step(Event::Code(text.as_bytes()), &mut Live);
        assert_eq!(f.state(), State::Refused(Refusal::NotASeed), "{text}");
    }

    // Eleven words are other text: unrecognised in one code, Sign
    // Message's in frames.
    let eleven = twelve.split(' ').take(11).collect::<Vec<_>>().join(" ");
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    f.step(Event::Code(eleven.as_bytes()), &mut Live);
    assert_eq!(f.state(), State::Refused(Refusal::NotRecognised));
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    f.step(Event::Opaque(eleven.as_bytes()), &mut Live);
    assert_eq!(f.state(), State::Refused(Refusal::PlainText));
}

/// Of two seeds the last loaded is in use; a tap on the other's row puts it
/// in use, and the fingerprint follows.
#[test]
fn a_tap_on_a_seed_puts_it_in_use() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    load(&mut f, &other_seedqr());
    assert_eq!(f.seed_count(), 2);
    let second = f.fingerprint().expect("in use");
    assert_ne!(second, wallet().fingerprint());
    assert!(f.seed(1).unwrap().active && !f.seed(0).unwrap().active);

    let row0 = on_seeds(&f, seeds::Target::Row(0));
    f.step(row0, &mut Live);
    opened(&mut f);
    assert_eq!(f.state(), State::Seeds { page: 0 });
    assert_eq!(f.fingerprint(), Some(wallet().fingerprint()));
    assert!(f.seed(0).unwrap().active && !f.seed(1).unwrap().active);
}

/// Delete asks first; Cancel keeps the seed, Delete wipes the slot and
/// closes the wallet of the seed in use.
#[test]
fn a_seed_is_deleted_only_on_delete() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    let del = on_seeds(&f, seeds::Target::Delete(0));
    let delete = answer(dialog::Target::Accept);
    let (Event::Tap { x, y }, Event::Tap { x: ox, y: oy }) =
        (delete, answer(dialog::Target::Cancel))
    else {
        unreachable!()
    };

    // Cancel keeps it.
    let out = f.step(del, &mut Live);
    assert_eq!(
        out.screen,
        Screen::Deleting {
            slot: 0,
            hold: None
        }
    );
    f.step(answer(dialog::Target::Cancel), &mut Live);
    assert_eq!(f.state(), State::Seeds { page: 0 });
    assert_eq!(f.seed_count(), 1);

    // A tap on Delete arms it, deleting nothing.
    f.step(del, &mut Live);
    let out = f.step(delete, &mut Live);
    assert_eq!(
        out.screen,
        Screen::Deleting {
            slot: 0,
            hold: Some(0)
        }
    );
    assert_eq!(f.seed_count(), 1);

    // Lifted before the time: kept.
    f.step(Event::Tick { now_us: 10 }, &mut Live);
    f.step(Event::Press { x, y }, &mut Live);
    f.step(
        Event::Tick {
            now_us: 10 + HOLD_US / 2,
        },
        &mut Live,
    );
    f.step(delete, &mut Live);
    assert_eq!(f.state(), State::Seeds { page: 0 });
    assert_eq!(f.seed_count(), 1, "released at half the time");

    // Slid off before the time: kept.
    f.step(del, &mut Live);
    f.step(delete, &mut Live);
    f.step(Event::Press { x, y }, &mut Live);
    f.step(Event::Drag { x: ox, y: oy }, &mut Live);
    assert_eq!(f.state(), State::Seeds { page: 0 });
    assert_eq!(f.seed_count(), 1, "slid onto Cancel");
    // The lift where it slid to hits nothing on the seeds screen.
    f.step(answer(dialog::Target::Cancel), &mut Live);
    assert_eq!(f.state(), State::Seeds { page: 0 });

    // Held for the time: gone, with its wallet.
    f.step(del, &mut Live);
    f.step(delete, &mut Live);
    let t = 1_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    f.step(Event::Press { x, y }, &mut Live);
    let out = f.step(
        Event::Tick {
            now_us: t + HOLD_US / 4,
        },
        &mut Live,
    );
    assert_eq!(
        out.screen,
        Screen::Deleting {
            slot: 0,
            hold: Some(25)
        }
    );
    f.step(
        Event::Tick {
            now_us: t + HOLD_US - 1,
        },
        &mut Live,
    );
    assert_eq!(f.seed_count(), 1, "not a microsecond early");
    f.step(
        Event::Tick {
            now_us: t + HOLD_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Seeds { page: 0 });
    assert_eq!(f.seed_count(), 0);
    assert_eq!(f.fingerprint(), None, "the wallet went with its seed");

    // The holding finger lifts on the seeds screen, on a `+` row: the end
    // of the hold, not a tap there.
    f.step(delete, &mut Live);
    assert_eq!(f.state(), State::Seeds { page: 0 }, "not taken to Tools");
    // The next touch pressed and lifted here is a tap.
    f.step(Event::Press { x, y }, &mut Live);
    f.step(delete, &mut Live);
    assert!(matches!(f.state(), State::Menu { .. }), "{:?}", f.state());
}

/// Full slots refuse one more seed and keep the ones they have.
#[test]
fn full_slots_refuse_another_seed() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    f.step(scan(), &mut Live);
    let other = other_seedqr();
    f.step(Event::Code(&other), &mut Live);
    f.touch(answer(dialog::Target::Accept));
    f.step(no_passphrase(), &mut Live);
    assert_eq!(f.state(), State::Refused(Refusal::SlotsFull));
    assert_eq!(f.fingerprint(), Some(wallet().fingerprint()));
}

/// Load opens the passphrase keyboard, storing nothing; what is typed is
/// never on the printed screen; OK asks for it again, and the second OK
/// stores the seed only if both match, a mismatch starting both again; Back
/// drops the seed and what was typed, on either keyboard.
#[test]
fn a_loaded_seed_takes_its_passphrase_from_the_keyboard() {
    use kassigner_fw::flow::Typing;
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    let digits = seedqr();
    f.step(Event::Code(&digits), &mut Live);
    let out = f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::Passphrase { page: 0 });
    assert!(matches!(
        out.screen,
        Screen::Keyboard {
            typing: Typing::Passphrase,
            page: 0,
            ..
        }
    ));
    assert_eq!(f.seed_count(), 0);

    // "aB 1" across three pages, with a deletion and a cursor move.
    let first = f.step(key(0, keyboard::Key::Char(b'a')), &mut Live).screen;
    f.step(key(0, keyboard::Key::Char(b'x')), &mut Live);
    f.step(key(0, keyboard::Key::Delete), &mut Live);
    f.step(key(0, keyboard::Key::Page), &mut Live);
    assert_eq!(f.state(), State::Passphrase { page: 1 });
    f.step(key(1, keyboard::Key::Char(b'B')), &mut Live);
    f.step(key(1, keyboard::Key::Page), &mut Live);
    f.step(key(2, keyboard::Key::Char(b'1')), &mut Live);
    f.step(key(2, keyboard::Key::Left), &mut Live);
    let out = f.step(key(2, keyboard::Key::Space), &mut Live);
    assert_eq!(f.typed(), ("aB 1", 3));
    assert_ne!(out.screen, first, "every edit is a new screen to draw");
    let printed = format!("{:?}", out.screen);
    assert!(
        !printed.contains("aB"),
        "the text is not on the screen: {printed}"
    );

    // OK: asked again on an empty line, nothing stored yet.
    f.step(key(2, keyboard::Key::Ok), &mut Live);
    assert_eq!(f.state(), State::PassphraseAgain { page: 2 });
    assert_eq!(f.typed(), ("", 0), "the first is not on the line");
    assert_eq!(f.keyboard_note(), Some(keyboard::Note::Again));
    assert_eq!(f.seed_count(), 0);

    // Typed again wrong: both start again, nothing stored.
    f.step(key(2, keyboard::Key::Char(b'1')), &mut Live);
    f.step(key(2, keyboard::Key::Ok), &mut Live);
    assert_eq!(f.state(), State::Passphrase { page: 2 });
    assert_eq!(f.keyboard_note(), Some(keyboard::Note::NoMatch));
    assert_eq!(f.typed(), ("", 0));
    assert_eq!(f.seed_count(), 0);

    // "aB 1" again from page 2: a, B and 1 sit on pages 0, 1 and 2.
    let type_ab1 = |f: &mut Flow<'_, 6>| {
        let mut at = 2;
        for (page, c) in [(0, b'a'), (1, b'B'), (2, b'1')] {
            while at != page {
                f.step(key(at, keyboard::Key::Page), &mut Live);
                at = keyboard::next_page(at);
            }
            f.step(key(page, keyboard::Key::Char(c)), &mut Live);
        }
        f.step(key(2, keyboard::Key::Left), &mut Live);
        f.step(key(2, keyboard::Key::Space), &mut Live);
    };

    // Typed twice the same: stored with it, and both wiped.
    type_ab1(&mut f);
    assert_eq!(f.keyboard_note(), None, "a key takes No match away");
    f.step(key(2, keyboard::Key::Ok), &mut Live);
    type_ab1(&mut f);
    assert_eq!(f.typed(), ("aB 1", 3));
    f.step(key(2, keyboard::Key::Ok), &mut Live);
    assert!(matches!(f.state(), State::Opening { .. }));
    assert_eq!(f.typed(), ("", 0));
    let seed = f.seed(0).expect("stored");
    assert!(seed.passphrase, "with its passphrase");

    // Back, on either keyboard: nothing stored, nothing kept.
    for twice in [false, true] {
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        f.step(scan(), &mut Live);
        f.step(Event::Code(&digits), &mut Live);
        f.touch(answer(dialog::Target::Accept));
        f.step(key(0, keyboard::Key::Char(b'q')), &mut Live);
        if twice {
            f.step(key(0, keyboard::Key::Ok), &mut Live);
            f.step(key(0, keyboard::Key::Char(b'q')), &mut Live);
            assert_eq!(f.state(), State::PassphraseAgain { page: 0 });
        }
        f.step(back_button(), &mut Live);
        assert_eq!(f.state(), State::Home);
        assert_eq!(f.seed_count(), 0);
        assert_eq!(f.typed(), ("", 0));
        assert!(!f.holds_secret(), "the first entry wiped too");
    }
}

/// 512-byte camera samples needed for `bits` at the credited rate: 43 for
/// 128 at one bit per 160 bytes.
fn camera_samples_for(bits: u32) -> u8 {
    bits.div_ceil(512 / kassigner_fw::limits::CAMERA_BYTES_PER_BIT) as u8
}

/// A seed is made from the unit's sources, its words shown, and stored;
/// LATER on BACKUP CHECK leaves it with no backup.
#[test]
fn a_seed_is_generated_from_every_source_then_stored() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[Source::Camera, Source::Touch]);
    let command = new_seed(&mut f, &mut Live);
    assert_eq!(f.state(), State::Generating);
    assert_eq!(command, Some(Command::SamplesOn));
    assert_eq!(
        f.step(Event::Tick { now_us: 0 }, &mut Live).screen,
        Screen::Generating {
            credited: 0,
            share: 128,
            short: Some(Source::Camera),
        }
    );

    // The camera fills only its share; the seed waits on touch.
    for salt in 0..camera_samples_for(128) {
        let s = camera_sample(salt);
        f.step(Event::CameraSample(&s), &mut Live);
    }
    assert_eq!(f.state(), State::Generating);
    let Screen::Generating {
        credited, short, ..
    } = f.step(Event::Tick { now_us: 1 }, &mut Live).screen
    else {
        panic!("still generating");
    };
    assert_eq!(credited, 128, "the camera stops at its share");
    assert_eq!(short, Some(Source::Touch));

    // Moving touches, half a bit each, until the seed is made.
    let mut out = None;
    for i in 0..1000u16 {
        let o = f.step(
            Event::TouchMoved {
                x: i % 300,
                y: (i * 7) % 200,
                since_us: 40_000 + u32::from(i),
            },
            &mut Live,
        );
        if matches!(f.state(), State::ShowWords { .. }) {
            out = Some(o);
            break;
        }
    }
    let out = out.expect("a seed was made from 256 moving touches");
    assert_eq!(out.command, Some(Command::SamplesOff));
    // Its words, a tap each, nothing stored meanwhile.
    assert_eq!(f.state(), State::ShowWords { pos: 0 });
    assert_eq!(f.seed_count(), 0);
    for i in 0..12u8 {
        assert_eq!(f.state(), State::ShowWords { pos: i });
        assert!(f.shown_word().is_some());
        f.step(on_choice(0), &mut Live);
    }
    assert_eq!(f.state(), State::BackupAsk { by: Check::Words });
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.seed_count(), 1);
    opened(&mut f);
    assert_eq!(f.state(), State::Seeds { page: 0 });
    assert!(f.fingerprint().is_some());
    assert!(!in_use_backed(&f), "LATER: no backup yet");
}

/// A dead generator refuses the seed at the last step; nothing is stored.
#[test]
fn a_dead_generator_refuses_the_seed() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[Source::Camera]);
    new_seed(&mut f, &mut Dead);
    // The only source, so the camera's share is all 256.
    for salt in 0..camera_samples_for(kassigner_fw::limits::SEED_MIN_BITS) {
        let s = camera_sample(salt);
        f.step(Event::CameraSample(&s), &mut Dead);
    }
    assert_eq!(f.state(), State::Refused(Refusal::NoEntropy));
    assert_eq!(f.seed_count(), 0, "nothing stored");
    f.step(Event::Tick { now_us: 1 << 40 }, &mut Dead);
    assert_eq!(f.state(), State::Home);
}

/// The back button leaves Generating, dropping the collector.
#[test]
fn generating_can_be_cancelled() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[Source::Camera]);
    new_seed(&mut f, &mut Live);
    let s = camera_sample(1);
    f.step(Event::CameraSample(&s), &mut Live);
    // A tap anywhere but the back button is a touch for the seed.
    let out = f.step(tap_in(Zone::new(160, 120, 1, 1)), &mut Live);
    assert_eq!(f.state(), State::Generating);
    assert_eq!(out.command, None);
    let out = f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedTools,
            page: 0
        },
        "back where it was started"
    );
    assert_eq!(out.command, Some(Command::SamplesOff));
    // Starting again starts from nothing.
    let out = f.step(item(&menu::SEED_TOOLS, 0), &mut Live);
    assert!(matches!(out.screen, Screen::Generating { credited: 0, .. }));
}

/// A 32-byte code shaped as a v1.0.7 set's last frame is held until its
/// frame zero comes, which for about one 24-word compact SeedQR in 266,000
/// never does. Read alone for `SEED_HINT_US`, the scan screen says how else
/// to load it. A gap over `SEED_GAP_US` restarts the count, a frame of a set
/// clears the line, and a new scan starts without it.
#[test]
fn a_seed_held_as_a_v107_frame_is_named_after_a_while() {
    use kassigner_fw::flow::{SEED_GAP_US, SEED_HINT_US};
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    let start = 10_000_000;
    let read = |f: &mut Flow<'_, 1>, now_us: u64| {
        f.step(Event::Tick { now_us }, &mut Live);
        f.step(Event::LastFrameOrSeed, &mut Live).screen
    };
    let hinted = |hint: bool| Screen::Scanning {
        have: 0,
        total: 0,
        received: 0,
        hint,
    };

    // Read twice a second: no line until the time is reached.
    f.step(scan(), &mut Live);
    let mut t = start;
    while t - start < SEED_HINT_US {
        assert_eq!(
            read(&mut f, t),
            hinted(false),
            "at {} ms",
            (t - start) / 1000
        );
        t += 500_000;
    }
    assert_eq!(read(&mut f, t), hinted(true));
    assert_eq!(f.state(), State::Scanning, "and the scan goes on");

    // A frame of a set: the held code was one of its frames.
    let out = f.step(
        Event::Progress {
            have: 1,
            total: 15,
            received: 1 << 14,
        },
        &mut Live,
    );
    assert_eq!(
        out.screen,
        Screen::Scanning {
            have: 1,
            total: 15,
            received: 1 << 14,
            hint: false
        }
    );

    // Reads further apart than the gap never add up.
    f.step(back_button(), &mut Live);
    f.step(scan(), &mut Live);
    let gap = SEED_GAP_US + 1;
    for k in 0..4 {
        assert_eq!(read(&mut f, t + k * gap), hinted(false), "read {k}");
    }

    // A line shown is gone from the next scan.
    let mut u = t + 4 * gap;
    let from = u;
    while u - from <= SEED_HINT_US {
        read(&mut f, u);
        u += 500_000;
    }
    assert_eq!(read(&mut f, u), hinted(true));
    f.step(back_button(), &mut Live);
    assert_eq!(f.step(scan(), &mut Live).screen, hinted(false));
}
