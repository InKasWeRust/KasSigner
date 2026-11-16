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

//! The sounds, and the one way a cue becomes notes.

use kassigner_fw::cues::{play, start_ticking, Cue, TICK};
use kassigner_hal::speaker::{Note, Silent, Speaker};

const ALL: [Cue; 7] = [
    Cue::Click,
    Cue::CodeFound,
    Cue::CodeDecoded,
    Cue::Error,
    Cue::Boot,
    Cue::Success,
    Cue::Warning,
];

/// **Every cue plays exactly these notes** (hertz, level, milliseconds);
/// the error beep's pause is a rest.
#[test]
fn every_cue_plays_its_notes() {
    let n = Note::new;
    let want: [(Cue, &[Note]); 7] = [
        (Cue::Click, &[n(4000, 8000, 30)]),
        (Cue::CodeFound, &[n(2000, 4000, 15)]),
        (Cue::CodeDecoded, &[n(2400, 8000, 30), n(3600, 8000, 30)]),
        (
            Cue::Error,
            &[n(300, 10000, 150), Note::rest(50), n(300, 10000, 150)],
        ),
        (
            Cue::Boot,
            &[n(800, 6000, 100), n(1200, 6000, 100), n(1600, 6000, 150)],
        ),
        (
            Cue::Success,
            &[n(1200, 6000, 80), n(1600, 6000, 80), n(2000, 6000, 120)],
        ),
        (Cue::Warning, &[n(1200, 8000, 120), n(600, 8000, 200)]),
    ];
    for (cue, notes) in want {
        assert_eq!(cue.notes(), notes, "{cue:?}");
    }
    assert_eq!(TICK, n(2000, 5000, 15), "the tick: 15 ms of 2 kHz");
    assert_eq!(
        Cue::Error.notes().iter().map(|n| n.ms).sum::<u16>(),
        350,
        "150, a 50 ms pause, and 150 again"
    );
}

/// What a board was asked to do.
#[derive(Debug, PartialEq)]
enum Call {
    Tone(Note),
    Silence,
    Tick(Note),
}

#[derive(Default)]
struct Recorder(Vec<Call>);

impl Speaker for Recorder {
    fn tone(&mut self, note: Note) {
        self.0.push(Call::Tone(note));
    }
    fn silence(&mut self) {
        self.0.push(Call::Silence);
    }
    fn set_volume(&mut self, _volume: u8) {}
    fn start_ticking(&mut self, note: Note) {
        self.0.push(Call::Tick(note));
    }
    fn stop_ticking(&mut self) {}
}

/// **Playing a cue is its notes in order, then silence, once.**
#[test]
fn a_cue_is_its_notes_then_silence() {
    for cue in ALL {
        let mut r = Recorder::default();
        play(&mut r, cue);
        let mut want: Vec<Call> = cue.notes().iter().map(|&n| Call::Tone(n)).collect();
        want.push(Call::Silence);
        assert_eq!(r.0, want, "{cue:?}");
    }
}

/// **The tick a flow starts is the tick note, and a board without a speaker
/// takes it.**
#[test]
fn the_tick_is_one_note_repeating() {
    let mut r = Recorder::default();
    start_ticking(&mut r);
    assert_eq!(r.0, vec![Call::Tick(TICK)]);

    start_ticking(&mut Silent);
    for cue in ALL {
        play(&mut Silent, cue);
    }
}

/// **Every tap that did something clicks, whatever else it sounds**: a
/// screen changed or a command given. CANCEL on CONFIRM SEND? clicks, then
/// sounds the error. A tap on nothing, and a step no tap made, do not
/// click.
#[test]
fn every_tap_that_does_something_clicks() {
    use kassigner_fw::cues::{clicks, for_step};
    use kassigner_fw::flow::{Refusal, Screen};

    let home = Screen::Home;
    let seeds = Screen::Seeds { page: 0 };
    let confirm = Screen::Confirm;
    let cancelled = Screen::Refused(Refusal::Declined);
    assert!(clicks(&home, &seeds, true, false));
    assert!(clicks(&home, &home, true, true), "a command");
    assert!(!clicks(&home, &home, true, false), "a tap on nothing");
    assert!(!clicks(&home, &seeds, false, false), "not a tap");
    assert!(clicks(&confirm, &cancelled, true, false), "CANCEL");
    assert_eq!(
        for_step(&confirm, &cancelled, true, false),
        Some(Cue::Error),
        "and then the error"
    );
    let signing = Screen::Signing;
    assert!(clicks(&confirm, &signing, true, false), "CONFIRM");
    assert!(!clicks(&signing, &Screen::ReplyFormat, false, false));
    // Home's logo held: no tap, the success sound once, then quiet.
    assert_eq!(
        for_step(&home, &Screen::Wiped, false, false),
        Some(Cue::Success)
    );
    assert_eq!(for_step(&Screen::Wiped, &Screen::Wiped, false, false), None);
    assert!(!clicks(&home, &Screen::Wiped, false, false));
}

/// **Each cue falls where its event happens**: a halt warns, a refusal is
/// an error, a reply shown and a seed opened succeed, the home screen after
/// the checks chimes, and a tap clicks when the step has no other sound.
/// Staying on a screen earns nothing.
#[test]
fn cues_fall_where_their_events_do() {
    use kassigner_fw::cues::for_step;
    use kassigner_fw::flow::{Halt, Refusal, Screen};
    use kassigner_fw::ui::brand::Check;
    use kassigner_hal::provisioning::Verdict;

    let clean = Check {
        verdict: Verdict::Provisioned,
        image_read: true,
    };
    let home = Screen::Home;
    let seeds = Screen::Seeds { page: 0 };
    let halted = Screen::Halted(Halt::SelfTest);
    let refused = Screen::Refused(Refusal::NotARequest);
    let reply = Screen::Reply {
        frame: 0,
        frames: 2,
    };
    let opening = Screen::Opening { done: 1, total: 2 };

    assert_eq!(for_step(&home, &seeds, true, false), Some(Cue::Click));
    assert_eq!(for_step(&home, &home, true, true), Some(Cue::Click));
    assert_eq!(
        for_step(&home, &home, true, false),
        None,
        "a tap on nothing"
    );
    assert_eq!(for_step(&home, &seeds, false, false), None, "not a tap");

    assert_eq!(for_step(&home, &halted, false, false), Some(Cue::Warning));
    assert_eq!(for_step(&halted, &halted, false, false), None);
    assert_eq!(for_step(&home, &refused, true, true), Some(Cue::Error));
    assert_eq!(for_step(&refused, &refused, false, false), None);
    assert_eq!(
        for_step(&reply, &reply, false, false),
        None,
        "the next frame"
    );
    // SIGNED TX QR sounds the success; the taps after it click; a save's
    // result giving way to SIGNED TX is silent.
    let confirm = Screen::Confirm;
    let signing = Screen::Signing;
    let format = Screen::ReplyFormat;
    let mode = Screen::ReplyMode;
    assert_eq!(
        for_step(&confirm, &signing, true, false),
        Some(Cue::Click),
        "CONFIRM's tap"
    );
    assert_eq!(
        for_step(&signing, &format, false, false),
        Some(Cue::Success)
    );
    assert_eq!(for_step(&format, &mode, true, false), Some(Cue::Click));
    assert_eq!(
        for_step(&mode, &format, true, false),
        Some(Cue::Click),
        "Back"
    );
    assert_eq!(
        for_step(&mode, &mode, true, false),
        None,
        "a tap on nothing"
    );
    assert_eq!(for_step(&mode, &reply, true, false), Some(Cue::Click));
    let next = Screen::Reply {
        frame: 1,
        frames: 2,
    };
    assert_eq!(
        for_step(&reply, &next, true, false),
        Some(Cue::Click),
        "Manual's next frame"
    );
    let done = Screen::ReplyDone;
    assert_eq!(for_step(&next, &done, true, false), Some(Cue::Click));
    use kassigner_fw::card::{Job as CardJob, Outcome as CardOutcome};
    let saved = Screen::CardDone {
        job: CardJob::Write,
        outcome: CardOutcome::Written,
    };
    assert_eq!(for_step(&saved, &done, false, false), None);
    assert_eq!(for_step(&opening, &seeds, false, false), Some(Cue::Success));
    assert_eq!(
        for_step(
            &opening,
            &Screen::Opening { done: 2, total: 2 },
            false,
            false
        ),
        None
    );
    assert_eq!(
        for_step(&Screen::Verified(clean), &home, false, false),
        Some(Cue::Boot)
    );

    // A job on the card: the success or the error, once.
    use kassigner_fw::card::{Error, Job, Outcome};
    let busy = Screen::CardBusy(Job::Test);
    let passed = Screen::CardDone {
        job: Job::Test,
        outcome: Outcome::Tested {
            bytes: 34,
            files: 1,
        },
    };
    let failed = Screen::CardDone {
        job: Job::Format,
        outcome: Outcome::Failed(Error::Data),
    };
    assert_eq!(for_step(&busy, &passed, false, false), Some(Cue::Success));
    assert_eq!(for_step(&busy, &failed, false, false), Some(Cue::Error));
    assert_eq!(for_step(&passed, &passed, false, false), None);
    let empty = Screen::CardDone {
        job: Job::List,
        outcome: Outcome::Listed { count: 0, extra: 0 },
    };
    let listing = Screen::CardBusy(Job::List);
    assert_eq!(
        for_step(&listing, &empty, false, false),
        None,
        "an empty card is said, not sounded"
    );
}

/// **A phrase that fails its checksum sounds as a refusal does**, once.
#[test]
fn an_invalid_phrase_sounds_the_error() {
    use kassigner_fw::cues::for_step;
    use kassigner_fw::flow::{Screen, WordsFor};
    use kassigner_fw::text::Typed;
    let field = Typed::<8>::new().field();
    let typing = |invalid| Screen::Words {
        action: WordsFor::Import,
        pos: 11,
        of: 12,
        filled: 12,
        field,
        invalid,
    };
    assert_eq!(
        for_step(&typing(false), &typing(true), true, false),
        Some(Cue::Error)
    );
    assert_eq!(for_step(&typing(true), &typing(true), false, false), None);
}

/// **A scan ticks for each frame it takes and chirps when it has read**,
/// CHECKING included, which gives way silently to the review or with the
/// error to a refusal. A refusal of what it read is the error alone, Back a
/// click, and the idle wipe to Home silent.
#[test]
fn a_scan_ticks_and_chirps() {
    use kassigner_fw::cues::{clicks, for_step};
    use kassigner_fw::flow::{Refusal, Screen};

    let scan = |have, total| Screen::Scanning {
        have,
        total,
        received: 0,
        hint: false,
    };
    let text = |have, total| Screen::MessageScan {
        have,
        total,
        received: 0,
    };
    let tick = Some(Cue::CodeFound);
    let chirp = Some(Cue::CodeDecoded);

    assert_eq!(for_step(&scan(0, 0), &scan(1, 3), false, false), tick);
    assert_eq!(for_step(&scan(1, 3), &scan(2, 3), false, false), tick);
    assert_eq!(
        for_step(&scan(2, 3), &scan(1, 5), false, false),
        tick,
        "another set"
    );
    assert_eq!(for_step(&text(0, 0), &text(1, 2), false, false), tick);
    assert_eq!(for_step(&scan(2, 3), &scan(2, 3), false, false), None);
    let hint = Screen::Scanning {
        have: 0,
        total: 0,
        received: 0,
        hint: true,
    };
    assert_eq!(for_step(&scan(0, 0), &hint, false, false), None, "the line");
    assert_eq!(
        for_step(&scan(0, 0), &scan(0, 0), true, false),
        None,
        "a tap on the picture"
    );

    let page = Screen::Page { index: 0, pages: 3 };
    assert_eq!(for_step(&scan(2, 3), &page, false, true), chirp);
    assert_eq!(for_step(&scan(2, 3), &Screen::Checking, false, true), chirp);
    assert_eq!(for_step(&Screen::Checking, &page, false, false), None);
    assert_eq!(
        for_step(
            &Screen::Checking,
            &Screen::Refused(Refusal::NoWallet),
            false,
            false
        ),
        Some(Cue::Error)
    );
    assert_eq!(
        for_step(&scan(0, 0), &Screen::Loading { words: 12 }, false, true),
        chirp
    );
    let preview = Screen::MessagePreview {
        page: 0,
        pages: 1,
        signed: false,
        live: true,
    };
    assert_eq!(for_step(&text(1, 2), &preview, false, true), chirp);

    let refused = Screen::Refused(Refusal::NotARequest);
    assert_eq!(
        for_step(&scan(0, 0), &refused, false, true),
        Some(Cue::Error)
    );
    assert_eq!(
        for_step(&scan(0, 0), &Screen::Home, true, true),
        Some(Cue::Click),
        "Back"
    );
    assert!(clicks(&scan(0, 0), &Screen::Home, true, true));
    assert_eq!(
        for_step(&scan(0, 0), &Screen::Home, false, true),
        None,
        "the idle wipe"
    );
}

/// **A message signed sounds as a transaction signed does**: SIGN's tap on
/// SIGN MESSAGE? clicks; a tap while it signs is nothing; SIGNING giving way
/// to the signature is the success, and to a refusal the error.
#[test]
fn a_message_signed_succeeds() {
    use kassigner_fw::cues::{clicks, for_step};
    use kassigner_fw::flow::{Refusal, Screen};
    let confirm = Screen::MessageConfirm;
    let signing = Screen::MessageSigning;
    let result = Screen::MessageResult { page: 0 };
    assert_eq!(for_step(&confirm, &signing, true, false), Some(Cue::Click));
    assert!(clicks(&confirm, &signing, true, false));
    assert_eq!(for_step(&signing, &signing, true, false), None);
    assert_eq!(
        for_step(&signing, &result, false, false),
        Some(Cue::Success)
    );
    assert_eq!(
        for_step(
            &signing,
            &Screen::Refused(Refusal::MessageNotSigned),
            false,
            false
        ),
        Some(Cue::Error)
    );
}

/// **The backup check's sounds**: a frame of a code's copy ticks as any
/// scan's; a failed check is the error, once; a passed one succeeds; a word
/// picked that leads on clicks.
#[test]
fn a_backup_check_sounds_as_it_goes() {
    use kassigner_fw::cues::for_step;
    use kassigner_fw::flow::Screen;

    let copy = |have, total| Screen::BackupScan {
        have,
        total,
        received: 0,
    };
    let check = |round| Screen::WordCheck { round, place: 4 };
    assert_eq!(
        for_step(&copy(0, 0), &copy(1, 2), false, false),
        Some(Cue::CodeFound)
    );
    assert_eq!(for_step(&copy(1, 2), &copy(1, 2), false, false), None);
    let failed = Screen::CheckFailed { qr: false };
    assert_eq!(for_step(&check(0), &failed, true, false), Some(Cue::Error));
    assert_eq!(for_step(&failed, &failed, false, false), None);
    assert_eq!(
        for_step(&copy(0, 0), &Screen::CheckFailed { qr: true }, false, true),
        Some(Cue::Error)
    );
    assert_eq!(
        for_step(&check(2), &Screen::BackupChecked, true, false),
        Some(Cue::Success)
    );
    assert_eq!(
        for_step(&Screen::BackupChecked, &Screen::BackupChecked, false, false),
        None
    );
    assert_eq!(
        for_step(&check(0), &check(1), true, false),
        Some(Cue::Click)
    );
}

/// **Uneven rolls warn**: the last face, bringing UNEVEN ROLLS, sounds the
/// warning, once.
#[test]
fn uneven_rolls_warn() {
    use kassigner_fw::cues::for_step;
    use kassigner_fw::flow::Screen;
    assert_eq!(
        for_step(
            &Screen::Dice {
                rolled: 98,
                target: 99
            },
            &Screen::DiceUneven,
            true,
            false
        ),
        Some(Cue::Warning)
    );
    assert_eq!(
        for_step(&Screen::DiceUneven, &Screen::DiceUneven, false, false),
        None
    );
}
