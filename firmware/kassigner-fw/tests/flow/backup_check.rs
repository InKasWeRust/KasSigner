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

//! The backup check: a seed made here is marked, and can only be backed up,
//! until three of its words are picked, its code is scanned back or a
//! backup is written; a loaded seed is never marked.

use super::*;
use kassigner_fw::ui::backup;

/// The test seed loaded and its 12-word BIP85 child at index 0 derived, up
/// to its first word; returns the child.
fn child_shown(f: &mut Flow<'_, 6>) -> bip39::Mnemonic {
    use kassigner_fw::ui::bip85::{zone, Target};
    use kassigner_fw::ui::words::{count_zone, Target as Count};
    load(f, &seedqr());
    f.step(home_button(), &mut Live);
    seed_tool(f, 5);
    f.step(
        tap_in(count_zone(SCALE, Count::Words(12)).unwrap()),
        &mut Live,
    );
    f.step(
        tap_in(zone(SCALE, true, Target::Derive).unwrap()),
        &mut Live,
    );
    f.step(Event::Tick { now_us: f.now_us() }, &mut Live);
    assert_eq!(f.state(), State::ShowWords { pos: 0 });
    let master = master_of(&mnemonic());
    kassigner_crypto::bip85::derive_mnemonic(&master, 12, 0).unwrap()
}

/// The child shown and stored with LATER: in use, with no backup.
fn child_unchecked(f: &mut Flow<'_, 6>) -> bip39::Mnemonic {
    let child = child_shown(f);
    words_through(f, &child);
    assert_eq!(f.state(), State::BackupAsk { by: Check::Words });
    f.touch(answer(dialog::Target::Accept));
    opened(f);
    assert!(!in_use_backed(f));
    child
}

/// A standard SeedQR's digits for `m`: four a word.
fn digits_of(m: &bip39::Mnemonic) -> Vec<u8> {
    (0..m.len())
        .flat_map(|i| format!("{:04}", m.index(i).unwrap()).into_bytes())
        .collect()
}

/// Tools, Import / Export, Export, and its row `row`.
fn export_row(f: &mut Flow<'_, 6>, row: usize) {
    f.step(home_button(), &mut Live);
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(backup::zone(SCALE, backup::Target::Export).unwrap()),
        &mut Live,
    );
    f.step(item(&menu::EXPORT, row), &mut Live);
}

/// A wrong pick fails the check, the seed kept; the words show again from
/// the first, and three right picks store it backed up.
#[test]
fn a_wrong_word_shows_the_words_again() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let child = child_shown(&mut f);
    words_through(&mut f, &child);
    let out = f.touch(answer(dialog::Target::Cancel));
    assert_eq!(f.state(), State::WordCheck { round: 0 });
    let (place, offered) = f.check_words().unwrap();
    assert_eq!(out.screen, Screen::WordCheck { round: 0, place });
    let right = child.word(usize::from(place)).unwrap();
    let wrong = offered.iter().position(|w| *w != right).unwrap();
    let out = f.touch(on_choice(wrong));
    assert_eq!(out.screen, Screen::CheckFailed { qr: false });
    assert_eq!(f.check_words(), None, "the check wiped");
    assert_eq!(f.seed_count(), 1, "the child kept, not stored");
    f.step(
        Event::Tick {
            now_us: f.now_us() + ERROR_US,
        },
        &mut Live,
    );
    words_through(&mut f, &child);
    f.touch(answer(dialog::Target::Cancel));
    pass_check(&mut f, &child);
    opened(&mut f);
    assert_eq!(f.seed_count(), 2);
    assert!(in_use_backed(&f), "checked: a backup");
}

/// BACKUP CHECK's Back is the last word, CHECK's Back is BACKUP CHECK, and
/// Home drops the seed being made.
#[test]
fn backup_check_goes_back_to_the_words() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let child = child_shown(&mut f);
    words_through(&mut f, &child);
    f.touch(back_button());
    assert_eq!(f.state(), State::ShowWords { pos: 11 });
    f.step(on_choice(0), &mut Live);
    f.touch(answer(dialog::Target::Cancel));
    f.touch(back_button());
    assert_eq!(f.state(), State::BackupAsk { by: Check::Words });
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.seed_count(), 1, "the child dropped");
}

/// A seed with no backup can only be backed up: its address, kpubs, keys, a
/// BIP85 child and a request to sign are refused (NO BACKUP YET), its row's
/// Address is dimmed and the row says NO BACKUP. Show Seed Words leads to
/// the check; once checked, it works as any seed.
#[test]
fn a_seed_with_no_backup_is_only_backed_up() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let child = child_unchecked(&mut f);
    let refused = State::Refused(Refusal::NotBackedUp);
    let rest = |f: &mut Flow<'_, 6>| {
        f.step(
            Event::Tick {
                now_us: f.now_us() + REFUSED_US,
            },
            &mut Live,
        );
        f.step(home_button(), &mut Live);
    };

    // The row, and its Address.
    let rows: Vec<_> = (0..f.seed_count()).filter_map(|r| f.seed(r)).collect();
    assert!(seeds::address_dimmed(&rows));
    assert!(seeds::zone(SCALE, &rows, 6, 0, seeds::Target::Address).is_none());
    let mut said = [0u8; 40];
    let active = rows.iter().find(|s| s.active).unwrap();
    assert_eq!(active.describe(&mut said), "Slot: NO BACKUP (12-word seed)");
    assert_eq!(f.state(), State::Seeds { page: 0 });
    f.step(tap_in(SCALE.zone(11, 54, 146, 28)), &mut Live);
    assert_eq!(f.state(), State::Seeds { page: 0 }, "Address dimmed");

    // Seed Tools' Address and BIP85 Child.
    f.step(home_button(), &mut Live);
    seed_tool(&mut f, 3);
    assert_eq!(f.state(), refused);
    rest(&mut f);
    seed_tool(&mut f, 5);
    assert_eq!(f.state(), refused);
    rest(&mut f);

    // Watch-Only's kpubs, on the tick after the tap.
    for row in 0..3 {
        export_row(&mut f, 1);
        f.step(item(&menu::WATCH_ONLY, row), &mut Live);
        f.step(Event::Tick { now_us: f.now_us() }, &mut Live);
        assert_eq!(f.state(), refused, "Watch-Only row {row}");
        rest(&mut f);
    }

    // Signing Keys.
    for row in 0..3 {
        export_row(&mut f, 2);
        f.step(item(&menu::SIGNING_KEYS, row), &mut Live);
        assert_eq!(f.state(), refused, "Signing Keys row {row}");
        rest(&mut f);
    }

    // A request scanned.
    f.step(scan(), &mut Live);
    deliver(&mut f, &ours());
    assert_eq!(f.state(), refused);
    rest(&mut f);

    // Show Seed Words, then the check at once; checked, the address opens.
    export_row(&mut f, 0);
    f.step(item(&menu::SEED_BACKUP, 0), &mut Live);
    words_through(&mut f, &child);
    pass_check(&mut f, &child);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedBackup,
            page: 0
        }
    );
    assert!(in_use_backed(&f));
    f.step(home_button(), &mut Live);
    seed_tool(&mut f, 3);
    assert_eq!(f.state(), State::Address);
}

/// A code scanned back checks the backup: after the SeedQR, CHECK opens the
/// camera; another seed's code fails and BACKUP CHECK returns; this seed's,
/// as words or digits, clears the mark. LATER is SEED EXPORTED.
#[test]
fn a_code_scanned_back_checks_the_backup() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let child = child_unchecked(&mut f);
    let by = Check::Code {
        plain: false,
        compact: false,
    };
    let shown = |f: &mut Flow<'_, 6>| {
        export_row(f, 0);
        f.step(item(&menu::SEED_BACKUP, 1), &mut Live);
        f.step(item(&menu::QR_EXPORT, 1), &mut Live);
        assert_eq!(f.state(), State::SeedQr { compact: false });
        f.step(on_choice(0), &mut Live);
        f.step(back_button(), &mut Live);
    };
    shown(&mut f);
    assert_eq!(f.state(), State::BackupAsk { by });
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(
        f.state(),
        State::SeedDone {
            plain: false,
            compact: false
        },
        "LATER: SEED EXPORTED"
    );
    f.touch(home_button());

    shown(&mut f);
    let out = f.touch(answer(dialog::Target::Cancel));
    assert_eq!(out.command, Some(Command::CameraOn));
    assert_eq!(
        f.state(),
        State::BackupScan {
            plain: false,
            compact: false
        }
    );
    let out = f.step(Event::Code(&seedqr()), &mut Live);
    assert_eq!(out.command, Some(Command::CameraOff));
    assert_eq!(out.screen, Screen::CheckFailed { qr: true });
    f.step(
        Event::Tick {
            now_us: f.now_us() + ERROR_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::BackupAsk { by });
    assert!(!in_use_backed(&f));

    f.touch(answer(dialog::Target::Cancel));
    let text = (0..child.len())
        .map(|i| child.word(i).unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    let out = f.step(Event::Code(text.as_bytes()), &mut Live);
    assert_eq!(out.screen, Screen::BackupChecked);
    assert!(in_use_backed(&f), "its words, read back");

    // Digits read as the same seed.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let child = child_unchecked(&mut f);
    shown(&mut f);
    f.touch(answer(dialog::Target::Cancel));
    f.step(Event::Code(&digits_of(&child)), &mut Live);
    assert_eq!(f.state(), State::BackupChecked { by });
    f.step(
        Event::Tick {
            now_us: f.now_us() + ERROR_US,
        },
        &mut Live,
    );
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedBackup,
            page: 0
        }
    );
    assert!(in_use_backed(&f));
}

/// A backup saved to the card clears the mark once the card says it is
/// written.
#[test]
fn a_backup_written_to_the_card_clears_the_mark() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    child_unchecked(&mut f);
    export_row(&mut f, 0);
    f.step(item(&menu::SEED_BACKUP, 2), &mut Live);
    assert_eq!(f.state(), State::BackupWarning);
    f.step(
        tap_in(backup::zone(SCALE, backup::Target::Understand).unwrap()),
        &mut Live,
    );
    f.step(Event::Card(Outcome::NextName(1)), &mut Live);
    press(&mut f, keyboard::Key::Ok);
    f.step(Event::Card(Outcome::Exists(false)), &mut Live);
    let password = b"Correct-Horse-9";
    type_on(&mut f, password);
    press(&mut f, keyboard::Key::Ok);
    type_on(&mut f, password);
    press(&mut f, keyboard::Key::Ok);
    let mut ticks = 0;
    while matches!(f.state(), State::BackupSealing { .. }) {
        f.step(Event::Tick { now_us: f.now_us() }, &mut Live);
        ticks += 1;
        assert!(ticks < 40);
    }
    assert_eq!(f.state(), State::CardBusy(Job::Write));
    assert!(!in_use_backed(&f), "not until it is written");
    f.step(Event::Card(Outcome::Written), &mut Live);
    assert!(in_use_backed(&f), "written: a backup");
}

/// A loaded seed has a backup, and loading a marked seed again clears its
/// mark.
#[test]
fn a_seed_loaded_has_a_backup() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    assert!(in_use_backed(&f));

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let child = child_unchecked(&mut f);
    f.step(home_button(), &mut Live);
    load(&mut f, &digits_of(&child));
    assert_eq!(f.seed_count(), 2, "the same slot");
    assert!(in_use_backed(&f), "loaded: a backup");
}
