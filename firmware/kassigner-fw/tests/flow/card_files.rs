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

//! The card's backups: written, written over, restored and deleted, and what
//! a card failure says.

use super::*;

/// **A card alone never opens the funds.** A seed with a passphrase is
/// asked ENCRYPT FILE? after its backup's name, as a seed with none is not
/// (the test after this one goes from the name straight to the password).
/// Yes is the password, held to the policy as ever. No is warned of first:
/// CANCEL and a SAVE lifted early go back to ENCRYPT FILE?, and SAVE held
/// for its time seals the seed under no password. The file is sealed all
/// the same and opens under the empty password, to the same words, and
/// under no other.
#[test]
fn a_seed_with_a_passphrase_may_be_saved_with_no_password() {
    use kassigner_crypto::backup::open_slot;
    use kassigner_fw::card::{Job, Outcome};
    use kassigner_fw::ui::backup;

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    // The seed, opened behind a passphrase typed twice.
    f.step(scan(), &mut Live);
    let digits = seedqr();
    f.step(Event::Code(&digits), &mut Live);
    f.touch(answer(dialog::Target::Accept));
    for _ in 0..2 {
        for &c in b"kas" {
            f.step(key(0, keyboard::Key::Char(c)), &mut Live);
        }
        f.step(key(0, keyboard::Key::Ok), &mut Live);
    }
    opened(&mut f);

    f.step(home_button(), &mut Live);
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(backup::zone(SCALE, backup::Target::Export).unwrap()),
        &mut Live,
    );
    f.step(item(&menu::EXPORT, 0), &mut Live);
    f.step(item(&menu::SEED_BACKUP, 2), &mut Live);
    assert_eq!(f.state(), State::BackupWarning);
    f.step(
        tap_in(backup::zone(SCALE, backup::Target::Understand).unwrap()),
        &mut Live,
    );
    f.step(Event::Card(Outcome::NextName(3)), &mut Live);
    f.step(key(0, keyboard::Key::Ok), &mut Live);

    // The name is free: ENCRYPT FILE?, not the password.
    let out = f.step(Event::Card(Outcome::Exists(false)), &mut Live);
    assert_eq!(out.screen, Screen::KpubEncrypt);

    // Yes: the password, and no weak one. Back out, and the name again.
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(
        f.state(),
        State::BackupPassword {
            page: 0,
            again: false
        }
    );
    type_on(&mut f, b"weak");
    press(&mut f, keyboard::Key::Ok);
    assert!(
        matches!(f.state(), State::BackupPassword { again: false, .. }),
        "a typed password is held to the policy"
    );
    f.step(back_button(), &mut Live);
    f.step(item(&menu::SEED_BACKUP, 2), &mut Live);
    f.step(
        tap_in(backup::zone(SCALE, backup::Target::Understand).unwrap()),
        &mut Live,
    );
    f.step(Event::Card(Outcome::NextName(3)), &mut Live);
    f.step(key(0, keyboard::Key::Ok), &mut Live);
    f.step(Event::Card(Outcome::Exists(false)), &mut Live);
    assert_eq!(f.state(), State::KpubEncrypt);

    // No: the warning. CANCEL goes back to ENCRYPT FILE?.
    let no_password = |armed, held_since| State::BackupNoPassword { armed, held_since };
    let out = f.touch(answer(dialog::Target::Accept));
    assert_eq!(out.screen, Screen::BackupNoPassword { hold: None });
    assert_eq!(out.command, None, "nothing written yet");
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(f.state(), State::KpubEncrypt);

    // SAVE armed, lifted at half the time: nothing saved, ENCRYPT FILE?.
    let Event::Tap { x, y } = answer(dialog::Target::Accept) else {
        unreachable!()
    };
    f.touch(answer(dialog::Target::Accept));
    let out = f.touch(answer(dialog::Target::Accept));
    assert_eq!(out.screen, Screen::BackupNoPassword { hold: Some(0) });
    assert_eq!(f.state(), no_password(true, None));
    let t = 20_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    f.step(Event::Press { x, y }, &mut Live);
    let out = f.step(
        Event::Tick {
            now_us: t + HOLD_US / 2,
        },
        &mut Live,
    );
    assert_eq!(out.screen, Screen::BackupNoPassword { hold: Some(50) });
    let out = f.step(answer(dialog::Target::Accept), &mut Live);
    assert_eq!(out.command, None);
    assert_eq!(f.state(), State::KpubEncrypt, "released at half the time");

    // Held for the time: sealed under no password, then written.
    f.touch(answer(dialog::Target::Accept));
    f.touch(answer(dialog::Target::Accept));
    let t = 40_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    f.step(Event::Press { x, y }, &mut Live);
    let out = f.step(
        Event::Tick {
            now_us: t + HOLD_US,
        },
        &mut Live,
    );
    assert!(matches!(out.screen, Screen::BackupSealing { done: 0, .. }));
    let mut ticks = 0;
    let out = loop {
        ticks += 1;
        let out = f.step(
            Event::Tick {
                now_us: t + HOLD_US,
            },
            &mut Live,
        );
        if !matches!(out.screen, Screen::BackupSealing { .. }) {
            break out;
        }
        assert!(ticks < 40, "sealed in its batches");
    };
    assert_eq!(out.command, Some(Command::Card(Job::Write)));
    let file = {
        let r = f.card_request();
        r.file[..r.len].to_vec()
    };

    // Sealed: a container, the words not readable in it; the empty password
    // opens it to the same words, and another does not.
    assert!(kassigner_protocol::container::parse(&file).is_ok());
    let opened = open_slot(&file, b"", b"kas", None).expect("opens under no password");
    let Slot::Mnemonic { mnemonic, .. } = &opened else {
        panic!("a seed backup")
    };
    let mut plain = [0u8; kassigner_crypto::backup::SEED_PLAINTEXT_MAX];
    let n = kassigner_crypto::backup::seed_plaintext(mnemonic, &mut plain);
    assert!(
        !file.windows(n).any(|w| w == &plain[..n]),
        "the words are not readable in the file"
    );
    assert_eq!(mnemonic.len(), digits.len() / 4, "the same words");
    assert!(open_slot(&file, b"Piggy-Bank-2026", b"kas", None).is_err());
}

/// Backup to SD, step by step: the warning; the next free name, kept or
/// changed; an existing name asked about; a weak password refused, a good
/// one typed twice, a mismatch starting both again; the seed sealed, words
/// only, and the file written opening again to the same words, with no
/// passphrase in it.
#[test]
fn a_seed_is_backed_up_to_the_card_and_the_file_opens_again() {
    use kassigner_crypto::backup::open_slot;
    use kassigner_fw::card::{Job, Outcome};
    use kassigner_fw::flow::Typing;
    use kassigner_fw::ui::backup;

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    // Export needs a seed in use.
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    assert_eq!(f.state(), State::ImportExport);
    let export = tap_in(backup::zone(SCALE, backup::Target::Export).unwrap());
    f.step(export, &mut Live);
    assert_eq!(
        f.state(),
        State::Refused(Refusal::NoWallet),
        "no seed in use"
    );

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(export, &mut Live);
    f.step(item(&menu::EXPORT, 0), &mut Live);
    f.step(item(&menu::SEED_BACKUP, 2), &mut Live);
    assert_eq!(f.state(), State::BackupWarning);

    // I understand: the card is asked for the next name.
    let understand = tap_in(backup::zone(SCALE, backup::Target::Understand).unwrap());
    let out = f.step(understand, &mut Live);
    assert_eq!(out.command, Some(Command::Card(Job::NextName)));
    f.step(Event::Card(Outcome::NextName(3)), &mut Live);
    assert_eq!(f.typed(), ("SD0003", 6), "v1.0.7's next number");
    assert_eq!(f.state(), State::BackupName { page: 0 });

    // A symbol is refused; OK asks whether the name is taken.
    f.step(key(0, keyboard::Key::Page), &mut Live);
    f.step(key(1, keyboard::Key::Page), &mut Live);
    f.step(key(2, keyboard::Key::Char(b'!')), &mut Live);
    assert_eq!(f.typed().0, "SD0003");
    f.step(key(2, keyboard::Key::Page), &mut Live);
    f.step(key(3, keyboard::Key::Page), &mut Live);
    let out = f.step(key(0, keyboard::Key::Ok), &mut Live);
    assert_eq!(out.command, Some(Command::Card(Job::Exists)));
    assert_eq!(&f.card_request().name, b"SD0003  KAS");

    // It is: Cancel goes back to the name; Overwrite reads the file first,
    // and a plain one goes on.
    f.step(Event::Card(Outcome::Exists(true)), &mut Live);
    assert_eq!(f.state(), State::BackupOverwrite);
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(f.typed().0, "SD0003");
    f.step(key(0, keyboard::Key::Ok), &mut Live);
    f.step(Event::Card(Outcome::Exists(true)), &mut Live);
    let out = f.touch(answer(dialog::Target::Accept));
    assert_eq!(out.command, Some(Command::Card(Job::Read)));
    let out = f.step(Event::Card(Outcome::Read(0)), &mut Live);
    assert!(matches!(
        out.screen,
        Screen::Keyboard {
            typing: Typing::Password,
            ..
        }
    ));

    let type_in = |f: &mut Flow<'_, 6>, text: &[u8]| {
        for &c in text {
            let page = (0..keyboard::PAGES)
                .find(|&p| {
                    keyboard::zone(SCALE, p, keyboard::Target::Key(keyboard::Key::Char(c)))
                        .is_some()
                })
                .expect("a key for it");
            let State::BackupPassword { page: at, .. } = f.state() else {
                panic!("{:?}", f.state())
            };
            for _ in 0..(page + keyboard::PAGES - at) % keyboard::PAGES {
                f.step(key(f_page(f), keyboard::Key::Page), &mut Live);
            }
            f.step(key(page, keyboard::Key::Char(c)), &mut Live);
        }
    };
    fn f_page(f: &Flow<'_, 6>) -> u8 {
        match f.state() {
            State::BackupPassword { page, .. } => page,
            other => panic!("{other:?}"),
        }
    }

    // Too weak: OK is not taken, and the line says why.
    type_in(&mut f, b"short");
    assert_eq!(f.keyboard_note(), Some(keyboard::Note::TooShort));
    f.step(key(f_page(&f), keyboard::Key::Ok), &mut Live);
    assert!(matches!(
        f.state(),
        State::BackupPassword { again: false, .. }
    ));
    for _ in 0..5 {
        f.step(key(f_page(&f), keyboard::Key::Delete), &mut Live);
    }

    // At its limit the line says so in the strength's place, and takes no
    // more: a password cut short without a word is not the one meant.
    type_in(&mut f, &[b'a'; 64]);
    assert!(f.typed_full());
    assert_eq!(
        f.keyboard_note(),
        Some(keyboard::Note::Count { used: 64, of: 64 })
    );
    f.step(key(f_page(&f), keyboard::Key::Char(b'a')), &mut Live);
    f.step(key(f_page(&f), keyboard::Key::Space), &mut Live);
    assert_eq!(f.typed().0.len(), 64);
    for _ in 0..64 {
        f.step(key(f_page(&f), keyboard::Key::Delete), &mut Live);
    }

    // Good, typed twice wrong: both start again.
    let password = b"Correct-Horse-9";
    type_in(&mut f, password);
    assert!(matches!(
        f.keyboard_note(),
        Some(keyboard::Note::Fair | keyboard::Note::Good | keyboard::Note::Strong)
    ));
    f.step(key(f_page(&f), keyboard::Key::Ok), &mut Live);
    assert!(matches!(
        f.state(),
        State::BackupPassword { again: true, .. }
    ));
    assert_eq!(f.typed(), ("", 0), "the first is not on the line");
    type_in(&mut f, b"Correct-Horse-8");
    f.step(key(f_page(&f), keyboard::Key::Ok), &mut Live);
    assert!(matches!(
        f.state(),
        State::BackupPassword { again: false, .. }
    ));
    assert_eq!(f.keyboard_note(), Some(keyboard::Note::NoMatch));

    // Typed twice right: sealed on the next tick, then written.
    type_in(&mut f, password);
    f.step(key(f_page(&f), keyboard::Key::Ok), &mut Live);
    type_in(&mut f, password);
    let out = f.step(key(f_page(&f), keyboard::Key::Ok), &mut Live);
    assert!(matches!(out.screen, Screen::BackupSealing { done: 0, .. }));
    assert_eq!(f.typed(), ("", 0));
    // A batch of rounds a tick, the bar moving, then the write.
    let mut ticks = 0;
    let mut bar = 0;
    let out = loop {
        ticks += 1;
        let out = f.step(Event::Tick { now_us: 1_000_000 }, &mut Live);
        if let Screen::BackupSealing { done, .. } = out.screen {
            assert!(done > bar, "the bar moves");
            bar = done;
        } else {
            break out;
        }
        assert!(ticks < 40, "sealed in its batches");
    };
    assert_eq!(
        ticks, 21,
        "the salt, then twenty batches, the last one sealing"
    );
    assert_eq!(out.command, Some(Command::Card(Job::Write)));
    // What the binary is handed to write.
    let file = {
        let r = f.card_request();
        r.file[..r.len].to_vec()
    };
    assert!(!file.is_empty());
    assert!(
        !file.windows(password.len()).any(|w| w == password),
        "the password is not in the file"
    );

    // The file opens under the password to the same words, with no
    // passphrase in it.
    let opened = open_slot(&file, password, b"", None).expect("opens");
    let Slot::Mnemonic {
        mnemonic: words,
        passphrase,
    } = &opened
    else {
        panic!("a seed backup")
    };
    let original = mnemonic();
    assert_eq!(words.len(), original.len());
    assert!(
        (0..original.len()).all(|i| words.index(i) == original.index(i)),
        "the same words"
    );
    assert!(passphrase.as_bytes().is_empty());
    assert!(
        open_slot(&file, b"Correct-Horse-8", b"", None).is_err(),
        "another password does not open it"
    );

    // Written: shown, then back to Seed Backup.
    let out = f.step(Event::Card(Outcome::Written), &mut Live);
    assert_eq!(
        out.screen,
        Screen::CardDone {
            job: Job::Write,
            outcome: Outcome::Written
        }
    );
    assert_eq!(
        f.card_request().len,
        0,
        "the sealed file is wiped once written"
    );
    let out = f.step(
        Event::Tick {
            now_us: 1_000_000 + card_done_us(Job::Write, Outcome::Written),
        },
        &mut Live,
    );
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedBackup,
            page: 0
        },
        "{:?}",
        out.screen
    );
}

/// From the home grid with a seed in use: Backup to SD, past the warning,
/// named `name`.
fn backup_as(f: &mut Flow<'_, 6>, sd: &mut Sd, name: &[u8]) {
    use kassigner_fw::ui::backup;
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(backup::zone(SCALE, backup::Target::Export).unwrap()),
        &mut Live,
    );
    f.step(item(&menu::EXPORT, 0), &mut Live);
    f.step(item(&menu::SEED_BACKUP, 2), &mut Live);
    assert_eq!(f.state(), State::BackupWarning);
    let understand = tap_in(backup::zone(SCALE, backup::Target::Understand).unwrap());
    assert_eq!(
        f.step(understand, &mut Live).command,
        Some(Command::Card(Job::NextName))
    );
    run_job(f, sd, Job::NextName);
    name_as(f, sd, name);
}

/// A sealed backup is overwritten only under its own password, as a delete
/// asks it. Saving under another seed's backup's name: Overwrite asks its
/// password. A wrong one writes nothing, fails as the save and comes back
/// to the name; Back leaves the save; the right one goes on to the new
/// password, and the card then holds the seed in use under it.
#[test]
fn a_sealed_backup_is_written_over_only_under_its_own_password() {
    use kassigner_crypto::backup::{open_slot, seal_slot, FILE_MAX};
    use kassigner_crypto::container::SealKdf;
    use kassigner_fw::card::Error;
    use kassigner_fw::flow::Typing;

    let old_password = b"Old-Horse-77!";
    let old = {
        let other = bip39::from_entropy(&[9u8; 16]).unwrap();
        let mut out = [0u8; FILE_MAX];
        let n = seal_slot(
            &Slot::mnemonic(other, b"").unwrap(),
            old_password,
            &[5; 16],
            &[6; 12],
            SealKdf::Pbkdf2Sha256,
            &mut out,
        )
        .unwrap();
        out[..n].to_vec()
    };
    let mut sd = card_with(&[(b"SD0001  KAS", &old)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    backup_as(&mut f, &mut sd, b"SD0001");
    let mut t = 1_000_000u64;

    // Its password, asked for the overwrite.
    assert!(matches!(
        overwrite(&mut f, &mut sd),
        Screen::Keyboard {
            typing: Typing::OverwritePassword,
            ..
        }
    ));
    assert!(Typing::OverwritePassword.secret());

    // Wrong: nothing written, said, and back to the name.
    type_on(&mut f, b"Wrong-Horse-99");
    press(&mut f, keyboard::Key::Ok);
    assert_eq!(f.typed(), ("", 0), "the password is off the line");
    assert_eq!(
        opened_at(&mut f, &mut t),
        Screen::CardDone {
            job: Job::Write,
            outcome: Outcome::Failed(Error::Backup("Wrong password or damaged file"))
        }
    );
    assert_eq!(on_card(&mut sd, b"SD0001  KAS"), old, "not a byte changed");
    t += card_done_us(
        Job::Write,
        Outcome::Failed(Error::Backup("Wrong password or damaged file")),
    );
    f.step(Event::Tick { now_us: t }, &mut Live);
    assert_eq!(f.state(), State::BackupName { page: 0 });
    assert_eq!(f.typed().0, "SD0001");

    // Back, from its password: out of the save, nothing written.
    assert_eq!(
        press(&mut f, keyboard::Key::Ok).command,
        Some(Command::Card(Job::Exists))
    );
    run_job(&mut f, &mut sd, Job::Exists);
    overwrite(&mut f, &mut sd);
    type_on(&mut f, b"half");
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedBackup,
            page: 0
        }
    );
    assert_eq!(f.typed(), ("", 0));
    assert_eq!(on_card(&mut sd, b"SD0001  KAS"), old);

    // Right: the new password, then sealed and written over it, back to
    // Seed Backup where the save began.
    f.step(item(&menu::SEED_BACKUP, 2), &mut Live);
    f.step(
        tap_in(
            kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Understand)
                .unwrap(),
        ),
        &mut Live,
    );
    run_job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "SD0002");
    name_as(&mut f, &mut sd, b"SD0001");
    overwrite(&mut f, &mut sd);
    type_on(&mut f, old_password);
    press(&mut f, keyboard::Key::Ok);
    assert!(matches!(
        opened_at(&mut f, &mut t),
        Screen::Keyboard {
            typing: Typing::Password,
            ..
        }
    ));
    let new_password = b"New-Horse-55!";
    for _ in 0..2 {
        type_on(&mut f, new_password);
        press(&mut f, keyboard::Key::Ok);
    }
    while matches!(f.state(), State::BackupSealing { .. }) {
        f.step(Event::Tick { now_us: t }, &mut Live);
    }
    assert_eq!(f.state(), State::CardBusy(Job::Write));
    run_job(&mut f, &mut sd, Job::Write);
    let now = on_card(&mut sd, b"SD0001  KAS");
    assert!(open_slot(&now, old_password, b"", None).is_err(), "gone");
    let Slot::Mnemonic {
        mnemonic: words, ..
    } = open_slot(&now, new_password, b"", None).unwrap()
    else {
        panic!("a seed backup")
    };
    let original = mnemonic();
    assert!((0..original.len()).all(|i| words.index(i) == original.index(i)));
    t += card_done_us(Job::Write, Outcome::Written);
    f.step(Event::Tick { now_us: t }, &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedBackup,
            page: 0
        }
    );
}

/// A file the unit cannot check is not overwritten; a plain one is. Under
/// the name: a P4's backup on a board without the memory, v1.0.5's layout,
/// an unknown derivation, a damaged file: each fails as the save, writes
/// nothing and comes back to the name. Text starting `KASPA`, like the
/// magic, is plain: nothing is asked.
#[test]
fn a_file_the_unit_cannot_check_is_not_written_over() {
    use kassigner_crypto::backup::{seal_slot, FILE_MAX};
    use kassigner_crypto::container::{Argon2Block, SealKdf, ARGON2_BLOCKS};
    use kassigner_fw::card::Error;
    use kassigner_fw::flow::Typing;

    let seal = |kdf: SealKdf<'_>| {
        let mut out = [0u8; FILE_MAX];
        let slot = Slot::mnemonic(mnemonic(), b"").unwrap();
        let n = seal_slot(&slot, b"Old-Horse-77!", &[5; 16], &[6; 12], kdf, &mut out).unwrap();
        out[..n].to_vec()
    };
    let pbkdf2 = seal(SealKdf::Pbkdf2Sha256);
    let mut memory = vec![Argon2Block::default(); ARGON2_BLOCKS];
    let p4 = seal(SealKdf::Argon2id(&mut memory));
    let mut v105 = pbkdf2.clone();
    v105[3] = 0x01;
    let mut unknown = pbkdf2.clone();
    unknown[6] = 9;
    let damaged = pbkdf2[..pbkdf2.len() - 1].to_vec();

    for (case, file, why) in [
        ("P4", &p4, "Made on a P4: overwrite it on a P4"),
        ("v1.0.5", &v105, "Unknown format"),
        ("unknown derivation", &unknown, "Unknown format"),
        ("damaged", &damaged, "File error"),
    ] {
        let mut sd = card_with(&[(b"SD0001  KAS", file)]);
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        load(&mut f, &seedqr());
        f.step(home_button(), &mut Live);
        backup_as(&mut f, &mut sd, b"SD0001");
        assert_eq!(
            overwrite(&mut f, &mut sd),
            Screen::CardDone {
                job: Job::Write,
                outcome: Outcome::Failed(Error::Backup(why))
            },
            "{case}"
        );
        assert_eq!(&on_card(&mut sd, b"SD0001  KAS"), file, "{case}");
        f.step(
            Event::Tick {
                now_us: VERIFIED_US + ERROR_US,
            },
            &mut Live,
        );
        assert_eq!(f.state(), State::BackupName { page: 0 }, "{case}");
        assert_eq!(f.typed().0, "SD0001", "{case}");
    }

    let text = b"KASPA notes, not a backup";
    let mut sd = card_with(&[(b"SD0001  KAS", text)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    backup_as(&mut f, &mut sd, b"SD0001");
    assert!(matches!(
        overwrite(&mut f, &mut sd),
        Screen::Keyboard {
            typing: Typing::Password,
            ..
        }
    ));
}

/// Restore from SD, against a card in memory: a wrong password is said and
/// goes back to the list; the right one opens the seed, asks its passphrase
/// and stores the same words. An Argon2id backup is named as the P4's on a
/// board without the memory. A read reported longer than the buffer lent is
/// refused, not sliced.
#[test]
fn a_backup_on_the_card_is_restored() {
    use kassigner_crypto::backup::{seal_slot, FILE_MAX};
    use kassigner_crypto::container::{Argon2Block, SealKdf, ARGON2_BLOCKS};
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{create_file, do_format_fat32, mount_fat32};
    use kassigner_fw::card::{self, Error, Job, Kind, Outcome};

    let password = b"Correct-Horse-9";
    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let info = mount_fat32(&mut sd).unwrap();
    let slot = Slot::mnemonic(mnemonic(), b"").unwrap();
    let mut out = [0u8; FILE_MAX];
    let n = seal_slot(
        &slot,
        password,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut out,
    )
    .unwrap();
    create_file(&mut sd, &info, b"SD0001  KAS", &out[..n]).unwrap();
    let mut memory = vec![Argon2Block::default(); ARGON2_BLOCKS];
    let n = seal_slot(
        &slot,
        password,
        &[3; 16],
        &[4; 12],
        SealKdf::Argon2id(&mut memory),
        &mut out,
    )
    .unwrap();
    create_file(&mut sd, &info, b"P4BACKUPKAS", &out[..n]).unwrap();

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    // The card does what the binary would have it do.
    let job = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, job: Job| {
        let outcome = card::run(job, Kind::SdV2High, sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live)
    };
    let row = |f: &Flow<'_, 6>, name: &[u8; 11]| {
        let i = f.backups().iter().position(|b| b == name).expect("listed");
        tap_in(
            kassigner_fw::ui::backup::pick_zone(
                SCALE,
                f.backups().len(),
                0,
                kassigner_fw::ui::backup::Pick::Row(i),
            )
            .unwrap(),
        )
    };
    let type_password = restore_type;
    let ok = restore_ok;

    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(
            kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Import)
                .unwrap(),
        ),
        &mut Live,
    );
    f.step(item(&menu::IMPORT, 0), &mut Live);
    let out = f.step(item(&menu::IMPORT_SD, 0), &mut Live);
    assert_eq!(out.command, Some(Command::Card(Job::List)));
    let out = job(&mut f, &mut sd, Job::List);
    assert!(
        matches!(
            out.screen,
            Screen::RestoreList {
                count: 2,
                extra: 0,
                ..
            }
        ),
        "{:?}",
        out.screen
    );

    // Wrong: said, and back to the list.
    f.step(row(&f, b"SD0001  KAS"), &mut Live);
    type_password(&mut f, b"Wrong-Horse-99");
    assert_eq!(ok(&mut f).command, Some(Command::Card(Job::Read)));
    job(&mut f, &mut sd, Job::Read);
    let mut t = 1_000_000;
    let out = loop {
        t += 1000;
        let out = f.step(Event::Tick { now_us: t }, &mut Live);
        if !matches!(out.screen, Screen::RestoreOpening { .. }) {
            break out;
        }
    };
    assert_eq!(
        out.screen,
        Screen::CardDone {
            job: Job::Read,
            outcome: Outcome::Failed(Error::Backup("Wrong password or damaged file"))
        }
    );
    f.step(
        Event::Tick {
            now_us: t + card_done_us(
                Job::Read,
                Outcome::Failed(Error::Backup("Wrong password or damaged file")),
            ),
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::RestoreList { page: 0 });

    // A P4's backup, on a board without the memory.
    f.step(row(&f, b"P4BACKUPKAS"), &mut Live);
    type_password(&mut f, password);
    ok(&mut f);
    let out = job(&mut f, &mut sd, Job::Read);
    assert_eq!(
        out.screen,
        Screen::CardDone {
            job: Job::Read,
            outcome: Outcome::Failed(Error::Backup("Made on a P4: open it on a P4"))
        }
    );
    t += 10_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);

    // A read reported longer than the buffer lent: refused as a damaged
    // file, never sliced past it.
    f.step(row(&f, b"SD0001  KAS"), &mut Live);
    type_password(&mut f, password);
    assert_eq!(ok(&mut f).command, Some(Command::Card(Job::Read)));
    let past = f.card_request().file.len() + 1;
    let out = f.step(Event::Card(Outcome::Read(past)), &mut Live);
    assert_eq!(
        out.screen,
        Screen::CardDone {
            job: Job::Read,
            outcome: Outcome::Failed(Error::Backup("File error"))
        }
    );
    t += 10_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    assert_eq!(f.state(), State::RestoreList { page: 0 });

    // Right: the seed, its passphrase asked, stored with the same words.
    f.step(row(&f, b"SD0001  KAS"), &mut Live);
    type_password(&mut f, password);
    ok(&mut f);
    job(&mut f, &mut sd, Job::Read);
    loop {
        t += 1000;
        f.step(Event::Tick { now_us: t }, &mut Live);
        if !matches!(f.state(), State::RestoreOpening { .. }) {
            break;
        }
    }
    assert_eq!(f.state(), State::Passphrase { page: 0 });
    f.step(no_passphrase(), &mut Live);
    assert!(matches!(f.state(), State::Opening { .. }));
    let stored = f.seed(0).expect("stored");
    assert!(!stored.passphrase);
    opened(&mut f);
    assert_eq!(
        f.fingerprint(),
        Some(wallet().fingerprint()),
        "the same seed"
    );
}

/// A backup is deleted from the list: its trash asks; Cancel keeps it;
/// DELETE removes it and reads the list again; the last one gone goes back
/// to Import from SD.
#[test]
fn a_backup_is_deleted_from_the_list() {
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{create_file, do_format_fat32, find_file_in_root, mount_fat32};
    use kassigner_fw::card::{self, Job, Kind, Outcome};
    use kassigner_fw::ui::backup::{pick_zone, Pick};

    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let info = mount_fat32(&mut sd).unwrap();
    let file = {
        use kassigner_crypto::backup::{seal_slot, FILE_MAX};
        use kassigner_crypto::container::SealKdf;
        let slot = Slot::mnemonic(mnemonic(), b"").unwrap();
        let mut out = [0u8; FILE_MAX];
        let n = seal_slot(
            &slot,
            b"Correct-Horse-9",
            &[1; 16],
            &[2; 12],
            SealKdf::Pbkdf2Sha256,
            &mut out,
        )
        .unwrap();
        out[..n].to_vec()
    };
    create_file(&mut sd, &info, b"SD0001  KAS", &file).unwrap();
    create_file(&mut sd, &info, b"SD0002  KAS", &file).unwrap();

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let job = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, job: Job| {
        let outcome = card::run(job, Kind::SdV2High, sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live)
    };
    let trash = |f: &Flow<'_, 6>, name: &[u8; 11]| {
        let i = f.backups().iter().position(|b| b == name).expect("listed");
        tap_in(pick_zone(SCALE, f.backups().len(), 0, Pick::Trash(i)).unwrap())
    };
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(
            kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Import)
                .unwrap(),
        ),
        &mut Live,
    );
    f.step(item(&menu::IMPORT, 0), &mut Live);
    f.step(item(&menu::IMPORT_SD, 0), &mut Live);
    job(&mut f, &mut sd, Job::List);
    assert_eq!(f.backups().len(), 2);

    // DELETE held for the time, as a seed's delete is.
    let Event::Tap { x, y } = answer(dialog::Target::Accept) else {
        unreachable!()
    };
    let t = core::cell::Cell::new(1_000_000u64);
    let held = |f: &mut Flow<'_, 6>| {
        let armed = f.step(answer(dialog::Target::Accept), &mut Live);
        assert!(matches!(
            armed.screen,
            Screen::RestoreDelete { hold: Some(0), .. }
        ));
        assert_eq!(armed.command, None, "a tap only arms it");
        t.set(t.get() + 10_000_000);
        f.step(Event::Tick { now_us: t.get() }, &mut Live);
        f.step(Event::Press { x, y }, &mut Live);
        let done = f.step(
            Event::Tick {
                now_us: t.get() + HOLD_US,
            },
            &mut Live,
        );
        // The finger lifts on the next screen, which a lift there ignores.
        f.step(Event::Tap { x, y }, &mut Live);
        done
    };

    // The trash asks the backup's password; the file must open before the
    // delete is asked.
    let password = b"Correct-Horse-9";
    let opens = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, pw: &[u8]| {
        restore_type(f, pw);
        assert_eq!(restore_ok(f).command, Some(Command::Card(Job::Read)));
        job(f, sd, Job::Read);
        loop {
            t.set(t.get() + 1_000);
            let out = f.step(Event::Tick { now_us: t.get() }, &mut Live);
            if !matches!(out.screen, Screen::RestoreOpening { .. }) {
                break out;
            }
        }
    };

    // A wrong password deletes nothing; the screen says it is for a delete.
    let out = f.step(trash(&f, b"SD0001  KAS"), &mut Live);
    assert!(matches!(
        out.screen,
        Screen::Keyboard {
            typing: kassigner_fw::flow::Typing::DeletePassword,
            ..
        }
    ));
    let out = opens(&mut f, &mut sd, b"Wrong-Horse-99");
    assert_eq!(
        out.screen,
        Screen::CardDone {
            job: Job::Delete,
            outcome: Outcome::Failed(kassigner_fw::card::Error::Backup(
                "Wrong password or damaged file"
            ))
        }
    );
    t.set(t.get() + 10_000_000);
    f.step(Event::Tick { now_us: t.get() }, &mut Live);
    assert_eq!(f.state(), State::RestoreList { page: 0 });
    assert_eq!(f.backups().len(), 2, "both still there");

    // The right one: the delete is asked; Cancel keeps it.
    f.step(trash(&f, b"SD0001  KAS"), &mut Live);
    let out = opens(&mut f, &mut sd, password);
    assert_eq!(
        out.screen,
        Screen::RestoreDelete {
            name: kassigner_fw::card::FileName(*b"SD0001  KAS"),
            hold: None
        }
    );
    f.step(answer(dialog::Target::Cancel), &mut Live);
    assert_eq!(f.state(), State::RestoreList { page: 0 });

    // Held: gone from the card, and the list read again.
    f.step(trash(&f, b"SD0001  KAS"), &mut Live);
    opens(&mut f, &mut sd, password);
    let out = held(&mut f);
    assert_eq!(out.command, Some(Command::Card(Job::Delete)));
    let out = job(&mut f, &mut sd, Job::Delete);
    assert_eq!(out.command, Some(Command::Card(Job::List)));
    let out = job(&mut f, &mut sd, Job::List);
    assert!(matches!(out.screen, Screen::RestoreList { count: 1, .. }));
    assert_eq!(f.backups(), &[*b"SD0002  KAS"]);
    let info = mount_fat32(&mut sd).unwrap();
    assert!(find_file_in_root(&mut sd, &info, b"SD0001  KAS").is_err());

    // The last one: the empty card said, then Import from SD.
    f.step(trash(&f, b"SD0002  KAS"), &mut Live);
    opens(&mut f, &mut sd, password);
    held(&mut f);
    job(&mut f, &mut sd, Job::Delete);
    let out = job(&mut f, &mut sd, Job::List);
    assert_eq!(
        out.screen,
        Screen::CardDone {
            job: Job::List,
            outcome: Outcome::Listed { count: 0, extra: 0 }
        }
    );
    f.step(
        Event::Tick {
            now_us: u64::MAX / 2,
        },
        &mut Live,
    );
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::ImportSd,
            page: 0
        }
    );
}

/// A v1.0.7 backup sealed with no password restores and deletes with none
/// typed. One with a password does not open with none typed, so is not
/// deleted.
///
/// The old card is v1.0.7's `SD000003.KAS` of the corpus, zoo 12 under the
/// empty password: nothing seals under one now, so only old cards hold
/// such files.
#[test]
fn a_backup_with_no_password_restores_with_none() {
    use kassigner_crypto::backup::{seal_slot, FILE_MAX};
    use kassigner_crypto::container::SealKdf;
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{create_file, do_format_fat32, mount_fat32};
    use kassigner_fw::card::{self, Job, Kind};
    use kassigner_fw::ui::backup::{pick_zone, Pick};

    // One sealed by v1.0.7 under nothing; one under a password.
    let old: &[u8] = include_bytes!("../../../../spec/vectors/v107/cards/SD000003.KAS");
    let zoo = {
        let words = bip39::from_entropy(&[0xFF; 16]).unwrap();
        let mut scratch = vec![0u8; bip39::scratch_for(0)];
        Wallet::open(&Slot::mnemonic(words, b"").unwrap(), &mut scratch).unwrap()
    };
    let mut file = [0u8; FILE_MAX];
    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let info = mount_fat32(&mut sd).unwrap();
    create_file(&mut sd, &info, b"OLD     KAS", old).unwrap();
    let slot = Slot::mnemonic(mnemonic(), b"").unwrap();
    let len = seal_slot(
        &slot,
        b"Correct-Horse-9",
        &[3; 16],
        &[4; 12],
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .unwrap();
    let info = mount_fat32(&mut sd).unwrap();
    create_file(&mut sd, &info, b"NEW     KAS", &file[..len]).unwrap();

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let job = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, job: Job| {
        let outcome = card::run(job, Kind::SdV2High, sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live)
    };
    let list = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>| {
        f.step(home_button(), &mut Live);
        f.step(card(2), &mut Live);
        f.step(item(&menu::TOOLS, 1), &mut Live);
        f.step(
            tap_in(
                kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Import)
                    .unwrap(),
            ),
            &mut Live,
        );
        f.step(item(&menu::IMPORT, 0), &mut Live);
        f.step(item(&menu::IMPORT_SD, 0), &mut Live);
        job(f, sd, Job::List);
    };
    let at = |f: &Flow<'_, 6>, name: &[u8; 11], pick: fn(usize) -> Pick| {
        let i = f.backups().iter().position(|b| b == name).unwrap();
        tap_in(pick_zone(SCALE, f.backups().len(), 0, pick(i)).unwrap())
    };
    let t = core::cell::Cell::new(1_000_000u64);
    // OK with nothing typed, the file read and opened, as far as it goes.
    let empty_ok = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>| {
        assert_eq!(restore_ok(f).command, Some(Command::Card(Job::Read)));
        job(f, sd, Job::Read);
        while matches!(f.state(), State::RestoreOpening { .. }) {
            t.set(t.get() + 1_000);
            f.step(Event::Tick { now_us: t.get() }, &mut Live);
        }
    };

    // The one with a password, nothing typed: it does not open, nothing goes.
    list(&mut f, &mut sd);
    f.step(at(&f, b"NEW     KAS", Pick::Trash), &mut Live);
    empty_ok(&mut f, &mut sd);
    assert!(
        matches!(
            f.state(),
            State::CardDone {
                job: Job::Delete,
                ..
            }
        ),
        "{:?}",
        f.state()
    );
    t.set(t.get() + 10_000_000);
    f.step(Event::Tick { now_us: t.get() }, &mut Live);
    assert_eq!(f.backups().len(), 2, "both still there");

    // The restore: nothing typed opens the password-less one.
    f.step(at(&f, b"OLD     KAS", Pick::Row), &mut Live);
    empty_ok(&mut f, &mut sd);
    assert_eq!(f.state(), State::Passphrase { page: 0 });
    f.step(no_passphrase(), &mut Live);
    opened(&mut f);
    assert_eq!(f.fingerprint(), Some(zoo.fingerprint()));

    // The delete: nothing typed opens it, the hold takes it off the card.
    list(&mut f, &mut sd);
    f.step(at(&f, b"OLD     KAS", Pick::Trash), &mut Live);
    empty_ok(&mut f, &mut sd);
    assert!(
        matches!(f.state(), State::RestoreDelete { .. }),
        "{:?}",
        f.state()
    );
    let Event::Tap { x, y } = answer(dialog::Target::Accept) else {
        unreachable!()
    };
    f.step(answer(dialog::Target::Accept), &mut Live);
    t.set(t.get() + 10_000_000);
    f.step(Event::Tick { now_us: t.get() }, &mut Live);
    f.step(Event::Press { x, y }, &mut Live);
    let out = f.step(
        Event::Tick {
            now_us: t.get() + HOLD_US,
        },
        &mut Live,
    );
    assert_eq!(out.command, Some(Command::Card(Job::Delete)));
    job(&mut f, &mut sd, Job::Delete);
    job(&mut f, &mut sd, Job::List);
    assert_eq!(
        f.backups(),
        &[*b"NEW     KAS"],
        "the password-less one gone"
    );
}

/// A card failure is titled with what was being done, never the card job
/// alone. A card that does not mount: at a kpub save's first step, Import
/// from SD's kpub and backup lists, Sign Message's file list. No card: at
/// an address save's and a seed backup's first step, a save's failure
/// saying no card in the same words as every other job. Each result gives
/// way to the screen its job began from.
#[test]
fn a_card_failure_says_what_was_being_done() {
    use kassigner_fw::card::NO_CARD;
    use kassigner_fw::ui::{address, backup, sd_card};

    let blank = || Sd::new(vec![[0u8; kassigner_fat32::block::BLOCK_SIZE]; 1024]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    let mut t = 1_000_000u64;
    // The result screen's title, then where it gives way to.
    let mut said = |f: &mut Flow<'_, 6>, job: Job, failed: &str| {
        let State::CardDone {
            job: shown,
            outcome,
        } = f.state()
        else {
            panic!("{:?}", f.state())
        };
        assert_eq!(shown, job);
        assert!(!outcome.ok(), "{outcome:?}");
        assert_eq!(f.card_said().failed, failed);
        t += 10_000_000;
        f.step(Event::Tick { now_us: t }, &mut Live);
        (outcome, f.state())
    };
    let menu_at = |menu| State::Menu { menu, page: 0 };

    // A card that does not mount.
    watch_only(&mut f, 1);
    run_job(&mut f, &mut blank(), Job::NextName);
    let (outcome, after) = said(&mut f, Job::NextName, sd_card::KPUB_SAVE_FAILED);
    assert!(matches!(
        outcome,
        Outcome::Failed(kassigner_fw::card::Error::Filesystem(_))
    ));
    assert_eq!(after, menu_at(MenuId::WatchOnly));

    for (row, failed) in [(2, sd_card::KPUB_LOAD_FAILED), (0, sd_card::RESTORE_FAILED)] {
        f.step(home_button(), &mut Live);
        f.step(card(2), &mut Live);
        f.step(item(&menu::TOOLS, 1), &mut Live);
        f.step(
            tap_in(backup::zone(SCALE, backup::Target::Import).unwrap()),
            &mut Live,
        );
        f.step(item(&menu::IMPORT, 0), &mut Live);
        f.step(item(&menu::IMPORT_SD, row), &mut Live);
        run_job(&mut f, &mut blank(), Job::List);
        assert_eq!(said(&mut f, Job::List, failed).1, menu_at(MenuId::ImportSd));
    }

    f.step(home_button(), &mut Live);
    assert_eq!(
        sign_message(&mut f, 1).command,
        Some(Command::Card(Job::ListText))
    );
    run_job(&mut f, &mut blank(), Job::ListText);
    assert_eq!(
        said(&mut f, Job::ListText, sd_card::MESSAGE_LOAD_FAILED).1,
        menu_at(MenuId::SignMessage)
    );

    // No card.
    f.step(home_button(), &mut Live);
    seed_tool(&mut f, 3);
    let on = |t| tap_in(address::zone(SCALE, false, true, t).expect("on the screen"));
    f.step(on(address::Target::Address), &mut Live);
    f.step(on(address::Target::Address), &mut Live);
    assert_eq!(f.state(), State::AddressDone);
    assert_eq!(
        f.touch(answer(dialog::Target::Cancel)).command,
        Some(Command::Card(Job::NextName))
    );
    f.step(Event::Card(Outcome::Absent), &mut Live);
    let (outcome, after) = said(&mut f, Job::NextName, sd_card::ADDRESS_SAVE_FAILED);
    assert_eq!(outcome, Outcome::Absent);
    assert_eq!(after, State::AddressDone);

    f.touch(home_button());
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(backup::zone(SCALE, backup::Target::Export).unwrap()),
        &mut Live,
    );
    f.step(item(&menu::EXPORT, 0), &mut Live);
    f.step(item(&menu::SEED_BACKUP, 2), &mut Live);
    f.step(
        tap_in(backup::zone(SCALE, backup::Target::Understand).unwrap()),
        &mut Live,
    );
    f.step(Event::Card(Outcome::Absent), &mut Live);
    let (outcome, after) = said(&mut f, Job::NextName, sd_card::BACKUP_FAILED);
    assert_eq!(outcome, Outcome::Absent);
    assert_eq!(after, menu_at(MenuId::SeedBackup));

    // The missing card's words, from every job's line.
    assert_eq!(
        kassigner_fw::card::Error::Device(kassigner_fat32::block::Error::NotPresent).describe(),
        NO_CARD
    );
}
