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

//! The kpub: shown, saved, scanned, and its files read and deleted.

use super::*;

/// The test seed's kpub for `key`, as text and its 78 raw bytes.
fn kpub_of(key: kassigner_fw::flow::KpubKey) -> (String, Vec<u8>) {
    use kassigner_crypto::wallet::Wallet as W;
    use kassigner_kaspa::bip32_public::{Prefix, TEXT_MAX};
    let w = wallet();
    let account = match (&w, key) {
        (W::Hd { single, .. }, kassigner_fw::flow::KpubKey::Single) => single,
        (
            W::Hd {
                multisig: Some(m), ..
            },
            kassigner_fw::flow::KpubKey::Cosigner,
        ) => m,
        _ => unreachable!(),
    };
    let public = account.to_extended_public_key();
    let mut text = [0u8; TEXT_MAX];
    let n = public.to_text(Prefix::Kpub, &mut text).unwrap();
    let mut raw = [0u8; 78];
    public.serialize(Prefix::Kpub, &mut raw).unwrap();
    (String::from_utf8(text[..n].to_vec()).unwrap(), raw.to_vec())
}

/// kpub as QR and kpub Multisig QR (the `45'` key): Wallet shows the text in
/// one code; KasSigner the raw form (marker 0x01) in two `Format::Kpub`
/// frames of 38 and 41 bytes, Manual a tap each, Auto Cycle every
/// `KASSIGNER_FRAME_US`. Then KPUB EXPORTED, whose Back to QR shows it
/// again. Each code is read back by the camera's decoder.
#[test]
fn a_kpub_is_shown_in_one_code_or_two_frames() {
    use kassigner_fw::flow::KpubKey;
    use kassigner_fw::ui::kpub;
    use kassigner_kaspa::bip32_public::ExtendedPublicKey;
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    let pick = |t| tap_in(kpub::zone(SCALE, t).unwrap());
    let middle = || {
        tap_in(Zone {
            x: 160,
            y: 120,
            width: 1,
            height: 1,
        })
    };

    for (row, key) in [(0, KpubKey::Single), (2, KpubKey::Cosigner)] {
        let (text, raw) = kpub_of(key);
        watch_only(&mut f, row);
        assert_eq!(f.state(), State::KpubFormat);

        // One code, the text.
        let out = f.step(pick(kpub::Target::Wallet), &mut Live);
        assert_eq!(
            out.screen,
            Screen::KpubQr {
                frame: 0,
                frames: 1
            }
        );
        assert_eq!(
            read_back(&f.kpub_code(0).unwrap()),
            text.as_bytes(),
            "{key:?}"
        );
        f.step(middle(), &mut Live);
        assert_eq!(f.state(), State::KpubExported);
        f.touch(answer(dialog::Target::Accept));
        assert_eq!(f.state(), State::KpubQr { frame: 0 }, "Back to QR");
        f.step(middle(), &mut Live);
        f.touch(back_button());
        assert_eq!(f.state(), State::KpubFormat);

        // Two frames, Manual, a tap each: the raw form, as v1.0.7 sends it.
        f.step(pick(kpub::Target::KasSigner), &mut Live);
        assert_eq!(f.state(), State::KpubMode);
        let out = f.touch(answer(dialog::Target::Accept));
        assert_eq!(
            out.screen,
            Screen::KpubQr {
                frame: 0,
                frames: 2
            }
        );
        let first = read_back(&f.kpub_code(0).unwrap());
        f.step(middle(), &mut Live);
        assert_eq!(f.state(), State::KpubQr { frame: 1 });
        let second = read_back(&f.kpub_code(1).unwrap());
        use kassigner_protocol::frame::{parse, Format};
        let (a, b) = (parse(&first, 8).unwrap(), parse(&second, 8).unwrap());
        assert_eq!(
            (a.format, a.index, a.total, a.fragment.len()),
            (Format::Kpub, 0, 2, 38)
        );
        assert_eq!(
            (b.format, b.index, b.total, b.fragment.len()),
            (Format::Kpub, 1, 2, 41)
        );
        let mut whole = a.fragment.to_vec();
        whole.extend_from_slice(b.fragment);
        assert_eq!(whole[0], 0x01, "the raw form's marker");
        assert_eq!(&whole[1..], &raw[..]);
        assert!(ExtendedPublicKey::deserialize(&whole[1..]).is_ok());
        f.step(middle(), &mut Live);
        assert_eq!(f.state(), State::KpubExported, "past the last frame");

        // Auto Cycle: the frames turn on their own.
        f.touch(back_button());
        f.step(pick(kpub::Target::KasSigner), &mut Live);
        f.touch(answer(dialog::Target::Cancel));
        // Past every earlier tick, so the clock only moves on.
        let t0 = 100_000_000 * (row as u64 + 1);
        f.step(Event::Tick { now_us: t0 }, &mut Live);
        let at = |f: &Flow<'_, 6>| match f.state() {
            State::KpubQr { frame } => frame,
            other => panic!("{other:?}"),
        };
        let start = at(&f);
        f.step(
            Event::Tick {
                now_us: t0 + kassigner_fw::limits::KASSIGNER_FRAME_US + 50_000,
            },
            &mut Live,
        );
        assert_ne!(at(&f), start, "turned");
        f.step(middle(), &mut Live);
        assert_eq!(f.state(), State::KpubExported, "a tap on cycling frames");
    }
}

/// A kpub saved plain or sealed: `KPnnnn.TXT`, ENCRYPT FILE? No writes the
/// text, Yes seals it under the KSPT purpose, as v1.0.7 did. The cosigner's
/// is `KMnnnn.K45`, the key with the seed's fingerprint and its path in
/// front, plain or sealed under the cosigner purpose.
#[test]
fn a_kpub_is_saved_plain_or_sealed() {
    use kassigner_crypto::container::open;
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{do_format_fat32, find_file_in_root, mount_fat32, read_file};
    use kassigner_fw::card::{self, Job, Kind};
    use kassigner_fw::flow::KpubKey;
    use kassigner_protocol::container::Purpose;

    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    let job = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, job: Job| {
        let outcome = card::run(job, Kind::SdV2High, sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live)
    };
    let file = |sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, name: &[u8; 11]| {
        let info = mount_fat32(sd).unwrap();
        let (entry, _, _) = find_file_in_root(sd, &info, name).unwrap();
        let mut out = vec![0u8; entry.file_size as usize];
        let n = read_file(sd, &info, &entry, &mut out).unwrap();
        out.truncate(n);
        out
    };
    let (text, _) = kpub_of(KpubKey::Single);

    // Plain.
    let out = watch_only(&mut f, 1);
    assert_eq!(out.command, Some(Command::Card(Job::NextName)));
    job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "KP0001");
    let State::BackupName { page } = f.state() else {
        panic!("{:?}", f.state())
    };
    assert_eq!(
        f.step(key(page, keyboard::Key::Ok), &mut Live).command,
        Some(Command::Card(Job::Exists))
    );
    job(&mut f, &mut sd, Job::Exists);
    assert_eq!(f.state(), State::KpubEncrypt);
    assert_eq!(
        f.touch(answer(dialog::Target::Accept)).command,
        Some(Command::Card(Job::Write))
    );
    let out = job(&mut f, &mut sd, Job::Write);
    assert!(matches!(
        out.screen,
        Screen::CardDone {
            job: Job::Write,
            ..
        }
    ));
    assert_eq!(f.saved_text(), "!! kpub Saved !!");
    assert_eq!(file(&mut sd, b"KP0001  TXT"), text.as_bytes());
    // The saved screen gives way to Watch-Only.
    let mut now = VERIFIED_US;
    let mut done = |f: &mut Flow<'_, 6>| {
        now += 10_000_000;
        f.step(Event::Tick { now_us: now }, &mut Live);
        assert_eq!(
            f.state(),
            State::Menu {
                menu: MenuId::WatchOnly,
                page: 0
            }
        );
    };
    done(&mut f);

    // Sealed, the next number.
    watch_only(&mut f, 1);
    job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "KP0002");
    let State::BackupName { page } = f.state() else {
        panic!()
    };
    f.step(key(page, keyboard::Key::Ok), &mut Live);
    job(&mut f, &mut sd, Job::Exists);
    f.touch(answer(dialog::Target::Cancel));
    assert!(matches!(
        f.state(),
        State::BackupPassword { again: false, .. }
    ));
    let password = b"Correct-Horse-9";
    for again in [false, true] {
        restore_type_password(&mut f, password, again);
    }
    while matches!(f.state(), State::BackupSealing { .. }) {
        f.step(Event::Tick { now_us: 1 }, &mut Live);
    }
    assert_eq!(f.state(), State::CardBusy(Job::Write));
    job(&mut f, &mut sd, Job::Write);
    done(&mut f);
    let sealed = file(&mut sd, b"KP0002  TXT");
    let mut plain = [0u8; 256];
    let opened = open(&sealed, password, &mut plain, None).unwrap();
    assert_eq!(opened.purpose, Purpose::Kspt);
    assert_eq!(&plain[..opened.len], text.as_bytes());

    // The cosigner's, from KPUB EXPORTED: its own name.
    let (cosigner, _) = kpub_of(KpubKey::Cosigner);
    watch_only(&mut f, 2);
    f.step(
        tap_in(
            kassigner_fw::ui::kpub::zone(SCALE, kassigner_fw::ui::kpub::Target::Wallet).unwrap(),
        ),
        &mut Live,
    );
    f.step(
        tap_in(Zone {
            x: 160,
            y: 120,
            width: 1,
            height: 1,
        }),
        &mut Live,
    );
    assert_eq!(
        f.touch(answer(dialog::Target::Cancel)).command,
        Some(Command::Card(Job::NextName))
    );
    job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "KM0001");
    let State::BackupName { page } = f.state() else {
        panic!()
    };
    f.step(key(page, keyboard::Key::Ok), &mut Live);
    job(&mut f, &mut sd, Job::Exists);
    f.touch(answer(dialog::Target::Accept));
    job(&mut f, &mut sd, Job::Write);
    let fingerprint = hex(&wallet().fingerprint());
    let origin = format!("[{fingerprint}/45'/111111'/0']{cosigner}");
    assert_eq!(file(&mut sd, b"KM0001  K45"), origin.as_bytes());
    let read = kassigner_fw::kpub::read_cosigner(origin.as_bytes());
    assert_eq!(read, kassigner_fw::kpub::read(cosigner.as_bytes()));
    assert!(read.is_some());

    // Sealed: the next number, the cosigner purpose.
    let now_us = f.now_us() + 10_000_000;
    f.step(Event::Tick { now_us }, &mut Live);
    watch_only(&mut f, 2);
    f.step(
        tap_in(
            kassigner_fw::ui::kpub::zone(SCALE, kassigner_fw::ui::kpub::Target::Wallet).unwrap(),
        ),
        &mut Live,
    );
    f.step(
        tap_in(Zone {
            x: 160,
            y: 120,
            width: 1,
            height: 1,
        }),
        &mut Live,
    );
    f.touch(answer(dialog::Target::Cancel));
    job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "KM0002");
    let State::BackupName { page } = f.state() else {
        panic!()
    };
    f.step(key(page, keyboard::Key::Ok), &mut Live);
    job(&mut f, &mut sd, Job::Exists);
    f.touch(answer(dialog::Target::Cancel));
    for again in [false, true] {
        restore_type_password(&mut f, password, again);
    }
    while matches!(f.state(), State::BackupSealing { .. }) {
        f.step(Event::Tick { now_us: 1 }, &mut Live);
    }
    job(&mut f, &mut sd, Job::Write);
    let sealed = file(&mut sd, b"KM0002  K45");
    let mut plain = [0u8; 256];
    let opened = open(&sealed, password, &mut plain, None).unwrap();
    assert_eq!(opened.purpose, Purpose::Cosigner);
    assert_eq!(&plain[..opened.len], origin.as_bytes());
}

/// A kpub scanned as text or frames brings KPUB SCANNED: Show QR shows the
/// same key, Back returns, Save to SD numbers it `KPnnnn`. Text that starts
/// like a kpub and is not one is refused.
#[test]
fn a_scanned_kpub_is_shown_or_saved() {
    use kassigner_fw::flow::KpubKey;
    use kassigner_fw::ui::kpub;
    let (text, raw) = kpub_of(KpubKey::Single);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);

    // As text.
    f.step(scan(), &mut Live);
    let out = f.step(Event::Code(text.as_bytes()), &mut Live);
    assert_eq!(out.command, Some(Command::CameraOff));
    assert_eq!(f.state(), State::KpubScanned);
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::KpubFormat, "Show QR, on the right");
    f.step(
        tap_in(kpub::zone(SCALE, kpub::Target::Wallet).unwrap()),
        &mut Live,
    );
    assert_eq!(
        read_back(&f.kpub_code(0).unwrap()),
        text.as_bytes(),
        "the same key"
    );
    f.step(
        tap_in(Zone {
            x: 160,
            y: 120,
            width: 1,
            height: 1,
        }),
        &mut Live,
    );
    f.touch(back_button());
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::KpubScanned, "Back from KPUB EXPORT QR");
    let out = f.touch(answer(dialog::Target::Cancel));
    assert_eq!(
        out.command,
        Some(Command::Card(kassigner_fw::card::Job::NextName)),
        "Save to SD, on the left as on every export dialog"
    );
    f.step(
        Event::Card(kassigner_fw::card::Outcome::NextName(3)),
        &mut Live,
    );
    assert_eq!(f.typed().0, "KP0003");

    // In frames: the raw form.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    let mut payload = vec![0x01];
    payload.extend_from_slice(&raw);
    deliver(&mut f, &payload);
    assert_eq!(f.state(), State::KpubScanned);
    f.touch(answer(dialog::Target::Accept));
    f.step(
        tap_in(kpub::zone(SCALE, kpub::Target::Wallet).unwrap()),
        &mut Live,
    );
    assert_eq!(read_back(&f.kpub_code(0).unwrap()), text.as_bytes());

    // Not a kpub.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    let mut bad = text.clone().into_bytes();
    bad[50] = if bad[50] == b'A' { b'B' } else { b'A' };
    f.step(Event::Code(&bad), &mut Live);
    assert_eq!(f.state(), State::Refused(Refusal::NotAKpub));
}

/// Import from SD's kpub files work as backups do. A row asks the password:
/// an unsealed file opens only to nothing typed, a sealed one only to its
/// own, also in the oldest layout (`KAS\x03`, a fixed salt, as units before
/// the per-file salt wrote it). The key shows on KPUB EXPORT QR, Back going
/// to the list. The trash asks the same, then the hold.
#[test]
fn kpub_files_are_read_and_deleted_as_backups_are() {
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{create_file, do_format_fat32, mount_fat32};
    use kassigner_fw::card::{self, Job, Kind};
    use kassigner_fw::flow::KpubKey;
    use kassigner_fw::ui::backup::{pick_zone, Pick};
    use kassigner_fw::ui::kpub;
    use kassigner_protocol::container::Purpose;

    let (text, _) = kpub_of(KpubKey::Single);
    let password = b"Correct-Horse-9";
    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let info = mount_fat32(&mut sd).unwrap();
    create_file(&mut sd, &info, b"KP0001  TXT", text.as_bytes()).unwrap();
    let mut sealed = [0u8; 512];
    let n = seal(
        Purpose::Kspt,
        text.as_bytes(),
        password,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut sealed,
    )
    .unwrap();
    let info = mount_fat32(&mut sd).unwrap();
    create_file(&mut sd, &info, b"KP0002  TXT", &sealed[..n]).unwrap();
    let info = mount_fat32(&mut sd).unwrap();
    create_file(
        &mut sd,
        &info,
        b"KP0003  TXT",
        &oldest(text.as_bytes(), password),
    )
    .unwrap();

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let job = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, job: Job| {
        let outcome = card::run(job, Kind::SdV2High, sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live)
    };
    let list = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>| {
        f.touch(home_button());
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
        let out = f.step(item(&menu::IMPORT_SD, 2), &mut Live);
        assert_eq!(out.command, Some(Command::Card(Job::List)));
        job(f, sd, Job::List)
    };
    let at = |f: &Flow<'_, 6>, name: &[u8; 11], pick: fn(usize) -> Pick| {
        let i = f.backups().iter().position(|b| b == name).unwrap();
        tap_in(pick_zone(SCALE, f.backups().len(), 0, pick(i)).unwrap())
    };
    let opened = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, typed: &[u8]| {
        restore_type(f, typed);
        assert_eq!(restore_ok(f).command, Some(Command::Card(Job::Read)));
        job(f, sd, Job::Read);
        while matches!(f.state(), State::RestoreOpening { .. }) {
            f.step(Event::Tick { now_us: 1 }, &mut Live);
        }
    };
    let shown = |f: &mut Flow<'_, 6>| {
        assert_eq!(f.state(), State::KpubFormat);
        f.step(
            tap_in(kpub::zone(SCALE, kpub::Target::Wallet).unwrap()),
            &mut Live,
        );
        read_back(&f.kpub_code(0).unwrap())
    };

    list(&mut f, &mut sd);
    assert_eq!(f.backups().len(), 3);

    // Unsealed: nothing typed opens it; anything typed does not.
    f.step(at(&f, b"KP0001  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, b"");
    assert_eq!(shown(&mut f), text.as_bytes());
    f.step(
        tap_in(Zone {
            x: 160,
            y: 120,
            width: 1,
            height: 1,
        }),
        &mut Live,
    );
    f.touch(back_button());
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::RestoreList { page: 0 },
        "Back to the list"
    );
    f.step(at(&f, b"KP0001  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, b"abc");
    assert!(
        matches!(f.state(), State::CardDone { job: Job::Read, .. }),
        "{:?}",
        f.state()
    );
    f.step(
        Event::Tick {
            now_us: 1_000_000_000,
        },
        &mut Live,
    );
    assert_eq!(
        f.state(),
        State::RestoreList { page: 0 },
        "the failure gives way"
    );

    // Sealed: its own password.
    list(&mut f, &mut sd);
    f.step(at(&f, b"KP0002  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, password);
    assert_eq!(shown(&mut f), text.as_bytes());
    f.step(
        tap_in(Zone {
            x: 160,
            y: 120,
            width: 1,
            height: 1,
        }),
        &mut Live,
    );
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);

    // The oldest layout: its own password, and not another.
    list(&mut f, &mut sd);
    f.step(at(&f, b"KP0003  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, password);
    assert_eq!(shown(&mut f), text.as_bytes());
    f.step(home_button(), &mut Live);
    list(&mut f, &mut sd);
    f.step(at(&f, b"KP0003  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, b"Correct-Horse-8");
    assert_eq!(
        f.state(),
        State::CardDone {
            job: Job::Read,
            outcome: Outcome::Failed(card::Error::Backup("Wrong password or damaged file")),
        }
    );
    f.step(
        Event::Tick {
            now_us: 2_000_000_000,
        },
        &mut Live,
    );

    // The trash: the password, then the hold.
    list(&mut f, &mut sd);
    f.step(at(&f, b"KP0001  TXT", Pick::Trash), &mut Live);
    opened(&mut f, &mut sd, b"");
    assert!(
        matches!(f.state(), State::RestoreDelete { .. }),
        "{:?}",
        f.state()
    );
    let Event::Tap { x, y } = answer(dialog::Target::Accept) else {
        unreachable!()
    };
    f.step(answer(dialog::Target::Accept), &mut Live);
    f.step(
        Event::Tick {
            now_us: 10_000_000_000,
        },
        &mut Live,
    );
    f.step(Event::Press { x, y }, &mut Live);
    let out = f.step(
        Event::Tick {
            now_us: 10_000_000_000 + HOLD_US,
        },
        &mut Live,
    );
    assert_eq!(out.command, Some(Command::Card(Job::Delete)));
    // The lift lands on the next screen, which ignores it.
    f.step(Event::Tap { x, y }, &mut Live);
    job(&mut f, &mut sd, Job::Delete);
    job(&mut f, &mut sd, Job::List);
    assert_eq!(f.backups(), &[*b"KP0002  TXT", *b"KP0003  TXT"]);

    // An empty card.
    let mut empty = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut empty).unwrap();
    list(&mut f, &mut empty);
    assert_eq!(f.card_said().empty, ("No .TXT files found", ""));
}

/// `plain` sealed under `password` in the oldest layout, `KAS\x03`: magic,
/// length, nonce, ciphertext and tag, the first six bytes authenticated, the
/// key from the fixed salt. Only units before the per-file salt wrote one.
fn oldest(plain: &[u8], password: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::{AeadInOut, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use kassigner_crypto::container::{derive_key, KdfParams};
    use kassigner_protocol::container::Purpose;

    let key = derive_key(KdfParams::Pbkdf2Sha256Fixed, password, Purpose::Kspt, None).unwrap();
    let nonce = [3u8; 12];
    let mut file = b"KAS\x03".to_vec();
    file.extend_from_slice(&(plain.len() as u16).to_le_bytes());
    file.extend_from_slice(&nonce);
    let mut body = plain.to_vec();
    let tag = Aes256Gcm::new(&(*key).into())
        .encrypt_inout_detached(&Nonce::from(nonce), &file[..6], body.as_mut_slice().into())
        .unwrap();
    file.extend_from_slice(&body);
    file.extend_from_slice(&tag);
    file
}
