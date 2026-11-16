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

//! Steganography: a backup hidden in a photo, and imported back from one.

use super::*;

// ── Steganography ───────────────────────────────────────────────────────────

/// The page IMAGE DESCRIPTOR's keyboard is at, hiding a backup or opening
/// one, or OLD DESCRIPTOR's.
fn descriptor_page<const N: usize>(f: &Flow<'_, N>) -> u8 {
    match f.state() {
        State::StegoDescriptor { page }
        | State::StegoKey { page }
        | State::StegoOldKey { page } => page,
        s => panic!("{s:?}"),
    }
}

/// Type `text` on IMAGE DESCRIPTOR's keyboard, turning its pages as needed.
fn descriptor_type<const N: usize>(f: &mut Flow<'_, N>, text: &[u8]) {
    for &c in text {
        let k = if c == b' ' {
            keyboard::Key::Space
        } else {
            keyboard::Key::Char(c)
        };
        let page = (0..keyboard::PAGES)
            .find(|&p| keyboard::zone(SCALE, p, keyboard::Target::Key(k)).is_some())
            .unwrap();
        loop {
            let at = descriptor_page(f);
            if at == page {
                break;
            }
            f.step(key(at, keyboard::Key::Page), &mut Live);
        }
        f.step(key(page, k), &mut Live);
    }
}

/// OK on IMAGE DESCRIPTOR's keyboard.
fn descriptor_ok<const N: usize>(f: &mut Flow<'_, N>) -> kassigner_fw::flow::Output {
    let page = descriptor_page(f);
    f.step(key(page, keyboard::Key::Ok), &mut Live)
}

/// A tap on a STEGANOGRAPHY card.
fn carrier(i: usize) -> Event<'static> {
    use kassigner_fw::ui::stego;
    tap_in(stego::zone(SCALE, stego::Target::Carrier(i)).expect("a carrier card"))
}

/// Export → Steganography, with a seed in use: the carrier screen.
fn to_stego(f: &mut Flow<'_, 6>) {
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(
            kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Export)
                .unwrap(),
        ),
        &mut Live,
    );
    f.step(item(&menu::EXPORT, 3), &mut Live);
    assert_eq!(f.state(), State::StegoCarrier);
}

/// Steganography's first screens: the carriers; a carrier lists only the
/// photos, by name, with no delete button; a photo asks the descriptor's
/// source; typed, it is previewed; EDIT brings it back to the keyboard;
/// Back goes where each screen came from.
#[test]
fn a_photo_is_chosen_and_a_descriptor_typed_for_it() {
    use kassigner_fw::ui::backup::{pick_zone_in, Pick};
    use kassigner_protocol::stego::Carrier;
    const GRAY: &[u8] = include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/gray.jpg");
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let mut sd = card_with(&[
        (b"ROCKY   JPG", COLOR),
        (b"SD000001KAS", b"not a photo"),
        (b"BEACH   JPE", GRAY),
        (b"NOTES   TXT", b"hello"),
    ]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut m);
    let job = |f: &mut Flow<'_, 6>, sd: &mut Sd, job: Job| {
        let outcome = card::run(job, Kind::SdV2High, sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live)
    };

    to_stego(&mut f);
    // Back is Export's menu.
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Export,
            page: 0
        }
    );
    f.step(item(&menu::EXPORT, 3), &mut Live);

    // Picture: the photos listed, the two of them, no trash.
    let out = f.step(carrier(1), &mut Live);
    assert_eq!(f.carrier(), Carrier::Picture);
    assert_eq!(out.command, Some(Command::Card(Job::ListPhotos)));
    let out = job(&mut f, &mut sd, Job::ListPhotos);
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
    assert_eq!(f.list_title(), "SELECT PHOTO");
    assert!(!f.list_trash());
    assert!(pick_zone_in(SCALE, 2, 0, false, Pick::Trash(0)).is_none());
    let names: Vec<&[u8; 11]> = f.backups().iter().collect();
    assert!(names.contains(&b"ROCKY   JPG") && names.contains(&b"BEACH   JPE"));
    // Back is the carrier screen.
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::StegoCarrier);
    f.step(carrier(2), &mut Live);
    assert_eq!(f.carrier(), Carrier::Both);
    job(&mut f, &mut sd, Job::ListPhotos);

    // A photo: the descriptor's source.
    let i = f
        .backups()
        .iter()
        .position(|n| n == b"ROCKY   JPG")
        .unwrap();
    f.step(
        tap_in(pick_zone_in(SCALE, 2, 0, false, Pick::Row(i)).unwrap()),
        &mut Live,
    );
    photo_read(&mut f, &mut sd);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::StegoSource,
            page: 0
        }
    );
    // Back is the list, listed again.
    let out = f.step(back_button(), &mut Live);
    assert_eq!(out.command, Some(Command::Card(Job::ListPhotos)));
    job(&mut f, &mut sd, Job::ListPhotos);
    assert_eq!(f.state(), State::RestoreList { page: 0 });
    assert_eq!(f.backups().len(), 2);
    f.step(
        tap_in(pick_zone_in(SCALE, 2, 0, false, Pick::Row(i)).unwrap()),
        &mut Live,
    );
    photo_read(&mut f, &mut sd);
    assert_eq!(f.photo_name(), b"ROCKY   JPG");

    // Typed: OK on nothing does nothing; a tab is refused; 64 is the most.
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    assert_eq!(f.state(), State::StegoDescriptor { page: 0 });
    descriptor_ok(&mut f);
    assert_eq!(f.state(), State::StegoDescriptor { page: 0 });
    descriptor_type(&mut f, b"Rocky at the beach, summer 2024");
    assert_eq!(f.typed().0, "Rocky at the beach, summer 2024");
    assert_eq!(
        f.keyboard_note(),
        Some(keyboard::Note::Count { used: 31, of: 64 })
    );
    let out = descriptor_ok(&mut f);
    assert_eq!(f.state(), State::StegoPreview);
    assert_eq!(out.screen, Screen::StegoPreview);
    assert_eq!(f.descriptor(), "Rocky at the beach, summer 2024");
    assert_eq!(f.typed().0, "", "the keyboard is cleared");

    // EDIT: back on the keyboard with the text, to fix in place.
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(f.state(), State::StegoDescriptor { page: 0 });
    assert_eq!(f.typed().0, "Rocky at the beach, summer 2024");
    descriptor_type(&mut f, b"!");
    descriptor_ok(&mut f);
    assert_eq!(f.descriptor(), "Rocky at the beach, summer 2024!");

    // The keyboard's Back is the source menu, the text dropped.
    f.touch(answer(dialog::Target::Cancel));
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::StegoSource,
            page: 0
        }
    );
    assert_eq!(f.typed().0, "");

    // The most: 64, and not one more.
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, &[b'a'; 70]);
    assert_eq!(f.typed().0.len(), 64);
    assert_eq!(
        f.keyboard_note(),
        Some(keyboard::Note::Count { used: 64, of: 64 })
    );

    // Home from the preview drops the descriptor.
    descriptor_ok(&mut f);
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.descriptor(), "");
}

/// Through the carriers and a photo to the source menu, the photos listed
/// from `sd`.
fn to_source(f: &mut Flow<'_, 6>, sd: &mut Sd, which: usize) {
    use kassigner_fw::ui::backup::{pick_zone_in, Pick};
    to_stego(f);
    f.step(carrier(which), &mut Live);
    let outcome = card::run(Job::ListPhotos, Kind::SdV2High, sd, &mut f.card_request());
    f.step(Event::Card(outcome), &mut Live);
    let n = f.backups().len();
    let i = f
        .backups()
        .iter()
        .position(|n| n == b"ROCKY   JPG")
        .unwrap();
    let out = f.step(
        tap_in(pick_zone_in(SCALE, n, 0, false, Pick::Row(i)).unwrap()),
        &mut Live,
    );
    assert_eq!(
        out.command,
        Some(Command::Card(Job::Read)),
        "read as chosen"
    );
    photo_read(f, sd);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::StegoSource,
            page: 0
        }
    );
}

/// The photo chosen to hide a backup in, read off `sd` as the binary would.
fn photo_read<const N: usize>(f: &mut Flow<'_, N>, sd: &mut Sd) -> kassigner_fw::flow::Output {
    let outcome = card::run(Job::Read, Kind::SdV2High, sd, &mut f.card_request());
    f.step(Event::Card(outcome), &mut Live)
}

/// A caption file chosen from SELECT FILE, by name, and read.
fn caption_file(f: &mut Flow<'_, 6>, sd: &mut Sd, name: &[u8; 11]) -> kassigner_fw::flow::Output {
    use kassigner_fw::ui::backup::{pick_zone_in, Pick};
    let out = f.step(item(&menu::DESCRIPTOR_SOURCE, 1), &mut Live);
    assert_eq!(out.command, Some(Command::Card(Job::ListText)));
    let outcome = card::run(Job::ListText, Kind::SdV2High, sd, &mut f.card_request());
    f.step(Event::Card(outcome), &mut Live);
    assert_eq!(f.list_title(), "SELECT FILE");
    assert!(!f.list_trash());
    let n = f.backups().len();
    let i = f.backups().iter().position(|b| b == name).expect("listed");
    let page = i / 4;
    for at in 0..page {
        f.step(
            tap_in(pick_zone_in(SCALE, n, at, false, Pick::Nav(Nav::PageDown)).unwrap()),
            &mut Live,
        );
    }
    let out = f.step(
        tap_in(pick_zone_in(SCALE, n, page, false, Pick::Row(i)).unwrap()),
        &mut Live,
    );
    assert_eq!(out.command, Some(Command::Card(Job::Read)));
    let outcome = card::run(Job::Read, Kind::SdV2High, sd, &mut f.card_request());
    f.step(Event::Card(outcome), &mut Live)
}

/// A descriptor from a `.TXT` is its first line, trimmed; a sealed file, a
/// long line and non-ASCII bytes are refused by name, back to the source
/// menu.
#[test]
fn a_descriptor_is_read_from_a_text_file() {
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let sealed = {
        let mut out = [0u8; 128];
        let n = kassigner_crypto::container::seal(
            kassigner_protocol::container::Purpose::Text,
            b"hidden",
            b"Correct-Horse-9",
            &[1u8; 16],
            &[2u8; 12],
            kassigner_crypto::container::SealKdf::Pbkdf2Sha256,
            &mut out,
        )
        .unwrap();
        out[..n].to_vec()
    };
    let long = [b'x'; 65];
    let mut sd = card_with(&[
        (b"ROCKY   JPG", COLOR),
        (
            b"CAPTION TXT",
            b"\xEF\xBB\xBF  Rocky at the beach, summer 2024 \r\nsecond line\n",
        ),
        (b"LONG    TXT", &long),
        (b"UTF8    TXT", "caf\u{e9} au lait".as_bytes()),
        (b"SEALED  TXT", &sealed),
        (b"EMPTY   TXT", b"\n\n"),
    ]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut m);
    to_source(&mut f, &mut sd, 0);

    let out = caption_file(&mut f, &mut sd, b"CAPTION TXT");
    assert_eq!(out.screen, Screen::StegoPreview);
    assert_eq!(f.descriptor(), "Rocky at the beach, summer 2024");

    for (k, (name, why)) in [
        (b"LONG    TXT", "Line over 64 characters"),
        (b"UTF8    TXT", "Not plain ASCII text"),
        (b"SEALED  TXT", "Not a text file"),
        (b"EMPTY   TXT", "Empty file"),
    ]
    .into_iter()
    .enumerate()
    {
        // Back from the preview to the keyboard, then to the source menu.
        if f.state() == State::StegoPreview {
            f.touch(back_button());
            f.step(back_button(), &mut Live);
        }
        assert_eq!(
            f.state(),
            State::Menu {
                menu: MenuId::StegoSource,
                page: 0
            },
            "{why}"
        );
        let out = caption_file(&mut f, &mut sd, name);
        assert_eq!(
            out.screen,
            Screen::CardDone {
                job: Job::Read,
                outcome: Outcome::Failed(card::Error::Backup(why))
            },
            "{why}"
        );
        assert_eq!(f.card_said().failed, sd_card::DESCRIPTOR_LOAD_FAILED);
        // A minute on, inside the idle wipe's four.
        f.step(
            Event::Tick {
                now_us: 60_000_000 * (k as u64 + 1),
            },
            &mut Live,
        );
    }
    assert_eq!(
        f.descriptor(),
        "Rocky at the beach, summer 2024",
        "the one read stays"
    );
}

/// ADD HINT?, the presets, a custom hint, and HIDE BACKUP?: NO goes to the
/// confirm with no hint; YES to the presets; Custom to the keyboard, 64 at
/// most; CANCEL drops everything, back to the carriers; Back goes where
/// each screen came from.
#[test]
fn a_hint_is_chosen_and_the_export_confirmed_or_dropped() {
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let mut sd = card_with(&[(b"ROCKY   JPG", COLOR)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut m);
    to_source(&mut f, &mut sd, 2);
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Rocky 2024");
    descriptor_ok(&mut f);
    assert_eq!(f.state(), State::StegoPreview);

    // USE: ADD HINT?. Back: the preview.
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::StegoHintAsk);
    f.touch(back_button());
    assert_eq!(f.state(), State::StegoPreview);
    f.touch(answer(dialog::Target::Accept));

    // NO: the confirm, no hint.
    let out = f.touch(answer(dialog::Target::Cancel));
    assert_eq!(out.screen, Screen::StegoConfirm { hint: false });
    assert_eq!(f.hint(), "");
    // Back: ADD HINT?.
    f.touch(back_button());
    assert_eq!(f.state(), State::StegoHintAsk);

    // YES: the presets; the second kept as it reads.
    use kassigner_fw::ui::stego::{hint_zone, HintTarget};
    let hint_row = |i| tap_in(hint_zone(SCALE, HintTarget::Row(i)).unwrap());
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::StegoHint);
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::StegoHintAsk);
    f.touch(answer(dialog::Target::Accept));
    let out = f.step(hint_row(1), &mut Live);
    assert_eq!(out.screen, Screen::StegoConfirm { hint: true });
    assert_eq!(f.hint(), "Name of my loved one?");

    // Custom: the keyboard, 64 at most, Back to the presets.
    f.touch(back_button());
    f.touch(answer(dialog::Target::Accept));
    f.step(hint_row(3), &mut Live);
    assert_eq!(f.state(), State::StegoHintType { page: 0 });
    f.step(key(0, keyboard::Key::Ok), &mut Live);
    assert_eq!(
        f.state(),
        State::StegoHintType { page: 0 },
        "nothing typed, OK does nothing"
    );
    for &c in b"dog" {
        f.step(key(0, keyboard::Key::Char(c)), &mut Live);
    }
    assert_eq!(
        f.keyboard_note(),
        Some(keyboard::Note::Count { used: 3, of: 64 })
    );
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::StegoHint);
    assert_eq!(f.typed().0, "");
    f.step(hint_row(3), &mut Live);
    for &c in b"Where did we meet" {
        let k = if c == b' ' {
            keyboard::Key::Space
        } else {
            keyboard::Key::Char(c)
        };
        let page = (0..keyboard::PAGES)
            .find(|&p| keyboard::zone(SCALE, p, keyboard::Target::Key(k)).is_some())
            .unwrap();
        while f.state() != (State::StegoHintType { page }) {
            let State::StegoHintType { page: at } = f.state() else {
                unreachable!()
            };
            f.step(key(at, keyboard::Key::Page), &mut Live);
        }
        f.step(key(page, k), &mut Live);
    }
    let State::StegoHintType { page } = f.state() else {
        unreachable!()
    };
    let out = f.step(key(page, keyboard::Key::Ok), &mut Live);
    assert_eq!(out.screen, Screen::StegoConfirm { hint: true });
    assert_eq!(f.hint(), "Where did we meet");
    assert_eq!(f.descriptor(), "Rocky 2024");
    assert_eq!(f.photo_name(), b"ROCKY   JPG");

    // CANCEL: everything dropped, the carriers.
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(f.state(), State::StegoCarrier);
    assert_eq!((f.descriptor(), f.hint()), ("", ""));
}

/// A card with no photo says so and goes back to the carriers.
#[test]
fn a_card_with_no_photos_says_so() {
    let mut sd = card_with(&[(b"SD000001KAS", b"not a photo")]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut m);
    to_stego(&mut f);
    f.step(carrier(0), &mut Live);
    let outcome = card::run(
        Job::ListPhotos,
        Kind::SdV2High,
        &mut sd,
        &mut f.card_request(),
    );
    let out = f.step(Event::Card(outcome), &mut Live);
    assert!(
        matches!(
            out.screen,
            Screen::CardDone {
                job: Job::ListPhotos,
                outcome: Outcome::Listed { count: 0, .. }
            }
        ),
        "{:?}",
        out.screen
    );
    assert_eq!(
        f.card_said().empty,
        ("No photos found", "No .JPG files on the card")
    );
    f.step(Event::Tick { now_us: 60_000_000 }, &mut Live);
    assert_eq!(f.state(), State::StegoCarrier);
}

/// A photo larger than the unit holds is not offered.
#[test]
fn a_photo_past_the_cap_is_not_listed() {
    let big = vec![0xFFu8; kassigner_fw::limits::PHOTO_MAX + 1];
    let mut names = [[0u8; 11]; 4];
    let mut sd = card_with(&[
        (b"BIG     JPG", &big),
        (b"SMALL   JPG", b"\xff\xd8\xff\xd9"),
    ]);
    let mut long = [0u8; 4 * card::LONG_SLOT];
    let (n, extra) = card::list_photos(
        &mut sd,
        kassigner_fw::limits::PHOTO_MAX,
        &mut names,
        &mut long,
    )
    .unwrap();
    assert_eq!((n, extra), (1, 0));
    assert_eq!(&names[0], b"SMALL   JPG");
    assert_eq!(card::long_name(&long, 0), Some("SMALL.JPG"));
    assert_eq!(card::long_name(&long, 1), None);
}

/// CONFIRM on HIDE BACKUP?, then every tick and the write to the result:
/// the photo on `sd` afterwards.
fn hide_backup(f: &mut Flow<'_, 6>, sd: &mut Sd) -> kassigner_fw::flow::Output {
    let out = f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::StegoSealing { done: 0 });
    assert!(matches!(out.screen, Screen::BackupSealing { done: 0, .. }));
    // Sealing: the bar moves a batch a tick.
    let mut ticks = 0;
    let mut now = 1_000_000u64;
    let out = loop {
        now += 50_000;
        let out = f.step(Event::Tick { now_us: now }, &mut Live);
        ticks += 1;
        match f.state() {
            State::StegoSealing { .. } => assert!(ticks < 40, "sealing never ends"),
            _ => break out,
        }
    };
    // The photo was read when chosen: straight on to the embedding.
    assert_eq!(out.command, None);
    assert_eq!(out.screen, Screen::StegoEmbedding);
    now += 50_000;
    let out = f.step(Event::Tick { now_us: now }, &mut Live);
    if out.command != Some(Command::Card(Job::Write)) {
        return out;
    }
    let outcome = card::run(Job::Write, Kind::SdV2High, sd, &mut f.card_request());
    f.step(Event::Card(outcome), &mut Live)
}

/// What a photo on the card gives up under `descriptor`: the words and the
/// hint, through the same crates the import will use.
fn opened_photo(photo: &[u8], descriptor: &[u8]) -> (Option<String>, Option<String>) {
    let mut window = TestWindow::new();
    let mut w = window.lend();
    let key = kassigner_crypto::stego::walk_key(descriptor);
    let mut p = [0u8; kassigner_protocol::stego::PAYLOAD_MAX];
    let mut d = [0u8; kassigner_protocol::stego::PAYLOAD_MAX];
    let mut tables = Box::new(kassigner_protocol::stego::picture::Tables::EMPTY);
    let x = kassigner_protocol::stego::extract(photo, &key, &mut w, &mut tables, &mut p, &mut d)
        .unwrap();
    // What opens under the descriptor; a payload that does not is none.
    let open = |payload: &[u8]| {
        let mut rebuilt = [0u8; 512];
        let u = kassigner_protocol::stego::blob::unpack(payload, &mut rebuilt).ok()?;
        let mut hint = [0u8; kassigner_crypto::stego::HINT_MAX];
        let (m, h) =
            kassigner_crypto::stego::open_backup(&rebuilt[u.seed], descriptor, &mut hint).ok()?;
        let words: Vec<&str> = (0..m.len()).map(|i| m.word(i).unwrap()).collect();
        Some(format!(
            "{}|{}",
            words.join(" "),
            core::str::from_utf8(&hint[..h]).unwrap()
        ))
    };
    (
        x.picture.and_then(|n| open(&p[..n])),
        x.descriptor.and_then(|n| open(&d[..n])),
    )
}

/// The backup is hidden by each carrier and opens back. Descriptor and Both
/// write the caption into the EXIF block; Picture leaves the metadata
/// alone; the photo stays a JPEG of the same size; the result leads to the
/// Export menu or the carriers; everything the export held is wiped.
#[test]
fn a_backup_is_hidden_in_a_photo_and_opens_back() {
    use kassigner_protocol::stego::Carrier;
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    const EXIF: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/exif_pil.jpg");
    let m = mnemonic();
    let phrase: Vec<&str> = (0..m.len()).map(|i| m.word(i).unwrap()).collect();
    let phrase = phrase.join(" ");
    for (which, carrier) in Carrier::ALL.iter().enumerate() {
        let mut sd = card_with(&[(b"ROCKY   JPG", COLOR), (b"BEACH   JPG", EXIF)]);
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = seeded(&mut m);
        to_source(&mut f, &mut sd, which);
        f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
        descriptor_type(&mut f, b"Rocky 2024");
        descriptor_ok(&mut f);
        f.touch(answer(dialog::Target::Accept));
        f.touch(answer(dialog::Target::Accept));
        use kassigner_fw::ui::stego::{hint_zone, HintTarget};
        f.step(
            tap_in(hint_zone(SCALE, HintTarget::Row(1)).unwrap()),
            &mut Live,
        );
        assert_eq!(f.state(), State::StegoConfirm);

        let out = hide_backup(&mut f, &mut sd);
        assert_eq!(out.screen, Screen::StegoDone, "{carrier:?}");
        assert_eq!((f.descriptor(), f.hint()), ("", ""), "wiped");

        let photo = on_card(&mut sd, b"ROCKY   JPG");
        assert_eq!(&photo[..2], &[0xFF, 0xD8]);
        assert!((photo.len() as i64 - COLOR.len() as i64).abs() < 2048);
        let (picture, descriptor) = opened_photo(&photo, b"Rocky 2024");
        let want = Some(format!("{phrase}|Name of my loved one?"));
        match carrier {
            Carrier::Descriptor => {
                assert_eq!((&picture, &descriptor), (&None, &want));
                assert_eq!(
                    kassigner_protocol::stego::exif::read_descriptor(&photo),
                    Some(&b"Rocky 2024"[..])
                );
            }
            Carrier::Picture => {
                assert_eq!((&picture, &descriptor), (&want, &None));
                assert!(kassigner_protocol::stego::exif::read_descriptor(&photo).is_none());
            }
            Carrier::Both => assert_eq!((&picture, &descriptor), (&want, &want)),
        }
        // A wrong descriptor opens nothing from the picture.
        if *carrier != Carrier::Descriptor {
            assert_eq!(opened_photo(&photo, b"Rocky 2023").0, None);
        }
        // The other photo untouched.
        assert_eq!(on_card(&mut sd, b"BEACH   JPG"), EXIF);

        // DONE: the Export menu. MORE: the carriers.
        f.touch(answer(dialog::Target::Cancel));
        assert_eq!(
            f.state(),
            State::Menu {
                menu: MenuId::Export,
                page: 0
            }
        );
    }
}

/// A photo with EXIF keeps it, caption merged in; MORE goes to the
/// carriers; the photo buffers are clean after.
#[test]
fn a_photo_with_exif_keeps_it_and_more_returns_to_the_carriers() {
    const EXIF: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/exif_pil.jpg");
    let mut sd = card_with(&[(b"ROCKY   JPG", EXIF)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut m);
    to_source(&mut f, &mut sd, 0);
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Sunset at Playa Blanca, Aug 2024");
    descriptor_ok(&mut f);
    f.touch(answer(dialog::Target::Accept));
    f.touch(answer(dialog::Target::Cancel));
    let out = hide_backup(&mut f, &mut sd);
    assert_eq!(out.screen, Screen::StegoDone);
    let photo = on_card(&mut sd, b"ROCKY   JPG");
    // The host's block carried forward: its Make still in the file, and
    // the caption beside it.
    assert!(photo.windows(9).any(|w| w == b"KasSigner"));
    assert_eq!(
        kassigner_protocol::stego::exif::read_descriptor(&photo),
        Some(&b"Sunset at Playa Blanca, Aug 2024"[..])
    );
    let (_, descriptor) = opened_photo(&photo, b"Sunset at Playa Blanca, Aug 2024");
    assert!(descriptor.unwrap().ends_with('|'), "no hint");
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::StegoCarrier);
    assert!(m.photo.iter().all(|&b| b == 0) && m.photo_out.iter().all(|&b| b == 0));
}

/// A photo the carrier cannot take (a progressive JPEG for Picture, one too
/// small for the payload) is refused by name, back to the carriers,
/// everything wiped.
#[test]
fn a_photo_the_carrier_cannot_take_is_refused_by_name() {
    use kassigner_protocol::stego::StegoError;
    const PROGRESSIVE: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/progressive.jpg");
    const GRAY: &[u8] = include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/gray.jpg");
    for (file, which, why) in [
        (PROGRESSIVE, 1, StegoError::Progressive),
        (GRAY, 2, StegoError::TooSmall),
    ] {
        let mut sd = card_with(&[(b"ROCKY   JPG", file)]);
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = seeded(&mut m);
        to_source(&mut f, &mut sd, which);
        f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
        descriptor_type(&mut f, b"Rocky 2024");
        descriptor_ok(&mut f);
        f.touch(answer(dialog::Target::Accept));
        // The longest hint, so the payload outgrows the 48 by 32 photo.
        f.touch(answer(dialog::Target::Accept));
        use kassigner_fw::ui::stego::{hint_zone, HintTarget};
        f.step(
            tap_in(hint_zone(SCALE, HintTarget::Row(3)).unwrap()),
            &mut Live,
        );
        for _ in 0..64 {
            f.step(key(0, keyboard::Key::Char(b'x')), &mut Live);
        }
        f.step(key(0, keyboard::Key::Ok), &mut Live);
        assert_eq!(f.state(), State::StegoConfirm);
        let out = hide_backup(&mut f, &mut sd);
        assert_eq!(out.screen, Screen::Refused(Refusal::Stego(why)), "{why:?}");
        assert_eq!(on_card(&mut sd, b"ROCKY   JPG"), file, "nothing written");
        f.step(Event::Tick { now_us: 30_000_000 }, &mut Live);
        assert_eq!(f.state(), State::StegoCarrier, "{why:?}");
        assert_eq!((f.descriptor(), f.hint()), ("", ""));
    }
}

// ── Stego Import ────────────────────────────────────────────────────────────

/// A v1.1.0 payload: `m` and `hint` sealed under `descriptor`, stripped as
/// the photo carries it.
fn sealed_payload(m: &bip39::Mnemonic, hint: &[u8], descriptor: &[u8]) -> Vec<u8> {
    let mut c = [0u8; kassigner_crypto::stego::CONTAINER_MAX];
    let n =
        kassigner_crypto::stego::seal_backup(m, hint, descriptor, &[3u8; 16], &[4u8; 12], &mut c)
            .unwrap();
    let mut p = [0u8; kassigner_protocol::stego::PAYLOAD_MAX];
    let k = kassigner_protocol::stego::blob::strip(&c[..n], &mut p).unwrap();
    p[..k].to_vec()
}

/// The Picture carrier's window, as the tests lend it.
struct TestWindow {
    coefficients: Vec<i16>,
    filled: Vec<u8>,
    changed: Vec<u8>,
}

impl TestWindow {
    fn new() -> Self {
        use kassigner_protocol::stego::picture::{bitmap_len, RANK_WINDOW};
        Self {
            coefficients: vec![0i16; RANK_WINDOW],
            filled: vec![0u8; bitmap_len(RANK_WINDOW)],
            changed: vec![0u8; bitmap_len(RANK_WINDOW)],
        }
    }

    fn lend(&mut self) -> kassigner_protocol::stego::picture::Window<'_> {
        kassigner_protocol::stego::picture::Window {
            coefficients: &mut self.coefficients,
            filled: &mut self.filled,
            changed: &mut self.changed,
        }
    }
}

/// `photo` with `payload` hidden by `carrier` under `descriptor`, by the
/// protocol's own export, whatever the payload's shape.
fn hidden(
    photo: &[u8],
    carrier: kassigner_protocol::stego::Carrier,
    descriptor: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut w = TestWindow::new();
    let key = kassigner_crypto::stego::walk_key(descriptor);
    let mut app1 = vec![0u8; kassigner_fw::limits::APP1_SCRATCH];
    let mut out = vec![0u8; photo.len() + 80_000];
    let n = kassigner_protocol::stego::export(
        photo,
        carrier,
        &kassigner_protocol::stego::Export {
            descriptor,
            payload,
            key: &key,
            random: &[5u8; 8],
        },
        &mut w.lend(),
        &mut Box::new(kassigner_protocol::stego::picture::Tables::EMPTY),
        &mut app1,
        &mut out,
    )
    .unwrap();
    out.truncate(n);
    out
}

/// Tools → Import / Export → Import → Stego Import: the card's photos
/// listed from `sd` and `name` chosen, to the descriptor's source.
fn to_unhide<const N: usize>(f: &mut Flow<'_, N>, sd: &mut Sd, name: &[u8; 11]) {
    use kassigner_fw::ui::backup::{pick_zone_in, zone, Pick, Target};
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(tap_in(zone(SCALE, Target::Import).unwrap()), &mut Live);
    let out = f.step(item(&menu::IMPORT, 1), &mut Live);
    assert_eq!(out.command, Some(Command::Card(Job::ListPhotos)));
    let outcome = card::run(Job::ListPhotos, Kind::SdV2High, sd, &mut f.card_request());
    f.step(Event::Card(outcome), &mut Live);
    assert_eq!(f.list_title(), "SELECT PHOTO");
    let n = f.backups().len();
    let i = f.backups().iter().position(|b| b == name).expect("listed");
    f.step(
        tap_in(pick_zone_in(SCALE, n, 0, false, Pick::Row(i)).unwrap()),
        &mut Live,
    );
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::StegoSource,
            page: 0
        }
    );
}

/// OK on the import's keyboard, then the photo's read and every tick, to
/// where the import stops: LOAD SEED?, or a refusal.
fn unhide<const N: usize>(f: &mut Flow<'_, N>, sd: &mut Sd) -> kassigner_fw::flow::Output {
    let out = descriptor_ok(f);
    assert_eq!(out.command, Some(Command::Card(Job::Read)));
    let outcome = card::run(Job::Read, Kind::SdV2High, sd, &mut f.card_request());
    let out = f.step(Event::Card(outcome), &mut Live);
    assert_eq!(out.screen, Screen::StegoReading);
    opening_over(f)
}

/// Every tick a stego opening takes, under DECRYPTING and its bar, to where
/// it stops.
fn opening_over<const N: usize>(f: &mut Flow<'_, N>) -> kassigner_fw::flow::Output {
    let mut now = f.now_us();
    let mut ticks = 0;
    loop {
        now += 50_000;
        ticks += 1;
        let out = f.step(Event::Tick { now_us: now }, &mut Live);
        match f.state() {
            State::StegoOpening { .. } => {
                assert!(
                    matches!(out.screen, Screen::RestoreOpening { .. }),
                    "{:?}",
                    out.screen
                );
                assert!(ticks < 200, "opening never ends");
            }
            _ => return out,
        }
    }
}

/// A refusal's time over: where it rests.
fn refusal_over<const N: usize>(f: &mut Flow<'_, N>) -> State {
    let now = f.now_us() + 10_000_000;
    f.step(Event::Tick { now_us: now }, &mut Live);
    f.state()
}

/// A backup hidden by each carrier is imported back on a unit with no seed:
/// the descriptor typed, both carriers read and the payload opened; LOAD
/// SEED? says the words and where they were; LOAD shows the hint, NEXT the
/// passphrase, and the seed is in use. Nothing of the import is left.
#[test]
fn a_backup_is_imported_back_from_each_carrier() {
    use kassigner_protocol::stego::Carrier;
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    for (which, carrier) in Carrier::ALL.iter().enumerate() {
        // Hidden on one unit.
        let mut sd = card_with(&[(b"ROCKY   JPG", COLOR)]);
        {
            let mut m = Memory::new();
            let mut f: Flow<'_, 6> = seeded(&mut m);
            to_source(&mut f, &mut sd, which);
            f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
            descriptor_type(&mut f, b"Rocky 2024");
            descriptor_ok(&mut f);
            f.touch(answer(dialog::Target::Accept));
            f.touch(answer(dialog::Target::Accept));
            use kassigner_fw::ui::stego::{hint_zone, HintTarget};
            f.step(
                tap_in(hint_zone(SCALE, HintTarget::Row(1)).unwrap()),
                &mut Live,
            );
            assert_eq!(hide_backup(&mut f, &mut sd).screen, Screen::StegoDone);
        }

        // Opened on another, with no seed.
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        to_unhide(&mut f, &mut sd, b"ROCKY   JPG");
        f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
        assert_eq!(f.state(), State::StegoKey { page: 0 });
        descriptor_type(&mut f, b"Rocky 2024");
        assert_eq!(f.typed().0, "Rocky 2024");
        assert_eq!(
            f.keyboard_note(),
            Some(keyboard::Note::Count { used: 10, of: 128 })
        );
        let out = unhide(&mut f, &mut sd);
        assert_eq!(
            out.screen,
            Screen::StegoFound {
                words: 12,
                carrier: *carrier,
                two: false
            },
            "{carrier:?}"
        );
        assert_eq!(f.descriptor(), "", "the descriptor goes once it opened");

        // LOAD: the hint; Back, LOAD SEED? again; NEXT, the passphrase.
        let out = f.touch(answer(dialog::Target::Accept));
        assert_eq!(out.screen, Screen::StegoHintShown);
        assert!(out.screen.shows_secret());
        assert_eq!(f.hint(), "Name of my loved one?");
        f.touch(back_button());
        assert_eq!(f.state(), State::StegoFound);
        f.touch(answer(dialog::Target::Accept));
        f.touch(answer(dialog::Target::Accept));
        assert_eq!(f.state(), State::Passphrase { page: 0 });
        assert_eq!(f.hint(), "", "the hint goes with the passphrase screen");
        f.step(no_passphrase(), &mut Live);
        opened(&mut f);
        assert_eq!(f.fingerprint(), Some(wallet().fingerprint()));
        // The photo, the window and the payloads, wiped.
        let clean = |b: &[u8]| b.iter().all(|&x| x == 0);
        assert!(clean(&m.photo) && clean(&m.photo_out) && clean(&m.window_bits));
        assert!(m.window.iter().all(|&x| x == 0));
    }
}

/// A wrong descriptor, a photo with no backup and a file that is not a
/// photo are refused by name, back to the keyboard with the descriptor kept
/// to fix and retry. A metadata payload that does not open means a wrong
/// descriptor; the picture's, found only along its own descriptor's walk,
/// reads as no backup.
#[test]
fn a_wrong_descriptor_is_refused_and_fixed_in_place() {
    use kassigner_protocol::stego::{Carrier, StegoError};
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let payload = sealed_payload(&mnemonic(), b"", b"Rocky 2024");
    let metadata = hidden(COLOR, Carrier::Descriptor, b"Rocky 2024", &payload);
    let picture = hidden(COLOR, Carrier::Picture, b"Rocky 2024", &payload);
    let mut sd = card_with(&[
        (b"META    JPG", &metadata),
        (b"PIC     JPG", &picture),
        (b"PLAIN   JPG", COLOR),
        (b"NOTPHOTOJPG", b"not a photo at all"),
    ]);
    for (name, why, opens) in [
        (b"META    JPG", Refusal::WrongDescriptor, true),
        (b"PIC     JPG", Refusal::NoBackup, true),
        (b"PLAIN   JPG", Refusal::NoBackup, false),
        (b"NOTPHOTOJPG", Refusal::Stego(StegoError::NotJpeg), false),
    ] {
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        to_unhide(&mut f, &mut sd, name);
        f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
        descriptor_type(&mut f, b"Rocky 2023");
        let out = unhide(&mut f, &mut sd);
        assert_eq!(out.screen, Screen::Refused(why), "{why:?}");
        assert_eq!(f.seed_count(), 0);
        // Back on the keyboard after its time, the descriptor as typed.
        assert_eq!(refusal_over(&mut f), State::StegoKey { page: 0 }, "{why:?}");
        assert_eq!(f.typed().0, "Rocky 2023");
        if opens {
            // Fixed in place and tried again: it opens.
            f.step(key(descriptor_page(&f), keyboard::Key::Delete), &mut Live);
            descriptor_type(&mut f, b"4");
            let out = unhide(&mut f, &mut sd);
            assert!(
                matches!(
                    out.screen,
                    Screen::StegoFound {
                        words: 12,
                        two: false,
                        ..
                    }
                ),
                "{:?}",
                out.screen
            );
        }
    }
}

/// Standard base64, padded: how v1.0.5 and v1.0.6 wrote a payload.
fn base64(bytes: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[(n >> (18 - 6 * i)) as usize & 63]
            } else {
                b'='
            });
        }
    }
    out
}

/// v1.0.7 and v1.0.6 photos open, from the metadata and the picture: seed
/// and hint, each sealed apart under its own salt and derived in turn.
/// v1.0.7's seed and hint containers from the corpus, both under `abc`,
/// laid as v1.0.7 laid them, each from its length byte on, one after the
/// other; and as v1.0.6 did, whole, in base64, a `|` between. A v1.0.5
/// payload, under the fixed salt every unit then shared, is refused by
/// name: v1.1.0 does not open those containers.
#[test]
fn a_v107_photo_opens_its_seed_and_its_hint() {
    use kassigner_protocol::stego::Carrier;
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let seed: &[u8] = include_bytes!("../../../../spec/vectors/v107/cards/SD000001.KAS");
    let raw: &[u8] = include_bytes!("../../../../spec/vectors/v107/cards/RAWHINT.KAS");
    let head = kassigner_protocol::stego::blob::V2_HEAD;
    let mut v2 = seed[head..].to_vec();
    v2.extend_from_slice(&raw[head..]);
    let mut v1 = base64(seed);
    v1.push(b'|');
    v1.extend_from_slice(&base64(raw));
    assert!(v1.starts_with(b"S0FT"));
    for (payload, carrier) in [
        (&v2, Carrier::Descriptor),
        (&v2, Carrier::Picture),
        // Base64 outgrows the fixture's picture; the picture's walk does
        // not look at what it carries.
        (&v1, Carrier::Descriptor),
    ] {
        let photo = hidden(COLOR, carrier, b"abc", payload);
        let mut sd = card_with(&[(b"V107    JPG", &photo)]);
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        to_unhide(&mut f, &mut sd, b"V107    JPG");
        f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
        descriptor_type(&mut f, b"abc");
        let out = unhide(&mut f, &mut sd);
        assert_eq!(
            out.screen,
            Screen::StegoFound {
                words: 12,
                carrier,
                two: false
            },
            "{carrier:?}"
        );
        f.touch(answer(dialog::Target::Accept));
        assert_eq!(f.state(), State::StegoHintShown);
        assert_eq!(f.hint(), "stego hint: abandon 12");
        f.touch(answer(dialog::Target::Accept));
        f.step(no_passphrase(), &mut Live);
        opened(&mut f);
        assert_eq!(f.fingerprint(), Some(fingerprint_of(ABANDON12)));
    }

    // v1.0.5's: a `KAS\x01` seed container, in base64.
    let mut old = b"KAS\x01".to_vec();
    old.extend_from_slice(&[0x5A; 72]);
    let photo = hidden(COLOR, Carrier::Descriptor, b"abc", &base64(&old));
    let mut sd = card_with(&[(b"V105    JPG", &photo)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    to_unhide(&mut f, &mut sd, b"V105    JPG");
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"abc");
    let out = unhide(&mut f, &mut sd);
    assert_eq!(out.screen, Screen::Refused(Refusal::UnknownFormat));
}

/// A photo holding two different backups restores the picture's and says
/// it held two; one whose picture holds nothing under the descriptor falls
/// back on the metadata's, saying nothing.
#[test]
fn a_photo_with_two_backups_restores_the_picture_one_and_says_so() {
    use kassigner_protocol::stego::Carrier;
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let abandon = bip39::from_words(ABANDON12.split(' ')).unwrap();
    let mine = sealed_payload(&mnemonic(), b"", b"Rocky 2024");
    let other = sealed_payload(&abandon, b"", b"Rocky 2024");
    let elsewhere = sealed_payload(&mnemonic(), b"", b"Beach 2023");
    let two = hidden(
        &hidden(COLOR, Carrier::Picture, b"Rocky 2024", &mine),
        Carrier::Descriptor,
        b"Rocky 2024",
        &other,
    );
    let apart = hidden(
        &hidden(COLOR, Carrier::Picture, b"Beach 2023", &elsewhere),
        Carrier::Descriptor,
        b"Rocky 2024",
        &other,
    );
    let mut sd = card_with(&[(b"TWO     JPG", &two), (b"APART   JPG", &apart)]);
    for (name, carrier, two, wallet_of) in [
        (
            b"TWO     JPG",
            Carrier::Picture,
            true,
            wallet().fingerprint(),
        ),
        (
            b"APART   JPG",
            Carrier::Descriptor,
            false,
            fingerprint_of(ABANDON12),
        ),
    ] {
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        to_unhide(&mut f, &mut sd, name);
        f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
        descriptor_type(&mut f, b"Rocky 2024");
        let out = unhide(&mut f, &mut sd);
        assert_eq!(
            out.screen,
            Screen::StegoFound {
                words: 12,
                carrier,
                two
            }
        );
        // No hint: LOAD goes to the passphrase.
        f.touch(answer(dialog::Target::Accept));
        assert_eq!(f.state(), State::Passphrase { page: 0 });
        f.step(no_passphrase(), &mut Live);
        opened(&mut f);
        assert_eq!(f.fingerprint(), Some(wallet_of));
    }
}

/// Stego Import reads a descriptor of up to 128 characters, as v1.0.7 wrote
/// them: typed, the keyboard takes 128 and no more; from a `.TXT`, the line
/// goes onto the keyboard to be looked over, and a longer one is refused by
/// name. A picture hidden under a 100-character descriptor, which v1.1.0
/// never writes, opens.
#[test]
fn an_import_reads_a_descriptor_up_to_128_characters() {
    use kassigner_protocol::stego::Carrier;
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let long: &[u8] = b"Me at the age of twenty with my family on the hill by the lake, \
the summer we drove south to see";
    assert_eq!(long.len(), 96);
    let payload = sealed_payload(&mnemonic(), b"", long);
    let photo = {
        let mut w = TestWindow::new();
        let key = kassigner_crypto::stego::walk_key(long);
        let mut out = vec![0u8; COLOR.len() + 80_000];
        let n = kassigner_protocol::stego::picture::embed(
            COLOR,
            &payload,
            &key,
            &mut w.lend(),
            &mut Box::new(kassigner_protocol::stego::picture::Tables::EMPTY),
            &mut out,
        )
        .unwrap();
        out.truncate(n);
        out
    };
    let mut caption = long.to_vec();
    caption.extend_from_slice(b"\r\n");
    let mut sd = card_with(&[
        (b"ROCKY   JPG", &photo),
        (b"CAPTION TXT", &caption),
        (b"LONG    TXT", &[b'y'; 129]),
    ]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    to_unhide(&mut f, &mut sd, b"ROCKY   JPG");

    // Typed: 128 and no more; Back drops it.
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, &[b'a'; 130]);
    assert_eq!(f.typed().0.len(), 128);
    assert_eq!(
        f.keyboard_note(),
        Some(keyboard::Note::Count { used: 128, of: 128 })
    );
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::StegoSource,
            page: 0
        }
    );
    assert_eq!(f.descriptor(), "");

    // A line past 128, refused by name, back to the source menu.
    let out = caption_file(&mut f, &mut sd, b"LONG    TXT");
    assert_eq!(
        out.screen,
        Screen::CardDone {
            job: Job::Read,
            outcome: Outcome::Failed(card::Error::Backup("Line over 128 characters"))
        }
    );
    let now = f.now_us() + 60_000_000;
    f.step(Event::Tick { now_us: now }, &mut Live);

    // The caption: on the keyboard to look over; OK opens the photo.
    caption_file(&mut f, &mut sd, b"CAPTION TXT");
    assert_eq!(f.state(), State::StegoKey { page: 0 });
    assert_eq!(f.typed().0.as_bytes(), long);
    let out = unhide(&mut f, &mut sd);
    assert_eq!(
        out.screen,
        Screen::StegoFound {
            words: 12,
            carrier: Carrier::Picture,
            two: false
        }
    );
}

/// LOAD SEED?'s CANCEL drops the seed, back to Import, and its Home goes
/// home; the keyboard's Home wipes the descriptor; a descriptor typed with
/// no seed is taken by the idle wipe.
#[test]
fn an_import_is_dropped_whole_and_its_descriptor_wiped() {
    use kassigner_protocol::stego::Carrier;
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let payload = sealed_payload(&mnemonic(), b"Name of my loved one?", b"Rocky 2024");
    let photo = hidden(COLOR, Carrier::Both, b"Rocky 2024", &payload);
    let mut sd = card_with(&[(b"ROCKY   JPG", &photo)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);

    // CANCEL, from LOAD SEED? and from the hint: Import, nothing kept.
    for from_hint in [false, true] {
        to_unhide(&mut f, &mut sd, b"ROCKY   JPG");
        f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
        descriptor_type(&mut f, b"Rocky 2024");
        let out = unhide(&mut f, &mut sd);
        assert_eq!(
            out.screen,
            Screen::StegoFound {
                words: 12,
                carrier: Carrier::Both,
                two: false
            }
        );
        if from_hint {
            f.touch(answer(dialog::Target::Accept));
            assert_eq!(f.state(), State::StegoHintShown);
        }
        f.touch(answer(dialog::Target::Cancel));
        assert_eq!(
            f.state(),
            State::Menu {
                menu: MenuId::Import,
                page: 0
            }
        );
        assert_eq!((f.descriptor(), f.hint()), ("", ""));
        assert_eq!(f.seed_count(), 0);
        f.step(home_button(), &mut Live);
    }

    // Home from LOAD SEED?: home, nothing kept.
    to_unhide(&mut f, &mut sd, b"ROCKY   JPG");
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Rocky 2024");
    unhide(&mut f, &mut sd);
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);
    assert_eq!((f.descriptor(), f.hint()), ("", ""));
    assert_eq!(f.seed_count(), 0);

    // The keyboard's Home wipes the descriptor.
    to_unhide(&mut f, &mut sd, b"ROCKY   JPG");
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Rocky");
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.descriptor(), "");

    // Typed and left: the idle wipe takes it, with no seed held.
    to_unhide(&mut f, &mut sd, b"ROCKY   JPG");
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Rocky");
    let t = f.now_us();
    f.step(
        Event::Tick {
            now_us: t + IDLE_WIPE_US - 1,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::StegoKey { page: 0 });
    f.step(
        Event::Tick {
            now_us: t + IDLE_WIPE_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.descriptor(), "");
}

/// Descriptor or Both overwrite a backup in a photo's metadata only under
/// its own descriptor, as a card file only under its password. OVERWRITE?
/// asks; CANCEL lists again; the keyboard's Back is OVERWRITE?; a wrong
/// descriptor writes nothing and returns to the list; the right one
/// replaces the old backup, keeping nothing of it. Picture leaves the
/// metadata and asks nothing; nor is a backup in the picture asked about:
/// it cannot be seen without its descriptor.
#[test]
fn a_backup_in_the_metadata_is_overwritten_only_under_its_descriptor() {
    use kassigner_fw::ui::backup::{pick_zone_in, Pick};
    use kassigner_protocol::stego::Carrier;
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let abandon = bip39::from_words(ABANDON12.split(' ')).unwrap();
    let old = sealed_payload(&abandon, b"", b"Rocky 2024");
    let meta = hidden(COLOR, Carrier::Descriptor, b"Rocky 2024", &old);
    let pic = hidden(COLOR, Carrier::Picture, b"Rocky 2024", &old);
    let mut sd = card_with(&[(b"META    JPG", &meta), (b"PIC     JPG", &pic)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut m);
    // Through the carriers to the list, and `name` chosen and read.
    let choose = |f: &mut Flow<'_, 6>, sd: &mut Sd, name: &[u8; 11]| {
        let n = f.backups().len();
        let i = f.backups().iter().position(|b| b == name).unwrap();
        let out = f.step(
            tap_in(pick_zone_in(SCALE, n, 0, false, Pick::Row(i)).unwrap()),
            &mut Live,
        );
        assert_eq!(out.command, Some(Command::Card(Job::Read)));
        photo_read(f, sd)
    };
    let list = |f: &mut Flow<'_, 6>, sd: &mut Sd| {
        let outcome = card::run(Job::ListPhotos, Kind::SdV2High, sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live);
    };
    to_stego(&mut f);
    f.step(carrier(0), &mut Live);
    list(&mut f, &mut sd);

    // OVERWRITE?: CANCEL is the list again.
    let out = choose(&mut f, &mut sd, b"META    JPG");
    assert_eq!(out.screen, Screen::StegoOverwrite);
    let out = f.touch(answer(dialog::Target::Cancel));
    assert_eq!(out.command, Some(Command::Card(Job::ListPhotos)));
    list(&mut f, &mut sd);
    assert_eq!(f.state(), State::RestoreList { page: 0 });

    // OVERWRITE: the old descriptor, titled for it; Back is OVERWRITE?.
    choose(&mut f, &mut sd, b"META    JPG");
    let out = f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::StegoOldKey { page: 0 });
    assert!(matches!(
        out.screen,
        Screen::Keyboard {
            typing: kassigner_fw::flow::Typing::OldDescriptor,
            ..
        }
    ));
    assert_eq!(
        kassigner_fw::flow::Typing::OldDescriptor.title(),
        "OLD DESCRIPTOR"
    );
    f.step(key(0, keyboard::Key::Char(b'x')), &mut Live);
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::StegoOverwrite);
    assert_eq!(f.descriptor(), "");

    // A wrong one: refused, nothing written, back to the list.
    f.touch(answer(dialog::Target::Accept));
    descriptor_type(&mut f, b"Rocky 2023");
    descriptor_ok(&mut f);
    let out = opening_over(&mut f);
    assert_eq!(out.screen, Screen::Refused(Refusal::WrongDescriptor));
    assert_eq!(refusal_over(&mut f), State::RestoreList { page: 0 });
    assert_eq!(f.descriptor(), "");
    assert_eq!(on_card(&mut sd, b"META    JPG"), meta, "nothing written");

    // The right one: the export goes on, nothing of the old backup kept.
    choose(&mut f, &mut sd, b"META    JPG");
    f.touch(answer(dialog::Target::Accept));
    descriptor_type(&mut f, b"Rocky 2024");
    descriptor_ok(&mut f);
    opening_over(&mut f);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::StegoSource,
            page: 0
        }
    );
    assert_eq!((f.descriptor(), f.hint()), ("", ""));
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Beach 2025");
    descriptor_ok(&mut f);
    f.touch(answer(dialog::Target::Accept));
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(hide_backup(&mut f, &mut sd).screen, Screen::StegoDone);
    let photo = on_card(&mut sd, b"META    JPG");
    let (_, now) = opened_photo(&photo, b"Beach 2025");
    assert!(now.is_some(), "the new backup");
    assert_eq!(
        opened_photo(&photo, b"Rocky 2024").1,
        None,
        "the old one gone"
    );

    // Picture over the metadata's backup: no question, the metadata kept.
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::StegoCarrier);
    f.step(carrier(1), &mut Live);
    list(&mut f, &mut sd);
    let out = choose(&mut f, &mut sd, b"META    JPG");
    assert_eq!(
        out.screen,
        Screen::Menu {
            menu: MenuId::StegoSource,
            page: 0
        }
    );

    // Descriptor over a backup in the picture: nothing can see it.
    f.step(back_button(), &mut Live);
    list(&mut f, &mut sd);
    f.step(back_button(), &mut Live);
    f.step(carrier(0), &mut Live);
    list(&mut f, &mut sd);
    let out = choose(&mut f, &mut sd, b"PIC     JPG");
    assert_eq!(
        out.screen,
        Screen::Menu {
            menu: MenuId::StegoSource,
            page: 0
        }
    );
}

/// The photo list shows each photo by its long name where the card holds
/// one, else `NAME.EXT`. It is still read and written by its 8.3 name; HIDE
/// BACKUP? and BACKUP HIDDEN show the listed name, kept past the embedding,
/// which overwrites where the list kept it. A caption file's list shows no
/// long names.
#[test]
fn the_photo_list_shows_long_names() {
    use kassigner_fat32::fat32::{
        find_file_in_root, mount_fat32, write_dir_entry_with_long_name, DirEntry,
    };
    use kassigner_fw::ui::backup::{pick_zone_in, Pick};
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let mut sd = card_with(&[(b"ROCKY   JPG", COLOR), (b"CAPTION TXT", b"Rocky 2024")]);
    // A camera's photo: its long name over its short one, on ROCKY's bytes.
    let info = mount_fat32(&mut sd).unwrap();
    let (rocky, _, _) = find_file_in_root(&mut sd, &info, b"ROCKY   JPG").unwrap();
    let camera = DirEntry {
        name: *b"IMG_20~1JPG",
        ..rocky
    };
    let long: Vec<u16> = "IMG_20241014_153022.jpg".encode_utf16().collect();
    write_dir_entry_with_long_name(&mut sd, &info, &camera, &long).unwrap();

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut m);
    to_stego(&mut f);
    f.step(carrier(0), &mut Live);
    let outcome = card::run(
        Job::ListPhotos,
        Kind::SdV2High,
        &mut sd,
        &mut f.card_request(),
    );
    f.step(Event::Card(outcome), &mut Live);
    let shown: Vec<&str> = (0..f.backups().len())
        .map(|i| card::long_name(f.long_names(), i).unwrap())
        .collect();
    assert_eq!(shown, ["ROCKY.JPG", "IMG_20241014_153022.jpg"]);

    // Chosen: read by its 8.3 name, shown by its long one.
    let i = f
        .backups()
        .iter()
        .position(|b| b == b"IMG_20~1JPG")
        .unwrap();
    f.step(
        tap_in(pick_zone_in(SCALE, 2, 0, false, Pick::Row(i)).unwrap()),
        &mut Live,
    );
    photo_read(&mut f, &mut sd);
    assert_eq!(f.photo_name(), b"IMG_20~1JPG");
    assert_eq!(f.photo_shown(), "IMG_20241014_153022.jpg");

    // A caption's list: no long names.
    let out = f.step(item(&menu::DESCRIPTOR_SOURCE, 1), &mut Live);
    assert_eq!(out.command, Some(Command::Card(Job::ListText)));
    let outcome = card::run(
        Job::ListText,
        Kind::SdV2High,
        &mut sd,
        &mut f.card_request(),
    );
    f.step(Event::Card(outcome), &mut Live);
    assert_eq!(f.list_title(), "SELECT FILE");
    assert!(f.long_names().is_empty());
    f.step(back_button(), &mut Live);

    // Hidden: the name still the long one on BACKUP HIDDEN.
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Rocky 2024");
    descriptor_ok(&mut f);
    f.touch(answer(dialog::Target::Accept));
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(hide_backup(&mut f, &mut sd).screen, Screen::StegoDone);
    assert_eq!(f.photo_shown(), "IMG_20241014_153022.jpg");
}

/// The idle wipe lets a backup being hidden in a photo finish, as it lets
/// one being sealed: with four minutes passing during the export, it seals,
/// embeds and writes, and the wipe comes on the tick after the write.
#[test]
fn the_idle_wipe_lets_a_stego_export_finish_first() {
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let mut sd = card_with(&[(b"ROCKY   JPG", COLOR)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut m);
    to_source(&mut f, &mut sd, 0);
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Rocky 2024");
    descriptor_ok(&mut f);
    f.touch(answer(dialog::Target::Accept));
    f.touch(answer(dialog::Target::Cancel));
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::StegoSealing { done: 0 });
    let late = f.now_us() + IDLE_WIPE_US;
    let mut ticks = 0;
    while matches!(
        f.state(),
        State::StegoSealing { .. } | State::StegoEmbedding
    ) {
        f.step(Event::Tick { now_us: late }, &mut Live);
        ticks += 1;
        assert!(ticks < 40, "it seals and embeds");
    }
    assert_eq!(f.state(), State::CardBusy(Job::Write), "not wiped");
    let outcome = card::run(Job::Write, Kind::SdV2High, &mut sd, &mut f.card_request());
    f.step(Event::Card(outcome), &mut Live);
    assert_eq!(f.state(), State::StegoDone);
    assert!(
        opened_photo(&on_card(&mut sd, b"ROCKY   JPG"), b"Rocky 2024")
            .1
            .is_some()
    );
    f.step(Event::Tick { now_us: late + 1 }, &mut Live);
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.seed_count(), 0);
}

/// OTHER opens the photo's other backup under the same descriptor, so each
/// of two seeds under one descriptor can be reached; OTHER again goes back.
/// One that does not open under the descriptor says so, and LOAD SEED?
/// comes back for the seed found; Back drops it.
#[test]
fn other_opens_the_photos_other_backup() {
    use kassigner_protocol::stego::Carrier;
    const COLOR: &[u8] =
        include_bytes!("../../../../crates/kassigner-jpeg/tests/fixtures/color_rst.jpg");
    let abandon = bip39::from_words(ABANDON12.split(' ')).unwrap();
    let mine = sealed_payload(&mnemonic(), b"", b"Rocky 2024");
    let other = sealed_payload(&abandon, b"", b"Rocky 2024");
    let elsewhere = sealed_payload(&abandon, b"", b"Beach 2023");
    let picture = hidden(COLOR, Carrier::Picture, b"Rocky 2024", &mine);
    let two = hidden(&picture, Carrier::Descriptor, b"Rocky 2024", &other);
    let split = hidden(&picture, Carrier::Descriptor, b"Beach 2023", &elsewhere);
    let mut sd = card_with(&[(b"TWO     JPG", &two), (b"SPLIT   JPG", &split)]);
    let found = |carrier| Screen::StegoFound {
        words: 12,
        carrier,
        two: true,
    };

    // One descriptor, two seeds: OTHER, OTHER back, OTHER, and the
    // metadata's loaded.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    to_unhide(&mut f, &mut sd, b"TWO     JPG");
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Rocky 2024");
    assert_eq!(unhide(&mut f, &mut sd).screen, found(Carrier::Picture));
    for carrier in [Carrier::Descriptor, Carrier::Picture, Carrier::Descriptor] {
        f.touch(answer(dialog::Target::Cancel));
        assert!(matches!(f.state(), State::StegoOpening { .. }));
        assert_eq!(opening_over(&mut f).screen, found(carrier));
    }
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::Passphrase { page: 0 });
    f.step(no_passphrase(), &mut Live);
    opened(&mut f);
    assert_eq!(f.fingerprint(), Some(fingerprint_of(ABANDON12)));
    let clean = |b: &[u8]| b.iter().all(|&x| x == 0);
    assert!(clean(&m.photo_out), "the payloads kept for OTHER, wiped");

    // The other under another descriptor: refused, and the seed found
    // still there to load.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    to_unhide(&mut f, &mut sd, b"SPLIT   JPG");
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Rocky 2024");
    assert_eq!(unhide(&mut f, &mut sd).screen, found(Carrier::Picture));
    f.touch(answer(dialog::Target::Cancel));
    let out = opening_over(&mut f);
    assert_eq!(out.screen, Screen::Refused(Refusal::WrongDescriptor));
    assert_eq!(refusal_over(&mut f), State::StegoFound);
    let now = f.now_us();
    let out = f.step(Event::Tick { now_us: now + 1 }, &mut Live);
    assert_eq!(out.screen, found(Carrier::Picture));
    // Back drops it.
    f.touch(back_button());
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Import,
            page: 0
        }
    );
    assert_eq!(f.seed_count(), 0);
    assert_eq!((f.descriptor(), f.hint()), ("", ""));

    // Again, and LOAD after the refusal: the picture's seed.
    f.step(home_button(), &mut Live);
    to_unhide(&mut f, &mut sd, b"SPLIT   JPG");
    f.step(item(&menu::DESCRIPTOR_SOURCE, 0), &mut Live);
    descriptor_type(&mut f, b"Rocky 2024");
    unhide(&mut f, &mut sd);
    f.touch(answer(dialog::Target::Cancel));
    opening_over(&mut f);
    refusal_over(&mut f);
    f.touch(answer(dialog::Target::Accept));
    f.step(no_passphrase(), &mut Live);
    opened(&mut f);
    assert_eq!(f.fingerprint(), Some(wallet().fingerprint()));
}
