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

//! Sign Message: a message typed, scanned or opened, signed, checked, and
//! wiped.

use super::*;

/// Turn a message's pages to its last, which SIGN waits for.
fn read_message<const N: usize>(f: &mut Flow<'_, N>) {
    use kassigner_fw::ui::address as screen;
    while let State::MessagePreview { page } = f.state() {
        if page + 1 >= screen::message_pages(f.message_text()) {
            return;
        }
        let next = screen::zone(SCALE, false, page == 0, screen::Target::After).unwrap();
        f.step(tap_in(next), &mut Live);
    }
}

/// Sign Message is Tools' third row, and its Back is Tools.
#[test]
fn sign_message_opens_from_tools_and_backs_out_to_it() {
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut mem);
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 2), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SignMessage,
            page: 0
        }
    );
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Tools,
            page: 0
        }
    );
}

/// A long message is signed only once its last page has been shown: SIGN
/// is dimmed and inert until then, then works from any page, also after
/// SIGN WITH's Back. The next message starts unread. CHECK on a signed
/// message is never held back: checking signs nothing.
#[test]
fn a_long_message_is_signed_only_once_read() {
    use kassigner_fw::ui::address as screen;
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut mem);
    let tap = |t, page: usize| tap_in(screen::zone(SCALE, false, page == 0, t).unwrap());
    let preview = |page, pages, live| Screen::MessagePreview {
        page,
        pages,
        signed: false,
        live,
    };

    sign_message(&mut f, 2);
    // Ending in a word: a space ending the text is not signed.
    let text = format!("{}Kaspa!", "Kaspa ".repeat(39));
    let out = f.step(Event::Code(text.as_bytes()), &mut Live);
    let pages = screen::message_pages(f.message_text());
    assert!(pages >= 3, "{pages}");
    assert_eq!(out.screen, preview(0, pages, false));

    // SIGN unread: nothing, and no command.
    let out = f.step(tap(screen::Target::Index, 0), &mut Live);
    assert_eq!((out.screen, out.command), (preview(0, pages, false), None));
    let out = f.step(tap(screen::Target::After, 0), &mut Live);
    assert_eq!(out.screen, preview(1, pages, false));
    let out = f.step(tap(screen::Target::Index, 1), &mut Live);
    assert_eq!(
        out.screen,
        preview(1, pages, false),
        "page 2 is not the last"
    );

    // The last page: SIGN lit, and lit on every page from then on.
    for page in 2..pages {
        let out = f.step(tap(screen::Target::After, page - 1), &mut Live);
        assert_eq!(out.screen, preview(page, pages, page + 1 == pages));
    }
    for page in (0..pages - 1).rev() {
        let out = f.step(tap(screen::Target::Before, page + 1), &mut Live);
        assert_eq!(out.screen, preview(page, pages, true));
    }
    let out = f.step(tap(screen::Target::Index, 0), &mut Live);
    assert_eq!(
        out.screen,
        Screen::SignWith {
            change: false,
            index: 0
        }
    );
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::MessagePreview { page: 0 });
    let out = f.step(tap(screen::Target::Index, 0), &mut Live);
    assert!(matches!(out.screen, Screen::SignWith { .. }), "still read");

    // The next message, unread.
    f.step(home_button(), &mut Live);
    sign_message(&mut f, 2);
    let out = f.step(Event::Code(text.as_bytes()), &mut Live);
    assert_eq!(out.screen, preview(0, pages, false));
    let out = f.step(tap(screen::Target::Index, 0), &mut Live);
    assert_eq!(out.screen, preview(0, pages, false));

    // A signed one: CHECK from its first page.
    f.step(home_button(), &mut Live);
    sign_message(&mut f, 2);
    let record = record_of(&text);
    let out = f.step(Event::Code(&record), &mut Live);
    assert!(matches!(
        out.screen,
        Screen::MessagePreview {
            page: 0,
            signed: true,
            live: true,
            ..
        }
    ));
    // The signature is checked on the tick after the tap.
    let out = f.step(tap(screen::Target::Index, 0), &mut Live);
    let out = settled(&mut f, out);
    assert_eq!(out.screen, Screen::MessageCheck { valid: Some(true) });
}

/// A typed message is signed rusty-kaspa's way: SIGN opens SIGN WITH, a tap
/// on the address asks, and SIGN signs the personal message hash with that
/// key and the unit's auxiliary bytes. Signature, address and codes read
/// back; SAVE SD starts a save.
#[test]
fn a_typed_message_is_signed() {
    use kassigner_crypto::sign::sign;
    use kassigner_fw::flow::Typing;
    use kassigner_fw::ui::address as screen;
    use kassigner_kaspa::sighash::personal_message_hash;
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut mem);
    let out = sign_message(&mut f, 0);
    assert!(matches!(
        out.screen,
        Screen::Keyboard {
            typing: Typing::Message,
            ..
        }
    ));
    let text = "Hello Kaspa!";
    let out = type_message(&mut f, text);
    assert_eq!(
        out.screen,
        Screen::MessagePreview {
            page: 0,
            pages: 1,
            signed: false,
            live: true
        }
    );
    assert_eq!(f.message_text(), text);

    let on = |t, first| tap_in(screen::zone(SCALE, false, first, t).expect("on the screen"));
    let out = f.step(on(screen::Target::Index, true), &mut Live);
    assert_eq!(
        out.screen,
        Screen::SignWith {
            change: false,
            index: 0
        }
    );
    let out = f.step(on(screen::Target::Address, true), &mut Live);
    assert_eq!(out.screen, Screen::MessageConfirm);
    assert_eq!(f.address_text(), address_of(Path::receive(0)));
    let out = message_signed(&mut f);
    assert_eq!(out.screen, Screen::MessageResult { page: 0 });

    let mut aux = [0u8; 32];
    for (i, b) in aux.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    let w = wallet();
    let k = w.signing_key(Path::receive(0)).unwrap();
    let hash = personal_message_hash(text.as_bytes());
    let want = hex(sign(k.private_key(), &hash, &aux).unwrap().as_bytes());
    assert_eq!(f.signature_text(), want);

    // A tap: the address; another: the signed message's code.
    let out = f.step(on(screen::Target::Address, true), &mut Live);
    assert_eq!(out.screen, Screen::MessageResult { page: 1 });
    let mut record = vec![0u8; 512];
    let n = kassigner_fw::message::write(
        text.as_bytes(),
        address_of(Path::receive(0)).as_bytes(),
        want.as_bytes(),
        &mut record,
    )
    .unwrap();
    record.truncate(n);
    let format = |f: &mut Flow<'_, 6>| {
        let out = f.step(on(screen::Target::Address, false), &mut Live);
        assert_eq!(out.screen, Screen::MessageFormat);
    };
    let pick = |t| tap_in(kassigner_fw::ui::kpub::zone(SCALE, t).unwrap());

    // Each choice, Manual: the frames read back join to the record, and a
    // tap on the last goes to MESSAGE EXPORTED. Wallet's are version-9
    // codes of 225 bytes, KasSigner's version-3 of 48 (frame 0 three fewer,
    // for the digest).
    for (target, per, most) in [
        (kassigner_fw::ui::kpub::Target::Wallet, 225, 53),
        (kassigner_fw::ui::kpub::Target::KasSigner, 48, 29),
    ] {
        format(&mut f);
        let wallet = target == kassigner_fw::ui::kpub::Target::Wallet;
        let frames = f.message_frames(wallet);
        assert_eq!(
            frames,
            kassigner_protocol::frame::frames_needed(record.len(), per)
        );
        assert!(frames > 1);
        f.step(pick(target), &mut Live);
        assert_eq!(f.state(), State::MessageMode);
        f.touch(answer(dialog::Target::Accept));
        let mut joined = Vec::new();
        for i in 0..frames {
            assert_eq!(f.state(), State::MessageFrames { frame: i as u8 });
            let code = f.message_frame(i as u8).unwrap();
            if wallet {
                assert_eq!(code.size, most, "every wallet frame at version 9");
            } else {
                assert!(code.size <= most, "{} modules", code.size);
            }
            let bytes = read_back(&code);
            let frame = kassigner_protocol::frame::parse(&bytes, 64).expect("a frame");
            assert_eq!((frame.index, usize::from(frame.total)), (i as u8, frames));
            joined.extend_from_slice(frame.fragment);
            f.step(on(screen::Target::Address, false), &mut Live);
        }
        assert_eq!(joined, record);
        assert_eq!(f.state(), State::MessageDone, "MESSAGE EXPORTED");
        f.touch(answer(dialog::Target::Accept));
        assert_eq!(f.state(), State::MessageFrames { frame: 0 }, "Back to QR");
        assert!(f.message_frame(0).is_some(), "drawn again");
        while f.state() != State::MessageDone {
            f.step(on(screen::Target::Address, false), &mut Live);
        }
        f.touch(answer(dialog::Target::Nav(Nav::Back)));
        assert_eq!(f.state(), State::MessageFormat, "Back is MESSAGE QR");
        f.step(back_button(), &mut Live);
        assert_eq!(f.state(), State::MessageResult { page: 1 });
    }

    let out = f.step(on(screen::Target::Index, false), &mut Live);
    assert_eq!(out.command, Some(Command::Card(Job::NextName)));
}

/// A signed message is not shown in more frames than a unit reassembles: a
/// 3,000-character text takes 69 KasSigner frames, past the 64 a unit
/// takes, so that card does nothing; the wallet's 15 are shown.
#[test]
fn a_message_too_long_for_a_unit_is_not_shown_in_frames() {
    use kassigner_fw::ui::address as screen;
    use kassigner_fw::ui::backup::{pick_zone, Pick};
    // 3,000 characters, ending in a word.
    let text = format!("{}Kaspa!", "Kaspa ".repeat(499));
    let mut sd = card_with(&[(b"NOTE    TXT", text.as_bytes())]);
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut mem);
    sign_message(&mut f, 1);
    run_job(&mut f, &mut sd, Job::ListText);
    f.step(
        tap_in(pick_zone(SCALE, 1, 0, Pick::Row(0)).unwrap()),
        &mut Live,
    );
    assert_eq!(restore_ok(&mut f).command, Some(Command::Card(Job::Read)));
    run_job(&mut f, &mut sd, Job::Read);
    assert!(
        matches!(f.state(), State::MessagePreview { page: 0 }),
        "{:?}",
        f.state()
    );
    assert_eq!(f.message_text(), text);

    // Every page, SIGN, the address, SIGN; then on to MESSAGE QR.
    read_message(&mut f);
    let on = |t, first| tap_in(screen::zone(SCALE, false, first, t).expect("on the screen"));
    f.step(on(screen::Target::Index, true), &mut Live);
    f.step(on(screen::Target::Address, true), &mut Live);
    message_signed(&mut f);
    f.step(on(screen::Target::Address, true), &mut Live);
    f.step(on(screen::Target::Address, false), &mut Live);
    assert_eq!(f.state(), State::MessageFormat);

    let most = P.max_frames;
    assert_eq!(f.message_frames(false), 69);
    assert!(!f.message_fits(false), "past {most} frames for a unit");
    f.step(reply_card(Card::KasSigner), &mut Live);
    assert_eq!(f.state(), State::MessageFormat, "KasSigner does nothing");

    assert_eq!(f.message_frames(true), 15);
    assert!(f.message_fits(true));
    f.step(reply_card(Card::Wallet), &mut Live);
    assert_eq!(f.state(), State::MessageMode, "Wallet shows its frames");
}

/// Scanned text, in one code or `Format::Opaque` frames, is the message; a
/// request's payload is refused.
#[test]
fn scanned_text_is_one_code_or_frames() {
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut mem);
    let out = sign_message(&mut f, 2);
    assert_eq!(out.command, Some(Command::CameraOn));
    assert_eq!(
        out.screen,
        Screen::MessageScan {
            have: 0,
            total: 0,
            received: 0
        }
    );
    f.step(Event::Code(b"I own this address."), &mut Live);
    assert_eq!(f.state(), State::MessagePreview { page: 0 });
    assert_eq!(f.message_text(), "I own this address.");

    f.step(home_button(), &mut Live);
    sign_message(&mut f, 2);
    f.step(
        Event::Progress {
            have: 1,
            total: 2,
            received: 0b1,
        },
        &mut Live,
    );
    f.step(Event::Opaque(b"framed\r\ntext"), &mut Live);
    assert_eq!(f.message_text(), "framed\r\ntext");

    f.step(home_button(), &mut Live);
    sign_message(&mut f, 2);
    let out = deliver(&mut f, b"KSPT");
    assert_eq!(out.command, Some(Command::CameraOff));
    assert_eq!(f.state(), State::Refused(Refusal::NotText));
}

/// A seed is never a message: a standard SeedQR, words in one code or in
/// frames, words with a bad checksum, and words typed are refused, and the
/// request buffer (PSRAM on a unit) stays all zeros. A compact SeedQR is
/// refused as not text. Sixteen or thirty-two printable characters, a
/// compact SeedQR's lengths, are still a message.
#[test]
fn a_seed_is_never_a_message() {
    const WORDS: &str = "abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon about";
    const BAD_CHECKSUM: &str = "abandon abandon abandon abandon abandon abandon \
                                abandon abandon abandon abandon abandon abandon";
    // Twelve short words, a valid phrase, within the keyboard's 64.
    const TYPED: &str = "act add age aim air all any arm art ask bag bus";
    let mut mem = Memory::new();
    {
        let mut f: Flow<'_, 6> = seeded(&mut mem);
        // A clock that only moves forward, past each refusal's time.
        let clock = std::cell::Cell::new(VERIFIED_US);
        let refused = |f: &mut Flow<'_, 6>, why: Refusal| {
            assert_eq!(f.state(), State::Refused(why));
            clock.set(clock.get() + 2 * REFUSED_US);
            f.step(
                Event::Tick {
                    now_us: clock.get(),
                },
                &mut Live,
            );
            assert_eq!(f.state(), State::Home);
        };
        let seed = seedqr();
        for event in [
            Event::Code(&seed),
            Event::Code(WORDS.as_bytes()),
            Event::Opaque(WORDS.as_bytes()),
            Event::Code(BAD_CHECKSUM.as_bytes()),
        ] {
            sign_message(&mut f, 2);
            let out = f.step(event, &mut Live);
            assert_eq!(out.command, Some(Command::CameraOff));
            refused(&mut f, Refusal::SeedNotMessage);
        }
        sign_message(&mut f, 2);
        f.step(Event::Code(&[7u8; 16]), &mut Live);
        refused(&mut f, Refusal::NotText);

        sign_message(&mut f, 0);
        type_message(&mut f, TYPED);
        refused(&mut f, Refusal::SeedNotMessage);
    }
    assert!(
        mem.request.iter().all(|&b| b == 0),
        "nothing of a seed copied"
    );

    let mut f: Flow<'_, 6> = seeded(&mut mem);
    for text in ["Sixteen letters.", "Thirty-two letters, exactly so.."] {
        sign_message(&mut f, 2);
        f.step(Event::Code(text.as_bytes()), &mut Live);
        assert_eq!(f.state(), State::MessagePreview { page: 0 });
        assert_eq!(f.message_text(), text);
        f.step(home_button(), &mut Live);
    }
}

/// A text to sign with a space ending a line or the text, or a line break
/// ending it, is refused and wiped, however it comes: signed, that would
/// not show. A signed message ending so is still shown to be checked:
/// checking signs nothing.
#[test]
fn a_text_ending_in_whitespace_is_not_signed() {
    let mut mem = Memory::new();
    {
        let mut f: Flow<'_, 6> = seeded(&mut mem);
        let clock = std::cell::Cell::new(VERIFIED_US);
        let refused = |f: &mut Flow<'_, 6>| {
            assert_eq!(f.state(), State::Refused(Refusal::TrailingWhitespace));
            clock.set(clock.get() + 2 * REFUSED_US);
            f.step(
                Event::Tick {
                    now_us: clock.get(),
                },
                &mut Live,
            );
            assert_eq!(f.state(), State::Home);
        };
        for event in [
            Event::Code(b"Pay me 5 KAS "),
            Event::Code(b"Pay me 5 KAS \nnow"),
            Event::Opaque(b"Pay me 5 KAS\n"),
            Event::Opaque(b"Pay me 5 KAS\r\n"),
        ] {
            sign_message(&mut f, 2);
            let out = f.step(event, &mut Live);
            assert_eq!(out.command, Some(Command::CameraOff));
            refused(&mut f);
        }
        sign_message(&mut f, 0);
        type_message(&mut f, "Pay me 5 KAS ");
        refused(&mut f);

        sign_message(&mut f, 2);
        f.step(Event::Code(&record_of("Pay me 5 KAS ")), &mut Live);
        assert_eq!(f.state(), State::MessagePreview { page: 0 });
        assert_eq!(f.message_text(), "Pay me 5 KAS ");
        f.step(home_button(), &mut Live);
    }
    assert!(
        !holds(&mem.request, b"Pay me 5 KAS "),
        "nothing of a refused text kept"
    );

    let mut sd = card_with(&[(b"NOTE    TXT", b"Pay me 5 KAS\n")]);
    let mut mem = Memory::new();
    {
        let mut f: Flow<'_, 6> = seeded(&mut mem);
        open_text_file(&mut f, &mut sd, b"", false);
        assert_eq!(
            f.state(),
            State::CardDone {
                job: Job::Read,
                outcome: Outcome::Failed(card::Error::Backup("Trailing spaces or lines")),
            }
        );
    }
    assert!(!holds(&mem.request, b"Pay me"), "the request's buffer");
}

/// A signed message's record for `text`, signed with receive address 0's
/// key and zero auxiliary bytes.
fn record_of(text: &str) -> Vec<u8> {
    use kassigner_kaspa::sighash::personal_message_hash;
    let w = wallet();
    let k = w.signing_key(Path::receive(0)).unwrap();
    let hash = personal_message_hash(text.as_bytes());
    let signature = hex(
        kassigner_crypto::sign::sign(k.private_key(), &hash, &[0; 32])
            .unwrap()
            .as_bytes(),
    );
    let mut out = vec![0u8; 1024];
    let n = kassigner_fw::message::write(
        text.as_bytes(),
        address_of(Path::receive(0)).as_bytes(),
        signature.as_bytes(),
        &mut out,
    )
    .unwrap();
    out.truncate(n);
    out
}

/// A signed message is checked with no seed: its text shows, CHECK finds
/// it valid against its address, DETAILS shows the signature. A changed
/// word is invalid, a script's address cannot be checked, and SIGN with no
/// seed is refused.
#[test]
fn a_signed_message_is_checked_without_a_wallet() {
    use kassigner_fw::ui::address as screen;
    let check = |f: &mut Flow<'_, 6>, record: &[u8]| {
        f.touch(home_button());
        sign_message(f, 2);
        f.step(Event::Code(record), &mut Live);
        assert!(matches!(f.state(), State::MessagePreview { page: 0 }));
        let on = tap_in(screen::zone(SCALE, false, true, screen::Target::Index).unwrap());
        let out = f.step(on, &mut Live);
        settled(f, out).screen
    };
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);

    let record = record_of("I own this address.");
    f.step(home_button(), &mut Live);
    sign_message(&mut f, 2);
    let out = f.step(Event::Code(&record), &mut Live);
    assert_eq!(
        out.screen,
        Screen::MessagePreview {
            page: 0,
            pages: 1,
            signed: true,
            live: true
        }
    );
    assert_eq!(f.message_text(), "I own this address.");
    assert_eq!(
        check(&mut f, &record),
        Screen::MessageCheck { valid: Some(true) }
    );
    assert_eq!(f.address_text(), address_of(Path::receive(0)));
    let out = f.touch(answer(dialog::Target::Accept));
    assert_eq!(out.screen, Screen::MessageResult { page: 0 });
    assert_eq!(f.signature_text().len(), 128);

    let forged: Vec<u8> = String::from_utf8(record.clone())
        .unwrap()
        .replace("I own", "I owe")
        .into_bytes();
    assert_eq!(
        check(&mut f, &forged),
        Screen::MessageCheck { valid: Some(false) }
    );

    let mut script = [0u8; 80];
    let n = kassigner_kaspa::address::encode(
        kassigner_kaspa::address::Prefix::Mainnet,
        kassigner_kaspa::address::Version::ScriptHash,
        &[7; 32],
        &mut script,
    )
    .unwrap();
    let theirs = String::from_utf8(record.clone())
        .unwrap()
        .replace(
            &address_of(Path::receive(0)),
            core::str::from_utf8(&script[..n]).unwrap(),
        )
        .into_bytes();
    assert_eq!(check(&mut f, &theirs), Screen::MessageCheck { valid: None });

    f.touch(home_button());
    sign_message(&mut f, 2);
    f.step(Event::Code(b"Sign me."), &mut Live);
    let on = tap_in(screen::zone(SCALE, false, true, screen::Target::Index).unwrap());
    f.step(on, &mut Live);
    assert_eq!(f.state(), State::Refused(Refusal::NoWallet));
}

/// Sign Message's file list, SELECT FILE, goes back to Sign Message, not
/// Import from SD.
#[test]
fn the_message_list_goes_back_to_sign_message() {
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{create_file, do_format_fat32, mount_fat32};
    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let info = mount_fat32(&mut sd).unwrap();
    create_file(&mut sd, &info, b"NOTE    TXT", b"Sign me.").unwrap();
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    let out = sign_message(&mut f, 1);
    assert_eq!(out.command, Some(Command::Card(Job::ListText)));
    let outcome = card::run(
        Job::ListText,
        Kind::SdV2High,
        &mut sd,
        &mut f.card_request(),
    );
    f.step(Event::Card(outcome), &mut Live);
    assert_eq!(f.state(), State::RestoreList { page: 0 });
    assert_eq!(f.list_title(), "SELECT FILE");
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SignMessage,
            page: 0
        }
    );
}

/// Deleting the last text file goes back to Sign Message, not to SELECT
/// FILE still listing it.
#[test]
fn deleting_the_last_text_file_goes_back_to_sign_message() {
    use kassigner_fw::ui::backup::{pick_zone, Pick};
    let mut sd = card_with(&[(b"NOTE    TXT", b"Sign me.")]);
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    sign_message(&mut f, 1);
    run_job(&mut f, &mut sd, Job::ListText);
    assert_eq!(f.backups(), &[*b"NOTE    TXT"]);

    // The trash: OK with nothing typed opens the plain file, then the hold.
    f.step(
        tap_in(pick_zone(SCALE, 1, 0, Pick::Trash(0)).unwrap()),
        &mut Live,
    );
    assert_eq!(restore_ok(&mut f).command, Some(Command::Card(Job::Read)));
    run_job(&mut f, &mut sd, Job::Read);
    assert!(
        matches!(f.state(), State::RestoreDelete { .. }),
        "{:?}",
        f.state()
    );
    let Event::Tap { x, y } = answer(dialog::Target::Accept) else {
        unreachable!()
    };
    let t = 1_000_000_000u64;
    f.step(answer(dialog::Target::Accept), &mut Live);
    f.step(Event::Tick { now_us: t }, &mut Live);
    f.step(Event::Press { x, y }, &mut Live);
    let out = f.step(
        Event::Tick {
            now_us: t + HOLD_US,
        },
        &mut Live,
    );
    assert_eq!(out.command, Some(Command::Card(Job::Delete)));
    f.step(Event::Tap { x, y }, &mut Live);
    let out = run_job(&mut f, &mut sd, Job::Delete);
    assert_eq!(out.command, Some(Command::Card(Job::ListText)));
    run_job(&mut f, &mut sd, Job::ListText);
    assert_eq!(f.card_said().empty, ("No .TXT files found", ""));

    // "No .TXT files found", then Sign Message.
    f.step(
        Event::Tick {
            now_us: t
                + HOLD_US
                + card_done_us(Job::ListText, Outcome::Listed { count: 0, extra: 0 }),
        },
        &mut Live,
    );
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SignMessage,
            page: 0
        }
    );
}

/// `text` sealed under `password`, as Sign Message's text files are.
fn sealed_text(text: &[u8], password: &[u8]) -> Vec<u8> {
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_protocol::container::{file_size, Purpose};
    let mut out = vec![0u8; file_size(text.len())];
    let n = seal(
        Purpose::Text,
        text,
        password,
        &[5; 16],
        &[6; 12],
        SealKdf::Pbkdf2Sha256,
        &mut out,
    )
    .unwrap();
    out.truncate(n);
    out
}

/// Sign Message's From SD: the card's one file picked (row or trash),
/// `password` typed, and the file read and opened as far as it goes.
fn open_text_file(f: &mut Flow<'_, 6>, sd: &mut Sd, password: &[u8], trash: bool) {
    use kassigner_fw::ui::backup::{pick_zone, Pick};
    sign_message(f, 1);
    run_job(f, sd, Job::ListText);
    let pick = if trash { Pick::Trash(0) } else { Pick::Row(0) };
    f.step(tap_in(pick_zone(SCALE, 1, 0, pick).unwrap()), &mut Live);
    type_on(f, password);
    assert_eq!(restore_ok(f).command, Some(Command::Card(Job::Read)));
    run_job(f, sd, Job::Read);
    let mut t = 1_000_000u64;
    while matches!(f.state(), State::RestoreOpening { .. }) {
        t += 1_000;
        f.step(Event::Tick { now_us: t }, &mut Live);
    }
}

/// Whether `text` is anywhere in `buffer`.
fn holds(buffer: &[u8], text: &[u8]) -> bool {
    buffer.windows(text.len()).any(|w| w == text)
}

/// A sealed text is wiped when Sign Message is left: after signing, its
/// codes and Home, neither the request buffer nor the document holds it.
/// Opened to be deleted, it is never kept.
#[test]
fn a_sealed_text_is_wiped_when_sign_message_is_left() {
    use kassigner_fw::ui::address as screen;
    let text = b"Meet at the usual place at nine.";
    let password = b"Correct-Horse-9";
    let mut sd = card_with(&[(b"NOTE    TXT", &sealed_text(text, password))]);

    let mut mem = Memory::new();
    {
        let mut f: Flow<'_, 6> = seeded(&mut mem);
        open_text_file(&mut f, &mut sd, password, false);
        assert_eq!(f.state(), State::MessagePreview { page: 0 });
        assert_eq!(f.message_text().as_bytes(), text);
        let on = |t, first| tap_in(screen::zone(SCALE, false, first, t).expect("on the screen"));
        f.step(on(screen::Target::Index, true), &mut Live);
        f.step(on(screen::Target::Address, true), &mut Live);
        message_signed(&mut f);
        f.step(on(screen::Target::Address, true), &mut Live);
        f.step(on(screen::Target::Address, false), &mut Live);
        f.step(reply_card(Card::Wallet), &mut Live);
        assert_eq!(f.state(), State::MessageMode, "two codes ask first");
        f.touch(answer(dialog::Target::Accept));
        while f.state() != State::MessageDone {
            assert!(matches!(f.state(), State::MessageFrames { .. }));
            f.step(on(screen::Target::Address, false), &mut Live);
        }
        f.touch(home_button());
        assert_eq!(f.state(), State::Home);
    }
    assert!(!holds(&mem.request, text), "the request's buffer");
    assert!(!holds(&mem.document, text), "the document");

    let mut mem = Memory::new();
    {
        let mut f: Flow<'_, 6> = seeded(&mut mem);
        open_text_file(&mut f, &mut sd, password, true);
        assert!(
            matches!(f.state(), State::RestoreDelete { .. }),
            "{:?}",
            f.state()
        );
    }
    assert!(!holds(&mem.request, text), "the request's buffer");
    assert!(!holds(&mem.document, text), "the document");
}

/// A sealed seed goes no further than the stack: a sealed text file of
/// twelve words is opened in internal RAM and refused as a seed; nothing
/// reaches the request buffer or the document, in PSRAM.
#[test]
fn a_sealed_seed_is_refused_before_it_reaches_psram() {
    let words: &[u8] = b"abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon about";
    let password = b"Correct-Horse-9";
    let mut sd = card_with(&[(b"NOTE    TXT", &sealed_text(words, password))]);
    let mut mem = Memory::new();
    {
        let mut f: Flow<'_, 6> = seeded(&mut mem);
        open_text_file(&mut f, &mut sd, password, false);
        assert_eq!(
            f.state(),
            State::CardDone {
                job: Job::Read,
                outcome: Outcome::Failed(card::Error::Backup("Seed, not a message")),
            }
        );
    }
    assert!(!holds(&mem.request, b"abandon"), "the request's buffer");
    assert!(!holds(&mem.document, b"abandon"), "the document");
}

/// A plain text file holding a seed is refused and wiped from the request
/// buffer the card read it into.
#[test]
fn a_plain_seed_file_is_refused_and_wiped() {
    let words: &[u8] = b"abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon about";
    let mut sd = card_with(&[(b"NOTE    TXT", words)]);
    let mut mem = Memory::new();
    {
        let mut f: Flow<'_, 6> = seeded(&mut mem);
        open_text_file(&mut f, &mut sd, b"", false);
        assert_eq!(
            f.state(),
            State::CardDone {
                job: Job::Read,
                outcome: Outcome::Failed(card::Error::Backup("Seed, not a message")),
            }
        );
    }
    assert!(!holds(&mem.request, b"abandon"), "the request's buffer");
}

/// A P4's Argon2id-sealed text opens the same way: a text is the message,
/// wiped on leaving, and a seed is refused on the stack.
#[test]
fn a_p4_sealed_text_opens_on_the_stack_too() {
    use kassigner_crypto::container::{seal, Argon2Block, SealKdf, ARGON2_BLOCKS};
    use kassigner_protocol::container::{file_size, Purpose};
    let password = b"Correct-Horse-9";
    let mut blocks = vec![Argon2Block::default(); ARGON2_BLOCKS];
    let mut argon = |text: &[u8]| {
        let mut out = vec![0u8; file_size(text.len())];
        let n = seal(
            Purpose::Text,
            text,
            password,
            &[5; 16],
            &[6; 12],
            SealKdf::Argon2id(&mut blocks),
            &mut out,
        )
        .unwrap();
        out.truncate(n);
        out
    };
    let text: &[u8] = b"Meet at the usual place at nine.";
    let words: &[u8] = b"abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon about";
    for (plain, file) in [(text, argon(text)), (words, argon(words))] {
        let mut sd = card_with(&[(b"NOTE    TXT", &file)]);
        let mut mem = Memory::new();
        mem.kdf = vec![Argon2Block::default(); ARGON2_BLOCKS];
        {
            let mut f: Flow<'_, 6> = seeded(&mut mem);
            open_text_file(&mut f, &mut sd, password, false);
            if plain == words {
                assert_eq!(
                    f.state(),
                    State::CardDone {
                        job: Job::Read,
                        outcome: Outcome::Failed(card::Error::Backup("Seed, not a message")),
                    }
                );
            } else {
                assert_eq!(f.state(), State::MessagePreview { page: 0 });
                assert_eq!(f.message_text().as_bytes(), text);
                f.step(home_button(), &mut Live);
                assert_eq!(f.state(), State::Home);
            }
        }
        assert!(!holds(&mem.request, plain), "the request's buffer");
        assert!(!holds(&mem.document, plain), "the document");
    }
}

/// The home Scan opens a signed message, in one code or `Format::Opaque`
/// frames, to be checked with no wallet; Back goes home. Plain text in
/// frames is refused there.
#[test]
fn the_home_scan_opens_a_signed_message() {
    use kassigner_fw::ui::address as screen;
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    let record = record_of("Scanned at home.");
    for event in [Event::Opaque(&record), Event::Code(&record)] {
        let out = f.step(scan(), &mut Live);
        assert_eq!(out.command, Some(Command::CameraOn));
        let out = f.step(event, &mut Live);
        assert_eq!(out.command, Some(Command::CameraOff));
        assert_eq!(
            out.screen,
            Screen::MessagePreview {
                page: 0,
                pages: 1,
                signed: true,
                live: true
            }
        );
        let on = tap_in(screen::zone(SCALE, false, true, screen::Target::Index).unwrap());
        let out = f.step(on, &mut Live);
        assert_eq!(
            settled(&mut f, out).screen,
            Screen::MessageCheck { valid: Some(true) }
        );
        f.touch(answer(dialog::Target::Cancel));
        f.step(back_button(), &mut Live);
        assert_eq!(f.state(), State::Home);
    }
    f.step(scan(), &mut Live);
    f.step(Event::Opaque(b"just text"), &mut Live);
    assert_eq!(f.state(), State::Refused(Refusal::PlainText));
}

/// A message signed by a testnet address is refused by the home scanner
/// and Sign Message's camera, and nothing of it is kept; the units are
/// mainnet only. The same record with its mainnet address opens.
#[test]
fn a_testnet_signed_message_is_refused() {
    use kassigner_kaspa::address::{decode, encode, Prefix, MAX_ADDRESS_LEN};
    let mainnet = record_of("Signed on testnet.");
    let parts = kassigner_fw::message::read(&mainnet).unwrap();
    let mut payload = [0u8; 40];
    let (_, version, n) = decode(&mainnet[parts.address.clone()], &mut payload).unwrap();
    let mut text = [0u8; MAX_ADDRESS_LEN];
    let len = encode(Prefix::Testnet, version, &payload[..n], &mut text).unwrap();
    assert!(text.starts_with(b"kaspatest:"));
    let mut testnet = vec![0u8; 1024];
    let m = kassigner_fw::message::write(
        &mainnet[parts.text.clone()],
        &text[..len],
        &mainnet[parts.signature.clone()],
        &mut testnet,
    )
    .unwrap();
    testnet.truncate(m);

    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    let over = |f: &mut Flow<'_, 6>| {
        let now_us = f.now_us() + (1 << 32);
        f.step(Event::Tick { now_us }, &mut Live);
        assert_eq!(f.state(), State::Home);
    };
    f.step(scan(), &mut Live);
    let out = f.step(Event::Code(&testnet), &mut Live);
    assert_eq!(out.command, Some(Command::CameraOff));
    assert_eq!(f.state(), State::Refused(Refusal::NotMainnet));
    assert_eq!(f.message_text(), "", "nothing of it kept");
    over(&mut f);
    sign_message(&mut f, 2);
    f.step(Event::Opaque(&testnet), &mut Live);
    assert_eq!(f.state(), State::Refused(Refusal::NotMainnet));
    over(&mut f);
    f.step(scan(), &mut Live);
    f.step(Event::Code(&mainnet), &mut Live);
    assert!(matches!(f.state(), State::MessagePreview { .. }));
}
