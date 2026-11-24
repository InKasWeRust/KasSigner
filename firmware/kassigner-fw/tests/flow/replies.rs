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

//! The reply: bundles, SIGNED TX QR, a reply saved or written over, and a
//! signed transaction opened from the card.

use super::*;

/// **A bundle is reviewed, signed and answered with a bundle**, as a v1.0.7
/// companion sends for an ordinary spend: read as a KSPT is, the reply in
/// the format that came.
#[test]
fn a_bundle_is_signed_and_answered_as_a_bundle() {
    let mut m = Memory::new();
    let spk = p2pk(&x_only(&wallet()));
    let req = bundle_request(
        100_000 * KAS,
        &spk,
        &[(60_000 * KAS, &spk), (30_000 * KAS, &spk)],
    );
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    reply_shown(&mut f);
    assert!(f.reply().starts_with(b"PSKB"), "answered as a bundle");
    assert_eq!(f.reply_format(), kassigner_protocol::frame::Format::Pskb);

    f.step(LEFT, &mut Live);
    assert_eq!(f.state(), State::ReplyDone);
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);
    assert_eq!(
        f.reply_format(),
        kassigner_protocol::frame::Format::Kspt,
        "and the bundle is gone with the request"
    );
}

/// The same request as kassigner.org 1.0.7 writes it, with no `payload` in
/// its global map.
fn as_kassigner_org_107(req: &[u8]) -> Vec<u8> {
    let doc = unhex(core::str::from_utf8(&req[4..]).expect("hex"));
    let doc = String::from_utf8(doc).expect("text");
    let without = doc.replacen(",\"payload\":null", "", 1);
    assert_ne!(without, doc, "it had one to take out");
    format!("PSKB{}", hex(without.as_bytes())).into_bytes()
}

/// **A bundle as kassigner.org 1.0.7 writes it, with no `payload`, is
/// signed**: rusty-kaspa 2.1.0's reader requires one, so the device puts in
/// upstream's `null` first, and the reply carries it.
#[test]
fn a_bundle_as_kassigner_org_107_writes_it_is_signed() {
    let mut m = Memory::new();
    let spk = p2pk(&x_only(&wallet()));
    let req = as_kassigner_org_107(&bundle_request(
        100_000 * KAS,
        &spk,
        &[(60_000 * KAS, &spk), (30_000 * KAS, &spk)],
    ));
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    reply_shown(&mut f);
    let reply = f.reply();
    assert!(reply.starts_with(b"PSKB"), "answered as a bundle");
    let doc = unhex(core::str::from_utf8(&reply[4..]).expect("hex"));
    let doc = String::from_utf8(doc).expect("text");
    assert!(
        doc.starts_with("[{\"global\":{\"payload\":null,\"version\":0,"),
        "the reply carries the payload filled in: {}",
        &doc[..60]
    );
}

/// **A reply is shown as SIGNED TX QR chooses, frames asking Auto Cycle or
/// Manual**: Wallet in version-9 frames every `WALLET_FRAME_US`, KasSigner
/// in more version-3 frames every `KASSIGNER_FRAME_US`; Manual a tap at a
/// time, past the last SIGNED TX. Back from SIGNED TX QR is done with the
/// reply, wiped.
#[test]
fn a_reply_is_shown_as_signed_tx_qr_chooses() {
    use kassigner_fw::limits::{KASSIGNER_FRAME_US, WALLET_FRAME_US};
    let spk = p2pk(&x_only(&wallet()));
    let req = bundle_request(
        100_000 * KAS,
        &spk,
        &[(60_000 * KAS, &spk), (30_000 * KAS, &spk)],
    );
    fn signed<'m>(m: &'m mut Memory, req: &[u8]) -> Flow<'m, 1> {
        let mut f = reviewing(m, req);
        let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
            Screen::Page { pages, .. } => pages,
            other => panic!("{other:?}"),
        };
        for _ in 1..pages {
            arrow(&mut f, RIGHT);
        }
        let out = confirmed(&mut f);
        assert_eq!(
            out.screen,
            Screen::ReplyFormat,
            "the first screen after signing"
        );
        f
    }

    // Wallet, Manual.
    let mut m = Memory::new();
    let mut f = signed(&mut m, &req);
    let (wallet, unit) = (f.reply_codes(true), f.reply_codes(false));
    assert!(wallet > 1, "a bundle's reply is in frames");
    assert!(unit > wallet, "version-3 frames are more");
    assert!(f.reply_fits(true) && f.reply_fits(false));
    f.step(reply_card(Card::Wallet), &mut Live);
    assert_eq!(f.state(), State::ReplyMode);
    assert_eq!(usize::from(f.reply_frames()), wallet);
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::Showing { frame: 0 });
    for i in 0..f.reply_frames() {
        assert_eq!(f.reply_code(i).unwrap().size, 53, "frame {i} at version 9");
    }
    f.step(Event::Tick { now_us: 60_000_000 }, &mut Live);
    assert_eq!(f.state(), State::Showing { frame: 0 }, "the clock waits");
    for next in 1..f.reply_frames() {
        f.step(LEFT, &mut Live);
        assert_eq!(f.state(), State::Showing { frame: next });
    }
    f.step(LEFT, &mut Live);
    assert_eq!(f.state(), State::ReplyDone, "past the last frame");
    f.touch(answer(dialog::Target::Nav(Nav::Back)));
    assert_eq!(f.state(), State::ReplyFormat, "Back is SIGNED TX QR");

    // Wallet's frames turn faster than KasSigner's.
    for (card, every) in [
        (Card::Wallet, WALLET_FRAME_US),
        (Card::KasSigner, KASSIGNER_FRAME_US),
    ] {
        let mut m = Memory::new();
        let mut f = signed(&mut m, &req);
        f.step(reply_card(card), &mut Live);
        f.touch(answer(dialog::Target::Cancel));
        assert_eq!(f.state(), State::Showing { frame: 0 });
        f.step(Event::Tick { now_us: every }, &mut Live);
        assert_eq!(f.state(), State::Showing { frame: 0 }, "not yet");
        f.step(Event::Tick { now_us: 1 + every }, &mut Live);
        assert_eq!(f.state(), State::Showing { frame: 1 }, "its turn");
    }

    // KasSigner's frames.
    let mut m = Memory::new();
    let mut f = signed(&mut m, &req);
    f.step(reply_card(Card::KasSigner), &mut Live);
    assert_eq!(usize::from(f.reply_frames()), unit);
    for i in 0..f.reply_frames() {
        assert!(
            f.reply_code(i).unwrap().size <= 29,
            "frame {i} at version 3"
        );
    }

    // Back on the question is SIGNED TX QR; Back there is done with it.
    f.touch(answer(dialog::Target::Nav(Nav::Back)));
    assert_eq!(f.state(), State::ReplyFormat);
    assert!(!f.reply().is_empty(), "still held");
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
    assert!(f.reply().is_empty(), "wiped");
}

/// **SIGNED TX saves the reply as `TXnnnn.KSP`** (v1.0.7's name), plain or
/// sealed under the KSPT purpose, then returns, the reply held, even after a
/// failed save. Home lets it go.
#[test]
fn signed_tx_saves_the_reply_plain_or_sealed() {
    use kassigner_crypto::container::open;
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{do_format_fat32, find_file_in_root, mount_fat32, read_file};
    use kassigner_fw::card::{self, Job, Kind, Outcome};
    use kassigner_protocol::container::Purpose;

    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let job = |f: &mut Flow<'_, 1>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, job: Job| {
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
    let mut now = 1u64;
    let mut later = |f: &mut Flow<'_, 1>| {
        now += 10_000_000;
        f.step(Event::Tick { now_us: now }, &mut Live);
    };

    let mut m = Memory::new();
    let req = ours();
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    reply_shown(&mut f);
    let reply = f.reply().to_vec();
    while f.state() != State::ReplyDone {
        f.step(LEFT, &mut Live);
    }

    // Plain.
    assert_eq!(
        f.touch(answer(dialog::Target::Cancel)).command,
        Some(Command::Card(Job::NextName))
    );
    job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "TX0001");
    let State::BackupName { page } = f.state() else {
        panic!("{:?}", f.state())
    };
    f.step(key(page, keyboard::Key::Ok), &mut Live);
    job(&mut f, &mut sd, Job::Exists);
    assert_eq!(f.state(), State::KpubEncrypt, "ENCRYPT FILE? first");
    assert_eq!(
        f.touch(answer(dialog::Target::Accept)).command,
        Some(Command::Card(Job::Write))
    );
    job(&mut f, &mut sd, Job::Write);
    assert_eq!(f.saved_text(), "!! Signed TX Saved !!");
    assert_eq!(file(&mut sd, b"TX0001  KSP"), reply);
    later(&mut f);
    assert_eq!(f.state(), State::ReplyDone, "back to SIGNED TX");
    assert_eq!(f.reply(), &reply[..], "still held");

    // Sealed, the next number.
    f.touch(answer(dialog::Target::Cancel));
    job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "TX0002");
    let State::BackupName { page } = f.state() else {
        panic!("{:?}", f.state())
    };
    f.step(key(page, keyboard::Key::Ok), &mut Live);
    job(&mut f, &mut sd, Job::Exists);
    f.touch(answer(dialog::Target::Cancel));
    let password = b"Correct-Horse-9";
    for again in [false, true] {
        restore_type_password(&mut f, password, again);
    }
    while matches!(f.state(), State::BackupSealing { .. }) {
        f.step(Event::Tick { now_us: 1 }, &mut Live);
    }
    assert_eq!(f.state(), State::CardBusy(Job::Write));
    job(&mut f, &mut sd, Job::Write);
    later(&mut f);
    assert_eq!(f.state(), State::ReplyDone);
    let sealed = file(&mut sd, b"TX0002  KSP");
    let mut plain = vec![0u8; sealed.len()];
    let opened = open(&sealed, password, &mut plain, None).unwrap();
    assert_eq!(opened.purpose, Purpose::Kspt);
    assert_eq!(&plain[..opened.len], &reply[..]);

    // Back to QR: the codes again, from the first.
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::Showing { frame: 0 });
    assert_eq!(f.reply(), &reply[..]);
    while f.state() != State::ReplyDone {
        f.step(LEFT, &mut Live);
    }

    // No card: the save fails, then SIGNED TX again, the reply held.
    f.touch(answer(dialog::Target::Cancel));
    f.step(Event::Card(Outcome::Absent), &mut Live);
    assert_eq!(
        f.state(),
        State::CardDone {
            job: Job::NextName,
            outcome: Outcome::Absent
        }
    );
    assert_eq!(
        f.card_said().failed,
        kassigner_fw::ui::sd_card::TX_SAVE_FAILED
    );
    later(&mut f);
    assert_eq!(f.state(), State::ReplyDone);
    assert_eq!(f.reply(), &reply[..]);

    // Home lets it go.
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);
    assert!(f.reply().is_empty());
    assert!(f.page(|_| ()).is_none());
}

/// **A sealed signed transaction is written over only under its password
/// too**, checked in the request's buffer (the file is larger than any
/// backup), the reply held untouched. A file that large claiming to hold a
/// seed is not opened.
#[test]
fn a_sealed_reply_is_written_over_only_under_its_own_password() {
    use kassigner_crypto::backup::FILE_MAX;
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_fw::card::Error;
    use kassigner_fw::flow::Typing;
    use kassigner_protocol::container::{file_size, Purpose};

    let password = b"Correct-Horse-9";
    let fake = {
        let mut out = vec![0u8; file_size(400)];
        seal(
            Purpose::Seed,
            &[0x41; 400],
            password,
            &[5; 16],
            &[6; 12],
            SealKdf::Pbkdf2Sha256,
            &mut out,
        )
        .unwrap();
        out
    };
    let mut sd = card_with(&[(b"TX0009  KSP", &fake)]);
    let mut m = Memory::new();
    let req = ours();
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    reply_shown(&mut f);
    let reply = f.reply().to_vec();
    while f.state() != State::ReplyDone {
        f.step(LEFT, &mut Live);
    }
    let mut t = 1u64;

    // Sealed as TX0001.
    f.touch(answer(dialog::Target::Cancel));
    run_job(&mut f, &mut sd, Job::NextName);
    name_as(&mut f, &mut sd, b"TX0001");
    assert_eq!(f.state(), State::KpubEncrypt);
    f.touch(answer(dialog::Target::Cancel));
    for _ in 0..2 {
        type_on(&mut f, password);
        press(&mut f, keyboard::Key::Ok);
    }
    while matches!(f.state(), State::BackupSealing { .. }) {
        f.step(Event::Tick { now_us: t }, &mut Live);
    }
    run_job(&mut f, &mut sd, Job::Write);
    let sealed = on_card(&mut sd, b"TX0001  KSP");
    assert!(sealed.len() > FILE_MAX, "larger than any backup");
    t += 10_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    assert_eq!(f.state(), State::ReplyDone);

    // Again as TX0001: its password asked; a wrong one writes nothing.
    f.touch(answer(dialog::Target::Cancel));
    run_job(&mut f, &mut sd, Job::NextName);
    name_as(&mut f, &mut sd, b"TX0001");
    assert!(matches!(
        overwrite(&mut f, &mut sd),
        Screen::Keyboard {
            typing: Typing::OverwritePassword,
            ..
        }
    ));
    type_on(&mut f, b"Wrong-Horse-99");
    press(&mut f, keyboard::Key::Ok);
    assert_eq!(
        opened_at(&mut f, &mut t),
        Screen::CardDone {
            job: Job::Write,
            outcome: Outcome::Failed(Error::Backup("Wrong password or damaged file"))
        }
    );
    assert_eq!(on_card(&mut sd, b"TX0001  KSP"), sealed);
    assert_eq!(f.reply(), &reply[..], "the reply is held as it was");

    // The right one: ENCRYPT FILE? as for a free name; plain, the reply.
    t += 10_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    assert_eq!(f.typed().0, "TX0001");
    press(&mut f, keyboard::Key::Ok);
    run_job(&mut f, &mut sd, Job::Exists);
    overwrite(&mut f, &mut sd);
    type_on(&mut f, password);
    press(&mut f, keyboard::Key::Ok);
    opened_at(&mut f, &mut t);
    assert_eq!(f.state(), State::KpubEncrypt);
    assert_eq!(f.reply(), &reply[..]);
    f.touch(answer(dialog::Target::Accept));
    run_job(&mut f, &mut sd, Job::Write);
    assert_eq!(on_card(&mut sd, b"TX0001  KSP"), reply);
    t += 10_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    assert_eq!(f.state(), State::ReplyDone);

    // A seed's container too large for a backup: not opened.
    f.touch(answer(dialog::Target::Cancel));
    run_job(&mut f, &mut sd, Job::NextName);
    name_as(&mut f, &mut sd, b"TX0009");
    assert_eq!(
        overwrite(&mut f, &mut sd),
        Screen::CardDone {
            job: Job::Write,
            outcome: Outcome::Failed(Error::Backup("File error"))
        }
    );
    assert_eq!(on_card(&mut sd, b"TX0009  KSP"), fake);
}

/// **A bundle paying out more than it spends is refused before review.**
#[test]
fn a_bundle_paying_more_than_it_spends_is_refused() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    let spk = p2pk(&x_only(&wallet()));
    let req = bundle_request(100_000, &spk, &[(190_000, &spk)]);
    deliver(&mut f, &req);
    assert!(matches!(f.state(), State::Refused(_)), "{:?}", f.state());
}

/// **A bundle with no outputs is refused before review**, as a KSPT is:
/// everything its inputs hold would go to the fee. Consensus allows one; no
/// wallet makes one for a payment.
#[test]
fn a_bundle_with_no_outputs_is_refused_before_review() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    let spk = p2pk(&x_only(&wallet()));
    let req = bundle_request(100_000 * KAS, &spk, &[]);
    deliver(&mut f, &req);
    let State::Refused(why) = f.state() else {
        panic!("{:?}", f.state())
    };
    assert_eq!(why.words(), ("Cannot review", "It has no outputs"));
    assert!(f.page(|_| ()).is_none(), "no review");
    assert!(f.reply().is_empty());
}

/// **A bundle is wiped when its request goes.** Declined: its decoded
/// document and scripts are zero. Signed and let go: the reply, its
/// generated members and its bundle read back too.
#[test]
fn a_bundle_is_wiped_when_its_request_goes() {
    let spk = p2pk(&x_only(&wallet()));
    let req = bundle_request(
        100_000 * KAS,
        &spk,
        &[(60_000 * KAS, &spk), (30_000 * KAS, &spk)],
    );
    let zero = |b: &[u8]| b.iter().all(|&x| x == 0);
    let to_last = |f: &mut Flow<'_, 1>| {
        let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
            Screen::Page { pages, .. } => pages,
            other => panic!("{other:?}"),
        };
        for _ in 1..pages {
            arrow(f, RIGHT);
        }
    };

    let mut m = Memory::new();
    {
        let mut f = reviewing(&mut m, &req);
        to_last(&mut f);
        arrow(&mut f, RIGHT);
        f.touch(on_confirm(review::Target::Cancel));
        assert_eq!(f.state(), State::Refused(Refusal::Declined));
        f.step(Event::Tick { now_us: 1 << 40 }, &mut Live);
        assert_eq!(f.state(), State::Home);
    }
    assert!(zero(&m.request), "the request");
    assert!(zero(&m.document), "the bundle's document");
    assert!(zero(&m.scripts), "its scripts");
    assert!(zero(&m.redeem), "the redeem scratch");

    let mut m = Memory::new();
    {
        let mut f = reviewing(&mut m, &req);
        to_last(&mut f);
        confirmed(&mut f);
        reply_shown(&mut f);
        f.step(LEFT, &mut Live);
        f.touch(home_button());
        assert_eq!(f.state(), State::Home);
    }
    assert!(zero(&m.request), "the request");
    assert!(zero(&m.reply), "the reply");
    assert!(zero(&m.document), "the bundle's document");
    assert!(zero(&m.scripts), "its scripts");
    assert!(zero(&m.text), "the reply's generated members");
    assert!(zero(&m.edited), "the reply's bundle read back");
}

/// **A transaction this seed signed already opens from the card to be shown
/// again**, so a saved send can be broadcast later: its review, then SIGNED
/// TX QR with the reply as written, nothing signed again. Scanned, it is
/// refused as already signed.
#[test]
fn a_transaction_signed_already_opens_from_the_card_to_be_shown() {
    for request in [
        &corpus!("site/kspt_send_1in.bin")[..],
        &corpus!("site/pskb_send.bin")[..],
    ] {
        signed_already_opens(request);
    }
}

/// [`a_transaction_signed_already_opens_from_the_card_to_be_shown`] for one
/// request.
fn signed_already_opens(request: &[u8]) {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);

    // Signed here, as a send is.
    f.step(scan(), &mut Live);
    deliver(&mut f, request);
    assert_eq!(f.state(), State::Reviewing);
    walk_review(&mut f);
    confirmed(&mut f);
    assert_eq!(f.state(), State::ReplyFormat);
    let signed = f.reply().to_vec();
    let signers = f.reply_signers();
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);

    // Import from SD, Transaction, the reply's file opened.
    let mut sd = card_with(&[(b"TX0001  KSP", &signed)]);
    let open = |f: &mut Flow<'_, 6>, sd: &mut Sd| open_from_card(f, sd, signed.len());
    open(&mut f, &mut sd);
    assert_eq!(f.state(), State::Reviewing, "its review, not refused");
    walk_review(&mut f);
    arrow(&mut f, RIGHT);
    assert_eq!(
        f.state(),
        State::ReplyFormat,
        "SIGNED TX QR, no CONFIRM SEND?"
    );
    assert_eq!(f.reply(), &signed[..], "the reply as it was written");
    assert_eq!(f.reply_signers(), signers);
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);

    // Left from its review: home, not declined.
    open(&mut f, &mut sd);
    assert_eq!(f.state(), State::Reviewing);
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);

    // Scanned: refused.
    f.step(scan(), &mut Live);
    deliver(&mut f, &signed);
    assert!(matches!(
        f.state(),
        State::Refused(Refusal::NotSigned(
            kassigner_fw::reply::Error::AlreadySigned { .. }
        ))
    ));
}

/// TX REVIEW's pages walked to the last, from its first.
fn walk_review(f: &mut Flow<'_, 6>) {
    let pages = match f.step(Event::Tick { now_us: f.now_us() }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(f, RIGHT);
    }
}

/// Import from SD, Transaction: the card's first file opened with no
/// password, through CHECKING (`len` bytes), to whatever follows.
fn open_from_card(f: &mut Flow<'_, 6>, sd: &mut Sd, len: usize) {
    use kassigner_fw::ui::backup::{self, pick_zone, Pick};

    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(backup::zone(SCALE, backup::Target::Import).unwrap()),
        &mut Live,
    );
    f.step(item(&menu::IMPORT, 0), &mut Live);
    f.step(item(&menu::IMPORT_SD, 1), &mut Live);
    run_job(f, sd, Job::ListText);
    let row = tap_in(pick_zone(SCALE, f.backups().len(), 0, Pick::Row(0)).unwrap());
    f.step(row, &mut Live);
    restore_type(f, b"");
    restore_ok(f);
    run_job(f, sd, Job::Read);
    let mut now_us = f.now_us();
    while matches!(f.state(), State::RestoreOpening { .. }) {
        now_us += 1_000;
        f.step(Event::Tick { now_us }, &mut Live);
    }
    assert_eq!(f.state(), State::Checking { len, card: true });
    f.step(Event::Tick { now_us: now_us + 1 }, &mut Live);
}

/// A file of the SDK's `spec/vectors/v110/sdk/`, a unit's replies among them.
macro_rules! sdk_vector {
    ($name:literal) => {
        &include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/v110/sdk/",
            $name
        ))[..]
    };
}

/// **A signed transaction opens from the card on any unit, to be shown**:
/// anyone may broadcast what someone else signed. The SDK's replies open
/// with no seed or another seed in use; a partly signed one goes on to be
/// signed by a cosigner seed. A changed signature is refused, and an
/// unsigned request still asks for a seed.
#[test]
fn a_signed_transaction_opens_from_the_card_on_any_unit() {
    let shown = |f: &mut Flow<'_, 6>, file: &[u8], signers: Option<(usize, usize)>| {
        let mut sd = card_with(&[(b"TX0001  KSP", file)]);
        open_from_card(f, &mut sd, file.len());
        assert_eq!(f.state(), State::Reviewing, "its review, not refused");
        walk_review(f);
        arrow(f, RIGHT);
        assert_eq!(f.state(), State::ReplyFormat, "SIGNED TX QR");
        assert_eq!(f.reply(), file, "the file as it was");
        assert_eq!(f.reply_signers().map(|s| (s.present, s.required)), signers);
        f.touch(home_button());
        assert_eq!(f.state(), State::Home);
    };
    let single = sdk_vector!("single.reply.abandon12");
    for (file, signers) in [
        (single, None),
        (sdk_vector!("pskb_send.reply.abandon12"), None),
        (sdk_vector!("multisig.reply.abandon12"), Some((1, 2))),
        (sdk_vector!("pskb_multisig.reply.zoo12"), Some((1, 2))),
    ] {
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        shown(&mut f, file, signers);
    }

    // Another seed, zoo 12: the single-key send, not its, still shown; the
    // 2-of-3's copy abandon 12 signed is its to sign.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/zoo12.standard"));
    f.step(home_button(), &mut Live);
    shown(&mut f, single, None);
    let partly = sdk_vector!("multisig.reply.abandon12");
    let mut sd = card_with(&[(b"TX0001  KSP", partly)]);
    open_from_card(&mut f, &mut sd, partly.len());
    assert_eq!(f.state(), State::Reviewing);
    walk_review(&mut f);
    arrow(&mut f, RIGHT);
    assert_eq!(
        f.state(),
        State::Confirming,
        "CONFIRM SEND?: zoo 12 signs it"
    );
    f.touch(home_button());

    // No seed: a changed signature refused; nothing signed, a seed asked
    // for; the camera's path unchanged. A refusal holds for its time.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let over = |f: &mut Flow<'_, 6>| {
        let now_us = f.now_us() + (1 << 32);
        f.step(Event::Tick { now_us }, &mut Live);
        assert_eq!(f.state(), State::Home);
    };
    let request = sdk_vector!("single.request");
    let at = (0..request.len())
        .find(|&k| request[k] != single[k])
        .unwrap();
    let mut forged = single.to_vec();
    forged[at + 10] ^= 1;
    let mut sd = card_with(&[(b"TX0001  KSP", &forged)]);
    open_from_card(&mut f, &mut sd, forged.len());
    assert!(matches!(
        f.state(),
        State::Refused(Refusal::NotSigned(
            kassigner_fw::reply::Error::BadSignature { .. }
        ))
    ));
    over(&mut f);
    let mut sd = card_with(&[(b"TX0001  KSP", request)]);
    open_from_card(&mut f, &mut sd, request.len());
    assert_eq!(f.state(), State::Refused(Refusal::NoWallet));
    over(&mut f);
    f.step(scan(), &mut Live);
    deliver(&mut f, single);
    assert_eq!(f.state(), State::Refused(Refusal::NoWallet));
}

/// **A signed transaction with an input no signature covers is not shown**:
/// that input's amount is a number nothing checks, so In and Fee would be
/// too. The SDK's two-input send with its first input signed, its second
/// left unsigned and its 2 KAS written as 900, as a KSPT and as a bundle:
/// refused with no seed in use, and with the seed that signed the first. The
/// same files whole are shown, and a multisig short of its threshold still
/// is: one signature on an input covers its amount.
#[test]
fn a_signed_transaction_with_an_unsigned_input_is_not_shown() {
    // The KSPT: the request with input 1's amount made up, and input 0's
    // signature from the unit's own reply, which covers no other amount.
    let request = sdk_vector!("single.request");
    let reply = sdk_vector!("single.reply.abandon12");
    let profile = P;
    let signed = kspt::parse(reply, &profile).unwrap();
    let sig = signed.inputs().next().unwrap().signatures().next().unwrap();
    let mut one = InputSignature::EMPTY;
    one.input = 0;
    one.pubkey_pos = sig.pubkey_pos;
    one.sighash_type = sig.sighash_type;
    one.signature.copy_from_slice(sig.bytes);
    let real = (2 * KAS).to_le_bytes();
    assert_eq!(request.windows(8).filter(|w| *w == real).count(), 1);
    let at = request.windows(8).position(|w| w == real).unwrap();
    let mut made_up = request.to_vec();
    made_up[at..at + 8].copy_from_slice(&(900 * KAS).to_le_bytes());
    let k = kspt::parse(&made_up, &profile).unwrap();
    let (mut ins, mut outs) = ([blank_in(); 8], [blank_out(); 8]);
    let (ni, no) = kspt_tx::fill(&k, &mut ins, &mut outs).unwrap();
    let tx = kspt_tx::build(&k, &ins[..ni], &outs[..no]);
    let mut kspt_file = vec![0u8; 4096];
    let n = kspt::write(&k, &tx, &[one], &profile, &mut kspt_file).unwrap();
    kspt_file.truncate(n);
    let read = kspt::parse(&kspt_file, &profile).unwrap();
    assert_eq!(
        read.inputs()
            .map(|i| i.signatures().count())
            .collect::<Vec<_>>(),
        [1, 0]
    );

    // The bundle: the unit's reply with input 1's signature taken out and
    // its amount made up.
    let whole = sdk_vector!("single.bundle.reply.abandon12");
    let text = String::from_utf8(unhex(core::str::from_utf8(&whole[4..]).unwrap())).unwrap();
    let second = text.rfind("\"partialSigs\":{").unwrap();
    let end = second + text[second..].find("}}").unwrap() + 2;
    let text = format!("{}\"partialSigs\":{{}}{}", &text[..second], &text[end..]);
    assert_eq!(text.matches("\"amount\":200000000,").count(), 1);
    let text = text.replacen("\"amount\":200000000,", "\"amount\":90000000000,", 1);
    assert_eq!(
        text.matches("\"schnorr\":").count(),
        1,
        "one signature left"
    );
    let bundle_file = [b"PSKB", hex(text.as_bytes()).as_bytes()].concat();

    let why = Refusal::NotSigned(kassigner_fw::reply::Error::InputUnsigned { input: 1 });
    assert_eq!(
        why.words(),
        ("Signing failed", "An input has no signature"),
        "the screen's two lines"
    );
    let refused = State::Refused(why);
    for seed in [None, Some(corpus!("seedqr/abandon12.standard"))] {
        for (file, entire) in [(&kspt_file, reply), (&bundle_file, whole)] {
            let mut m = Memory::new();
            let mut f: Flow<'_, 6> = booted(&mut m, &[]);
            if let Some(seed) = seed {
                load(&mut f, seed);
                f.step(home_button(), &mut Live);
            }
            let mut sd = card_with(&[(b"TX0001  KSP", file)]);
            open_from_card(&mut f, &mut sd, file.len());
            assert_eq!(f.state(), refused, "seed in use: {}", seed.is_some());
            // The file as the unit signed it, every input covered: shown.
            let now_us = f.now_us() + (1 << 32);
            f.step(Event::Tick { now_us }, &mut Live);
            assert_eq!(f.state(), State::Home);
            let mut sd = card_with(&[(b"TX0001  KSP", entire)]);
            open_from_card(&mut f, &mut sd, entire.len());
            assert_eq!(f.state(), State::Reviewing, "the whole file is shown");
        }
    }
    // A multisig with one of its two signatures on its input: shown.
    let partly = sdk_vector!("multisig.reply.abandon12");
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let mut sd = card_with(&[(b"TX0001  KSP", partly)]);
    open_from_card(&mut f, &mut sd, partly.len());
    assert_eq!(f.state(), State::Reviewing);
}

/// **Import from SD's Transaction: a request from the card, reviewed as a
/// scanned one.** SELECT FILE lists only `.KSP` files, plain or sealed under
/// the KSPT purpose. A sealed one opens only under its own password, a
/// `.KSP` that is no request is refused as the camera refuses it, and an
/// empty card is said. Failures are titled TX Load Failed.
#[test]
fn a_transaction_is_read_from_the_card() {
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_fw::ui::backup::{self, pick_zone, Pick};
    use kassigner_fw::ui::review::Shown;
    use kassigner_protocol::container::{file_size, Purpose};

    let request = corpus!("site/kspt_send_1in.bin");
    let password = b"Correct-Horse-9";
    let mut sealed = vec![0u8; file_size(request.len())];
    let n = seal(
        Purpose::Kspt,
        request,
        password,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut sealed,
    )
    .unwrap();
    sealed.truncate(n);
    let mut sd = card_with(&[
        (b"TX0001  KSP", request),
        (b"TX0002  KSP", &sealed),
        (b"TX0003  KSP", b"hello"),
        (b"NOTE    TXT", b"Sign me."),
    ]);

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);

    // TX REVIEW's first page, and home from it.
    let summary = |f: &Flow<'_, 6>| {
        f.review(|s| match *s {
            Shown::Summary {
                totals,
                inputs,
                outputs,
                group,
                ..
            } => (totals, inputs, outputs, group),
            _ => panic!("TX REVIEW first"),
        })
        .unwrap()
    };
    let home = |f: &mut Flow<'_, 6>| {
        f.touch(home_button());
        let now_us = f.now_us() + REFUSED_US + 1;
        f.step(Event::Tick { now_us }, &mut Live);
        assert_eq!(f.state(), State::Home);
    };
    // Import from SD, Transaction, the card listed.
    let list = |f: &mut Flow<'_, 6>, sd: &mut Sd| {
        f.step(card(2), &mut Live);
        f.step(item(&menu::TOOLS, 1), &mut Live);
        f.step(
            tap_in(backup::zone(SCALE, backup::Target::Import).unwrap()),
            &mut Live,
        );
        f.step(item(&menu::IMPORT, 0), &mut Live);
        let out = f.step(item(&menu::IMPORT_SD, 1), &mut Live);
        assert_eq!(out.command, Some(Command::Card(Job::ListText)));
        run_job(f, sd, Job::ListText)
    };
    // A file's row, `typed` as its password, the file read and opened as
    // far as it goes.
    let opened = |f: &mut Flow<'_, 6>, sd: &mut Sd, name: &[u8; 11], typed: &[u8]| {
        let i = f.backups().iter().position(|b| b == name).unwrap();
        let row = tap_in(pick_zone(SCALE, f.backups().len(), 0, Pick::Row(i)).unwrap());
        f.step(row, &mut Live);
        restore_type(f, typed);
        assert_eq!(restore_ok(f).command, Some(Command::Card(Job::Read)));
        run_job(f, sd, Job::Read);
        let mut now_us = f.now_us();
        while matches!(f.state(), State::RestoreOpening { .. }) {
            now_us += 1_000;
            f.step(Event::Tick { now_us }, &mut Live);
        }
        // CHECKING, as from the camera; the next tick reads the request.
        if matches!(f.state(), State::Checking { .. }) {
            now_us += 1_000;
            f.step(Event::Tick { now_us }, &mut Live);
        }
    };
    // Why it failed, under TX Load Failed, then the list again.
    let failed = |f: &mut Flow<'_, 6>, why: &'static str| {
        let outcome = Outcome::Failed(card::Error::Backup(why));
        assert_eq!(
            f.state(),
            State::CardDone {
                job: Job::Read,
                outcome
            }
        );
        assert_eq!(f.card_said().failed, sd_card::TX_LOAD_FAILED);
        let now_us = f.now_us() + card_done_us(Job::Read, outcome) + 1;
        f.step(Event::Tick { now_us }, &mut Live);
        assert_eq!(f.state(), State::RestoreList { page: 0 });
    };

    // From the camera.
    f.step(scan(), &mut Live);
    deliver(&mut f, request);
    assert_eq!(f.state(), State::Reviewing);
    let scanned = summary(&f);
    home(&mut f);

    // The card's `.KSP` files, and only those.
    list(&mut f, &mut sd);
    assert_eq!(f.state(), State::RestoreList { page: 0 });
    assert_eq!(f.list_title(), "SELECT FILE");
    assert_eq!(
        f.backups(),
        &[*b"TX0001  KSP", *b"TX0002  KSP", *b"TX0003  KSP"]
    );

    // Plain, nothing typed: the review, as from the camera.
    opened(&mut f, &mut sd, b"TX0001  KSP", b"");
    assert_eq!(f.state(), State::Reviewing);
    assert_eq!(summary(&f), scanned);
    home(&mut f);

    // Sealed, its password: the same.
    list(&mut f, &mut sd);
    opened(&mut f, &mut sd, b"TX0002  KSP", password);
    assert_eq!(f.state(), State::Reviewing);
    assert_eq!(summary(&f), scanned);
    home(&mut f);

    // Sealed, another password; plain, a password typed.
    list(&mut f, &mut sd);
    opened(&mut f, &mut sd, b"TX0002  KSP", b"Correct-Horse-8");
    failed(&mut f, "Wrong password or damaged file");
    opened(&mut f, &mut sd, b"TX0001  KSP", password);
    failed(&mut f, "Wrong password or damaged file");

    // No request in it: refused as the camera refuses one.
    opened(&mut f, &mut sd, b"TX0003  KSP", b"");
    assert_eq!(f.state(), State::Refused(Refusal::NotARequest));
    home(&mut f);

    // Sign Message's list of the same card: its text alone.
    sign_message(&mut f, 1);
    run_job(&mut f, &mut sd, Job::ListText);
    assert_eq!(f.backups(), &[*b"NOTE    TXT"]);
    home(&mut f);

    // An empty card says so, then IMPORT FROM SD.
    let mut empty = card_with(&[]);
    list(&mut f, &mut empty);
    assert_eq!(f.card_said().empty, ("No .KSP files found", ""));
    let now_us = f.now_us() + 10_000_000;
    f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::ImportSd,
            page: 0
        }
    );
}
