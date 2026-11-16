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

//! Signing: a request scanned, searched for its keys, reviewed page by page,
//! and nothing but CONFIRM SEND signing it.

use super::*;

/// One scanner: a request with no seed in use is refused.
#[test]
fn a_request_with_no_seed_is_refused() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    let req = ours();
    deliver(&mut f, &req);
    assert_eq!(f.state(), State::Refused(Refusal::NoWallet));
}

/// **A request read whole shows CHECKING before it is planned**: only the
/// next tick plans it and opens the review, not a tap nor the idle wipe. A
/// code that is no request is refused at once.
#[test]
fn a_request_read_whole_shows_checking_before_it_is_planned() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    let req = ours();
    let out = f.step(Event::Payload(&req), &mut Live);
    assert_eq!(
        (out.screen, out.command),
        (Screen::Checking, Some(Command::CameraOff))
    );
    assert_eq!(
        f.state(),
        State::Checking {
            len: req.len(),
            card: false
        }
    );
    for e in [GOOD, RIGHT, Event::Payload(&req)] {
        let out = f.step(e, &mut Live);
        assert_eq!(
            (out.screen, f.state()),
            (
                Screen::Checking,
                State::Checking {
                    len: req.len(),
                    card: false
                }
            ),
            "{e:?}"
        );
    }
    let late = f.now_us() + IDLE_WIPE_US + 1;
    let out = f.step(Event::Tick { now_us: late }, &mut Live);
    assert_eq!(f.state(), State::Reviewing);
    assert!(matches!(out.screen, Screen::Page { index: 0, .. }));

    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    let out = f.step(Event::Payload(b"not a request"), &mut Live);
    assert_eq!(f.state(), State::Refused(Refusal::NotARequest));
    assert_ne!(out.screen, Screen::Checking);
}

/// Only the back button leaves a scan, not the viewfinder.
#[test]
fn a_scan_is_left_by_the_back_button() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    let out = f.step(tap_in(Zone::new(160, 120, 1, 1)), &mut Live);
    assert_eq!(f.state(), State::Scanning, "a tap on the viewfinder");
    assert_eq!(out.command, None);
    let out = f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
    assert_eq!(out.command, Some(Command::CameraOff));
}

// ── Signing ─────────────────────────────────────────────────────────────────

/// The Scan card starts the camera; the back button goes home.
#[test]
fn the_scan_card_scans_and_a_scan_can_be_cancelled() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    assert_eq!(
        f.step(Event::Tick { now_us: 1 }, &mut Live).screen,
        Screen::Home
    );
    let out = f.step(scan(), &mut Live);
    assert_eq!(f.state(), State::Scanning);
    assert_eq!(out.command, Some(Command::CameraOn));
    assert_eq!(
        out.screen,
        Screen::Scanning {
            have: 0,
            total: 0,
            received: 0,
            hint: false
        }
    );
    let out = f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
    assert_eq!(out.command, Some(Command::CameraOff));
}

/// A payload that is not a request is refused, then the unit goes home.
#[test]
fn a_payload_that_is_not_a_request_is_refused() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    let out = deliver(&mut f, b"not a request");
    assert_eq!(f.state(), State::Refused(Refusal::NotARequest));
    assert_eq!(out.command, Some(Command::CameraOff));
    assert_eq!(out.screen, Screen::Refused(Refusal::NotARequest));
    f.step(
        Event::Tick {
            now_us: VERIFIED_US + REFUSED_US - 1,
        },
        &mut Live,
    );
    assert_eq!(
        f.state(),
        State::Refused(Refusal::NotARequest),
        "a refusal holds for its time; the clock was at VERIFIED_US when it began"
    );
    f.step(Event::Tick { now_us: 1 << 40 }, &mut Live);
    assert_eq!(f.state(), State::Home);
}

/// The pages are walked with taps; CONFIRM SEND? comes only past the last.
#[test]
fn the_review_walks_its_pages_and_offers_a_decision_only_at_the_end() {
    let mut m = Memory::new();
    let req = ours();
    let mut f = reviewing(&mut m, &req);

    let out = f.step(Event::Tick { now_us: 1 }, &mut Live);
    let Screen::Page { index, pages } = out.screen else {
        panic!("a page: {:?}", out.screen);
    };
    assert_eq!(index, 0);
    assert!(
        pages >= 3,
        "summary, two outputs, and whatever else: {pages}"
    );
    let summary = f.page(|p| matches!(p, Page::Summary { outputs: 2, .. }));
    assert_eq!(summary, Some(true));
    let sums = f
        .page(|p| match *p {
            Page::Summary {
                spending,
                receiving,
                fee,
                ..
            } => Some((spending, receiving, fee)),
            _ => None,
        })
        .flatten();
    let counts = f
        .page(|p| match *p {
            Page::Summary {
                inputs, outputs, ..
            } => Some((inputs, outputs)),
            _ => None,
        })
        .flatten();

    // Left on the first page stays; right walks forward; left walks back.
    f.touch(LEFT);
    assert!(matches!(
        f.step(Event::Tick { now_us: 2 }, &mut Live).screen,
        Screen::Page { index: 0, .. }
    ));
    arrow(&mut f, RIGHT);
    assert!(matches!(
        f.step(Event::Tick { now_us: 3 }, &mut Live).screen,
        Screen::Page { index: 1, .. }
    ));
    arrow(&mut f, LEFT);
    assert!(matches!(
        f.step(Event::Tick { now_us: 4 }, &mut Live).screen,
        Screen::Page { index: 0, .. }
    ));

    // Forward to the last page: every step a page, none CONFIRM SEND?.
    for i in 1..pages {
        let out = arrow(&mut f, RIGHT);
        assert_eq!(out.screen, Screen::Page { index: i, pages });
    }
    assert_eq!(f.state(), State::Reviewing);
    // Past the last page: CONFIRM SEND?, its left side back.
    assert_eq!(arrow(&mut f, RIGHT).screen, Screen::Confirm);
    assert_eq!(f.state(), State::Confirming);
    // Its rows and counts are the summary's: a single key's send, no group.
    let t = f.totals().expect("the totals");
    assert_eq!(Some((t.spent, t.out, t.fee)), sums);
    let (shown, counted) = f.summary().expect("TX REVIEW's window");
    assert_eq!(shown, t);
    assert_eq!(Some((counted.inputs, counted.outputs)), counts);
    assert_eq!(counted.group, None);
    let out = f.touch(on_confirm(review::Target::Previous));
    assert_eq!(
        out.screen,
        Screen::Page {
            index: pages - 1,
            pages
        }
    );
    assert!(f.reply().is_empty(), "nothing signed on the way");
}

/// **Each output is shown as its address**, a script's marked as one; the
/// seed's change is CHANGE and its receive YOURS, with their place, unless
/// past the keys at hand and unplaced by the request.
#[test]
fn the_review_shows_each_output_as_its_address() {
    use kassigner_fw::ui::review::{Change, Shown, Totals};
    use kassigner_kaspa::address::{encode, Prefix, Version, MAX_ADDRESS_LEN};

    #[derive(Debug, PartialEq)]
    enum Seen {
        Summary(Totals, usize, usize),
        Output(usize, u64, String, bool, Change),
        LockTime(u64, bool),
        Card(String, u64, usize, bool, Option<String>),
        Covenant([u8; 32], usize, u32, Option<usize>),
    }
    fn seen(f: &Flow<'_, 1>) -> Option<Seen> {
        f.review(|s| match *s {
            Shown::Summary {
                totals,
                inputs,
                outputs,
                ..
            } => Seen::Summary(totals, inputs, outputs),
            Shown::Output {
                number,
                value,
                address,
                script,
                change,
            } => Seen::Output(number, value, address.to_string(), script, change),
            Shown::LockTime { value, ignored } => Seen::LockTime(value, ignored),
            Shown::Card {
                address,
                unlock,
                utxos,
                recover,
                other,
            } => Seen::Card(
                address.to_string(),
                unlock,
                utxos,
                recover,
                other.map(str::to_string),
            ),
            Shown::Covenant {
                id,
                spent,
                outputs,
                from,
            } => Seen::Covenant(id, spent, outputs, from),
        })
    }
    let text = |version: Version, payload: &[u8]| {
        let mut out = [0u8; MAX_ADDRESS_LEN];
        let n = encode(Prefix::Mainnet, version, payload, &mut out).unwrap();
        String::from_utf8(out[..n].to_vec()).unwrap()
    };

    let w = wallet();
    let receive = x_only(&w);
    let change = w.signing_key(Path::change(3)).unwrap().x_only();
    let far = w.signing_key(Path::change(7)).unwrap().x_only();
    let stranger = [0x42; 32];
    let mut p2sh = vec![0xaa, 0x20];
    p2sh.extend_from_slice(&[0x17; 32]);
    p2sh.push(0x87);
    let (to_stranger, to_change, to_receive, to_far) =
        (p2pk(&stranger), p2pk(&change), p2pk(&receive), p2pk(&far));
    let outputs: [(u64, &[u8]); 5] = [
        (20_000 * KAS, &to_stranger),
        (20_000 * KAS, &p2sh),
        (20_000 * KAS, &to_change),
        (15_000 * KAS, &to_receive),
        (15_000 * KAS, &to_far),
    ];
    let req = request(100_000 * KAS, &to_receive, &outputs);
    let mut m = Memory::new();
    let mut f = reviewing(&mut m, &req);
    f.step(Event::Tick { now_us: 1 }, &mut Live);

    let totals = Totals {
        out: 90_000 * KAS,
        spent: 100_000 * KAS,
        fee: 10_000 * KAS,
    };
    let expected = [
        Seen::Summary(totals, 1, 5),
        Seen::Output(
            1,
            20_000 * KAS,
            text(Version::PubKey, &stranger),
            false,
            Change::No,
        ),
        Seen::Output(
            2,
            20_000 * KAS,
            text(Version::ScriptHash, &[0x17; 32]),
            true,
            Change::No,
        ),
        Seen::Output(
            3,
            20_000 * KAS,
            text(Version::PubKey, &change),
            false,
            Change::At(3),
        ),
        Seen::Output(
            4,
            15_000 * KAS,
            text(Version::PubKey, &receive),
            false,
            Change::Yours(0),
        ),
        Seen::Output(
            5,
            15_000 * KAS,
            text(Version::PubKey, &far),
            false,
            Change::No,
        ),
    ];
    for (i, want) in expected.into_iter().enumerate() {
        if i > 0 {
            arrow(&mut f, RIGHT);
        }
        assert_eq!(seen(&f), Some(want), "page {i}");
    }
    assert!(matches!(seen(&f), Some(Seen::Output(5, ..))));
    // CONFIRM SEND? has no page: its totals are read on their own.
    arrow(&mut f, RIGHT);
    assert_eq!(f.state(), State::Confirming);
    assert_eq!(seen(&f), None);
    assert_eq!(f.totals(), Some(totals));
}

/// **A lock time is reviewed on its own page, and signed over**, ignored
/// when every input is final. A payload is refused as it arrives.
#[test]
fn a_lock_time_is_reviewed_and_a_payload_refused() {
    use kassigner_fw::ui::review::Shown;
    let mine = x_only(&wallet());
    let spk = p2pk(&mine);
    let plain = request(
        100_000 * KAS,
        &spk,
        &[(60_000 * KAS, &spk), (30_000 * KAS, &spk)],
    );
    // The header's lock time follows the counts; the input's sequence its
    // outpoint and amount, after the header's 44 bytes.
    let at = MAGIC.len() + 6;
    let sequence_at = MAGIC.len() + 44 + 32 + 4 + 8;
    for (value, ignored) in [
        (99_999_999u64, false),
        (1_798_761_599_000, false),
        (99_999_999, true),
    ] {
        let mut locked = plain.clone();
        locked[at..at + 8].copy_from_slice(&value.to_le_bytes());
        if ignored {
            locked[sequence_at..sequence_at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        assert_ne!(digest(&locked), digest(&plain), "the lock time is signed");
        let mut m = Memory::new();
        let mut f = reviewing(&mut m, &locked);
        let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
            Screen::Page { pages, .. } => pages,
            other => panic!("{other:?}"),
        };
        assert_eq!(pages, 4, "TX REVIEW, two outputs and LOCK TIME");
        for _ in 1..pages {
            arrow(&mut f, RIGHT);
        }
        assert_eq!(
            f.review(|s| *s == Shown::LockTime { value, ignored }),
            Some(true),
            "{value} {ignored}"
        );
        confirmed(&mut f);
        reply_shown(&mut f);
        let k = kspt::parse(f.reply(), &P).expect("the reply parses");
        let sigs: Vec<_> = k.inputs().next().expect("input").signatures().collect();
        let sig: &[u8; 64] = sigs[0].bytes.try_into().expect("64 bytes");
        assert!(bip340::verify(&mine, &digest(&locked), sig), "{value}");
    }

    // The payload's length follows the subnetwork and the gas, and the
    // payload that length.
    let len_at = at + 8 + 20 + 8;
    let mut carried = plain.clone();
    carried[len_at..len_at + 2].copy_from_slice(&4u16.to_le_bytes());
    for (k, b) in [0xde, 0xad, 0xbe, 0xef].into_iter().enumerate() {
        carried.insert(len_at + 2 + k, b);
    }
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &carried);
    let why = Refusal::Unshown(Unshown::Payload);
    assert_eq!(f.state(), State::Refused(why));
    assert!(f.page(|_| ()).is_none());
    assert_eq!(why.words(), ("Cannot review", "Payloads not shown yet"));
}

/// **An input of ours under a script that is not a multisig is refused as
/// it arrives**: no page shows the script its signature agrees to.
#[test]
fn a_script_input_of_ours_is_refused_until_its_page_is_drawn() {
    let mine = x_only(&wallet());
    let mut redeem = vec![0x63, 0xb1, 0x75, 0x20];
    redeem.extend_from_slice(&mine);
    redeem.extend_from_slice(&[0xad, 0x68]);
    let mut spk = vec![0xaa, 0x20];
    spk.extend_from_slice(&kassigner_kaspa::script::redeem_hash(&redeem));
    spk.push(0x87);
    // No signatures, then the redeem script after its `u16` length.
    let mut tail = vec![0];
    tail.extend_from_slice(&(redeem.len() as u16).to_le_bytes());
    tail.extend_from_slice(&redeem);
    let to = p2pk(&mine);
    let req = request_as(
        VERSION,
        0,
        &tail,
        100_000 * KAS,
        &spk,
        &[(90_000 * KAS, &to)],
    );

    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    let out = deliver(&mut f, &req);
    let why = Refusal::Unshown(Unshown::Script);
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(out.screen, Screen::Refused(why));
    assert_eq!(
        why.words(),
        ("Cannot review", "Script inputs not shown yet")
    );
    assert!(f.page(|_| ()).is_none(), "no review was started");
    assert!(f.reply().is_empty());
}

/// CONFIRM on CONFIRM SEND? signs: the reply parses, carries one signature
/// at position zero, and verifies over the session's hash.
#[test]
fn confirming_on_confirm_send_signs_and_shows_the_reply() {
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
    let mut out = confirmed(&mut f);
    assert_eq!(out.command, None);
    assert_eq!(out.screen, Screen::ReplyFormat, "Wallet or KasSigner first");
    out = f.step(reply_card(Card::Wallet), &mut Live);
    if f.reply_frames() > 1 {
        assert_eq!(out.screen, Screen::ReplyMode, "frames ask first");
        out = f.touch(answer(dialog::Target::Cancel));
    }
    assert_eq!(f.state(), State::Showing { frame: 0 });
    assert_eq!(
        out.screen,
        Screen::Reply {
            frame: 0,
            frames: f.reply_frames(),
        }
    );
    assert_eq!(
        usize::from(f.reply_frames()),
        kassigner_protocol::frame::frames_needed(f.reply().len(), 225),
        "frames of the unit's 225 bytes"
    );

    let reply = f.reply().to_vec();
    assert_eq!(reply[MAGIC.len()], VERSION, "answered as 0x06");
    let k = kspt::parse(&reply, &P).expect("the reply parses");
    let sigs: Vec<_> = k.inputs().next().expect("input").signatures().collect();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].pubkey_pos, 0);
    assert_eq!(sigs[0].sighash_type, SIG_HASH_ALL.to_u8());
    let sig: &[u8; 64] = sigs[0].bytes.try_into().expect("64 bytes");
    assert!(bip340::verify(&x_only(&wallet()), &digest(&req), sig));

    // The frames turn every `WALLET_FRAME_US`; one code stays.
    let frames = f.reply_frames();
    f.step(
        Event::Tick {
            now_us: 1 + kassigner_fw::limits::WALLET_FRAME_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Showing { frame: 1 % frames });

    // A tap is SIGNED TX; Home there lets the reply and the request go.
    f.step(LEFT, &mut Live);
    assert_eq!(f.state(), State::ReplyDone);
    assert!(!f.reply().is_empty(), "still held");
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);
    assert!(f.reply().is_empty());
    assert!(f.page(|_| ()).is_none());
}

/// A request from an older companion, in every version it may write, is
/// signed like a canonical one and answered in `0x06`.
#[test]
fn a_legacy_request_is_signed_and_answered_as_0x06() {
    let spk = p2pk(&x_only(&wallet()));
    let outputs: [(u64, &[u8]); 2] = [(60_000 * KAS, &spk), (30_000 * KAS, &spk)];
    // What follows an unsigned input's script in each shape.
    let shapes: [(u8, u8, &[u8]); 6] = [
        (0x01, 0x00, &[]),        // unsigned, no redeem
        (0x01, 0x01, &[0]),       // single-signature: a zero length
        (0x02, 0x00, &[0, 0]),    // no signatures, a `u8` redeem length
        (0x03, 0x00, &[0, 0, 0]), // no signatures, a `u16` redeem length
        (0x04, 0x00, &[]),        // unsigned, no redeem
        (0x05, 0x00, &[0, 0, 0]), // no signatures, a `u16` redeem length
    ];
    for (version, flags, tail) in shapes {
        let req = request_as(version, flags, tail, 100_000 * KAS, &spk, &outputs);
        assert_eq!(
            kspt::parse(&req, &P).err(),
            Some(kspt::KsptError::UseLegacyParser(version)),
            "{version:#04x} is not canonical"
        );

        let mut m = Memory::new();
        let mut f = reviewing(&mut m, &req);
        let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
            Screen::Page { pages, .. } => pages,
            other => panic!("{version:#04x}: {other:?}"),
        };
        for _ in 1..pages {
            arrow(&mut f, RIGHT);
        }
        confirmed(&mut f);
        reply_shown(&mut f);

        let reply = f.reply().to_vec();
        assert_eq!(
            reply[MAGIC.len()],
            VERSION,
            "{version:#04x} answered as 0x06"
        );
        let k = kspt::parse(&reply, &P).expect("the reply parses");
        let sigs: Vec<_> = k.inputs().next().expect("input").signatures().collect();
        assert_eq!(sigs.len(), 1, "{version:#04x}");
        let sig: &[u8; 64] = sigs[0].bytes.try_into().expect("64 bytes");
        assert!(
            bip340::verify(&x_only(&wallet()), &digest(&req), sig),
            "{version:#04x}: the signature is over the request's transaction"
        );
    }
}

/// Nothing but CONFIRM signs: not the walk, nor any other event or tap.
#[test]
fn nothing_but_confirm_signs() {
    let mut m = Memory::new();
    let req = ours();
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
        assert_eq!(f.state(), State::Reviewing);
        assert!(f.reply().is_empty());
    }
    // On the last page, nothing but a tap does anything.
    let payload = ours();
    let not_taps = [
        Event::Tick { now_us: 60_000_000 },
        Event::Progress {
            have: 9,
            total: 9,
            received: 0x1FF,
        },
        Event::Payload(&payload),
        Event::CameraSample(&payload),
        GOOD,
    ];
    for e in not_taps {
        f.step(e, &mut Live);
        assert_eq!(f.state(), State::Reviewing, "{e:?} moved the review");
    }
    // Where CONFIRM will be, on the last page: nothing.
    f.touch(on_confirm(review::Target::Confirm));
    assert_eq!(f.state(), State::Reviewing);
    arrow(&mut f, RIGHT);
    assert_eq!(f.state(), State::Confirming);
    for e in not_taps {
        f.step(e, &mut Live);
        assert_eq!(f.state(), State::Confirming, "{e:?} moved CONFIRM SEND?");
    }
    for e in [
        RIGHT,
        Event::Tap { x: 160, y: 205 },
        Event::Tap {
            x: 65_535,
            y: 65_535,
        },
    ] {
        f.touch(e);
        assert_eq!(f.state(), State::Confirming, "{e:?} answered");
    }
    assert!(f.reply().is_empty());
    // CONFIRM puts up SIGNING; taps on it are not answers, and the next
    // tick signs.
    let out = f.touch(on_confirm(review::Target::Confirm));
    assert_eq!(out.screen, Screen::Signing);
    for e in [
        on_confirm(review::Target::Cancel),
        on_confirm(review::Target::Previous),
        tap_in(chrome::corner(SCALE, Nav::Back)),
        home_button(),
    ] {
        f.touch(e);
        assert_eq!(f.state(), State::Signing, "{e:?} during the signing");
    }
    assert!(f.reply().is_empty());
    let out = f.step(Event::Tick { now_us: 2 }, &mut Live);
    assert_eq!(out.screen, Screen::ReplyFormat);
    assert!(!f.reply().is_empty());
}

/// **Only a tap down and up on one arrow turns a review page**: not the
/// page between, a slide, or a lift with no press; the dark left arrow of
/// the first page does nothing.
#[test]
fn only_a_tap_on_an_arrow_turns_a_review_page() {
    let mut m = Memory::new();
    let req = ours();
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    assert!(pages > 1, "a page after the first");
    // The dark arrow: nothing, and nothing to click for.
    let out = f.touch(LEFT);
    assert_eq!(out.screen, Screen::Page { index: 0, pages });
    assert_eq!(out.command, None);
    assert_eq!(f.state(), State::Reviewing);

    let page_1 = Screen::Page { index: 1, pages };
    assert_eq!(arrow(&mut f, RIGHT).screen, page_1);
    let (left, right) = (point(LEFT), point(RIGHT));
    let middle = (160, 120);
    // Down and up between the columns, edges included.
    for at in [
        (42, 120),
        (60, 120),
        middle,
        (100, 160),
        (260, 120),
        (277, 120),
    ] {
        let out = slide(&mut f, at, at);
        assert_eq!(out.screen, page_1, "a tap at {at:?}");
    }
    // Slid onto an arrow, or off one.
    for (from, to) in [
        (left, right),
        (right, left),
        (middle, right),
        (middle, left),
        (right, middle),
        (left, middle),
    ] {
        let out = slide(&mut f, from, to);
        assert_eq!(out.screen, page_1, "down at {from:?}, up at {to:?}");
        assert_eq!(f.state(), State::Reviewing);
    }
    // A lift with no press seen.
    assert_eq!(f.step(RIGHT, &mut Live).screen, page_1, "a bare lift");
    assert_eq!(f.step(LEFT, &mut Live).screen, page_1, "a bare lift");
    // Down and up on an arrow, moving inside it, turns the page next tick.
    let out = slide(&mut f, left, (left.0 - 10, left.1 + 20));
    assert_eq!(out.screen, page_1, "until the tick");
    let out = settled(&mut f, out);
    assert_eq!(out.screen, Screen::Page { index: 0, pages });
    assert!(f.reply().is_empty());
}

/// **On CONFIRM SEND? a slide answers nothing**, nor a lift with no press,
/// nor the left of the screen past the arrow; the arrow goes back, and
/// CONFIRM down and up signs.
#[test]
fn a_slide_on_confirm_send_answers_nothing() {
    let mut m = Memory::new();
    let req = ours();
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 0..pages {
        arrow(&mut f, RIGHT);
    }
    assert_eq!(f.state(), State::Confirming);
    let at = |t: review::Target| point(on_confirm(t));
    let (cancel, confirm, back) = (
        at(review::Target::Cancel),
        at(review::Target::Confirm),
        at(review::Target::Previous),
    );
    for (from, to) in [
        (cancel, confirm),
        (confirm, cancel),
        ((160, 120), confirm),
        (back, confirm),
        (confirm, (160, 120)),
        (confirm, back),
        ((60, 120), (60, 120)),
        ((100, 150), (100, 150)),
    ] {
        let out = slide(&mut f, from, to);
        assert_eq!(
            out.screen,
            Screen::Confirm,
            "down at {from:?}, up at {to:?}"
        );
        assert_eq!(f.state(), State::Confirming);
        assert!(f.reply().is_empty());
    }
    let out = f.step(on_confirm(review::Target::Confirm), &mut Live);
    assert_eq!(out.screen, Screen::Confirm, "a bare lift on CONFIRM");
    let out = f.touch(on_confirm(review::Target::Previous));
    assert_eq!(
        out.screen,
        Screen::Page {
            index: pages - 1,
            pages
        },
        "the arrow is the way back"
    );
    arrow(&mut f, RIGHT);
    let out = f.touch(on_confirm(review::Target::Confirm));
    assert_eq!(out.screen, Screen::Signing);
    assert_eq!(f.state(), State::Signing);
}

/// CANCEL on CONFIRM SEND? declines: no reply, the request dropped, home
/// after the refusal.
#[test]
fn cancelling_confirm_send_drops_the_request() {
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
    arrow(&mut f, RIGHT);
    let out = f.touch(on_confirm(review::Target::Cancel));
    assert_eq!(f.state(), State::Refused(Refusal::Declined));
    assert_eq!(out.screen, Screen::Refused(Refusal::Declined));
    assert!(f.reply().is_empty());
    assert!(f.page(|_| ()).is_none());
    assert!(f.totals().is_none());
    f.step(Event::Tick { now_us: 1 << 40 }, &mut Live);
    assert_eq!(f.state(), State::Home);
}

/// Back and Home cancel, on any page and on CONFIRM SEND?: nothing signed,
/// the request dropped.
#[test]
fn back_and_home_cancel_the_review() {
    let back = tap_in(chrome::corner(SCALE, Nav::Back));
    for (corner, confirm) in [
        (back, false),
        (home_button(), false),
        (back, true),
        (home_button(), true),
    ] {
        let mut m = Memory::new();
        let req = ours();
        let mut f = reviewing(&mut m, &req);
        let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
            Screen::Page { pages, .. } => pages,
            other => panic!("{other:?}"),
        };
        if confirm {
            for _ in 0..pages {
                arrow(&mut f, RIGHT);
            }
            assert_eq!(f.state(), State::Confirming);
        } else {
            arrow(&mut f, RIGHT);
        }
        f.touch(corner);
        assert_eq!(f.state(), State::Refused(Refusal::Declined), "{confirm}");
        assert!(f.reply().is_empty());
        assert!(f.page(|_| ()).is_none());
    }
}

/// A review page or CONFIRM SEND? the panel did not take
/// (`Event::NotDrawn`) refuses the review: nothing signed, the request
/// dropped, and a tap on the refusal reaches neither an arrow nor CONFIRM.
/// Elsewhere the event does nothing.
#[test]
fn a_screen_the_panel_did_not_take_refuses_the_review() {
    let req = ours();
    let pages = {
        let mut m = Memory::new();
        let mut f = reviewing(&mut m, &req);
        match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
            Screen::Page { pages, .. } => pages,
            other => panic!("{other:?}"),
        }
    };
    assert!(pages > 1, "a page past the first to fail on");
    // `pages` arrows from the first page is CONFIRM SEND?.
    for at in 0..=pages {
        let mut m = Memory::new();
        let mut f = reviewing(&mut m, &req);
        let out = f.step(Event::Tick { now_us: 1 }, &mut Live);
        assert_eq!(out.screen, Screen::Page { index: 0, pages });
        for _ in 0..at {
            arrow(&mut f, RIGHT);
        }
        let on = if at == pages {
            State::Confirming
        } else {
            State::Reviewing
        };
        assert_eq!(f.state(), on, "{at}");
        let out = f.step(Event::NotDrawn, &mut Live);
        assert_eq!(out.screen, Screen::Refused(Refusal::NotDrawn), "{at}");
        assert_eq!(out.command, None, "{at}");
        assert_eq!(f.state(), State::Refused(Refusal::NotDrawn), "{at}");
        assert!(f.page(|_| ()).is_none(), "{at}: the request dropped");
        assert!(f.totals().is_none(), "{at}");
        for e in [RIGHT, on_confirm(review::Target::Confirm)] {
            f.touch(e);
            assert_eq!(f.state(), State::Refused(Refusal::NotDrawn), "{at}: {e:?}");
        }
        assert!(f.reply().is_empty(), "{at}: nothing signed");
        f.step(Event::Tick { now_us: 1 << 40 }, &mut Live);
        assert_eq!(f.state(), State::Home, "{at}");
        let out = f.step(Event::NotDrawn, &mut Live);
        assert_eq!(f.state(), State::Home, "{at}: nothing at Home");
        assert_eq!(out.screen, Screen::Home, "{at}");
    }
}

/// **An output under a script version consensus does not run is refused
/// before any review**: anyone could spend it, and it has no address.
#[test]
fn an_output_under_an_unknown_script_version_is_refused() {
    let mut m = Memory::new();
    let spk = p2pk(&x_only(&wallet()));
    let mut req = request(100_000, &spk, &[(90_000, &spk)]);
    // The output's script version: past the input, its 3-byte tail, and the
    // output's value.
    let at = 101 + 2 + spk_len(spk.len()).len() + spk.len() + 3 + 8;
    req[at..at + 2].copy_from_slice(&1u16.to_le_bytes());
    let parsed = kspt::parse(&req, &P).expect("parse");
    assert_eq!(parsed.outputs().next().expect("output").spk_version, 1);

    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    let why = Refusal::NotReviewable(kassigner_fw::session::Error::NonStandard(
        kassigner_kaspa::tx::NonStandardError::RejectScriptPublicKeyVersion(0),
    ));
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(why.words(), ("Cannot review", "Unknown script version"));
    assert!(f.page(|_| ()).is_none(), "no review was started");
}

/// **A request over the block's storage mass limit is refused before any
/// review**: every node's mempool refuses the transaction (upstream's
/// `RejectStorageMass`), so the unit does not sign it. One KAS in, half a KAS
/// and a thousand sompi out.
#[test]
fn a_request_over_the_storage_mass_limit_is_refused() {
    let mut m = Memory::new();
    let spk = p2pk(&x_only(&wallet()));
    let req = request(KAS, &spk, &[(KAS / 2, &spk), (1_000, &spk)]);

    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    let why = Refusal::NotReviewable(kassigner_fw::session::Error::Review(
        kassigner_fw::review::Error::StorageMass {
            mass: 1_000_010_000,
        },
    ));
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(
        why.words(),
        ("Cannot review", "Over the storage mass limit")
    );
    assert!(f.page(|_| ()).is_none(), "no review was started");
}

/// A `0x49` record: the covenant input `index`'s coin is bound to.
fn coin_covenant(index: u8, id: [u8; 32]) -> Vec<u8> {
    let mut r = vec![0x49, index];
    r.extend_from_slice(&id);
    r
}

/// **A coin bound to a covenant is counted as a node counts it, in a KSPT
/// and in a bundle**: the request says which covenant the coin is bound to
/// (a KSPT's `0x49` record, a bundle's `utxoEntry.covenantId`), a bound coin
/// takes more storage (upstream's `utxo_plurality`), and so frees more when
/// spent. The same small coin is over the storage limit unbound and under
/// it bound. The signed KSPT reply still says the coin is bound, for the
/// next reader.
#[test]
fn a_coin_bound_to_a_covenant_is_counted_as_such() {
    let spk = p2pk(&x_only(&wallet()));
    let id = [0x77; 32];
    let over = Refusal::NotReviewable(kassigner_fw::session::Error::Review(
        kassigner_fw::review::Error::StorageMass { mass: 1_111_111 },
    ));
    let arrives = |req: &[u8]| {
        let mut m = Memory::new();
        let mut f: Flow<'_, 1> = seeded(&mut m);
        f.step(scan(), &mut Live);
        deliver(&mut f, req);
        f.state()
    };

    // A KSPT: 100,000 sompi in, 90,000 out.
    let plain = request(100_000, &spk, &[(90_000, &spk)]);
    assert_eq!(arrives(&plain), State::Refused(over));
    let mut bound = plain.clone();
    bound.extend_from_slice(&coin_covenant(0, id));
    assert_eq!(arrives(&bound), State::Reviewing);

    // The same as a bundle.
    let plain = bundle_request(100_000, &spk, &[(90_000, &spk)]);
    assert_eq!(arrives(&plain), State::Refused(over));
    let bound_bundle = bundle_edited(&plain, |doc| {
        doc.replacen(
            "\"isCoinbase\":false}",
            &format!("\"isCoinbase\":false,\"covenantId\":\"{}\"}}", hex(&id)),
            1,
        )
    });
    assert_eq!(arrives(&bound_bundle), State::Reviewing);
    // A covenant id that does not read is no transaction to review.
    let bent = bundle_edited(&plain, |doc| {
        doc.replacen(
            "\"isCoinbase\":false}",
            "\"isCoinbase\":false,\"covenantId\":\"77\"}",
            1,
        )
    });
    assert!(
        matches!(arrives(&bent), State::Refused(_)),
        "{:?}",
        arrives(&bent)
    );

    // Signed, the KSPT reply carries the record as it came.
    let mut m = Memory::new();
    let mut f = reviewing(&mut m, &bound);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    let reply = f.reply().to_vec();
    let k = kspt::parse(&reply, &P).expect("the reply parses");
    assert_eq!(k.inputs().next().expect("input").sig_count, 1);
    let mut coins = [None; 1];
    kspt::transaction::coins(&k, &mut coins);
    assert_eq!(coins, [Some(id)]);
}

/// **An output bound to a covenant must continue its coin's covenant or
/// start its own** (upstream's `CovenantsContext::from_tx`): an id that is
/// neither is refused before any review, as a node refuses it
/// (`WrongGenesisCovenantId`). With the coin said to be bound to that
/// covenant, the output continues it: the request is reviewed, the covenant
/// on a page of its own after the output's.
#[test]
fn a_binding_that_continues_no_covenant_and_starts_none_is_refused() {
    let spk = p2pk(&x_only(&wallet()));
    let id = [0x77; 32];
    // Output 0 bound to `id`, authorized by input 0.
    let mut binding = vec![0x43, 0];
    binding.extend_from_slice(&0u16.to_le_bytes());
    binding.extend_from_slice(&id);
    let mut req = request(100_000 * KAS, &spk, &[(90_000 * KAS, &spk)]);
    req.extend_from_slice(&binding);

    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    let why = Refusal::NotReviewable(kassigner_fw::session::Error::Consensus(
        kassigner_kaspa::tx::TxRuleError::WrongGenesisCovenantId(0, id),
    ));
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(why.words(), ("Cannot review", "Consensus refuses it"));
    assert!(f.page(|_| ()).is_none(), "no review was started");

    // The coin bound to that covenant: a continuation, which a node takes.
    // TX REVIEW, OUTPUT 1, then COVENANT: one UTXO spent, continued in
    // output 0.
    req.extend_from_slice(&coin_covenant(0, id));
    let mut m = Memory::new();
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    assert_eq!(pages, 3);
    arrow(&mut f, RIGHT);
    arrow(&mut f, RIGHT);
    let shown = f.review(|s| match *s {
        kassigner_fw::ui::review::Shown::Covenant {
            id,
            spent,
            outputs,
            from,
        } => Some((id, spent, outputs, from)),
        _ => None,
    });
    assert_eq!(shown, Some(Some((id, 1, 0b1, None))));
    // Confirming waits for it, as for every page; then it is signed and the
    // reply still says which covenant the coin is bound to.
    confirmed(&mut f);
    let reply = f.reply().to_vec();
    let k = kspt::parse(&reply, &P).expect("the reply parses");
    assert_eq!(k.inputs().next().expect("input").sig_count, 1);
    let mut coins = [None; 1];
    kspt::transaction::coins(&k, &mut coins);
    assert_eq!(coins, [Some(id)]);
}

/// **Outputs worth more than the inputs are refused before any review**
/// (upstream's `SpendTooHigh`); exactly the inputs, a zero fee, is fine.
#[test]
fn outputs_worth_more_than_the_inputs_are_refused() {
    let mut m = Memory::new();
    let spk = p2pk(&x_only(&wallet()));
    let req = request(100_000, &spk, &[(100_001, &spk)]);

    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    let why = Refusal::NotReviewable(kassigner_fw::session::Error::Consensus(
        kassigner_kaspa::tx::TxRuleError::SpendTooHigh(100_001, 100_000),
    ));
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(why.words(), ("Cannot review", "Amounts out of range"));
    assert!(f.page(|_| ()).is_none(), "no review was started");

    let mut m = Memory::new();
    let req = request(100_000, &spk, &[(100_000, &spk)]);
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(f.state(), State::Reviewing);
    assert_eq!(f.totals().map(|t| t.fee), Some(0));
}

/// **A request spending one UTXO twice is refused before any review**
/// (upstream's `TxDuplicateInputs`): its amount would count twice. The
/// same inputs on two outpoints are reviewed.
#[test]
fn a_request_spending_one_utxo_twice_is_refused() {
    let spk = p2pk(&x_only(&wallet()));
    let inputs: [(u64, &[u8]); 2] = [(60_000, &spk), (40_000, &spk)];
    let outputs: [(u64, &[u8]); 1] = [(90_000, &spk)];
    let mut req = request_of(VERSION, 0, &[0, 0, 0], &inputs, &outputs);
    // The second input's outpoint, index 1, given the first's index, 0.
    let mut second = [0x11u8; 36];
    second[32..].copy_from_slice(&1u32.to_le_bytes());
    let at = req
        .windows(second.len())
        .position(|w| w == second)
        .expect("the second input's outpoint");
    req[at + 32..at + 36].copy_from_slice(&0u32.to_le_bytes());

    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    let why = Refusal::NotReviewable(kassigner_fw::session::Error::Consensus(
        kassigner_kaspa::tx::TxRuleError::TxDuplicateInputs,
    ));
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(why.words(), ("Cannot review", "A UTXO is spent twice"));
    assert!(f.page(|_| ()).is_none(), "no review was started");

    let req = request_of(VERSION, 0, &[0, 0, 0], &inputs, &outputs);
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(f.state(), State::Reviewing, "two outpoints");
}

/// **An unknown transaction version is refused before any review.**
#[test]
fn an_unknown_transaction_version_is_refused() {
    let mut m = Memory::new();
    let spk = p2pk(&x_only(&wallet()));
    let mut req = request(100_000, &spk, &[(90_000, &spk)]);
    // The transaction's version: the u16 after the magic, the format's own
    // version and the flags.
    let at = MAGIC.len() + 2;
    assert_eq!(&req[at..at + 2], &1u16.to_le_bytes(), "a version-1 request");
    req[at..at + 2].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(kspt::parse(&req, &P).expect("parse").tx_version, 2);

    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    let why = Refusal::NotReviewable(kassigner_fw::session::Error::Consensus(
        kassigner_kaspa::tx::TxRuleError::UnknownTxVersion(2),
    ));
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(
        why.words(),
        ("Cannot review", "Unknown transaction version")
    );
    assert!(f.page(|_| ()).is_none(), "no review was started");
}

/// **A record naming what the request lacks is refused before any
/// review**: a covenant binding's input as "Covenant input out of range",
/// a hint's input as no request, a binding's output as no transaction.
#[test]
fn a_record_naming_what_is_not_there_is_refused() {
    let mut m = Memory::new();
    let spk = p2pk(&x_only(&wallet()));
    let mut f: Flow<'_, 1> = seeded(&mut m);

    // A version-1 request, its output bound to input 1 of its one input.
    let mut req = request(100_000, &spk, &[(90_000, &spk)]);
    req.push(0x43);
    req.push(0);
    req.extend_from_slice(&1u16.to_le_bytes());
    req.extend_from_slice(&[0x5a; 32]);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    let why = Refusal::NotReviewable(kassigner_fw::session::Error::Consensus(
        kassigner_kaspa::tx::TxRuleError::AuthInputOutOfBounds(0, 1),
    ));
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(
        why.words(),
        ("Cannot review", "Covenant input out of range")
    );
    assert!(f.page(|_| ()).is_none(), "no review was started");
    f.step(
        Event::Tick {
            now_us: VERIFIED_US + REFUSED_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home);

    // An input hint for input 3.
    let mut req = request(100_000, &spk, &[(90_000, &spk)]);
    req.push(0x44);
    req.push(3);
    req.extend_from_slice(&[0u8; 12]);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(f.state(), State::Refused(Refusal::NotARequest));
    assert_eq!(
        Refusal::NotARequest.words(),
        ("Request not readable", "Not a KSPT or PSKB it reads")
    );
    f.step(
        Event::Tick {
            now_us: VERIFIED_US + 2 * REFUSED_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home);

    // A covenant binding for output 5 of one: no transaction, as the steps
    // after the parser would say it.
    let mut req = request(100_000, &spk, &[(90_000, &spk)]);
    req.push(0x43);
    req.push(5);
    req.extend_from_slice(&0u16.to_le_bytes());
    req.extend_from_slice(&[0x5a; 32]);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(f.state(), State::Refused(Refusal::NotATransaction));
}

/// **A non-standard output is refused before any review**: a mempool
/// refuses it.
#[test]
fn an_output_that_is_no_standard_form_is_refused() {
    let mut m = Memory::new();
    let spk = p2pk(&x_only(&wallet()));
    let req = request(100_000, &spk, &[(90_000, &[0x51])]);
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    let why = Refusal::NotReviewable(kassigner_fw::session::Error::NonStandard(
        kassigner_kaspa::tx::NonStandardError::RejectOutputScriptClass(0),
    ));
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(why.words(), ("Cannot review", "Non-standard output"));
    assert!(f.page(|_| ()).is_none(), "no review was started");
}

/// **A keyring refusal says why**: each reason the keyring gives for not
/// resolving an input is the second line of "Signing failed".
#[test]
fn a_keyring_refusal_says_why() {
    use kassigner_crypto::wallet::WalletError;
    use kassigner_fw::keyring::Error as K;
    for (error, why) in [
        (
            K::UnsupportedMultisig {
                required: 2,
                keys: 6,
            },
            "More than 5 multisig keys",
        ),
        (
            K::UnsupportedMultisig {
                required: 0,
                keys: 3,
            },
            "Multisig with no threshold",
        ),
        (K::RepeatedKey { position: 1 }, "Multisig repeats a key"),
        (K::RedeemMismatch, "Redeem script doesn't match"),
        (K::NoRedeemScript, "No redeem script"),
        (K::Wallet(WalletError::EmptySlot), "Key derivation failed"),
    ] {
        let refusal = Refusal::NotSigned(kassigner_fw::reply::Error::Keyring { input: 0, error });
        assert_eq!(refusal.words(), ("Signing failed", why), "{error:?}");
    }
}

/// A request with no input among the seed's first addresses is asked about
/// before each batch derived, and refused if the sweep finds nothing.
#[test]
fn a_request_that_is_not_ours_is_asked_about_then_searched() {
    let mut m = Memory::new();
    let theirs = p2pk(&[0x42; 32]);
    let req = request(100_000 * KAS, &theirs, &[(90_000 * KAS, &theirs)]);
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    // Nothing pumped yet: the first tick finds nothing to look through.
    let out = f.step(
        Event::Tick {
            now_us: VERIFIED_US,
        },
        &mut Live,
    );
    assert_eq!(out.screen, Screen::Asking { checked: 25 });
    assert!(f.page(|_| ()).is_none(), "no review was started");
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(f.state(), State::Home, "dropped");

    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    let asked = swept(&mut f);
    assert_eq!(
        asked,
        kassigner_fw::keyring::SWEEP.div_ceil(kassigner_fw::flow::BATCH),
        "asked before every batch"
    );
    assert_eq!(
        f.state(),
        State::Refused(Refusal::NotSigned(
            kassigner_fw::reply::Error::NothingSigned
        ))
    );
    assert!(f.reply().is_empty());
}

/// **An input past the first addresses is found and signed**: receive 30,
/// in the first batch.
#[test]
fn an_input_further_on_is_found_and_signed() {
    let mut m = Memory::new();
    let deep = wallet().signing_key(Path::receive(30)).unwrap().x_only();
    let spk = p2pk(&deep);
    let req = request(100_000 * KAS, &spk, &[(90_000 * KAS, &spk)]);
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(swept(&mut f), 1, "one batch");
    assert_eq!(f.state(), State::Reviewing, "found, and reviewed");

    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    reply_shown(&mut f);
    let k = kspt::legacy::parse_any(f.reply(), &P).expect("a KSPT");
    let sigs: Vec<_> = k.inputs().next().expect("input").signatures().collect();
    let sig: &[u8; 64] = sigs[0].bytes.try_into().expect("64 bytes");
    assert!(bip340::verify(&deep, &digest(&req), sig));
}

/// **A request with an input this seed does not sign is refused, not half
/// signed**: TX REVIEW's In and Fee would count an amount no signature of
/// the unit commits to. An ECDSA input is refused as it arrives, another
/// seed's once the search ends; with every input the seed's, it is
/// reviewed.
#[test]
fn a_request_with_an_input_not_the_seeds_is_refused() {
    let why = Refusal::NotSigned(kassigner_fw::reply::Error::NotEveryInput {
        signed: 2,
        inputs: 3,
    });
    assert_eq!(
        why.words(),
        ("Signing failed", "An input is not this seed's")
    );
    let spk = p2pk(&x_only(&wallet()));
    let second = p2pk(&wallet().signing_key(Path::receive(1)).unwrap().x_only());
    let mut ecdsa = vec![0x21, 0x02];
    ecdsa.extend_from_slice(&[0x5A; 32]);
    ecdsa.push(0xab);
    // The second seed of the tests that hold two (`other_seedqr`).
    let other = Wallet::open(
        &Slot::mnemonic(bip39::from_entropy(&[9u8; 16]).unwrap(), b"").unwrap(),
        &mut vec![0u8; bip39::scratch_for(0)],
    )
    .unwrap();
    let foreign = p2pk(&x_only(&other));
    let outputs: [(u64, &[u8]); 1] = [(250_000, &spk)];

    for third in [&ecdsa, &foreign] {
        let req = request_of(
            VERSION,
            0,
            &[0, 0, 0],
            &[(100_000, &spk), (100_000, &second), (100_000, third)],
            &outputs,
        );
        let mut m = Memory::new();
        let mut f: Flow<'_, 1> = seeded(&mut m);
        f.step(scan(), &mut Live);
        deliver(&mut f, &req);
        swept(&mut f);
        assert_eq!(f.state(), State::Refused(why), "{third:02x?}");
        assert!(f.page(|_| ()).is_none(), "no review was started");
    }

    let req = request_of(
        VERSION,
        0,
        &[0, 0, 0],
        &[(100_000, &spk), (100_000, &second)],
        &[(150_000, &spk)],
    );
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(f.state(), State::Reviewing, "every input the seed's");
}

/// **A search that finds what it cannot sign says so at once**: receive
/// 30, already signed by this seed, is refused at the first batch, not after
/// nine more.
#[test]
fn a_search_that_finds_what_it_cannot_sign_refuses_at_once() {
    let mut m = Memory::new();
    let key = wallet().signing_key(Path::receive(30)).unwrap();
    let deep = key.x_only();
    let spk = p2pk(&deep);
    // One signature at position 0 with SIGHASH_ALL, no redeem script: this
    // seed's own, over the request's hash (which excludes signatures). A
    // made-up one would be refused on arrival as a bad signature.
    let with = |sig: &[u8; 64]| {
        let mut tail = vec![1, 0, SIG_HASH_ALL.to_u8()];
        tail.extend_from_slice(sig);
        tail.extend_from_slice(&0u16.to_le_bytes());
        request_as(
            VERSION,
            0,
            &tail,
            100_000 * KAS,
            &spk,
            &[(90_000 * KAS, &spk)],
        )
    };
    let sig = kassigner_crypto::sign::sign(key.private_key(), &digest(&with(&[0; 64])), &[0; 32])
        .expect("sign");
    let req = with(sig.as_bytes());
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(swept(&mut f), 1, "asked about the first batch only");
    let why = Refusal::NotSigned(kassigner_fw::reply::Error::AlreadySigned {
        input: 0,
        position: 0,
    });
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(why.words().1, "Already signed by this seed");
    assert!(f.reply().is_empty());
}

/// **The idle pump**: on the home grid the unit derives the seed's keys a
/// tick at a time, then searches a request without asking.
#[test]
fn a_pumped_unit_searches_without_asking() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    for _ in 0..kassigner_fw::keyring::SWEEP {
        f.step(
            Event::Tick {
                now_us: VERIFIED_US,
            },
            &mut Live,
        );
    }
    let deep = wallet().signing_key(Path::change(700)).unwrap().x_only();
    let spk = p2pk(&deep);
    let req = request(100_000 * KAS, &spk, &[(90_000 * KAS, &spk)]);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(swept(&mut f), 0, "nothing asked");
    assert_eq!(f.state(), State::Reviewing, "change 700, found");
}

/// The back button ends a search, and the request goes with it.
#[test]
fn a_search_can_be_left() {
    let mut m = Memory::new();
    let theirs = p2pk(&[0x42; 32]);
    let req = request(100_000 * KAS, &theirs, &[(90_000 * KAS, &theirs)]);
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    f.step(answer(dialog::Target::Accept), &mut Live);
    for _ in 0..3 {
        f.step(Event::Tick { now_us: 1 }, &mut Live);
    }
    // Down on the button, the search going on, then up.
    let Event::Tap { x, y } = back_button() else {
        unreachable!()
    };
    f.step(Event::Press { x, y }, &mut Live);
    f.step(Event::Tick { now_us: 1 }, &mut Live);
    f.step(Event::Tick { now_us: 1 }, &mut Live);
    let out = f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Home,
        "the count moved; the screen did not"
    );
    assert_eq!(out.screen, Screen::Home);
    assert!(f.page(|_| ()).is_none());
}

/// The scanning screen reports the frames collected.
#[test]
fn scanning_reports_progress() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    for (have, total, received) in [(1, 4, 0b0100), (2, 4, 0b0110), (4, 4, 0b1111)] {
        let out = f.step(
            Event::Progress {
                have,
                total,
                received,
            },
            &mut Live,
        );
        assert_eq!(
            out.screen,
            Screen::Scanning {
                have,
                total,
                received,
                hint: false
            }
        );
    }
}

// ── Time-Locked Savings cards ───────────────────────────────────────────────

use kassigner_protocol::card::savings::{Savings, UnlockAt};

/// 1 January 2027, 14:30 UTC, in minutes after 1970: a card opening at a
/// time of day, to the minute.
const SAVINGS_AT: u32 = 20_819 * 1_440 + 14 * 60 + 30;

/// A key of no seed of this unit's: a raw key's.
fn strangers_key() -> [u8; 32] {
    let w = Wallet::open(
        &Slot::RawKey(kassigner_crypto::slot::RawKey::new(&[9; 32]).unwrap()),
        &mut [],
    )
    .unwrap();
    x_only(&w)
}

/// A version 0 KSPT spending one UTXO of `savings` to a stranger, at
/// `lock_time`, its input at `sequence` committing one signature operation.
fn savings_request(savings: &Savings, lock_time: u64, sequence: u64) -> Vec<u8> {
    let program = savings.program();
    let spk = savings.locking_script();
    let to = p2pk(&strangers_key());
    let mut b = Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(VERSION);
    b.push(0);
    b.extend_from_slice(&0u16.to_le_bytes());
    b.push(1);
    b.push(1);
    b.extend_from_slice(&lock_time.to_le_bytes());
    b.extend_from_slice(&[0u8; 20]);
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&[0x11u8; 32]);
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&(100_000 * KAS).to_le_bytes());
    b.extend_from_slice(&sequence.to_le_bytes());
    b.push(1);
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&spk_len(spk.len()));
    b.extend_from_slice(&spk);
    b.push(0);
    b.extend_from_slice(&(program.len() as u16).to_le_bytes());
    b.extend_from_slice(&program);
    b.extend_from_slice(&(90_000 * KAS).to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&spk_len(to.len()));
    b.extend_from_slice(&to);
    b
}

/// A key as its mainnet address.
fn address_text(version: kassigner_kaspa::address::Version, payload: &[u8]) -> String {
    use kassigner_kaspa::address::{encode, Prefix, MAX_ADDRESS_LEN};
    let mut out = [0u8; MAX_ADDRESS_LEN];
    let n = encode(Prefix::Mainnet, version, payload, &mut out).unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// A SAVINGS CARD page: the card's address, its time, its UTXOs,
/// recovering or not, the other key's address.
type SavingsPage = (String, u64, usize, bool, Option<String>);

/// The SAVINGS CARD page on the screen, if it is up.
fn savings_shown(f: &Flow<'_, 1>) -> Option<SavingsPage> {
    f.review(|s| match *s {
        review::Shown::Card {
            address,
            unlock,
            utxos,
            recover,
            other,
        } => Some((
            address.to_string(),
            unlock,
            utxos,
            recover,
            other.map(str::to_string),
        )),
        _ => None,
    })
    .flatten()
}

/// `req` reviewed and confirmed: its page count, its SAVINGS CARD page,
/// and the reply.
fn savings_reviewed(req: &[u8]) -> (usize, SavingsPage, Vec<u8>) {
    let mut m = Memory::new();
    let mut f = reviewing(&mut m, req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    assert!(savings_shown(&f).is_none(), "TX REVIEW first");
    arrow(&mut f, RIGHT);
    let shown = savings_shown(&f).expect("SAVINGS CARD second");
    for _ in 2..pages {
        arrow(&mut f, RIGHT);
    }
    let out = confirmed(&mut f);
    assert_eq!(out.screen, Screen::ReplyFormat);
    (pages, shown, f.reply().to_vec())
}

/// **A card's claim is reviewed on its page and signed** by its owner: the
/// page shows one UTXO, the opening time, the card's address and its
/// recovery wallet's; the signature is at the owner's place.
#[test]
fn a_card_claim_is_reviewed_on_its_page_and_signed() {
    use kassigner_kaspa::address::Version;
    let mine = x_only(&wallet());
    let theirs = strangers_key();
    let opens = UnlockAt::new(SAVINGS_AT).unwrap();
    let savings = Savings::new(mine, Some(theirs), opens).unwrap();
    let req = savings_request(&savings, opens.ms(), 0);
    let (pages, shown, reply) = savings_reviewed(&req);
    assert_eq!(pages, 4, "summary, card, output, lock time");
    let card_address = address_text(
        Version::ScriptHash,
        &kassigner_kaspa::script::redeem_hash(&savings.program()),
    );
    assert_eq!(
        shown,
        (
            card_address,
            opens.ms(),
            1,
            false,
            Some(address_text(Version::PubKey, &theirs))
        )
    );
    let k = kspt::parse(&reply, &P).expect("the reply parses");
    let sigs: Vec<_> = k.inputs().next().expect("input").signatures().collect();
    assert_eq!(sigs.len(), 1);
    assert_eq!(
        (sigs[0].pubkey_pos, sigs[0].sighash_type),
        (0, SIG_HASH_ALL.to_u8())
    );
    let sig: &[u8; 64] = sigs[0].bytes.try_into().unwrap();
    assert!(bip340::verify(&mine, &digest(&req), sig));
}

/// **A card's recovery is said as one**, naming the owner's key, the
/// signature at the second place. With no recovery wallet, none is named.
#[test]
fn a_card_recovery_is_said_as_such() {
    use kassigner_kaspa::address::Version;
    let mine = x_only(&wallet());
    let theirs = strangers_key();
    let opens = UnlockAt::new(SAVINGS_AT).unwrap();
    let savings = Savings::new(theirs, Some(mine), opens).unwrap();
    let req = savings_request(&savings, opens.ms() + 1, 0);
    let (_, (_, _, utxos, recover, other), reply) = savings_reviewed(&req);
    assert_eq!(
        (utxos, recover, other),
        (1, true, Some(address_text(Version::PubKey, &theirs)))
    );
    let k = kspt::parse(&reply, &P).unwrap();
    let sigs: Vec<_> = k.inputs().next().unwrap().signatures().collect();
    assert_eq!(sigs[0].pubkey_pos, 1);
    let sig: &[u8; 64] = sigs[0].bytes.try_into().unwrap();
    assert!(bip340::verify(&mine, &digest(&req), sig));

    let alone = Savings::new(mine, None, opens).unwrap();
    let req = savings_request(&alone, opens.ms(), 0);
    let (_, (_, _, _, recover, other), _) = savings_reviewed(&req);
    assert_eq!((recover, other), (false, None));
}

/// **A card still locked is refused as it arrives**: a lock time before it
/// opens (by a millisecond or a minute, or none), or a final input.
#[test]
fn a_card_still_locked_is_refused_as_it_arrives() {
    use kassigner_fw::flow::CardLock;
    let mine = x_only(&wallet());
    let opens = UnlockAt::new(SAVINGS_AT).unwrap();
    let savings = Savings::new(mine, None, opens).unwrap();
    for (lock_time, sequence, lock, second) in [
        (
            opens.ms() - 1,
            0,
            CardLock::Early,
            "Lock time is before it opens",
        ),
        (
            opens.ms() - 60_000,
            0,
            CardLock::Early,
            "Lock time is before it opens",
        ),
        (0, 0, CardLock::Early, "Lock time is before it opens"),
        (
            opens.ms(),
            u64::MAX,
            CardLock::Final,
            "Its input skips the lock",
        ),
    ] {
        let req = savings_request(&savings, lock_time, sequence);
        let mut m = Memory::new();
        let mut f: Flow<'_, 1> = seeded(&mut m);
        f.step(scan(), &mut Live);
        let out = deliver(&mut f, &req);
        let why = Refusal::CardLocked(lock);
        assert_eq!(f.state(), State::Refused(why));
        assert_eq!(out.screen, Screen::Refused(why));
        assert_eq!(why.words(), ("Card still locked", second));
        assert!(f.page(|_| ()).is_none(), "no review was started");
    }
}

/// **A relative lock is refused as it arrives**, as a page not drawn yet:
/// a sequence neither 0 nor final, here on a key's input.
#[test]
fn a_relative_lock_is_refused_as_it_arrives() {
    let mine = x_only(&wallet());
    let spk = p2pk(&mine);
    let mut req = request(100_000 * KAS, &spk, &[(90_000 * KAS, &spk)]);
    // The input's sequence, after the header, outpoint and amount.
    let at = MAGIC.len() + 2 + 2 + 2 + 8 + 20 + 8 + 2 + 32 + 4 + 8;
    req[at..at + 8].copy_from_slice(&2_592_000u64.to_le_bytes());
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    let out = deliver(&mut f, &req);
    let why = Refusal::Unshown(Unshown::RelativeLock);
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(out.screen, Screen::Refused(why));
    assert_eq!(
        why.words(),
        ("Cannot review", "Relative locks not shown yet")
    );
}

/// **What the review cannot show is said first**: a bundle input with a
/// relative lock and a sighash type other than ALL is refused for the lock.
#[test]
fn a_relative_lock_is_said_before_an_inputs_own_refusal() {
    let spk = p2pk(&x_only(&wallet()));
    let req = bundle_edited(
        &bundle_request(100_000 * KAS, &spk, &[(90_000 * KAS, &spk)]),
        |doc| {
            doc.replacen("\"sequence\":null", "\"sequence\":5", 1)
                .replacen("\"sighashType\":1,", "\"sighashType\":2,", 1)
        },
    );
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(
        f.state(),
        State::Refused(Refusal::Unshown(Unshown::RelativeLock))
    );
}

/// `req`, a bundle from [`bundle_request`], its document changed by `edit`.
fn bundle_edited(req: &[u8], edit: impl FnOnce(&str) -> String) -> Vec<u8> {
    let doc = decoded(req);
    let edited = edit(&doc);
    assert_ne!(edited, doc, "it had something to change");
    format!("PSKB{}", hex(edited.as_bytes())).into_bytes()
}

/// A bundle's document, from its envelope: `PSKB` and the hex of the JSON.
fn decoded(envelope: &[u8]) -> String {
    let doc = unhex(core::str::from_utf8(&envelope[4..]).expect("hex"));
    String::from_utf8(doc).expect("text")
}

/// A bundle spending one UTXO of `savings` to a stranger, as rusty-kaspa's
/// PSKB writes one: `redeemScript` the card's program, `minTime`
/// `lock_time`, `sequence` as given (`null`, none, is final).
fn savings_bundle(savings: &Savings, lock_time: u64, sequence: &str) -> Vec<u8> {
    let spk = savings.locking_script();
    let to = p2pk(&strangers_key());
    bundle_edited(
        &bundle_request(100_000 * KAS, &spk, &[(90_000 * KAS, &to)]),
        |doc| {
            doc.replacen(
                "\"sequence\":null,\"minTime\":null",
                &format!("\"sequence\":{sequence},\"minTime\":{lock_time}"),
                1,
            )
            .replacen(
                "\"redeemScript\":null,\"sigOpCount\":1",
                &format!(
                    "\"redeemScript\":\"{}\",\"sigOpCount\":1",
                    hex(&savings.program())
                ),
                1,
            )
        },
    )
}

/// **A card in a bundle is reviewed on its page and signed as in a KSPT**,
/// claim or recovery, the signature in `partialSigs`.
#[test]
fn a_card_in_a_bundle_is_reviewed_on_its_page_and_signed() {
    use kassigner_kaspa::address::Version;
    let mine = x_only(&wallet());
    let theirs = strangers_key();
    let opens = UnlockAt::new(SAVINGS_AT).unwrap();
    for (savings, recover) in [
        (Savings::new(mine, Some(theirs), opens).unwrap(), false),
        (Savings::new(theirs, Some(mine), opens).unwrap(), true),
    ] {
        let req = savings_bundle(&savings, opens.ms(), "0");
        let (pages, shown, reply) = savings_reviewed(&req);
        assert_eq!(pages, 4, "summary, card, output, lock time");
        let card_address = address_text(
            Version::ScriptHash,
            &kassigner_kaspa::script::redeem_hash(&savings.program()),
        );
        assert_eq!(
            shown,
            (
                card_address,
                opens.ms(),
                1,
                recover,
                Some(address_text(Version::PubKey, &theirs))
            )
        );
        assert!(reply.starts_with(b"PSKB"), "answered as a bundle");
        let text = decoded(&reply);
        assert!(
            text.contains(&format!("{}\":{{\"schnorr\":\"", hex(&mine))),
            "signed under this seed's key"
        );
    }
}

/// **A card in a bundle still locked is refused as it arrives**, as in a
/// KSPT: a lock time before it opens, or no sequence, which a bundle reads
/// as final.
#[test]
fn a_card_in_a_bundle_still_locked_is_refused_as_it_arrives() {
    use kassigner_fw::flow::CardLock;
    let mine = x_only(&wallet());
    let opens = UnlockAt::new(SAVINGS_AT).unwrap();
    let savings = Savings::new(mine, None, opens).unwrap();
    for (lock_time, sequence, lock) in [
        (opens.ms() - 1, "0", CardLock::Early),
        (opens.ms(), "null", CardLock::Final),
    ] {
        let req = savings_bundle(&savings, lock_time, sequence);
        let mut m = Memory::new();
        let mut f: Flow<'_, 1> = seeded(&mut m);
        f.step(scan(), &mut Live);
        let out = deliver(&mut f, &req);
        let why = Refusal::CardLocked(lock);
        assert_eq!(f.state(), State::Refused(why), "{sequence}");
        assert_eq!(out.screen, Screen::Refused(why));
        assert!(f.page(|_| ()).is_none(), "no review was started");
    }
}
