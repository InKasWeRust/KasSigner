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

//! A covenant card's backup line on the unit: scanned on Home, shown on
//! SAVINGS CARD's pages with its codes, saved as `CVnnnn.TXT` and opened
//! again from either Covenant Restore.

use super::*;

use kassigner_fw::flow::BATCH;
use kassigner_fw::limits::{KASSIGNER_FRAME_US, WALLET_FRAME_US};
use kassigner_fw::ui::backup::{self, pick_zone, Pick};
use kassigner_fw::ui::kpub::{self, Target as Card};
use kassigner_fw::ui::savings::{self, Seen, Target};
use kassigner_kaspa::address::{self as kaspa_address, Prefix, Version};
use kassigner_protocol::card::backup as card_line;
use kassigner_protocol::card::savings::{Savings, UnlockAt};
use kassigner_protocol::frame::{self, Format};

/// The SDK's card: abandon 12's receive 0 its owner, zoo 12's its
/// recovery wallet, opening on 01/01/2027 at 00:00 UTC.
const LINE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/vectors/v110/sdk/savings.backup"
));

/// A tap on one of SAVINGS CARD QR's cards, Wallet or KasSigner.
fn pick(card: Card) -> Event<'static> {
    tap_in(kpub::zone(SCALE, card).unwrap())
}

/// A tap on one of SAVINGS CARD's targets at `page`, pressed and lifted.
fn on(f: &mut Flow<'_, 6>, page: usize, file: bool, t: Target) -> kassigner_fw::flow::Output {
    let z = savings::zone(SCALE, (page, file), t).expect("a target there");
    f.touch(tap_in(z))
}

/// A key's address, as the card shows it.
fn key_text(key: &[u8; 32]) -> String {
    let mut out = [0u8; 80];
    let n = kaspa_address::encode(Prefix::Mainnet, Version::PubKey, key, &mut out).unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// What SAVINGS CARD shows: its card's address, its owner's, its recovery
/// wallet's, where each is in the seed in use, and whether from a file.
fn shown(f: &Flow<'_, 6>) -> Option<(String, String, Option<String>, Seen, Seen, bool)> {
    let mut texts = savings::NO_TEXTS;
    let s = f.savings_shown(&mut texts)?;
    Some((
        s.address.to_string(),
        s.owner.to_string(),
        s.recovery.map(str::to_string),
        s.owner_seen,
        s.recovery_seen,
        s.file,
    ))
}

/// The card `line` rebuilds, as SAVINGS CARD would show it with `seen`.
fn expected(
    line: &[u8],
    seen: (Seen, Seen),
    file: bool,
) -> (String, String, Option<String>, Seen, Seen, bool) {
    let card = card_line::read(line).unwrap();
    let mut address = [0u8; 80];
    let n = card.address(&mut address).unwrap();
    (
        String::from_utf8(address[..n].to_vec()).unwrap(),
        key_text(card.owner()),
        card.recovery().map(key_text),
        seen.0,
        seen.1,
        file,
    )
}

/// Scan `line` from Home.
fn scan_line(f: &mut Flow<'_, 6>, line: &[u8]) -> kassigner_fw::flow::Output {
    f.step(scan(), &mut Live);
    let out = f.step(Event::Code(line), &mut Live);
    assert_eq!(out.command, Some(Command::CameraOff));
    out
}

/// A backup line scanned on Home opens SAVINGS CARD: card, owner and
/// recovery pages, the arrows stopping at either end. Each key's place in
/// the seed in use is found as it is read: abandon 12 holds the owner's at
/// receive 0, not the recovery wallet's; zoo 12 the reverse; with no seed
/// nothing is said. The first page's address is its own code. Show QR gives
/// two version-9 frames for a wallet and five version-3 for a unit, which
/// another unit's home scanner reads back as the card. Back lets the card
/// go. Whitespace around the line does not matter.
#[test]
fn a_backup_line_scanned_on_home_shows_its_card() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);

    let out = scan_line(&mut f, LINE);
    assert_eq!(out.screen, Screen::Savings { page: 0 });
    assert_eq!(
        shown(&f),
        Some(expected(LINE, (Seen::At(0), Seen::Missed(20)), false))
    );

    // The pages, and their ends.
    for (t, page) in [
        (Target::Next, 1),
        (Target::Next, 2),
        (Target::Next, 2),
        (Target::Previous, 1),
        (Target::Previous, 0),
        (Target::Previous, 0),
    ] {
        let State::Savings { page: at } = f.state() else {
            panic!("{:?}", f.state())
        };
        on(&mut f, usize::from(at), false, t);
        assert_eq!(f.state(), State::Savings { page }, "{t:?} from {at}");
    }

    // Its address's code, and back to the first page.
    let out = on(&mut f, 0, false, Target::Address);
    assert_eq!(out.screen, Screen::SavingsAddressQr);
    let (address, ..) = expected(LINE, (Seen::NoSeed, Seen::NoSeed), false);
    assert_eq!(
        read_back(&f.savings_address_code().unwrap()),
        address.as_bytes()
    );
    f.step(tap_in(chrome::corner(SCALE, Nav::Back)), &mut Live);
    assert_eq!(f.state(), State::Savings { page: 0 });

    // Its line's codes, from the second page: SAVINGS CARD QR, Back to it.
    on(&mut f, 0, false, Target::Next);
    let out = on(&mut f, 1, false, Target::Show);
    assert_eq!(out.screen, Screen::SavingsFormat);
    assert_eq!(f.state(), State::SavingsFormat { page: 1 });
    assert_eq!((f.savings_codes(true), f.savings_codes(false)), (2, 5));
    f.step(tap_in(chrome::corner(SCALE, Nav::Back)), &mut Live);
    assert_eq!(f.state(), State::Savings { page: 1 }, "Back, the page");
    on(&mut f, 1, false, Target::Show);
    f.step(pick(Card::Wallet), &mut Live);
    assert_eq!(f.state(), State::SavingsMode { page: 1 });
    f.touch(tap_in(chrome::corner(SCALE, Nav::Back)));
    assert_eq!(
        f.state(),
        State::SavingsFormat { page: 1 },
        "Back, the card"
    );
    for (card, frames, most, every, mode) in [
        (
            Card::Wallet,
            2u8,
            53,
            WALLET_FRAME_US,
            dialog::Target::Accept,
        ),
        (
            Card::KasSigner,
            5,
            29,
            KASSIGNER_FRAME_US,
            dialog::Target::Cancel,
        ),
    ] {
        assert_eq!(f.state(), State::SavingsFormat { page: 1 });
        f.step(pick(card), &mut Live);
        assert_eq!(f.state(), State::SavingsMode { page: 1 }, "{card:?}");
        let out = f.touch(answer(mode));
        assert_eq!(out.screen, Screen::SavingsFrames { frame: 0, frames });
        let mut joined = Vec::new();
        for i in 0..frames {
            assert_eq!(f.state(), State::SavingsFrames { page: 1, frame: i });
            let code = f.savings_frame(i).unwrap();
            if card == Card::Wallet {
                assert_eq!(code.size, most, "every wallet frame at version 9");
            } else {
                assert!(code.size <= most, "{} modules", code.size);
            }
            let bytes = read_back(&code);
            let read = frame::parse(&bytes, 64).expect("a frame");
            assert_eq!(read.format, Format::Opaque);
            assert_eq!((read.index, read.total), (i, frames));
            joined.extend_from_slice(read.fragment);
            if mode == dialog::Target::Accept {
                // Manual: a tap a frame, the last's back to the page.
                f.step(tap_in(SCALE.zone(100, 100, 10, 10)), &mut Live);
            } else {
                let now_us = f.now_us() + every;
                f.step(Event::Tick { now_us }, &mut Live);
            }
        }
        assert_eq!(joined, LINE, "{card:?}: the line");
        if mode == dialog::Target::Cancel {
            assert_eq!(
                f.state(),
                State::SavingsFrames { page: 1, frame: 0 },
                "round"
            );
            f.step(tap_in(SCALE.zone(100, 100, 10, 10)), &mut Live);
        }
        assert_eq!(
            f.state(),
            State::Savings { page: 1 },
            "the page it came from"
        );

        // Another unit's home scanner, given the frames joined.
        let mut m = Memory::new();
        let mut other: Flow<'_, 6> = booted(&mut m, &[]);
        other.step(scan(), &mut Live);
        let out = other.step(Event::Opaque(&joined), &mut Live);
        assert_eq!(out.screen, Screen::Savings { page: 0 }, "{card:?}");
        assert_eq!(
            shown(&other),
            Some(expected(LINE, (Seen::NoSeed, Seen::NoSeed), false))
        );
        on(&mut f, 1, false, Target::Show);
    }
    f.step(tap_in(chrome::corner(SCALE, Nav::Back)), &mut Live);
    assert_eq!(f.state(), State::Savings { page: 1 });
    assert_eq!(
        savings::zone(SCALE, (1, false), Target::Address),
        None,
        "the address is a tap on the first page only"
    );

    // Back: the card let go, home.
    on(&mut f, 1, false, Target::Nav(Nav::Back));
    assert_eq!(f.state(), State::Home);
    assert_eq!(shown(&f), None);

    // With line ends around it, as text, and Home from the last page.
    let mut padded = b"  ".to_vec();
    padded.extend_from_slice(LINE);
    padded.extend_from_slice(b"\r\n");
    scan_line(&mut f, &padded);
    assert_eq!(f.state(), State::Savings { page: 0 });
    on(&mut f, 0, false, Target::Next);
    on(&mut f, 1, false, Target::Next);
    on(&mut f, 2, false, Target::Nav(Nav::Home));
    assert_eq!(f.state(), State::Home);
    assert_eq!(shown(&f), None);

    // Zoo 12 in use: the recovery wallet's key, not the owner's.
    load(&mut f, corpus!("seedqr/zoo12.standard"));
    f.step(home_button(), &mut Live);
    scan_line(&mut f, LINE);
    assert_eq!(
        shown(&f),
        Some(expected(LINE, (Seen::Missed(20), Seen::At(0)), false))
    );

    // No seed in use: nothing said of either.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    scan_line(&mut f, LINE);
    assert_eq!(
        shown(&f),
        Some(expected(LINE, (Seen::NoSeed, Seen::NoSeed), false))
    );
}

/// A card with no recovery wallet has two pages, no RECOVERY. It opens at a
/// time of day, shown to the minute; its line fits one code for a wallet
/// and four frames for a unit. Home from SAVINGS CARD QR lets the card go.
#[test]
fn a_card_with_no_recovery_wallet_has_two_pages() {
    let owner = card_line::read(LINE).unwrap();
    let card = Savings::new(
        *owner.owner(),
        None,
        UnlockAt::from_date_time(2027, 1, 1, 14, 30).unwrap(),
    )
    .unwrap();
    let mut line = [0u8; card_line::MAX_LEN];
    let n = card_line::write(&card, &mut line).unwrap();
    let line = &line[..n];
    assert!(line.windows(6).any(|w| w == b",none,"));

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    scan_line(&mut f, line);
    assert_eq!(
        shown(&f),
        Some(expected(line, (Seen::NoSeed, Seen::NoSeed), false))
    );
    on(&mut f, 0, false, Target::Next);
    assert_eq!(f.state(), State::Savings { page: 1 });
    on(&mut f, 1, false, Target::Next);
    assert_eq!(f.state(), State::Savings { page: 1 }, "no third page");
    let mut texts = savings::NO_TEXTS;
    let s = f.savings_shown(&mut texts).unwrap();
    assert_eq!(s.unlock, 1_798_813_800_000, "01/01/2027 14:30 UTC");

    on(&mut f, 1, false, Target::Show);
    assert_eq!((f.savings_codes(true), f.savings_codes(false)), (1, 4));
    let out = f.step(pick(Card::Wallet), &mut Live);
    assert_eq!(
        out.screen,
        Screen::SavingsFrames {
            frame: 0,
            frames: 1
        }
    );
    assert_eq!(read_back(&f.savings_frame(0).unwrap()), line);
    f.step(tap_in(SCALE.zone(100, 100, 10, 10)), &mut Live);
    assert_eq!(f.state(), State::Savings { page: 1 });
    on(&mut f, 1, false, Target::Show);
    f.step(tap_in(chrome::corner(SCALE, Nav::Home)), &mut Live);
    assert_eq!(f.state(), State::Home);
    assert_eq!(shown(&f), None, "the card let go");
}

/// A raw key is one key: the card's key matching it is at receive 0, the
/// other not found.
#[test]
fn a_raw_key_is_found_as_its_one_key() {
    let w = wallet();
    let owner = card_line::read(LINE).unwrap();
    let card = Savings::new(
        *owner.owner(),
        Some(x_only(&w)),
        UnlockAt::from_date_time(2027, 1, 1, 0, 0).unwrap(),
    )
    .unwrap();
    let mut line = [0u8; card_line::MAX_LEN];
    let n = card_line::write(&card, &mut line).unwrap();
    let line = &line[..n];

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    raw_key_keyboard(&mut f);
    type_hex(&mut f, &private_hex(&w, Path::receive(0)));
    let out = f.step(hex_key(&f, keyboard::Key::Ok), &mut Live);
    settled(&mut f, out);
    read(&mut f);
    f.touch(answer(dialog::Target::Accept));
    while matches!(f.state(), State::Opening { .. }) {
        f.step(
            Event::Tick {
                now_us: 2_000_000_000,
            },
            &mut Live,
        );
    }
    f.step(home_button(), &mut Live);
    scan_line(&mut f, line);
    assert_eq!(
        shown(&f),
        Some(expected(line, (Seen::NotFound, Seen::At(0)), false))
    );
}

/// A card's line for `owner` and `recovery`, opening on 01/01/2027 at
/// 00:00 UTC.
fn card_of(owner: [u8; 32], recovery: Option<[u8; 32]>) -> Vec<u8> {
    let card = Savings::new(
        owner,
        recovery,
        UnlockAt::from_date_time(2027, 1, 1, 0, 0).unwrap(),
    )
    .unwrap();
    let mut line = [0u8; card_line::MAX_LEN];
    let n = card_line::write(&card, &mut line).unwrap();
    line[..n].to_vec()
}

/// Where SAVINGS CARD says the card's two keys are.
fn seen(f: &Flow<'_, 6>) -> (Seen, Seen) {
    let (.., owner, recovery, _) = shown(f).expect("a card held");
    (owner, recovery)
}

/// Ticks until SAVINGS CARD's search ends, the clock still: a batch's
/// keys at two a tick, and the tick that ends it, at most.
fn searched(f: &mut Flow<'_, 6>) {
    for _ in 0..=BATCH / 2 {
        if !matches!(f.state(), State::SavingsSearching { .. }) {
            return;
        }
        let now_us = f.now_us();
        f.step(Event::Tick { now_us }, &mut Live);
    }
    panic!("the search went past its batch: {:?}", f.state());
}

/// A card's key past the keys at hand is searched for on its page. Scanned
/// with nothing derived ahead, both keys are missed past receive 19, the
/// bank's last. The owner's SEARCH PAST searches the next 200 receive keys,
/// two a tick, for both keys; only Back and Home act meanwhile. The owner's,
/// at receive 150, ends it there, the recovery wallet's then missed past
/// 150. Its own search goes on from 151, a batch a tap, to 999: then
/// not in the seed, its button gone. A tap on a key found or not in the
/// seed does nothing.
#[test]
fn a_card_key_past_the_keys_at_hand_is_searched_for() {
    let w = wallet();
    let deep = w.signing_key(Path::receive(150)).unwrap().x_only();
    let other = *card_line::read(LINE).unwrap().owner();
    let line = card_of(deep, Some(other));

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    scan_line(&mut f, &line);
    assert_eq!(seen(&f), (Seen::Missed(20), Seen::Missed(20)));
    assert_eq!(savings::zone(SCALE, (0, false), Target::Search), None);

    on(&mut f, 0, false, Target::Next);
    let out = on(&mut f, 1, false, Target::Search);
    assert_eq!(
        f.state(),
        State::SavingsSearching {
            page: 1,
            next: 20,
            stop: 220
        }
    );
    assert_eq!(out.screen, Screen::SavingsSearching { page: 1, at: 20 });
    assert_eq!(seen(&f), (Seen::Searching(20), Seen::Searching(20)));
    let now_us = f.now_us();
    let out = f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(out.screen, Screen::SavingsSearching { page: 1, at: 22 });
    for t in [
        Target::Previous,
        Target::Next,
        Target::Save,
        Target::Show,
        Target::Search,
    ] {
        on(&mut f, 1, false, t);
        assert!(
            matches!(f.state(), State::SavingsSearching { page: 1, .. }),
            "{t:?}"
        );
    }
    searched(&mut f);
    assert_eq!(f.state(), State::Savings { page: 1 });
    assert_eq!(seen(&f), (Seen::At(150), Seen::Missed(151)));
    on(&mut f, 1, false, Target::Search);
    assert_eq!(
        f.state(),
        State::Savings { page: 1 },
        "found: nothing to do"
    );

    on(&mut f, 1, false, Target::Next);
    for (from, to) in [(151, 351), (351, 551), (551, 751), (751, 951)] {
        on(&mut f, 2, false, Target::Search);
        assert_eq!(
            f.state(),
            State::SavingsSearching {
                page: 2,
                next: from,
                stop: to
            }
        );
        searched(&mut f);
        assert_eq!(seen(&f), (Seen::At(150), Seen::Missed(to)));
    }
    on(&mut f, 2, false, Target::Search);
    assert_eq!(
        f.state(),
        State::SavingsSearching {
            page: 2,
            next: 951,
            stop: 1000
        },
        "the last batch stops where every search does"
    );
    searched(&mut f);
    assert_eq!(f.state(), State::Savings { page: 2 });
    assert_eq!(seen(&f), (Seen::At(150), Seen::NotFound));
    on(&mut f, 2, false, Target::Search);
    assert_eq!(f.state(), State::Savings { page: 2 }, "not in the seed");
}

/// Back and Home stop SAVINGS CARD's search and let the card go: a scanned
/// card goes home either way.
#[test]
fn back_and_home_stop_a_card_search() {
    let other = *card_line::read(LINE).unwrap().owner();
    let line = card_of(other, None);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    for nav in [Nav::Back, Nav::Home] {
        scan_line(&mut f, &line);
        on(&mut f, 0, false, Target::Next);
        on(&mut f, 1, false, Target::Search);
        let now_us = f.now_us();
        f.step(Event::Tick { now_us }, &mut Live);
        assert!(matches!(f.state(), State::SavingsSearching { .. }));
        on(&mut f, 1, false, Target::Nav(nav));
        assert_eq!(f.state(), State::Home, "{nav:?}");
        assert_eq!(shown(&f), None, "the card let go");
    }
}

/// The receive keys the idle pump derived are looked through as the card
/// is read: sixty ticks on Home derive receive 20 to 69, then change 5 to
/// 14. A key at receive 30 is found at once; one not among them is missed
/// past receive 69 (change keys do not count), its search starting at 70.
#[test]
fn the_keys_derived_ahead_are_looked_through_as_a_card_is_read() {
    let w = wallet();
    let near = w.signing_key(Path::receive(30)).unwrap().x_only();
    let other = *card_line::read(LINE).unwrap().owner();
    let line = card_of(near, Some(other));

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    for _ in 0..60 {
        let now_us = f.now_us();
        f.step(Event::Tick { now_us }, &mut Live);
    }
    scan_line(&mut f, &line);
    assert_eq!(seen(&f), (Seen::At(30), Seen::Missed(70)));
    on(&mut f, 0, false, Target::Next);
    on(&mut f, 1, false, Target::Next);
    on(&mut f, 2, false, Target::Search);
    assert_eq!(
        f.state(),
        State::SavingsSearching {
            page: 2,
            next: 70,
            stop: 270
        }
    );
}

/// A line that does not rebuild its card is refused with the reason:
/// another card's address, a minute apart, a date written another way or
/// without a time, a key that is not a key's address, a field missing.
/// ERROR says "Card backup not read" and the reader's reason; then home,
/// nothing held.
#[test]
fn a_backup_line_that_is_not_its_card_is_refused() {
    let text = core::str::from_utf8(LINE).unwrap();
    let card_at = text.rfind(",kaspa:p").unwrap() + 1;
    let other = {
        let card = card_line::read(LINE).unwrap();
        let theirs = Savings::new(
            *card.owner(),
            None,
            UnlockAt::from_date_time(2027, 1, 1, 0, 1).unwrap(),
        )
        .unwrap();
        let mut out = [0u8; 80];
        let n = theirs.address(&mut out).unwrap();
        String::from_utf8(out[..n].to_vec()).unwrap()
    };
    let swapped = format!("{}{other})", &text[..card_at]);
    let early = text.replace("01/01/2027", "1/1/2027");
    let untimed = text.replace("01/01/2027 00:00", "01/01/2027");
    let not_a_key = text.replacen("kaspa:q", "kaspa:p", 1);
    let short = format!("{})", &text[..card_at - 1]);
    let cases = [
        (swapped.as_str(), Some(card_line::BackupError::NotTheCard)),
        (early.as_str(), Some(card_line::BackupError::BadDate)),
        (untimed.as_str(), Some(card_line::BackupError::BadDate)),
        (not_a_key.as_str(), None),
        (short.as_str(), None),
    ];
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    for (line, why) in cases {
        let read = card_line::read(line.as_bytes()).unwrap_err();
        if let Some(why) = why {
            assert_eq!(read, why, "{line}");
        }
        let out = scan_line(&mut f, line.as_bytes());
        assert_eq!(
            out.screen,
            Screen::Refused(Refusal::CardBackup(read)),
            "{line}"
        );
        let (first, second) = Refusal::CardBackup(read).words();
        assert_eq!(first, "Card backup not read");
        assert!(!second.is_empty(), "why, for {read:?}");
        assert_eq!(shown(&f), None, "nothing held");
        let now_us = f.now_us() + ERROR_US;
        f.step(Event::Tick { now_us }, &mut Live);
        assert_eq!(f.state(), State::Home);
    }
}

/// Home from a card's save, on ENCRYPT FILE? or the overwrite question,
/// lets the card go, as SAVINGS CARD's Home does.
#[test]
fn home_from_a_card_save_lets_the_card_go() {
    let mut sd = card_with(&[(b"CV0001  TXT", LINE)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);

    // ENCRYPT FILE?, for a name the card has no file of.
    scan_line(&mut f, LINE);
    assert!(f.savings_address_code().is_some(), "the card held");
    on(&mut f, 0, false, Target::Save);
    run_job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "CV0002");
    press(&mut f, keyboard::Key::Ok);
    run_job(&mut f, &mut sd, Job::Exists);
    assert_eq!(f.state(), State::KpubEncrypt, "ENCRYPT FILE?");
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);
    assert!(f.savings_address_code().is_none(), "the card let go");

    // The overwrite question, for a name the card has.
    scan_line(&mut f, LINE);
    on(&mut f, 0, false, Target::Save);
    run_job(&mut f, &mut sd, Job::NextName);
    name_as(&mut f, &mut sd, b"CV0001");
    assert_eq!(f.state(), State::BackupOverwrite);
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);
    assert!(f.savings_address_code().is_none(), "the card let go");
}

/// Save to SD writes the line alone as `CVnnnn.TXT`, plain or sealed as
/// text, then "!! Card Saved !!" and the card again. Both Covenant Restore
/// rows list only `CV` files holding a line, plain or sealed as text; a
/// row asks its password (nothing typed for a plain one) and opens the
/// card with Show QR alone, Back being the list. A sealed file opening to
/// something else fails as Card Load Failed, saying why. An empty list
/// goes back to the menu, on its row's page.
#[test]
fn a_card_is_saved_to_the_sd_card_and_restored() {
    use kassigner_crypto::container::open;
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_protocol::container::{parse, Purpose};
    let password = b"Correct-Horse-9";
    let answer_at = |t| tap_in(dialog::zone(SCALE, t).unwrap());
    let sealed_text = |text: &[u8]| {
        let mut out = [0u8; 512];
        let n = seal(
            Purpose::Text,
            text,
            password,
            &[1; 16],
            &[2; 12],
            SealKdf::Pbkdf2Sha256,
            &mut out,
        )
        .unwrap();
        out[..n].to_vec()
    };
    let mut sd = card_with(&[]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);
    let mut t = f.now_us();

    // Plain, CV0001: the line alone.
    scan_line(&mut f, LINE);
    on(&mut f, 0, false, Target::Next);
    let out = on(&mut f, 1, false, Target::Save);
    assert_eq!(out.command, Some(Command::Card(Job::NextName)));
    run_job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "CV0001");
    assert_eq!(
        press(&mut f, keyboard::Key::Ok).command,
        Some(Command::Card(Job::Exists))
    );
    run_job(&mut f, &mut sd, Job::Exists);
    assert_eq!(f.state(), State::KpubEncrypt, "ENCRYPT FILE?");
    assert_eq!(
        f.touch(answer_at(dialog::Target::Accept)).command,
        Some(Command::Card(Job::Write))
    );
    run_job(&mut f, &mut sd, Job::Write);
    assert_eq!(f.saved_text(), "!! Card Saved !!");
    assert_eq!(on_card(&mut sd, b"CV0001  TXT"), LINE);
    t += 10_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    assert_eq!(f.state(), State::Savings { page: 1 }, "the card again");

    // Sealed, CV0002: as text, opening to the line.
    on(&mut f, 1, false, Target::Save);
    run_job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "CV0002");
    press(&mut f, keyboard::Key::Ok);
    run_job(&mut f, &mut sd, Job::Exists);
    f.touch(answer_at(dialog::Target::Cancel));
    for _ in 0..2 {
        type_on(&mut f, password);
        press(&mut f, keyboard::Key::Ok);
    }
    while matches!(f.state(), State::BackupSealing { .. }) {
        f.step(Event::Tick { now_us: t }, &mut Live);
    }
    run_job(&mut f, &mut sd, Job::Write);
    assert_eq!(f.saved_text(), "!! Card Saved !!");
    let sealed = on_card(&mut sd, b"CV0002  TXT");
    assert_eq!(parse(&sealed).unwrap().purpose, Purpose::Text);
    let mut text = vec![0u8; sealed.len()];
    let opened = open(&sealed, password, &mut text, None).unwrap();
    assert_eq!(&text[..opened.len], LINE);
    t += 10_000_000;
    f.step(Event::Tick { now_us: t }, &mut Live);
    assert_eq!(f.state(), State::Savings { page: 1 });
    on(&mut f, 1, false, Target::Nav(Nav::Home));

    // Other files beside the two saved: text in a card's name, sealed text
    // that is not a line, a group's address, a line in another name.
    {
        use kassigner_fat32::fat32::{create_file, mount_fat32};
        let info = mount_fat32(&mut sd).unwrap();
        let sealed = sealed_text(b"hello");
        for (name, bytes) in [
            (b"CV0003  TXT", &b"hello"[..]),
            (b"CV0004  TXT", &sealed[..]),
            (
                b"MS0001  TXT",
                &b"kaspa:prvfzy9wjlewtyk9qeczkd0ehyxfcycxz9c99yr2x3nu7uk6zw872c06xr7d9"[..],
            ),
            (b"XX0001  TXT", LINE),
        ] {
            create_file(&mut sd, &info, name, bytes).unwrap();
        }
    }

    // Import's Covenant Restore: the cards' files, and only those.
    let tools = |f: &mut Flow<'_, 6>| {
        f.touch(home_button());
        f.step(card(2), &mut Live);
        f.step(item(&menu::TOOLS, 1), &mut Live);
        f.step(
            tap_in(backup::zone(SCALE, backup::Target::Import).unwrap()),
            &mut Live,
        );
    };
    tools(&mut f);
    let out = f.step(item(&menu::IMPORT, 3), &mut Live);
    assert_eq!(out.command, Some(Command::Card(Job::ListCards)));
    run_job(&mut f, &mut sd, Job::ListCards);
    assert_eq!(f.list_title(), "SELECT CARD");
    assert_eq!(
        f.backups(),
        &[*b"CV0001  TXT", *b"CV0002  TXT", *b"CV0004  TXT"],
        "a line, or sealed as text; not hello, nor other names"
    );
    let at = |f: &Flow<'_, 6>, name: &[u8; 11]| {
        let i = f.backups().iter().position(|b| b == name).unwrap();
        tap_in(pick_zone(SCALE, f.backups().len(), 0, Pick::Row(i)).unwrap())
    };
    let opened = |f: &mut Flow<'_, 6>, sd: &mut Sd, typed: &[u8]| {
        restore_type(f, typed);
        assert_eq!(restore_ok(f).command, Some(Command::Card(Job::Read)));
        run_job(f, sd, Job::Read);
        while matches!(f.state(), State::RestoreOpening { .. }) {
            let now_us = f.now_us();
            f.step(Event::Tick { now_us }, &mut Live);
        }
    };

    // Plain: nothing typed; Show QR alone; Back, the list.
    f.step(at(&f, b"CV0001  TXT"), &mut Live);
    opened(&mut f, &mut sd, b"");
    assert_eq!(f.state(), State::Savings { page: 0 });
    assert_eq!(
        shown(&f),
        Some(expected(LINE, (Seen::At(0), Seen::Missed(20)), true))
    );
    assert_eq!(savings::zone(SCALE, (0, true), Target::Save), None);
    let out = on(&mut f, 0, true, Target::Show);
    assert_eq!(out.screen, Screen::SavingsFormat, "as for a card scanned");
    f.step(tap_in(chrome::corner(SCALE, Nav::Back)), &mut Live);
    assert_eq!(f.state(), State::Savings { page: 0 });
    on(&mut f, 0, true, Target::Nav(Nav::Back));
    assert_eq!(f.state(), State::RestoreList { page: 0 });

    // Sealed: its password.
    f.step(at(&f, b"CV0002  TXT"), &mut Live);
    opened(&mut f, &mut sd, password);
    assert_eq!(
        shown(&f),
        Some(expected(LINE, (Seen::At(0), Seen::Missed(20)), true))
    );
    on(&mut f, 0, true, Target::Nav(Nav::Back));

    // Sealed over something else: Card Load Failed, and why.
    f.step(at(&f, b"CV0004  TXT"), &mut Live);
    opened(&mut f, &mut sd, password);
    assert_eq!(
        f.state(),
        State::CardDone {
            job: Job::Read,
            outcome: Outcome::Failed(card::Error::Backup("Not a card's backup line")),
        }
    );
    assert_eq!(f.card_said().failed, "Card Load Failed");
    let now_us = f.now_us() + 10_000_000;
    f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(f.state(), State::RestoreList { page: 0 });

    // The trash: the password, then the hold; the list is what is left.
    let trash = |f: &Flow<'_, 6>, name: &[u8; 11]| {
        let i = f.backups().iter().position(|b| b == name).unwrap();
        tap_in(pick_zone(SCALE, f.backups().len(), 0, Pick::Trash(i)).unwrap())
    };
    f.step(trash(&f, b"CV0001  TXT"), &mut Live);
    opened(&mut f, &mut sd, b"");
    assert!(
        matches!(f.state(), State::RestoreDelete { .. }),
        "the delete asked, not the card shown: {:?}",
        f.state()
    );
    assert_eq!(shown(&f), None);
    let Event::Tap { x, y } = answer(dialog::Target::Accept) else {
        unreachable!()
    };
    f.step(answer(dialog::Target::Accept), &mut Live);
    let now_us = f.now_us() + 1_000_000;
    f.step(Event::Tick { now_us }, &mut Live);
    f.step(Event::Press { x, y }, &mut Live);
    let out = f.step(
        Event::Tick {
            now_us: now_us + HOLD_US,
        },
        &mut Live,
    );
    assert_eq!(out.command, Some(Command::Card(Job::Delete)));
    f.step(Event::Tap { x, y }, &mut Live);
    assert_eq!(
        run_job(&mut f, &mut sd, Job::Delete).command,
        Some(Command::Card(Job::ListCards)),
        "the cards listed again"
    );
    run_job(&mut f, &mut sd, Job::ListCards);
    assert_eq!(f.backups(), &[*b"CV0002  TXT", *b"CV0004  TXT"]);

    // Import from SD's row, on its second page; an empty card goes back
    // there, and Import's to Import.
    let mut empty = card_with(&[]);
    tools(&mut f);
    f.step(item(&menu::IMPORT, 0), &mut Live);
    let down = menu::zone(SCALE, &menu::IMPORT_SD, 0, menu::Target::Nav(Nav::PageDown));
    f.step(tap_in(down.expect("a second page")), &mut Live);
    let out = f.step(item(&menu::IMPORT_SD, 5), &mut Live);
    assert_eq!(out.command, Some(Command::Card(Job::ListCards)));
    run_job(&mut f, &mut empty, Job::ListCards);
    assert_eq!(f.card_said().empty, ("No card backups found", ""));
    let now_us = f.now_us() + 10_000_000;
    f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::ImportSd,
            page: 1
        }
    );
    tools(&mut f);
    f.step(item(&menu::IMPORT, 3), &mut Live);
    run_job(&mut f, &mut empty, Job::ListCards);
    let now_us = f.now_us() + 10_000_000;
    f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Import,
            page: 0
        }
    );
}
