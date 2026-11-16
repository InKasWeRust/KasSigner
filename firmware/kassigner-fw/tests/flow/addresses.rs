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

//! Addresses: the seed's own and KCC-3's, the keypad, and ADDRESS EXPORTED.

use super::*;

/// A deferred tap's work is done before the next event: a press before the
/// tick gets the new address first, then counts on its screen.
#[test]
fn a_tap_that_waits_is_done_before_the_next_event() {
    use kassigner_fw::ui::address as screen;
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    seed_tool(&mut f, 3);
    let after = tap_in(screen::zone(SCALE, false, true, screen::Target::After).unwrap());
    let out = f.step(after, &mut Live);
    assert_eq!(out.command, Some(Command::Deferred));
    assert_eq!(
        out.screen,
        Screen::Address {
            change: false,
            index: 0,
            single: false
        }
    );
    assert_eq!(f.address_text(), address_of(Path::receive(0)));
    let (x, y) = point(after);
    let out = f.step(Event::Press { x, y }, &mut Live);
    assert_eq!(
        out.screen,
        Screen::Address {
            change: false,
            index: 1,
            single: false
        }
    );
    assert_eq!(out.command, None);
    assert_eq!(f.address_text(), address_of(Path::receive(1)));
    // Lifting there is ">" again, on index 1.
    let out = f.step(after, &mut Live);
    let out = settled(&mut f, out);
    assert_eq!(
        out.screen,
        Screen::Address {
            change: false,
            index: 2,
            single: false
        }
    );
}

/// Seed Tools' Address: refused with no seed. With one, ">" and "<" step
/// (no "<" at index 0), Receive or Change switches chain back to 0, the
/// keypad takes up to five digits past the bank without wrapping, the code
/// shows and returns, and Back goes where the tool was opened from.
#[test]
fn the_address_tool_shows_every_address() {
    use kassigner_fw::ui::{address as screen, keypad};
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    seed_tool(&mut f, 3);
    assert_eq!(
        f.state(),
        State::Refused(Refusal::NoWallet),
        "no seed in use"
    );

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    seed_tool(&mut f, 3);
    assert_eq!(f.state(), State::Address);
    assert_eq!(f.address_text(), address_of(Path::receive(0)));

    let on = |t, first| tap_in(screen::zone(SCALE, false, first, t).expect("on the screen"));
    // A move: the address comes on the tick after the tap.
    let moved = |f: &mut Flow<'_, 6>, e| {
        let out = f.step(e, &mut Live);
        settled(f, out)
    };
    assert!(
        screen::zone(SCALE, false, true, screen::Target::Before).is_none(),
        "< at #0"
    );
    moved(&mut f, on(screen::Target::After, true));
    assert_eq!(f.address_text(), address_of(Path::receive(1)));
    moved(&mut f, on(screen::Target::Before, false));
    assert_eq!(f.address_text(), address_of(Path::receive(0)));

    moved(&mut f, on(screen::Target::After, true));
    let out = moved(&mut f, on(screen::Target::Chain, false));
    assert_eq!(
        out.screen,
        Screen::Address {
            change: true,
            index: 0,
            single: false
        }
    );
    assert_eq!(f.address_text(), address_of(Path::change(0)));

    // The keypad: 25, past the bank's five change keys.
    f.step(on(screen::Target::Index, true), &mut Live);
    assert_eq!(f.state(), State::AddressIndex);
    let key = |k| tap_in(keypad::zone(SCALE, keypad::Target::Key(k)).unwrap());
    f.step(key(keypad::Key::Digit(2)), &mut Live);
    f.step(key(keypad::Key::Digit(5)), &mut Live);
    moved(&mut f, key(keypad::Key::Go));
    assert_eq!(f.state(), State::Address);
    assert_eq!(f.address_text(), address_of(Path::change(25)));

    // Five digits at most, and an index past 65,535 is not wrapped.
    f.step(on(screen::Target::Index, false), &mut Live);
    for _ in 0..7 {
        f.step(key(keypad::Key::Digit(9)), &mut Live);
    }
    let out = f.step(Event::Tick { now_us: 1 }, &mut Live);
    assert_eq!(
        out.screen,
        Screen::AddressIndex {
            typed: Hidden(*b"99999"),
            len: 5
        }
    );
    f.step(key(keypad::Key::Clear), &mut Live);
    for d in [7, 0, 0, 0, 0] {
        f.step(key(keypad::Key::Digit(d)), &mut Live);
    }
    moved(&mut f, key(keypad::Key::Go));
    assert_eq!(
        f.address_text(),
        address_of(Path::change(70_000)),
        "past 65,535"
    );

    // The code, ADDRESS EXPORTED after it, and back.
    f.step(on(screen::Target::Address, false), &mut Live);
    assert_eq!(f.state(), State::AddressQr);
    let code_tap = || tap_in(screen::zone(SCALE, false, false, screen::Target::Address).unwrap());
    f.step(code_tap(), &mut Live);
    assert_eq!(f.state(), State::AddressDone);
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::AddressQr, "Back to QR");
    f.step(code_tap(), &mut Live);
    f.touch(answer(dialog::Target::Nav(Nav::Back)));
    assert_eq!(f.state(), State::Address);

    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedTools,
            page: 0
        }
    );

    // From the seeds screen, back to it.
    f.step(home_button(), &mut Live);
    f.step(card(1), &mut Live);
    let rows: Vec<_> = (0..f.seed_count()).filter_map(|i| f.seed(i)).collect();
    f.step(
        tap_in(seeds::zone(SCALE, &rows, 6, 0, seeds::Target::Address).unwrap()),
        &mut Live,
    );
    assert_eq!(f.state(), State::Address);
    assert_eq!(
        f.address_text(),
        address_of(Path::receive(0)),
        "from #0 again"
    );
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::Seeds { page: 0 });
}

/// The test seed's KCC-3 address at `path`: the hash of `<P> OP_CHECKSIG`
/// as a script-hash address.
fn kcc3_address_of(path: Path) -> String {
    use kassigner_kaspa::address::{encode, Prefix, Version, MAX_ADDRESS_LEN};
    use kassigner_kaspa::script::kcc3_script_hash;
    let key = wallet().signing_key(path).unwrap().x_only();
    let mut out = [0u8; MAX_ADDRESS_LEN];
    let n = encode(
        Prefix::Mainnet,
        Version::ScriptHash,
        &kcc3_script_hash(&key),
        &mut out,
    )
    .unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// KCC-3 Address shows the seed's KCC-3 addresses. Refused with no seed or
/// an account kprv (no `22'` tree); a master kprv has one. With a seed it
/// starts at the first `kaspa:p...` address, steps, switches chain, takes
/// the keypad, shows the code, and Back returns to the row's Seed Tools
/// page.
#[test]
fn kcc3_address_shows_the_seeds_kcc3_addresses() {
    use kassigner_fw::ui::{address as screen, keypad};
    use kassigner_kaspa::derivation::SINGLE_ACCOUNT;
    const KCC3: usize = 4;

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    seed_tool(&mut f, KCC3);
    assert_eq!(f.state(), State::Refused(Refusal::NoWallet));

    let master = master_of(&mnemonic());
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    restore_xprv(&mut f, master.derive_path(&SINGLE_ACCOUNT).unwrap());
    seed_tool(&mut f, KCC3);
    let why = Refusal::NoKcc3Key;
    assert_eq!(f.state(), State::Refused(why));
    assert_eq!(
        why.words(),
        ("No KCC-3 keys", "Only seed words or a master xprv")
    );

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    restore_xprv(&mut f, master);
    seed_tool(&mut f, KCC3);
    assert_eq!(f.state(), State::Address, "a master kprv has the tree");
    assert_eq!(f.address_text(), kcc3_address_of(Path::kcc3_receive(0)));

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    seed_tool(&mut f, KCC3);
    assert_eq!(f.state(), State::Address);
    let shown = f.step(Event::Tick { now_us: 1 }, &mut Live).screen;
    assert_eq!(
        shown,
        Screen::Kcc3Address {
            change: false,
            index: 0
        }
    );
    assert!(f.address_text().starts_with("kaspa:p"));
    assert_eq!(f.address_text(), kcc3_address_of(Path::kcc3_receive(0)));

    let on = |t, first| tap_in(screen::zone(SCALE, false, first, t).expect("on the screen"));
    let moved = |f: &mut Flow<'_, 6>, e| {
        let out = f.step(e, &mut Live);
        settled(f, out)
    };
    moved(&mut f, on(screen::Target::After, true));
    assert_eq!(f.address_text(), kcc3_address_of(Path::kcc3_receive(1)));
    let out = moved(&mut f, on(screen::Target::Chain, false));
    assert_eq!(
        out.screen,
        Screen::Kcc3Address {
            change: true,
            index: 0
        }
    );
    assert_eq!(f.address_text(), kcc3_address_of(Path::kcc3_change(0)));

    // The keypad: 25, past the bank's five change keys.
    f.step(on(screen::Target::Index, true), &mut Live);
    assert_eq!(f.state(), State::AddressIndex);
    let key = |k| tap_in(keypad::zone(SCALE, keypad::Target::Key(k)).unwrap());
    f.step(key(keypad::Key::Digit(2)), &mut Live);
    f.step(key(keypad::Key::Digit(5)), &mut Live);
    moved(&mut f, key(keypad::Key::Go));
    assert_eq!(f.state(), State::Address);
    assert_eq!(f.address_text(), kcc3_address_of(Path::kcc3_change(25)));

    // The code, ADDRESS EXPORTED after it, and back.
    f.step(on(screen::Target::Address, false), &mut Live);
    assert_eq!(f.state(), State::AddressQr);
    assert_eq!(
        f.step(Event::Tick { now_us: 2 }, &mut Live).screen,
        Screen::AddressQr {
            change: true,
            index: 25
        }
    );
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::AddressDone);
    f.touch(answer(dialog::Target::Nav(Nav::Back)));
    assert_eq!(f.state(), State::Address);
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedTools,
            page: 1
        }
    );

    // Address after it is the single-signature one again.
    f.step(home_button(), &mut Live);
    seed_tool(&mut f, 3);
    assert_eq!(f.state(), State::Address);
    assert_eq!(f.address_text(), address_of(Path::receive(0)));
}

/// ADDRESS EXPORTED saves the address as `ADnnnn.TXT` after ENCRYPT FILE?,
/// then returns to ADDRESS EXPORTED.
#[test]
fn address_exported_saves_the_address() {
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{do_format_fat32, find_file_in_root, mount_fat32, read_file};
    use kassigner_fw::card::{self, Job, Kind};
    use kassigner_fw::ui::address as screen;

    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    seed_tool(&mut f, 3);
    assert_eq!(f.state(), State::Address);
    let address = f.address_text().to_string();
    let on = |t| tap_in(screen::zone(SCALE, false, true, t).expect("on the screen"));
    f.step(on(screen::Target::Address), &mut Live);
    assert_eq!(f.state(), State::AddressQr);
    f.step(on(screen::Target::Address), &mut Live);
    assert_eq!(f.state(), State::AddressDone);

    let job = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, job: Job| {
        let outcome = card::run(job, Kind::SdV2High, sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live)
    };
    assert_eq!(
        f.touch(answer(dialog::Target::Cancel)).command,
        Some(Command::Card(Job::NextName))
    );
    job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "AD0001");
    let State::BackupName { page } = f.state() else {
        panic!("{:?}", f.state())
    };
    f.step(key(page, keyboard::Key::Ok), &mut Live);
    job(&mut f, &mut sd, Job::Exists);
    assert_eq!(f.state(), State::KpubEncrypt, "ENCRYPT FILE? first");
    f.touch(answer(dialog::Target::Accept));
    job(&mut f, &mut sd, Job::Write);
    assert_eq!(f.saved_text(), "!! Address Saved !!");
    let info = mount_fat32(&mut sd).unwrap();
    let (entry, _, _) = find_file_in_root(&mut sd, &info, b"AD0001  TXT").unwrap();
    let mut out = vec![0u8; entry.file_size as usize];
    let n = read_file(&mut sd, &info, &entry, &mut out).unwrap();
    assert_eq!(&out[..n], address.as_bytes());
    f.step(
        Event::Tick {
            now_us: VERIFIED_US + card_done_us(Job::Write, Outcome::Written),
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::AddressDone, "back to ADDRESS EXPORTED");
}
