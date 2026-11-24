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

//! Multisig: a group made, its keys from the scanner, a seed or the card, its
//! address and descriptor, and a group's spend.

use super::*;

/// **MULTISIG and CREATE MULTISIG, under Tools.** MULTISIG's group rows are
/// dimmed and inert with no group held. CREATE MULTISIG opens at 2 of 3 and
/// steps M (1 to N) and N (1 to 5), silently doing nothing past either end;
/// N below M takes M down. NEXT opens KEY 1/N, whose Back returns to CREATE
/// MULTISIG, the group dropped.
#[test]
fn create_multisig_steps_m_and_n() {
    use kassigner_fw::ui::multisig::{zone, Row, Target};

    let multisig = Screen::Menu {
        menu: MenuId::Multisig,
        page: 0,
    };
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    f.step(card(2), &mut Live);
    assert_eq!(f.step(item(&menu::TOOLS, 3), &mut Live).screen, multisig);
    assert_eq!(f.dimmed(MenuId::Multisig), 0b110);
    assert_eq!(f.dimmed(MenuId::Tools), 0);
    for row in [1, 2] {
        assert_eq!(
            f.step(item(&menu::MULTISIG, row), &mut Live).screen,
            multisig
        );
    }

    let out = f.step(item(&menu::MULTISIG, 0), &mut Live);
    assert_eq!(out.screen, Screen::CreateMultisig { m: 2, n: 3 });
    assert_eq!(f.forming(), None);

    let tap = |f: &mut Flow<'_, 6>, t: Target| {
        f.step(tap_in(zone(SCALE, t).expect("a target")), &mut Live)
            .screen
    };
    // A "-" or "+" with nowhere to go: the same screen, no command.
    let stays = |f: &mut Flow<'_, 6>, t: Target| {
        let before = f.state();
        let out = f.step(tap_in(zone(SCALE, t).unwrap()), &mut Live);
        assert_eq!(f.state(), before, "{t:?} at its end");
        assert_eq!(out.command, None);
    };

    let at = |m, n| Screen::CreateMultisig { m, n };
    assert_eq!(tap(&mut f, Target::Plus(Row::Required)), at(3, 3));
    stays(&mut f, Target::Plus(Row::Required));
    assert_eq!(
        tap(&mut f, Target::Minus(Row::Total)),
        at(2, 2),
        "M follows N"
    );
    assert_eq!(tap(&mut f, Target::Minus(Row::Total)), at(1, 1));
    for t in [
        Target::Minus(Row::Required),
        Target::Plus(Row::Required),
        Target::Minus(Row::Total),
    ] {
        stays(&mut f, t);
    }
    for n in 2..=5 {
        assert_eq!(tap(&mut f, Target::Plus(Row::Total)), at(1, n));
    }
    stays(&mut f, Target::Plus(Row::Total));
    for m in 2..=5 {
        assert_eq!(tap(&mut f, Target::Plus(Row::Required)), at(m, 5));
    }
    assert_eq!(tap(&mut f, Target::Minus(Row::Required)), at(4, 5));

    assert_eq!(tap(&mut f, Target::Next), Screen::AddKey { key: 1, of: 5 });
    let g = f.forming().expect("a group being made");
    assert_eq!((g.required(), g.total(), g.keys().len()), (4, 5, 0));
    assert_eq!(f.step(back_button(), &mut Live).screen, at(4, 5));
    assert!(f.forming().is_none());

    // Back to MULTISIG; opened again, 2 of 3; Back to MULTISIG, then Tools.
    assert_eq!(tap(&mut f, Target::Nav(Nav::Back)), multisig);
    assert_eq!(f.step(item(&menu::MULTISIG, 0), &mut Live).screen, at(2, 3));
    assert_eq!(tap(&mut f, Target::Nav(Nav::Back)), multisig);
    assert!(f.forming().is_none());
    assert_eq!(
        f.step(back_button(), &mut Live).screen,
        Screen::Menu {
            menu: MenuId::Tools,
            page: 0
        }
    );
    f.step(item(&menu::TOOLS, 3), &mut Live);
    f.step(item(&menu::MULTISIG, 0), &mut Live);
    assert_eq!(tap(&mut f, Target::Nav(Nav::Home)), Screen::Home);
}

/// **A group's keys scanned through KEY k/N and COSIGNER KEY.** A kpub, as
/// text or raw, is the next key; a repeat or anything not a kpub (a testnet
/// one too) is refused. With the last key the group is held in rusty-kaspa's
/// order (sorted as kpub text) and MULTISIG's rows light. Home drops a group
/// being made, never the held one.
#[test]
fn a_groups_keys_are_scanned() {
    use kassigner_fw::ui::multisig::{self as ms, zone, Target};
    use kassigner_kaspa::bip32_public::{ExtendedPublicKey, Prefix, TEXT_MAX};

    let key = |text: &str| ExtendedPublicKey::from_text(text.as_bytes()).unwrap().1;
    let raw = |text: &str| {
        let mut out = vec![0x01u8; 79];
        key(text).serialize(Prefix::Kpub, &mut out[1..]).unwrap();
        out
    };
    let ktub = {
        let mut out = [0u8; TEXT_MAX];
        let n = key(ABANDON24_KPUB45)
            .to_text(Prefix::Ktub, &mut out)
            .unwrap();
        out[..n].to_vec()
    };
    let at = |key, of| Screen::AddKey { key, of };
    // Scan Multisig kpub, the same row on every KEY k/N.
    let scan_row = || item(&ms::add_key(1, 1), 0);
    let open = |f: &mut Flow<'_, 6>| {
        f.step(scan_row(), &mut Live);
        assert_eq!(f.state(), State::CosignerKey);
        let out = f.touch(answer(dialog::Target::Accept));
        assert_eq!(out.command, Some(Command::CameraOn));
        assert_eq!(f.state(), State::Scanning);
    };
    let mut now = VERIFIED_US;
    let mut refused = |f: &mut Flow<'_, 6>, why: Refusal, back: Screen| {
        assert_eq!(f.state(), State::Refused(why));
        now += REFUSED_US;
        let out = f.step(Event::Tick { now_us: now }, &mut Live);
        assert_eq!(out.screen, back, "back after {why:?}");
    };

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 3), &mut Live);
    f.step(item(&menu::MULTISIG, 0), &mut Live);
    let next = tap_in(zone(SCALE, Target::Next).unwrap());
    assert_eq!(f.step(next, &mut Live).screen, at(1, 3));

    // COSIGNER KEY: CANCEL, Back; SCAN, and the camera's Back.
    assert_eq!(f.step(scan_row(), &mut Live).screen, Screen::CosignerKey);
    assert_eq!(f.touch(answer(dialog::Target::Cancel)).screen, at(1, 3));
    f.step(scan_row(), &mut Live);
    assert_eq!(f.touch(back_button()).screen, at(1, 3));
    open(&mut f);
    let out = f.step(back_button(), &mut Live);
    assert_eq!(
        (out.screen, out.command),
        (at(1, 3), Some(Command::CameraOff))
    );

    // The first key, as text; again, refused.
    open(&mut f);
    let out = f.step(Event::Code(ZOO12_KPUB45.as_bytes()), &mut Live);
    assert_eq!(
        (out.screen, out.command),
        (at(2, 3), Some(Command::CameraOff))
    );
    open(&mut f);
    f.step(Event::Code(ZOO12_KPUB45.as_bytes()), &mut Live);
    refused(&mut f, Refusal::KeyAdded, at(2, 3));
    // Raw, as v1.0.7's and v1.1.0's frames carry it: the same key.
    open(&mut f);
    deliver(&mut f, &raw(ZOO12_KPUB45));
    refused(&mut f, Refusal::KeyAdded, at(2, 3));

    // The second, raw; Back takes it out; in again.
    open(&mut f);
    assert_eq!(deliver(&mut f, &raw(ABANDON12_KPUB45)).screen, at(3, 3));
    assert_eq!(f.step(back_button(), &mut Live).screen, at(2, 3));
    assert_eq!(f.forming().unwrap().keys().len(), 1);
    open(&mut f);
    deliver(&mut f, &raw(ABANDON12_KPUB45));
    assert_eq!(f.state(), State::AddKey);

    // Not a kpub: a SeedQR, text, a testnet key.
    for code in [seedqr(), b"hello".to_vec(), ktub] {
        open(&mut f);
        f.step(Event::Code(&code), &mut Live);
        refused(&mut f, Refusal::NotAKpub, at(3, 3));
    }
    open(&mut f);
    f.step(Event::Opaque(b"kpub in frames of text"), &mut Live);
    refused(&mut f, Refusal::NotAKpub, at(3, 3));

    // The last: the group made and held, MULTISIG lit.
    assert!(f.group().is_none());
    assert_eq!(f.dimmed(MenuId::Multisig), 0b110);
    open(&mut f);
    let out = f.step(Event::Code(ABANDON24_KPUB45.as_bytes()), &mut Live);
    assert_eq!(
        out.screen,
        Screen::Menu {
            menu: MenuId::Multisig,
            page: 0
        }
    );
    assert!(f.forming().is_none());
    let g = f.group().expect("the group held");
    assert_eq!((g.required(), g.total()), (2, 3));
    assert_eq!(
        g.keys(),
        [ZOO12_KPUB45, ABANDON24_KPUB45, ABANDON12_KPUB45].map(key),
        "step 4's order: zoo 12, abandon 24, abandon 12"
    );
    let mut text = [0u8; TEXT_MAX];
    assert_eq!(f.group_key_text(1, &mut text), Some(ABANDON24_KPUB45));
    assert_eq!(f.group_key_text(3, &mut text), None);
    assert_eq!(f.group_position(), None, "no seed in use");
    assert_eq!(f.dimmed(MenuId::Multisig), 0);
    // Its address at the first cosigner's branch (no seed in use is in the
    // group), DERIVING first; Back to MULTISIG.
    assert_eq!(
        open_group_address(&mut f),
        Screen::GroupDeriving { done: 0, total: 9 }
    );
    assert_eq!(
        group_derived(&mut f),
        Screen::GroupAddress {
            change: false,
            index: 0,
            cosigner: 0
        }
    );
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Multisig,
            page: 0
        }
    );

    // The scanner, from Home: a kpub is KPUB SCANNED again.
    f.step(home_button(), &mut Live);
    f.step(scan(), &mut Live);
    f.step(Event::Code(ABANDON24_KPUB45.as_bytes()), &mut Live);
    assert_eq!(f.state(), State::KpubScanned);

    // Home from KEY k/N or COSIGNER KEY drops the group being made.
    for from_warning in [false, true] {
        f.touch(home_button());
        assert_eq!(f.state(), State::Home);
        f.step(card(2), &mut Live);
        f.step(item(&menu::TOOLS, 3), &mut Live);
        f.step(item(&menu::MULTISIG, 0), &mut Live);
        f.step(next, &mut Live);
        let out = if from_warning {
            f.step(scan_row(), &mut Live);
            f.touch(home_button())
        } else {
            f.step(home_button(), &mut Live)
        };
        assert_eq!(out.screen, Screen::Home);
        assert!(f.forming().is_none());
        assert_eq!(f.group().map(|g| g.total()), Some(3));
    }
}

/// A group's key scanned on KEY k/N, through COSIGNER KEY.
fn scan_cosigner<const N: usize>(f: &mut Flow<'_, N>, code: &[u8]) -> Screen {
    f.step(
        item(&kassigner_fw::ui::multisig::add_key(1, 1), 0),
        &mut Live,
    );
    assert_eq!(f.state(), State::CosignerKey);
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::Scanning);
    f.step(Event::Code(code), &mut Live).screen
}

/// CREATE MULTISIG at `m` of `n`, from Home, and NEXT: KEY 1/N.
fn create_group<const N: usize>(f: &mut Flow<'_, N>, m: u8, n: u8) {
    use kassigner_fw::ui::multisig::{zone, Row, Target};
    let tap = |f: &mut Flow<'_, N>, t| {
        f.step(tap_in(zone(SCALE, t).unwrap()), &mut Live);
    };
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 3), &mut Live);
    f.step(item(&menu::MULTISIG, 0), &mut Live);
    for _ in 0..4 {
        tap(f, Target::Minus(Row::Total));
    }
    for _ in 1..n {
        tap(f, Target::Plus(Row::Total));
    }
    for _ in 1..m {
        tap(f, Target::Plus(Row::Required));
    }
    assert_eq!(f.state(), State::CreateMultisig { m, n });
    tap(f, Target::Next);
    assert_eq!(f.state(), State::AddKey);
}

/// Multisig Address tapped on MULTISIG, which stays up until the next tick:
/// the screen then, DERIVING the first time for a group, else its address.
fn open_group_address<const N: usize>(f: &mut Flow<'_, N>) -> Screen {
    let out = f.step(item(&menu::MULTISIG, 1), &mut Live);
    assert_eq!(
        out.screen,
        Screen::Menu {
            menu: MenuId::Multisig,
            page: 0
        },
        "MULTISIG until the tick"
    );
    settled(f, out).screen
}

/// Multisig Address's first DERIVING for a group: one key at one branch a
/// tick, the bar a step longer each, the address on the last tick. A tap on
/// it does nothing, and a finger that went down on it does not tap the
/// address.
fn group_derived<const N: usize>(f: &mut Flow<'_, N>) -> Screen {
    let total = f.group().expect("a group").total().pow(2);
    assert_eq!(f.state(), State::GroupDeriving, "DERIVING first");
    f.touch(back_button());
    assert_eq!(f.state(), State::GroupDeriving, "a tap while it derives");
    // The clock held, so the test's own times stay valid.
    let now_us = f.now_us();
    for done in 1..total {
        let out = f.step(Event::Tick { now_us }, &mut Live);
        assert_eq!(out.screen, Screen::GroupDeriving { done, total });
        assert_eq!(out.command, None);
    }
    // A finger down on DERIVING, where the address will be.
    let (x, y) = (SCALE.x(160) as u16, SCALE.y(130) as u16);
    f.step(Event::Press { x, y }, &mut Live);
    let out = f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(
        f.state(),
        State::Address,
        "the address, on the last step's tick"
    );
    assert_eq!(out.command, None);
    // Lifted there, it does not tap the address.
    f.step(Event::Tap { x, y }, &mut Live);
    assert_eq!(f.state(), State::Address, "not the address's code");
    out.screen
}

/// A tap that moves a group's address, `out` its answer: the same screen
/// and [`Command::Deferred`], clicking at once; the address worked out
/// silently on the next tick, and its screen returned.
fn group_moved<const N: usize>(
    f: &mut Flow<'_, N>,
    before: Screen,
    out: kassigner_fw::flow::Output,
) -> Screen {
    use kassigner_fw::cues;
    assert_eq!(out.screen, before, "the screen stays until the tick");
    assert_eq!(out.command, Some(Command::Deferred));
    assert!(cues::clicks(&before, &out.screen, true, true), "it clicks");
    assert_eq!(
        cues::for_step(&before, &out.screen, true, true),
        Some(cues::Cue::Click)
    );
    let now_us = f.now_us();
    let next = f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(f.state(), State::Address, "the address, on the tick after");
    assert_eq!(next.command, None);
    assert_eq!(
        cues::for_step(&out.screen, &next.screen, false, false),
        None
    );
    next.screen
}

/// **The group held, and the seed in use's place in it**: abandon 12's key
/// at 2 in the 2-of-3 of zoo 12, abandon 12 and abandon 24. A later 1-of-1
/// replaces it; the idle wipe takes it.
#[test]
fn a_group_is_held_with_the_seed_in_uses_place() {
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);
    create_group(&mut f, 2, 3);
    for kpub in [ZOO12_KPUB45, ABANDON12_KPUB45] {
        scan_cosigner(&mut f, kpub.as_bytes());
    }
    let out = scan_cosigner(&mut f, ABANDON24_KPUB45.as_bytes());
    assert_eq!(
        out,
        Screen::Menu {
            menu: MenuId::Multisig,
            page: 0
        }
    );
    assert_eq!(f.group_position(), Some(2));
    assert_eq!(f.dimmed(MenuId::Multisig), 0);
    // Its rows lit: the address at the seed in use's branch; the
    // descriptor, the seed in use's key at 2.
    open_group_address(&mut f);
    assert_eq!(
        group_derived(&mut f),
        Screen::GroupAddress {
            change: false,
            index: 0,
            cosigner: 2
        }
    );
    assert_eq!(f.step(back_button(), &mut Live).screen, out);
    let tapped = f.step(item(&menu::MULTISIG, 2), &mut Live);
    assert_eq!(tapped.screen, out, "MULTISIG until the tick");
    assert_eq!(
        settled(&mut f, tapped).screen,
        Screen::Descriptor { own: Some(2) }
    );
    assert_eq!(f.step(back_button(), &mut Live).screen, out);

    f.step(home_button(), &mut Live);
    create_group(&mut f, 1, 1);
    scan_cosigner(&mut f, ZOO12_KPUB45.as_bytes());
    let g = f.group().unwrap();
    assert_eq!((g.required(), g.total()), (1, 1));
    assert_eq!(f.group_position(), None);
    // A new group: DERIVING again, its one key at its one branch.
    assert_eq!(
        open_group_address(&mut f),
        Screen::GroupDeriving { done: 0, total: 1 }
    );
    assert_eq!(
        group_derived(&mut f),
        Screen::GroupAddress {
            change: false,
            index: 0,
            cosigner: 0
        }
    );
    let mut text = [0u8; 128];
    let n = f
        .group()
        .unwrap()
        .address(
            kassigner_kaspa::address::Prefix::Mainnet,
            0,
            0,
            0,
            &mut text,
        )
        .expect("the 1-of-1's address");
    assert_eq!(f.address_text().as_bytes(), &text[..n]);
    f.step(back_button(), &mut Live);

    f.step(
        Event::Tick {
            now_us: VERIFIED_US + IDLE_WIPE_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home);
    assert!(f.group().is_none());
    assert_eq!(f.dimmed(MenuId::Multisig), 0b110);
}

/// **Use Loaded Seed, through SELECT SEED**: the seed tapped is put in use
/// (opened if need be) and its cosigner key added; a repeat is refused, as
/// is the row with no seed held. The group keeps each key's seed: zoo 12
/// (in use) at 0, abandon 24 (scanned) at 1, abandon 12 at 2.
#[test]
fn loaded_seeds_join_a_group() {
    use kassigner_fw::ui::multisig::add_key;
    let use_seed = || item(&add_key(1, 1), 1);
    let row = |r| tap_in(seeds::pick_zone(SCALE, 2, 0, seeds::Pick::Row(r)).unwrap());
    let refused = |f: &mut Flow<'_, 6>, why: Refusal, back: Screen| {
        assert_eq!(f.state(), State::Refused(why));
        let now_us = f.now_us() + REFUSED_US;
        assert_eq!(f.step(Event::Tick { now_us }, &mut Live).screen, back);
    };
    let open = |f: &mut Flow<'_, 6>| {
        assert!(
            matches!(f.state(), State::Opening { .. }),
            "{:?}",
            f.state()
        );
        while matches!(f.state(), State::Opening { .. }) {
            let now_us = f.now_us();
            f.step(Event::Tick { now_us }, &mut Live);
        }
    };
    let at = |key, of| Screen::AddKey { key, of };

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    create_group(&mut f, 2, 3);
    f.step(use_seed(), &mut Live);
    refused(&mut f, Refusal::NoWallet, at(1, 3));
    f.step(home_button(), &mut Live);

    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);
    load(&mut f, corpus!("seedqr/zoo12.standard"));
    f.step(home_button(), &mut Live);
    let (a12, zoo) = (f.seed(0).unwrap(), f.seed(1).unwrap());
    assert!(zoo.active && !a12.active);

    create_group(&mut f, 2, 3);
    assert_eq!(
        f.step(use_seed(), &mut Live).screen,
        Screen::SelectSeed {
            page: 0,
            key: 1,
            of: 3
        }
    );
    assert_eq!(f.step(back_button(), &mut Live).screen, at(1, 3));

    // Abandon 12, not in use: opened, in use, its key in.
    f.step(use_seed(), &mut Live);
    f.step(row(0), &mut Live);
    open(&mut f);
    assert_eq!(f.state(), State::AddKey);
    assert!(f.seed(0).unwrap().active);
    let keys = f.forming().unwrap().keys().to_vec();
    assert_eq!(keys.len(), 1);
    let mut text = [0u8; 128];
    let n = keys[0]
        .to_text(kassigner_kaspa::bip32_public::Prefix::Kpub, &mut text)
        .unwrap();
    assert_eq!(&text[..n], ABANDON12_KPUB45.as_bytes());

    // Again, in use now: its key worked out on the next tick, and refused
    // as already added.
    f.step(use_seed(), &mut Live);
    let out = f.step(row(0), &mut Live);
    settled(&mut f, out);
    refused(&mut f, Refusal::KeyAdded, at(2, 3));

    // Zoo 12: opened, its key in; abandon 24 scanned, the last.
    f.step(use_seed(), &mut Live);
    assert_eq!(
        f.step(row(1), &mut Live).screen,
        Screen::Opening {
            done: 0,
            total: OPEN_STEPS
        }
    );
    open(&mut f);
    assert_eq!(
        f.step(Event::Tick { now_us: f.now_us() }, &mut Live).screen,
        at(3, 3)
    );
    assert_eq!(
        scan_cosigner(&mut f, ABANDON24_KPUB45.as_bytes()),
        Screen::Menu {
            menu: MenuId::Multisig,
            page: 0
        }
    );
    let g = f.group().unwrap();
    assert_eq!((g.required(), g.total()), (2, 3));
    assert_eq!(f.group_key_text(0, &mut text), Some(ZOO12_KPUB45));
    assert_eq!(
        (0..3).map(|i| f.group_seed(i)).collect::<Vec<_>>(),
        [Some(zoo.fingerprint), None, Some(a12.fingerprint)]
    );
    assert_eq!(f.group_position(), Some(0), "zoo 12, in use");
}

/// **A raw key has no cosigner key**: picked on SELECT SEED, refused, back
/// to KEY k/N with nothing added.
#[test]
fn a_raw_key_is_refused_as_a_cosigner() {
    use kassigner_fw::ui::multisig::add_key;
    let hex = private_hex(&wallet(), Path::receive(5));
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    raw_key_keyboard(&mut f);
    type_hex(&mut f, &hex);
    let out = f.step(hex_key(&f, keyboard::Key::Ok), &mut Live);
    settled(&mut f, out);
    read(&mut f);
    f.touch(answer(dialog::Target::Accept));
    while matches!(f.state(), State::Opening { .. }) {
        let now_us = f.now_us();
        f.step(Event::Tick { now_us }, &mut Live);
    }
    assert_eq!(f.seed(0).unwrap().kind, seeds::Kind::Key);
    f.step(home_button(), &mut Live);

    create_group(&mut f, 1, 1);
    f.step(item(&add_key(1, 1), 1), &mut Live);
    let out = f.step(
        tap_in(seeds::pick_zone(SCALE, 1, 0, seeds::Pick::Row(0)).unwrap()),
        &mut Live,
    );
    settled(&mut f, out);
    assert_eq!(f.state(), State::Refused(Refusal::NoCosignerKey));
    let now_us = f.now_us() + REFUSED_US;
    let out = f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(out.screen, Screen::AddKey { key: 1, of: 1 });
    assert!(f.forming().unwrap().keys().is_empty());
}

/// **Load kpub from SD lists only the card's `.K45` cosigner files**, and
/// takes one (under its password if sealed) only as a cosigner's: the key
/// after a fingerprint and the cosigner path, at that path's depth, or
/// sealed under the cosigner purpose. Anything else is refused by name, a
/// repeat as when scanned, and an empty card is said. Import from SD's kpub
/// list shows them too.
#[test]
fn a_groups_key_is_loaded_from_the_card() {
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{create_file, do_format_fat32, mount_fat32};
    use kassigner_fw::card::{self, Job, Kind};
    use kassigner_fw::ui::backup::{pick_zone, Pick};
    use kassigner_fw::ui::multisig::add_key;
    use kassigner_kaspa::bip32_public::{ExtendedPublicKey, Prefix, TEXT_MAX};
    use kassigner_protocol::container::Purpose;

    let origin = |kpub: &str| format!("[3f635a63/45'/111111'/0']{kpub}");
    let password = b"Correct-Horse-9";
    let sealed = |purpose, text: &[u8]| {
        let mut out = [0u8; 512];
        let n = seal(
            purpose,
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
    let deep = {
        let (_, mut key) = ExtendedPublicKey::from_text(ZOO12_KPUB45.as_bytes()).unwrap();
        key.depth = 2;
        let mut out = [0u8; TEXT_MAX];
        let n = key.to_text(Prefix::Kpub, &mut out).unwrap();
        origin(core::str::from_utf8(&out[..n]).unwrap())
    };
    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let files: [(&[u8; 11], Vec<u8>); 7] = [
        (b"KM0001  K45", origin(ZOO12_KPUB45).into_bytes()),
        (b"KP0001  TXT", ABANDON24_KPUB45.as_bytes().to_vec()),
        (
            b"KM0002  K45",
            sealed(Purpose::Cosigner, origin(ABANDON12_KPUB45).as_bytes()),
        ),
        (b"KM0003  K45", origin(ZOO12_KPUB45).into_bytes()),
        (b"BARE    K45", ABANDON24_KPUB45.as_bytes().to_vec()),
        (
            b"WATCH   K45",
            sealed(Purpose::Kspt, ABANDON24_KPUB45.as_bytes()),
        ),
        (b"DEEP    K45", deep.into_bytes()),
    ];
    for (name, body) in &files {
        let info = mount_fat32(&mut sd).unwrap();
        create_file(&mut sd, &info, name, body).unwrap();
    }

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    let job = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, job: Job| {
        let outcome = card::run(job, Kind::SdV2High, sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live)
    };
    let list = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>| {
        let out = f.step(item(&add_key(1, 1), 2), &mut Live);
        assert_eq!(out.command, Some(Command::Card(Job::List)));
        job(f, sd, Job::List)
    };
    // A file's row, the list turned to its page first.
    let pick = |f: &mut Flow<'_, 6>, name: &[u8; 11]| {
        let (i, n) = (
            f.backups().iter().position(|b| b == name).unwrap(),
            f.backups().len(),
        );
        loop {
            let State::RestoreList { page } = f.state() else {
                panic!("{:?}", f.state())
            };
            if let Some(z) = pick_zone(SCALE, n, page, Pick::Row(i)) {
                f.step(tap_in(z), &mut Live);
                return;
            }
            let down = pick_zone(SCALE, n, page, Pick::Nav(Nav::PageDown));
            f.step(tap_in(down.expect("a page that way")), &mut Live);
        }
    };
    let opened = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, typed: &[u8]| {
        restore_type(f, typed);
        assert_eq!(restore_ok(f).command, Some(Command::Card(Job::Read)));
        job(f, sd, Job::Read);
        while matches!(f.state(), State::RestoreOpening { .. }) {
            let now_us = f.now_us();
            f.step(Event::Tick { now_us }, &mut Live);
        }
    };
    let later = |f: &mut Flow<'_, 6>| {
        let now_us = f.now_us() + 1_000_000_000;
        f.step(Event::Tick { now_us }, &mut Live).screen
    };
    // A file that is not a cosigner's: refused by name, back to the list.
    let not_one = |f: &mut Flow<'_, 6>| {
        assert_eq!(
            f.state(),
            State::CardDone {
                job: Job::Read,
                outcome: Outcome::Failed(card::Error::Backup("Not a 45' kpub file")),
            }
        );
        later(f);
        assert_eq!(f.state(), State::RestoreList { page: 0 });
    };
    let at = |key, of| Screen::AddKey { key, of };

    create_group(&mut f, 2, 3);
    list(&mut f, &mut sd);
    assert_eq!(f.state(), State::RestoreList { page: 0 });
    let k45: Vec<[u8; 11]> = files
        .iter()
        .map(|(name, _)| **name)
        .filter(|name| name[8..] == card::COSIGNER_EXT)
        .collect();
    assert_eq!(f.backups(), &k45[..]);
    assert_eq!(f.step(back_button(), &mut Live).screen, at(1, 3));

    // Plain: nothing typed; its key the first.
    list(&mut f, &mut sd);
    pick(&mut f, b"KM0001  K45");
    opened(&mut f, &mut sd, b"");
    assert_eq!(f.state(), State::AddKey);
    assert_eq!(f.forming().unwrap().keys().len(), 1);

    // The same key under another name: refused, KEY 2/3 again.
    list(&mut f, &mut sd);
    pick(&mut f, b"KM0003  K45");
    opened(&mut f, &mut sd, b"");
    assert_eq!(f.state(), State::Refused(Refusal::KeyAdded));
    assert_eq!(later(&mut f), at(2, 3));

    // Not a cosigner's: a bare kpub, a sealed watch-only one, a wrong
    // depth.
    list(&mut f, &mut sd);
    pick(&mut f, b"BARE    K45");
    opened(&mut f, &mut sd, b"");
    not_one(&mut f);
    pick(&mut f, b"WATCH   K45");
    opened(&mut f, &mut sd, password);
    not_one(&mut f);
    pick(&mut f, b"DEEP    K45");
    opened(&mut f, &mut sd, b"");
    not_one(&mut f);

    // Sealed: a wrong password goes back to the list; its own opens it.
    pick(&mut f, b"KM0002  K45");
    opened(&mut f, &mut sd, b"Correct-Horse-8");
    assert!(
        matches!(f.state(), State::CardDone { job: Job::Read, .. }),
        "{:?}",
        f.state()
    );
    later(&mut f);
    assert_eq!(f.state(), State::RestoreList { page: 0 });
    pick(&mut f, b"KM0002  K45");
    opened(&mut f, &mut sd, password);
    assert_eq!(f.state(), State::AddKey);

    // The last, scanned: the group made, no key from a seed held.
    scan_cosigner(&mut f, ABANDON24_KPUB45.as_bytes());
    let g = f.group().expect("the group held");
    assert_eq!((g.required(), g.total()), (2, 3));
    assert!((0..3).all(|i| f.group_seed(i).is_none()));

    // Home from the list leaves the group being made.
    f.step(home_button(), &mut Live);
    create_group(&mut f, 1, 1);
    list(&mut f, &mut sd);
    assert_eq!(f.step(home_button(), &mut Live).screen, Screen::Home);
    assert!(f.forming().is_none());

    // Import from SD's kpubs: the .TXT and every .K45, a cosigner's shown
    // as its kpub.
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
    f.step(item(&menu::IMPORT_SD, 2), &mut Live);
    job(&mut f, &mut sd, Job::List);
    assert_eq!(f.backups().len(), files.len());
    pick(&mut f, b"KM0001  K45");
    opened(&mut f, &mut sd, b"");
    assert_eq!(f.state(), State::KpubFormat);
    f.touch(home_button());

    // No .K45 file: said, and KEY 1/1 again.
    let mut bare = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut bare).unwrap();
    let info = mount_fat32(&mut bare).unwrap();
    create_file(
        &mut bare,
        &info,
        b"KP0001  TXT",
        ABANDON24_KPUB45.as_bytes(),
    )
    .unwrap();
    f.touch(home_button());
    create_group(&mut f, 1, 1);
    list(&mut f, &mut bare);
    assert!(
        matches!(
            f.state(),
            State::CardDone {
                outcome: Outcome::Listed { count: 0, .. },
                ..
            }
        ),
        "{:?}",
        f.state()
    );
    assert_eq!(f.card_said().empty, ("No .K45 files found", ""));
    assert_eq!(later(&mut f), at(1, 1));
}

/// **A cosigner's file text reads back only as written**: the seed's eight
/// hex digits and the cosigner path before the kpub, nothing after it, its
/// child number the path's `0'`.
#[test]
fn a_cosigner_file_reads_back_only_as_written() {
    use kassigner_fw::kpub::{read, read_cosigner, write_cosigner, COSIGNER_MAX};
    use kassigner_kaspa::bip32_public::{ChildNumber, Prefix, HARDENED_OFFSET, TEXT_MAX};
    let key = read(ZOO12_KPUB45.as_bytes()).unwrap();
    let mut out = [0u8; COSIGNER_MAX];
    let n = write_cosigner([0x3f, 0x63, 0x5a, 0x63], ZOO12_KPUB45.as_bytes(), &mut out).unwrap();
    let written = format!("[3f635a63/45'/111111'/0']{ZOO12_KPUB45}");
    assert_eq!(&out[..n], written.as_bytes());
    assert_eq!(read_cosigner(&out[..n]), Some(key));
    assert_eq!(
        write_cosigner([0; 4], ZOO12_KPUB45.as_bytes(), &mut [0u8; 40]),
        None
    );

    let mut other = key;
    other.child_number = ChildNumber(HARDENED_OFFSET + 1);
    let mut text = [0u8; TEXT_MAX];
    let k = other.to_text(Prefix::Kpub, &mut text).unwrap();
    let other = core::str::from_utf8(&text[..k]).unwrap();
    for bad in [
        ZOO12_KPUB45.to_string(),
        format!("[3f635a63/44'/111111'/0']{ZOO12_KPUB45}"),
        format!("[3f635a63/45'/111111'/1']{ZOO12_KPUB45}"),
        format!("[3f635a6/45'/111111'/0']{ZOO12_KPUB45}"),
        format!("[3f635a6g/45'/111111'/0']{ZOO12_KPUB45}"),
        format!("{written}\n"),
        format!("[3f635a63/45'/111111'/0']{other}"),
    ] {
        assert_eq!(read_cosigner(bad.as_bytes()), None, "{bad}");
    }
}

/// **Multisig Address: the held group's address**, opening at the seed in
/// use's branch. The cosigner, chain, arrows and keypad move it: DERIVING
/// the first time, after that a click at once and the address on the next
/// tick. Its code, ADDRESS EXPORTED and Save to SD (`MS0001.TXT`) as on
/// Address.
#[test]
fn the_group_address_is_shown_and_saved() {
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{do_format_fat32, find_file_in_root, mount_fat32, read_file};
    use kassigner_fw::card::{self, Job, Kind};
    use kassigner_fw::ui::address::{group_zone, Target};
    use kassigner_fw::ui::keypad;

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);
    create_group(&mut f, 2, 3);
    for kpub in [ZOO12_KPUB45, ABANDON12_KPUB45, ABANDON24_KPUB45] {
        scan_cosigner(&mut f, kpub.as_bytes());
    }
    let at = |change, index, cosigner| Screen::GroupAddress {
        change,
        index,
        cosigner,
    };
    // A target as placed past index 0 ("<" is absent at 0, and tapped
    // only past it).
    let tap = |f: &mut Flow<'_, 6>, t: Target| {
        let z = group_zone(SCALE, false, t).expect("a target");
        f.step(tap_in(z), &mut Live).screen
    };
    // A target that moves the address from screen `on`: the same screen
    // and address, a click at once, the new address next tick, into `on`.
    let moved = |f: &mut Flow<'_, 6>, on: &mut Screen, t: Target| {
        let shown = f.address_text().to_string();
        let out = f.step(tap_in(group_zone(SCALE, false, t).unwrap()), &mut Live);
        assert_eq!(f.address_text(), shown, "{t:?}: until the tick");
        *on = group_moved(f, *on, out);
        *on
    };

    assert_eq!(
        open_group_address(&mut f),
        Screen::GroupDeriving { done: 0, total: 9 }
    );
    let mut on = group_derived(&mut f);
    assert_eq!(on, at(false, 0, 2));
    assert_eq!(
        f.address_text(),
        "kaspa:prvfzy9wjlewtyk9qeczkd0ehyxfcycxz9c99yr2x3nu7uk6zw872c06xr7d9"
    );
    let on = &mut on;
    assert_eq!(
        moved(&mut f, on, Target::CosignerAfter),
        at(false, 0, 0),
        "round"
    );
    assert_eq!(
        moved(&mut f, on, Target::CosignerBefore),
        at(false, 0, 2),
        "and back"
    );
    assert_eq!(moved(&mut f, on, Target::CosignerBefore), at(false, 0, 1));
    assert_eq!(moved(&mut f, on, Target::CosignerBefore), at(false, 0, 0));
    assert_eq!(moved(&mut f, on, Target::Chain), at(true, 0, 0));
    for i in 1..=5 {
        assert_eq!(moved(&mut f, on, Target::After), at(true, i, 0));
    }
    assert_eq!(
        f.address_text(),
        "kaspa:pqr82f7wkmsa35682a7crkc6ay8zxzx5ct4m56k7pa7arnktwy4m5f6k30s8s"
    );
    assert_eq!(moved(&mut f, on, Target::Before), at(true, 4, 0));

    // The keypad: index 12. Its Back is the address unchanged, nothing
    // derived.
    tap(&mut f, Target::Index);
    assert_eq!(f.state(), State::AddressIndex);
    let before = f.address_text().to_string();
    assert_eq!(f.step(back_button(), &mut Live).screen, at(true, 4, 0));
    assert_eq!(f.address_text(), before);
    tap(&mut f, Target::Index);
    let digit = |k| tap_in(keypad::zone(SCALE, keypad::Target::Key(k)).unwrap());
    f.step(digit(keypad::Key::Digit(1)), &mut Live);
    let pad = f.step(digit(keypad::Key::Digit(2)), &mut Live).screen;
    let out = f.step(digit(keypad::Key::Go), &mut Live);
    assert_eq!(f.state(), State::AddressIndex, "the keypad, until the tick");
    assert_eq!(group_moved(&mut f, pad, out), at(true, 12, 0));

    // Its code; ADDRESS EXPORTED; Back to the address.
    let shown = f.address_text().to_string();
    tap(&mut f, Target::Address);
    assert_eq!(f.state(), State::AddressQr);
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::AddressDone);
    assert_eq!(f.touch(back_button()).screen, at(true, 12, 0));

    // Save to SD: MS0001.TXT, plain.
    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let job = |f: &mut Flow<'_, 6>, sd: &mut Ram<Vec<[u8; BLOCK_SIZE]>>, job: Job| {
        let outcome = card::run(job, Kind::SdV2High, sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live)
    };
    tap(&mut f, Target::Address);
    f.step(home_button(), &mut Live);
    assert_eq!(
        f.touch(answer(dialog::Target::Cancel)).command,
        Some(Command::Card(Job::NextName))
    );
    job(&mut f, &mut sd, Job::NextName);
    assert_eq!(f.typed().0, "MS0001");
    let State::BackupName { page } = f.state() else {
        panic!("{:?}", f.state())
    };
    f.step(key(page, keyboard::Key::Ok), &mut Live);
    job(&mut f, &mut sd, Job::Exists);
    assert_eq!(f.state(), State::KpubEncrypt);
    f.touch(answer(dialog::Target::Accept));
    job(&mut f, &mut sd, Job::Write);
    assert_eq!(f.saved_text(), "!! Address Saved !!");
    let info = mount_fat32(&mut sd).unwrap();
    let (entry, _, _) = find_file_in_root(&mut sd, &info, b"MS0001  TXT").unwrap();
    let mut out = vec![0u8; entry.file_size as usize];
    let n = read_file(&mut sd, &info, &entry, &mut out).unwrap();
    assert_eq!(&out[..n], shown.as_bytes());

    // Back from the address: MULTISIG.
    let now_us = f.now_us() + 10_000_000;
    f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(f.state(), State::AddressDone);
    f.touch(back_button());
    let listed = f.step(back_button(), &mut Live).screen;
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Multisig,
            page: 0
        }
    );

    // Open again: still this group's keys, so no DERIVING; MULTISIG until
    // the next tick, then index 0 of its own branch.
    let out = f.step(item(&menu::MULTISIG, 1), &mut Live);
    assert_eq!(group_moved(&mut f, listed, out), at(false, 0, 2));
    assert_eq!(
        f.address_text(),
        "kaspa:prvfzy9wjlewtyk9qeczkd0ehyxfcycxz9c99yr2x3nu7uk6zw872c06xr7d9"
    );
}

/// **DESCRIPTOR, from MULTISIG**: nothing with no group held; else, on the
/// next tick, the held group with the seed in use's key marked, if it is
/// in it. Save to SD: `the_descriptor_is_saved_plain_or_sealed`.
#[test]
fn the_descriptor_shows_the_held_group() {
    let listed = Screen::Menu {
        menu: MenuId::Multisig,
        page: 0,
    };
    let open = |f: &mut Flow<'_, 6>| {
        let out = f.step(item(&menu::MULTISIG, 2), &mut Live);
        assert_eq!(out.screen, listed, "MULTISIG until the tick");
        settled(f, out).screen
    };
    let answer_at = |t| tap_in(dialog::zone(SCALE, t).unwrap());

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 3), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Multisig,
            page: 0
        }
    );
    let out = f.step(item(&menu::MULTISIG, 2), &mut Live);
    assert_eq!(
        (out.screen, out.command),
        (listed, None),
        "no group, nothing"
    );
    f.step(home_button(), &mut Live);

    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);
    create_group(&mut f, 2, 3);
    for kpub in [ZOO12_KPUB45, ABANDON24_KPUB45, ABANDON12_KPUB45] {
        scan_cosigner(&mut f, kpub.as_bytes());
    }
    assert_eq!(open(&mut f), Screen::Descriptor { own: Some(2) });
    let mut text = [0u8; 128];
    assert_eq!(f.group_key_text(0, &mut text), Some(ZOO12_KPUB45));
    let out = f.touch(answer_at(dialog::Target::Accept));
    assert_eq!(out.screen, Screen::DescriptorFormat, "Show QR");
    assert_eq!(
        f.step(back_button(), &mut Live).screen,
        Screen::Descriptor { own: Some(2) },
        "its Back, the seed in use's key still marked"
    );
    assert_eq!(f.step(back_button(), &mut Live).screen, listed);
    open(&mut f);
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::Home);

    // A group none of whose keys is the seed in use's: nothing marked.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    create_group(&mut f, 2, 2);
    for kpub in [ZOO12_KPUB45, ABANDON24_KPUB45] {
        scan_cosigner(&mut f, kpub.as_bytes());
    }
    assert_eq!(open(&mut f), Screen::Descriptor { own: None });
}

/// **DESCRIPTOR QR: the descriptor in codes, as a signed message's.** The
/// 2-of-3's 349 bytes are 2 version-9 frames for a wallet, 8 version-3 for
/// a unit, reading back as the group; a 1-of-1's is one bare code for a
/// wallet, 3 frames for a unit.
#[test]
fn the_descriptor_is_shown_as_codes() {
    use kassigner_fw::flow::HeldGroup;
    use kassigner_fw::limits::{KASSIGNER_FRAME_US, WALLET_FRAME_US};
    use kassigner_fw::ui::kpub::{zone, Target as Card};
    use kassigner_protocol::descriptor::max_len;
    use kassigner_protocol::frame::{self, Format};
    let pick = |t| tap_in(zone(SCALE, t).unwrap());
    let answer_at = |t| tap_in(dialog::zone(SCALE, t).unwrap());
    let descriptor_of = |f: &Flow<'_, 6>| {
        let mut text = vec![0u8; max_len(5)];
        let n = f.group().unwrap().write_descriptor(&mut text).unwrap();
        text.truncate(n);
        text
    };
    let open = |f: &mut Flow<'_, 6>| {
        let out = f.step(item(&menu::MULTISIG, 2), &mut Live);
        settled(f, out);
        assert_eq!(f.state(), State::Descriptor);
        let out = f.touch(answer_at(dialog::Target::Accept));
        assert_eq!(out.screen, Screen::DescriptorFormat);
    };

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);
    create_group(&mut f, 2, 3);
    for kpub in [ZOO12_KPUB45, ABANDON24_KPUB45, ABANDON12_KPUB45] {
        scan_cosigner(&mut f, kpub.as_bytes());
    }
    let text = descriptor_of(&f);
    assert_eq!(text.len(), 349);
    assert_eq!(text.len(), max_len(3), "its length, exactly");
    open(&mut f);
    assert_eq!(
        (f.descriptor_codes(true), f.descriptor_codes(false)),
        (2, 8)
    );
    assert!(f.descriptor_fits(true) && f.descriptor_fits(false));

    for (card, frames, most, every) in [
        (Card::Wallet, 2u8, 53, WALLET_FRAME_US),
        (Card::KasSigner, 8, 29, KASSIGNER_FRAME_US),
    ] {
        assert_eq!(f.state(), State::DescriptorFormat);
        f.step(pick(card), &mut Live);
        assert_eq!(f.state(), State::DescriptorMode, "{card:?}");
        let out = f.touch(answer_at(dialog::Target::Cancel));
        assert_eq!(out.screen, Screen::DescriptorFrames { frame: 0, frames });
        let mut joined = Vec::new();
        for i in 0..frames {
            assert_eq!(f.state(), State::DescriptorFrames { frame: i });
            let code = f.descriptor_frame(i).unwrap();
            if card == Card::Wallet {
                assert_eq!(code.size, most, "every wallet frame at version 9");
            } else {
                assert!(code.size <= most, "{} modules", code.size);
            }
            let bytes = read_back(&code);
            let read = frame::parse(&bytes, 64).expect("a frame");
            assert_eq!(read.format, Format::Descriptor);
            assert_eq!((read.index, read.total), (i, frames));
            joined.extend_from_slice(read.fragment);
            let now_us = f.now_us() + every;
            f.step(Event::Tick { now_us }, &mut Live);
        }
        assert_eq!(joined, text);
        let read = HeldGroup::from_descriptor(core::str::from_utf8(&joined).unwrap());
        assert_eq!(
            read.as_ref(),
            Ok(f.group().unwrap()),
            "the group, read back"
        );
        assert_eq!(f.state(), State::DescriptorFrames { frame: 0 }, "round");
        f.step(tap_in(SCALE.zone(100, 100, 10, 10)), &mut Live);
        assert_eq!(f.state(), State::Descriptor, "a tap is DESCRIPTOR");
        f.touch(answer_at(dialog::Target::Accept));
    }

    // A 1-of-1: one code for a wallet, the text itself.
    f.step(home_button(), &mut Live);
    create_group(&mut f, 1, 1);
    scan_cosigner(&mut f, ZOO12_KPUB45.as_bytes());
    let text = descriptor_of(&f);
    assert_eq!(text.len(), max_len(1));
    open(&mut f);
    assert_eq!(
        (f.descriptor_codes(true), f.descriptor_codes(false)),
        (1, 3)
    );
    let out = f.step(pick(Card::Wallet), &mut Live);
    assert_eq!(
        out.screen,
        Screen::DescriptorFrames {
            frame: 0,
            frames: 1
        }
    );
    assert_eq!(read_back(&f.descriptor_frame(0).unwrap()), text);
    f.step(tap_in(SCALE.zone(100, 100, 10, 10)), &mut Live);
    assert_eq!(f.state(), State::Descriptor);
}

/// **DESCRIPTOR's Save to SD, `MDnnnn.TXT`**: plain, v1.0.7's comment line
/// then the QR's text, reading back as the group; or sealed under the
/// descriptor's purpose. Written over, the old file is read first, and a
/// sealed one's password asked.
#[test]
fn the_descriptor_is_saved_plain_or_sealed() {
    use kassigner_crypto::backup::FILE_MAX;
    use kassigner_crypto::container::open;
    use kassigner_fw::flow::{HeldGroup, Typing};
    use kassigner_kaspa::kat::MULTISIG_45;
    use kassigner_protocol::container::{parse, Purpose};
    use kassigner_protocol::descriptor::max_len;
    let password = b"Correct-Horse-9";
    let answer_at = |t| tap_in(dialog::zone(SCALE, t).unwrap());
    // What the file holds: the comment line, then the QR's text.
    let file_of = |f: &Flow<'_, 6>| {
        let group = f.group().unwrap();
        let mut text = vec![0u8; max_len(5)];
        let n = group.write_descriptor(&mut text).unwrap();
        let mut file = format!(
            "# KasSigner multisig, 45' coordinated, {}-of-{}\n",
            group.required(),
            group.total()
        )
        .into_bytes();
        file.extend_from_slice(&text[..n]);
        file
    };
    // From MULTISIG: Multisig Descriptor, Save to SD, the next name
    // offered.
    let save = |f: &mut Flow<'_, 6>, sd: &mut Sd| {
        let out = f.step(item(&menu::MULTISIG, 2), &mut Live);
        settled(f, out);
        assert_eq!(f.state(), State::Descriptor);
        assert_eq!(
            f.touch(answer_at(dialog::Target::Cancel)).command,
            Some(Command::Card(Job::NextName))
        );
        run_job(f, sd, Job::NextName);
    };
    // Plain, from ENCRYPT FILE?.
    let plain = |f: &mut Flow<'_, 6>, sd: &mut Sd| {
        assert_eq!(f.state(), State::KpubEncrypt);
        assert_eq!(
            f.touch(answer_at(dialog::Target::Accept)).command,
            Some(Command::Card(Job::Write))
        );
        run_job(f, sd, Job::Write);
        assert_eq!(f.saved_text(), "!! Descriptor Saved !!");
    };
    // Saved: DESCRIPTOR again, then its Back, MULTISIG.
    let saved = |f: &mut Flow<'_, 6>, t: &mut u64| {
        *t += 10_000_000;
        f.step(Event::Tick { now_us: *t }, &mut Live);
        assert_eq!(f.state(), State::Descriptor, "DESCRIPTOR again");
        f.step(back_button(), &mut Live);
        assert_eq!(
            f.state(),
            State::Menu {
                menu: MenuId::Multisig,
                page: 0
            }
        );
    };

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);
    create_group(&mut f, 2, 3);
    for kpub in [ZOO12_KPUB45, ABANDON24_KPUB45, ABANDON12_KPUB45] {
        scan_cosigner(&mut f, kpub.as_bytes());
    }
    let mut sd = card_with(&[]);
    let mut t = f.now_us();

    // Plain, MD0001.TXT: the comment line and the group's descriptor.
    save(&mut f, &mut sd);
    assert_eq!(f.typed().0, "MD0001");
    assert_eq!(
        press(&mut f, keyboard::Key::Ok).command,
        Some(Command::Card(Job::Exists))
    );
    run_job(&mut f, &mut sd, Job::Exists);
    plain(&mut f, &mut sd);
    let three = file_of(&f);
    assert!(three.starts_with(b"# KasSigner multisig, 45' coordinated, 2-of-3\n"));
    assert_eq!(on_card(&mut sd, b"MD0001  TXT"), three);
    let read = HeldGroup::from_descriptor(core::str::from_utf8(&three).unwrap());
    assert_eq!(
        read.as_ref(),
        Ok(f.group().unwrap()),
        "the group, read back"
    );
    saved(&mut f, &mut t);

    // A 5-of-5, the longest file, over MD0001: read, then replaced.
    f.step(home_button(), &mut Live);
    create_group(&mut f, 5, 5);
    for kpub in MULTISIG_45.kpubs {
        scan_cosigner(&mut f, kpub.as_bytes());
    }
    save(&mut f, &mut sd);
    assert_eq!(f.typed().0, "MD0002", "the next number");
    name_as(&mut f, &mut sd, b"MD0001");
    overwrite(&mut f, &mut sd);
    plain(&mut f, &mut sd);
    let five = file_of(&f);
    assert_eq!(
        five.len(),
        "# KasSigner multisig, 45' coordinated, 5-of-5\n".len() + max_len(5),
        "the longest"
    );
    assert_eq!(on_card(&mut sd, b"MD0001  TXT"), five);
    saved(&mut f, &mut t);

    // Sealed, MD0002: the descriptor's own purpose, opening to the same.
    save(&mut f, &mut sd);
    assert_eq!(f.typed().0, "MD0002");
    press(&mut f, keyboard::Key::Ok);
    run_job(&mut f, &mut sd, Job::Exists);
    assert_eq!(f.state(), State::KpubEncrypt);
    f.touch(answer_at(dialog::Target::Cancel));
    for _ in 0..2 {
        type_on(&mut f, password);
        press(&mut f, keyboard::Key::Ok);
    }
    while matches!(f.state(), State::BackupSealing { .. }) {
        f.step(Event::Tick { now_us: t }, &mut Live);
    }
    run_job(&mut f, &mut sd, Job::Write);
    assert_eq!(f.saved_text(), "!! Descriptor Saved !!");
    let sealed = on_card(&mut sd, b"MD0002  TXT");
    assert!(sealed.len() > FILE_MAX, "larger than any backup");
    assert_eq!(
        parse(&sealed).unwrap().purpose,
        Purpose::Descriptor,
        "marked, before the password"
    );
    let mut text = vec![0u8; sealed.len()];
    let opened = open(&sealed, password, &mut text, None).unwrap();
    assert_eq!(opened.purpose, Purpose::Descriptor);
    assert_eq!(&text[..opened.len], &five[..]);
    saved(&mut f, &mut t);

    // Over the sealed MD0002: its password asked, then plain.
    save(&mut f, &mut sd);
    name_as(&mut f, &mut sd, b"MD0002");
    assert!(matches!(
        overwrite(&mut f, &mut sd),
        Screen::Keyboard {
            typing: Typing::OverwritePassword,
            ..
        }
    ));
    type_on(&mut f, password);
    press(&mut f, keyboard::Key::Ok);
    opened_at(&mut f, &mut t);
    plain(&mut f, &mut sd);
    assert_eq!(on_card(&mut sd, b"MD0002  TXT"), five);
    saved(&mut f, &mut t);
}

/// **Import from SD's Multisig Descriptor: a group from the card.** SELECT
/// FILE lists the descriptors; LOAD MULTISIG? says what was read, the seed
/// in use's place and what it does to the held group; LOAD holds it. A
/// wrong password, keys that are not kpubs and an empty card are said; the
/// trash deletes one.
#[test]
fn a_descriptor_is_loaded_from_the_card() {
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_fw::flow::HeldGroup;
    use kassigner_fw::ui::backup::{self, pick_zone, Pick};
    use kassigner_fw::ui::multisig::{Held, SeedIn};
    use kassigner_kaspa::kat::MULTISIG_45;
    use kassigner_protocol::container::Purpose;

    let password = b"Correct-Horse-9";
    let three = format!(
        "# KasSigner multisig, 45' coordinated, 2-of-3\nmulti_hd45(2,{ZOO12_KPUB45},{ABANDON12_KPUB45},{ABANDON24_KPUB45})"
    );
    let five = format!("multi_hd45(2,{})", MULTISIG_45.kpubs.join(","));
    let not_keys = format!("multi_hd45(1,kpub{})", "1".repeat(107));
    let mut sealed = [0u8; 1024];
    let n = seal(
        Purpose::Descriptor,
        five.as_bytes(),
        password,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut sealed,
    )
    .unwrap();
    let mut sd = card_with(&[
        (b"MD0001  TXT", three.as_bytes()),
        (b"MD0002  TXT", &sealed[..n]),
        (b"MD0003  TXT", not_keys.as_bytes()),
        (b"KP0001  TXT", ZOO12_KPUB45.as_bytes()),
    ]);
    let group_of = |text: &str| HeldGroup::from_descriptor(text).unwrap();

    // From anywhere: Import from SD, Multisig Descriptor, the card listed.
    let list = |f: &mut Flow<'_, 6>, sd: &mut Sd| {
        f.touch(home_button());
        f.step(card(2), &mut Live);
        f.step(item(&menu::TOOLS, 1), &mut Live);
        f.step(
            tap_in(backup::zone(SCALE, backup::Target::Import).unwrap()),
            &mut Live,
        );
        f.step(item(&menu::IMPORT, 0), &mut Live);
        let down = menu::zone(SCALE, &menu::IMPORT_SD, 0, menu::Target::Nav(Nav::PageDown));
        f.step(tap_in(down.expect("a second page")), &mut Live);
        let out = f.step(item(&menu::IMPORT_SD, 4), &mut Live);
        assert_eq!(out.command, Some(Command::Card(Job::ListGroups)));
        run_job(f, sd, Job::ListGroups)
    };
    let at = |f: &Flow<'_, 6>, name: &[u8; 11], pick: fn(usize) -> Pick| {
        let i = f.backups().iter().position(|b| b == name).unwrap();
        tap_in(pick_zone(SCALE, f.backups().len(), 0, pick(i)).unwrap())
    };
    // A row's password typed, OK, the file read, and opened.
    let opened = |f: &mut Flow<'_, 6>, sd: &mut Sd, typed: &[u8]| {
        restore_type(f, typed);
        assert_eq!(restore_ok(f).command, Some(Command::Card(Job::Read)));
        let mut out = run_job(f, sd, Job::Read);
        while matches!(f.state(), State::RestoreOpening { .. }) {
            let now_us = f.now_us();
            out = f.step(Event::Tick { now_us }, &mut Live);
        }
        out.screen
    };
    // A failure, said, then gone: the list again.
    let failed = |f: &mut Flow<'_, 6>, why: &'static str| {
        assert_eq!(
            f.state(),
            State::CardDone {
                job: Job::Read,
                outcome: Outcome::Failed(card::Error::Backup(why)),
            }
        );
        assert_eq!(f.card_said().failed, "Descriptor Load Failed");
        let now_us = f.now_us() + 10_000_000;
        f.step(Event::Tick { now_us }, &mut Live);
        assert_eq!(f.state(), State::RestoreList { page: 0 });
    };
    let take = |f: &mut Flow<'_, 6>| f.touch(answer(dialog::Target::Accept)).screen;

    // abandon 12 in use, a 1-of-2 held.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);
    create_group(&mut f, 1, 2);
    for kpub in [ZOO12_KPUB45, ABANDON24_KPUB45] {
        scan_cosigner(&mut f, kpub.as_bytes());
    }
    let held = *f.group().unwrap();

    list(&mut f, &mut sd);
    assert_eq!(f.list_title(), "SELECT FILE");
    assert_eq!(
        f.backups(),
        &[*b"MD0001  TXT", *b"MD0002  TXT", *b"MD0003  TXT"],
        "the descriptors, and not the kpub"
    );

    // Plain: anything typed does not open it.
    f.step(at(&f, b"MD0001  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, b"abc");
    failed(&mut f, "Wrong password or damaged file");

    // Nothing typed: LOAD MULTISIG?; CANCEL, the list, the 1-of-2 held.
    f.step(at(&f, b"MD0001  TXT", Pick::Row), &mut Live);
    let asked = Screen::LoadGroup {
        m: 2,
        n: 3,
        seed: SeedIn::Cosigner(2),
        held: Held::Other(1, 2),
    };
    assert_eq!(opened(&mut f, &mut sd, b""), asked);
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(f.state(), State::RestoreList { page: 0 });
    assert_eq!(f.group(), Some(&held), "the group held as it was");

    // LOAD: held, DESCRIPTOR with the seed in use's key marked; Back is
    // MULTISIG, and Multisig Address derives the new keys.
    f.step(at(&f, b"MD0001  TXT", Pick::Row), &mut Live);
    assert_eq!(opened(&mut f, &mut sd, b""), asked);
    assert_eq!(take(&mut f), Screen::Descriptor { own: Some(2) });
    assert_eq!(f.group(), Some(&group_of(&three)));
    f.step(back_button(), &mut Live);
    assert_eq!(
        open_group_address(&mut f),
        Screen::GroupDeriving { done: 0, total: 9 }
    );
    assert_eq!(
        group_derived(&mut f),
        Screen::GroupAddress {
            change: false,
            index: 0,
            cosigner: 2
        }
    );
    assert_eq!(
        f.address_text(),
        "kaspa:prvfzy9wjlewtyk9qeczkd0ehyxfcycxz9c99yr2x3nu7uk6zw872c06xr7d9",
        "the group made on the units, its address"
    );

    // The group already held: nothing changes, nothing derived again.
    list(&mut f, &mut sd);
    f.step(at(&f, b"MD0001  TXT", Pick::Row), &mut Live);
    assert_eq!(
        opened(&mut f, &mut sd, b""),
        Screen::LoadGroup {
            m: 2,
            n: 3,
            seed: SeedIn::Cosigner(2),
            held: Held::Same,
        }
    );
    take(&mut f);
    f.step(back_button(), &mut Live);
    assert_eq!(
        open_group_address(&mut f),
        Screen::GroupAddress {
            change: false,
            index: 0,
            cosigner: 2
        },
        "no DERIVING"
    );

    // Sealed: not another password; its own.
    list(&mut f, &mut sd);
    f.step(at(&f, b"MD0002  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, b"Correct-Horse-8");
    failed(&mut f, "Wrong password or damaged file");
    f.step(at(&f, b"MD0002  TXT", Pick::Row), &mut Live);
    assert_eq!(
        opened(&mut f, &mut sd, password),
        Screen::LoadGroup {
            m: 2,
            n: 5,
            seed: SeedIn::Not,
            held: Held::Other(2, 3),
        }
    );
    assert_eq!(take(&mut f), Screen::Descriptor { own: None });
    assert_eq!(f.group(), Some(&group_of(&five)));

    // Not kpubs: refused, the group held as it was.
    list(&mut f, &mut sd);
    f.step(at(&f, b"MD0003  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, b"");
    failed(&mut f, "Not a valid descriptor");
    assert_eq!(f.group(), Some(&group_of(&five)));

    // The trash: the password, then the hold; the list is what is left.
    f.step(at(&f, b"MD0003  TXT", Pick::Trash), &mut Live);
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
        Some(Command::Card(Job::ListGroups)),
        "the descriptors listed again"
    );
    run_job(&mut f, &mut sd, Job::ListGroups);
    assert_eq!(f.backups(), &[*b"MD0001  TXT", *b"MD0002  TXT"]);

    // No seed in use: said; LOAD holds the group, nothing marked.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    list(&mut f, &mut sd);
    f.step(at(&f, b"MD0001  TXT", Pick::Row), &mut Live);
    assert_eq!(
        opened(&mut f, &mut sd, b""),
        Screen::LoadGroup {
            m: 2,
            n: 3,
            seed: SeedIn::NoSeed,
            held: Held::Nothing,
        }
    );
    assert_eq!(take(&mut f), Screen::Descriptor { own: None });
    assert_eq!(f.group(), Some(&group_of(&three)));

    // An empty card.
    let mut empty = card_with(&[]);
    list(&mut f, &mut empty);
    assert_eq!(f.card_said().empty, ("No descriptors found", ""));
    let now_us = f.now_us() + 10_000_000;
    f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::ImportSd,
            page: 1
        },
        "back on its row's page"
    );
}

/// **Import from SD's Multisig Address: a group's address from the card.**
/// SELECT FILE lists the card's `MSnnnn.TXT`; MULTISIG ADDRESS shows one
/// under its name, its code a tap away. A wrong password, a file that is
/// not a mainnet multisig address and an empty card are said; the trash
/// deletes one.
#[test]
fn a_multisig_address_is_read_from_the_card() {
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_fw::ui::address::{zone, Target};
    use kassigner_fw::ui::backup::{self, pick_zone, Pick};
    use kassigner_protocol::container::Purpose;

    let password = b"Correct-Horse-9";
    let address = "kaspa:prvfzy9wjlewtyk9qeczkd0ehyxfcycxz9c99yr2x3nu7uk6zw872c06xr7d9";
    let sealed = |text: &[u8]| {
        let mut out = [0u8; 256];
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
    // The same script on testnet.
    let mut testnet = [0u8; 80];
    let n = kassigner_kaspa::address::encode(
        kassigner_kaspa::address::Prefix::Testnet,
        kassigner_kaspa::address::Version::ScriptHash,
        &[7; 32],
        &mut testnet,
    )
    .unwrap();
    let mut sd = card_with(&[
        (b"MS0001  TXT", format!("{address}\r\n").as_bytes()),
        (b"MS0002  TXT", &sealed(address.as_bytes())),
        (b"MS0003  TXT", &sealed(b"hello")),
        (b"MS0004  TXT", &sealed(&testnet[..n])),
        (b"MS0005  TXT", &testnet[..n]),
        (b"KP0001  TXT", ZOO12_KPUB45.as_bytes()),
    ]);

    // From anywhere: Import from SD, Multisig Address, the card listed.
    let list = |f: &mut Flow<'_, 6>, sd: &mut Sd| {
        f.touch(home_button());
        f.step(card(2), &mut Live);
        f.step(item(&menu::TOOLS, 1), &mut Live);
        f.step(
            tap_in(backup::zone(SCALE, backup::Target::Import).unwrap()),
            &mut Live,
        );
        f.step(item(&menu::IMPORT, 0), &mut Live);
        let out = f.step(item(&menu::IMPORT_SD, 3), &mut Live);
        assert_eq!(out.command, Some(Command::Card(Job::ListAddresses)));
        run_job(f, sd, Job::ListAddresses)
    };
    let at = |f: &Flow<'_, 6>, name: &[u8; 11], pick: fn(usize) -> Pick| {
        let i = f.backups().iter().position(|b| b == name).unwrap();
        tap_in(pick_zone(SCALE, f.backups().len(), 0, pick(i)).unwrap())
    };
    let opened = |f: &mut Flow<'_, 6>, sd: &mut Sd, typed: &[u8]| {
        restore_type(f, typed);
        assert_eq!(restore_ok(f).command, Some(Command::Card(Job::Read)));
        let mut out = run_job(f, sd, Job::Read);
        while matches!(f.state(), State::RestoreOpening { .. }) {
            let now_us = f.now_us();
            out = f.step(Event::Tick { now_us }, &mut Live);
        }
        out.screen
    };
    let failed = |f: &mut Flow<'_, 6>, why: &'static str| {
        assert_eq!(
            f.state(),
            State::CardDone {
                job: Job::Read,
                outcome: Outcome::Failed(card::Error::Backup(why)),
            }
        );
        assert_eq!(f.card_said().failed, "Address Load Failed");
        let now_us = f.now_us() + 10_000_000;
        f.step(Event::Tick { now_us }, &mut Live);
        assert_eq!(f.state(), State::RestoreList { page: 0 });
    };
    let shown = |name: &[u8; 11]| Screen::FileAddress {
        name: card::FileName(*name),
    };
    let on_address = tap_in(zone(SCALE, true, true, Target::Address).unwrap());

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    list(&mut f, &mut sd);
    assert_eq!(f.list_title(), "SELECT FILE");
    assert_eq!(
        f.backups(),
        &[
            *b"MS0001  TXT",
            *b"MS0002  TXT",
            *b"MS0003  TXT",
            *b"MS0004  TXT"
        ],
        "the group's addresses, and not the kpub nor another network's"
    );

    // Plain: opens only with nothing typed; its code a tap away and back;
    // Back, the list.
    f.step(at(&f, b"MS0001  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, b"abc");
    failed(&mut f, "Wrong password or damaged file");
    f.step(at(&f, b"MS0001  TXT", Pick::Row), &mut Live);
    assert_eq!(opened(&mut f, &mut sd, b""), shown(b"MS0001  TXT"));
    assert_eq!(f.file_address(), address, "its line end aside");
    assert_eq!(f.step(on_address, &mut Live).screen, Screen::FileAddressQr);
    assert_eq!(f.step(on_address, &mut Live).screen, shown(b"MS0001  TXT"));
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::RestoreList { page: 0 });

    // Sealed: not another password; its own. Home is home.
    f.step(at(&f, b"MS0002  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, b"Correct-Horse-8");
    failed(&mut f, "Wrong password or damaged file");
    f.step(at(&f, b"MS0002  TXT", Pick::Row), &mut Live);
    assert_eq!(opened(&mut f, &mut sd, password), shown(b"MS0002  TXT"));
    assert_eq!(f.file_address(), address);
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::Home);

    // Sealed over something else: refused.
    list(&mut f, &mut sd);
    f.step(at(&f, b"MS0003  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, password);
    failed(&mut f, "Not a multisig address");

    // Another network's script address, sealed: refused as not one (plain,
    // it was not listed).
    list(&mut f, &mut sd);
    f.step(at(&f, b"MS0004  TXT", Pick::Row), &mut Live);
    opened(&mut f, &mut sd, password);
    failed(&mut f, "Not a multisig address");

    // The trash: the password, then the hold; the list is what is left.
    f.step(at(&f, b"MS0003  TXT", Pick::Trash), &mut Live);
    opened(&mut f, &mut sd, password);
    assert!(
        matches!(f.state(), State::RestoreDelete { .. }),
        "{:?}",
        f.state()
    );
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
        Some(Command::Card(Job::ListAddresses)),
        "the addresses listed again"
    );
    run_job(&mut f, &mut sd, Job::ListAddresses);
    assert_eq!(
        f.backups(),
        &[*b"MS0001  TXT", *b"MS0002  TXT", *b"MS0004  TXT"]
    );

    // An empty card.
    let mut empty = card_with(&[]);
    list(&mut f, &mut empty);
    assert_eq!(f.card_said().empty, ("No addresses found", ""));
    let now_us = f.now_us() + 10_000_000;
    f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::ImportSd,
            page: 0
        },
        "back on its row's page"
    );
}

/// **A descriptor scanned on Home asks LOAD MULTISIG?, as from the card**:
/// one code, with or without v1.0.7's comment line, a unit's frames, or
/// v1.0.7's frames, which come as text. Keys that are not kpubs are
/// refused; while a group is being made a descriptor is refused as no key.
#[test]
fn a_descriptor_is_loaded_from_the_scanner() {
    use kassigner_fw::flow::HeldGroup;
    use kassigner_fw::ui::multisig::{Held, SeedIn};
    use kassigner_kaspa::kat::MULTISIG_45;

    let three = format!("multi_hd45(2,{ZOO12_KPUB45},{ABANDON12_KPUB45},{ABANDON24_KPUB45})");
    let headed = format!("# KasSigner multisig, 45' coordinated, 2-of-3\n{three}");
    let five = format!("multi_hd45(2,{})", MULTISIG_45.kpubs.join(","));
    let group_of = |text: &str| HeldGroup::from_descriptor(text).unwrap();
    let scanned = |f: &mut Flow<'_, 6>, event: Event<'_>| {
        assert_eq!(f.step(scan(), &mut Live).command, Some(Command::CameraOn));
        let out = f.step(event, &mut Live);
        assert_eq!(out.command, Some(Command::CameraOff));
        out.screen
    };

    // abandon 12 in use, a 1-of-2 held.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);
    create_group(&mut f, 1, 2);
    for kpub in [ZOO12_KPUB45, ABANDON24_KPUB45] {
        scan_cosigner(&mut f, kpub.as_bytes());
    }
    f.step(home_button(), &mut Live);
    let held = *f.group().unwrap();

    // One code: CANCEL is home, the 1-of-2 held as it was.
    let asked = Screen::LoadGroup {
        m: 2,
        n: 3,
        seed: SeedIn::Cosigner(2),
        held: Held::Other(1, 2),
    };
    assert_eq!(scanned(&mut f, Event::Code(three.as_bytes())), asked);
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.group(), Some(&held));

    // Its comment line over it: the same; LOAD holds it.
    assert_eq!(scanned(&mut f, Event::Code(headed.as_bytes())), asked);
    assert_eq!(
        f.touch(answer(dialog::Target::Accept)).screen,
        Screen::Descriptor { own: Some(2) }
    );
    assert_eq!(f.group(), Some(&group_of(&three)));
    f.step(home_button(), &mut Live);

    // A unit's frames, and v1.0.7's, which come as text.
    assert_eq!(
        scanned(&mut f, Event::Payload(five.as_bytes())),
        Screen::LoadGroup {
            m: 2,
            n: 5,
            seed: SeedIn::Not,
            held: Held::Other(2, 3),
        }
    );
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(
        scanned(&mut f, Event::Opaque(headed.as_bytes())),
        Screen::LoadGroup {
            m: 2,
            n: 3,
            seed: SeedIn::Cosigner(2),
            held: Held::Same,
        }
    );
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(f.group(), Some(&group_of(&three)));

    // Keys that are not kpubs: refused, the group held as it was.
    let not_keys = format!("multi_hd45(1,kpub{})", "1".repeat(107));
    assert_eq!(
        scanned(&mut f, Event::Code(not_keys.as_bytes())),
        Screen::Refused(Refusal::NotADescriptor)
    );
    assert_eq!(f.group(), Some(&group_of(&three)));
    let now_us = f.now_us() + REFUSED_US + 1;
    f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(f.state(), State::Home);

    // A group being made: a descriptor is no key.
    create_group(&mut f, 2, 2);
    assert_eq!(
        scan_cosigner(&mut f, three.as_bytes()),
        Screen::Refused(Refusal::NotAKpub)
    );
    assert_eq!(f.group(), Some(&group_of(&three)));
}

/// **A group's spend: TX REVIEW says its M of N, and an output to the held
/// group's change says CHANGE.** On kassigner.org 1.0.7's 2-of-3 spends, a
/// KSPT and a bundle, TX REVIEW says 2-of-3 from the request's script. The
/// output the request places at the group's change (by output hint or key
/// path) is CHANGE only with that group held, whether Multisig Address has
/// derived or not; misplaced, it is not. With no group held TX REVIEW says
/// the spend is unchecked. With another group held the spend is refused,
/// even one whose change goes to that group's own change address: a held
/// group's change is change only for the group's own inputs.
#[test]
fn a_group_spend_shows_its_group_and_its_change() {
    use kassigner_fw::flow::HeldGroup;
    use kassigner_fw::ui::review::Shown;
    use kassigner_kaspa::bip32_public::ExtendedPublicKey;
    use kassigner_kaspa::kat::MULTISIG_45;
    use kassigner_kaspa::script::{pay_to_script_hash, redeem_hash};
    /// TX REVIEW's group, and each output page's CHANGE; CONFIRM SEND?
    /// repeats TX REVIEW's counts and group.
    fn reviewed(f: &mut Flow<'_, 6>, req: &[u8]) -> (Option<(usize, usize)>, Vec<review::Change>) {
        f.step(scan(), &mut Live);
        deliver(f, req);
        assert_eq!(f.state(), State::Reviewing);
        let (group, counts, unchecked) = f
            .review(|s| match *s {
                Shown::Summary {
                    group,
                    inputs,
                    outputs,
                    unchecked,
                    ..
                } => (group, (inputs, outputs), unchecked),
                _ => panic!("TX REVIEW first"),
            })
            .unwrap();
        // A multisig's spend with no group held, and only that, says so.
        assert_eq!(unchecked, group.is_some() && f.group().is_none());
        let mut change = Vec::new();
        loop {
            arrow(f, RIGHT);
            if f.state() != State::Reviewing {
                break;
            }
            change.push(
                f.review(|s| match *s {
                    Shown::Output { change, .. } => change,
                    _ => panic!("an output"),
                })
                .unwrap(),
            );
        }
        assert_eq!(f.state(), State::Confirming);
        let (_, counted) = f.summary().expect("CONFIRM SEND?'s window");
        assert_eq!(counted.group, group);
        assert_eq!(counted.unchecked, unchecked, "CONFIRM SEND? says it too");
        assert_eq!((counted.inputs, counted.outputs), counts);
        // Home on CONFIRM SEND? declines it; home once that is said.
        f.touch(home_button());
        let now_us = f.now_us() + REFUSED_US + 1;
        f.step(Event::Tick { now_us }, &mut Live);
        assert_eq!(f.state(), State::Home);
        (group, change)
    }
    let held = |f: &mut Flow<'_, 6>, (m, n): (u8, u8), keys: &[&str]| {
        f.step(home_button(), &mut Live);
        create_group(f, m, n);
        for kpub in keys {
            scan_cosigner(f, kpub.as_bytes());
        }
        f.step(home_button(), &mut Live);
    };
    let spends: [&[u8]; 2] = [
        corpus!("site/kspt2_relay_multisig.bin"),
        corpus!("site/pskb_multisig.bin"),
    ];

    // Change placed at index 0 of a change chain, the group's or the key's.
    const NO: review::Change = review::Change::No;
    const AT_0: review::Change = review::Change::At(0);
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);

    // No group held: the request's 2-of-3, nothing CHANGE.
    for req in spends {
        assert_eq!(reviewed(&mut f, req), (Some((2, 3)), vec![NO, NO]));
    }

    // The 2-of-3 held: its change.
    held(
        &mut f,
        (2, 3),
        &[ZOO12_KPUB45, ABANDON24_KPUB45, ABANDON12_KPUB45],
    );
    for req in spends {
        assert_eq!(reviewed(&mut f, req), (Some((2, 3)), vec![NO, AT_0]));
    }
    // Its keys worked out by Multisig Address: the same.
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 3), &mut Live);
    open_group_address(&mut f);
    group_derived(&mut f);
    f.step(home_button(), &mut Live);
    for req in spends {
        assert_eq!(reviewed(&mut f, req), (Some((2, 3)), vec![NO, AT_0]));
    }

    // The bundle's change placed at index 1, or nowhere: no CHANGE.
    let bundle_with = |from: &str, to: &str| {
        use kassigner_kaspa::pskb::{decode_envelope, encode_envelope};
        let mut json = vec![0u8; spends[1].len()];
        let n = decode_envelope(spends[1], &mut json).unwrap();
        let text = String::from_utf8(json[..n].to_vec()).unwrap();
        assert!(text.contains(from), "{from}");
        let edited = text.replace(from, to);
        let mut out = vec![0u8; 4 + 2 * edited.len()];
        let n = encode_envelope(edited.as_bytes(), &mut out).unwrap();
        out.truncate(n);
        out
    };
    let moved = bundle_with("m/45'/111111'/0'/0/1/0", "m/45'/111111'/0'/0/1/1");
    assert_eq!(reviewed(&mut f, &moved), (Some((2, 3)), vec![NO, NO]));
    let unplaced = bundle_with("m/45'/111111'/0'/0/1/0", "m/45'/111111'/0'/0/9");
    assert_eq!(reviewed(&mut f, &unplaced), (Some((2, 3)), vec![NO, NO]));

    // Another 2-of-3, and a 1-of-2: the inputs are not theirs, refused.
    assert_eq!(
        Refusal::NotTheGroups.words(),
        ("Signing failed", "An input is not this group's")
    );
    let refused = |f: &mut Flow<'_, 6>, req: &[u8]| {
        f.step(scan(), &mut Live);
        deliver(f, req);
        assert_eq!(f.state(), State::Refused(Refusal::NotTheGroups));
        let now_us = f.now_us() + REFUSED_US + 1;
        f.step(Event::Tick { now_us }, &mut Live);
        assert_eq!(f.state(), State::Home);
    };
    held(&mut f, (2, 3), &MULTISIG_45.kpubs[..3]);
    for req in spends {
        refused(&mut f, req);
    }
    held(&mut f, (1, 2), &[ZOO12_KPUB45, ABANDON24_KPUB45]);
    for req in spends {
        refused(&mut f, req);
    }

    // A look-alike 2-of-3, this seed's key with two of someone else's, and
    // the bundle's change sent to that group's own change address: the
    // inputs are still the other group's, refused.
    let alike = [ABANDON12_KPUB45, MULTISIG_45.kpubs[0], MULTISIG_45.kpubs[1]];
    let keys: Vec<ExtendedPublicKey> = alike
        .iter()
        .map(|t| ExtendedPublicKey::from_text(t.as_bytes()).unwrap().1)
        .collect();
    let mut redeem = [0u8; 256];
    let n = HeldGroup::new(2, &keys)
        .unwrap()
        .redeem(0, 1, 0, &mut redeem)
        .unwrap();
    let its_change: String = pay_to_script_hash(&redeem_hash(&redeem[..n]))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let swapped = bundle_with(
        "aa20f13e98ad1d340b3e555a6128d23388e00630c73cb0a5fcc3e6e09e3e469d7ce587",
        &its_change,
    );
    held(&mut f, (2, 3), &alike);
    refused(&mut f, &swapped);

    // A single key's send: no group, its own change.
    assert_eq!(
        reviewed(&mut f, corpus!("site/kspt_send_1in.bin")),
        (None, vec![NO, AT_0])
    );
}

/// **The warning that no group is held does not depend on the inputs
/// sharing one M of N.** A bundle spending a single key's coin beside the
/// 2-of-3's has no M of N to show; with no group held TX REVIEW and CONFIRM
/// SEND? still say the spend is unchecked, where they once said nothing. A
/// host that knows the seed's coins could otherwise add one to a multisig
/// spend and so take the warning off the screen. With the group held such a
/// request is refused, as any input that is not the group's is.
#[test]
fn inputs_of_two_shapes_are_still_said_unchecked() {
    use kassigner_fw::ui::review::Shown;
    use kassigner_kaspa::pskb::{decode_envelope, encode_envelope};
    // A bundle's text, and its inputs' objects.
    let text_of = |bundle: &[u8]| {
        let mut json = vec![0u8; bundle.len()];
        let n = decode_envelope(bundle, &mut json).unwrap();
        String::from_utf8(json[..n].to_vec()).unwrap()
    };
    let inputs_of = |text: &str| {
        let from = text.find("\"inputs\":[").expect("inputs") + "\"inputs\":[".len();
        let to = text.find("],\"outputs\"").expect("outputs");
        text[from..to].to_string()
    };
    let multisig = text_of(corpus!("site/pskb_multisig.bin"));
    let single = inputs_of(&text_of(corpus!("site/pskb_send.bin")));
    let its = inputs_of(&multisig);
    let mixed = multisig
        .replacen(&its, &format!("{its},{single}"), 1)
        .replacen("\"inputCount\":1", "\"inputCount\":2", 1);
    let mut req = vec![0u8; 4 + 2 * mixed.len()];
    let n = encode_envelope(mixed.as_bytes(), &mut req).unwrap();
    req.truncate(n);

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, corpus!("seedqr/abandon12.standard"));
    f.step(home_button(), &mut Live);

    // No group held: two inputs, no M of N, and the warning.
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(f.state(), State::Reviewing);
    let said = f
        .review(|s| match *s {
            Shown::Summary {
                inputs,
                group,
                unchecked,
                ..
            } => (inputs, group, unchecked),
            _ => panic!("TX REVIEW first"),
        })
        .unwrap();
    assert_eq!(said, (2, None, true), "no M of N, and still unchecked");
    while f.state() == State::Reviewing {
        arrow(&mut f, RIGHT);
    }
    assert_eq!(f.state(), State::Confirming);
    let (_, counted) = f.summary().expect("CONFIRM SEND?'s window");
    assert_eq!((counted.group, counted.unchecked), (None, true));
    f.touch(home_button());
    let now_us = f.now_us() + REFUSED_US + 1;
    f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(f.state(), State::Home);

    // The group held: an input that is not its own, refused.
    create_group(&mut f, 2, 3);
    for kpub in [ZOO12_KPUB45, ABANDON24_KPUB45, ABANDON12_KPUB45] {
        scan_cosigner(&mut f, kpub.as_bytes());
    }
    f.step(home_button(), &mut Live);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(f.state(), State::Refused(Refusal::NotTheGroups));
}
