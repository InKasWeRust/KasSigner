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

//! Signing Keys and Import Raw Key: the kprvs and a private key shown, a raw
//! key typed and used, and its dialogs.

use super::*;

// ── Signing Keys ────────────────────────────────────────────────────────────

/// A key's text, as kprv.
fn kprv_text(k: &kassigner_crypto::bip32::ExtendedPrivateKey) -> String {
    use kassigner_crypto::bip32::{PrivatePrefix, XPRV_TEXT_MAX};
    let mut out = [0u8; XPRV_TEXT_MAX];
    let n = k.to_text(PrivatePrefix::Kprv, &mut out).unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// Private Key's DERIVING, on opening and after each change of chain or
/// index, and the tick that works the key out. No key is held while it is
/// up.
fn derived<const N: usize>(f: &mut Flow<'_, N>) -> kassigner_fw::flow::Output {
    assert_eq!(f.state(), State::KeyDeriving, "DERIVING first");
    assert_eq!(f.key_text(), None, "no key while it is worked out");
    let now_us = f.now_us() + 1;
    let out = f.step(Event::Tick { now_us }, &mut Live);
    assert_eq!(f.state(), State::Address, "the key, on the tick after");
    out
}

/// Export, Signing Keys, row `row`, from the home grid.
fn signing_key<const N: usize>(f: &mut Flow<'_, N>, row: usize) -> kassigner_fw::flow::Output {
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(
            kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Export)
                .unwrap(),
        ),
        &mut Live,
    );
    f.step(item(&menu::EXPORT, 2), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SigningKeys,
            page: 0
        }
    );
    f.step(item(&menu::SIGNING_KEYS, row), &mut Live)
}

/// A tap on the text of the address screen's layout, `single` as drawn.
fn on_text(single: bool) -> Event<'static> {
    use kassigner_fw::ui::address as screen;
    tap_in(screen::zone(SCALE, single, true, screen::Target::Address).unwrap())
}

/// **kprv Master is rusty-kaspa's**: a 24-word seed from rusty-kaspa's own
/// mnemonic vectors (the kaspa mainnet entry) gives the kprv rusty-kaspa
/// writes for it.
#[test]
fn kprv_master_is_rusty_kaspas() {
    let phrase = "cruise village slam canyon monster scrub myself farm add riot large board \
                  sentence outer nice coast raven bird scheme undo december blanket trim hero";
    let m = bip39::from_words(phrase.split(' ')).unwrap();
    let mut qr = [0u8; slot::SEEDQR_MAX];
    let n = slot::to_seedqr(&m, &mut qr);
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    load(&mut f, &qr[..n]);
    f.step(home_button(), &mut Live);
    let out = signing_key(&mut f, 0);
    assert_eq!(out.screen, Screen::KprvDeriving);
    assert_eq!(f.key_text(), None, "nothing before the tick");
    let out = f.step(Event::Tick { now_us: 1 }, &mut Live);
    assert_eq!(out.screen, Screen::Kprv { master: true });
    assert_eq!(
        f.key_text(),
        Some(
            "kprv5y2qurMHCsXYr8yytxy6ZwYWLtFbdtWWavDL6bPfz2fNLvnZymmNfE6KpQqNHHjb7mAWYCtuUkZPbkgUR19LSKS9VasqRR852L5GMVY8wf9"
        )
    );
}

/// **Signing Keys shows the three keys and keeps none**: kprv Master (`m`),
/// kprv Account (`m/44'/111111'/0'` with its origin), and Private Key, the
/// Address screen over each address's key; each with its code. Once left,
/// no key is held.
#[test]
fn signing_keys_shows_the_three_keys() {
    use kassigner_crypto::bip32::ExtendedPrivateKey;
    use kassigner_fw::ui::{address as screen, keypad};
    use kassigner_kaspa::derivation::SINGLE_ACCOUNT;
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = seeded(&mut mem);
    let master = master_of(&mnemonic());
    let signing_keys = State::Menu {
        menu: MenuId::SigningKeys,
        page: 0,
    };

    // kprv Master.
    signing_key(&mut f, 0);
    f.step(Event::Tick { now_us: 1 }, &mut Live);
    assert_eq!(f.state(), State::Kprv { master: true });
    let text = f.key_text().unwrap().to_owned();
    assert_eq!(text, kprv_text(&master));
    let (_, k) = ExtendedPrivateKey::from_text(text.as_bytes()).unwrap();
    assert_eq!(k.depth(), 0);
    let out = f.step(on_text(true), &mut Live);
    assert_eq!(out.screen, Screen::KprvQr { master: true });
    assert_eq!(read_back(&f.key_code().unwrap()), text.as_bytes());
    f.step(on_text(true), &mut Live);
    assert_eq!(f.state(), State::Kprv { master: true });
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), signing_keys);
    assert_eq!(f.key_text(), None);
    assert!(f.key_code().is_none());

    // kprv Account, with its origin.
    let out = f.step(item(&menu::SIGNING_KEYS, 1), &mut Live);
    assert_eq!(out.screen, Screen::Kprv { master: false });
    let text = f.key_text().unwrap().to_owned();
    let account = master.derive_path(&SINGLE_ACCOUNT).unwrap();
    assert_eq!(text, kprv_text(&account));
    let (_, k) = ExtendedPrivateKey::from_text(text.as_bytes()).unwrap();
    assert_eq!(k.depth(), 3);
    assert_eq!(k.child_number(), SINGLE_ACCOUNT[2]);
    let parent = master.derive_path(&SINGLE_ACCOUNT[..2]).unwrap();
    assert_eq!(k.parent_fingerprint(), parent.fingerprint());
    f.step(on_text(true), &mut Live);
    assert_eq!(read_back(&f.key_code().unwrap()), text.as_bytes());
    f.step(on_text(true), &mut Live);
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.key_text(), None);

    // Private Key: DERIVING first, a tap on it nothing; then receive key 0,
    // the picker, the keypad, the code, each change under DERIVING.
    let w = wallet();
    let out = signing_key(&mut f, 2);
    assert_eq!(out.screen, Screen::KeyDeriving);
    f.touch(back_button());
    assert_eq!(f.state(), State::KeyDeriving, "a tap while it derives");
    let out = derived(&mut f);
    assert_eq!(
        out.screen,
        Screen::PrivateKey {
            change: false,
            index: 0,
            single: false
        }
    );
    assert_eq!(
        f.key_text(),
        Some(private_hex(&w, Path::receive(0)).as_str())
    );
    assert_eq!(f.address_text(), "", "no address on the key's screen");
    let on = |t, first| tap_in(screen::zone(SCALE, false, first, t).expect("on the screen"));
    f.step(on(screen::Target::After, true), &mut Live);
    derived(&mut f);
    assert_eq!(
        f.key_text(),
        Some(private_hex(&w, Path::receive(1)).as_str())
    );
    f.step(on(screen::Target::Chain, false), &mut Live);
    let out = derived(&mut f);
    assert_eq!(
        out.screen,
        Screen::PrivateKey {
            change: true,
            index: 0,
            single: false
        }
    );
    assert_eq!(
        f.key_text(),
        Some(private_hex(&w, Path::change(0)).as_str())
    );
    f.step(on(screen::Target::Index, true), &mut Live);
    assert_eq!(f.state(), State::AddressIndex);
    assert!(f.key_text().is_some(), "held while the keypad is up");
    let key = |k| tap_in(keypad::zone(SCALE, keypad::Target::Key(k)).unwrap());
    for d in [7, 0, 0, 0, 0] {
        f.step(key(keypad::Key::Digit(d)), &mut Live);
    }
    f.step(key(keypad::Key::Go), &mut Live);
    derived(&mut f);
    assert_eq!(
        f.key_text(),
        Some(private_hex(&w, Path::change(70_000)).as_str())
    );
    let out = f.step(on(screen::Target::Address, false), &mut Live);
    assert_eq!(
        out.screen,
        Screen::PrivateKeyQr {
            change: true,
            index: 70_000
        }
    );
    assert_eq!(
        read_back(&f.key_code().unwrap()),
        private_hex(&w, Path::change(70_000)).as_bytes()
    );
    f.step(on(screen::Target::Address, false), &mut Live);
    assert_eq!(f.state(), State::Address);
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), signing_keys);
    assert_eq!(f.key_text(), None);

    // Address, after it: addresses again.
    f.step(home_button(), &mut Live);
    seed_tool(&mut f, 3);
    let out = f.step(Event::Tick { now_us: 2 }, &mut Live);
    assert_eq!(
        out.screen,
        Screen::Address {
            change: false,
            index: 0,
            single: false
        }
    );
    assert_eq!(f.address_text(), address_of(Path::receive(0)));
    assert_eq!(f.key_text(), None);
}

/// **Signing Keys follows the seed in use**: a v1.0.7 xprv backup at the
/// master, or at the account (no master; kprv Account keeps the zero parent
/// fingerprint v1.0.7 wrote).
#[test]
fn signing_keys_follow_the_seed_in_use() {
    use kassigner_crypto::bip32::ExtendedPrivateKey;
    use kassigner_kaspa::bip32_public::ChildNumber;
    use kassigner_kaspa::derivation::SINGLE_ACCOUNT;
    let master = master_of(&mnemonic());
    let account = master.derive_path(&SINGLE_ACCOUNT).unwrap();
    let w = wallet();

    // A master xprv.
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    restore_xprv(&mut f, master.clone());
    signing_key(&mut f, 0);
    f.step(Event::Tick { now_us: 1 }, &mut Live);
    assert_eq!(f.key_text(), Some(kprv_text(&master).as_str()));
    f.step(back_button(), &mut Live);
    f.step(item(&menu::SIGNING_KEYS, 1), &mut Live);
    assert_eq!(f.key_text(), Some(kprv_text(&account).as_str()));
    f.step(back_button(), &mut Live);
    f.step(item(&menu::SIGNING_KEYS, 2), &mut Live);
    derived(&mut f);
    assert_eq!(
        f.key_text(),
        Some(private_hex(&w, Path::receive(0)).as_str())
    );

    // An account xprv as v1.0.7 wrote one from an xprv slot: zero parent.
    let v107 = ExtendedPrivateKey::from_parts(
        account.private_key(),
        account.chain_code(),
        3,
        [0; 4],
        ChildNumber(SINGLE_ACCOUNT[2].0),
    )
    .unwrap();
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    restore_xprv(&mut f, v107.clone());
    signing_key(&mut f, 0);
    assert_eq!(
        f.state(),
        State::Refused(Refusal::NoPhrase),
        "no master above it"
    );
    assert_eq!(f.key_text(), None);
    // The refusal's time, from the last tick the restore reported.
    f.step(
        Event::Tick {
            now_us: VERIFIED_US + REFUSED_US,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home);
    signing_key(&mut f, 1);
    assert_eq!(f.key_text(), Some(kprv_text(&v107).as_str()));
    assert_ne!(kprv_text(&v107), kprv_text(&account), "the origin kept");
    f.step(back_button(), &mut Live);
    f.step(item(&menu::SIGNING_KEYS, 2), &mut Live);
    derived(&mut f);
    assert_eq!(
        f.key_text(),
        Some(private_hex(&w, Path::receive(0)).as_str())
    );
}

/// **Import Raw Key takes a private key in hex and uses it.** OK needs all
/// 64 digits; zero is refused. A raw key has no checksum, so its address is
/// shown first, Cancel keeping the text for a typo. kprv Master is refused,
/// a raw key having no tree.
#[test]
fn a_raw_key_is_typed_and_used() {
    use kassigner_fw::flow::{Typing, RAW_KEY_HEX};
    let hex = private_hex(&wallet(), Path::receive(5));
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);

    let out = raw_key_keyboard(&mut f);
    assert_eq!(f.state(), State::RawKey);
    assert!(matches!(
        out.screen,
        Screen::Keyboard {
            typing: Typing::RawKey,
            page: keyboard::HEX_PAGE,
            ..
        }
    ));

    // Short of 64: OK does nothing; Back wipes the text.
    type_hex(&mut f, &hex[..10]);
    assert_eq!(f.typed().0, &hex[..10]);
    f.step(hex_key(&f, keyboard::Key::Ok), &mut Live);
    assert_eq!(f.state(), State::RawKey);
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::Import,
            page: 0
        }
    );
    assert_eq!(f.typed().0, "");

    // Zero is no key.
    f.step(item(&menu::IMPORT, 2), &mut Live);
    type_hex(&mut f, &"0".repeat(RAW_KEY_HEX));
    assert_eq!(
        f.keyboard_note(),
        Some(keyboard::Note::Count { used: 64, of: 64 })
    );
    let out = f.step(hex_key(&f, keyboard::Key::Ok), &mut Live);
    settled(&mut f, out);
    assert_eq!(f.state(), State::Refused(Refusal::NotAKey));
    assert_eq!(f.typed().0, "");
    f.step(
        Event::Tick {
            now_us: 1_000_000_000,
        },
        &mut Live,
    );
    assert_eq!(f.state(), State::Home);

    // A key: its address first; Cancel keeps the text.
    raw_key_keyboard(&mut f);
    type_hex(&mut f, &hex);
    assert_eq!(f.typed().0, hex);
    let out = f.step(hex_key(&f, keyboard::Key::Ok), &mut Live);
    let out = settled(&mut f, out);
    assert_eq!(out.screen, Screen::RawKeyConfirm);
    assert_eq!(f.address_text(), address_of(Path::receive(5)));
    read(&mut f);
    f.touch(answer(dialog::Target::Cancel));
    assert_eq!(f.state(), State::RawKey);
    assert_eq!(f.typed().0, hex, "the text, to put a typo right");

    // IMPORT: stored, opened, shown back.
    let out = f.step(hex_key(&f, keyboard::Key::Ok), &mut Live);
    settled(&mut f, out);
    assert_eq!(f.state(), State::RawKeyConfirm);
    read(&mut f);
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.typed().0, "");
    while matches!(f.state(), State::Opening { .. }) {
        f.step(
            Event::Tick {
                now_us: 2_000_000_000,
            },
            &mut Live,
        );
    }
    assert!(matches!(f.state(), State::Seeds { .. }), "{:?}", f.state());
    f.step(home_button(), &mut Live);
    signing_key(&mut f, 2);
    let out = derived(&mut f);
    assert_eq!(
        out.screen,
        Screen::PrivateKey {
            change: false,
            index: 0,
            single: true
        }
    );
    assert_eq!(f.key_text(), Some(hex.as_str()));
    f.step(home_button(), &mut Live);
    signing_key(&mut f, 0);
    assert_eq!(f.state(), State::Refused(Refusal::NoPhrase));
}

/// **LOAD SEED? and IMPORT KEY? answer only a tap down and up on the same
/// answer**, as CONFIRM SEND? does: not a slide, nor a lift with no press.
#[test]
fn a_slide_on_a_dialog_answers_nothing() {
    let (accept, cancel, back) = (
        point(answer(dialog::Target::Accept)),
        point(answer(dialog::Target::Cancel)),
        point(back_button()),
    );
    let middle = (160, 120);
    let slides = [
        (cancel, accept),
        (accept, cancel),
        (middle, accept),
        (back, accept),
        (accept, back),
        (middle, middle),
    ];

    // LOAD SEED?
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    f.step(scan(), &mut Live);
    let digits = seedqr();
    f.step(Event::Code(&digits), &mut Live);
    assert_eq!(f.state(), State::Loading);
    for (from, to) in slides {
        slide(&mut f, from, to);
        assert_eq!(f.state(), State::Loading, "down at {from:?}, up at {to:?}");
    }
    f.step(answer(dialog::Target::Accept), &mut Live);
    assert_eq!(f.state(), State::Loading, "a bare lift on Load");
    f.touch(answer(dialog::Target::Accept));
    assert_ne!(f.state(), State::Loading, "down and up on Load");

    // IMPORT KEY?
    let hex = private_hex(&wallet(), Path::receive(5));
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    raw_key_keyboard(&mut f);
    type_hex(&mut f, &hex);
    let out = f.step(hex_key(&f, keyboard::Key::Ok), &mut Live);
    settled(&mut f, out);
    assert_eq!(f.state(), State::RawKeyConfirm);
    read(&mut f);
    for (from, to) in slides {
        slide(&mut f, from, to);
        assert_eq!(
            f.state(),
            State::RawKeyConfirm,
            "down at {from:?}, up at {to:?}"
        );
        assert_eq!(f.seed_count(), 0);
    }
    f.step(answer(dialog::Target::Accept), &mut Live);
    assert_eq!(f.state(), State::RawKeyConfirm, "a bare lift on IMPORT");
    assert_eq!(f.seed_count(), 0);
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.seed_count(), 1, "down and up on IMPORT");
}

/// **A double tap answers neither IMPORT KEY? nor SIGN MESSAGE?** Each is
/// put up by a button under its answer: the hex keyboard's OK, a raw key's
/// message SIGN. No tap answers until the question has been up
/// [`SETTLE_US`]; from then on one does.
#[test]
fn a_double_tap_answers_neither_question() {
    use kassigner_fw::flow::Typing;
    use kassigner_fw::ui::address as screen;
    let accept = dialog::zone(SCALE, dialog::Target::Accept).unwrap();
    // A point in both a button and the answer put over it.
    let over = |button: Zone| {
        let (x, y) = (button.x.max(accept.x), button.y.max(accept.y));
        assert!(button.contains(x, y) && accept.contains(x, y), "{button:?}");
        Event::Tap { x, y }
    };

    // IMPORT KEY?, over the hex keyboard's OK.
    let hex = private_hex(&wallet(), Path::receive(5));
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    raw_key_keyboard(&mut f);
    type_hex(&mut f, &hex);
    let mode = Typing::RawKey.mode(f.typed_full());
    let ok = keyboard::zone_in(
        SCALE,
        keyboard::HEX_PAGE,
        mode,
        keyboard::Target::Key(keyboard::Key::Ok),
    )
    .unwrap();
    let twice = over(ok);
    let out = f.touch(twice);
    settled(&mut f, out);
    assert_eq!(f.state(), State::RawKeyConfirm, "OK");
    let up = f.now_us();
    f.touch(twice);
    assert_eq!(f.state(), State::RawKeyConfirm, "the second tap");
    f.step(
        Event::Tick {
            now_us: up + SETTLE_US - 1,
        },
        &mut Live,
    );
    f.touch(twice);
    assert_eq!(f.state(), State::RawKeyConfirm, "short of the time");
    assert_eq!(f.seed_count(), 0);
    f.step(
        Event::Tick {
            now_us: up + SETTLE_US,
        },
        &mut Live,
    );
    f.touch(twice);
    assert_eq!(f.seed_count(), 1, "once the question has been up");
    while matches!(f.state(), State::Opening { .. }) {
        f.step(
            Event::Tick {
                now_us: 2_000_000_000,
            },
            &mut Live,
        );
    }
    f.step(home_button(), &mut Live);

    // SIGN MESSAGE?, over the message's SIGN, for a raw key.
    sign_message(&mut f, 0);
    type_message(&mut f, "Hello Kaspa!");
    let twice = over(screen::zone(SCALE, false, true, screen::Target::Index).unwrap());
    f.touch(twice);
    assert_eq!(f.state(), State::MessageConfirm, "SIGN");
    let up = f.now_us();
    f.touch(twice);
    assert_eq!(f.state(), State::MessageConfirm, "the second tap");
    f.step(
        Event::Tick {
            now_us: up + SETTLE_US - 1,
        },
        &mut Live,
    );
    f.touch(twice);
    assert_eq!(f.state(), State::MessageConfirm, "short of the time");
    assert!(f.signature_text().is_empty());
    f.step(
        Event::Tick {
            now_us: up + SETTLE_US,
        },
        &mut Live,
    );
    f.touch(twice);
    assert_eq!(
        f.state(),
        State::MessageSigning,
        "once the question has been up"
    );
}

/// **A raw key signs a message under its own address, after Private Key**
/// left the Address screen in its key mode (Sign Message with a raw key
/// asks at once, with no Address screen to reset it). SIGN MESSAGE? and the
/// result show the key's address, and the signature verifies against it.
#[test]
fn a_raw_key_signs_under_its_address_after_private_key() {
    use kassigner_fw::ui::address as screen;
    use kassigner_kaspa::address::{decode, Version};
    use kassigner_kaspa::sighash::personal_message_hash;
    let hex = private_hex(&wallet(), Path::receive(5));
    let address = address_of(Path::receive(5));
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    raw_key_keyboard(&mut f);
    type_hex(&mut f, &hex);
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
    signing_key(&mut f, 2);
    derived(&mut f);
    assert_eq!(f.key_text(), Some(hex.as_str()), "Private Key, opened");
    f.step(home_button(), &mut Live);

    sign_message(&mut f, 0);
    let text = "Hello Kaspa!";
    type_message(&mut f, text);
    let index = tap_in(screen::zone(SCALE, false, true, screen::Target::Index).unwrap());
    let out = f.step(index, &mut Live);
    assert_eq!(out.screen, Screen::MessageConfirm, "a raw key asks at once");
    assert_eq!(f.address_text(), address);
    message_signed(&mut f);
    assert_eq!(f.state(), State::MessageResult { page: 0 });
    assert_eq!(f.address_text(), address);

    let mut key = [0u8; 40];
    let (_, version, n) = decode(address.as_bytes(), &mut key).unwrap();
    assert_eq!((version, n), (Version::PubKey, 32));
    let sig = f.signature_text();
    let signature: [u8; 64] = unhex_array(&sig[..128]);
    let hash = personal_message_hash(text.as_bytes());
    assert!(bip340::verify(
        &key[..32].try_into().unwrap(),
        &hash,
        &signature
    ));
}
