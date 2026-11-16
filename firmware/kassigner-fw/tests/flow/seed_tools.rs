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

//! Seed Tools: Import Words, Calc Last Word, Dice Seed, BIP85 Child, Show
//! Seed Words and QR Export.

use super::*;

/// The word keyboard with every key live, for locating keys: the grid is
/// the same whatever acts.
const WORD_KEYS: keyboard::Mode = keyboard::Mode::Word {
    back: true,
    on: true,
    take: true,
    chips: 3,
};

/// A tap on the word keyboard's `k`.
fn word_key(k: keyboard::Key) -> Event<'static> {
    tap_in(keyboard::zone_in(SCALE, 0, WORD_KEYS, keyboard::Target::Key(k)).expect("on the grid"))
}

/// Type `word` on the word keyboard and take it with OK.
fn type_word<const N: usize>(f: &mut Flow<'_, N>, word: &str) {
    for c in word.bytes() {
        f.step(word_key(keyboard::Key::Char(c)), &mut Live);
    }
    f.step(word_key(keyboard::Key::Ok), &mut Live);
}

/// Import Words: 12 words typed, one from a suggestion; a last word that
/// breaks the checksum is flagged and kept in place; the arrows step back
/// and on; the right last word opens the same seed. Back keeps nothing.
#[test]
fn words_are_imported_and_a_wrong_one_is_fixed_in_place() {
    use kassigner_fw::flow::WordsFor;
    use kassigner_fw::ui::words::{count_zone, Target};
    let m = mnemonic();
    let words: Vec<&str> = (0..12).map(|i| m.word(i).unwrap()).collect();

    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    seed_tool(&mut f, 2);
    assert_eq!(
        f.state(),
        State::WordCount {
            action: kassigner_fw::flow::CountFor::Words(WordsFor::Import)
        }
    );
    f.step(
        tap_in(count_zone(SCALE, Target::Words(12)).unwrap()),
        &mut Live,
    );
    assert_eq!(
        f.state(),
        State::Words {
            action: WordsFor::Import
        }
    );

    // The first word from its suggestions.
    let first = words[0];
    f.step(
        word_key(keyboard::Key::Char(first.as_bytes()[0])),
        &mut Live,
    );
    f.step(
        word_key(keyboard::Key::Char(first.as_bytes()[1])),
        &mut Live,
    );
    let (_, line) = f.word_line();
    let chip = line.chips[..line.shown].iter().position(|&c| c == first);
    if let Some(i) = chip {
        f.step(
            tap_in(
                keyboard::zone_in(SCALE, 0, WORD_KEYS, keyboard::Target::Chip(i as u8)).unwrap(),
            ),
            &mut Live,
        );
    } else {
        for c in first.bytes().skip(2) {
            f.step(word_key(keyboard::Key::Char(c)), &mut Live);
        }
        f.step(word_key(keyboard::Key::Ok), &mut Live);
    }
    for w in &words[1..11] {
        type_word(&mut f, w);
    }

    // A last word that breaks the checksum: flagged, kept.
    let wrong = (0..2048u16)
        .map(|i| bip39::index_to_word(i).unwrap())
        .find(|&w| {
            let mut all: Vec<u16> = (0..11).map(|i| m.index(i).unwrap()).collect();
            all.push(bip39::word_to_index(w).unwrap());
            bip39::from_indices(&all).is_err()
        })
        .unwrap();
    type_word(&mut f, wrong);
    let out = f.step(Event::Tick { now_us: 1 }, &mut Live);
    assert!(
        matches!(
            out.screen,
            Screen::Words {
                pos: 11,
                invalid: true,
                filled: 12,
                ..
            }
        ),
        "{:?}",
        out.screen
    );
    assert_eq!(f.typed().0, wrong);

    // Back a word and on again, each showing its word.
    f.step(word_key(keyboard::Key::Left), &mut Live);
    assert_eq!(f.typed().0, words[10]);
    f.step(word_key(keyboard::Key::Right), &mut Live);
    assert_eq!(f.typed().0, wrong);

    // The right one, typed over: the same seed.
    for _ in 0..wrong.len() {
        f.step(word_key(keyboard::Key::Delete), &mut Live);
    }
    type_word(&mut f, words[11]);
    assert_eq!(f.state(), State::Passphrase { page: 0 });
    assert_eq!(f.typed(), ("", 0), "the letters wiped");
    f.step(no_passphrase(), &mut Live);
    opened(&mut f);
    assert_eq!(f.fingerprint(), Some(wallet().fingerprint()));

    // Back keeps nothing.
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    seed_tool(&mut f, 2);
    f.step(
        tap_in(count_zone(SCALE, Target::Words(12)).unwrap()),
        &mut Live,
    );
    type_word(&mut f, words[0]);
    f.step(back_button(), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedTools,
            page: 0
        }
    );
    f.step(item(&menu::SEED_TOOLS, 2), &mut Live);
    f.step(
        tap_in(count_zone(SCALE, Target::Words(12)).unwrap()),
        &mut Live,
    );
    assert!(matches!(f.state(), State::Words { .. }));
    let out = f.step(Event::Tick { now_us: 1 }, &mut Live);
    assert!(matches!(
        out.screen,
        Screen::Words {
            pos: 0,
            filled: 0,
            ..
        }
    ));
}

/// Calc Last Word: after 11 words the screen opens on the first valid last
/// word; the arrows step and wrap, the choice not on the printed screen; OK
/// stores the 11 words and that one.
#[test]
fn the_last_word_is_chosen_from_every_valid_one() {
    use kassigner_fw::flow::WordsFor;
    use kassigner_fw::ui::words::{count_zone, last_zone, Target};
    let m = mnemonic();
    let first: Vec<u16> = (0..11).map(|i| m.index(i).unwrap()).collect();

    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    seed_tool(&mut f, 6);
    assert_eq!(
        f.state(),
        State::WordCount {
            action: kassigner_fw::flow::CountFor::Words(WordsFor::LastWord)
        }
    );
    f.step(
        tap_in(count_zone(SCALE, Target::Words(12)).unwrap()),
        &mut Live,
    );
    for i in 0..11 {
        type_word(&mut f, m.word(i).unwrap());
    }
    assert_eq!(f.state(), State::LastWord { choice: 0 });
    let last = bip39::last_word(&first, 0).unwrap();
    assert_eq!(
        f.last_word(),
        Some((bip39::index_to_word(last).unwrap(), 0, 128))
    );

    let arrow = |nav| tap_in(last_zone(SCALE, Target::Nav(nav)).unwrap());
    let out = f.step(arrow(Nav::PageUp), &mut Live);
    assert_eq!(
        f.state(),
        State::LastWord { choice: 127 },
        "round at the ends"
    );
    assert!(
        !format!("{:?}", out.screen).contains("127"),
        "which is not printed"
    );
    f.step(arrow(Nav::PageDown), &mut Live);
    f.step(arrow(Nav::PageDown), &mut Live);
    f.step(arrow(Nav::PageDown), &mut Live);
    assert_eq!(f.state(), State::LastWord { choice: 2 });

    f.step(tap_in(last_zone(SCALE, Target::Ok).unwrap()), &mut Live);
    assert_eq!(f.state(), State::Passphrase { page: 0 });
    f.step(no_passphrase(), &mut Live);
    opened(&mut f);
    let mut all = first.clone();
    all.push(bip39::last_word(&first, 2).unwrap());
    let chosen = bip39::from_indices(&all).unwrap();
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    let expected = Wallet::open(&Slot::mnemonic(chosen, b"").unwrap(), &mut scratch).unwrap();
    assert_eq!(f.fingerprint(), Some(expected.fingerprint()));
}

/// 99 rolls that look like dice: every face at least 12 times (over eight
/// percent), no long runs.
fn fair_rolls() -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..kassigner_fw::flow::DICE_ROLLS_12)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            ((x >> 16) % 6) as u8 + 1
        })
        .collect()
}

/// A tap on the dice screen's `t`.
fn on_dice(t: kassigner_fw::ui::dice::Target, rolled: usize) -> Event<'static> {
    tap_in(kassigner_fw::ui::dice::zone(SCALE, rolled, t).expect("on the dice screen"))
}

/// Dice Seed: 12 words take 99 rolls, UNDO takes one back; at the count the
/// crate's seed from the rolls shows its words, then its passphrase, and
/// opens. Rolls that do not look like dice are refused and wiped, then Seed
/// Tools. The printed screen holds only the count.
#[test]
fn a_dice_seed_is_made_shown_and_opened() {
    use kassigner_crypto::seed::{from_dice, Words};
    use kassigner_fw::flow::CountFor;
    use kassigner_fw::ui::dice::Target;
    use kassigner_fw::ui::words::{count_zone, Target as Count};
    let rolls = fair_rolls();
    let typed: Vec<u8> = rolls.iter().map(|r| b'0' + r).collect();
    let expected = from_dice(&typed, Words::Twelve).expect("these look like dice");

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    seed_tool(&mut f, 1);
    assert_eq!(
        f.state(),
        State::WordCount {
            action: CountFor::Dice
        }
    );
    f.step(
        tap_in(count_zone(SCALE, Count::Words(12)).unwrap()),
        &mut Live,
    );
    assert_eq!(f.state(), State::Dice);

    // A wrong face, taken back.
    f.step(on_dice(Target::Face(6), 0), &mut Live);
    let out = f.step(on_dice(Target::Undo, 1), &mut Live);
    assert_eq!(
        out.screen,
        Screen::Dice {
            rolled: 0,
            target: 99
        }
    );
    for (i, &r) in rolls.iter().enumerate() {
        let out = f.step(on_dice(Target::Face(r), i), &mut Live);
        if i + 1 < rolls.len() {
            assert_eq!(
                out.screen,
                Screen::Dice {
                    rolled: i as u16 + 1,
                    target: 99
                }
            );
        }
    }
    // Its words, BACKUP CHECK passed, then its passphrase.
    words_through(&mut f, &expected);
    assert_eq!(f.state(), State::BackupAsk { by: Check::Words });
    f.touch(answer(dialog::Target::Cancel));
    pass_check(&mut f, &expected);
    assert_eq!(f.state(), State::Passphrase { page: 0 });
    f.step(no_passphrase(), &mut Live);
    opened(&mut f);
    assert!(in_use_backed(&f), "checked: backed up");
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    let w = Wallet::open(&Slot::mnemonic(expected, b"").unwrap(), &mut scratch).unwrap();
    assert_eq!(f.fingerprint(), Some(w.fingerprint()));

    // All ones: refused and wiped.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    seed_tool(&mut f, 1);
    f.step(
        tap_in(count_zone(SCALE, Count::Words(12)).unwrap()),
        &mut Live,
    );
    for i in 0..99 {
        f.step(on_dice(Target::Face(1), i), &mut Live);
    }
    assert_eq!(f.state(), State::DiceRefused);
    let out = f.step(Event::Tick { now_us: 10_000_000 }, &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SeedTools,
            page: 0
        },
        "{:?}",
        out.screen
    );
    f.step(item(&menu::SEED_TOOLS, 1), &mut Live);
    f.step(
        tap_in(count_zone(SCALE, Count::Words(12)).unwrap()),
        &mut Live,
    );
    let out = f.step(Event::Tick { now_us: 11_000_000 }, &mut Live);
    assert_eq!(
        out.screen,
        Screen::Dice {
            rolled: 0,
            target: 99
        },
        "nothing kept"
    );
}

/// BIP85 Child needs a seed in use. "-" and "+" step (no "-" at 0), the
/// keypad sets an index, DERIVE derives the crate's child there; its words
/// show, then it is stored and opens as a seed of its own.
#[test]
fn a_bip85_child_is_derived_shown_and_stored() {
    use kassigner_crypto::bip32::ExtendedPrivateKey;
    use kassigner_fw::flow::CountFor;
    use kassigner_fw::ui::bip85::{zone, Target};
    use kassigner_fw::ui::keypad;
    use kassigner_fw::ui::words::{count_zone, Target as Count};

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    seed_tool(&mut f, 5);
    assert_eq!(f.state(), State::Refused(Refusal::NoWallet));

    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    load(&mut f, &seedqr());
    f.step(home_button(), &mut Live);
    seed_tool(&mut f, 5);
    assert_eq!(
        f.state(),
        State::WordCount {
            action: CountFor::Bip85
        }
    );
    f.step(
        tap_in(count_zone(SCALE, Count::Words(12)).unwrap()),
        &mut Live,
    );
    assert_eq!(f.state(), State::Bip85);

    assert!(zone(SCALE, true, Target::Minus).is_none(), "- at 0");
    f.step(tap_in(zone(SCALE, true, Target::Plus).unwrap()), &mut Live);
    f.step(tap_in(zone(SCALE, false, Target::Plus).unwrap()), &mut Live);
    let out = f.step(
        tap_in(zone(SCALE, false, Target::Minus).unwrap()),
        &mut Live,
    );
    assert_eq!(
        out.screen,
        Screen::Bip85 {
            words: 12,
            index: Hidden(1)
        }
    );

    f.step(
        tap_in(zone(SCALE, false, Target::Index).unwrap()),
        &mut Live,
    );
    assert_eq!(f.state(), State::Bip85Index);
    let key = |k| tap_in(keypad::zone(SCALE, keypad::Target::Key(k)).unwrap());
    f.step(key(keypad::Key::Digit(4)), &mut Live);
    f.step(key(keypad::Key::Digit(2)), &mut Live);
    let out = f.step(key(keypad::Key::Go), &mut Live);
    assert_eq!(
        out.screen,
        Screen::Bip85 {
            words: 12,
            index: Hidden(42)
        }
    );

    f.step(
        tap_in(zone(SCALE, false, Target::Derive).unwrap()),
        &mut Live,
    );
    assert_eq!(f.state(), State::Bip85Deriving);
    f.step(Event::Tick { now_us: 1_000_000 }, &mut Live);
    assert_eq!(f.state(), State::ShowWords { pos: 0 });

    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    let seed = bip39::to_seed(&mnemonic(), "", &mut scratch).unwrap();
    let master = ExtendedPrivateKey::from_seed(seed.as_bytes()).unwrap();
    let child = kassigner_crypto::bip85::derive_mnemonic(&master, 12, 42).unwrap();
    words_through(&mut f, &child);
    assert_eq!(f.state(), State::BackupAsk { by: Check::Words });
    f.touch(answer(dialog::Target::Accept));
    opened(&mut f);
    assert!(!in_use_backed(&f), "LATER: no backup yet");
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    let w = Wallet::open(&Slot::mnemonic(child, b"").unwrap(), &mut scratch).unwrap();
    assert_eq!(f.fingerprint(), Some(w.fingerprint()));
    assert_eq!(f.seed_count(), 2, "the child beside its parent");
}

/// Show Seed Words: the seed in use's words, a tap each; the last word and
/// Back both return to Seed Backup, the seed kept.
#[test]
fn show_seed_words_shows_the_seed_in_use() {
    let m = mnemonic();
    let mut mem = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
    let seed_backup = State::Menu {
        menu: MenuId::SeedBackup,
        page: 0,
    };
    let open = |f: &mut Flow<'_, 6>| {
        f.step(home_button(), &mut Live);
        f.step(card(2), &mut Live);
        f.step(item(&menu::TOOLS, 1), &mut Live);
        f.step(
            tap_in(
                kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Export)
                    .unwrap(),
            ),
            &mut Live,
        );
        f.step(item(&menu::EXPORT, 0), &mut Live);
        f.step(item(&menu::SEED_BACKUP, 0), &mut Live)
    };
    let next = || {
        tap_in(
            kassigner_fw::ui::words::count_zone(SCALE, kassigner_fw::ui::words::Target::Words(12))
                .unwrap(),
        )
    };

    load(&mut f, &seedqr());
    open(&mut f);
    assert_eq!(f.state(), State::ShowWords { pos: 0 });
    let out = f.step(Event::Tick { now_us: 1 }, &mut Live);
    assert_eq!(out.screen, Screen::ShowWords { pos: 0, of: 12 });
    for i in 0..12 {
        assert_eq!(f.shown_word(), m.word(i), "word {i}");
        f.step(next(), &mut Live);
    }
    assert_eq!(f.state(), seed_backup, "after the last word");

    f.step(item(&menu::SEED_BACKUP, 0), &mut Live);
    f.step(next(), &mut Live);
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), seed_backup, "Back");
    assert_eq!(f.seed_count(), 1, "the seed stays");
}

/// QR Export, for 12 and 24 words: CompactSeedQR and Standard SeedQR read
/// back, by the camera's decoder, to the same seed at the grid view's size;
/// Plain Text QR reads back to the words. A tap on a SeedQR opens the grid
/// view, a module a tap within the code; its Back, or a tap on the plain
/// text, goes to SEED EXPORTED, whose Back is QR Export.
#[test]
fn qr_export_shows_the_seed_in_use() {
    use kassigner_fw::flow::seedqr_size;
    use kassigner_fw::ui::seedqr;
    for words in [12usize, 24] {
        let m = if words == 12 {
            mnemonic()
        } else {
            bip39::from_entropy(&[7u8; 32]).unwrap()
        };
        let mut qr = [0u8; slot::SEEDQR_MAX];
        let n = slot::to_seedqr(&m, &mut qr);
        let mut mem = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut mem, &[]);
        load(&mut f, &qr[..n]);
        let open = |f: &mut Flow<'_, 6>, row: usize| {
            f.touch(home_button());
            f.step(card(2), &mut Live);
            f.step(item(&menu::TOOLS, 1), &mut Live);
            f.step(
                tap_in(
                    kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Export)
                        .unwrap(),
                ),
                &mut Live,
            );
            f.step(item(&menu::EXPORT, 0), &mut Live);
            f.step(item(&menu::SEED_BACKUP, 1), &mut Live);
            f.step(item(&menu::QR_EXPORT, row), &mut Live);
        };

        open(&mut f, 0);
        assert_eq!(f.state(), State::SeedQr { compact: true });
        let code = f.export_code().unwrap();
        assert_eq!(code.size, seedqr_size(true, words));
        let back = slot::from_compact_seedqr(&read_back(&code)).unwrap();
        let all = |m: &bip39::Mnemonic| (0..m.len()).map(|i| m.index(i)).collect::<Vec<_>>();
        assert_eq!(all(&back), all(&m), "compact, {words} words");
        // A tap for the grid view, then Back.
        let middle = || {
            tap_in(Zone {
                x: 160,
                y: 120,
                width: 1,
                height: 1,
            })
        };
        f.step(middle(), &mut Live);
        f.step(back_button(), &mut Live);

        open(&mut f, 1);
        assert_eq!(f.state(), State::SeedQr { compact: false });
        let code = f.export_code().unwrap();
        assert_eq!(code.size, seedqr_size(false, words));
        let back = slot::from_seedqr(&read_back(&code)).unwrap();
        assert_eq!(all(&back), all(&m), "standard, {words} words");

        // The grid view: a tap, then the strips.
        f.step(middle(), &mut Live);
        assert_eq!(
            f.state(),
            State::SeedQrGrid {
                compact: false,
                x: 0,
                y: 0
            }
        );
        let strip = |t| tap_in(seedqr::zone(SCALE, t).unwrap());
        f.step(strip(seedqr::Target::Left), &mut Live);
        f.step(strip(seedqr::Target::Up), &mut Live);
        assert_eq!(
            f.state(),
            State::SeedQrGrid {
                compact: false,
                x: 0,
                y: 0
            },
            "no further"
        );
        f.step(strip(seedqr::Target::Right), &mut Live);
        f.step(strip(seedqr::Target::Down), &mut Live);
        assert_eq!(
            f.state(),
            State::SeedQrGrid {
                compact: false,
                x: 1,
                y: 1
            }
        );
        let edge = seedqr_size(false, words) - seedqr::VIEW;
        for _ in 0..40 {
            f.step(strip(seedqr::Target::Right), &mut Live);
        }
        assert_eq!(
            f.state(),
            State::SeedQrGrid {
                compact: false,
                x: edge,
                y: 1
            },
            "the edge"
        );
        f.step(back_button(), &mut Live);
        let done = State::SeedDone {
            plain: false,
            compact: false,
        };
        assert_eq!(f.state(), done, "SEED EXPORTED after the grid");
        f.touch(answer(dialog::Target::Accept));
        assert_eq!(f.state(), State::SeedQr { compact: false }, "Back to QR");
        f.step(middle(), &mut Live);
        f.step(back_button(), &mut Live);
        assert_eq!(f.state(), done);
        f.touch(answer(dialog::Target::Cancel));
        assert_eq!(f.state(), State::BackupWarning, "Save to SD is the backup");
        f.step(back_button(), &mut Live);
        assert_eq!(f.state(), done, "and back");
        f.touch(answer(dialog::Target::Nav(Nav::Back)));
        assert_eq!(
            f.state(),
            State::Menu {
                menu: MenuId::QrExport,
                page: 0
            }
        );

        // Plain Text QR: Wallet, one code up to version 9; KasSigner,
        // version-3 `Format::Opaque` frames that join back to the words.
        let qr_export = State::Menu {
            menu: MenuId::QrExport,
            page: 0,
        };
        let text: Vec<&str> = (0..words).map(|i| m.word(i).unwrap()).collect();
        let text = text.join(" ").into_bytes();
        let pick = |t| tap_in(kassigner_fw::ui::kpub::zone(SCALE, t).unwrap());
        open(&mut f, 2);
        assert_eq!(f.state(), State::PlainFormat);
        assert_eq!(f.plain_codes(true), 1, "{words} words fit one code");
        f.step(pick(kassigner_fw::ui::kpub::Target::Wallet), &mut Live);
        assert_eq!(f.state(), State::PlainQr);
        let code = f.export_code().unwrap();
        assert!(code.size <= 53, "version 9 at most");
        assert_eq!(read_back(&code), text, "{words} words");
        f.step(middle(), &mut Live);
        let plain_done = State::SeedDone {
            plain: true,
            compact: false,
        };
        assert_eq!(f.state(), plain_done, "SEED EXPORTED after the code");
        f.touch(answer(dialog::Target::Accept));
        assert_eq!(f.state(), State::PlainQr, "Back to QR");
        f.step(middle(), &mut Live);
        assert_eq!(f.state(), plain_done);

        open(&mut f, 2);
        let frames = f.plain_codes(false);
        assert_eq!(
            frames,
            kassigner_protocol::frame::frames_needed(text.len(), 48),
            "{words} words"
        );
        assert!(frames > 1);
        f.step(pick(kassigner_fw::ui::kpub::Target::KasSigner), &mut Live);
        assert_eq!(f.state(), State::PlainMode);
        f.touch(answer(dialog::Target::Accept));
        let mut joined = Vec::new();
        for i in 0..frames {
            assert_eq!(f.state(), State::PlainFrames { frame: i as u8 });
            let screen = f.step(Event::Tick { now_us: 1 }, &mut Live).screen;
            assert!(screen.shows_secret(), "the words are a secret");
            let code = f.plain_frame(i as u8).unwrap();
            assert!(code.size <= 29, "version 3, {} modules", code.size);
            let bytes = read_back(&code);
            let frame = kassigner_protocol::frame::parse(&bytes, 64).expect("a frame");
            assert_eq!((frame.index, usize::from(frame.total)), (i as u8, frames));
            joined.extend_from_slice(frame.fragment);
            f.step(middle(), &mut Live);
        }
        assert_eq!(joined, text);
        assert_eq!(f.state(), plain_done, "a tap past the last");
        f.touch(answer(dialog::Target::Accept));
        assert_eq!(f.state(), State::PlainFrames { frame: 0 }, "Back to QR");
        while f.state() != plain_done {
            f.step(middle(), &mut Live);
        }

        // Back from the format screen is QR Export.
        open(&mut f, 2);
        f.step(back_button(), &mut Live);
        assert_eq!(f.state(), qr_export);
    }
}

/// LATER on a dice seed then dropped at its passphrase marks nothing after
/// it: a SeedQR loaded next goes in backed up, as it came from a backup.
#[test]
fn a_dice_seed_put_off_and_dropped_marks_nothing_after_it() {
    use kassigner_fw::ui::dice::Target;
    use kassigner_fw::ui::words::{count_zone, Target as Count};
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    seed_tool(&mut f, 1);
    f.step(
        tap_in(count_zone(SCALE, Count::Words(12)).unwrap()),
        &mut Live,
    );
    for (i, &r) in fair_rolls().iter().enumerate() {
        f.step(on_dice(Target::Face(r), i), &mut Live);
    }
    for _ in 0..12 {
        f.step(on_choice(0), &mut Live);
    }
    assert_eq!(f.state(), State::BackupAsk { by: Check::Words });
    f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::Passphrase { page: 0 });
    f.step(back_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.seed_count(), 0, "dropped");
    load(&mut f, &seedqr());
    assert!(in_use_backed(&f), "loaded: a backup");
}

/// `n` rolls with face 6 seen `sixes` times, spread out, the other five
/// faces in turn: no runs, every other face well over eight percent.
fn rolls_with_sixes(n: usize, sixes: usize) -> Vec<u8> {
    let mut rolls: Vec<u8> = (0..n - sixes).map(|i| (i % 5) as u8 + 1).collect();
    for k in 0..sixes {
        rolls.insert(k * (n / sixes), 6);
    }
    rolls
}

/// Dice Seed for `words`, each of `rolls` tapped.
fn rolled(f: &mut Flow<'_, 6>, words: u8, rolls: &[u8]) {
    use kassigner_fw::ui::dice::Target;
    use kassigner_fw::ui::words::{count_zone, Target as Count};
    seed_tool(f, 1);
    f.step(
        tap_in(count_zone(SCALE, Count::Words(words)).unwrap()),
        &mut Live,
    );
    for (i, &r) in rolls.iter().enumerate() {
        f.step(on_dice(Target::Face(r), i), &mut Live);
    }
}

/// Uneven rolls are warned of, never refused: a face under eight percent (7
/// of 99, 15 of 198) brings UNEVEN ROLLS; 8 and 16 go straight to the
/// words. ROLL AGAIN or Back starts over, USE THEM shows the rolls' seed,
/// Home drops it.
#[test]
fn uneven_rolls_are_warned_of_and_the_user_chooses() {
    use kassigner_crypto::seed::{from_dice, Words};
    let digits = |r: &[u8]| r.iter().map(|d| b'0' + d).collect::<Vec<u8>>();

    for (words, n, warned, fine) in [(12, 99, 7, 8), (24, 198, 15, 16)] {
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        rolled(&mut f, words, &rolls_with_sixes(n, fine));
        assert_eq!(
            f.state(),
            State::ShowWords { pos: 0 },
            "{fine} of {n}: no warning"
        );

        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        let rolls = rolls_with_sixes(n, warned);
        let mut out = None;
        seed_tool(&mut f, 1);
        f.step(
            tap_in(
                kassigner_fw::ui::words::count_zone(
                    SCALE,
                    kassigner_fw::ui::words::Target::Words(words),
                )
                .unwrap(),
            ),
            &mut Live,
        );
        for (i, &r) in rolls.iter().enumerate() {
            out = Some(f.step(
                on_dice(kassigner_fw::ui::dice::Target::Face(r), i),
                &mut Live,
            ));
        }
        let out = out.unwrap();
        assert_eq!(out.screen, Screen::DiceUneven, "{warned} of {n}");
        assert_eq!(f.dice_uneven(), Some((6, warned, n)));
        assert_eq!(f.seed_count(), 0, "nothing stored yet");

        // USE THEM: the rolls' seed, its words shown.
        f.touch(answer(dialog::Target::Accept));
        let words_of = if words == 24 {
            Words::TwentyFour
        } else {
            Words::Twelve
        };
        let expected = from_dice(&digits(&rolls), words_of).unwrap();
        assert_eq!(f.state(), State::ShowWords { pos: 0 });
        assert_eq!(f.shown_word(), expected.word(0));
        assert_eq!(f.dice_uneven(), None);
    }

    // ROLL AGAIN and Back: start over, nothing kept.
    for again in [answer(dialog::Target::Cancel), back_button()] {
        let mut m = Memory::new();
        let mut f: Flow<'_, 6> = booted(&mut m, &[]);
        rolled(&mut f, 12, &rolls_with_sixes(99, 5));
        assert_eq!(f.state(), State::DiceUneven);
        f.touch(again);
        assert_eq!(f.state(), State::Dice);
        assert_eq!(f.dice_uneven(), None);
        rolled_on(&mut f, &fair_rolls());
        assert_eq!(
            f.state(),
            State::ShowWords { pos: 0 },
            "rolled again from the first"
        );
    }

    // Home drops it.
    let mut m = Memory::new();
    let mut f: Flow<'_, 6> = booted(&mut m, &[]);
    rolled(&mut f, 12, &rolls_with_sixes(99, 5));
    f.touch(home_button());
    assert_eq!(f.state(), State::Home);
    assert_eq!(f.seed_count(), 0);
}

/// Each of `rolls` tapped on the dice screen already up.
fn rolled_on(f: &mut Flow<'_, 6>, rolls: &[u8]) {
    for (i, &r) in rolls.iter().enumerate() {
        f.step(
            on_dice(kassigner_fw::ui::dice::Target::Face(r), i),
            &mut Live,
        );
    }
}
