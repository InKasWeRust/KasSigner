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

//! Texts that must fit their screens: refusals, card failures, messages,
//! titles, addresses, descriptors, long names.

use super::*;

/// Every refusal's lines, the dice's and PANIC's included, fit within 300
/// design pixels (the width less its margins) on both panels.
#[test]
fn every_refusal_fits_its_screen() {
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let room = scale.len(300);
        let lines = REFUSALS.iter().map(|(_, w)| *w).chain([refusal::NOT_DICE]);
        for (first, second) in lines {
            assert!(kit.title.width(first) <= room, "{first:?} at {size:?}");
            assert!(kit.body.width(second) <= room, "{second:?} at {size:?}");
        }
        for reason in refusal::HALTS {
            assert!(kit.body.width(reason) <= room, "{reason:?} at {size:?}");
        }
    }
}

/// Every card failure's title, and the missing card's line, fit within 300
/// design pixels on both panels.
#[test]
fn every_card_failure_fits_its_screen() {
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let room = scale.len(300);
        for title in [
            sd_card::BACKUP_FAILED,
            sd_card::KPUB_SAVE_FAILED,
            sd_card::SIGNATURE_SAVE_FAILED,
            sd_card::TX_SAVE_FAILED,
            sd_card::ADDRESS_SAVE_FAILED,
            sd_card::DESCRIPTOR_SAVE_FAILED,
            sd_card::CARD_SAVE_FAILED,
            sd_card::RESTORE_FAILED,
            sd_card::KPUB_LOAD_FAILED,
            sd_card::DESCRIPTOR_LOAD_FAILED,
            sd_card::ADDRESS_LOAD_FAILED,
            sd_card::CARD_LOAD_FAILED,
            sd_card::MESSAGE_LOAD_FAILED,
            sd_card::DELETE_FAILED,
            sd_card::FORMAT_FAILED,
        ] {
            assert!(kit.title.width(title) <= room, "{title:?} at {size:?}");
        }
        let line = kassigner_fw::card::NO_CARD;
        assert!(kit.body.width(line) <= room, "{line:?} at {size:?}");
    }
}

/// Each of a 24-word Standard SeedQR's 29 rows has its own label, A to Z
/// then a', b' and c', ending at least two design pixels short of the grid
/// on both panels.
#[test]
fn every_seedqr_row_label_is_its_own_and_fits() {
    use kassigner_fw::ui::seedqr::{row_label, ROW_LABEL_DX};
    let labels: Vec<String> = (0..29u8)
        .map(|row| {
            let mut buf = [0u8; 2];
            row_label(row, &mut buf).to_string()
        })
        .collect();
    assert_eq!(labels[0], "A");
    assert_eq!(labels[25], "Z");
    assert_eq!(labels[26..], ["a'", "b'", "c'"]);
    let mut seen = std::collections::HashSet::new();
    for label in &labels {
        assert_ne!(label, "?");
        assert!(seen.insert(label), "{label} twice");
        for size in SIZES {
            let (scale, kit) = (Scale::for_panel(size), kit(size));
            let room = scale.len(ROW_LABEL_DX - 2);
            let w = kit.hint.width(label);
            assert!(w <= room, "{label}: {w} of {room} at {size:?}");
        }
    }
}

/// Texts for the message screen: runs of the widest letters, and ordinary
/// ones.
fn message_texts() -> Vec<String> {
    vec![
        "W".repeat(60),
        "M".repeat(45),
        "WWWWWW MMMMMM WWWWWW MMMMMM WWW".into(),
        "WMWMWMWMWMWMWMWMWMWMWMWMWM".into(),
        "WITHDRAW MAXIMUM NOW, WWW.MMM".into(),
        "mmmmmmmmmmmmmmmmmmmmmmmm".into(),
        "I, the holder of this address, confirm the payment of 12 KAS.\nSigned.".into(),
        "kaspa:qypr7ayn2rx5vstkxs9uf2kl0n3lnsvnmu2fm34ghsyspra0dkt2yqcmwhv3kqs".into(),
        "line one\r\nline two\r\n\r\nafter a blank".into(),
        " leading and  double  spaces ".into(),
    ]
}

/// Every line of a message, twenty characters at most, fits within 300
/// design pixels on both panels; only the line breaks are lost.
#[test]
fn every_message_line_fits_its_screen() {
    use kassigner_fw::ui::address::message_lines;
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let room = scale.len(300);
        for text in message_texts() {
            let lines: Vec<&str> = message_lines(&text).collect();
            for line in &lines {
                let w = kit.title.width(line);
                assert!(w <= room, "{line:?}: {w} of {room} at {size:?}");
                assert!(line.len() <= 20, "{line:?}");
            }
            let kept: String = text.chars().filter(|&c| c != '\n' && c != '\r').collect();
            assert_eq!(lines.concat(), kept, "{text:?}");
        }
    }
}

/// Ordinary text breaks as by count alone, twenty characters at the last
/// space among them: the width only breaks a line sooner, and only the
/// widest letters need it.
#[test]
fn ordinary_message_text_breaks_as_before() {
    use kassigner_fw::ui::address::message_lines;
    // Breaking by count alone.
    fn by_count(text: &str) -> Vec<&str> {
        let mut out = Vec::new();
        for line in text.split('\n') {
            let mut rest = line.trim_end_matches('\r');
            let mut first = true;
            while !rest.is_empty() || first {
                first = false;
                if rest.len() <= 20 {
                    out.push(core::mem::take(&mut rest));
                    break;
                }
                let cut = rest[..20].rfind(' ').map_or(20, |i| i + 1);
                let (head, tail) = rest.split_at(cut);
                out.push(head);
                rest = tail;
            }
        }
        out
    }
    let ordinary = message_texts()
        .into_iter()
        .filter(|t| !t.contains(['W', 'M']))
        .collect::<Vec<_>>();
    assert!(ordinary.len() >= 5);
    for text in &ordinary {
        assert_eq!(
            message_lines(text).collect::<Vec<_>>(),
            by_count(text),
            "{text:?}"
        );
    }
    // The widest break sooner than by count.
    let wide = "W".repeat(60);
    assert!(message_lines(&wide).count() > by_count(&wide).len());
}

/// SIGNED TX and every screen after a code fit within 300 design pixels,
/// and SIGNED TX QR's hints, the longest count and "Too much data" among
/// them, fit a card.
#[test]
fn signed_tx_and_its_hints_fit() {
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        for d in [
            dialog::signed_tx(),
            dialog::message_exported(),
            dialog::address_exported(),
            dialog::seed_exported(),
        ] {
            for (line, _) in d.lines {
                assert!(
                    kit.body.width(line) <= scale.len(300),
                    "{line:?} at {size:?}"
                );
            }
        }
        let (mut buf, mut old) = ([0u8; 24], [0u8; 24]);
        let longest = kassigner_fw::ui::kpub::codes_hint("PSKB", 64, &mut buf);
        let v107 =
            kassigner_fw::ui::kpub::codes_hint(kassigner_fw::ui::kpub::REPLY_V107, 64, &mut old);
        assert_eq!(v107, "KSPT v1.0.7, 64 QR");
        for hint in [longest, v107, refusal::TOO_LARGE] {
            assert!(
                kit.hint.width(hint) <= scale.len(130),
                "{hint:?} at {size:?}"
            );
        }
    }
}

/// The multisig refusal's written-out words name
/// [`kassigner_fw::limits::MAX_MULTISIG_KEYS`], so they cannot drift from it.
#[test]
fn the_multisig_refusal_counts_the_keys() {
    let n = kassigner_fw::limits::MAX_MULTISIG_KEYS.to_string();
    assert!(refusal::MULTISIG_TOO_MANY_KEYS.contains(&format!(" {n} ")));
}

/// SLOTS FULL's written-out words name [`kassigner_fw::limits::SLOTS`], so
/// they cannot drift from it.
#[test]
fn the_slots_full_refusal_counts_the_slots() {
    let n = kassigner_fw::limits::SLOTS.to_string();
    assert!(refusal::SLOTS_FULL.0.contains(&format!("All {n} ")));
}

/// Every keyboard title, PASSWORD (OVERWRITE) the longest, fits between
/// Back and Home on both panels.
#[test]
fn keyboard_titles_fit_between_the_corners() {
    use kassigner_fw::flow::Typing;
    for size in [Size::new(320, 240), Size::new(480, 320)] {
        let scale = Scale::for_panel(size);
        let kit = kit(size);
        let back = kassigner_fw::ui::chrome::corner(scale, Nav::Back);
        let home = kassigner_fw::ui::chrome::corner(scale, Nav::Home);
        let room = i32::from(home.x) - i32::from(back.x + back.width);
        for typing in [
            Typing::Passphrase,
            Typing::PassphraseAgain,
            Typing::FileName,
            Typing::Password,
            Typing::PasswordAgain,
            Typing::DeletePassword,
            Typing::OverwritePassword,
            Typing::KpubFileName,
            Typing::Descriptor,
            Typing::Hint,
            Typing::OldDescriptor,
        ] {
            let w = kit.header.width(typing.title());
            assert!(
                w <= room,
                "{} is {w} wide in {room} at {size:?}",
                typing.title()
            );
        }
    }
}

/// Signing Keys' screens fit on both panels: titles at the longest index, a
/// private key's hex, and the master and account kprv of 64 seeds in at
/// most [`TEXT_LINES`] lines.
#[test]
fn signing_keys_screens_fit() {
    use kassigner_crypto::bip32::{ExtendedPrivateKey, PrivatePrefix, XPRV_TEXT_MAX};
    use kassigner_fw::ui::address::{self, TEXT_LINES};
    use kassigner_kaspa::derivation::SINGLE_ACCOUNT;
    let mut kprvs = Vec::new();
    for i in 0..64u8 {
        let m = kassigner_crypto::bip39::from_entropy(&[i; 16]).unwrap();
        let mut scratch = vec![0u8; kassigner_crypto::bip39::scratch_for(0)];
        let seed = kassigner_crypto::bip39::to_seed(&m, "", &mut scratch).unwrap();
        let master = ExtendedPrivateKey::from_seed(seed.as_bytes()).unwrap();
        for k in [master.clone(), master.derive_path(&SINGLE_ACCOUNT).unwrap()] {
            let mut out = [0u8; XPRV_TEXT_MAX];
            let n = k.to_text(PrivatePrefix::Kprv, &mut out).unwrap();
            kprvs.push(String::from_utf8(out[..n].to_vec()).unwrap());
        }
    }
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let kit = kit(size);
        let back = kassigner_fw::ui::chrome::corner(scale, Nav::Back);
        let home = kassigner_fw::ui::chrome::corner(scale, Nav::Home);
        let room = i32::from(home.x) - i32::from(back.x + back.width);
        for title in [
            "RECEIVE KEY #99999",
            "CHANGE KEY #99999",
            address::KPRV_MASTER,
            address::KPRV_ACCOUNT,
        ] {
            let w = kit.header.width(title);
            assert!(w <= room, "{title} is {w} wide in {room} at {size:?}");
        }
        let width = i32::from(size.width) - 2 * scale.len(10);
        let hex = "d".repeat(25);
        assert!(kit.title.width(&hex) <= width, "hex at {size:?}");
        for text in &kprvs {
            let per = address::text_per_line(scale, kit, text);
            let lines: Vec<&[u8]> = text.as_bytes().chunks(per).collect();
            assert!(lines.len() <= TEXT_LINES, "{text}: {} lines", lines.len());
            for line in lines {
                let line = core::str::from_utf8(line).unwrap();
                let w = kit.title.width(line);
                assert!(w <= width, "{line} is {w} wide in {width} at {size:?}");
            }
        }
    }
}

/// KEY k/N and SELECT SEED (k/N) say which key of how many; on both panels
/// the longest titles, KEY k/N's count and COSIGNER KEY's lines fit.
#[test]
fn key_k_of_n_and_cosigner_key_fit() {
    use kassigner_fw::ui::multisig::{add_key, select_seed};
    for of in 1..=5 {
        for key in 1..=of {
            assert_eq!(add_key(key, of).title, format!("KEY {key}/{of}"));
            assert_eq!(select_seed(key, of), format!("SELECT SEED ({key}/{of})"));
        }
    }
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let back = chrome::corner(scale, Nav::Back);
        let home = chrome::corner(scale, Nav::Home);
        let room = i32::from(home.x) - i32::from(back.x + back.width);
        let w = kit.header.width(select_seed(5, 5));
        assert!(
            w <= room,
            "SELECT SEED (5/5) is {w} wide in {room} at {size:?}"
        );
        let rows = add_key(5, 5);
        let last = menu::zone(scale, &rows, 0, menu::Target::Item(2)).unwrap();
        // The count's baseline, and its tallest letters above it.
        let base = scale.y(46 + 3 * 46 + 26);
        assert!(base - i32::from(kit.body.ascent) >= i32::from(last.y + last.height));
        assert!(base <= i32::from(size.height));
        assert!(kit.body.width("4 keys added") <= scale.len(300));
        for (line, _) in dialog::cosigner_key().lines {
            assert!(
                kit.body.width(line) <= scale.len(300),
                "{line:?} at {size:?}"
            );
        }
    }
}

/// Raw's hint says the frames the flow shows, from the one constant both
/// take.
#[test]
fn raws_hint_says_the_frames_shown() {
    use kassigner_fw::ui::kpub::{KPUB_FRAMES, KPUB_HINTS};
    assert_eq!(KPUB_HINTS.1, format!("Raw, {KPUB_FRAMES} QR"));
}

/// KCC-3 Address's titles at the keypad's longest index, KCC-3 RECEIVE
/// #99999 and KCC-3 CHANGE #99999, fit between Back and Home on both panels.
#[test]
fn the_kcc3_address_titles_fit() {
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let kit = kit(size);
        let back = kassigner_fw::ui::chrome::corner(scale, Nav::Back);
        let home = kassigner_fw::ui::chrome::corner(scale, Nav::Home);
        let room = i32::from(home.x) - i32::from(back.x + back.width);
        for title in ["KCC-3 RECEIVE #99999", "KCC-3 CHANGE #99999"] {
            let w = kit.header.width(title);
            assert!(w <= room, "{title} is {w} wide in {room} at {size:?}");
        }
    }
}

/// Every screen breaks a mainnet address alike, 23, 23 and 21 characters,
/// which fits within 300 design pixels even in bech32's widest character,
/// where 25 would not. A private key's hex, 25 a line, fits too.
#[test]
fn every_address_breaks_alike_and_fits() {
    use kassigner_fw::ui::address::address_per_line;
    const BECH32: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let widest = |chars: &str, kit: &Kit| {
        chars
            .chars()
            .max_by_key(|c| kit.title.width(&c.to_string()))
            .unwrap()
    };
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let kit = kit(size);
        let room = scale.len(300);
        for address in [REVIEW_ADDRESS, REVIEW_CHANGE, REVIEW_P2SH] {
            assert_eq!(address.len(), 67);
            assert_eq!(
                address_per_line(scale, kit, address),
                23,
                "{address} at {size:?}"
            );
        }

        let worst = format!("kaspa:{}", widest(BECH32, kit).to_string().repeat(61));
        let per = address_per_line(scale, kit, &worst);
        for line in worst.as_bytes().chunks(per) {
            let w = kit.title.width(core::str::from_utf8(line).unwrap());
            assert!(w <= room, "{w} in {room} at {size:?}, {per} a line");
        }
        let old = kit.title.width(&worst[..25]);
        assert!(old > room, "25 a line ran to {old} in {room} at {size:?}");

        let key = widest("0123456789abcdef", kit).to_string().repeat(25);
        assert!(kit.title.width(&key) <= room, "a key's line at {size:?}");
    }
}

/// DESCRIPTOR's key lines fit within 300 design pixels on both panels
/// whatever the key, each key shown by its first ten characters and last
/// six.
#[test]
fn the_descriptor_lines_fit() {
    use kassigner_fw::ui::multisig::{key_line, KEY_HEAD, KEY_TAIL};
    let worst = format!("kpub{}", "W".repeat(107));
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let mut line = [0u8; 32];
        let w = kit.title.width(key_line(4, &worst, &mut line));
        assert!(w <= scale.len(300), "{w} at {size:?}");
    }
    let key = "kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14";
    let mut line = [0u8; 32];
    assert_eq!(key_line(2, key, &mut line), "2: kpub2JKepG...Lq8y14");
    assert_eq!((KEY_HEAD, KEY_TAIL), (10, 6));
    let mut line = [0u8; 32];
    assert_eq!(
        key_line(0, "kpub", &mut line),
        "0: kpub",
        "too short to cut"
    );
}

/// The Fee is red only over one KAS: one KAS exactly is not, one sompi more
/// is. (One KAS is 100,000,000 sompi.)
#[test]
fn the_fee_turns_red_over_one_kas() {
    use kassigner_fw::ui::color::{RED, TEXT};
    assert_eq!(review::fee_ink(0), TEXT);
    assert_eq!(review::fee_ink(100_000_000), TEXT, "one KAS exactly");
    assert_eq!(review::fee_ink(100_000_001), RED, "one sompi over");
    assert_eq!(review::fee_ink(u64::MAX), RED);
}

/// The line for a multisig spend with no group held says its M of N and
/// that the change is unchecked; for inputs that share no M of N it says
/// the warning alone, never nothing. It fits within 300 design pixels on
/// both panels at a group's widest numbers.
#[test]
fn the_unchecked_line_fits() {
    let mut out = [0u8; 48];
    assert_eq!(
        review::unchecked_line(Some((2, 3)), &mut out),
        "2 of 3. No Descriptor: change unchecked"
    );
    assert_eq!(
        review::unchecked_line(None, &mut out),
        "No Descriptor: change unchecked"
    );
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let mut out = [0u8; 48];
        let line = review::unchecked_line(Some((5, 5)), &mut out);
        assert!(
            kit.body.width(line) <= scale.len(300),
            "{line:?} at {size:?}"
        );
    }
}

/// LOAD MULTISIG?'s lines say what was read, and every line it can say
/// fits within 300 design pixels on both panels at a group's widest numbers.
#[test]
fn load_multisig_fits() {
    use kassigner_fw::ui::multisig::{load_lines, Held, SeedIn};
    let mut out = [[0u8; 40]; 3];
    assert_eq!(
        load_lines((2, 3), SeedIn::Cosigner(2), Held::Other(3, 5), &mut out),
        [
            "2-of-3 multisig read.",
            "The seed in use is cosigner 2.",
            "It replaces the 3-of-5 held."
        ]
    );
    let mut out = [[0u8; 40]; 3];
    assert_eq!(
        load_lines((1, 1), SeedIn::NoSeed, Held::Nothing, &mut out),
        ["1-of-1 multisig read.", "No seed in use.", ""]
    );
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let room = scale.len(300);
        for (seed, held) in [
            (SeedIn::Cosigner(4), Held::Other(5, 5)),
            (SeedIn::Not, Held::Same),
            (SeedIn::NoSeed, Held::Nothing),
        ] {
            let mut out = [[0u8; 40]; 3];
            for line in load_lines((5, 5), seed, held, &mut out) {
                let w = kit.body.width(line);
                assert!(w <= room, "{line:?}: {w} at {size:?}");
            }
        }
    }
}

/// A long name is cut in the middle to fit a photo list row, around `...`
/// with the end the longer part, since a camera's names differ at the end;
/// a name that fits stays whole, and no room gives nothing.
#[test]
fn a_long_name_is_cut_in_the_middle_to_fit() {
    for size in [Size::new(320, 240), Size::new(480, 320)] {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        let room = scale.len(182);
        let mut out = [0u8; 81];
        assert_eq!(kit.title.fit("ROCKY.JPG", room, &mut out), "ROCKY.JPG");
        for (name, next) in [
            ("IMG_20241014_153022.jpg", "IMG_20241014_153145.jpg"),
            (
                "PXL_20241014_153022123.MP.jpg",
                "PXL_20241014_153022987.MP.jpg",
            ),
        ] {
            let mut a = [0u8; 81];
            let mut b = [0u8; 81];
            let (a, b) = (
                kit.title.fit(name, room, &mut a),
                kit.title.fit(next, room, &mut b),
            );
            assert!(kit.title.width(a) <= room, "{a} at {size:?}");
            let (head, tail) = a.split_once("...").expect("cut");
            assert!(name.starts_with(head) && name.ends_with(tail), "{a}");
            assert!(tail.len() >= head.len(), "{a}: the end kept the longer");
            assert_ne!(a, b, "two photos a second apart read apart");
        }
        assert_eq!(kit.title.fit("IMG_20241014_153022.jpg", 0, &mut out), "");
        let mut short = [0u8; 4];
        assert_eq!(
            kit.title.fit("IMG_20241014_153022.jpg", room, &mut short),
            "",
            "too little to hold it"
        );
    }
}

/// UNEVEN ROLLS says its face and count in full, longest and shortest
/// within 300 design pixels on both panels.
#[test]
fn uneven_rolls_fits() {
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        for (said, first_line, second_line) in [
            ((6, 15, 198), "Face 6 came up 15 times", "in 198 rolls."),
            ((2, 1, 99), "Face 2 came up 1 time", "in 99 rolls."),
        ] {
            let (mut first, mut second) = ([0u8; 32], [0u8; 16]);
            let d = dialog::uneven_rolls(said, &mut first, &mut second);
            assert_eq!(d.lines[0].0, first_line);
            assert_eq!(d.lines[1].0, second_line);
            for (line, _) in d.lines {
                assert!(
                    kit.body.width(line) <= scale.len(300),
                    "{line:?} at {size:?}"
                );
            }
        }
    }
}

/// A covenant page's two lines say what becomes of the covenant, in the
/// colours that mark the two cases to stop on (one that ends here, one that
/// starts), and the widest a unit can say fits within 300 design pixels on
/// both panels: every input and every output it takes.
#[test]
fn the_covenant_lines_say_what_becomes_of_it_and_fit() {
    use kassigner_fw::ui::color::{ACCENT, ORANGE, TEXT_DIM};
    use kassigner_fw::ui::review::{covenant_lines, COVENANT_LINE_MAX};
    let said = |what: (usize, u32, Option<usize>)| {
        let (mut a, mut b) = ([0u8; COVENANT_LINE_MAX], [0u8; COVENANT_LINE_MAX]);
        let [first, second] = covenant_lines(what, &mut a, &mut b);
        [
            (first.0.to_string(), first.1),
            (second.0.to_string(), second.1),
        ]
    };
    let line = |text: &str, ink: u16| (text.to_string(), ink);

    // Bound UTXOs spent, the covenant continued.
    assert_eq!(
        said((1, 0b1, None)),
        [
            line("Spends 1 UTXO", ACCENT),
            line("Continues in output 1", ACCENT)
        ]
    );
    assert_eq!(
        said((2, 0b1010, None)),
        [
            line("Spends 2 UTXOs", ACCENT),
            line("Continues in outputs 2, 4", ACCENT)
        ]
    );
    // Ending here.
    assert_eq!(
        said((1, 0, None)),
        [
            line("Spends 1 UTXO", ACCENT),
            line("No output continues it", ORANGE)
        ]
    );
    // Starting here; the input counted from 1, as the outputs are.
    assert_eq!(
        said((0, 0b10, Some(0))),
        [
            line("Starts in output 2", ORANGE),
            line("From input 1", TEXT_DIM)
        ]
    );

    let widest = [
        said((kassigner_fw::limits::MAX_INPUTS, 0xFF, None)),
        said((0, 0xFF, Some(kassigner_fw::limits::MAX_INPUTS - 1))),
    ];
    assert_eq!(widest[0][0].0, "Spends 32 UTXOs");
    assert_eq!(
        widest[0][1].0,
        "Continues in outputs 1, 2, 3, 4, 5, 6, 7, 8"
    );
    assert_eq!(widest[1][0].0, "Starts in outputs 1, 2, 3, 4, 5, 6, 7, 8");
    assert_eq!(widest[1][1].0, "From input 32");
    assert_eq!(
        kassigner_fw::limits::MAX_OUTPUTS,
        8,
        "the widest list above"
    );
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        for (text, _) in widest.iter().flatten() {
            assert!(text.len() <= COVENANT_LINE_MAX, "{text:?}");
            assert!(
                kit.body.width(text) <= scale.len(300),
                "{text:?} at {size:?}"
            );
        }
    }
}
