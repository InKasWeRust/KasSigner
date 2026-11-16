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

//! BIP39 against the reference implementation's `vectors.json`, the Trezor
//! set: entropy, its mnemonic, and the seed under the passphrase `TREZOR`.
//! A round trip through our own encoder and decoder would agree even if both
//! were wrong.

use kassigner_crypto::bip39::{
    from_entropy, from_words, index_to_word, scratch_for, to_seed, validate, word_to_index,
    Bip39Error, ENTROPY_12, ENTROPY_24, WORDS_12, WORDS_24,
};

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::{hex, unhex};

/// Derive with a buffer sized to the passphrase, as a caller does.
fn seed_of(
    m: &kassigner_crypto::bip39::Mnemonic,
    passphrase: &str,
) -> kassigner_crypto::bip39::Seed {
    let mut scratch = vec![0u8; scratch_for(passphrase.len())];
    to_seed(m, passphrase, &mut scratch).expect("derive")
}

/// The all-zero vector: entropy, its mnemonic, and its seed under `TREZOR`.
/// Other lengths and bit patterns are covered by the round trip below,
/// which needs no published value.
const VECTOR: (&str, &str, &str) = (
    "00000000000000000000000000000000",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
);

/// A mnemonic built from entropy matches the specification's.
#[test]
fn entropy_to_mnemonic_matches_the_specification() {
    let (entropy_hex, phrase, _) = VECTOR;
    let entropy = unhex(entropy_hex);
    let m = from_entropy(&entropy).expect("build");

    assert_eq!(m.len(), WORDS_12);
    let words: Vec<&str> = (0..m.len()).map(|i| m.word(i).unwrap()).collect();
    assert_eq!(words.join(" "), phrase);
}

/// The all-zero and all-ones 24-word cases, which exercise the wider checksum.
#[test]
fn the_twenty_four_word_form_matches_too() {
    let entropy = [0u8; ENTROPY_24];
    let m = from_entropy(&entropy).expect("build");
    assert_eq!(m.len(), WORDS_24);
    let words: Vec<&str> = (0..m.len()).map(|i| m.word(i).unwrap()).collect();
    assert_eq!(
        words.join(" "),
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art"
    );

    let entropy = [0xFFu8; ENTROPY_24];
    let m = from_entropy(&entropy).expect("build");
    let words: Vec<&str> = (0..m.len()).map(|i| m.word(i).unwrap()).collect();
    assert!(
        words[0] == "zoo",
        "all-ones entropy starts at the last word"
    );
}

/// A mnemonic parsed back yields its entropy, over several one-byte
/// patterns, so a bit-ordering error in the eleven-bit packing shows.
#[test]
fn entropy_round_trips_through_words() {
    for fill in [0x00u8, 0x01, 0x0F, 0x55, 0xAA, 0x7F, 0x80, 0xFE, 0xFF] {
        for len in [ENTROPY_12, ENTROPY_24] {
            let entropy = vec![fill; len];
            let m = from_entropy(&entropy).expect("build");

            let words: Vec<&str> = (0..m.len()).map(|i| m.word(i).unwrap()).collect();
            let back = from_words(words.iter().copied()).expect("parse");

            let mut out = vec![0u8; len];
            let n = back.entropy(&mut out).expect("recover");
            assert_eq!(n, len);
            assert_eq!(out, entropy, "fill {fill:#04x}, {len} bytes");
        }
    }
}

/// The checksum catches a word swapped for another valid one, which no
/// dictionary check would notice.
#[test]
fn the_checksum_catches_a_valid_but_wrong_word() {
    let m = from_entropy(&[0u8; ENTROPY_12]).unwrap();
    let mut words: Vec<&str> = (0..m.len()).map(|i| m.word(i).unwrap()).collect();
    assert!(validate(&m).is_ok());

    // "ability" for "abandon": adjacent in the list, both valid.
    words[3] = "ability";
    assert_eq!(
        from_words(words.iter().copied()).err(),
        Some(Bip39Error::BadChecksum)
    );
}

/// Malformed phrases are refused, each for its own reason.
#[test]
fn malformed_phrases_are_refused() {
    let m = from_entropy(&[0u8; ENTROPY_12]).unwrap();
    let words: Vec<&str> = (0..m.len()).map(|i| m.word(i).unwrap()).collect();

    // Too few, and too many. `.err()`, as `Mnemonic` has no `PartialEq`:
    // `==` on secrets is not constant-time.
    assert_eq!(
        from_words(words.iter().copied().take(11)).err(),
        Some(Bip39Error::BadWordCount(11))
    );
    let mut long = words.clone();
    long.push("abandon");
    assert_eq!(
        from_words(long.iter().copied()).err(),
        Some(Bip39Error::BadWordCount(13))
    );

    // A word that is not in the list, reported by position.
    let mut bad = words.clone();
    bad[5] = "notaword";
    assert_eq!(
        from_words(bad.iter().copied()).err(),
        Some(Bip39Error::UnknownWord { position: 5 })
    );

    // Entropy of a length this crate does not encode, with the word count
    // it would make: 160, 192 and 224 bits are BIP39's 15, 18 and 21 words.
    for (bytes, words) in [(20usize, 15usize), (24, 18), (28, 21), (8, 6), (0, 0)] {
        assert_eq!(
            from_entropy(&vec![0u8; bytes]).err(),
            Some(Bip39Error::BadWordCount(words)),
            "{bytes} bytes"
        );
    }
}

/// The word list is sorted and complete: `word_to_index` binary-searches
/// it, so an unsorted list would miss words that are present.
#[test]
fn the_word_list_is_sorted_and_two_thousand_and_forty_eight_long() {
    let mut prev = "";
    let mut n = 0usize;
    while let Some(w) = index_to_word(n as u16) {
        assert!(w > prev, "word {n} ({w}) is not after {prev}");
        assert_eq!(word_to_index(w), Ok(n as u16), "{w} does not round-trip");
        prev = w;
        n += 1;
    }
    assert_eq!(n, 2048);
    assert_eq!(index_to_word(2048), None);
}

/// The seed matches the specification, under a passphrase and without one.
#[test]
fn the_seed_matches_the_specification() {
    let (entropy_hex, _, seed_hex) = VECTOR;
    let m = from_entropy(&unhex(entropy_hex)).expect("build");

    let seed = seed_of(&m, "TREZOR");
    assert_eq!(hex(seed.as_bytes()), seed_hex);
    // The boot check's constant is this seed, whole.
    assert_eq!(*seed.as_bytes(), kassigner_crypto::kat::BIP39_SEED);

    // A different passphrase is a different wallet, not an error: BIP39 has
    // no wrong-passphrase result.
    let other = seed_of(&m, "");
    assert_ne!(other.as_bytes(), seed.as_bytes());
    let third = seed_of(&m, "trezor");
    assert_ne!(
        third.as_bytes(),
        seed.as_bytes(),
        "the passphrase is case-sensitive"
    );
}

/// The caller's buffer is the only limit, and a short one is refused, not
/// truncated: BIP39 sets no length limit, so a shortened passphrase would
/// derive a seed no other wallet reproduces, and nothing would say so.
#[test]
fn the_callers_buffer_is_the_only_limit() {
    let m = from_entropy(&[0u8; ENTROPY_12]).unwrap();

    // A passphrase far past any keypad works, given a buffer for it.
    let long = "x".repeat(4096);
    let mut roomy = vec![0u8; scratch_for(long.len())];
    assert!(to_seed(&m, &long, &mut roomy).is_ok());

    // One byte short is refused.
    let mut tight = vec![0u8; scratch_for(long.len()) - 1];
    assert_eq!(
        to_seed(&m, &long, &mut tight).err(),
        Some(Bip39Error::BufferTooSmall)
    );

    // A truncated passphrase gives a different seed: why refusing matters.
    let cut = &long[..long.len() - 1];
    let a = seed_of(&m, &long);
    let b = seed_of(&m, cut);
    assert_ne!(a.as_bytes(), b.as_bytes(), "one byte changes the wallet");
}

/// A multi-byte passphrase is measured in bytes (`str::len`), as PBKDF2
/// salts with bytes, and never split.
#[test]
fn a_multibyte_passphrase_is_measured_in_bytes() {
    let m = from_entropy(&[0u8; ENTROPY_12]).unwrap();

    let emoji = "\u{1F510}".repeat(64);
    assert_eq!(emoji.len(), 256, "four bytes per character");

    let mut exact = vec![0u8; scratch_for(emoji.len())];
    assert!(to_seed(&m, &emoji, &mut exact).is_ok());

    // Three bytes short: room for only one byte of the last character.
    let mut short = vec![0u8; scratch_for(emoji.len()) - 3];
    assert_eq!(
        to_seed(&m, &emoji, &mut short).err(),
        Some(Bip39Error::BufferTooSmall)
    );
}

/// For 11 and 23 words, the last-word choices are exactly the words that
/// make a valid phrase, each once, in the list's order. A built phrase
/// passes; one word changed fails.
#[test]
fn every_valid_last_word_is_a_choice() {
    use kassigner_crypto::bip39::{from_indices, last_word, last_word_choices, Bip39Error};
    for n in [11usize, 23] {
        let first: Vec<u16> = (0..n as u16).map(|i| (i * 211 + 7) % 2048).collect();
        let choices = last_word_choices(n).unwrap();
        let picked: Vec<u16> = (0..choices)
            .map(|c| last_word(&first, c).unwrap())
            .collect();
        let valid: Vec<u16> = (0..2048u16)
            .filter(|&w| {
                let mut all = first.clone();
                all.push(w);
                from_indices(&all).is_ok()
            })
            .collect();
        assert_eq!(picked, valid, "{n} words");
        assert_eq!(picked.len(), choices as usize);
        assert!(last_word(&first, choices).is_err(), "past the choices");
        let mut all = first.clone();
        all.push(picked[0]);
        all[0] = (all[0] + 1) % 2048;
        assert_eq!(from_indices(&all).err(), Some(Bip39Error::BadChecksum));
    }
    assert_eq!(last_word_choices(11), Some(128));
    assert_eq!(last_word_choices(23), Some(8));
    assert_eq!(last_word_choices(12), None);
}

/// An emptied mnemonic has no seed. `take` leaves a mnemonic of no words,
/// whose seed would be the empty phrase's, a wallet nobody can restore; it
/// is refused as a word count of zero.
#[test]
fn an_emptied_mnemonic_has_no_seed() {
    let mut m = from_entropy(&[7u8; ENTROPY_12]).unwrap();
    let taken = m.take();
    assert!(m.is_empty());
    let mut scratch = vec![0u8; scratch_for(0)];
    assert!(matches!(
        to_seed(&m, "", &mut scratch),
        Err(Bip39Error::BadWordCount(0))
    ));
    assert!(to_seed(&taken, "", &mut scratch).is_ok(), "the words moved");
}
