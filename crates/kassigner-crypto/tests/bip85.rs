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

//! BIP85 against the specification's vector. It starts from an `xprv`,
//! whose version bytes this crate's text form (`kprv`, `ktrv`) refuses, so
//! its key and chain code are given as bytes, decoded from
//! `xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb`
//! with base58check, its checksum checked.

use kassigner_crypto::bip32::ExtendedPrivateKey;
use kassigner_crypto::bip39::{from_entropy, scratch_for, to_seed, ENTROPY_12, ENTROPY_24};
use kassigner_crypto::bip85::{
    derive_mnemonic, path_for, Bip85Error, APPLICATION_BIP39, LANGUAGE_ENGLISH, PURPOSE,
};
use kassigner_kaspa::bip32_public::ChildNumber;
use kassigner_kaspa::bip32_public::HARDENED_OFFSET;

/// A master key from a fixed mnemonic.
fn master() -> ExtendedPrivateKey {
    let m = from_entropy(&[0x11u8; ENTROPY_24]).expect("mnemonic");
    let mut scratch = vec![0u8; scratch_for(0)];
    let seed = to_seed(&m, "", &mut scratch).expect("seed");
    ExtendedPrivateKey::from_seed(seed.as_bytes()).expect("master")
}

fn words_of(m: &kassigner_crypto::bip39::Mnemonic) -> Vec<&'static str> {
    (0..m.len()).map(|i| m.word(i).unwrap()).collect()
}

/// The path is what the specification says, every level hardened.
#[test]
fn the_path_is_the_specifications() {
    let p = path_for(12, 0).expect("12 words, index 0");
    assert_eq!(p[0].0, PURPOSE + HARDENED_OFFSET);
    assert_eq!(p[1].0, APPLICATION_BIP39 + HARDENED_OFFSET);
    assert_eq!(p[2].0, LANGUAGE_ENGLISH + HARDENED_OFFSET);
    assert_eq!(p[3].0, 12 + HARDENED_OFFSET);
    assert_eq!(p[4].0, HARDENED_OFFSET);

    for (i, c) in p.iter().enumerate() {
        assert!(c.0 >= HARDENED_OFFSET, "level {i} is not hardened");
    }

    // The word count and the index are the last two levels.
    let q = path_for(24, 7).expect("24 words, index 7");
    assert_eq!(q[3].0, 24 + HARDENED_OFFSET);
    assert_eq!(q[4].0, 7 + HARDENED_OFFSET);
}

/// A path that cannot be derived is refused, not built: every level adds
/// `HARDENED_OFFSET`, so an index at or above it would overflow (a panic
/// with overflow checks on, as in the firmware profile; a wrong path
/// without). `derive_mnemonic` builds its path with `path_for`, so it
/// refuses the same.
#[test]
fn a_path_that_cannot_be_derived_is_refused() {
    assert_eq!(
        path_for(12, HARDENED_OFFSET),
        Err(Bip85Error::IndexTooLarge(HARDENED_OFFSET))
    );
    assert_eq!(
        path_for(12, u32::MAX),
        Err(Bip85Error::IndexTooLarge(u32::MAX))
    );
    assert_eq!(path_for(13, 0), Err(Bip85Error::BadWordCount(13)));
    assert_eq!(path_for(0, 0), Err(Bip85Error::BadWordCount(0)));

    // The last index that is still a path.
    let last = path_for(24, HARDENED_OFFSET - 1).expect("the last usable index");
    assert_eq!(last[4].0, u32::MAX);

    // And `derive_mnemonic` refuses exactly what `path_for` does.
    let master = master();
    assert_eq!(
        derive_mnemonic(&master, 12, HARDENED_OFFSET).err(),
        Some(Bip85Error::IndexTooLarge(HARDENED_OFFSET))
    );
    assert_eq!(
        derive_mnemonic(&master, 13, 0).err(),
        Some(Bip85Error::BadWordCount(13))
    );
}

/// The same index always gives the same words: a lost child wallet is
/// recovered from the parent seed and its index.
#[test]
fn a_child_is_reproducible_from_the_parent() {
    let m = master();
    let a = derive_mnemonic(&m, 12, 0).expect("child");
    let b = derive_mnemonic(&m, 12, 0).expect("child again");
    assert_eq!(words_of(&a), words_of(&b));

    // And a second master built the same way reaches the same child.
    let m2 = master();
    let c = derive_mnemonic(&m2, 12, 0).expect("child from a rebuilt master");
    assert_eq!(words_of(&a), words_of(&c));
}

/// Children differ from each other, over adjacent and distant indices and
/// both word counts: if two matched, one child would leak another.
#[test]
fn children_are_independent() {
    let m = master();

    let mut seen: Vec<Vec<&str>> = Vec::new();
    for words in [12u32, 24] {
        for index in [0u32, 1, 2, 100, 4096] {
            let child = derive_mnemonic(&m, words, index).expect("child");
            assert_eq!(child.len(), words as usize);
            let w = words_of(&child);
            assert!(
                !seen.contains(&w),
                "{words}-word child {index} repeats an earlier child"
            );
            seen.push(w);
        }
    }
    assert_eq!(seen.len(), 10);
}

/// A child's entropy is the right length for its word count.
#[test]
fn the_entropy_length_follows_the_word_count() {
    let m = master();

    let twelve = derive_mnemonic(&m, 12, 0).expect("child");
    assert_eq!(twelve.entropy_len(), ENTROPY_12);
    let mut e = [0u8; ENTROPY_24];
    assert_eq!(twelve.entropy(&mut e).unwrap(), ENTROPY_12);

    let twentyfour = derive_mnemonic(&m, 24, 0).expect("child");
    assert_eq!(twentyfour.entropy_len(), ENTROPY_24);
    assert_eq!(twentyfour.entropy(&mut e).unwrap(), ENTROPY_24);
}

/// A child mnemonic is valid BIP39, checksum included, as a person types it
/// into other wallets.
#[test]
fn a_child_is_a_valid_bip39_mnemonic() {
    use kassigner_crypto::bip39::from_words;

    let m = master();
    for words in [12u32, 24] {
        for index in [0u32, 1, 999] {
            let child = derive_mnemonic(&m, words, index).expect("child");
            let w = words_of(&child);
            let reparsed = from_words(w.iter().copied())
                .unwrap_or_else(|e| panic!("{words}-word child {index}: {e:?}"));
            assert_eq!(words_of(&reparsed), w);
        }
    }
}

/// A child mnemonic derives its own wallet, unrelated to the parent's.
#[test]
fn a_child_mnemonic_is_a_standalone_wallet() {
    let parent = master();
    let child = derive_mnemonic(&parent, 12, 0).expect("child");

    let mut scratch = vec![0u8; scratch_for(0)];
    let child_seed = to_seed(&child, "", &mut scratch).expect("seed");
    let child_master = ExtendedPrivateKey::from_seed(child_seed.as_bytes()).expect("master");

    assert_ne!(child_master.private_key(), parent.private_key());
    assert_ne!(child_master.chain_code(), parent.chain_code());
    assert_eq!(child_master.depth(), 0, "a child is its own root");
}

/// Bad arguments are refused, each for its own reason.
#[test]
fn bad_arguments_are_refused() {
    let m = master();

    for n in [0u32, 1, 11, 13, 18, 23, 25] {
        assert_eq!(
            derive_mnemonic(&m, n, 0).err(),
            Some(Bip85Error::BadWordCount(n)),
            "{n} words"
        );
    }

    // An index already carrying the hardened bit: the offset is added here,
    // so it would silently derive another path.
    assert_eq!(
        derive_mnemonic(&m, 12, HARDENED_OFFSET).err(),
        Some(Bip85Error::IndexTooLarge(HARDENED_OFFSET))
    );
    assert_eq!(
        derive_mnemonic(&m, 12, u32::MAX).err(),
        Some(Bip85Error::IndexTooLarge(u32::MAX))
    );

    // The last index below the offset is fine.
    assert!(derive_mnemonic(&m, 12, HARDENED_OFFSET - 1).is_ok());
}

/// Only the master key derives a child: BIP85's path starts at `m`, and a
/// child of a lower node could not be made again from the seed.
#[test]
fn only_the_master_key_derives_a_child() {
    let m = master();

    let account = m
        .derive_path(&[
            ChildNumber(44 + HARDENED_OFFSET),
            ChildNumber(111_111 + HARDENED_OFFSET),
            ChildNumber(HARDENED_OFFSET),
        ])
        .expect("account node");
    assert_eq!(
        derive_mnemonic(&account, 12, 0).err(),
        Some(Bip85Error::NotMaster(3))
    );

    let one_down = m
        .derive_path(&[ChildNumber(HARDENED_OFFSET)])
        .expect("first child");
    assert_eq!(
        derive_mnemonic(&one_down, 24, 0).err(),
        Some(Bip85Error::NotMaster(1))
    );

    // The master itself still derives.
    assert!(derive_mnemonic(&m, 12, 0).is_ok());
}

// ── The specification's vector ───────────────────────────────────────────────

/// Private key of BIP85's published master, decoded from its `xprv`.
const SPEC_KEY: [u8; 32] = [
    0x3f, 0x15, 0xe5, 0xd8, 0x52, 0xdc, 0x2e, 0x9b, 0xa5, 0xe9, 0xfe, 0x18, 0x9a, 0x8d, 0xd2, 0xe1,
    0x54, 0x7b, 0xad, 0xef, 0x5b, 0x56, 0x3b, 0xbe, 0x65, 0x79, 0xfc, 0x68, 0x07, 0xd8, 0x0e, 0xd9,
];

/// Chain code of the same key.
const SPEC_CHAIN_CODE: [u8; 32] = [
    0x1b, 0x67, 0x96, 0x9d, 0x1e, 0xc6, 0x9b, 0xdf, 0xee, 0xae, 0x43, 0x21, 0x3d, 0xa8, 0x46, 0x0b,
    0xa3, 0x4b, 0x92, 0xd0, 0x78, 0x8c, 0x8f, 0x7b, 0xfc, 0xfa, 0x44, 0x90, 0x6e, 0x8a, 0x58, 0x9c,
];

/// The specification's master key, rebuilt from its parts.
fn spec_master() -> ExtendedPrivateKey {
    ExtendedPrivateKey::from_parts(&SPEC_KEY, &SPEC_CHAIN_CODE, 0, [0u8; 4], ChildNumber(0))
        .expect("the specification's key is valid")
}

/// The specification's 12-word and 24-word children: the one test here
/// against a published value; those above prove only self-consistency.
#[test]
fn the_children_match_the_specification() {
    let m = spec_master();

    let twelve = derive_mnemonic(&m, 12, 0).expect("12-word child");
    assert_eq!(
        words_of(&twelve).join(" "),
        "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
    );

    let eighteen_words_is_not_supported = derive_mnemonic(&m, 18, 0);
    assert!(
        eighteen_words_is_not_supported.is_err(),
        "only 12 and 24 here"
    );

    let twentyfour = derive_mnemonic(&m, 24, 0).expect("24-word child");
    assert_eq!(
        words_of(&twentyfour).join(" "),
        "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact \
         gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"
    );
}
