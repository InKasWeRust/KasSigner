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

//! The boot known answers, run here too: a vector that rots, or a primitive
//! that changes behaviour, fails on a laptop first. The suites beside this
//! file check the primitives fully; these check the set a unit runs, and
//! that each function ran: one that did nothing reports zero of zero, so
//! `total` is asserted.

use kassigner_crypto::container::{derive_key, Argon2Block, KdfParams};
use kassigner_crypto::kat;
use kassigner_crypto::slot::from_seedqr;
use kassigner_protocol::container::parse;

#[test]
fn bip39_known_answer() {
    let (passed, total) = kat::bip39();
    assert!(total > 0, "no vectors ran");
    assert_eq!(passed, total, "BIP39 boot vector: {passed}/{total}");
}

#[test]
fn bip32_known_answer() {
    let (passed, total) = kat::bip32();
    assert!(total > 0, "no vectors ran");
    assert_eq!(passed, total, "BIP32 boot vector: {passed}/{total}");
}

#[test]
fn bip340_known_answer() {
    let (passed, total) = kat::bip340();
    assert!(total > 0, "no vectors ran");
    assert_eq!(passed, total, "BIP340 boot vector: {passed}/{total}");
}

/// The BIP340 answer a unit checks is vector 0 whole, typed here from
/// BIP340's `test-vectors.csv`: the key's 32 bytes and the signature's 64.
/// Whole, as a signature's first 32 bytes, `R`, depend on the nonce alone.
#[test]
fn the_bip340_answer_is_the_whole_vector() {
    let public = hex::decode("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        .expect("hex");
    let signature = hex::decode(concat!(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215",
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    ))
    .expect("hex");
    assert_eq!(kat::BIP340_PUBLIC_KEY.as_slice(), public.as_slice());
    assert_eq!(kat::BIP340_SIGNATURE.as_slice(), signature.as_slice());
}

#[test]
fn slot_known_answer() {
    let (passed, total) = kat::slot();
    assert!(total > 0, "no vectors ran");
    assert_eq!(passed, total, "seed slot boot vector: {passed}/{total}");
}

/// The slot check's answers are rusty-kaspa's, none of them this crate's
/// code: its words to seed, master fingerprint and derivation to receive
/// address 0. And the SeedQR the check reads holds the phrase.
#[test]
fn the_slot_answers_are_upstreams() {
    use kaspa_bip32::{ChildNumber, ExtendedPrivateKey, Language, Mnemonic, SecretKey};
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about";
    const HARDENED: u32 = 1 << 31;

    let seed = Mnemonic::new(PHRASE, Language::English)
        .expect("upstream reads the phrase")
        .to_seed("");
    let master = ExtendedPrivateKey::<SecretKey>::new(seed.as_bytes()).expect("a master key");
    assert_eq!(master.public_key().fingerprint(), kat::SLOT_FINGERPRINT);

    let receive0 = [HARDENED + 44, HARDENED + 111_111, HARDENED, 0, 0]
        .into_iter()
        .try_fold(master, |k, c| k.derive_child(ChildNumber(c)))
        .expect("receive address 0");
    let public = receive0.public_key().public_key().serialize();
    assert_eq!(public[1..], kat::SLOT_RECEIVE0);

    let m = from_seedqr(kat::SLOT_SEEDQR).expect("the SeedQR reads");
    let words: Vec<&str> = (0..m.len()).map(|i| m.word(i).expect("a word")).collect();
    assert_eq!(words.join(" "), PHRASE);
}

#[test]
fn container_known_answer() {
    let (passed, total) = kat::container();
    assert!(total > 0, "no vectors ran");
    assert_eq!(
        passed, total,
        "seal and open boot vectors: {passed}/{total}"
    );
}

/// Argon2id's answer in lent memory, handed back wiped; with too little
/// lent, failed, not skipped.
#[test]
fn argon2id_known_answer() {
    let mut memory = vec![Argon2Block::default(); kat::ARGON2ID_BLOCKS];
    let (passed, total) = kat::argon2id(&mut memory);
    assert!(total > 0, "no vectors ran");
    assert_eq!(passed, total, "Argon2id boot vector: {passed}/{total}");
    assert!(
        memory.iter().all(|b| b.as_ref().iter().all(|&w| w == 0)),
        "the lent memory is handed back wiped"
    );
    let mut short = vec![Argon2Block::default(); kat::ARGON2ID_BLOCKS - 1];
    assert_eq!(kat::argon2id(&mut short), (0, total));
}

/// The key the boot opens the v1.0.7 card with, derived from its password
/// and the corpus file: 100,000 rounds, too many for a boot.
#[test]
fn the_v107_card_key_is_its_password_s() {
    let file = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/v107/cards/SD000001.KAS"
    ));
    let c = parse(file).expect("the corpus card parses");
    let params = KdfParams::of(&c).expect("its derivation");
    let key = derive_key(params, b"abc", c.purpose, None).expect("PBKDF2 needs no memory");
    assert_eq!(*key, kat::V107_CARD_KEY);
}

/// The set a device runs, as one number.
#[test]
fn the_whole_set_passes() {
    let (passed, total) = kat::all();
    assert_eq!(
        total, 17,
        "the boot set changed size; update the device's budget"
    );
    assert_eq!(passed, total, "boot set: {passed}/{total}");
}
