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

//! Every reader here that takes outside bytes, under the mutation loop in
//! `testkit/mutate.rs`, must return on any input: a seed off a code (SeedQR
//! digits, compact entropy, words), a card's backup file before its
//! password and after a key, an encrypted message, a typed password.
//!
//! Files open with a fixed key, as a password's KDF costs too much per
//! input; the cipher and the plaintext's reader after it are the same.

#[path = "../../../testkit/mutate.rs"]
mod mutate;
#[path = "../../../testkit/vectors.rs"]
mod vectors;

use kassigner_crypto::backup;
use kassigner_crypto::bip39;
use kassigner_crypto::container::{self, KEY_SIZE};
use kassigner_crypto::ecies;
use kassigner_crypto::password;
use kassigner_crypto::sign::public_key;
use kassigner_crypto::slot::{self, SEEDQR_MAX};
use kassigner_crypto::stego::{self, HINT_MAX};

// ── A seed off a code ───────────────────────────────────────────────────────

/// Digits, entropy or words, read as a unit reads a scanned seed; what
/// reads as a SeedQR writes back as the same digits.
fn seed_codes(data: &[u8]) {
    if let Ok(m) = slot::from_seedqr(data) {
        let mut out = [0u8; SEEDQR_MAX];
        let n = slot::to_seedqr(&m, &mut out);
        assert_eq!(&out[..n], data, "a SeedQR that does not write back");
    }
    let _ = slot::from_compact_seedqr(data);
    let _ = backup::mnemonic_from_plaintext(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = bip39::from_words(text.split_ascii_whitespace());
        for word in text.split_ascii_whitespace().take(32) {
            let _ = bip39::word_to_index(word);
        }
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_seed_code_any_bytes() {
    let mut seeds = vectors::files("v107/seedqr", &[".standard", ".compact"]);
    for entropy in [[0u8; 16].as_slice(), &[0xFF; 32], &[7; 16]] {
        let m = bip39::from_entropy(entropy).unwrap();
        let mut plain = [0u8; backup::SEED_PLAINTEXT_MAX];
        let n = backup::seed_plaintext(&m, &mut plain);
        seeds.push(plain[..n].to_vec());
        let words: Vec<&str> = (0..m.len()).map(|i| m.word(i).unwrap()).collect();
        seeds.push(words.join(" ").into_bytes());
    }
    mutate::run("seed code", 4000, seeds, seed_codes);
}

// ── A backup file off a card ────────────────────────────────────────────────

/// The key every file is opened with, not the files' own, so each file
/// goes through the cipher to its refusal.
const KEY: [u8; KEY_SIZE] = [0x5C; KEY_SIZE];

/// A card's file, read as a unit reads one: its KDF before a password is
/// asked, then opened as every kind a unit opens.
fn card_files(data: &[u8]) {
    let _ = backup::backup_kdf(data);
    let _ = stego::kdf_of(data);
    if let Ok(c) = kassigner_protocol::container::parse(data) {
        let mut out = vec![0u8; c.len];
        let _ = container::open_with_key(&c, &KEY, &mut out);
    }
    let _ = container::check_with_key(&mut data.to_vec(), &KEY);
    let _ = backup::open_slot_with_key(data, &KEY, b"");
    let mut hint = [0u8; HINT_MAX];
    let _ = stego::open_backup_with_key(data, &KEY, &mut hint);
    let _ = stego::check_backup_with_key(&mut data.to_vec(), &KEY);
    let _ = stego::open_legacy_seed_with_key(data, &KEY);
    let _ = stego::open_legacy_hint_with_key(data, &KEY, &mut hint);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_backup_file_any_bytes() {
    let mut seeds = vectors::files("v107/cards", &[".KAS", ".TXT"]);
    seeds.extend(vectors::files("v107/unit", &[".KAS"]));
    mutate::run("backup file", 4000, seeds, card_files);
}

// ── An encrypted message, a password ────────────────────────────────────────

/// The private key messages are decrypted with.
const PRIVATE: [u8; 32] = [7; 32];

fn messages(data: &[u8]) {
    let mut out = vec![0u8; data.len()];
    let _ = ecies::decrypt(&PRIVATE, data, &mut out);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn an_encrypted_message_any_bytes() {
    let recipient = public_key(&PRIVATE).unwrap();
    let seeds = [0usize, 1, 32, 500]
        .iter()
        .map(|&len| {
            let plain: Vec<u8> = (0..len).map(|i| (i * 13 + 1) as u8).collect();
            let mut wire = vec![0u8; ecies::encrypted_size(len)];
            let n = ecies::encrypt(&recipient, &plain, &[9; 32], &[3; 12], &mut wire).unwrap();
            wire.truncate(n);
            wire
        })
        .collect();
    mutate::run("ecies decrypt", 2000, seeds, messages);
}

fn passwords(data: &[u8]) {
    let _ = password::check(data);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_password_any_bytes() {
    let seeds = [
        &b""[..],
        b"a",
        b"correct horse battery staple",
        b"Tr0ub4dor&3",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "contraseña segura".as_bytes(),
    ]
    .iter()
    .map(|s| s.to_vec())
    .collect();
    mutate::run("password", 4000, seeds, passwords);
}
