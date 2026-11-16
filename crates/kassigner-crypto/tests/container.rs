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

//! Opening and sealing a container across both halves: level 1 parses the
//! file, level 2 holds the password and the plaintext. Either alone proves
//! nothing about reading a card.

use kassigner_crypto::container::{
    check_with_key, derive_key, open, open_with_key, seal, seal_with_key, Argon2Block, KdfParams,
    OpenError, Pbkdf2Steps, SealKdf, SealingKey, ARGON2_BLOCKS, ARGON2_M_COST_KIB, ARGON2_P_COST,
    ARGON2_T_COST, KEY_SIZE, PBKDF2_ITERATIONS,
};
use kassigner_crypto::password::Weakness;
use kassigner_protocol::container::{
    file_size, parse, ContainerError, Kdf, Layout, Purpose, NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};

const SALT: [u8; SALT_SIZE] = [0x11; SALT_SIZE];
const NONCE: [u8; NONCE_SIZE] = [0x22; NONCE_SIZE];
/// A password the policy takes, as every seal's must be.
const PASSWORD: &[u8] = b"Correct horse battery staple 7";

/// The password [`ARGON2ID_SEED_KEY`] was derived under, held to no policy:
/// nothing is sealed under it.
const KAT_PASSWORD: &[u8] = b"correct horse battery staple";

/// A key to seal with, for `password` under `salt` and `purpose`: the
/// policy's steps, run to the end.
fn sealing_key(password: &[u8], salt: &[u8; SALT_SIZE], purpose: Purpose) -> SealingKey {
    let mut steps = Pbkdf2Steps::sealing(password, salt, purpose).expect("the policy takes it");
    steps.step(PBKDF2_ITERATIONS);
    steps.sealing_key().expect("every round done")
}

/// A sealed container opens back to what went in.
#[test]
fn a_container_round_trips() {
    for len in [0usize, 1, 32, 64, 512, 4096] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();

        let mut file = vec![0u8; file_size(len)];
        let n = seal(
            Purpose::Seed,
            &plaintext,
            PASSWORD,
            &SALT,
            &NONCE,
            SealKdf::Pbkdf2Sha256,
            &mut file,
        )
        .unwrap_or_else(|e| panic!("{len} bytes: {e:?}"));
        assert_eq!(n, file.len());

        let mut out = vec![0u8; len];
        let opened =
            open(&file, PASSWORD, &mut out, None).unwrap_or_else(|e| panic!("{len}: {e:?}"));
        assert_eq!(opened.len, len);
        assert_eq!(opened.purpose, Purpose::Seed);
        assert_eq!(opened.layout, Layout::V1);
        assert_eq!(out, plaintext, "{len} bytes changed");
    }
}

/// What this seals, level 1 parses, field for field: the two halves agree on
/// where the salt sits and how long the header is.
#[test]
fn what_this_seals_level_one_parses() {
    let plaintext = b"a seed would go here";
    let mut file = vec![0u8; file_size(plaintext.len())];
    seal(
        Purpose::Xprv,
        plaintext,
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .unwrap();

    let c = parse(&file).expect("level 1 reads it");
    assert_eq!(c.purpose, Purpose::Xprv);
    assert_eq!(c.kdf, Kdf::Pbkdf2Sha256);
    assert_eq!(c.len, plaintext.len());
    assert_eq!(c.salt, Some(&SALT));
    assert_eq!(c.nonce, &NONCE);
    assert_eq!(c.tag.len(), TAG_SIZE);
    assert_eq!(c.aad, &file[..Layout::V1.header_size()]);
}

/// A wrong password fails as a corrupt file does: telling a person which it
/// was would tell an attacker too.
#[test]
fn a_wrong_password_and_a_corrupt_file_fail_alike() {
    let plaintext = b"secret";
    let mut file = vec![0u8; file_size(plaintext.len())];
    seal(
        Purpose::Raw,
        plaintext,
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .unwrap();

    let mut out = [0u8; 32];
    assert_eq!(
        open(&file, b"wrong", &mut out, None).err(),
        Some(OpenError::Authentication)
    );

    // One flipped ciphertext bit.
    let mut damaged = file.clone();
    let ct_at = Layout::V1.header_size() + NONCE_SIZE;
    damaged[ct_at] ^= 1;
    assert_eq!(
        open(&damaged, PASSWORD, &mut out, None).err(),
        Some(OpenError::Authentication)
    );
}

/// Every header byte is in the AAD, so editing one fails the tag: otherwise
/// `kdf_id` could be weakened, or `purpose` rewritten so a seed reads as a
/// transaction, and the file would still decrypt.
#[test]
fn editing_any_header_byte_fails_the_tag() {
    let plaintext = b"seed material";
    let mut file = vec![0u8; file_size(plaintext.len())];
    seal(
        Purpose::Seed,
        plaintext,
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .unwrap();

    let mut out = [0u8; 64];
    assert!(
        open(&file, PASSWORD, &mut out, None).is_ok(),
        "the original opens"
    );

    // `purpose`, byte 5: still valid, so only the tag catches it.
    let mut swapped = file.clone();
    swapped[5] = Purpose::Kspt as u8;
    assert!(parse(&swapped).is_ok(), "level 1 sees nothing wrong");
    assert_eq!(
        open(&swapped, PASSWORD, &mut out, None).err(),
        Some(OpenError::Authentication)
    );

    // The salt, which also changes the key.
    let mut resalted = file.clone();
    resalted[9] ^= 1;
    assert_eq!(
        open(&resalted, PASSWORD, &mut out, None).err(),
        Some(OpenError::Authentication)
    );

    // Every header byte, salt included, one at a time.
    for i in 0..Layout::V1.header_size() {
        let mut d = file.clone();
        d[i] ^= 0x80;
        let r = open(&d, PASSWORD, &mut out, None);
        assert!(r.is_err(), "byte {i} was not authenticated");
    }
}

/// A short buffer is refused before anything is decrypted.
#[test]
fn a_short_buffer_is_refused_before_decryption() {
    let plaintext = [0xAAu8; 100];
    let mut file = vec![0u8; file_size(plaintext.len())];
    seal(
        Purpose::Raw,
        &plaintext,
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .unwrap();

    let mut small = [0u8; 99];
    assert_eq!(
        open(&file, PASSWORD, &mut small, None).err(),
        Some(OpenError::BufferTooSmall { needed: 100 })
    );
    assert_eq!(small, [0u8; 99], "nothing was written");

    let mut exact = [0u8; 100];
    assert!(open(&file, PASSWORD, &mut exact, None).is_ok());
}

/// A failed open leaves `out` zeroed: it held the ciphertext, copied in
/// before the tag check, and a caller that ignores the error finds nothing.
#[test]
fn a_failed_open_wipes_what_it_wrote() {
    let plaintext = [0x5Au8; 64];
    let mut file = vec![0u8; file_size(plaintext.len())];
    seal(
        Purpose::Seed,
        &plaintext,
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .unwrap();

    let mut out = [0xFFu8; 64];
    assert_eq!(
        open(&file, b"wrong password", &mut out, None).err(),
        Some(OpenError::Authentication)
    );
    assert_eq!(out, [0u8; 64], "the buffer was left holding something");
}

/// A container is checked where it lies, as a unit does before writing over
/// a sealed file: the right key verifies it; a wrong one, or the right one
/// over an edited header, does not. The ciphertext is wiped in place each
/// time, the header, nonce and tag left as they were. A non-container is
/// refused before any key.
#[test]
fn a_container_is_checked_in_place() {
    let plaintext = [0x5Au8; 64];
    let mut file = vec![0u8; file_size(plaintext.len())];
    seal(
        Purpose::Seed,
        &plaintext,
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .unwrap();
    let derive = |password: &[u8]| {
        derive_key(
            KdfParams::Pbkdf2Sha256 { salt: &SALT },
            password,
            Purpose::Seed,
            None,
        )
        .unwrap()
    };
    let (key, wrong) = (derive(PASSWORD), derive(b"wrong password"));
    let ct_at = Layout::V1.header_size() + NONCE_SIZE;
    let mut edited = file.clone();
    edited[ct_at - NONCE_SIZE - 1] ^= 1;
    for (name, before, k, verifies) in [
        ("right", &file, &key, true),
        ("wrong", &file, &wrong, false),
        ("edited header", &edited, &key, false),
    ] {
        let mut copy = before.clone();
        let r = check_with_key(&mut copy, k);
        if verifies {
            let o = r.unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(
                (o.len, o.purpose, o.layout),
                (64, Purpose::Seed, Layout::V1)
            );
        } else {
            assert_eq!(r.err(), Some(OpenError::Authentication), "{name}");
        }
        assert_eq!(&copy[..ct_at], &before[..ct_at], "{name}: header, nonce");
        assert_eq!(&copy[ct_at + 64..], &before[ct_at + 64..], "{name}: tag");
        assert_eq!(&copy[ct_at..ct_at + 64], &[0u8; 64][..], "{name}: wiped");
    }

    let mut text = b"KASPA to the moon, and back".to_vec();
    assert!(matches!(
        check_with_key(&mut text, &key),
        Err(OpenError::Framing(_))
    ));
    assert_eq!(text, b"KASPA to the moon, and back", "left as it was");
}

/// Deriving once and opening several containers matches deriving each
/// time: 100,000 rounds are slow, so cards under one password pay once.
#[test]
fn deriving_once_matches_deriving_each_time() {
    let key = derive_key(
        KdfParams::Pbkdf2Sha256 { salt: &SALT },
        PASSWORD,
        Purpose::Raw,
        None,
    )
    .unwrap();
    let sealing = sealing_key(PASSWORD, &SALT, Purpose::Raw);

    for (i, plaintext) in [&b"one"[..], &b"two"[..], &b"three"[..]].iter().enumerate() {
        // From 1: an all-zero nonce is refused.
        let nonce = [i as u8 + 1; NONCE_SIZE];
        let mut file = vec![0u8; file_size(plaintext.len())];
        seal_with_key(
            Purpose::Raw,
            plaintext,
            &sealing,
            Kdf::Pbkdf2Sha256,
            &SALT,
            &nonce,
            &mut file,
        )
        .unwrap();

        // Opened from the password, deriving again.
        let mut out = vec![0u8; plaintext.len()];
        assert!(open(&file, PASSWORD, &mut out, None).is_ok());
        assert_eq!(&out[..], *plaintext);

        // And by the fast one.
        let c = parse(&file).unwrap();
        let mut out2 = vec![0u8; plaintext.len()];
        assert!(open_with_key(&c, &key, &mut out2).is_ok());
        assert_eq!(out, out2);
    }
}

/// The derivation comes from the container: `KdfParams::of` pairs the
/// parsed KDF and salt and refuses a mismatched pair, which `parse` cannot
/// produce: the fixed derivation is implied by the layout without a salt,
/// and `Kdf::from_u8` has no byte for it.
#[test]
fn the_parameters_come_from_the_container() {
    let mut out = vec![0u8; file_size(16)];
    let n = seal(
        Purpose::Seed,
        &[0xEE; 16],
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Pbkdf2Sha256,
        &mut out,
    )
    .expect("seal");

    let c = parse(&out[..n]).expect("parse");
    assert_eq!(
        KdfParams::of(&c).expect("a container this crate wrote"),
        KdfParams::Pbkdf2Sha256 { salt: &SALT },
        "the salt the file records is the salt the key comes from"
    );

    // The key that pair derives opens the file.
    let key = derive_key(KdfParams::of(&c).unwrap(), PASSWORD, c.purpose, None).unwrap();
    let mut plain = vec![0u8; 16];
    assert!(open_with_key(&c, &key, &mut plain).is_ok());
    assert_eq!(plain, vec![0xEE; 16]);
}

/// The salt changes the key, which is why it is per file: with a fixed
/// salt, one precomputed table opens every card sharing a password.
#[test]
fn the_salt_changes_the_key() {
    let a = derive_key(
        KdfParams::Pbkdf2Sha256 { salt: &SALT },
        PASSWORD,
        Purpose::Seed,
        None,
    )
    .unwrap();
    let mut other = SALT;
    other[0] ^= 1;
    let b = derive_key(
        KdfParams::Pbkdf2Sha256 { salt: &other },
        PASSWORD,
        Purpose::Seed,
        None,
    )
    .unwrap();
    assert_ne!(a, b, "one bit of salt must change the key");

    // So does the password; checked, not assumed.
    let c = derive_key(
        KdfParams::Pbkdf2Sha256 { salt: &SALT },
        b"other password",
        Purpose::Seed,
        None,
    )
    .unwrap();
    assert_ne!(a, c);

    // And the purpose: it is in the KDF salt, not only the AAD, so a
    // container of one kind cannot produce the key of another.
    for p in [Purpose::Xprv, Purpose::Raw, Purpose::Kspt] {
        let d = derive_key(KdfParams::Pbkdf2Sha256 { salt: &SALT }, PASSWORD, p, None).unwrap();
        assert_ne!(a, d, "{p:?} must derive a different key from Seed");
    }

    assert_eq!(a.len(), KEY_SIZE);
    assert_eq!(
        PBKDF2_ITERATIONS, 100_000,
        "changing this makes every card unreadable"
    );
}

/// A malformed file is reported as framing, not as a wrong password.
#[test]
fn framing_faults_are_not_authentication_faults() {
    let mut out = [0u8; 64];

    assert_eq!(
        open(&[], PASSWORD, &mut out, None).err(),
        Some(OpenError::Framing(ContainerError::BadMagic))
    );

    let plaintext = b"x";
    let mut file = vec![0u8; file_size(1)];
    seal(
        Purpose::Raw,
        plaintext,
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .unwrap();

    let truncated = &file[..file.len() - 1];
    assert!(matches!(
        open(truncated, PASSWORD, &mut out, None).err(),
        Some(OpenError::Framing(_))
    ));
}

/// Sealing refuses a buffer that cannot hold the file.
#[test]
fn sealing_refuses_a_short_buffer() {
    let plaintext = [0u8; 50];
    let needed = file_size(50);
    let mut small = vec![0u8; needed - 1];
    assert_eq!(
        seal(
            Purpose::Raw,
            &plaintext,
            PASSWORD,
            &SALT,
            &NONCE,
            SealKdf::Pbkdf2Sha256,
            &mut small
        )
        .err(),
        Some(OpenError::BufferTooSmall { needed })
    );
}

/// The block cipher wipes its round keys when dropped (`aes`'s `zeroize`
/// feature, passed down by `aes-gcm`'s), checked by type.
#[test]
fn the_cipher_wipes_its_round_keys() {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_on_drop::<aes_gcm::aes::Aes256>();
}

// ── kdf_id = 2: Argon2id ────────────────────────────────────────────────────

/// Argon2id working memory, as a board would allocate it.
fn argon2_memory() -> Vec<Argon2Block> {
    vec![Argon2Block::default(); ARGON2_BLOCKS]
}

/// An Argon2id container round-trips, its header naming the derivation.
#[test]
fn an_argon2id_container_round_trips() {
    let plaintext = [0xA5u8; 48];
    let mut file = vec![0u8; file_size(plaintext.len())];
    let mut memory = argon2_memory();
    let n = seal(
        Purpose::Seed,
        &plaintext,
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Argon2id(&mut memory),
        &mut file,
    )
    .expect("seal");
    assert_eq!(n, file.len());

    let c = parse(&file).unwrap();
    assert_eq!(c.kdf, Kdf::Argon2id);
    assert_eq!(c.layout, Layout::V1);
    assert_eq!(c.salt, Some(&SALT));
    assert_eq!(
        KdfParams::of(&c).unwrap(),
        KdfParams::Argon2id { salt: &SALT },
        "the parsed header names the derivation it was written with"
    );

    let mut out = vec![0u8; plaintext.len()];
    let opened = open(&file, PASSWORD, &mut out, Some(&mut memory)).expect("open");
    assert_eq!(opened.len, plaintext.len());
    assert_eq!(opened.purpose, Purpose::Seed);
    assert_eq!(out, plaintext);

    assert!(
        memory.iter().all(|b| b.as_ref().iter().all(|&w| w == 0)),
        "the working memory is wiped before derive_key returns"
    );
}

/// A board without the memory (an ESP32-S3 reading an ESP32-P4's card)
/// refuses an Argon2id card as `KdfMemory` before any derivation, not as a
/// wrong password.
#[test]
fn an_argon2id_card_without_memory_is_refused_by_name() {
    let plaintext = [0x3Cu8; 16];
    let mut file = vec![0u8; file_size(plaintext.len())];
    let mut memory = argon2_memory();
    seal(
        Purpose::Xprv,
        &plaintext,
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Argon2id(&mut memory),
        &mut file,
    )
    .unwrap();

    let mut out = vec![0u8; plaintext.len()];
    let needed = ARGON2_BLOCKS;
    assert_eq!(
        open(&file, PASSWORD, &mut out, None).err(),
        Some(OpenError::KdfMemory { needed })
    );
    // Too little memory is the same refusal, not a derivation over less.
    let mut short = vec![Argon2Block::default(); ARGON2_BLOCKS - 1];
    assert_eq!(
        open(&file, PASSWORD, &mut out, Some(&mut short)).err(),
        Some(OpenError::KdfMemory { needed })
    );
    // A wrong password is not reported: nothing was derived to check it.
    assert_eq!(
        open(&file, b"wrong", &mut out, None).err(),
        Some(OpenError::KdfMemory { needed })
    );
    assert!(out.iter().all(|&b| b == 0), "nothing was written");

    // Sealing has the same requirement.
    assert_eq!(
        seal(
            Purpose::Xprv,
            &plaintext,
            PASSWORD,
            &SALT,
            &NONCE,
            SealKdf::Argon2id(&mut short),
            &mut file,
        )
        .err(),
        Some(OpenError::KdfMemory { needed })
    );
}

/// The header's derivation is authenticated: an Argon2id card rewritten to
/// claim PBKDF2 fails the tag rather than opening under the weaker one.
#[test]
fn the_kdf_byte_cannot_be_downgraded() {
    let plaintext = [0x77u8; 32];
    let mut file = vec![0u8; file_size(plaintext.len())];
    let mut memory = argon2_memory();
    seal(
        Purpose::Seed,
        &plaintext,
        PASSWORD,
        &SALT,
        &NONCE,
        SealKdf::Argon2id(&mut memory),
        &mut file,
    )
    .unwrap();

    assert_eq!(file[6], Kdf::Argon2id as u8);
    file[6] = Kdf::Pbkdf2Sha256 as u8;
    let mut out = vec![0u8; plaintext.len()];
    assert_eq!(
        open(&file, PASSWORD, &mut out, None).err(),
        Some(OpenError::Authentication)
    );
}

/// `kdf_id = 2` means exactly these parameters, so they and the key they
/// derive are pinned: a change in the argon2 crate, or in how salt and
/// purpose reach it, shows here before a card stops opening.
#[test]
fn argon2id_parameters_and_derivation_are_pinned() {
    assert_eq!(ARGON2_M_COST_KIB, 16 * 1024, "16 MiB: part of kdf_id = 2");
    assert_eq!(ARGON2_T_COST, 4, "four passes: part of kdf_id = 2");
    assert_eq!(ARGON2_P_COST, 1, "one lane: part of kdf_id = 2");
    assert_eq!(ARGON2_BLOCKS, ARGON2_M_COST_KIB as usize);

    let mut memory = argon2_memory();
    let seed = derive_key(
        KdfParams::Argon2id { salt: &SALT },
        KAT_PASSWORD,
        Purpose::Seed,
        Some(&mut memory),
    )
    .unwrap();
    let xprv = derive_key(
        KdfParams::Argon2id { salt: &SALT },
        KAT_PASSWORD,
        Purpose::Xprv,
        Some(&mut memory),
    )
    .unwrap();
    assert_ne!(seed, xprv, "the purpose is inside the Argon2id salt too");

    let pbkdf2 = derive_key(
        KdfParams::Pbkdf2Sha256 { salt: &SALT },
        KAT_PASSWORD,
        Purpose::Seed,
        None,
    )
    .unwrap();
    assert_ne!(seed, pbkdf2);

    assert_eq!(
        hex::encode(seed),
        ARGON2ID_SEED_KEY,
        "the Argon2id derivation changed: every kdf_id = 2 card would stop opening"
    );
}

/// `derive_key(Argon2id { SALT }, KAT_PASSWORD, Seed)` by libargon2 through
/// `argon2-cffi`, not the `argon2` crate: salt `SALT || 0x01`, m = 16384
/// KiB, t = 4, p = 1, 32 bytes, Argon2id v19. Regenerate only with a new id.
const ARGON2ID_SEED_KEY: &str = "6f83ff50485e5557126a4a7dec6bfd8b535b60667b6b02e16c72729ceca234c3";

/// The fixed-salt derivation belongs to a layout this crate does not write,
/// so sealing with a key under it is refused.
#[test]
fn sealing_with_a_key_refuses_the_fixed_derivation() {
    let key = sealing_key(PASSWORD, &SALT, Purpose::Raw);
    let mut file = vec![0u8; file_size(8)];
    assert_eq!(
        seal_with_key(
            Purpose::Raw,
            &[0u8; 8],
            &key,
            Kdf::Pbkdf2Sha256Fixed,
            &SALT,
            &NONCE,
            &mut file,
        )
        .err(),
        Some(OpenError::Framing(ContainerError::UnsupportedKdf(
            Kdf::Pbkdf2Sha256Fixed as u8
        )))
    );
}

/// An all-zero salt or nonce, the one value a stopped generator is sure to
/// give, is refused by both ways of sealing, and nothing is written.
#[test]
fn seal_refuses_a_zero_salt_or_nonce() {
    let key = sealing_key(PASSWORD, &SALT, Purpose::Seed);
    let zero_salt = [0u8; SALT_SIZE];
    let zero_nonce = [0u8; NONCE_SIZE];
    for (salt, nonce) in [
        (&zero_salt, &NONCE),
        (&SALT, &zero_nonce),
        (&zero_salt, &zero_nonce),
    ] {
        let mut file = vec![0u8; file_size(4)];
        let r = seal(
            Purpose::Seed,
            b"four",
            PASSWORD,
            salt,
            nonce,
            SealKdf::Pbkdf2Sha256,
            &mut file,
        );
        assert_eq!(r.err(), Some(OpenError::ZeroSaltOrNonce));
        assert!(file.iter().all(|&b| b == 0), "nothing written");

        let r = seal_with_key(
            Purpose::Seed,
            b"four",
            &key,
            Kdf::Pbkdf2Sha256,
            salt,
            nonce,
            &mut file,
        );
        assert_eq!(r.err(), Some(OpenError::ZeroSaltOrNonce));
        assert!(file.iter().all(|&b| b == 0), "nothing written");
    }
    // One byte set in each is enough: this is not a test of randomness.
    let mut salt = [0u8; SALT_SIZE];
    salt[SALT_SIZE - 1] = 1;
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0] = 1;
    let mut file = vec![0u8; file_size(4)];
    assert!(seal(
        Purpose::Seed,
        b"four",
        PASSWORD,
        &salt,
        &nonce,
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .is_ok());
}

/// Sealing refuses a short buffer before it derives the key (seconds of
/// PBKDF2 or 16 MiB of Argon2id): with the Argon2id memory short as well,
/// the buffer is what is named.
#[test]
fn sealing_checks_the_buffer_before_the_derivation() {
    let plaintext = [0u8; 50];
    let needed = file_size(50);
    let mut small = vec![0u8; needed - 1];
    let mut short = vec![Argon2Block::default(); ARGON2_BLOCKS - 1];
    assert_eq!(
        seal(
            Purpose::Raw,
            &plaintext,
            PASSWORD,
            &SALT,
            &NONCE,
            SealKdf::Argon2id(&mut short),
            &mut small
        )
        .err(),
        Some(OpenError::BufferTooSmall { needed })
    );
}

/// Every seal but a stego backup's (a descriptor, not a chosen password)
/// holds its password to the policy before anything is derived or written,
/// the steps too. Opening takes any password, so cards under weaker ones
/// still open.
#[test]
fn every_seal_but_a_stego_backups_holds_the_password_to_the_policy() {
    let weak = b"short";
    for purpose in [
        Purpose::Seed,
        Purpose::Xprv,
        Purpose::Raw,
        Purpose::Kspt,
        Purpose::Text,
        Purpose::Cosigner,
        Purpose::Descriptor,
    ] {
        let mut file = vec![0u8; file_size(4)];
        let r = seal(
            purpose,
            b"four",
            weak,
            &SALT,
            &NONCE,
            SealKdf::Pbkdf2Sha256,
            &mut file,
        );
        assert_eq!(
            r.err(),
            Some(OpenError::WeakPassword(Weakness::TooShort {
                have: 5,
                min: 12
            })),
            "{purpose:?}"
        );
        assert!(file.iter().all(|&b| b == 0), "{purpose:?}: nothing written");
        assert!(
            matches!(
                Pbkdf2Steps::sealing(weak, &SALT, purpose),
                Err(Weakness::TooShort { .. })
            ),
            "{purpose:?}: the steps"
        );
    }

    let mut file = vec![0u8; file_size(4)];
    let r = seal(
        Purpose::Stego,
        b"four",
        weak,
        &SALT,
        &NONCE,
        SealKdf::Pbkdf2Sha256,
        &mut file,
    );
    assert!(r.is_ok(), "a stego descriptor: {r:?}");
    assert!(Pbkdf2Steps::sealing(weak, &SALT, Purpose::Stego).is_ok());
    let mut out = [0u8; 4];
    assert_eq!(open(&file, weak, &mut out, None).map(|o| o.len), Ok(4));
    assert_eq!(&out, b"four");
}

/// Only steps made to seal give a key to seal with, once every round is
/// done; steps made to open give only the key to open with. The key seals a
/// file the password opens, and never prints.
#[test]
fn only_steps_made_to_seal_give_a_sealing_key() {
    let mut to_open = Pbkdf2Steps::new(PASSWORD, &SALT, Purpose::Kspt);
    to_open.step(PBKDF2_ITERATIONS);
    assert!(to_open.key().is_some());
    assert!(to_open.sealing_key().is_none());

    let mut steps = Pbkdf2Steps::sealing(PASSWORD, &SALT, Purpose::Kspt).expect("policy");
    assert!(steps.sealing_key().is_none(), "not before every round");
    steps.step(PBKDF2_ITERATIONS);
    let key = steps.sealing_key().expect("every round done");
    assert_eq!(format!("{key:?}"), "SealingKey(redacted)");

    let mut file = vec![0u8; file_size(4)];
    seal_with_key(
        Purpose::Kspt,
        b"four",
        &key,
        Kdf::Pbkdf2Sha256,
        &SALT,
        &NONCE,
        &mut file,
    )
    .expect("seal");
    let mut out = [0u8; 4];
    assert_eq!(open(&file, PASSWORD, &mut out, None).map(|o| o.len), Ok(4));
    assert_eq!(&out, b"four");
}
