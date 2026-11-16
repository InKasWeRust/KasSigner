// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The encrypted container. Test files are built field by field, not pasted
//! as hex.

use kassigner_protocol::container::{
    file_size, parse, write_header, ContainerError, Kdf, Layout, Purpose, MAGIC_LEGACY,
    MAGIC_LEGACY_NO_SALT, MAGIC_V1, NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};

const SALT: [u8; SALT_SIZE] = [0x11; SALT_SIZE];
const NONCE: [u8; NONCE_SIZE] = [0x22; NONCE_SIZE];
const TAG: [u8; TAG_SIZE] = [0x33; TAG_SIZE];

fn v1(purpose: u8, kdf: u8, plaintext: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&MAGIC_V1);
    f.push(1); // version
    f.push(purpose);
    f.push(kdf);
    f.extend_from_slice(&(plaintext.len() as u16).to_le_bytes());
    f.extend_from_slice(&SALT);
    f.extend_from_slice(&NONCE);
    f.extend_from_slice(plaintext);
    f.extend_from_slice(&TAG);
    f
}

fn legacy(purpose: u8, kdf: u8, plaintext: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&MAGIC_LEGACY);
    f.push(3); // version
    f.push(purpose);
    f.push(kdf);
    f.push(plaintext.len() as u8); // one byte, not two
    f.extend_from_slice(&SALT);
    f.extend_from_slice(&NONCE);
    f.extend_from_slice(plaintext);
    f.extend_from_slice(&TAG);
    f
}

/// The oldest layout, `KAS\x03`: the magic, a two-byte length, and nothing
/// else before the nonce.
fn no_salt(plaintext: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&MAGIC_LEGACY_NO_SALT);
    f.extend_from_slice(&(plaintext.len() as u16).to_le_bytes());
    f.extend_from_slice(&NONCE);
    f.extend_from_slice(plaintext);
    f.extend_from_slice(&TAG);
    f
}

/// A current container parses, and every part comes back.
#[test]
fn a_v1_container_parses() {
    let pt = vec![0xAAu8; 120];
    let f = v1(Purpose::Seed as u8, Kdf::Pbkdf2Sha256 as u8, &pt);
    let c = parse(&f).expect("parse");

    assert_eq!(c.layout, Layout::V1);
    assert_eq!(c.version, 1);
    assert_eq!(c.purpose, Purpose::Seed);
    assert_eq!(c.kdf, Kdf::Pbkdf2Sha256);
    assert_eq!(c.len, pt.len());
    assert_eq!(c.salt, Some(&SALT));
    assert_eq!(c.nonce, &NONCE);
    assert_eq!(c.ciphertext, &pt[..]);
    assert_eq!(c.tag, &TAG);
}

/// The AAD is the whole header through the salt, as one slice.
#[test]
fn the_aad_is_the_header_through_the_salt() {
    let pt = vec![0xAAu8; 40];
    let f = v1(Purpose::Kspt as u8, Kdf::Pbkdf2Sha256 as u8, &pt);
    let c = parse(&f).expect("parse");

    assert_eq!(c.aad.len(), Layout::V1.header_size());
    assert_eq!(c.aad, &f[..25], "magic, version, purpose, kdf, len, salt");
    assert_eq!(&c.aad[..4], &MAGIC_V1);
    assert_eq!(c.aad[5], Purpose::Kspt as u8, "purpose is inside the AAD");
    assert_eq!(c.aad[6], Kdf::Pbkdf2Sha256 as u8, "kdf is inside the AAD");
    assert_eq!(&c.aad[9..25], &SALT, "the salt is inside the AAD");

    // It stops before the nonce, which GCM authenticates on its own.
    assert_eq!(c.aad.len(), 25);
}

/// The legacy layout still reads, with its one-byte length field.
#[test]
fn the_legacy_layout_still_reads() {
    let pt = vec![0xBBu8; 100];
    let f = legacy(Purpose::Xprv as u8, Kdf::Pbkdf2Sha256 as u8, &pt);
    let c = parse(&f).expect("parse");

    assert_eq!(c.layout, Layout::Legacy);
    assert_eq!(c.version, 3);
    assert_eq!(c.purpose, Purpose::Xprv);
    assert_eq!(c.len, 100);
    assert_eq!(c.ciphertext, &pt[..]);
    assert_eq!(c.aad.len(), 24, "one byte shorter than v1");
    assert_eq!(Layout::Legacy.overhead(), Layout::V1.overhead() - 1);
}

/// The oldest layout reads: the magic, the length, the nonce, with no
/// version, purpose, kdf or salt, the AAD those six bytes. It reads as KSPT
/// under the fixed-salt derivation. A wrong length or a cut is refused.
#[test]
fn the_oldest_layout_reads() {
    let pt: Vec<u8> = (0..300u16).map(|i| i as u8).collect();
    let f = no_salt(&pt);
    let c = parse(&f).expect("parse");

    assert_eq!(c.layout, Layout::LegacyNoSalt);
    assert_eq!(c.version, 0);
    assert_eq!(c.purpose, Purpose::Kspt);
    assert_eq!(c.kdf, Kdf::Pbkdf2Sha256Fixed);
    assert_eq!(c.len, 300, "two bytes of length: 300 does not fit one");
    assert_eq!(c.salt, None);
    assert_eq!(c.aad, &f[..6], "the magic and the length");
    assert_eq!(c.nonce, &NONCE);
    assert_eq!(c.ciphertext, &pt[..]);
    assert_eq!(c.tag, &TAG);
    assert_eq!(f.len(), Layout::LegacyNoSalt.overhead() + pt.len());
    assert_eq!(Layout::LegacyNoSalt.overhead(), 6 + NONCE_SIZE + TAG_SIZE);
    assert!(!Layout::LegacyNoSalt.has_salt());

    for declared in [299u16, 301, u16::MAX] {
        let mut lying = f.clone();
        lying[4..6].copy_from_slice(&declared.to_le_bytes());
        assert_eq!(
            parse(&lying),
            Err(ContainerError::LengthMismatch {
                declared: usize::from(declared),
                available: 300
            }),
            "{declared}"
        );
    }
    for n in 0..f.len() {
        assert!(parse(&f[..n]).is_err(), "prefix of {n} bytes parsed");
    }
    // Nothing to hold: the smallest it can be.
    let empty = no_salt(&[]);
    assert_eq!(parse(&empty).map(|c| c.len), Ok(0));
}

/// Every purpose round-trips, and an unknown one is refused. The purpose is
/// bound into the AAD and the key, so one purpose cannot open as another.
#[test]
fn purposes_round_trip_and_unknown_ones_are_refused() {
    for (byte, want) in [
        (1u8, Purpose::Seed),
        (2, Purpose::Xprv),
        (3, Purpose::Raw),
        (4, Purpose::Kspt),
        (5, Purpose::Text),
        (6, Purpose::Cosigner),
        (7, Purpose::Descriptor),
        (8, Purpose::Stego),
    ] {
        let f = v1(byte, 1, &[0u8; 8]);
        assert_eq!(parse(&f).unwrap().purpose, want);
    }
    for bad in [0u8, 9, 200, 255] {
        let f = v1(bad, 1, &[0u8; 8]);
        assert_eq!(parse(&f), Err(ContainerError::BadPurpose(bad)));
    }
}

/// An unimplemented KDF is reported as such, not as damage: the file is
/// probably valid and this reader too old.
#[test]
fn an_unknown_kdf_is_distinguished_from_damage() {
    let f = v1(Purpose::Seed as u8, 3, &[0u8; 8]);
    assert_eq!(parse(&f), Err(ContainerError::UnsupportedKdf(3)));

    let f = v1(Purpose::Seed as u8, 0, &[0u8; 8]);
    assert_eq!(parse(&f), Err(ContainerError::UnsupportedKdf(0)));
}

/// Both derivations parse, and the one named is in the AAD: rewritten from
/// `Argon2id` to `Pbkdf2Sha256`, a file fails its tag at level 2.
#[test]
fn every_defined_kdf_parses_and_is_authenticated() {
    let f = v1(Purpose::Seed as u8, Kdf::Argon2id as u8, &[0u8; 8]);
    let c = parse(&f).unwrap();
    assert_eq!(c.kdf, Kdf::Argon2id);
    assert_eq!(c.aad[6], Kdf::Argon2id as u8, "kdf is inside the AAD");
    assert_eq!(Kdf::from_u8(Kdf::Argon2id as u8), Some(Kdf::Argon2id));
    assert_eq!(
        Kdf::from_u8(Kdf::Pbkdf2Sha256 as u8),
        Some(Kdf::Pbkdf2Sha256)
    );
}

/// A declared length that disagrees with the file is refused: GCM
/// ciphertext is as long as its plaintext, so it can be checked.
#[test]
fn a_lying_length_is_refused() {
    let pt = vec![0xAAu8; 50];
    let mut f = v1(Purpose::Raw as u8, 1, &pt);

    let mut over = f.clone();
    over[7..9].copy_from_slice(&60u16.to_le_bytes());
    assert_eq!(
        parse(&over),
        Err(ContainerError::LengthMismatch {
            declared: 60,
            available: 50
        })
    );

    f[7..9].copy_from_slice(&40u16.to_le_bytes());
    assert_eq!(
        parse(&f),
        Err(ContainerError::LengthMismatch {
            declared: 40,
            available: 50
        })
    );
}

/// Each header fault has its own error.
#[test]
fn header_faults_are_distinguished() {
    let good = v1(Purpose::Seed as u8, 1, &[0u8; 16]);

    let mut bad = good.clone();
    bad[3] = 0x09;
    assert_eq!(parse(&bad), Err(ContainerError::BadMagic));

    let mut bad = good.clone();
    bad[4] = 2;
    assert_eq!(parse(&bad), Err(ContainerError::BadVersion(2)));

    // A legacy magic with the v1 version byte is not a v1 container.
    let mut bad = legacy(Purpose::Seed as u8, 1, &[0u8; 16]);
    bad[4] = 1;
    assert_eq!(parse(&bad), Err(ContainerError::BadVersion(1)));
}

/// Truncation at any point is refused, and never panics.
#[test]
fn truncation_anywhere_is_refused_without_panicking() {
    let full = v1(Purpose::Kspt as u8, 1, &[0xCCu8; 200]);
    assert!(parse(&full).is_ok());
    for n in 0..full.len() {
        assert!(parse(&full[..n]).is_err(), "prefix of {n} bytes parsed");
    }
    // An empty file.
    assert_eq!(parse(&[]), Err(ContainerError::BadMagic));
}

/// A written header parses back, and the AAD is the slice `write_header`
/// returned.
#[test]
fn a_written_header_parses_back() {
    let pt = vec![0xDDu8; 77];
    let mut out = vec![0u8; file_size(pt.len())];

    let aad_len = {
        let aad = write_header(Purpose::Xprv, Kdf::Pbkdf2Sha256, pt.len(), &SALT, &mut out)
            .expect("write");
        assert_eq!(aad.len(), Layout::V1.header_size());
        aad.len()
    };

    out[aad_len..aad_len + NONCE_SIZE].copy_from_slice(&NONCE);
    out[aad_len + NONCE_SIZE..aad_len + NONCE_SIZE + pt.len()].copy_from_slice(&pt);
    let tag_at = aad_len + NONCE_SIZE + pt.len();
    out[tag_at..tag_at + TAG_SIZE].copy_from_slice(&TAG);

    let c = parse(&out).expect("parse what we wrote");
    assert_eq!(c.purpose, Purpose::Xprv);
    assert_eq!(c.kdf, Kdf::Pbkdf2Sha256);
    assert_eq!(c.ciphertext, &pt[..]);
    assert_eq!(c.salt, Some(&SALT));
    assert_eq!(c.aad, &out[..aad_len]);
}

/// Only the current layout can be written; the legacy ones are only read.
#[test]
fn only_the_current_layout_is_written() {
    let mut out = vec![0u8; file_size(10)];
    let aad = write_header(Purpose::Seed, Kdf::Pbkdf2Sha256, 10, &SALT, &mut out).unwrap();
    assert_eq!(&aad[..4], &MAGIC_V1);
    assert_eq!(aad[4], 1);

    // Too small a buffer is refused rather than truncating a header.
    let mut tiny = [0u8; 8];
    assert_eq!(
        write_header(Purpose::Seed, Kdf::Pbkdf2Sha256, 10, &SALT, &mut tiny),
        Err(ContainerError::BufferTooSmall)
    );

    // The fixed-salt derivation has no byte a reader takes, so it is refused,
    // not written as `0xFE`.
    assert_eq!(
        write_header(Purpose::Seed, Kdf::Pbkdf2Sha256Fixed, 10, &SALT, &mut out),
        Err(ContainerError::UnsupportedKdf(0xFE))
    );
    for kdf in [Kdf::Pbkdf2Sha256, Kdf::Argon2id] {
        let aad = write_header(Purpose::Seed, kdf, 10, &SALT, &mut out).unwrap();
        assert_eq!(Kdf::from_u8(aad[6]), Some(kdf));
    }
}

/// What is written and what is parsed agree on sizes.
#[test]
fn sizes_agree() {
    for n in [0usize, 1, 77, 255, 256, 1000] {
        let total = file_size(n);
        assert_eq!(total, Layout::V1.overhead() + n);
        let f = v1(Purpose::Raw as u8, 1, &vec![0u8; n]);
        assert_eq!(f.len(), total, "built file disagrees with file_size at {n}");
        assert_eq!(parse(&f).unwrap().len, n);
    }
}
