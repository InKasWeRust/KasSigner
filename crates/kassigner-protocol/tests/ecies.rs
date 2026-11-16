// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The ECIES envelope, framing only: decryption is `kassigner-crypto`'s.

use kassigner_protocol::ecies::{
    ciphertext_offset, parse, wire_size, write_header, EciesError, EPHEMERAL_SIZE, NONCE_SIZE,
    OVERHEAD, TAG_SIZE,
};

const EPH: [u8; EPHEMERAL_SIZE] = {
    let mut e = [0x11u8; EPHEMERAL_SIZE];
    e[0] = 0x02;
    e
};
const NONCE: [u8; NONCE_SIZE] = [0x22; NONCE_SIZE];
const TAG: [u8; TAG_SIZE] = [0x33; TAG_SIZE];

fn envelope(plaintext: &[u8]) -> Vec<u8> {
    let mut w = Vec::new();
    w.extend_from_slice(&EPH);
    w.extend_from_slice(&NONCE);
    w.extend_from_slice(plaintext);
    w.extend_from_slice(&TAG);
    w
}

/// An envelope parses and every part comes back.
#[test]
fn an_envelope_parses() {
    for len in [0usize, 1, 32, 1000] {
        let ct: Vec<u8> = (0..len).map(|i| (i * 5) as u8).collect();
        let wire = envelope(&ct);
        assert_eq!(wire.len(), wire_size(len));

        let e = parse(&wire).unwrap_or_else(|err| panic!("{len} bytes: {err:?}"));
        assert_eq!(e.ephemeral_key, &EPH);
        assert_eq!(e.nonce, &NONCE);
        assert_eq!(e.ciphertext, &ct[..]);
        assert_eq!(e.tag, &TAG);
    }
}

/// Both compressed prefixes are accepted and nothing else is: a framing
/// error, not a curve error.
#[test]
fn only_a_compressed_prefix_is_accepted() {
    for prefix in [0x02u8, 0x03] {
        let mut wire = envelope(b"x");
        wire[0] = prefix;
        assert!(parse(&wire).is_ok(), "prefix {prefix:#04x}");
    }
    for prefix in [0x00u8, 0x01, 0x04, 0x05, 0xFF] {
        let mut wire = envelope(b"x");
        wire[0] = prefix;
        assert_eq!(
            parse(&wire).err(),
            Some(EciesError::BadEphemeralPrefix(prefix))
        );
    }
}

/// Anything shorter than [`OVERHEAD`], an empty plaintext's envelope, is
/// refused.
#[test]
fn a_short_envelope_is_refused() {
    let empty = envelope(&[]);
    assert_eq!(empty.len(), OVERHEAD);
    assert!(
        parse(&empty).is_ok(),
        "the overhead alone is a valid envelope"
    );

    for n in 0..OVERHEAD {
        assert_eq!(
            parse(&empty[..n]).err(),
            Some(EciesError::TooShort { len: n })
        );
    }
}

/// A header written here parses back at the offsets it promises.
#[test]
fn a_written_header_parses_back() {
    let plaintext = b"some bytes";
    let mut out = vec![0u8; wire_size(plaintext.len())];

    let n = write_header(&EPH, &NONCE, plaintext.len(), &mut out).expect("write");
    assert_eq!(n, out.len());

    let ct_at = ciphertext_offset();
    assert_eq!(ct_at, EPHEMERAL_SIZE + NONCE_SIZE);
    out[ct_at..ct_at + plaintext.len()].copy_from_slice(plaintext);
    let tag_at = ct_at + plaintext.len();
    out[tag_at..tag_at + TAG_SIZE].copy_from_slice(&TAG);

    let e = parse(&out).expect("parse what we wrote");
    assert_eq!(e.ephemeral_key, &EPH);
    assert_eq!(e.nonce, &NONCE);
    assert_eq!(e.ciphertext, plaintext);
    assert_eq!(e.tag, &TAG);
}

/// Writing refuses a buffer that cannot hold the envelope.
#[test]
fn writing_refuses_a_short_buffer() {
    let needed = wire_size(50);
    let mut small = vec![0u8; needed - 1];
    assert_eq!(
        write_header(&EPH, &NONCE, 50, &mut small).err(),
        Some(EciesError::BufferTooSmall { needed })
    );
}

/// Truncation anywhere is refused and never panics.
#[test]
fn truncation_anywhere_is_refused_without_panicking() {
    let wire = envelope(&[0xAAu8; 200]);
    assert!(parse(&wire).is_ok());
    for n in 0..wire.len() {
        // From the overhead up, a cut is a shorter but valid envelope.
        let r = parse(&wire[..n]);
        if n < OVERHEAD {
            assert!(r.is_err(), "{n} bytes parsed");
        } else {
            assert!(r.is_ok(), "{n} bytes should be a valid shorter envelope");
        }
    }
}
