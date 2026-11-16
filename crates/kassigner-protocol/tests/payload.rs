// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Payload envelopes.

use kassigner_protocol::payload::{
    classify_blob, covenant_len, parse_covenant, write_covenant, write_raw_blob, BlobFormat,
    PayloadError, BLOB_RAW_PREFIX, COVENANT_VERSION,
};

/// A covenant payload round-trips, parameters unchanged.
#[test]
fn a_covenant_payload_round_trips() {
    for params in [&[][..], &[0x01][..], &[0xAB; 200][..]] {
        let mut out = vec![0u8; covenant_len(params.len())];
        let n = write_covenant(0x07, params, &mut out).expect("write");
        assert_eq!(n, out.len());

        let p = parse_covenant(&out[..n]).expect("parse");
        assert_eq!(p.version, COVENANT_VERSION);
        assert_eq!(p.covenant_type, 0x07);
        assert_eq!(p.params, params);
    }
}

/// Every type byte round-trips uninterpreted, defined or not: a signer that
/// read it would trust a label from the party it exists to distrust.
#[test]
fn every_type_byte_is_carried_without_meaning() {
    for t in [0u8, 1, 12, 99, 255] {
        let mut out = [0u8; 8];
        let n = write_covenant(t, &[0xFF; 4], &mut out).unwrap();
        assert_eq!(parse_covenant(&out[..n]).unwrap().covenant_type, t);
    }
}

/// Short and unsupported payloads are refused, each with its own error.
#[test]
fn malformed_covenant_payloads_are_refused() {
    assert_eq!(parse_covenant(&[]), Err(PayloadError::TooShort));
    assert_eq!(parse_covenant(&[0x01]), Err(PayloadError::TooShort));
    assert_eq!(
        parse_covenant(&[0x02, 0x00]),
        Err(PayloadError::UnsupportedVersion(0x02))
    );
    assert_eq!(
        parse_covenant(&[0x00, 0x00]),
        Err(PayloadError::UnsupportedVersion(0x00))
    );

    let mut tiny = [0u8; 1];
    assert_eq!(
        write_covenant(1, &[0u8; 4], &mut tiny),
        Err(PayloadError::BufferTooSmall)
    );
}

/// A raw blob is recognised by its prefix, `0x01`, which no legacy payload
/// starts with: base58 runs 0x31 to 0x7A, hex 0x30 to 0x66, a mnemonic 0x61
/// to 0x7A.
#[test]
fn the_raw_prefix_cannot_collide_with_legacy_payloads() {
    let body = b"hello";
    let mut out = [0u8; 16];
    let n = write_raw_blob(body, &mut out).unwrap();
    assert_eq!(out[0], BLOB_RAW_PREFIX);
    assert_eq!(classify_blob(&out[..n]), (BlobFormat::Raw, &body[..]));

    // Bytes a legacy payload can start with classify as legacy.
    for &first in b"19AZafz0" {
        let blob = [first, b'x', b'y'];
        let (fmt, rest) = classify_blob(&blob);
        assert_eq!(fmt, BlobFormat::LegacyAscii, "byte {first:#04x}");
        assert_eq!(rest, &blob[..], "a legacy blob is read whole");
    }

    // Empty is legacy with an empty body: there is no prefix to find.
    assert_eq!(classify_blob(&[]), (BlobFormat::LegacyAscii, &[][..]));
}
