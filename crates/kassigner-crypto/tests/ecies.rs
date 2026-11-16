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

//! ECIES. No published document describes this recipe, so these check
//! what needs no published vector: both parties reach the same key, every
//! field is bound into it, and the two halves agree on the bytes. The
//! differential against v1.0.7's recorded outputs is `tests/device.rs`.

use kassigner_crypto::ecies::{decrypt, encrypt, encrypted_size, EciesError, DOMAIN};
use kassigner_crypto::sign::public_key;
use kassigner_protocol::ecies::{parse, EciesError as WireError, NONCE_SIZE, OVERHEAD, TAG_SIZE};

const EPHEMERAL: [u8; 32] = [0x42; 32];
const NONCE: [u8; NONCE_SIZE] = [0x24; NONCE_SIZE];

/// A recipient key pair.
fn recipient(seed: u8) -> ([u8; 32], [u8; 32]) {
    let sk = [seed; 32];
    let pk = public_key(&sk).expect("x-only key");
    (sk, pk)
}

/// A message encrypted to a key decrypts with that key.
#[test]
fn a_message_round_trips() {
    let (sk, pk) = recipient(7);

    for len in [0usize, 1, 16, 64, 1000] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 5) as u8).collect();

        let mut wire = vec![0u8; encrypted_size(len)];
        let n = encrypt(&pk, &plaintext, &EPHEMERAL, &NONCE, &mut wire)
            .unwrap_or_else(|e| panic!("{len} bytes: {e:?}"));
        assert_eq!(n, wire.len());
        assert_eq!(n, len + OVERHEAD);

        let mut out = vec![0u8; len];
        let m = decrypt(&sk, &wire, &mut out).unwrap_or_else(|e| panic!("{len}: {e:?}"));
        assert_eq!(m, len);
        assert_eq!(out, plaintext, "{len} bytes changed");
    }
}

/// What this encrypts, level 1 parses, field for field: the halves agree on
/// where the nonce sits.
#[test]
fn what_this_encrypts_level_one_parses() {
    let (_, pk) = recipient(3);
    let plaintext = b"a covenant payload";

    let mut wire = vec![0u8; encrypted_size(plaintext.len())];
    encrypt(&pk, plaintext, &EPHEMERAL, &NONCE, &mut wire).unwrap();

    let e = parse(&wire).expect("level 1 reads it");
    assert_eq!(e.nonce, &NONCE);
    assert_eq!(e.ciphertext.len(), plaintext.len());
    assert_eq!(e.tag.len(), TAG_SIZE);
    assert!(
        matches!(e.ephemeral_key[0], 0x02 | 0x03),
        "a compressed point"
    );
    assert_ne!(e.ciphertext, &plaintext[..], "it is actually encrypted");
}

/// The wrong private key fails, and fails like a corrupt message.
#[test]
fn the_wrong_key_and_a_corrupt_message_fail_alike() {
    let (_, pk) = recipient(1);
    let (other_sk, _) = recipient(2);

    let mut wire = vec![0u8; encrypted_size(32)];
    encrypt(&pk, &[0xAAu8; 32], &EPHEMERAL, &NONCE, &mut wire).unwrap();

    let mut out = [0u8; 32];
    assert_eq!(
        decrypt(&other_sk, &wire, &mut out).err(),
        Some(EciesError::Authentication)
    );

    let (sk, _) = recipient(1);
    let mut damaged = wire.clone();
    let ct_at = OVERHEAD - TAG_SIZE;
    damaged[ct_at] ^= 1;
    assert_eq!(
        decrypt(&sk, &damaged, &mut out).err(),
        Some(EciesError::Authentication)
    );
}

/// Every header byte is authenticated: the ephemeral key is inside the
/// derived key, and both it and the nonce are in the AAD.
#[test]
fn the_header_is_authenticated() {
    let (sk, pk) = recipient(11);
    let mut wire = vec![0u8; encrypted_size(48)];
    encrypt(&pk, &[0x5Au8; 48], &EPHEMERAL, &NONCE, &mut wire).unwrap();

    let mut out = [0u8; 48];
    assert!(
        decrypt(&sk, &wire, &mut out).is_ok(),
        "the original decrypts"
    );

    // Every byte of the ephemeral key and the nonce, one at a time.
    for i in 0..OVERHEAD - TAG_SIZE {
        let mut d = wire.clone();
        d[i] ^= 0x40;
        let r = decrypt(&sk, &d, &mut out);
        assert!(
            r.is_err(),
            "byte {i} of the header was not bound into the key"
        );
    }
}

/// A failed decryption leaves nothing behind.
#[test]
fn a_failed_decrypt_wipes_what_it_wrote() {
    let (_, pk) = recipient(4);
    let (wrong_sk, _) = recipient(5);

    let mut wire = vec![0u8; encrypted_size(64)];
    encrypt(&pk, &[0x77u8; 64], &EPHEMERAL, &NONCE, &mut wire).unwrap();

    let mut out = [0xFFu8; 64];
    assert_eq!(
        decrypt(&wrong_sk, &wire, &mut out).err(),
        Some(EciesError::Authentication)
    );
    assert_eq!(out, [0u8; 64], "the buffer was left holding something");
}

/// A different ephemeral key or nonce gives a different ciphertext. Both
/// must be fresh: a repeated ephemeral key under one recipient makes two
/// messages share a key, and a repeated nonce under one key breaks AES-GCM.
#[test]
fn the_ephemeral_key_and_nonce_must_be_fresh() {
    let (sk, pk) = recipient(6);
    let plaintext = [0x11u8; 32];

    let mut a = vec![0u8; encrypted_size(32)];
    encrypt(&pk, &plaintext, &EPHEMERAL, &NONCE, &mut a).unwrap();

    let mut b = vec![0u8; encrypted_size(32)];
    encrypt(&pk, &plaintext, &[0x43u8; 32], &NONCE, &mut b).unwrap();
    assert_ne!(a, b, "a different ephemeral key must change everything");

    let mut c = vec![0u8; encrypted_size(32)];
    encrypt(&pk, &plaintext, &EPHEMERAL, &[0x25u8; NONCE_SIZE], &mut c).unwrap();
    assert_ne!(a, c, "a different nonce must change the ciphertext");

    // All three decrypt to the same plaintext.
    for wire in [&a, &b, &c] {
        let mut out = [0u8; 32];
        assert_eq!(decrypt(&sk, wire, &mut out).unwrap(), 32);
        assert_eq!(out, plaintext);
    }

    // The same inputs give the same bytes, which makes a differential
    // against the firmware possible.
    let mut again = vec![0u8; encrypted_size(32)];
    encrypt(&pk, &plaintext, &EPHEMERAL, &NONCE, &mut again).unwrap();
    assert_eq!(a, again);
}

/// A recipient whose key has odd y still decrypts. An x-only key is lifted
/// to the even-y point, but only the shared point's x feeds the derivation,
/// and negating a point keeps its x.
#[test]
fn a_recipient_with_an_odd_y_key_still_decrypts() {
    use k256::elliptic_curve::point::AffineCoordinates;
    use k256::elliptic_curve::PrimeField;
    use k256::{ProjectivePoint, Scalar};

    let mut odd_found = false;
    for seed in 1u8..30 {
        let sk = [seed; 32];
        let d: Scalar = Option::from(Scalar::from_repr(sk.into())).expect("scalar");
        let point = (ProjectivePoint::GENERATOR * d).to_affine();
        if !bool::from(point.y_is_odd()) {
            continue;
        }
        odd_found = true;

        let pk = public_key(&sk).unwrap();
        let mut wire = vec![0u8; encrypted_size(16)];
        encrypt(&pk, &[0x99u8; 16], &EPHEMERAL, &NONCE, &mut wire).unwrap();

        let mut out = [0u8; 16];
        assert_eq!(
            decrypt(&sk, &wire, &mut out).unwrap(),
            16,
            "seed {seed} has an odd-y key and failed to decrypt"
        );
        assert_eq!(out, [0x99u8; 16]);
    }
    assert!(odd_found, "the sweep must find an odd-y key");
}

/// Malformed inputs are refused, each for its own reason.
#[test]
fn malformed_inputs_are_refused() {
    let (sk, pk) = recipient(8);
    let mut out = [0u8; 64];

    // Framing, from level 1.
    assert_eq!(
        decrypt(&sk, &[], &mut out).err(),
        Some(EciesError::Wire(WireError::TooShort { len: 0 }))
    );

    // A bad ephemeral scalar, and a bad recipient x.
    let mut wire = vec![0u8; encrypted_size(8)];
    assert_eq!(
        encrypt(&pk, &[0u8; 8], &[0u8; 32], &NONCE, &mut wire).err(),
        Some(EciesError::InvalidEphemeral)
    );
    assert_eq!(
        encrypt(&[0xFFu8; 32], &[0u8; 8], &EPHEMERAL, &NONCE, &mut wire).err(),
        Some(EciesError::InvalidRecipient)
    );

    // Buffers that cannot hold the result.
    let needed = encrypted_size(8);
    let mut small = vec![0u8; needed - 1];
    assert_eq!(
        encrypt(&pk, &[0u8; 8], &EPHEMERAL, &NONCE, &mut small).err(),
        Some(EciesError::BufferTooSmall { needed })
    );

    encrypt(&pk, &[0u8; 8], &EPHEMERAL, &NONCE, &mut wire).unwrap();
    let mut tiny = [0u8; 7];
    assert_eq!(
        decrypt(&sk, &wire, &mut tiny).err(),
        Some(EciesError::BufferTooSmall { needed: 8 })
    );
}

/// The domain separator is what it is, and changing it is a format change.
#[test]
fn the_domain_separator_is_part_of_the_format() {
    assert_eq!(DOMAIN, b"KasSigner-ECIES-v2");
}

/// The key derivation's hasher wipes itself on drop: it absorbs the ECDH
/// secret, the shared point's x, which sits in its block buffer until
/// `finalize`. The 32-byte `Blake2b` carries no marker of its own, so its
/// compression state and buffer are pinned as type bounds: without
/// `blake2`'s `zeroize` feature this does not compile.
#[test]
fn the_key_derivation_hasher_wipes_on_drop() {
    use blake2::digest::block_api::Buffer;
    use blake2::Blake2bVarCore;

    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_on_drop::<Blake2bVarCore>();
    wipes_on_drop::<Buffer<Blake2bVarCore>>();
}

/// An all-zero nonce is refused, and an ephemeral key with a valid prefix
/// but an x on no curve point is `InvalidEphemeral`.
#[test]
fn a_zero_nonce_and_an_off_curve_point_are_refused_by_name() {
    let (sk, pk) = recipient(9);
    let mut wire = vec![0u8; encrypted_size(8)];
    assert_eq!(
        encrypt(&pk, &[0u8; 8], &EPHEMERAL, &[0u8; NONCE_SIZE], &mut wire).err(),
        Some(EciesError::ZeroNonce)
    );
    encrypt(&pk, &[0u8; 8], &EPHEMERAL, &NONCE, &mut wire).unwrap();
    let mut out = [0u8; 8];
    let mut off_curve = 0;
    for x in 1u8..=16 {
        let mut d = wire.clone();
        d[0] = 0x02;
        d[1..33].fill(0);
        d[32] = x;
        match decrypt(&sk, &d, &mut out).err() {
            Some(EciesError::InvalidEphemeral) => off_curve += 1,
            Some(EciesError::Authentication) => {}
            other => panic!("x = {x}: {other:?}"),
        }
    }
    assert!(off_curve > 0, "some x of the sixteen has no point");
}
