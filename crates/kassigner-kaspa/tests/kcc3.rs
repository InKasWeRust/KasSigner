// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KCC-3, "Pay-to-Public-Key-Hash via P2SH": account path, redeem script and
//! address.
//!
//! The draft has no vectors yet. These are the first receive and change keys
//! of the 12-word "abandon ... about" seed at `m/22'/111111'/0'`, recomputed
//! outside this tree in plain Python from the BIP39, BIP32, Blake2b-256 and
//! address checksum specifications. That script also reproduces the seed's
//! `44'` change address, `kaspa:qqnkyg4h...`, which the firmware's UI tests
//! hold: it is checked against a number it did not produce.

use kassigner_kaspa::address::{encode, Prefix, Version, MAX_ADDRESS_LEN};
use kassigner_kaspa::bip32_public::{ChildNumber, HARDENED_OFFSET};
use kassigner_kaspa::derivation::{Path, KCC3_ACCOUNT, PURPOSE_KCC3};
use kassigner_kaspa::script::{
    classify, kcc3_key, kcc3_redeem, kcc3_script_hash, redeem_hash, redeem_matches, ScriptClass,
};
use kassigner_kaspa::tx::ScriptPublicKey;

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::unhex_array;

/// The seed's KCC-3 receive 0: key, script hash, address.
const RECEIVE_0: (&str, &str, &str) = (
    "fa507ef4400da1016770879248322820e16cdea980b83261b5bb5d384f2e2b45",
    "1ea68b16641e8d5eff2c0b8a9ea963dd069630fadd859604da7ada91cfd29d42",
    "kaspa:pq02dzckvs0g6hhl9s9c484fv0wsd93sltwct9symfad4yw062w5y4v4mtlxa",
);

/// The seed's KCC-3 change 0.
const CHANGE_0: (&str, &str, &str) = (
    "a7521d727b42682622c3b507d7ec4342c108c7181b59601188645cba60fe2f6a",
    "9857e1c54da814ff32e0806d5579a36ae46d37508019b4b3a33ba0e337a59397",
    "kaspa:pzv90cw9fk5pflejuzqx64te5d4wgmfh2zqpnd9n5va6pceh5kfew40ett9em",
);

/// The account is `m/22'/111111'/0'`, chains and indices soft below it.
#[test]
fn the_kcc3_account_is_purpose_22() {
    let h = HARDENED_OFFSET;
    assert_eq!(PURPOSE_KCC3, 22);
    assert_eq!(
        KCC3_ACCOUNT,
        [
            ChildNumber(h + 22),
            ChildNumber(h + 111_111),
            ChildNumber(h)
        ]
    );
    let mut below = [ChildNumber(0); 3];
    let p = Path::kcc3_change(7);
    assert!(p.is_kcc3() && !p.is_multisig());
    assert_eq!(p.account(), KCC3_ACCOUNT);
    assert_eq!(
        p.children(&mut below).unwrap(),
        &[ChildNumber(1), ChildNumber(7)]
    );
    assert_eq!(Path::kcc3_receive(3), Path::Kcc3 { chain: 0, index: 3 });
    assert!(Path::kcc3_receive(h).children(&mut below).is_err());
}

/// A KCC-3 key's script, hash and address, for both vector keys.
#[test]
fn a_kcc3_address_is_the_hash_of_its_script() {
    for (key, hash, address) in [RECEIVE_0, CHANGE_0] {
        let key = unhex_array::<32>(key);
        let redeem = kcc3_redeem(&key);
        assert_eq!(redeem[0], 0x20, "a 32-byte push");
        assert_eq!(&redeem[1..33], &key);
        assert_eq!(redeem[33], 0xac, "OP_CHECKSIG");
        assert_eq!(kcc3_key(&redeem), Some(&key[..]));

        assert_eq!(kcc3_script_hash(&key), unhex_array::<32>(hash));
        assert_eq!(redeem_hash(&redeem), unhex_array::<32>(hash));
        let mut text = [0u8; MAX_ADDRESS_LEN];
        let n = encode(
            Prefix::Mainnet,
            Version::ScriptHash,
            &kcc3_script_hash(&key),
            &mut text,
        )
        .unwrap();
        assert_eq!(core::str::from_utf8(&text[..n]).unwrap(), address);

        // The lock the address stands for holds exactly this script.
        let mut lock = [0u8; 35];
        lock[0] = 0xaa;
        lock[1] = 0x20;
        lock[2..34].copy_from_slice(&kcc3_script_hash(&key));
        lock[34] = 0x87;
        let spk = ScriptPublicKey {
            version: 0,
            script: &lock,
        };
        assert_eq!(classify(&spk), ScriptClass::ScriptHash);
        assert!(redeem_matches(&spk, &redeem));
    }
}

/// Only the exact script is KCC-3's.
#[test]
fn only_the_exact_script_is_kcc3s() {
    let key = unhex_array::<32>(RECEIVE_0.0);
    let exact = kcc3_redeem(&key);
    let mut verify = exact;
    verify[33] = 0xad; // OP_CHECKSIGVERIFY
    let mut ecdsa = exact;
    ecdsa[33] = 0xab; // OP_CHECKSIGECDSA
    let mut longer = exact.to_vec();
    longer.push(0x51); // OP_1 after the check
    let mut prefixed = vec![0x51];
    prefixed.extend_from_slice(&exact); // OP_1 before the key
    let mut one_of_one = vec![0x51, 0x20];
    one_of_one.extend_from_slice(&key);
    one_of_one.extend_from_slice(&[0x51, 0xae]); // 1-of-1 multisig
    let mut short_push = vec![0x1f];
    short_push.extend_from_slice(&key[..31]);
    short_push.push(0xac);
    for (name, script) in [
        ("CHECKSIGVERIFY", &verify[..]),
        ("ECDSA check", &ecdsa[..]),
        ("an opcode after", &longer[..]),
        ("an opcode before", &prefixed[..]),
        ("a 1-of-1 multisig", &one_of_one[..]),
        ("a 31-byte push", &short_push[..]),
        ("the key alone", &exact[..33]),
        ("nothing", &[][..]),
    ] {
        assert_eq!(kcc3_key(script), None, "{name}");
    }
}
