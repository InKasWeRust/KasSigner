// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a unit hands over reads as what it is, and nothing else does.

use kassigner_kaspa::address::{encode, Version, MAX_ADDRESS_LEN};
use kassigner_kaspa::kat::MULTISIG_45;
use kassigner_protocol::{kpub, message};
use kassigner_sdk::import::{read, Import, ImportError};
use kassigner_sdk::watch::{Group, WatchError};
use kassigner_sdk::Network;

/// The 12-word abandon seed's `m/44'/111111'/0'`
/// (`kassigner-crypto/tests/v107.rs`).
const ABANDON12_KPUB44: &str = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";

/// A seed's KCC-3 receive 0 (`kassigner-kaspa/tests/kcc3.rs`).
const KCC3_RECEIVE0: &str = "kaspa:pq02dzckvs0g6hhl9s9c484fv0wsd93sltwct9symfad4yw062w5y4v4mtlxa";

/// The Go wallet's 2-of-5 descriptor, keys in upstream's order.
fn descriptor() -> String {
    format!("multi_hd45(2,{})", MULTISIG_45.kpubs.join(","))
}

/// A kpub reads as a `44'` account, as text or raw, with whitespace around it;
/// cut short, it does not.
#[test]
fn a_kpub_reads_as_an_account() {
    let key = kpub::read(ABANDON12_KPUB44.as_bytes()).expect("a kpub");
    let text = format!("  {ABANDON12_KPUB44}\n");
    let Ok(Import::Account(account)) = read(text.as_bytes()) else {
        panic!("not an account");
    };
    assert_eq!(*account.key(), key);
    let mut raw = [0u8; kpub::RAW_LEN];
    kpub::write_raw(&key, &mut raw).unwrap();
    let Ok(Import::Account(from_raw)) = read(&raw) else {
        panic!("the raw form");
    };
    assert_eq!(from_raw, account);
    assert_eq!(read(&raw[..raw.len() - 1]), Err(ImportError::NotRecognised));
    assert_eq!(
        read(&text.as_bytes()[..text.len() - 3]),
        Err(ImportError::NotRecognised),
        "a kpub cut short"
    );
}

/// A cosigner's file reads with its fingerprint; a bad one is `Cosigner`.
#[test]
fn a_cosigner_file_reads_with_its_fingerprint() {
    let key = kpub::read(ABANDON12_KPUB44.as_bytes()).expect("a kpub");
    let mut file = [0u8; kpub::COSIGNER_MAX];
    let n = kpub::write_cosigner(
        [0x73, 0xc5, 0xda, 0x0a],
        ABANDON12_KPUB44.as_bytes(),
        &mut file,
    )
    .unwrap();
    assert_eq!(
        read(&file[..n]),
        Ok(Import::Cosigner {
            fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            key
        })
    );
    assert_eq!(
        read(b"[73c5da0a/44'/111111'/0']kpub..."),
        Err(ImportError::Cosigner)
    );
}

/// A descriptor reads, header and all, as the line of its group; six keys or a
/// bad key is `Descriptor`.
#[test]
fn a_descriptor_reads_as_a_group() {
    let line = descriptor();
    let text = format!("# the Go wallet's group\n{line}\n");
    let Ok(Import::Descriptor(got)) = read(text.as_bytes()) else {
        panic!("not a descriptor");
    };
    assert_eq!(got, line);
    let group = Group::from_descriptor(got).expect("a group");
    assert_eq!(group.required(), 2);
    assert_eq!(group.total(), 5);
    let six = format!(
        "multi_hd45(2,{},{})",
        MULTISIG_45.kpubs.join(","),
        ABANDON12_KPUB44
    );
    assert!(matches!(
        read(six.as_bytes()),
        Err(ImportError::Descriptor(_))
    ));
    assert!(matches!(
        read(b"multi_hd45(2,x)"),
        Err(ImportError::Descriptor(_))
    ));
}

/// A `22'` address reads; a key's address, or one off mainnet, is refused by
/// name.
#[test]
fn a_kcc3_address_reads() {
    let Ok(Import::Kcc3Address(a)) = read(format!(" {KCC3_RECEIVE0} ").as_bytes()) else {
        panic!("not an address");
    };
    assert_eq!(a.text(), KCC3_RECEIVE0.as_bytes());
    let mut mine = [0u8; MAX_ADDRESS_LEN];
    let n = encode(Network::Mainnet, Version::PubKey, &[7u8; 32], &mut mine).unwrap();
    assert_eq!(
        read(&mine[..n]),
        Err(ImportError::Address(WatchError::NotScriptHash))
    );
    let n = encode(Network::Testnet, Version::ScriptHash, &[7u8; 32], &mut mine).unwrap();
    assert_eq!(
        read(&mine[..n]),
        Err(ImportError::Address(WatchError::NotMainnet(
            Network::Testnet
        )))
    );
    assert_eq!(read(b"kaspa:pq02dz"), Err(ImportError::NotRecognised));
}

/// A signed message reads as one, its parts where they are.
#[test]
fn a_signed_message_reads() {
    let mut out = [0u8; 512];
    let n = message::write(b"Hello Kaspa!", b"kaspa:qyp...", &[b'a'; 128], &mut out).unwrap();
    let Ok(Import::SignedMessage(parts)) = read(&out[..n]) else {
        panic!("not a message");
    };
    assert_eq!(&out[parts.text], b"Hello Kaspa!");
}

/// Anything else is not recognised.
#[test]
fn anything_else_is_not_recognised() {
    for bytes in [&b"hello"[..], b"", b"KSPT\x06", b"\xff\xfe", b"zpub..."] {
        assert_eq!(read(bytes), Err(ImportError::NotRecognised), "{bytes:?}");
    }
}
