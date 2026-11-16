// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The addresses and scripts an app watches are the unit's.

use kassigner_kaspa::address::{decode, encode, Version, MAX_ADDRESS_LEN};
use kassigner_kaspa::kat::MULTISIG_45;
use kassigner_kaspa::script::{pay_to_pubkey, pay_to_script_hash};
use kassigner_protocol::kpub;
use kassigner_sdk::request::script_of_address;
use kassigner_sdk::watch::{
    address_of_script, group_address, group_script, Account, Group, Kcc3Address, WatchError,
    CHANGE, RECEIVE,
};
use kassigner_sdk::Network;

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::unhex_array;

/// The 12-word abandon seed's `m/44'/111111'/0'` and its receive 0 key
/// (`kassigner-crypto/tests/v107.rs`).
const ABANDON12_KPUB44: &str = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";
const ABANDON12_RECEIVE0: &str = "1bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058";

/// A seed's KCC-3 receive 0: script hash and address
/// (`kassigner-kaspa/tests/kcc3.rs`).
const KCC3_HASH: &str = "1ea68b16641e8d5eff2c0b8a9ea963dd069630fadd859604da7ada91cfd29d42";
const KCC3_ADDRESS: &str = "kaspa:pq02dzckvs0g6hhl9s9c484fv0wsd93sltwct9symfad4yw062w5y4v4mtlxa";

fn text(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap()
}

/// A `44'` account's keys, scripts and addresses are the unit's: receive 0 is
/// the key v1.0.7 spends; a hardened index and a short buffer are refused.
#[test]
fn an_account_derives_what_the_unit_derives() {
    let account = Account::new(kpub::read(ABANDON12_KPUB44.as_bytes()).unwrap());
    let key = unhex_array::<32>(ABANDON12_RECEIVE0);
    assert_eq!(account.public_key(RECEIVE, 0), Ok(key));
    assert_eq!(account.script(RECEIVE, 0), Ok(pay_to_pubkey(&key)));
    let mut out = [0u8; MAX_ADDRESS_LEN];
    let n = account.address(RECEIVE, 0, &mut out).unwrap();
    let mut payload = [0u8; 33];
    assert_eq!(
        decode(&out[..n], &mut payload),
        Ok((Network::Mainnet, Version::PubKey, 32))
    );
    assert_eq!(payload[..32], key);
    assert!(text(&out[..n]).starts_with("kaspa:q"));
    assert_ne!(account.public_key(CHANGE, 0), Ok(key));
    assert!(matches!(
        account.public_key(RECEIVE, 0x8000_0000),
        Err(WatchError::Derivation(_))
    ));
    assert_eq!(
        account.address(RECEIVE, 0, &mut [0u8; 8]),
        Err(WatchError::BufferTooSmall)
    );
}

/// A group's address is the Go wallet's, and its script pays that hash.
#[test]
fn a_group_derives_the_go_wallets_address() {
    let line = format!("multi_hd45(2,{})", MULTISIG_45.kpubs.join(","));
    let group = Group::from_descriptor(&line).unwrap();
    let mut out = [0u8; MAX_ADDRESS_LEN];
    let n = group_address(
        &group,
        MULTISIG_45.cosigner,
        MULTISIG_45.chain,
        MULTISIG_45.index,
        &mut out,
    )
    .unwrap();
    assert_eq!(text(&out[..n]), MULTISIG_45.address);
    let mut payload = [0u8; 33];
    decode(&out[..n], &mut payload).unwrap();
    let hash = <[u8; 32]>::try_from(&payload[..32]).unwrap();
    assert_eq!(
        group_script(
            &group,
            MULTISIG_45.cosigner,
            MULTISIG_45.chain,
            MULTISIG_45.index
        ),
        Ok(pay_to_script_hash(&hash))
    );
    assert!(matches!(
        group_script(&group, 0x8000_0000, 0, 0),
        Err(WatchError::Group(_))
    ));
    assert!(matches!(
        group_address(&group, 0x8000_0000, 0, 0, &mut out),
        Err(WatchError::Group(_))
    ));
    assert_eq!(
        group_address(&group, 0, 0, 0, &mut [0u8; 8]),
        Err(WatchError::BufferTooSmall)
    );
}

/// A `22'` address is held as text, with its hash and script.
#[test]
fn a_kcc3_address_is_held_as_text() {
    let a = Kcc3Address::read(format!("{KCC3_ADDRESS}\n").as_bytes()).unwrap();
    assert_eq!(a.text(), KCC3_ADDRESS.as_bytes());
    assert_eq!(*a.hash(), unhex_array::<32>(KCC3_HASH));
    assert_eq!(
        a.script(),
        pay_to_script_hash(&unhex_array::<32>(KCC3_HASH))
    );
    let mut mine = [0u8; MAX_ADDRESS_LEN];
    let n = encode(Network::Mainnet, Version::PubKey, &[7u8; 32], &mut mine).unwrap();
    assert_eq!(
        Kcc3Address::read(&mine[..n]).err(),
        Some(WatchError::NotScriptHash)
    );
    assert!(matches!(
        Kcc3Address::read(b"kaspa:pq02dz"),
        Err(WatchError::NotAnAddress(_))
    ));
}

/// Only a mainnet address is paid or watched: a key's or a script hash's on
/// another network is refused by the network it names.
#[test]
fn only_a_mainnet_address_is_paid_or_watched() {
    let key = unhex_array::<32>(ABANDON12_RECEIVE0);
    let hash = unhex_array::<32>(KCC3_HASH);
    let mut text = [0u8; MAX_ADDRESS_LEN];
    let mut script = [0u8; 35];
    for network in [Network::Testnet, Network::Simnet, Network::Devnet] {
        for (version, payload) in [(Version::PubKey, &key), (Version::ScriptHash, &hash)] {
            let n = encode(network, version, payload, &mut text).unwrap();
            assert_eq!(
                script_of_address(&text[..n], &mut script),
                Err(WatchError::NotMainnet(network))
            );
        }
        let n = encode(network, Version::ScriptHash, &hash, &mut text).unwrap();
        assert_eq!(
            Kcc3Address::read(&text[..n]).err(),
            Some(WatchError::NotMainnet(network))
        );
    }
}

/// A script's address is the address's script back; a script that pays no
/// address, or a short buffer, is refused.
#[test]
fn a_scripts_address_is_the_addresss_script_back() {
    let account = Account::new(kpub::read(ABANDON12_KPUB44.as_bytes()).unwrap());
    let mut out = [0u8; MAX_ADDRESS_LEN];
    let n = account.address(RECEIVE, 0, &mut out).unwrap();
    let mut back = [0u8; MAX_ADDRESS_LEN];
    let m = address_of_script(&account.script(RECEIVE, 0).unwrap(), &mut back).unwrap();
    assert_eq!(&back[..m], &out[..n]);
    let mut script = [0u8; 35];
    let k = script_of_address(KCC3_ADDRESS.as_bytes(), &mut script).unwrap();
    let m = address_of_script(&script[..k], &mut back).unwrap();
    assert_eq!(text(&back[..m]), KCC3_ADDRESS);
    assert_eq!(
        address_of_script(&[0x51, 0x87], &mut back),
        Err(WatchError::NotScriptHash)
    );
    assert_eq!(
        address_of_script(&script[..k], &mut [0u8; 8]),
        Err(WatchError::BufferTooSmall)
    );
}
