// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A multisig group: upstream's order, its addresses, its descriptor, and
//! what it refuses.

use kassigner_kaspa::address::Prefix as Network;
use kassigner_kaspa::bip32_public::{Bip32Error, ChildNumber, ExtendedPublicKey, Prefix};
use kassigner_kaspa::kat::MULTISIG_45;
use kassigner_kaspa::multisig::MultisigError;
use kassigner_protocol::descriptor::{self, DescriptorError};
use kassigner_protocol::group::{Group, GroupError};

fn key(text: &str) -> ExtendedPublicKey {
    ExtendedPublicKey::from_text(text.as_bytes())
        .expect("a kpub")
        .1
}

fn text(key: &ExtendedPublicKey, prefix: Prefix) -> String {
    let mut out = [0u8; 128];
    let n = key.to_text(prefix, &mut out).expect("text");
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// The Go wallet's five keys, in upstream's order, which is not sorted.
fn go_keys() -> Vec<ExtendedPublicKey> {
    MULTISIG_45.kpubs.iter().map(|t| key(t)).collect()
}

fn line(m: usize, texts: &[String]) -> String {
    format!("multi_hd45({m},{})", texts.join(","))
}

fn address<const N: usize>(g: &Group<N>, cosigner: u32, chain: u32, index: u32) -> String {
    let mut out = [0u8; 128];
    let n = g
        .address(Network::Mainnet, cosigner, chain, index, &mut out)
        .expect("address");
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// The Go wallet's 2-of-5 address, the boot self-test's vector, comes out of
/// a group made by [`Group::new`] and by a descriptor.
#[test]
fn the_go_wallets_address_comes_out_of_a_group() {
    let v = MULTISIG_45;
    let made = Group::<5>::new(v.required, &go_keys()).expect("group");
    assert_eq!(address(&made, v.cosigner, v.chain, v.index), v.address);

    let texts: Vec<String> = v.kpubs.iter().map(|t| t.to_string()).collect();
    let read = Group::<5>::from_descriptor(&line(v.required, &texts)).expect("descriptor");
    assert_eq!(read, made);
}

/// The order the keys are given in does not matter: the group sorts them.
#[test]
fn the_order_given_does_not_matter() {
    let keys = go_keys();
    let mut reversed = keys.clone();
    reversed.reverse();
    let a = Group::<5>::new(2, &keys).unwrap();
    let b = Group::<5>::new(2, &reversed).unwrap();
    assert_eq!(a, b);
    assert_eq!(address(&a, 0, 1, 7), address(&b, 0, 1, 7));
}

/// A group's descriptor, kpubs in cosigner order, reads back as the group.
#[test]
fn a_group_round_trips_through_its_descriptor() {
    let g = Group::<5>::new(3, &go_keys()).unwrap();
    let mut out = vec![0u8; descriptor::max_len(5)];
    let n = g.write_descriptor(&mut out).unwrap();
    let written = core::str::from_utf8(&out[..n]).unwrap();
    assert!(written.starts_with("multi_hd45(3,kpub"));
    assert_eq!(Group::<5>::from_descriptor(written), Ok(g));
}

/// A position is upstream's cosigner index, matched on the whole key: the
/// same public key under another parent is not found.
#[test]
fn a_position_is_the_sorted_place_of_the_whole_key() {
    let g = Group::<5>::new(2, &go_keys()).unwrap();
    for (i, k) in g.keys().iter().enumerate() {
        assert_eq!(g.position(k), Some(i));
    }
    let mut other = g.keys()[0];
    other.parent_fingerprint[0] ^= 1;
    assert_eq!(g.position(&other), None);
}

/// A group refuses a key that is not a mainnet kpub, a key twice, more keys
/// than it holds, a threshold of zero or above the keys, no keys, and a
/// hardened step.
#[test]
fn what_a_group_refuses() {
    let keys = go_keys();
    let texts: Vec<String> = keys.iter().map(|k| text(k, Prefix::Kpub)).collect();
    let with = |i: usize, t: String| {
        let mut v = texts[..3].to_vec();
        v[i] = t;
        line(2, &v)
    };

    // A testnet key, a key of another scheme, a checksum that disagrees.
    let ktub = with(0, text(&keys[0], Prefix::Ktub));
    let xpub = with(0, "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8".into());
    let mut bent = texts[0].clone().into_bytes();
    bent[60] = if bent[60] == b'z' { b'y' } else { b'z' };
    let bent = with(0, String::from_utf8(bent).unwrap());
    for d in [ktub, xpub, bent] {
        assert!(
            matches!(
                Group::<5>::from_descriptor(&d),
                Err(GroupError::NotAKpub { .. })
            ),
            "{d}"
        );
    }

    // One key twice: the descriptor refuses the same text, the group another
    // text of the same key.
    assert_eq!(
        Group::<5>::from_descriptor(&with(1, texts[0].clone())),
        Err(GroupError::Descriptor(DescriptorError::DuplicateKey {
            index: 1
        }))
    );
    let mut twin = keys[0];
    twin.parent_fingerprint[0] ^= 1;
    assert!(matches!(
        Group::<5>::from_descriptor(&with(1, text(&twin, Prefix::Kpub))),
        Err(GroupError::RepeatedKey { .. })
    ));
    assert!(matches!(
        Group::<5>::new(2, &[keys[0], twin, keys[1]]),
        Err(GroupError::RepeatedKey { .. })
    ));

    // A sixth key for a holder of five.
    let mut six = keys.clone();
    six.push(keys[0].derive_child(ChildNumber(9)).unwrap());
    assert_eq!(
        Group::<5>::new(2, &six),
        Err(GroupError::TooManyKeys { found: 6, limit: 5 })
    );
    let six_texts: Vec<String> = six.iter().map(|k| text(k, Prefix::Kpub)).collect();
    assert!(matches!(
        Group::<5>::from_descriptor(&line(2, &six_texts)),
        Err(GroupError::Descriptor(DescriptorError::TooManyKeys { .. }))
    ));
    assert!(Group::<6>::new(2, &six).is_ok(), "a holder of six");

    // Thresholds.
    assert_eq!(Group::<5>::new(0, &keys), Err(GroupError::NoThreshold));
    assert_eq!(
        Group::<5>::new(6, &keys),
        Err(GroupError::Multisig(MultisigError::ThresholdAboveKeys {
            m: 6,
            n: 5
        }))
    );
    assert_eq!(
        Group::<5>::new(1, &[]),
        Err(GroupError::Multisig(MultisigError::NoKeys))
    );

    // A hardened step has no public derivation.
    let g = Group::<5>::new(2, &keys).unwrap();
    let mut out = [0u8; 128];
    assert_eq!(
        g.address(Network::Mainnet, 0x8000_0000, 0, 0, &mut out),
        Err(GroupError::Multisig(MultisigError::Derivation(
            Bip32Error::HardenedFromPublic
        )))
    );
}

/// A redeem script holding one key twice gives the second copy's place;
/// distinct keys, or a script that is not a multisig, give `None`.
#[test]
fn a_redeem_script_that_repeats_a_key_is_found() {
    use kassigner_kaspa::multisig::{redeem_script, redeem_script_len};
    use kassigner_protocol::group::repeated_key;
    let (a, b, c) = ([0xA1; 32], [0xB2; 32], [0xC3; 32]);
    let script = |m: usize, keys: &[[u8; 32]]| {
        let mut out = vec![0u8; redeem_script_len(m, keys.len())];
        let n = redeem_script(m, keys, &mut out).unwrap();
        out.truncate(n);
        out
    };
    for (m, keys, found) in [
        (2, &[a, a][..], Some(1)),
        (2, &[a, b, a][..], Some(2)),
        (2, &[b, c, a, c][..], Some(3)),
        (3, &[a, a, b][..], Some(1)),
        (1, &[a][..], None),
        (2, &[a, b, c][..], None),
    ] {
        assert_eq!(repeated_key(&script(m, keys)), found, "{m} of {keys:02x?}");
    }
    // A key pushed twice in a script that is not a multisig.
    let mut not_multisig = vec![0x20];
    not_multisig.extend_from_slice(&a);
    not_multisig.push(0x20);
    not_multisig.extend_from_slice(&a);
    not_multisig.push(0xac);
    assert_eq!(repeated_key(&not_multisig), None);
}

/// A key's depth is not checked, as upstream does not: a key one level below
/// an account still makes a group.
#[test]
fn a_keys_depth_is_not_checked() {
    let keys = go_keys();
    let deeper = keys[0].derive_child(ChildNumber(0)).unwrap();
    assert_eq!(deeper.depth, keys[0].depth + 1);
    assert!(Group::<5>::new(2, &[deeper, keys[1], keys[2]]).is_ok());
}

/// Keys derived by [`kassigner_kaspa::multisig::address_keys`], then
/// [`Group::address_of_keys`], give what [`Group::address`] gives, the Go
/// wallet's address among them. Keys past the group's count are not read.
#[test]
fn an_address_of_derived_keys_is_the_groups() {
    use kassigner_kaspa::multisig::address_keys;
    let v = MULTISIG_45;
    for (required, total) in [(v.required, 5), (2, 3), (1, 1)] {
        let g = Group::<5>::new(required, &go_keys()[..total]).unwrap();
        for (cosigner, chain, index) in [
            (v.cosigner, v.chain, v.index),
            (0, 0, 0),
            (total as u32 - 1, 1, 7),
            (0, 1, 99_999),
        ] {
            let mut keys = [[0xa5u8; 32]; 5];
            assert_eq!(
                address_keys(g.keys(), cosigner, chain, index, &mut keys),
                Ok(total)
            );
            let mut out = [0u8; 128];
            let n = g
                .address_of_keys(Network::Mainnet, &keys, &mut out)
                .expect("address");
            let made = core::str::from_utf8(&out[..n]).unwrap();
            assert_eq!(made, address(&g, cosigner, chain, index));
            if total == 5 && (cosigner, chain, index) == (v.cosigner, v.chain, v.index) {
                assert_eq!(made, v.address);
            }
        }
    }
    let g = Group::<5>::new(1, &go_keys()[..1]).unwrap();
    assert_eq!(
        g.address_of_keys(Network::Mainnet, &[[1u8; 32]; 5], &mut [0u8; 10]),
        Err(GroupError::BufferTooSmall)
    );
}
