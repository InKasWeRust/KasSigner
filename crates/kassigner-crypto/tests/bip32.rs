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

//! BIP32 private derivation, checked two ways: against the specification's
//! published vectors, which prove the algorithm, and against `kaspa-bip32`
//! at the pinned commit, the implementation a unit must agree with. Upstream
//! alone would agree just as well if both were wrong the same way.

use kassigner_crypto::bip32::{Bip32Error, ExtendedPrivateKey, PRIVATE_KEY_SIZE};
use kassigner_crypto::bip39::{from_entropy, scratch_for, to_seed, ENTROPY_12};
use kassigner_kaspa::bip32_public::{ChildNumber, HARDENED_OFFSET};

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::{hex, unhex};

/// BIP32 test vector 1: seed `000102...0f`.
const VECTOR_1_SEED: &str = "000102030405060708090a0b0c0d0e0f";

/// BIP32's first test vector's master key, which everything below builds
/// on.
#[test]
fn the_master_key_matches_the_specification() {
    let seed = unhex(VECTOR_1_SEED);
    let m = ExtendedPrivateKey::from_seed(&seed).expect("master");

    assert_eq!(
        hex(m.private_key()),
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    );
    assert_eq!(
        hex(m.chain_code()),
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    );
    assert_eq!(m.depth(), 0);
    assert_eq!(
        hex(&m.public_key()),
        "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    );

    // The boot check's constants are this key, whole.
    use kassigner_crypto::kat;
    assert_eq!(*m.private_key(), kat::BIP32_MASTER_KEY);
    assert_eq!(*m.chain_code(), kat::BIP32_MASTER_CHAIN_CODE);
    assert_eq!(m.public_key(), kat::BIP32_MASTER_PUBLIC_KEY);
}

/// The vector's chain `m/0'/1/2'/2/1000000000`, step by step. It alternates
/// hardened and normal, so a mix-up between the two branches shows.
#[test]
fn the_derivation_chain_matches_the_specification() {
    let seed = unhex(VECTOR_1_SEED);
    let m = ExtendedPrivateKey::from_seed(&seed).expect("master");

    // (path element, expected private key)
    let steps: &[(u32, &str)] = &[
        (
            HARDENED_OFFSET,
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
        ),
        (
            1,
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
        ),
        (
            2 + HARDENED_OFFSET,
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
        ),
        (
            2,
            "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
        ),
        (
            1_000_000_000,
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
        ),
    ];

    let mut node = m;
    for (i, (child, want)) in steps.iter().enumerate() {
        node = node.derive_child(ChildNumber(*child)).expect("derive");
        assert_eq!(hex(node.private_key()), *want, "step {i}, child {child:#x}");
        assert_eq!(node.depth(), i as u8 + 1);
    }
}

/// A whole path in one call matches the same path stepped through.
#[test]
fn derive_path_matches_stepping() {
    let seed = unhex(VECTOR_1_SEED);
    let m = ExtendedPrivateKey::from_seed(&seed).expect("master");

    let path = [
        ChildNumber(HARDENED_OFFSET),
        ChildNumber(1),
        ChildNumber(2 + HARDENED_OFFSET),
    ];
    let by_path = m.derive_path(&path).expect("path");

    let mut stepped = m.derive_child(path[0]).unwrap();
    stepped = stepped.derive_child(path[1]).unwrap();
    stepped = stepped.derive_child(path[2]).unwrap();

    assert_eq!(by_path.private_key(), stepped.private_key());
    assert_eq!(by_path.chain_code(), stepped.chain_code());
    assert_eq!(by_path.depth(), 3);
}

/// Derivation agrees with upstream, key and chain code, at every level of a
/// five-level path.
#[test]
fn derivation_agrees_with_upstream() {
    use kaspa_bip32::{ChildNumber as UpChild, ExtendedPrivateKey as UpXPrv, SecretKey};

    // 64 bytes, a BIP39 seed's length, and one of the three upstream takes
    // (`a_bad_seed_length_is_refused`).
    let seed = unhex(&format!(
        "{VECTOR_1_SEED}{VECTOR_1_SEED}{VECTOR_1_SEED}{VECTOR_1_SEED}"
    ));
    assert_eq!(seed.len(), 64);

    let ours = ExtendedPrivateKey::from_seed(&seed).expect("master");
    let theirs = UpXPrv::<SecretKey>::new(&seed).expect("upstream master");

    assert_eq!(
        hex(ours.private_key()),
        hex(&theirs.private_key().secret_bytes()),
        "master key"
    );
    assert_eq!(
        hex(ours.chain_code()),
        hex(&theirs.attrs().chain_code),
        "master chain code"
    );

    // The account's three hardened levels, then two normal ones.
    let path = [
        HARDENED_OFFSET + 44,
        HARDENED_OFFSET + 111_111,
        HARDENED_OFFSET,
        0,
        7,
    ];
    let mut o = ours;
    let mut t = theirs;
    for (i, c) in path.iter().enumerate() {
        o = o.derive_child(ChildNumber(*c)).expect("ours");
        t = t.derive_child(UpChild(*c)).expect("theirs");

        assert_eq!(
            hex(o.private_key()),
            hex(&t.private_key().secret_bytes()),
            "key at level {}, child {c:#x}",
            i + 1
        );
        assert_eq!(
            hex(o.chain_code()),
            hex(&t.attrs().chain_code),
            "chain code at level {}",
            i + 1
        );
    }
}

/// `kassigner-kaspa`'s public half derives the same normal children: a
/// companion holding only a `kpub` must watch the addresses a unit derives
/// from the seed.
#[test]
fn the_public_half_reaches_the_same_normal_children() {
    let seed = unhex(VECTOR_1_SEED);
    let account = ExtendedPrivateKey::from_seed(&seed)
        .expect("master")
        .derive_path(&[
            ChildNumber(HARDENED_OFFSET + 44),
            ChildNumber(HARDENED_OFFSET + 111_111),
            ChildNumber(HARDENED_OFFSET),
        ])
        .expect("account");

    let xpub = account.to_extended_public_key();
    assert_eq!(xpub.public_key, account.public_key());
    assert_eq!(&xpub.chain_code, account.chain_code());

    // Both sides walk the same normal path.
    for chain in [0u32, 1] {
        for index in [0u32, 1, 5, 1000] {
            let priv_child = account
                .derive_path(&[ChildNumber(chain), ChildNumber(index)])
                .expect("private");
            let pub_child = xpub
                .derive_child(ChildNumber(chain))
                .and_then(|c| c.derive_child(ChildNumber(index)))
                .expect("public");

            assert_eq!(
                priv_child.public_key(),
                pub_child.public_key,
                "chain {chain}, index {index}"
            );
        }
    }
}

/// A seed outside BIP32's 16 to 64 bytes is refused. Upstream takes only 16,
/// 32 or 64; this follows the specification, so a 20-byte seed works here
/// and not there. A BIP39 seed is 64 bytes.
#[test]
fn a_bad_seed_length_is_refused() {
    assert_eq!(
        ExtendedPrivateKey::from_seed(&[0u8; 15]).err(),
        Some(Bip32Error::BadSeedLength(15))
    );
    assert_eq!(
        ExtendedPrivateKey::from_seed(&[0u8; 65]).err(),
        Some(Bip32Error::BadSeedLength(65))
    );

    // The three upstream also takes.
    for n in [16usize, 32, 64] {
        assert!(
            ExtendedPrivateKey::from_seed(&vec![0u8; n]).is_ok(),
            "{n} bytes"
        );
    }
    // And one it does not, which the specification allows.
    assert!(
        ExtendedPrivateKey::from_seed(&[0u8; 20]).is_ok(),
        "BIP32 permits 20 bytes"
    );
}

/// A BIP39 seed feeds straight into a master key: words in, master key out.
#[test]
fn a_bip39_seed_produces_a_master_key() {
    let m = from_entropy(&[0x42u8; ENTROPY_12]).expect("mnemonic");
    let mut scratch = vec![0u8; scratch_for(0)];
    let seed = to_seed(&m, "", &mut scratch).expect("seed");

    let master = ExtendedPrivateKey::from_seed(seed.as_bytes()).expect("master");
    assert_eq!(master.depth(), 0);
    assert_eq!(master.private_key().len(), PRIVATE_KEY_SIZE);

    // A passphrase gives a different master key.
    let mut scratch2 = vec![0u8; scratch_for(4)];
    let other = to_seed(&m, "salt", &mut scratch2).expect("seed");
    let other_master = ExtendedPrivateKey::from_seed(other.as_bytes()).expect("master");
    assert_ne!(master.private_key(), other_master.private_key());
}

/// Debug never prints the key or the chain code: with the public key and one
/// normal child's private key, the chain code gives the parent's key.
#[test]
fn debug_is_redacted() {
    let seed = unhex(VECTOR_1_SEED);
    let m = ExtendedPrivateKey::from_seed(&seed).expect("master");
    let shown = format!("{m:?}");

    assert!(!shown.contains(&hex(m.private_key())), "the key leaked");
    assert!(
        !shown.contains(&hex(m.chain_code())),
        "the chain code leaked"
    );
    assert!(shown.contains("redacted"));
    assert!(shown.contains("depth 0"), "depth is safe and useful");
}

/// A 256th level is refused, not folded onto the 255th: depth is one byte,
/// and a child at its parent's depth could not be told from it in an
/// exported key.
#[test]
fn a_child_past_the_last_depth_is_refused() {
    let seed = unhex(VECTOR_1_SEED);
    let m = ExtendedPrivateKey::from_seed(&seed).expect("master");

    // A real key placed at the last depth the field holds.
    let deep = ExtendedPrivateKey::from_parts(
        m.private_key(),
        m.chain_code(),
        255,
        [0u8; 4],
        ChildNumber(0),
    )
    .expect("a key at depth 255");
    assert_eq!(deep.depth(), 255);

    assert_eq!(
        deep.derive_child(ChildNumber(HARDENED_OFFSET)).err(),
        Some(Bip32Error::DepthOverflow)
    );
    assert_eq!(
        deep.derive_child(ChildNumber(0)).err(),
        Some(Bip32Error::DepthOverflow),
        "normal derivation too, not just hardened"
    );

    // One level below it still works, and lands on the last depth.
    let almost = ExtendedPrivateKey::from_parts(
        m.private_key(),
        m.chain_code(),
        254,
        [0u8; 4],
        ChildNumber(0),
    )
    .expect("a key at depth 254");
    let last = almost
        .derive_child(ChildNumber(HARDENED_OFFSET))
        .expect("the last level is reachable");
    assert_eq!(last.depth(), 255);
}

/// The text form of an extended private key is the one upstream writes, for
/// both prefixes, and reads back to the same key.
#[test]
fn the_xprv_text_form_is_upstreams() {
    use kaspa_bip32::{ExtendedPrivateKey as UpXPrv, Prefix as UpPrefix, SecretKey};
    use kassigner_crypto::bip32::{PrivatePrefix, XPRV_TEXT_MAX};

    let seed = [7u8; 64];
    let ours = ExtendedPrivateKey::from_seed(&seed)
        .unwrap()
        .derive_child(ChildNumber(HARDENED_OFFSET + 44))
        .unwrap()
        .derive_child(ChildNumber(3))
        .unwrap();
    let theirs = UpXPrv::<SecretKey>::new(seed)
        .unwrap()
        .derive_child(kaspa_bip32::ChildNumber(HARDENED_OFFSET + 44))
        .unwrap()
        .derive_child(kaspa_bip32::ChildNumber(3))
        .unwrap();
    for (ours_p, theirs_p) in [
        (PrivatePrefix::Kprv, UpPrefix::KPRV),
        (PrivatePrefix::Ktrv, UpPrefix::KTRV),
    ] {
        let mut text = [0u8; XPRV_TEXT_MAX];
        let n = ours.to_text(ours_p, &mut text).unwrap();
        let up = theirs.to_string(theirs_p);
        assert_eq!(core::str::from_utf8(&text[..n]).unwrap(), up.as_str());

        let (p, back) = ExtendedPrivateKey::from_text(&text[..n]).unwrap();
        assert_eq!(p, ours_p);
        assert_eq!(back.private_key(), ours.private_key());
        assert_eq!(back.chain_code(), ours.chain_code());
        assert_eq!(back.depth(), ours.depth());
        assert_eq!(back.child_number(), ours.child_number());
        assert_eq!(back.parent_fingerprint(), ours.parent_fingerprint());
    }

    // A public key's text, and damaged text, are refused.
    let kpub = theirs.public_key().to_string(Some(UpPrefix::KPUB));
    assert!(ExtendedPrivateKey::from_text(kpub.as_bytes()).is_err());
    let mut text = [0u8; XPRV_TEXT_MAX];
    let n = ours.to_text(PrivatePrefix::Kprv, &mut text).unwrap();
    text[n / 2] = if text[n / 2] == b'1' { b'2' } else { b'1' };
    assert!(ExtendedPrivateKey::from_text(&text[..n]).is_err());
}

/// A master key names no parent and no child number: BIP32's own invalid
/// vectors refuse a key at depth 0 with either.
#[test]
fn a_master_key_names_no_parent() {
    let key = [7u8; PRIVATE_KEY_SIZE];
    let cc = [9u8; 32];
    assert!(ExtendedPrivateKey::from_parts(&key, &cc, 0, [0; 4], ChildNumber(0)).is_ok());
    assert_eq!(
        ExtendedPrivateKey::from_parts(&key, &cc, 0, [1, 2, 3, 4], ChildNumber(0)).err(),
        Some(Bip32Error::NotAMaster)
    );
    assert_eq!(
        ExtendedPrivateKey::from_parts(&key, &cc, 0, [0; 4], ChildNumber(1)).err(),
        Some(Bip32Error::NotAMaster)
    );
    assert_eq!(
        ExtendedPrivateKey::from_parts(&key, &cc, 0, [0; 4], ChildNumber(HARDENED_OFFSET)).err(),
        Some(Bip32Error::NotAMaster)
    );
    // Below the master, both are what a key names.
    assert!(ExtendedPrivateKey::from_parts(
        &key,
        &cc,
        1,
        [1, 2, 3, 4],
        ChildNumber(HARDENED_OFFSET)
    )
    .is_ok());
}
