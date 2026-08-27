// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// reference_vectors_tests.rs — agreement with rusty-kaspa 2.0.1 on values
// it publishes, checked against fixtures rather than against a linked
// dependency.
//
// A linked differential suite is not available to us: rusty-kaspa 2.0.1 is
// edition 2024 and needs Rust 1.91, so it cannot be a dev-dependency of a
// crate the firmware links. Fixtures cost nothing, need no network and run
// inside the Docker reproducible build like every other test here.
//
// Every constant below is copied verbatim from the rusty-kaspa 2.0.1 tree,
// with its file and line, so any of them can be re-derived by opening that
// file. Where their vector covers something our code cannot express (a
// non-mainnet prefix, which our encoder hardcodes), it is used as a
// negative: the value must be rejected, not silently accepted.

extern crate std;
use crate::wallet::address::{self, AddressType, MAX_ADDR_LEN};
use crate::wallet::xpub;

fn encoded(payload: &[u8], ty: AddressType) -> alloc::string::String {
    let mut buf = [0u8; MAX_ADDR_LEN];
    let n = address::encode_address(payload, ty, &mut buf);
    alloc::string::String::from(core::str::from_utf8(&buf[..n]).expect("utf8"))
}

/// The two mainnet rows of their address table
/// (`crypto/addresses/src/lib.rs:492-493`). Our encoder hardcodes the
/// mainnet prefix and its checksum salt, so these are the rows it can
/// reproduce; the rest of their table is used as negatives below.
#[test]
fn mainnet_p2pk_matches_reference() {
    // (Address::new(Prefix::Mainnet, Version::PubKey, &[0u8; 32]), ...)
    assert_eq!(
        encoded(&[0u8; 32], AddressType::P2PK),
        "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e",
    );

    // (Address::new(Prefix::Mainnet, Version::PubKey, b"\x5f\xff..."), ...)
    const KEY: [u8; 32] = [
        0x5f, 0xff, 0x3c, 0x4d, 0xa1, 0x8f, 0x45, 0xad, 0xcd, 0xd4, 0x99, 0xe4, 0x46, 0x11, 0xe9, 0xff,
        0xf1, 0x48, 0xba, 0x69, 0xdb, 0x3c, 0x4e, 0xa2, 0xdd, 0xd9, 0x55, 0xfc, 0x46, 0xa5, 0x95, 0x22,
    ];
    assert_eq!(
        encoded(&KEY, AddressType::P2PK),
        "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj",
    );

    // What we encode, we must accept.
    let mut buf = [0u8; MAX_ADDR_LEN];
    let n = address::encode_address(&KEY, AddressType::P2PK, &mut buf);
    assert!(address::validate_kaspa_address(&buf[..n]));
}

/// A mainnet P2SH address produced by the Go implementation, via
/// rusty-kaspa's golang multisig import test
/// (`wallet/core/src/compat/gen1.rs:134`, commented "taken from golang
/// impl"): a 2-of-5 m/45' multisig receive address. Our validator must
/// accept it, which checks the P2SH branch of the checksum and length
/// rules against a third implementation.
///
/// This is the address the m/45' implementation was built against, and the
/// boot KAT already pins it: `transaction::test_multisig_45_vector` derives
/// the five kpubs, assembles the 2-of-5 redeem script and checks its blake2b
/// hash against `EXPECT_SCRIPT_HASH`. That constant is a bare 32-byte array
/// with no note of where it came from, so the connection was invisible to a
/// reader. The test below closes it: encoding that same hash as a P2SH
/// address reproduces the Go implementation's string exactly.
///
/// So the chain kpub parse -> `m/45'/111111'/0'/<cosigner>/0/0` derivation
/// (`wallet/keys/src/derivation/gen1/hd.rs:197`) -> redeem script -> P2SH
/// hash -> address agrees end to end with the Go implementation, and now
/// says so in a place someone auditing the address code will find.
#[test]
fn golang_multisig_p2sh_address_validates() {
    const GOLANG_P2SH: &[u8] = b"kaspa:pqvgkyjeuxmd8k70egrrzpdz5rqj0acmr6y94mwsltxfp6nc50742295c3998";
    assert!(address::validate_kaspa_address(GOLANG_P2SH));

    // The redeem-script hash the m/45' KAT produces from the five kpubs
    // (`wallet/transaction.rs`, `test_multisig_45_vector::EXPECT_SCRIPT_HASH`).
    const MS45_SCRIPT_HASH: [u8; 32] = [
        0x18, 0x8b, 0x12, 0x59, 0xe1, 0xb6, 0xd3, 0xdb, 0xcf, 0xca, 0x06, 0x31, 0x05, 0xa2, 0xa0, 0xc1,
        0x27, 0xf7, 0x1b, 0x1e, 0x88, 0x5a, 0xed, 0xd0, 0xfa, 0xcc, 0x90, 0xea, 0x78, 0xa3, 0xfd, 0x55,
    ];
    assert_eq!(
        encoded(&MS45_SCRIPT_HASH, AddressType::P2SH),
        core::str::from_utf8(GOLANG_P2SH).unwrap(),
        "the m/45' KAT hash must encode to the Go implementation's address",
    );

    // And the KAT itself still produces that hash from the kpubs.
    assert!(crate::wallet::transaction::test_multisig_45_vector());

    // A single character changed anywhere must fail the checksum.
    let mut broken = alloc::vec::Vec::from(GOLANG_P2SH);
    let last = broken.len() - 1;
    broken[last] = if broken[last] == b'8' { b'9' } else { b'8' };
    assert!(!address::validate_kaspa_address(&broken));
}

/// The non-mainnet rows of their table, and their malformed neighbours.
/// The device speaks mainnet only, so every one of these must be refused
/// rather than accepted with the wrong network or a bad checksum.
#[test]
fn foreign_and_malformed_addresses_are_refused() {
    const REFUSED: [&[u8]; 8] = [
        // crypto/addresses/src/lib.rs:489-491, testnet rows.
        b"kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhqrxplya",
        b"kaspatest:qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhe837j2d",
        b"kaspatest:qxaqrlzlf6wes72en3568khahq66wf27tuhfxn5nytkd8tcep2c0vrse6gdmpks",
        // :477-478, the short `a:` prefix rows.
        b"a:qqeq69uvrh",
        b"a:pq99546ray",
        // :485, a `b:` row.
        b"b:ppskycc8txxxn2w",
        // Mainnet prefix, mainnet-shaped, checksum from a different string.
        b"kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhqrxplya",
        // Right length, no prefix separator.
        b"kaspaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e",
    ];
    for a in REFUSED {
        assert!(
            !address::validate_kaspa_address(a),
            "must refuse {}",
            core::str::from_utf8(a).unwrap_or("?"),
        );
    }
}

/// Every character position of a good address, mutated one at a time, must
/// fail. This is the property the checksum exists for, and it is what
/// protects a user who mistypes or misreads one character of a scanned
/// address on the review screen.
#[test]
fn single_character_corruption_always_fails() {
    const GOOD: &[u8] = b"kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj";
    assert!(address::validate_kaspa_address(GOOD));
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut checked = 0u32;
    for i in 6..GOOD.len() {
        for &c in CHARSET {
            if c == GOOD[i] {
                continue;
            }
            let mut m = alloc::vec::Vec::from(GOOD);
            m[i] = c;
            assert!(!address::validate_kaspa_address(&m), "corruption at {i} accepted");
            checked += 1;
        }
    }
    assert!(checked > 1_800, "only {checked} mutations tried");
}

// ─── Extended keys ──────────────────────────────────────────────────────
//
// Kaspa's extended-key version bytes are its own: KPRV 0x038f2ef4 and KPUB
// 0x038f332e (`wallet/bip32/src/prefix.rs:31,34`), where Bitcoin uses
// 0x0488ade4 and 0x0488b21e. The strings below are lifted from the
// rusty-kaspa tree; where a value is asserted here that they do not assert
// themselves, it comes from an independent base58check decode of their
// string rather than from our own code, and the comment says so.

/// BIP32 test vector 1, as rusty-kaspa carries it
/// (`wallet/bip32/src/xkey.rs:122,140`). Both are Bitcoin-versioned, and the
/// device must refuse them: an `xprv` is a valid extended key for a
/// different chain, and importing one as if it were a Kaspa key would put
/// funds on addresses the user cannot see from any Kaspa wallet. Every
/// entry point has to refuse, not just the one a given screen happens to
/// call.
#[test]
fn bitcoin_versioned_keys_are_refused() {
    const BTC_XPRV: &[u8] = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const BTC_XPUB: &[u8] = b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    // Both carry a valid base58check checksum, so only the version bytes
    // stand between them and being accepted.
    assert!(xpub::import_xprv(BTC_XPRV).is_err(), "Bitcoin xprv must not import");
    assert!(xpub::import_xprv(BTC_XPUB).is_err());
    assert!(xpub::import_kpub(BTC_XPUB).is_err(), "Bitcoin xpub must not import");
    assert!(xpub::import_kpub(BTC_XPRV).is_err());
    assert!(xpub::parse_kpub_parts(BTC_XPUB).is_none());
    assert!(xpub::import_kpub_any(BTC_XPUB).is_err());
    assert!(xpub::parse_kpub_parts_any(BTC_XPUB).is_none());
}

/// A Kaspa-versioned master key from their tree
/// (`wallet/bip32/src/xkey.rs:122`, the commented-out `kprv` line; it is a
/// different key from the `xprv` asserted on the next line, not the same one
/// re-encoded). It must import, which is the positive half of the check
/// above: the refusal is about the version bytes, not about rejecting
/// everything unfamiliar.
#[test]
fn kaspa_versioned_master_key_imports() {
    const KAS_KPRV: &[u8] = b"kprv5y2qurMHCsXYrNfU3GCihuwG3vMqFji7PZXajMEqyBkNh9UZUJgoHYBLTKu1eM4MvUtomcXPQ3Sw9HZ5ebbM4byoUciHo1zrPJBQfqpLorQ";
    assert!(xpub::import_xprv(KAS_KPRV).is_ok(), "Kaspa kprv must import");

    // One character changed: the base58check checksum must catch it.
    let mut broken = alloc::vec::Vec::from(KAS_KPRV);
    broken[10] = if broken[10] == b'M' { b'N' } else { b'M' };
    assert!(xpub::import_xprv(&broken).is_err());
}

/// Two of the five account-level kpubs from the golang multisig wallet
/// (`wallet/core/src/compat/gen1.rs:118-119`), decoded field by field.
///
/// The expected bytes are NOT from an assertion rusty-kaspa publishes; they
/// come from an independent base58check decode of those two strings, done
/// outside this codebase. What the test establishes is that our parser
/// splits a real Kaspa kpub into the same fields any conformant decoder
/// does, and that the depth is 3, which is what `m/45'/111111'/<account>'`
/// produces and what the m/45' path relies on.
#[test]
fn kpub_fields_decode_as_expected() {
    struct Case {
        s: &'static [u8],
        fp: [u8; 4],
        child: [u8; 4],
        chain: [u8; 32],
        pubkey: [u8; 33],
    }
    let cases = [
        Case {
            s: b"kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK",
            fp: [0x40, 0x5a, 0xb6, 0x83],
            child: [0x80, 0x00, 0x00, 0x00],
            chain: [
                0xf0, 0x45, 0x3f, 0x08, 0x94, 0xcc, 0x8c, 0x84, 0xeb, 0xf6, 0xe6, 0x20, 0x8e, 0x0c, 0x79, 0x16,
                0xe9, 0xdd, 0xbd, 0x14, 0x91, 0x9f, 0x9b, 0xbb, 0x92, 0xb0, 0x69, 0x0b, 0x4e, 0x35, 0x33, 0x92,
            ],
            pubkey: [
                0x02, 0x03, 0x27, 0xc7, 0x13, 0x69, 0x72, 0x88, 0x3e, 0xab, 0x5a, 0x77, 0x22, 0xec, 0x3d, 0x43,
                0x02, 0xf8, 0x88, 0x80, 0x4e, 0xcc, 0xe6, 0x16, 0x58, 0xae, 0x96, 0x2a, 0x2c, 0x56, 0xbb, 0x75,
                0x71,
            ],
        },
        Case {
            s: b"kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
            fp: [0xa7, 0x45, 0x72, 0x70],
            child: [0x80, 0x00, 0x00, 0x00],
            chain: [
                0x29, 0x08, 0xbe, 0x01, 0xd7, 0x57, 0x35, 0x94, 0x4f, 0x29, 0xbe, 0xfb, 0xdb, 0xcd, 0x17, 0x3a,
                0xb0, 0x0d, 0xf2, 0xd4, 0x4c, 0x6d, 0x5a, 0xb5, 0x1a, 0x83, 0x94, 0x13, 0xfd, 0xa9, 0x0c, 0xbf,
            ],
            pubkey: [
                0x03, 0x5b, 0x98, 0x6b, 0x58, 0x4d, 0xe2, 0x44, 0xf5, 0xd6, 0xa1, 0x93, 0x91, 0x92, 0xf6, 0x76,
                0xa9, 0xf2, 0x99, 0x2a, 0x63, 0xb0, 0xf4, 0x3c, 0xdc, 0x45, 0x2d, 0xcb, 0x40, 0xd9, 0xdd, 0x70,
                0x81,
            ],
        },
    ];

    for (i, c) in cases.iter().enumerate() {
        let p = xpub::parse_kpub_parts(c.s).unwrap_or_else(|| panic!("kpub {i} must parse"));
        assert_eq!(p.depth, 3, "kpub {i} depth");
        assert_eq!(p.parent_fp, c.fp, "kpub {i} parent fingerprint");
        assert_eq!(p.child_num, c.child, "kpub {i} child number");
        assert_eq!(p.chain_code, c.chain, "kpub {i} chain code");
        assert_eq!(p.pubkey, c.pubkey, "kpub {i} pubkey");
        // Compressed SEC1: the parity byte is the only thing that varies.
        assert!(c.pubkey[0] == 0x02 || c.pubkey[0] == 0x03);
    }
}
