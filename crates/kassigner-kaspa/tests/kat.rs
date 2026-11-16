// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The boot known answers, run here too: what gates a boot gates a commit.
//! `upstream.rs` computes every expectation with rusty-kaspa; this asserts
//! the subset a device can afford passes and ran at all.

use kassigner_kaspa::kat;

#[test]
fn address_known_answer() {
    let (passed, total) = kat::address();
    assert!(total > 0, "no vectors ran");
    assert_eq!(passed, total, "address boot vector: {passed}/{total}");
}

/// The 45' vector from the Go implementation, via rusty-kaspa's import test:
/// the one multisig answer here that is not ours.
#[test]
fn multisig_45_known_answer() {
    let (passed, total) = kat::multisig_45();
    assert!(total > 0, "no vectors ran");
    assert_eq!(passed, total, "45' multisig boot vector: {passed}/{total}");
}

/// The frozen sighash answers; `upstream.rs` writes them from rusty-kaspa.
#[test]
fn sighash_known_answer() {
    let (passed, total) = kat::sighash();
    assert!(total > 0, "no vectors ran");
    assert_eq!(passed, total, "sighash boot vectors: {passed}/{total}");
    // The boot's Schnorr digest is the one checked against rusty-kaspa's.
    for (case, input) in kat::SIGHASH_BOOT {
        assert_eq!(
            kat::sighash_schnorr(case, input),
            kat::sighash_digests(case, input).map(|d| d.0)
        );
    }
}

/// A table entry outside the six hash types gives no hash, failing the boot
/// check; every allowed one hashes.
#[test]
fn a_hash_type_outside_the_six_gives_no_hash() {
    for byte in [0x00, 0x03, 0x05, 0x07, 0x40, 0x80, 0x83, 0xFF] {
        let case = kat::SighashCase {
            hash_type: byte,
            ..kat::SighashCase::new(0, 2, 2)
        };
        assert_eq!(kat::sighash_digests(case, 1), None, "{byte:#04x}");
    }
    for byte in [0x01, 0x02, 0x04, 0x81, 0x82, 0x84] {
        let case = kat::SighashCase {
            hash_type: byte,
            ..kat::SighashCase::new(0, 2, 2)
        };
        assert!(kat::sighash_digests(case, 1).is_some(), "{byte:#04x}");
    }
}

/// Every input spends a script of its own, one at a version other than 0,
/// and the boot set signs inputs past the first: a hash using the first
/// input's script for all would fail.
#[test]
fn every_input_spends_a_script_of_its_own() {
    let spks = kat::SIGHASH_INPUT_SPKS;
    for (i, a) in spks.iter().enumerate() {
        for b in &spks[..i] {
            assert_ne!(a.1, b.1, "input {i} repeats a script");
            assert_ne!(a.1.len(), b.1.len(), "input {i} repeats a length");
        }
        assert_ne!(
            a.1,
            &kat::SIGHASH_SPK[..],
            "input {i} spends the outputs' script"
        );
    }
    assert!(spks.iter().any(|(version, _)| *version != 0));
    assert!(kat::SIGHASH_BOOT.iter().any(|(_, input)| *input > 0));
}

#[test]
fn the_whole_set_passes() {
    let (passed, total) = kat::all();
    assert_eq!(
        total, 22,
        "the boot set changed size; update the device's budget"
    );
    assert_eq!(passed, total, "boot set: {passed}/{total}");
}
