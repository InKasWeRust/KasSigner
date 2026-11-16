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

//! A scanned payload becoming a transaction, then a session: bytes in, a review
//! out, with no camera or screen.

use kassigner_fw::review::Page;
use kassigner_fw::session::{Decision, Session, Stage};
use kassigner_hal::entropy::{self, Entropy};
use kassigner_kaspa::constants::SOMPI_PER_KASPA as KAS;
use kassigner_kaspa::sighash::SIG_HASH_ALL;
use kassigner_protocol::kspt;
use kassigner_protocol::kspt::transaction::{build, fill};
use kassigner_protocol::profile::Profile;

#[path = "../../../testkit/kspt_bytes.rs"]
pub mod kspt_bytes;
use kspt_bytes::payload_bytes;
#[path = "../../../testkit/transaction.rs"]
pub mod transaction;
use transaction::arrays;

const KEY: [u8; 32] = [0x22; 32];

struct Live;

impl Entropy for Live {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), entropy::Error> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        Ok(())
    }
}

/// Pay to a 32-byte public key: a standard form, as a reviewed output must be.
const SPK: [u8; 34] = {
    let mut s = [0x20u8; 34];
    s[33] = 0xac;
    s
};
const P: Profile = Profile::ESP32S3;

/// Bytes to a signature with no hardware: a payload becomes a transaction,
/// reviewed page by page, confirmed and signed.
#[test]
fn a_payload_is_reviewed_and_signed() {
    let bytes = payload_bytes(&SPK, &[100 * KAS], &[(90 * KAS, None)]);
    let k = kspt::parse(&bytes, &P).expect("parse");
    let (mut ins, mut outs) = arrays();
    let (ni, no) = fill(&k, &mut ins, &mut outs).expect("fill");
    let tx = build(&k, &ins[..ni], &outs[..no]);

    let mut s = Session::new(tx).expect("session");
    assert_eq!(s.stage(), Stage::Reviewing);

    // The fee is what the payload implies, not what a caller passed.
    match s.next_page() {
        Some((
            _,
            Page::Summary {
                spending,
                receiving,
                fee,
                ..
            },
        )) => {
            assert_eq!(spending, 100 * KAS);
            assert_eq!(receiving, 90 * KAS);
            assert_eq!(fee, 10 * KAS);
        }
        other => panic!("{other:?}"),
    }

    while let Some((i, _)) = s.next_page() {
        s.page_shown(i).expect("mark");
    }
    s.decide(Decision::Confirm).expect("confirm");

    let sig = s.sign_input(0, &KEY, &mut Live).expect("signature");

    let pk = kassigner_crypto::sign::public_key(&KEY).expect("key");
    let digest = kassigner_kaspa::sighash::schnorr_signature_hash(s.transaction(), 0, SIG_HASH_ALL)
        .expect("an input");
    assert!(kassigner_kaspa::bip340::verify(
        &pk,
        &digest,
        sig.as_bytes()
    ));
}

/// A covenant binding survives the conversion and reaches the review, as level
/// 1 re-exports level 0's binding type.
#[test]
fn a_covenant_binding_reaches_the_review() {
    let bytes = payload_bytes(&SPK, &[50 * KAS], &[(40 * KAS, Some([0xAB; 32]))]);
    let k = kspt::parse(&bytes, &P).expect("parse");

    let (mut ins, mut outs) = arrays();
    let (ni, no) = fill(&k, &mut ins, &mut outs).expect("fill");
    let tx = build(&k, &ins[..ni], &outs[..no]);

    assert_eq!(
        tx.outputs[0].covenant.map(|c| c.covenant_id),
        Some([0xAB; 32])
    );

    // It reaches the review, so a person sees it before confirming. The
    // coin is bound to the covenant the output continues.
    let mut s = Session::with_coins(tx, |_| None, &[Some([0xAB; 32])]).expect("session");
    let mut found = false;
    while let Some((i, page)) = s.next_page() {
        if let Page::Covenant {
            id,
            outputs,
            spent,
            from,
        } = page
        {
            assert_eq!(id, [0xAB; 32]);
            assert_eq!(outputs, 0b1, "output 0 continues it");
            assert_eq!(spent, 1);
            assert_eq!(from, None);
            found = true;
        }
        s.page_shown(i).expect("mark");
    }
    assert!(found, "the binding must be on a page");
}
