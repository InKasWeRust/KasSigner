// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A KSPT becoming a transaction, decided by the payload alone. Carrying one
//! on to a review and a signature is the device's, tested in `kassigner-fw`.

use kassigner_protocol::kspt;
use kassigner_protocol::kspt::transaction::{build, fill, Error};
use kassigner_protocol::profile::Profile;

#[path = "../../../testkit/kspt_bytes.rs"]
pub mod kspt_bytes;
use kspt_bytes::payload_bytes;
#[path = "../../../testkit/transaction.rs"]
pub mod transaction;
use transaction::arrays;

const SPK: [u8; 34] = [0x20u8; 34];
const P: Profile = Profile::ESP32S3;

/// A payload becomes a transaction with the right values.
#[test]
fn a_payload_becomes_a_transaction() {
    let bytes = payload_bytes(&SPK, &[100_000], &[(60_000, None), (35_000, None)]);
    let k = kspt::parse(&bytes, &P).expect("parse");
    assert_eq!(k.num_inputs, 1);
    assert_eq!(k.num_outputs, 2);

    let (mut ins, mut outs) = arrays();
    let (ni, no) = fill(&k, &mut ins, &mut outs).expect("fill");
    assert_eq!((ni, no), (1, 2));

    let tx = build(&k, &ins[..ni], &outs[..no]);
    assert_eq!(tx.version, 1);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.inputs[0].utxo_entry.amount, 100_000);
    assert_eq!(tx.outputs[0].value, 60_000);
    assert_eq!(tx.outputs[1].value, 35_000);
}

/// The signature script is empty: a signature over a transaction carrying
/// its own signatures would commit to itself.
#[test]
fn inputs_carry_no_signature_script() {
    let bytes = payload_bytes(&SPK, &[10_000, 5_000], &[(12_000, None)]);
    let k = kspt::parse(&bytes, &P).expect("parse");
    let (mut ins, mut outs) = arrays();
    let (ni, no) = fill(&k, &mut ins, &mut outs).expect("fill");
    let tx = build(&k, &ins[..ni], &outs[..no]);

    for i in tx.inputs {
        assert!(i.signature_script.is_empty());
    }
}

/// An array too small says how much room is needed, before writing anything.
#[test]
fn a_short_array_reports_what_it_needs() {
    let bytes = payload_bytes(
        &SPK,
        &[1, 2, 3],
        &[(1, None), (2, None), (3, None), (4, None)],
    );
    let k = kspt::parse(&bytes, &P).expect("parse");

    let (mut ins, mut outs) = arrays();
    assert_eq!(
        fill(&k, &mut ins[..2], &mut outs).err(),
        Some(Error::TooManyInputs { needed: 3, room: 2 })
    );
    assert_eq!(
        fill(&k, &mut ins, &mut outs[..3]).err(),
        Some(Error::TooManyOutputs { needed: 4, room: 3 })
    );

    // Nothing was written, so a caller can size and retry.
    assert_eq!(ins[0].utxo_entry.amount, 0);

    assert!(fill(&k, &mut ins, &mut outs).is_ok());
}

/// A covenant record naming a missing output is refused by the parser,
/// before `fill`'s own check.
#[test]
fn a_covenant_for_a_missing_output_is_refused() {
    let mut bytes = payload_bytes(&SPK, &[50_000], &[(40_000, None)]);
    // A 0x43 record for output 5; the payload has one output.
    bytes.push(0x43);
    bytes.push(5);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&[0xCD; 32]);

    assert!(matches!(
        kspt::parse(&bytes, &P),
        Err(kspt::KsptError::RecordIndexOutOfRange {
            marker: 0x43,
            index: 5,
            ..
        })
    ));
}

/// Several bindings all land, each on its own output.
#[test]
fn several_bindings_all_land() {
    let bytes = payload_bytes(
        &SPK,
        &[100_000],
        &[
            (20_000, Some([1u8; 32])),
            (20_000, Some([2u8; 32])),
            (20_000, Some([3u8; 32])),
        ],
    );
    let k = kspt::parse(&bytes, &P).expect("parse");
    let (mut ins, mut outs) = arrays();
    let (ni, no) = fill(&k, &mut ins, &mut outs).expect("fill");
    let tx = build(&k, &ins[..ni], &outs[..no]);

    for (i, o) in tx.outputs.iter().enumerate() {
        assert_eq!(
            o.covenant.map(|c| c.covenant_id),
            Some([(i + 1) as u8; 32]),
            "output {i}"
        );
    }
}
