// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The finisher over spends an app builds by hand.

use kassigner_kaspa::mass::{Cell, MassRates};
use kassigner_kaspa::subnets::SUBNETWORK_ID_NATIVE;
use kassigner_kaspa::tx::{
    Outpoint, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput, UtxoEntry,
};
use kassigner_sdk::reply::{finish, FinishScratch, ReplyError, Spend};

/// A key's input with no signature is refused, not a panic, even when the
/// spend says it needs none.
#[test]
fn a_keys_input_with_no_signature_is_refused() {
    let mut script = [0u8; 34];
    script[0] = 0x20;
    script[1..33].fill(0x11);
    script[33] = 0xAC;
    let spk = ScriptPublicKey {
        version: 0,
        script: &script,
    };
    let mut inputs = [TransactionInput {
        previous_outpoint: Outpoint {
            transaction_id: [1; 32],
            index: 0,
        },
        sequence: 0,
        sig_op_count: 1,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: UtxoEntry {
            amount: 100_000_000,
            script_public_key: spk,
        },
    }];
    let outputs = [TransactionOutput {
        value: 99_000_000,
        script_public_key: spk,
        covenant: None,
    }];
    let header = Transaction {
        version: 0,
        inputs: &[],
        outputs: &[],
        lock_time: 0,
        subnetwork_id: SUBNETWORK_ID_NATIVE,
        gas: 0,
        payload: &[],
    };
    let spends = [Spend {
        need: 0,
        redeem: &[],
        signatures: &[],
        bound: false,
    }];
    let cell = Cell {
        plurality: 0,
        amount: 0,
    };
    let mut unlocks = [0u8; 256];
    let mut unlock_lens = [0usize; 1];
    let (mut cells_in, mut cells_out) = ([cell; 1], [cell; 1]);
    let scratch = FinishScratch {
        unlocks: &mut unlocks,
        unlock_lens: &mut unlock_lens,
        cells_in: &mut cells_in,
        cells_out: &mut cells_out,
    };
    let got = finish(
        &header,
        &mut inputs,
        &outputs,
        &spends,
        &MassRates::MAINNET,
        scratch,
    );
    assert_eq!(
        got.map(|_| ()),
        Err(ReplyError::Signatures {
            input: 0,
            have: 0,
            need: 1
        })
    );
}
