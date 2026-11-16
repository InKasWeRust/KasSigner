// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Transactions for the tests, as `kassigner-kaspa` builds them: empty
//! arrays for a reader to fill, a transaction around given inputs and
//! outputs, a pay-to-key script. Included by path, like `hex.rs`, as a
//! `pub mod`.

use kassigner_kaspa::tx::{
    Outpoint, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput, UtxoEntry,
    SUBNETWORK_ID_NATIVE,
};

/// Eight empty inputs and outputs, for a reader to write into.
pub fn arrays() -> (
    [TransactionInput<'static>; 8],
    [TransactionOutput<'static>; 8],
) {
    let i = TransactionInput {
        previous_outpoint: Outpoint {
            transaction_id: [0u8; 32],
            index: 0,
        },
        sequence: 0,
        sig_op_count: 0,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: UtxoEntry {
            amount: 0,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: &[],
            },
        },
    };
    let o = TransactionOutput {
        value: 0,
        script_public_key: ScriptPublicKey {
            version: 0,
            script: &[],
        },
        covenant: None,
    };
    ([i; 8], [o; 8])
}

/// A native version-1 transaction around `inputs` and `outputs`, with no
/// lock time, gas or payload.
pub fn tx<'a>(
    inputs: &'a [TransactionInput<'a>],
    outputs: &'a [TransactionOutput<'a>],
) -> Transaction<'a> {
    Transaction {
        version: 1,
        inputs,
        outputs,
        lock_time: 0,
        subnetwork_id: SUBNETWORK_ID_NATIVE,
        gas: 0,
        payload: &[],
    }
}

/// Pay to the x-only key `x`: push 32 bytes, the key, `OP_CHECKSIG`.
pub fn p2pk(x: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![0x20];
    v.extend_from_slice(x);
    v.push(0xac);
    v
}
