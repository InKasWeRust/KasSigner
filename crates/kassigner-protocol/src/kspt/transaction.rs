// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Turning a parsed KSPT into the [`Transaction`] a signature hash needs.
//! It lives with the format because all it knows is KSPT: which field
//! becomes which, what KSPT does not carry, and that a covenant binding can
//! arrive inline or as a record.
//!
//! Two steps, since nothing here allocates: [`fill`] writes into the
//! caller's arrays and reports how many entries it used, then [`build`]
//! borrows them. A type owning arrays sized for the largest transaction
//! would make every caller pay for that size.
//!
//! Nothing here judges a transaction: that is for a signer's review and a
//! person, who would not see refusals made here.

use super::{Input, Kspt, Output, Record};
use kassigner_kaspa::tx::{
    CovenantBinding, Outpoint, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput,
    UtxoEntry,
};

/// Why a payload did not become a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The caller's input array is too small.
    TooManyInputs { needed: usize, room: usize },
    /// The caller's output array is too small.
    TooManyOutputs { needed: usize, room: usize },
    /// The body holds another number of inputs or outputs than the header
    /// declared. Refused, not truncated: a transaction unlike its own header
    /// is not for a review.
    CountMismatch { declared: usize, found: usize },
    /// A covenant record names an output that does not exist. Refused, not
    /// ignored: a review built from the outputs would not show it. (A second
    /// record for one output never reaches here: the parser refuses it.)
    CovenantForMissingOutput { output: usize, outputs: usize },
}

/// Write a payload's inputs and outputs into the caller's arrays; returns
/// how many of each were used.
///
/// # Errors
///
/// `TooManyInputs` or `TooManyOutputs` if an array is too small, before
/// anything is written, so a caller can size and retry. `CountMismatch` if
/// the body's count differs from the header's. `CovenantForMissingOutput`
/// for a covenant record naming no output.
pub fn fill<'a>(
    kspt: &Kspt<'a>,
    inputs: &mut [TransactionInput<'a>],
    outputs: &mut [TransactionOutput<'a>],
) -> Result<(usize, usize), Error> {
    if kspt.num_inputs > inputs.len() {
        return Err(Error::TooManyInputs {
            needed: kspt.num_inputs,
            room: inputs.len(),
        });
    }
    if kspt.num_outputs > outputs.len() {
        return Err(Error::TooManyOutputs {
            needed: kspt.num_outputs,
            room: outputs.len(),
        });
    }

    let mut ni = 0usize;
    for i in kspt.inputs() {
        if ni >= kspt.num_inputs {
            return Err(Error::CountMismatch {
                declared: kspt.num_inputs,
                found: ni + 1,
            });
        }
        inputs[ni] = input_of(&i);
        ni += 1;
    }
    if ni != kspt.num_inputs {
        return Err(Error::CountMismatch {
            declared: kspt.num_inputs,
            found: ni,
        });
    }

    let mut no = 0usize;
    for o in kspt.outputs() {
        if no >= kspt.num_outputs {
            return Err(Error::CountMismatch {
                declared: kspt.num_outputs,
                found: no + 1,
            });
        }
        // The inline binding, on legacy shapes only; records are merged
        // below.
        outputs[no] = output_of(&o);
        no += 1;
    }
    if no != kspt.num_outputs {
        return Err(Error::CountMismatch {
            declared: kspt.num_outputs,
            found: no,
        });
    }

    // Merge the bindings sent as `0x43` records, the only form `0x06` has:
    // reading only the inline form would hide from the review a binding the
    // signature commits to. None replaces another: the parser refuses a
    // record for an output already bound, inline or by a record.
    for (idx, binding) in bindings(kspt) {
        if idx >= no {
            return Err(Error::CovenantForMissingOutput {
                output: idx,
                outputs: no,
            });
        }
        outputs[idx].covenant = Some(binding);
    }

    Ok((ni, no))
}

/// An input as the transaction holds it: what [`fill`] writes, and what
/// [`matches`] compares.
fn input_of<'a>(i: &Input<'a>) -> TransactionInput<'a> {
    TransactionInput {
        previous_outpoint: Outpoint {
            transaction_id: i.prev_tx_id,
            index: i.prev_index,
        },
        sequence: i.sequence,
        sig_op_count: i.sig_op_count,
        // Not carried by KSPT; zero, as upstream's own extraction uses.
        // It never enters the signature hash, at any version
        // (`consensus/core/src/hashing/sighash.rs`). From version 1 it
        // counts toward mass, the coordinator's arithmetic.
        compute_budget: 0,
        // Empty: a signature cannot commit to itself.
        signature_script: &[],
        utxo_entry: UtxoEntry {
            amount: i.amount,
            script_public_key: ScriptPublicKey {
                version: i.spk_version,
                script: i.spk,
            },
        },
    }
}

/// An output as the transaction holds it, with its inline binding only:
/// the records' are the caller's to merge ([`bindings`]).
fn output_of<'a>(o: &Output<'a>) -> TransactionOutput<'a> {
    TransactionOutput {
        value: o.value,
        script_public_key: ScriptPublicKey {
            version: o.spk_version,
            script: o.spk,
        },
        covenant: o.covenant,
    }
}

/// The bindings a payload sends as `0x43` records, each with the output it
/// names, which may not exist.
fn bindings<'k>(kspt: &'k Kspt<'_>) -> impl Iterator<Item = (usize, CovenantBinding)> + 'k {
    kspt.records().filter_map(|r| match r {
        Record::Covenant {
            output_index,
            authorizing_input,
            covenant_id,
        } => Some((
            usize::from(output_index),
            CovenantBinding {
                authorizing_input,
                covenant_id: *covenant_id,
            },
        )),
        _ => None,
    })
}

/// Whether `kspt` is `tx`: field for field the transaction [`fill`] and
/// [`build`] would make of it, read in place with no arrays. A payload
/// [`fill`] refuses, by its counts or a record naming no output, is not.
///
/// What a reply's read-back holds the reply to, as the PSKB one holds a
/// bundle ([`crate::check::same_transaction`]): its signatures are verified
/// over the reviewed transaction's hashes, which say nothing of the body
/// it carries.
pub fn matches(kspt: &Kspt<'_>, tx: &Transaction<'_>) -> bool {
    if kspt.tx_version != tx.version
        || kspt.lock_time != tx.lock_time
        || kspt.subnetwork_id != tx.subnetwork_id
        || kspt.gas != tx.gas
        || kspt.payload != tx.payload
        || kspt.num_inputs != tx.inputs.len()
        || kspt.num_outputs != tx.outputs.len()
    {
        return false;
    }
    let mut ni = 0usize;
    for i in kspt.inputs() {
        if tx.inputs.get(ni) != Some(&input_of(&i)) {
            return false;
        }
        ni += 1;
    }
    let mut no = 0usize;
    for o in kspt.outputs() {
        let mut out = output_of(&o);
        if let Some((_, binding)) = bindings(kspt).find(|(idx, _)| *idx == no) {
            out.covenant = Some(binding);
        }
        if tx.outputs.get(no) != Some(&out) {
            return false;
        }
        no += 1;
    }
    ni == tx.inputs.len() && no == tx.outputs.len() && bindings(kspt).all(|(idx, _)| idx < no)
}

/// Each input's coin's covenant id, from the payload's `0x49` records:
/// `coins[i]` for input `i`, `None` for an input with no record, whose coin
/// is unbound. As [`Transaction::check_covenant_ids`] and the storage mass
/// take them. A legacy payload has no such record, so every coin reads as
/// unbound. Inputs past `coins`' end are not written.
pub fn coins(kspt: &Kspt<'_>, coins: &mut [Option<[u8; 32]>]) {
    coins.fill(None);
    for r in kspt.records() {
        if let Record::CoinCovenant {
            input_index,
            covenant_id,
        } = r
        {
            if let Some(slot) = coins.get_mut(usize::from(input_index)) {
                *slot = Some(*covenant_id);
            }
        }
    }
}

/// Build a transaction over arrays [`fill`] has written: a separate step
/// because the arrays cannot be borrowed while they are being written.
pub fn build<'a>(
    kspt: &Kspt<'a>,
    inputs: &'a [TransactionInput<'a>],
    outputs: &'a [TransactionOutput<'a>],
) -> Transaction<'a> {
    Transaction {
        version: kspt.tx_version,
        inputs,
        outputs,
        lock_time: kspt.lock_time,
        subnetwork_id: kspt.subnetwork_id,
        gas: kspt.gas,
        payload: kspt.payload,
    }
}
