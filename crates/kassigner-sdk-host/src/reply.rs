// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A reply read, merged and finished: [`kassigner_sdk::reply`] over owned
//! values.

use kassigner_kaspa::mass::Cell;
use kassigner_kaspa::script::unlock::{script_hash_len, PositionedSignature};
use kassigner_kaspa::tx::{
    EntryDetails, Outpoint, ScriptPublicKey, TransactionInput, TransactionOutput, UtxoEntry,
};
use kassigner_protocol::check::Signers;
use kassigner_protocol::kspt::InputSignature;
use kassigner_sdk::node::{self, Encoding, Params};
use kassigner_sdk::reply::{self, FinalScratch, SafeScratch, Scratch, Shape, Spend};

use crate::{hex, Fault, Profile, Rates};

/// One unsigned input slot.
pub(crate) const INPUT: TransactionInput<'static> = TransactionInput {
    previous_outpoint: Outpoint {
        transaction_id: [0; 32],
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

/// One empty output slot.
pub(crate) const OUTPUT: TransactionOutput<'static> = TransactionOutput {
    value: 0,
    script_public_key: ScriptPublicKey {
        version: 0,
        script: &[],
    },
    covenant: None,
};

/// One empty cell.
pub(crate) const CELL: Cell = Cell {
    plurality: 0,
    amount: 0,
};

/// One empty signature slot.
pub(crate) const SIGNATURE: PositionedSignature<'static> = PositionedSignature {
    position: 0,
    sighash_type: 0,
    signature: &[0; 64],
};

/// One empty spend slot.
pub(crate) const SPEND: Spend<'static> = Spend {
    need: 0,
    redeem: &[],
    signatures: &[],
    bound: false,
};

/// Bytes the unlocking scripts of a profile's inputs take at most.
pub(crate) fn unlocks_len(p: &kassigner_sdk::Profile) -> usize {
    p.max_inputs * script_hash_len(p.max_sigs_per_input, p.max_redeem)
}

/// What a checked reply holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checked {
    /// Signatures on the reply, every one verified.
    pub signatures: u32,
    /// For a multisig, the signatures present that count.
    pub present: Option<u32>,
    /// For a multisig, the signatures the transaction needs.
    pub required: Option<u32>,
    /// Whether every input holds what its script needs to be finalized.
    pub complete: bool,
}

impl Checked {
    /// From what the SDK read.
    pub(crate) fn of(signatures: usize, signers: Option<Signers>, complete: bool) -> Checked {
        Checked {
            signatures: signatures as u32,
            present: signers.map(|s| s.present as u32),
            required: signers.map(|s| s.required as u32),
            complete,
        }
    }
}

/// Read `reply` against `request`: the reply's transaction held to the
/// request's, and every signature verified over it.
///
/// # Errors
///
/// The SDK's [`ReplyError`](kassigner_sdk::reply::ReplyError):
/// `Request(..)` or `Reply(..)` for bytes that are not a KSPT,
/// `Transaction(..)`, `NotTheRequest`, `Unverified(..)` (`Nothing` for no
/// signature at all), `Redeem { input }`, `Unspendable { input }`.
pub fn read_reply(request: &[u8], reply: &[u8], profile: &Profile) -> Result<Checked, Fault> {
    read(Some(request), reply, profile)
}

/// Read `signed`, a transaction signed already, with no request: every
/// signature verified over its own transaction.
///
/// # Errors
///
/// As [`read_reply`], with `Reply(..)` for bytes that are not a KSPT.
pub fn read_signed_reply(signed: &[u8], profile: &Profile) -> Result<Checked, Fault> {
    read(None, signed, profile)
}

/// [`read_reply`], or [`read_signed_reply`] with no request.
fn read(request: Option<&[u8]>, reply: &[u8], profile: &Profile) -> Result<Checked, Fault> {
    let p = profile.inner();
    let mut inputs = vec![INPUT; p.max_inputs];
    let mut outputs = vec![OUTPUT; p.max_outputs];
    let mut scratch = Scratch {
        inputs: &mut inputs,
        outputs: &mut outputs,
    };
    let c = match request {
        Some(request) => reply::read(request, reply, p, &mut scratch),
        None => reply::read_signed(reply, p, &mut scratch),
    }
    .map_err(Fault::of)?;
    Ok(Checked::of(c.signatures, c.signers, c.complete))
}

/// Merge `replies`, cosigners' answers to `request`, into one reply.
///
/// # Errors
///
/// `Request(..)`, `Reply(..)`, `Transaction(..)`, `NotTheRequest` and
/// `Unverified(..)` as [`read_reply`]; `Redeem { input }` for a redeem
/// script a reply supplies that is not the coin's; `Merge(..)` for two
/// signatures at one position; `ScratchTooSmall("sigs")` for more
/// signatures in all than a transaction of the profile holds.
pub fn merge_replies(
    request: &[u8],
    replies: &[&[u8]],
    profile: &Profile,
) -> Result<Vec<u8>, Fault> {
    merge(Some(request), replies, profile)
}

/// Merge `copies` of one transaction signed already into one; a signature
/// at a position an earlier copy holds is left out.
///
/// # Errors
///
/// As [`merge_replies`], with `Reply(..)` for bytes that are not a KSPT,
/// `NotTheRequest` for a copy of another transaction, and
/// `Unverified(Nothing)` for no copies.
pub fn merge_signed_replies(copies: &[&[u8]], profile: &Profile) -> Result<Vec<u8>, Fault> {
    merge(None, copies, profile)
}

/// [`merge_replies`], or [`merge_signed_replies`] with no request.
fn merge(request: Option<&[u8]>, replies: &[&[u8]], profile: &Profile) -> Result<Vec<u8>, Fault> {
    let p = profile.inner();
    let mut inputs = vec![INPUT; p.max_inputs];
    let mut outputs = vec![OUTPUT; p.max_outputs];
    let mut scratch = Scratch {
        inputs: &mut inputs,
        outputs: &mut outputs,
    };
    let mut sigs = vec![InputSignature::EMPTY; p.max_inputs * p.max_sigs_per_input];
    let mut out = vec![0u8; p.max_reassembled];
    let n = match request {
        Some(request) => reply::merge(request, replies, p, &mut scratch, &mut sigs, &mut out),
        None => reply::merge_signed(replies, p, &mut scratch, &mut sigs, &mut out),
    }
    .map_err(Fault::of)?;
    out.truncate(n);
    Ok(out)
}

/// A finished transaction: its id, what it pays, and the
/// `submitTransaction` request for a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized {
    /// The transaction id, hex, as a node names it.
    pub id: String,
    /// The fee it pays, sompi.
    pub fee: u64,
    /// The storage mass it commits.
    pub storage_mass: u64,
    /// Its compute mass as signed.
    pub compute_mass: u64,
    /// The `submitTransaction` call's `params` as JSON, for a node's wRPC
    /// JSON port. Send it as it is: parsed and written again in a language
    /// without 64-bit integers, the amounts would round.
    pub submit_json: String,
    /// The same request in kaspa-rest-server's model: the body of
    /// `POST /transactions` on api.kaspa.org or any other instance.
    pub rest_json: String,
    /// The same params in Borsh, which
    /// [`Node::submit_transaction`](crate::node::Node::submit_transaction)
    /// frames with its id.
    pub submit_borsh: Vec<u8>,
    /// Each input's unlocking script, hex.
    pub unlocks: Vec<String>,
}

impl Finalized {
    /// From what the SDK finished.
    pub(crate) fn of(f: &reply::Finalized<'_>, allow_orphan: bool) -> Result<Finalized, Fault> {
        let written = |shape: Shape| -> Result<String, Fault> {
            let mut json = vec![0u8; f.submit_json_len(allow_orphan, shape)];
            let n = f
                .submit_json(allow_orphan, shape, &mut json)
                .map_err(Fault::of)?;
            json.truncate(n);
            Ok(String::from_utf8_lossy(&json).into_owned())
        };
        let submit = Params::SubmitTransaction {
            transaction: &f.transaction,
            storage_mass: f.storage_mass,
            allow_orphan,
        };
        let mut borsh = vec![0u8; node::params_len(&submit, Encoding::Borsh).map_err(Fault::of)?];
        let n = node::params(&submit, Encoding::Borsh, &mut borsh).map_err(Fault::of)?;
        borsh.truncate(n);
        Ok(Finalized {
            id: hex(&f.id),
            fee: f.fee,
            storage_mass: f.storage_mass,
            compute_mass: f.compute_mass,
            submit_json: written(Shape::Rpc)?,
            rest_json: written(Shape::Rest)?,
            submit_borsh: borsh,
            unlocks: f
                .transaction
                .inputs
                .iter()
                .map(|i| hex(i.signature_script))
                .collect(),
        })
    }
}

/// Finish `reply`, a complete reply to `request`: read as [`read_reply`]
/// reads it, every unlocking script written, the masses computed and the
/// fee checked against the signed transaction's minimum relay fee.
///
/// # Errors
///
/// As [`read_reply`]; `Signatures { input, have, need }` for an input
/// short of its threshold; `Unlock(..)`, `Mass`,
/// `FeeTooLow { fee, minimum }`, `Dust { output }`.
pub fn finalize_reply(
    request: &[u8],
    reply: &[u8],
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    finalize(Some(request), reply, allow_orphan, rates, profile)
}

/// Finish `signed`, a complete transaction signed already, with no
/// request, as [`finalize_reply`] does.
///
/// # Errors
///
/// As [`finalize_reply`], with `Reply(..)` for bytes that are not a KSPT.
pub fn finalize_signed_reply(
    signed: &[u8],
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    finalize(None, signed, allow_orphan, rates, profile)
}

/// [`finalize_reply`], or [`finalize_signed_reply`] with no request.
fn finalize(
    request: Option<&[u8]>,
    reply: &[u8],
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    let p = profile.inner();
    let mut inputs = vec![INPUT; p.max_inputs];
    let mut outputs = vec![OUTPUT; p.max_outputs];
    let mut unlocks = vec![0u8; unlocks_len(p)];
    let mut unlock_lens = vec![0usize; p.max_inputs];
    let mut signatures = vec![SIGNATURE; p.max_inputs * p.max_sigs_per_input];
    let mut ranges = vec![(0usize, 0usize); p.max_inputs];
    let mut spends = vec![SPEND; p.max_inputs];
    let mut cells_in = vec![CELL; p.max_inputs];
    let mut cells_out = vec![CELL; p.max_outputs];
    let mut scratch = FinalScratch {
        inputs: &mut inputs,
        outputs: &mut outputs,
        unlocks: &mut unlocks,
        unlock_lens: &mut unlock_lens,
        signatures: &mut signatures,
        ranges: &mut ranges,
        spends: &mut spends,
        cells_in: &mut cells_in,
        cells_out: &mut cells_out,
    };
    let f = match request {
        Some(request) => reply::finalize(request, reply, p, rates.inner(), &mut scratch),
        None => reply::finalize_signed(reply, p, rates.inner(), &mut scratch),
    }
    .map_err(Fault::of)?;
    Finalized::of(&f, allow_orphan)
}

/// Finish `signed`, a wallet's signed safe JSON, against `request`, the
/// safe JSON it was handed: the same transaction but for its unlocking
/// scripts, every input carrying one, its id its own; then the masses
/// computed and the fee checked. The node verifies the signatures.
///
/// # Errors
///
/// `RequestJson(..)`, `ReplyJson(..)`, `NotTheRequest`,
/// `Unsigned { input }`, `WrongId`, `Mass`, `FeeTooLow { fee, minimum }`,
/// `Dust { output }`.
pub fn finalize_safe_json(
    request: &str,
    signed: &str,
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    let p = profile.inner();
    let details = EntryDetails {
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    };
    let mut request_inputs = vec![INPUT; p.max_inputs];
    let mut request_outputs = vec![OUTPUT; p.max_outputs];
    let mut request_details = vec![details; p.max_inputs];
    let mut request_bytes = vec![0u8; request.len() / 2];
    let mut inputs = vec![INPUT; p.max_inputs];
    let mut outputs = vec![OUTPUT; p.max_outputs];
    let mut signed_details = vec![details; p.max_inputs];
    let mut bytes = vec![0u8; signed.len() / 2];
    let mut cells_in = vec![CELL; p.max_inputs];
    let mut cells_out = vec![CELL; p.max_outputs];
    let mut scratch = SafeScratch {
        request_inputs: &mut request_inputs,
        request_outputs: &mut request_outputs,
        request_details: &mut request_details,
        request_bytes: &mut request_bytes,
        inputs: &mut inputs,
        outputs: &mut outputs,
        details: &mut signed_details,
        bytes: &mut bytes,
        cells_in: &mut cells_in,
        cells_out: &mut cells_out,
    };
    let f = reply::finalize_safe_json(
        request.as_bytes(),
        signed.as_bytes(),
        rates.inner(),
        &mut scratch,
    )
    .map_err(Fault::of)?;
    Finalized::of(&f, allow_orphan)
}
