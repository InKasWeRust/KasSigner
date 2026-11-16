// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A reply: what a unit signed, checked, merged and finished.
//!
//! A reply is read with the request it answers. The request's transaction
//! is what the app built for review, so a reply carrying another is refused
//! before any signature is looked at, and every signature is verified over
//! the request's hashes ([`kassigner_protocol::check::verify_kspt`]).
//!
//! A transaction already signed may come back alone: a unit's SIGNED TX QR
//! shown again from its card, or a cosigner's partly signed copy.
//! [`read_signed`], [`merge_signed`] and [`finalize_signed`] hold it to
//! itself, every signature verified over its own transaction by the key its
//! script names. That says what was signed, not that this app built it;
//! what it pays is for whoever broadcasts it to read.
//!
//! [`merge`] writes cosigners' signatures, each at its own key position,
//! into one KSPT through the level 1 writer, which orders them and refuses
//! two at one position; the result is a reply like any other. Copies of a
//! signed transaction merge the same way, a position already held left out,
//! so the same cosigner in two copies is no conflict.
//!
//! [`finalize`] checks the reply as [`read`] does, then writes every
//! input's unlocking script ([`kassigner_kaspa::script::unlock`]): a single
//! key's signature; for a script hash, the threshold's signatures in key
//! order and the redeem script, a group's or KCC-3's `<P> OP_CHECKSIG` the
//! unit supplied; for a Time-Locked Savings card, the card's signature
//! script, claim for the owner's key and recover for the recovery wallet's.
//! The storage mass is computed, since a node checks the committed one
//! against its own. The fee is checked against the minimum relay fee as a
//! node prices it, over compute mass or bytes, never storage mass. Out come
//! the transaction, its id, and the `submitTransaction` JSON in the taker's
//! [`Shape`] ([`kassigner_kaspa::rpc`]); the call is the app's.

use kassigner_kaspa::mass::{
    compute_budget_for, is_dust, minimum_relay_fee, non_contextual_masses, plurality,
    relay_fee_mass, storage_mass, Cell, MassRates, BLOCK_STORAGE_MASS_LIMIT,
};
use kassigner_kaspa::rpc::{self, RpcError};
use kassigner_kaspa::safe_json::{self, SafeJsonError};

pub use kassigner_kaspa::rpc::Shape;
use kassigner_kaspa::script::unlock::{self, PositionedSignature, UnlockError};
use kassigner_kaspa::script::{classify, kcc3_key, multisig_shape, redeem_matches, ScriptClass};
use kassigner_kaspa::sighash::{transaction_id, Hash};
use kassigner_kaspa::tx::{EntryDetails, Transaction, TransactionInput, TransactionOutput};
use kassigner_protocol::card::savings::{Entry, Savings, SIG_LEN as CARD_SIG_LEN};
use kassigner_protocol::check::{self, Signers, Unverified};
use kassigner_protocol::kspt::transaction as kspt_tx;
use kassigner_protocol::kspt::{self, InputSignature, Kspt, KsptError, SIGNATURE_LEN};
use kassigner_protocol::profile::Profile;

/// Why a reply was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// The request does not parse.
    Request(KsptError),
    /// The reply does not parse.
    Reply(KsptError),
    /// The request or the reply does not map to a transaction.
    Transaction(kspt_tx::Error),
    /// The reply's transaction is not the request's.
    NotTheRequest,
    /// Verification refused the reply, as [`Unverified`] says.
    Unverified(Unverified),
    /// The writer refused the merge: two signatures at one position, or
    /// another reason it names.
    Merge(KsptError),
    /// Input `input` has `have` signatures where its script needs `need`.
    Signatures {
        input: usize,
        have: usize,
        need: usize,
    },
    /// Input `input` is a script hash with no redeem script, or one that
    /// is not its lock's.
    Redeem { input: usize },
    /// Input `input`'s script is one no unlocking script is written for: a
    /// script hash whose redeem is not a multisig, KCC-3's or a card's
    /// program, an ECDSA key, a non-standard script; or a card's input with
    /// no signature at either key's position.
    Unspendable { input: usize },
    /// An unlocking script could not be written.
    Unlock(UnlockError),
    /// The mass or the fee could not be computed (outputs worth more than
    /// the inputs, a value out of range), or the transaction is of a
    /// version consensus does not know.
    Mass,
    /// Input `input` of a version 1 transaction commits signature
    /// operations, which consensus refuses there (`SigopCountInV1`), or its
    /// script is one no compute budget is known for.
    Budget { input: usize },
    /// The signed transaction's storage mass is over the block limit
    /// ([`BLOCK_STORAGE_MASS_LIMIT`]); no node would accept it. A backstop:
    /// the request builder already refuses to build one.
    StorageMass { mass: u64 },
    /// The fee is under the minimum relay fee a node asks of the signed
    /// transaction, over compute mass or bytes, whichever weigh more.
    FeeTooLow { fee: u64, minimum: u64 },
    /// An output is dust, which a node would not relay.
    Dust { output: usize },
    /// A buffer of the caller's scratch is too small; the field says which.
    ScratchTooSmall(&'static str),
    /// The request JSON could not be written.
    Rpc(RpcError),
    /// A request in the safe JSON does not read.
    RequestJson(SafeJsonError),
    /// A signed transaction in the safe JSON does not read.
    ReplyJson(SafeJsonError),
    /// Input `input` of a signed transaction carries no unlocking script.
    Unsigned { input: usize },
    /// A signed transaction says an id that is not its own.
    WrongId,
}

impl From<Unverified> for ReplyError {
    fn from(e: Unverified) -> Self {
        ReplyError::Unverified(e)
    }
}

impl From<UnlockError> for ReplyError {
    fn from(e: UnlockError) -> Self {
        ReplyError::Unlock(e)
    }
}

impl From<RpcError> for ReplyError {
    fn from(e: RpcError) -> Self {
        ReplyError::Rpc(e)
    }
}

/// What a checked reply holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checked {
    /// Signatures on the reply, every one verified.
    pub signatures: usize,
    /// Present of required signers, as the unit shows them; `None` when no
    /// input is a multisig.
    pub signers: Option<Signers>,
    /// Whether every input holds what its script needs: the reply can be
    /// finalized.
    pub complete: bool,
}

/// The buffers a reply is read in: one slot per input and per output of
/// the request's transaction.
pub struct Scratch<'s> {
    pub inputs: &'s mut [TransactionInput<'s>],
    pub outputs: &'s mut [TransactionOutput<'s>],
}

/// Whether `rep` carries `req`'s transaction: every field a signature
/// commits to, and the covenant records, the outputs' and the spent
/// coins', the same.
fn same_transaction(req: &Kspt<'_>, rep: &Kspt<'_>) -> bool {
    if req.tx_version != rep.tx_version
        || req.lock_time != rep.lock_time
        || req.subnetwork_id != rep.subnetwork_id
        || req.gas != rep.gas
        || req.payload != rep.payload
        || req.num_inputs != rep.num_inputs
        || req.num_outputs != rep.num_outputs
    {
        return false;
    }
    let inputs = req.inputs().zip(rep.inputs()).all(|(a, b)| {
        a.prev_tx_id == b.prev_tx_id
            && a.prev_index == b.prev_index
            && a.amount == b.amount
            && a.sequence == b.sequence
            && a.sig_op_count == b.sig_op_count
            && a.spk_version == b.spk_version
            && a.spk == b.spk
    });
    let outputs = req.outputs().zip(rep.outputs()).all(|(a, b)| {
        a.value == b.value
            && a.spk_version == b.spk_version
            && a.spk == b.spk
            && a.covenant == b.covenant
    });
    inputs
        && outputs
        && covenants(req).count() == covenants(rep).count()
        && covenants(req).zip(covenants(rep)).all(|(a, b)| a == b)
}

/// The covenant records of `k`, in order: each bound output's, and each
/// input's whose coin is bound.
fn covenants<'k, 'a>(k: &'k Kspt<'a>) -> impl Iterator<Item = kspt::Record<'a>> + 'k {
    k.records().filter(|r| {
        matches!(
            r,
            kspt::Record::Covenant { .. } | kspt::Record::CoinCovenant { .. }
        )
    })
}

/// Whether input `i`'s coin is bound to a covenant, by `k`'s records.
fn coin_bound(k: &Kspt<'_>, i: usize) -> bool {
    k.records().any(|r| {
        matches!(r, kspt::Record::CoinCovenant { input_index, .. } if usize::from(input_index) == i)
    })
}

/// Map a parsed payload to its transaction in `inputs` and `outputs`.
fn transaction_of<'a>(
    k: &Kspt<'a>,
    inputs: &'a mut [TransactionInput<'a>],
    outputs: &'a mut [TransactionOutput<'a>],
) -> Result<Transaction<'a>, ReplyError> {
    let (ni, no) = kspt_tx::fill(k, inputs, outputs).map_err(ReplyError::Transaction)?;
    Ok(kspt_tx::build(k, &inputs[..ni], &outputs[..no]))
}

/// What input `i` of `k` needs: the signatures its script wants, and the
/// redeem script it spends with, empty for a single key.
fn needs<'a>(k: &Kspt<'a>, i: usize) -> Result<(usize, &'a [u8]), ReplyError> {
    let input = k
        .inputs()
        .nth(i)
        .ok_or(ReplyError::Unspendable { input: i })?;
    let spk = check::script_of(&input);
    match classify(&spk) {
        ScriptClass::PubKey => Ok((1, &[])),
        ScriptClass::ScriptHash => {
            if input.redeem.is_empty() || !redeem_matches(&spk, input.redeem) {
                return Err(ReplyError::Redeem { input: i });
            }
            if let Some(ms) = multisig_shape(input.redeem) {
                return Ok((usize::from(ms.required), input.redeem));
            }
            if kcc3_key(input.redeem).is_some() || Savings::from_program(input.redeem).is_ok() {
                return Ok((1, input.redeem));
            }
            Err(ReplyError::Unspendable { input: i })
        }
        _ => Err(ReplyError::Unspendable { input: i }),
    }
}

/// Read `reply` against `request`: the reply's transaction held to be the
/// request's, and every signature verified over it.
///
/// # Errors
///
/// `Request` or `Reply` for bytes that do not parse; `Transaction` for a
/// request that does not map to a transaction in `scratch`;
/// `NotTheRequest`; `Unverified` for a signature that does not verify,
/// `Unverified(Nothing)` for none at all; `Redeem` or `Unspendable` for a
/// signed input no unlocking script can be written for.
pub fn read<'s>(
    request: &'s [u8],
    reply: &'s [u8],
    profile: &Profile,
    scratch: &'s mut Scratch<'s>,
) -> Result<Checked, ReplyError> {
    let req = kspt::parse(request, profile).map_err(ReplyError::Request)?;
    let rep = kspt::parse(reply, profile).map_err(ReplyError::Reply)?;
    let Scratch { inputs, outputs } = scratch;
    if !same_transaction(&req, &rep) {
        return Err(ReplyError::NotTheRequest);
    }
    let tx = transaction_of(&req, inputs, outputs)?;
    let signatures = check::verify_kspt(reply, &tx, profile)?;
    let mut complete = true;
    for (i, input) in rep.inputs().enumerate() {
        let (need, _) = match needs(&rep, i) {
            Ok(n) => n,
            Err(ReplyError::Redeem { .. }) if input.signatures().next().is_none() => {
                // A KCC-3 input not signed yet: its redeem comes with the
                // signature.
                complete = false;
                continue;
            }
            Err(e) => return Err(e),
        };
        if input.signatures().count() < need {
            complete = false;
        }
    }
    Ok(Checked {
        signatures,
        signers: check::kspt_signers(reply, profile),
        complete,
    })
}

/// A signed transaction read as both the request and the reply: its parse
/// refused as the reply's.
fn as_copy(e: ReplyError) -> ReplyError {
    match e {
        ReplyError::Request(k) => ReplyError::Reply(k),
        e => e,
    }
}

/// Read `signed`, a transaction already signed, by itself, as [`read`]
/// reads a reply: every signature verified over its own transaction.
///
/// # Errors
///
/// `Reply` for bytes that do not parse; `Unverified(Nothing)` for none
/// signed; the rest as [`read`].
pub fn read_signed<'s>(
    signed: &'s [u8],
    profile: &Profile,
    scratch: &'s mut Scratch<'s>,
) -> Result<Checked, ReplyError> {
    read(signed, signed, profile, scratch).map_err(as_copy)
}

/// Merge `copies` of one signed transaction into one KSPT in `out`: its
/// length. Every copy is held to the first and verified over it; a
/// signature at a position already held is left out.
///
/// # Errors
///
/// `NotTheRequest` for a copy of another transaction; `Unverified(Nothing)`
/// for no copy, or one with no signature; the rest as [`merge`].
pub fn merge_signed<'s>(
    copies: &[&'s [u8]],
    profile: &Profile,
    scratch: &'s mut Scratch<'s>,
    sigs: &mut [InputSignature],
    out: &mut [u8],
) -> Result<usize, ReplyError> {
    let first = copies
        .first()
        .ok_or(ReplyError::Unverified(Unverified::Nothing))?;
    merge_into(first, copies, true, profile, scratch, sigs, out).map_err(as_copy)
}

/// Finish `signed`, a complete signed transaction, by itself: as
/// [`finalize`] with the transaction as its own request.
///
/// # Errors
///
/// `Reply` for bytes that do not parse; the rest as [`finalize`].
pub fn finalize_signed<'s>(
    signed: &'s [u8],
    profile: &Profile,
    rates: &MassRates,
    scratch: &'s mut FinalScratch<'s>,
) -> Result<Finalized<'s>, ReplyError> {
    finalize(signed, signed, profile, rates, scratch).map_err(as_copy)
}

/// Merge `replies` to `request` into one KSPT in `out`: its length. Each
/// reply is held to the request and verified, as [`read`] does; `sigs` is
/// scratch, one slot per signature across the replies.
///
/// # Errors
///
/// `Request`, `Reply`, `Transaction`, `NotTheRequest` and `Unverified` as
/// [`read`]; `Redeem` for a supplied redeem script that is not the coin's
/// or not KCC-3's; `ScratchTooSmall("sigs")`; `Merge` for two signatures at
/// one position, or anything else the writer refuses.
pub fn merge<'s>(
    request: &'s [u8],
    replies: &[&'s [u8]],
    profile: &Profile,
    scratch: &'s mut Scratch<'s>,
    sigs: &mut [InputSignature],
    out: &mut [u8],
) -> Result<usize, ReplyError> {
    merge_into(request, replies, false, profile, scratch, sigs, out)
}

/// What [`merge`] and [`merge_signed`] share: `replies` merged into
/// `request`. With `once`, a signature at a position the request or an
/// earlier reply holds is left out, not refused.
fn merge_into<'s>(
    request: &'s [u8],
    replies: &[&'s [u8]],
    once: bool,
    profile: &Profile,
    scratch: &'s mut Scratch<'s>,
    sigs: &mut [InputSignature],
    out: &mut [u8],
) -> Result<usize, ReplyError> {
    let req = kspt::parse(request, profile).map_err(ReplyError::Request)?;
    let Scratch { inputs, outputs } = scratch;
    let tx = transaction_of(&req, inputs, outputs)?;
    let mut n = 0usize;
    for reply in replies {
        let rep = kspt::parse(reply, profile).map_err(ReplyError::Reply)?;
        if !same_transaction(&req, &rep) {
            return Err(ReplyError::NotTheRequest);
        }
        check::verify_kspt(reply, &tx, profile)?;
        for (i, (mine, theirs)) in req.inputs().zip(rep.inputs()).enumerate() {
            // A redeem script the unit supplied, KCC-3's, goes with its
            // signature into an input that had none, and must be the script
            // the coin commits to.
            let supplied = if mine.redeem.is_empty() && !theirs.redeem.is_empty() {
                if !redeem_matches(&check::script_of(&mine), theirs.redeem) {
                    return Err(ReplyError::Redeem { input: i });
                }
                Some(
                    <[u8; 34]>::try_from(theirs.redeem)
                        .map_err(|_| ReplyError::Redeem { input: i })?,
                )
            } else {
                None
            };
            for s in theirs.signatures() {
                let held = |pos: u8| {
                    mine.signatures().any(|h| h.pubkey_pos == pos)
                        || sigs[..n]
                            .iter()
                            .any(|h| h.input == i && h.pubkey_pos == pos)
                };
                if once && held(s.pubkey_pos) {
                    continue;
                }
                let slot = sigs.get_mut(n).ok_or(ReplyError::ScratchTooSmall("sigs"))?;
                let mut signature = [0u8; SIGNATURE_LEN];
                if s.bytes.len() != SIGNATURE_LEN {
                    return Err(ReplyError::Unverified(Unverified::Malformed { input: i }));
                }
                signature.copy_from_slice(s.bytes);
                *slot = InputSignature {
                    input: i,
                    pubkey_pos: s.pubkey_pos,
                    sighash_type: s.sighash_type,
                    signature,
                    redeem: supplied,
                };
                n += 1;
            }
        }
    }
    kspt::write(&req, &tx, &sigs[..n], profile, out).map_err(ReplyError::Merge)
}

/// The buffers a reply is finalized in.
pub struct FinalScratch<'s> {
    /// The reply's transaction: one slot per input and output.
    pub inputs: &'s mut [TransactionInput<'s>],
    pub outputs: &'s mut [TransactionOutput<'s>],
    /// The unlocking scripts, one after another: per input at most
    /// [`unlock::script_hash_len`] of its threshold and redeem script,
    /// [`crate::card::SIGNATURE_SCRIPT_LEN`] for a card's.
    pub unlocks: &'s mut [u8],
    /// One per input: its unlocking script's length.
    pub unlock_lens: &'s mut [usize],
    /// One per signature on the reply, across its inputs.
    pub signatures: &'s mut [PositionedSignature<'s>],
    /// One per input: where its signatures lie in `signatures`.
    pub ranges: &'s mut [(usize, usize)],
    /// One per input: what it spends with.
    pub spends: &'s mut [Spend<'s>],
    /// One per input, for the storage mass.
    pub cells_in: &'s mut [Cell],
    /// One per output, for the storage mass.
    pub cells_out: &'s mut [Cell],
}

/// A finished transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finalized<'s> {
    /// The transaction, every input's unlocking script in place.
    pub transaction: Transaction<'s>,
    /// Its id, as a node names it.
    pub id: Hash,
    /// The storage mass it commits.
    pub storage_mass: u64,
    /// Its compute mass as signed.
    pub compute_mass: u64,
    /// The fee it pays.
    pub fee: u64,
}

/// What one input spends with, for [`finish`]: the signatures its script
/// needs, the redeem script (empty for a single key) and the signatures
/// held, with their key positions; and whether the coin it spends is bound
/// to a covenant, which the storage mass counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spend<'a> {
    pub need: usize,
    pub redeem: &'a [u8],
    pub signatures: &'a [PositionedSignature<'a>],
    /// The coin's entry names a covenant (`covenantId`).
    pub bound: bool,
}

/// The buffers [`finish`] writes in.
pub struct FinishScratch<'s, 'c> {
    /// The unlocking scripts, one after another.
    pub unlocks: &'s mut [u8],
    /// One per input: its unlocking script's length.
    pub unlock_lens: &'c mut [usize],
    /// One per input and one per output, for the storage mass.
    pub cells_in: &'c mut [Cell],
    pub cells_out: &'c mut [Cell],
}

/// Finish a transaction whose inputs are filled, with `spends` one per
/// input: every unlocking script written into `unlocks`, the masses
/// computed, the fee checked, the id taken. `header` gives the fields
/// besides inputs and outputs. Shared by the KSPT and bundle finalizers.
///
/// # Errors
///
/// `Signatures` for an input short of its threshold; `Unspendable` for a
/// card's input with no signature at either key's position; `Unlock`,
/// `FeeTooLow`, `Dust`, `Mass`, `ScratchTooSmall`.
pub fn finish<'s>(
    header: &Transaction<'s>,
    inputs: &'s mut [TransactionInput<'s>],
    outputs: &'s [TransactionOutput<'s>],
    spends: &[Spend<'_>],
    rates: &MassRates,
    scratch: FinishScratch<'s, '_>,
) -> Result<Finalized<'s>, ReplyError> {
    let FinishScratch {
        unlocks,
        unlock_lens,
        cells_in,
        cells_out,
    } = scratch;
    let (ni, no) = (inputs.len(), outputs.len());
    if spends.len() != ni {
        return Err(ReplyError::ScratchTooSmall("spends"));
    }
    if cells_in.len() < ni || cells_out.len() < no || unlock_lens.len() < ni {
        return Err(ReplyError::ScratchTooSmall("cells"));
    }
    let mut at = 0usize;
    for (i, spend) in spends.iter().enumerate() {
        let have = spend.signatures.len();
        if have < spend.need {
            return Err(ReplyError::Signatures {
                input: i,
                have,
                need: spend.need,
            });
        }
        let room = unlocks
            .get_mut(at..)
            .ok_or(ReplyError::ScratchTooSmall("unlocks"))?;
        let len = if spend.redeem.is_empty() {
            // A key's input needs its one signature, whatever `need` says.
            let s = spend.signatures.first().ok_or(ReplyError::Signatures {
                input: i,
                have: 0,
                need: 1,
            })?;
            unlock::single_key(s.signature, s.sighash_type, room)?
        } else if let Ok(card) = Savings::from_program(spend.redeem) {
            card_unlock(&card, spend.signatures, i, room)?
        } else {
            unlock::script_hash(spend.signatures, spend.need, spend.redeem, room)?
        };
        unlock_lens[i] = len;
        at += len;
    }
    let unlocks: &'s [u8] = unlocks;
    let mut start = 0usize;
    for (input, &len) in inputs.iter_mut().zip(unlock_lens.iter()) {
        input.signature_script = &unlocks[start..start + len];
        start += len;
    }
    // A version 1 input commits a compute budget, which no signature
    // covers and a KSPT does not carry: the one that buys what its script's
    // signature operations cost, as the request builder priced it.
    if header.version >= 1 {
        for (i, (input, spend)) in inputs.iter_mut().zip(spends).enumerate() {
            let sig_ops =
                check::committed_sig_ops(&input.utxo_entry.script_public_key, spend.redeem)
                    .ok_or(ReplyError::Budget { input: i })?;
            input.compute_budget = compute_budget_for(sig_ops);
        }
    }
    let inputs: &'s [TransactionInput<'s>] = inputs;
    let transaction = Transaction {
        version: header.version,
        inputs,
        outputs,
        lock_time: header.lock_time,
        subnetwork_id: header.subnetwork_id,
        gas: header.gas,
        payload: header.payload,
    };
    seal(
        transaction,
        |i| spends.get(i).is_some_and(|s| s.bound),
        rates,
        cells_in,
        cells_out,
    )
}

/// Input `input`'s Time-Locked Savings signature script into `room`: the
/// owner's signature, at the program's first key, spends by claim; the
/// recovery wallet's, at the second, by recover; the owner's when both are
/// held. A card with no recovery wallet holds the owner's key at both, and
/// the unit signs at the first.
///
/// # Errors
///
/// `Unspendable` for no signature at either place; `ScratchTooSmall` for a
/// `room` short of the script.
fn card_unlock(
    card: &Savings,
    signatures: &[PositionedSignature<'_>],
    input: usize,
    room: &mut [u8],
) -> Result<usize, ReplyError> {
    let at = |position: u8| signatures.iter().find(|s| s.position == position);
    let (entry, s) = match (at(0), at(1)) {
        (Some(s), _) => (Entry::Claim, s),
        (None, Some(s)) => (Entry::Recover, s),
        (None, None) => return Err(ReplyError::Unspendable { input }),
    };
    let mut sig = [0u8; CARD_SIG_LEN];
    sig[..64].copy_from_slice(s.signature);
    sig[64] = s.sighash_type;
    let script = card.signature_script(entry, &sig);
    room.get_mut(..script.len())
        .ok_or(ReplyError::ScratchTooSmall("unlocks"))?
        .copy_from_slice(&script);
    Ok(script.len())
}

/// Seal a transaction whose every input carries its unlocking script: the
/// masses as a node computes them, every output above dust, the fee over
/// the minimum relay fee as a node prices it ([`relay_fee_mass`]), the id.
/// `bound(i)` says whether input `i`'s coin is bound to a covenant, 32
/// bytes more of storage (upstream's `UtxoPlurality`). What [`finish`] and
/// [`finalize_safe_json`] share.
fn seal<'s>(
    transaction: Transaction<'s>,
    bound: impl Fn(usize) -> bool,
    rates: &MassRates,
    cells_in: &mut [Cell],
    cells_out: &mut [Cell],
) -> Result<Finalized<'s>, ReplyError> {
    let (inputs, outputs) = (transaction.inputs, transaction.outputs);
    let (ni, no) = (inputs.len(), outputs.len());
    if cells_in.len() < ni || cells_out.len() < no {
        return Err(ReplyError::ScratchTooSmall("cells"));
    }
    // Consensus takes a signature operation count in version 0 alone
    // (`SigopCountInV1`), and a node's RPC refuses one in version 1.
    if transaction.version >= 1 {
        if let Some(input) = inputs.iter().position(|i| i.sig_op_count != 0) {
            return Err(ReplyError::Budget { input });
        }
    }
    let (compute_mass, transient_mass) =
        non_contextual_masses(&transaction, rates).ok_or(ReplyError::Mass)?;
    for (i, (cell, input)) in cells_in.iter_mut().zip(inputs).enumerate() {
        *cell = Cell {
            plurality: plurality(input.utxo_entry.script_public_key.script.len(), bound(i)),
            amount: input.utxo_entry.amount,
        };
    }
    for (k, (cell, output)) in cells_out.iter_mut().zip(outputs).enumerate() {
        if is_dust(output.value, output.script_public_key.script.len()) {
            return Err(ReplyError::Dust { output: k });
        }
        *cell = Cell {
            plurality: plurality(
                output.script_public_key.script.len(),
                output.covenant.is_some(),
            ),
            amount: output.value,
        };
    }
    let storage = storage_mass(
        &cells_in[..ni],
        &cells_out[..no],
        rates.storage_mass_parameter,
    )
    .ok_or(ReplyError::Mass)?;
    if storage > BLOCK_STORAGE_MASS_LIMIT {
        return Err(ReplyError::StorageMass { mass: storage });
    }
    // The minimum relay fee as a node applies it: over compute mass, or the
    // transaction's bytes where they weigh more, never over storage mass.
    let fee = transaction.fee().map_err(|_| ReplyError::Mass)?;
    let minimum = minimum_relay_fee(relay_fee_mass(compute_mass, transient_mass));
    if fee < minimum {
        return Err(ReplyError::FeeTooLow { fee, minimum });
    }
    let id = transaction_id(&transaction).ok_or(ReplyError::Mass)?;
    Ok(Finalized {
        transaction,
        id,
        storage_mass: storage,
        compute_mass,
        fee,
    })
}

/// Finish `reply`, a complete reply to `request`: checked as [`read`]
/// checks it, then every input's unlocking script written, the masses
/// computed, the fee checked.
///
/// # Errors
///
/// As [`read`], with `Redeem` and `Unspendable` for any input, signed or
/// not; then as [`finish`].
pub fn finalize<'s>(
    request: &[u8],
    reply: &'s [u8],
    profile: &Profile,
    rates: &MassRates,
    scratch: &'s mut FinalScratch<'s>,
) -> Result<Finalized<'s>, ReplyError> {
    let req = kspt::parse(request, profile).map_err(ReplyError::Request)?;
    let rep = kspt::parse(reply, profile).map_err(ReplyError::Reply)?;
    if !same_transaction(&req, &rep) {
        return Err(ReplyError::NotTheRequest);
    }
    let FinalScratch {
        inputs,
        outputs,
        unlocks,
        unlock_lens,
        signatures,
        ranges,
        spends,
        cells_in,
        cells_out,
    } = scratch;
    let (ni, no) = kspt_tx::fill(&rep, inputs, outputs).map_err(ReplyError::Transaction)?;
    // The reply's transaction is the request's, field for field, so its
    // signatures are verified over it.
    check::verify_kspt(
        reply,
        &kspt_tx::build(&rep, &inputs[..ni], &outputs[..no]),
        profile,
    )?;
    if spends.len() < ni || ranges.len() < ni {
        return Err(ReplyError::ScratchTooSmall("spends"));
    }
    // Every input's signatures with their positions, one run each in
    // `signatures`; then each input's spend over its run.
    let mut k = 0usize;
    for (i, input) in rep.inputs().enumerate() {
        let from = k;
        for s in input.signatures() {
            let bytes = <&[u8; 64]>::try_from(s.bytes)
                .map_err(|_| ReplyError::Unverified(Unverified::Malformed { input: i }))?;
            let slot = signatures
                .get_mut(k)
                .ok_or(ReplyError::ScratchTooSmall("signatures"))?;
            *slot = PositionedSignature {
                position: s.pubkey_pos,
                sighash_type: s.sighash_type,
                signature: bytes,
            };
            k += 1;
        }
        ranges[i] = (from, k);
    }
    let signatures: &'s [PositionedSignature<'s>] = signatures;
    for i in 0..ni {
        let (need, redeem) = needs(&rep, i)?;
        let (from, to) = ranges[i];
        spends[i] = Spend {
            need,
            redeem,
            signatures: &signatures[from..to],
            // The request's record, which the reply was held to above.
            bound: coin_bound(&req, i),
        };
    }
    let outputs: &'s [TransactionOutput<'s>] = &outputs[..no];
    let header = kspt_tx::build(&rep, &[], outputs);
    finish(
        &header,
        &mut inputs[..ni],
        outputs,
        &spends[..ni],
        rates,
        FinishScratch {
            unlocks,
            unlock_lens,
            cells_in,
            cells_out,
        },
    )
}

/// The buffers a signed safe JSON is finished in. For the request and the
/// signed transaction each: one slot per input and output, one entry's
/// details per input, and half the text's length for its decoded hex. One
/// cell per input and output for the storage mass.
pub struct SafeScratch<'s> {
    pub request_inputs: &'s mut [TransactionInput<'s>],
    pub request_outputs: &'s mut [TransactionOutput<'s>],
    pub request_details: &'s mut [EntryDetails],
    pub request_bytes: &'s mut [u8],
    pub inputs: &'s mut [TransactionInput<'s>],
    pub outputs: &'s mut [TransactionOutput<'s>],
    pub details: &'s mut [EntryDetails],
    pub bytes: &'s mut [u8],
    pub cells_in: &'s mut [Cell],
    pub cells_out: &'s mut [Cell],
}

/// Whether `a` and `b` are one transaction but for their unlocking
/// scripts, every coin's entry the same.
fn same_but_signed(
    a: &Transaction<'_>,
    a_details: &[EntryDetails],
    b: &Transaction<'_>,
    b_details: &[EntryDetails],
) -> bool {
    let same_input = |x: &TransactionInput<'_>, y: &TransactionInput<'_>| {
        x.previous_outpoint == y.previous_outpoint
            && x.sequence == y.sequence
            && x.sig_op_count == y.sig_op_count
            && x.compute_budget == y.compute_budget
            && x.utxo_entry == y.utxo_entry
    };
    a.version == b.version
        && a.lock_time == b.lock_time
        && a.subnetwork_id == b.subnetwork_id
        && a.gas == b.gas
        && a.payload == b.payload
        && a.inputs.len() == b.inputs.len()
        && a.inputs.iter().zip(b.inputs).all(|(x, y)| same_input(x, y))
        && a_details == b_details
        && a.outputs == b.outputs
}

/// Finish `signed`, a transaction a wallet signed and handed back in the
/// WASM SDK's safe JSON, against `request`, the safe JSON it was handed
/// ([`crate::request::safe_json`]): held to be the request's transaction,
/// coin entries included, unlocking scripts aside; every input carrying
/// one; its id its own; then its masses and fee checked as [`finish`] does.
/// The signatures are not verified, since a node verifies them on arrival:
/// what this guards is that the transaction is the one the app built.
///
/// # Errors
///
/// `RequestJson` and `ReplyJson` for text that does not read;
/// `NotTheRequest`; `Unsigned { input }`; `WrongId` for an id not its own;
/// then as [`finish`]: `Budget`, `FeeTooLow`, `Dust`,
/// `Mass`, `ScratchTooSmall`.
pub fn finalize_safe_json<'s>(
    request: &[u8],
    signed: &[u8],
    rates: &MassRates,
    scratch: &'s mut SafeScratch<'s>,
) -> Result<Finalized<'s>, ReplyError> {
    let SafeScratch {
        request_inputs,
        request_outputs,
        request_details,
        request_bytes,
        inputs,
        outputs,
        details,
        bytes,
        cells_in,
        cells_out,
    } = scratch;
    let req = safe_json::fill(
        request,
        request_inputs,
        request_details,
        request_outputs,
        request_bytes,
    )
    .map_err(ReplyError::RequestJson)?;
    let rep =
        safe_json::fill(signed, inputs, details, outputs, bytes).map_err(ReplyError::ReplyJson)?;
    let requested = safe_json::build(
        &req.header,
        &request_inputs[..req.inputs],
        &request_outputs[..req.outputs],
    );
    let inputs: &'s [TransactionInput<'s>] = &inputs[..rep.inputs];
    let outputs: &'s [TransactionOutput<'s>] = &outputs[..rep.outputs];
    let transaction = safe_json::build(&rep.header, inputs, outputs);
    if !same_but_signed(
        &requested,
        &request_details[..req.inputs],
        &transaction,
        &details[..rep.inputs],
    ) {
        return Err(ReplyError::NotTheRequest);
    }
    if let Some(input) = inputs.iter().position(|i| i.signature_script.is_empty()) {
        return Err(ReplyError::Unsigned { input });
    }
    if transaction_id(&transaction) != Some(rep.id) {
        return Err(ReplyError::WrongId);
    }
    // The request's entries, which the signed transaction's were held to.
    let entries = &request_details[..req.inputs];
    seal(
        transaction,
        |i| entries.get(i).is_some_and(|d| d.covenant_id.is_some()),
        rates,
        cells_in,
        cells_out,
    )
}

impl Finalized<'_> {
    /// Bytes [`Finalized::submit_json`] writes.
    pub fn submit_json_len(&self, allow_orphan: bool, shape: Shape) -> usize {
        rpc::submit_transaction_len(&self.transaction, self.storage_mass, allow_orphan, shape)
    }

    /// The `submitTransaction` request, as JSON in `shape` into `out`: its
    /// length. [`Shape::Rpc`] for a node's wRPC JSON port, [`Shape::Rest`]
    /// for kaspa-rest-server's `POST /transactions`.
    ///
    /// # Errors
    ///
    /// `Rpc(BufferTooSmall)`.
    pub fn submit_json(
        &self,
        allow_orphan: bool,
        shape: Shape,
        out: &mut [u8],
    ) -> Result<usize, ReplyError> {
        Ok(rpc::submit_transaction(
            &self.transaction,
            self.storage_mass,
            allow_orphan,
            shape,
            out,
        )?)
    }
}
