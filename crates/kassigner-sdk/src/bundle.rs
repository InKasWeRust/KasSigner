// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A rusty-kaspa bundle (PSKB) through a unit, as [`crate::request`] and
//! [`crate::reply`] handle a KSPT, under the same rules
//! ([`kassigner_protocol::check`]).
//!
//! [`prepare`] refuses what a unit would and writes the derivation hints
//! rusty-kaspa 2.1.0 leaves out; without one, a unit searches up to a thousand
//! keys a chain for an input. A `22'` input gets none: the app holds only its
//! address.
//!
//! [`crate::reply::finish`] writes the unlocking scripts, not rusty-kaspa's
//! finalizer, which knows no card and makes an input with no sequence final.
//! [`read_signed`], [`merge_signed`] and [`finalize_signed`] take a signed
//! bundle without its request.

use kassigner_kaspa::bip32_public::{ChildNumber, PUBLIC_KEY_SIZE};
use kassigner_kaspa::derivation::{COIN_TYPE, PURPOSE_MULTISIG, PURPOSE_SINGLE};
use kassigner_kaspa::mass::MassRates;
use kassigner_kaspa::pskb::signature::{
    self, hint_splices, hint_text_len, presence, signers, splices, text_len, Derivation, EditError,
    PartialSig,
};
use kassigner_kaspa::pskb::transaction::{
    self as pskb_tx, input_covenant_id, input_extras, ReadError,
};
use kassigner_kaspa::pskb::write::{key_source, key_source_max};
use kassigner_kaspa::pskb::{
    self, decode_envelope, emit, emitted_len, encode_envelope, Checked as Bundle, EmitError,
    EnvelopeError, Splice,
};
use kassigner_kaspa::script::unlock::PositionedSignature;
use kassigner_kaspa::script::{
    classify, kcc3_key, redeem_matches, schnorr_keys, ScriptClass, KCC3_REDEEM_LEN,
};
use kassigner_kaspa::tx::{Transaction, TransactionInput, TransactionOutput};
use kassigner_protocol::bundle as legacy;
use kassigner_protocol::card::savings::Savings;
use kassigner_protocol::check::{self, MultisigError, Signers};
use kassigner_protocol::profile::Profile;

use crate::reply::{finish, Finalized, FinishScratch, ReplyError, Spend};
use crate::watch::{Account, Group};

/// Why a bundle was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError {
    /// Not a `PSKB` envelope over hex, or an `out` too small for one.
    Envelope(EnvelopeError),
    /// The document does not read as a bundle.
    Read(ReadError),
    /// The document holds this many transactions; a unit answers one.
    NotOneTransaction { count: usize },
    /// An input fails a unit's rule, a signature's check among them.
    Check(check::Error),
    /// The whole transaction fails a consensus or mempool rule, or has no
    /// outputs ([`check::transaction`]).
    Transaction(check::TransactionError),
    /// A multisig a unit does not sign.
    Multisig(MultisigError),
    /// Input `input` is not one a unit spends: neither a key's nor a script
    /// hash's, or its redeem script is not its lock's, is of no kind a unit
    /// signs, or is missing at finishing.
    Redeem { input: usize },
    /// The hint for input `input` is refused: no such input, a hardened level,
    /// a chain past change, or a key BIP32 skips.
    Hint { input: usize },
    /// The bundle editor refused.
    Edit(EditError),
    /// The document could not be put back together.
    Emit(EmitError),
    /// The reply's transaction is not the request's.
    NotTheRequest,
    /// Finishing refused, as [`ReplyError`] says.
    Finish(ReplyError),
    /// A scratch buffer is too small, named by the field. `"profile"` means
    /// more inputs or outputs than the profile allows; `"inputs"` may mean that
    /// too.
    ScratchTooSmall(&'static str),
}

impl From<EnvelopeError> for BundleError {
    fn from(e: EnvelopeError) -> Self {
        BundleError::Envelope(e)
    }
}
impl From<ReadError> for BundleError {
    fn from(e: ReadError) -> Self {
        BundleError::Read(e)
    }
}
impl From<check::Error> for BundleError {
    fn from(e: check::Error) -> Self {
        BundleError::Check(e)
    }
}
impl From<check::TransactionError> for BundleError {
    fn from(e: check::TransactionError) -> Self {
        BundleError::Transaction(e)
    }
}
impl From<EditError> for BundleError {
    fn from(e: EditError) -> Self {
        BundleError::Edit(e)
    }
}
impl From<EmitError> for BundleError {
    fn from(e: EmitError) -> Self {
        BundleError::Emit(e)
    }
}
impl From<ReplyError> for BundleError {
    fn from(e: ReplyError) -> Self {
        BundleError::Finish(e)
    }
}

/// A derivation hint for one input: its watched key, and the seed's fingerprint
/// or zeros (a unit reads only the path).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hint<'a> {
    /// A `44'` account's `chain`/`index`.
    Account {
        account: &'a Account,
        chain: u32,
        index: u32,
        fingerprint: [u8; 4],
    },
    /// A `45'` group's `cosigner`/`chain`/`index`: an entry per key, each with
    /// its fingerprint from `fingerprints`, zeros past its end.
    Group {
        group: &'a Group,
        cosigner: u32,
        chain: u32,
        index: u32,
        fingerprints: &'a [[u8; 4]],
    },
}

/// The most bytes a derivation member's value takes: a six-level `KeySource`
/// ([`key_source_max`]), a group's path being the longest.
pub const DERIVATION_MAX: usize = key_source_max(6);

/// The most keys one hint names: a group's.
pub const HINT_KEYS: usize = kassigner_protocol::check::MAX_MULTISIG_KEYS;

/// Upstream's `KeySource` ([`key_source`]) of `purpose`'s account, `levels`
/// below it and `fingerprint`, into `out`: its length.
fn derivation_value(
    purpose: u32,
    levels: &[u32],
    fingerprint: &[u8; 4],
    out: &mut [u8; DERIVATION_MAX],
) -> Result<usize, BundleError> {
    const HARD: u32 = 0x8000_0000;
    let mut path = [0u32; 6];
    let n = 3 + levels.len();
    let path = path
        .get_mut(..n)
        .ok_or(BundleError::ScratchTooSmall("path"))?;
    path[..3].copy_from_slice(&[purpose | HARD, COIN_TYPE | HARD, HARD]);
    path[3..].copy_from_slice(levels);
    key_source(fingerprint, path, out).map_err(|_| BundleError::ScratchTooSmall("derivation"))
}

/// `hint`'s keys and values into `keys`, `values` and `lens`, in the watched
/// thing's order: how many.
pub(crate) fn entries(
    hint: &Hint<'_>,
    input: usize,
    keys: &mut [[u8; PUBLIC_KEY_SIZE]],
    values: &mut [[u8; DERIVATION_MAX]],
    lens: &mut [usize],
) -> Result<usize, BundleError> {
    let soft = |levels: &[u32]| levels.iter().all(|&l| l & 0x8000_0000 == 0);
    match *hint {
        Hint::Account {
            account,
            chain,
            index,
            fingerprint,
        } => {
            if !soft(&[chain, index]) || chain > 1 {
                return Err(BundleError::Hint { input });
            }
            let key = account
                .key()
                .derive_child(ChildNumber(chain))
                .and_then(|k| k.derive_child(ChildNumber(index)))
                .map_err(|_| BundleError::Hint { input })?;
            *keys
                .first_mut()
                .ok_or(BundleError::ScratchTooSmall("keys"))? = key.public_key;
            let value = values
                .first_mut()
                .ok_or(BundleError::ScratchTooSmall("values"))?;
            *lens
                .first_mut()
                .ok_or(BundleError::ScratchTooSmall("lens"))? =
                derivation_value(PURPOSE_SINGLE, &[chain, index], &fingerprint, value)?;
            Ok(1)
        }
        Hint::Group {
            group,
            cosigner,
            chain,
            index,
            fingerprints,
        } => {
            if !soft(&[cosigner, chain, index]) || chain > 1 {
                return Err(BundleError::Hint { input });
            }
            let mut n = 0;
            for (k, account) in group.keys().iter().enumerate() {
                let key = account
                    .derive_child(ChildNumber(cosigner))
                    .and_then(|x| x.derive_child(ChildNumber(chain)))
                    .and_then(|x| x.derive_child(ChildNumber(index)))
                    .map_err(|_| BundleError::Hint { input })?;
                *keys
                    .get_mut(n)
                    .ok_or(BundleError::ScratchTooSmall("keys"))? = key.public_key;
                let fingerprint = fingerprints.get(k).copied().unwrap_or([0; 4]);
                let value = values
                    .get_mut(n)
                    .ok_or(BundleError::ScratchTooSmall("values"))?;
                *lens
                    .get_mut(n)
                    .ok_or(BundleError::ScratchTooSmall("lens"))? = derivation_value(
                    PURPOSE_MULTISIG,
                    &[cosigner, chain, index],
                    &fingerprint,
                    value,
                )?;
                n += 1;
            }
            Ok(n)
        }
    }
}

/// The caller's buffers a bundle is worked in, sized by the envelope and the
/// profile.
pub struct Scratch<'s> {
    /// The decoded document:
    /// [`decoded_len`](kassigner_kaspa::pskb::decoded_len) of the envelope,
    /// plus 15 bytes for a `payload` a legacy bundle lacks.
    pub doc: &'s mut [u8],
    /// One per input and output of the transaction.
    pub inputs: &'s mut [TransactionInput<'s>],
    pub outputs: &'s mut [TransactionOutput<'s>],
    /// Decoded scripts and payload: a quarter of the document.
    pub bytes: &'s mut [u8],
    /// A redeem script: the profile's `max_redeem`.
    pub redeem: &'s mut [u8],
    /// Member text the editor writes.
    pub text: &'s mut [u8],
    /// One per member written, two per signature.
    pub splices: &'s mut [Splice<'s>],
    /// The edited document: the decoded one and the text.
    pub json: &'s mut [u8],
}

/// What [`prepare`] made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// Bytes of the envelope in `out`.
    pub len: usize,
    /// Inputs of the transaction.
    pub inputs: usize,
    /// Signatures the unit's reply will carry in all.
    pub signatures: usize,
}

/// The one transaction of `doc`, checked.
fn one(doc: &[u8]) -> Result<Bundle<'_>, BundleError> {
    let bundle = pskb::check(doc).map_err(ReadError::from)?;
    let count = bundle.transactions();
    if count != 1 {
        return Err(BundleError::NotOneTransaction { count });
    }
    Ok(bundle)
}

/// The signatures input `i` needs, and whether its redeem script is a KCC-3 one
/// the unit has yet to supply.
fn needs(
    tx: &Transaction<'_>,
    extras_redeem: &[u8],
    i: usize,
) -> Result<(usize, bool), BundleError> {
    let spk = tx.inputs[i].utxo_entry.script_public_key;
    match classify(&spk) {
        ScriptClass::PubKey => Ok((1, false)),
        ScriptClass::ScriptHash => {
            if extras_redeem.is_empty() {
                // KCC-3's, which the unit supplies: one signature.
                return Ok((1, true));
            }
            if !redeem_matches(&spk, extras_redeem) {
                return Err(BundleError::Redeem { input: i });
            }
            if let Some(ms) = check::multisig(extras_redeem).map_err(BundleError::Multisig)? {
                return Ok((usize::from(ms.required), false));
            }
            if kcc3_key(extras_redeem).is_some() || Savings::from_program(extras_redeem).is_ok() {
                return Ok((1, false));
            }
            Err(BundleError::Redeem { input: i })
        }
        _ => Err(BundleError::Redeem { input: i }),
    }
}

/// Prepare `bundle`, a wallet's `PSKB` envelope, for a unit: checked, `hints`
/// written into their inputs, the envelope into `out`. Its length and what the
/// unit will sign.
///
/// # Errors
///
/// `Envelope`, `Read` and `NotOneTransaction` for what does not read;
/// `Transaction`, `Check`, `Multisig`, `Redeem` and `Hint` for what is refused;
/// `Envelope(BufferTooSmall)` for a short `out`; the rest as [`BundleError`].
/// Nothing is written to `out` on an error.
pub fn prepare<'s>(
    bundle: &[u8],
    hints: &[(usize, Hint<'_>)],
    profile: &Profile,
    scratch: &'s mut Scratch<'s>,
    out: &mut [u8],
) -> Result<Prepared, BundleError> {
    let Scratch {
        doc,
        inputs,
        outputs,
        bytes,
        redeem,
        text,
        splices,
        json,
    } = scratch;
    let (checked, tx) = transaction_of(bundle, doc, inputs, outputs, bytes)?;
    let doc: &'s [u8] = checked.doc();
    if tx.inputs.len() > profile.max_inputs || tx.outputs.len() > profile.max_outputs {
        return Err(BundleError::ScratchTooSmall("profile"));
    }
    // The whole transaction first, as a unit checks it on arrival: its
    // own rules, then every covenant binding against the coins the inputs
    // spend (upstream's `CovenantsContext::from_tx`).
    check::transaction(&tx)?;
    for i in 0..tx.inputs.len() {
        input_covenant_id(checked, 0, i)?;
    }
    tx.check_covenant_ids_of(|i| input_covenant_id(checked, 0, i).ok().flatten())
        .map_err(|e| BundleError::Transaction(check::TransactionError::Consensus(e)))?;
    let mut signatures = 0usize;
    for i in 0..tx.inputs.len() {
        let extras = input_extras(checked, 0, i, redeem)?;
        check::sighash_all(extras.sighash_type, i)?;
        // The sequence, and a card's own rules: its input with no sequence is
        // final, which its program refuses.
        check::sequence(&tx, i)?;
        check::card(&tx, i, extras.redeem)?;
        let (need, _) = needs(&tx, extras.redeem, i)?;
        check::sig_ops(&tx, i, extras.redeem)?;
        check::pskb_signatures(
            checked,
            &tx,
            i,
            tx.inputs[i].utxo_entry.script_public_key,
            extras.redeem,
        )?;
        signatures += need;
    }
    // The hints, a member per key, through the editor.
    let mut keys = [[0u8; PUBLIC_KEY_SIZE]; HINT_KEYS];
    let mut values = [[0u8; DERIVATION_MAX]; HINT_KEYS];
    let mut lens = [0usize; HINT_KEYS];
    let mut written = 0usize;
    // Copied into `text` first: the editor borrows them while the splices live.
    let mut at = 0usize;
    let mut members = 0usize;
    for &(input, ref hint) in hints {
        if input >= tx.inputs.len() {
            return Err(BundleError::Hint { input });
        }
        let k = entries(hint, input, &mut keys, &mut values, &mut lens)?;
        for j in 0..k {
            let room = text
                .get_mut(at..at + PUBLIC_KEY_SIZE + lens[j])
                .ok_or(BundleError::ScratchTooSmall("text"))?;
            room[..PUBLIC_KEY_SIZE].copy_from_slice(&keys[j]);
            room[PUBLIC_KEY_SIZE..].copy_from_slice(&values[j][..lens[j]]);
            at += PUBLIC_KEY_SIZE + lens[j];
            members += 1;
        }
    }
    let (held, free) = text.split_at_mut(at);
    let held: &'s [u8] = held;
    // The level 0 hints borrow the held text: a second pass, same order.
    let mut level0 = [signature::Hint {
        input: 0,
        public_key: &[0; PUBLIC_KEY_SIZE],
        derivation: &[],
    }; HINT_KEYS * 32];
    if members > level0.len() {
        return Err(BundleError::ScratchTooSmall("hints"));
    }
    let mut at = 0usize;
    let mut m = 0usize;
    for &(input, ref hint) in hints {
        let k = entries(hint, input, &mut keys, &mut values, &mut lens)?;
        for &len in &lens[..k] {
            let key = <&[u8; PUBLIC_KEY_SIZE]>::try_from(&held[at..at + PUBLIC_KEY_SIZE])
                .map_err(|_| BundleError::ScratchTooSmall("text"))?;
            level0[m] = signature::Hint {
                input,
                public_key: key,
                derivation: &held[at + PUBLIC_KEY_SIZE..at + PUBLIC_KEY_SIZE + len],
            };
            at += PUBLIC_KEY_SIZE + len;
            m += 1;
        }
    }
    if free.len() < hint_text_len(&level0[..m]) {
        return Err(BundleError::ScratchTooSmall("text"));
    }
    let e = hint_splices(checked, 0, &level0[..m], free, splices)?;
    written += e;
    let edits = &mut splices[..written];
    let need = emitted_len(doc, edits)?;
    let json = json
        .get_mut(..need)
        .ok_or(BundleError::ScratchTooSmall("json"))?;
    emit(doc, edits, json)?;
    let len = encode_envelope(json, out)?;
    Ok(Prepared {
        len,
        inputs: tx.inputs.len(),
        signatures,
    })
}

/// What a checked bundle reply holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checked {
    /// Signatures on the reply, all verified.
    pub signatures: usize,
    /// The signer count a unit shows beside a multisig reply.
    pub signers: Option<Signers>,
    /// Whether every input has what its script needs.
    pub complete: bool,
}

/// The buffers a reply and its request are read in.
pub struct ReadScratch<'s> {
    /// The request's side.
    pub request: Scratch<'s>,
    /// The reply's document and transaction.
    pub doc: &'s mut [u8],
    pub inputs: &'s mut [TransactionInput<'s>],
    pub outputs: &'s mut [TransactionOutput<'s>],
    pub bytes: &'s mut [u8],
    pub redeem: &'s mut [u8],
}

/// `envelope` into `doc` as a unit decodes one, a bundle from the v1.0.7
/// companion turned into upstream's shape ([`kassigner_protocol::bundle`]):
/// the document's length.
fn decode(envelope: &[u8], doc: &mut [u8]) -> Result<usize, BundleError> {
    let n = decode_envelope(envelope, doc)?;
    let lex = |e: pskb::LexError| BundleError::Read(ReadError::from(pskb::ParseError::from(e)));
    legacy::upstream_names(&mut doc[..n]).map_err(lex)?;
    legacy::fill_payload(doc, n).map_err(|e| match e {
        legacy::FillError::NoRoom { .. } => BundleError::ScratchTooSmall("doc"),
        legacy::FillError::Lex(e) => lex(e),
    })
}

/// `envelope`'s one transaction, decoded into `doc`, `inputs`, `outputs` and
/// `bytes` as a unit decodes it, unverified, with its bundle.
///
/// # Errors
///
/// `Envelope`, `Read`, `NotOneTransaction`, `ScratchTooSmall("doc")`.
pub fn transaction_of<'s>(
    envelope: &[u8],
    doc: &'s mut [u8],
    inputs: &'s mut [TransactionInput<'s>],
    outputs: &'s mut [TransactionOutput<'s>],
    bytes: &'s mut [u8],
) -> Result<(Bundle<'s>, Transaction<'s>), BundleError> {
    let n = decode(envelope, doc)?;
    let doc: &'s [u8] = &doc[..n];
    let checked = one(doc)?;
    let filled = pskb_tx::fill(doc, 0, inputs, outputs, bytes)?;
    let tx = pskb_tx::build(
        &filled.header,
        &inputs[..filled.inputs],
        &outputs[..filled.outputs],
    );
    Ok((checked, tx))
}

/// Read `reply` against `request`, both envelopes: the same transaction,
/// members verified, signers counted.
///
/// # Errors
///
/// As [`prepare`] for what does not read, `Multisig` and `Redeem`;
/// `NotTheRequest`; `Check(SighashNotAll)`; `Check(BadSignature)` for a member
/// that does not verify or is not by the script's key; the rest as
/// [`BundleError`].
pub fn read<'s>(
    request: &[u8],
    reply: &[u8],
    profile: &Profile,
    scratch: &'s mut ReadScratch<'s>,
) -> Result<Checked, BundleError> {
    let ReadScratch {
        request: req_scratch,
        doc,
        inputs,
        outputs,
        bytes,
        redeem,
    } = scratch;
    let (_, tx) = transaction_of(
        request,
        req_scratch.doc,
        req_scratch.inputs,
        req_scratch.outputs,
        req_scratch.bytes,
    )?;
    let (checked, theirs) = transaction_of(reply, doc, inputs, outputs, bytes)?;
    if theirs != tx {
        return Err(BundleError::NotTheRequest);
    }
    if tx.inputs.len() > profile.max_inputs {
        return Err(BundleError::ScratchTooSmall("profile"));
    }
    let mut signatures = 0usize;
    let mut complete = true;
    for i in 0..tx.inputs.len() {
        let extras = input_extras(checked, 0, i, redeem)?;
        check::sighash_all(extras.sighash_type, i)?;
        let spk = tx.inputs[i].utxo_entry.script_public_key;
        check::pskb_signatures(checked, &tx, i, spk, extras.redeem)?;
        let (need, _) = needs(&tx, extras.redeem, i)?;
        let mut have = 0usize;
        signers(checked, 0, i, |_| {
            have += 1;
            true
        })?;
        signatures += have;
        if have < need {
            complete = false;
        }
    }
    Ok(Checked {
        signatures,
        signers: check::pskb_signers(checked, &tx, redeem),
        complete,
    })
}

/// [`read`] of `signed`, a bundle signed already, as its own request.
///
/// # Errors
///
/// As [`read`].
pub fn read_signed<'s>(
    signed: &[u8],
    profile: &Profile,
    scratch: &'s mut ReadScratch<'s>,
) -> Result<Checked, BundleError> {
    read(signed, signed, profile, scratch)
}

/// Merge `copies` of one signed bundle into one envelope in `out`: its length.
/// Members are verified over the first copy's transaction; a key that signed
/// several copies is held once.
///
/// # Errors
///
/// `Check(BadSignature)` for a copy of another transaction;
/// `NotOneTransaction { count: 0 }` for none; the rest as [`merge`].
pub fn merge_signed<'s>(
    copies: &[&[u8]],
    profile: &Profile,
    scratch: &'s mut ReadScratch<'s>,
    merging: &'s mut MergeScratch<'s>,
    out: &mut [u8],
) -> Result<usize, BundleError> {
    let first = copies
        .first()
        .ok_or(BundleError::NotOneTransaction { count: 0 })?;
    merge_into(first, copies, true, profile, scratch, merging, out)
}

/// [`finalize`] of `signed`, a complete signed bundle, as its own request.
///
/// # Errors
///
/// As [`finalize`].
pub fn finalize_signed<'s>(
    signed: &[u8],
    profile: &Profile,
    rates: &MassRates,
    scratch: &'s mut FinalScratch<'s>,
) -> Result<Finalized<'s>, BundleError> {
    finalize(signed, signed, profile, rates, scratch)
}

/// The buffers a merge works in, beside a [`ReadScratch`].
pub struct MergeScratch<'s> {
    /// One per signature across the replies.
    pub keys: &'s mut [[u8; PUBLIC_KEY_SIZE]],
    pub signatures: &'s mut [[u8; pskb::SIGNATURE_LEN]],
    pub partial: &'s mut [PartialSig<'s>],
    /// One per supplied redeem script (KCC-3).
    pub redeems: &'s mut [SuppliedRedeem],
}

/// A redeem script a reply supplied where the request had none, as the value
/// that replaces its `null`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuppliedRedeem {
    pub input: usize,
    pub value: [u8; 2 + 2 * KCC3_REDEEM_LEN],
}

impl SuppliedRedeem {
    /// An empty slot.
    pub const EMPTY: SuppliedRedeem = SuppliedRedeem {
        input: 0,
        value: [0; 2 + 2 * KCC3_REDEEM_LEN],
    };
}

/// Merge `replies` to `request` into one envelope in `out`: its length. Members
/// are verified over the request's transaction; a KCC-3 redeem script a reply
/// supplies goes in with them.
///
/// # Errors
///
/// As [`read`] for what does not read and for `Check`, a reply to another
/// transaction being `Check(BadSignature)`; `Redeem` for a supplied redeem
/// script the coin does not commit to; `Edit(SameKeyTwice)` for a key signing
/// twice; the rest as [`BundleError`].
pub fn merge<'s>(
    request: &[u8],
    replies: &[&[u8]],
    profile: &Profile,
    scratch: &'s mut ReadScratch<'s>,
    merging: &'s mut MergeScratch<'s>,
    out: &mut [u8],
) -> Result<usize, BundleError> {
    merge_into(request, replies, false, profile, scratch, merging, out)
}

/// What [`merge`] and [`merge_signed`] share: with `once`, a member for a key
/// already held is left out, not refused.
fn merge_into<'s>(
    request: &[u8],
    replies: &[&[u8]],
    once: bool,
    profile: &Profile,
    scratch: &'s mut ReadScratch<'s>,
    merging: &'s mut MergeScratch<'s>,
    out: &mut [u8],
) -> Result<usize, BundleError> {
    let ReadScratch {
        request: req_scratch,
        doc,
        redeem,
        ..
    } = scratch;
    let Scratch {
        doc: req_doc,
        inputs,
        outputs,
        bytes,
        text,
        splices: splices_out,
        json,
        ..
    } = req_scratch;
    let MergeScratch {
        keys,
        signatures,
        partial,
        redeems,
    } = merging;
    let (checked, tx) = transaction_of(request, req_doc, inputs, outputs, bytes)?;
    let ni = tx.inputs.len();
    if ni > profile.max_inputs {
        return Err(BundleError::ScratchTooSmall("profile"));
    }
    // Copied out: each reply is decoded into the one buffer in turn. A reply to
    // another request fails to verify.
    let mut n = 0usize;
    let mut supplied = 0usize;
    for reply in replies {
        let m = decode(reply, doc)?;
        let rdoc: &[u8] = &doc[..m];
        let rchecked = one(rdoc)?;
        for i in 0..ni {
            let mine = input_extras(checked, 0, i, redeem)?;
            let unsupplied = mine.redeem_at.is_some() && mine.redeem.is_empty();
            let extras = input_extras(rchecked, 0, i, redeem)?;
            check::sighash_all(extras.sighash_type, i)?;
            let spk = tx.inputs[i].utxo_entry.script_public_key;
            check::pskb_signatures(rchecked, &tx, i, spk, extras.redeem)?;
            let again = redeems[..supplied].iter().any(|r| r.input == i);
            if unsupplied && !again && !extras.redeem.is_empty() {
                // A supplied redeem script, hex in quotes for the request's
                // `null`: a KCC-3 script the coin commits to, or the reply is
                // refused.
                if extras.redeem.len() != KCC3_REDEEM_LEN || !redeem_matches(&spk, extras.redeem) {
                    return Err(BundleError::Redeem { input: i });
                }
                let slot = redeems
                    .get_mut(supplied)
                    .ok_or(BundleError::ScratchTooSmall("redeems"))?;
                const HEX: &[u8; 16] = b"0123456789abcdef";
                slot.value[0] = b'"';
                for (k, &b) in extras.redeem.iter().enumerate() {
                    slot.value[1 + 2 * k] = HEX[usize::from(b >> 4)];
                    slot.value[2 + 2 * k] = HEX[usize::from(b & 0x0f)];
                }
                slot.value[1 + 2 * KCC3_REDEEM_LEN] = b'"';
                slot.input = i;
                supplied += 1;
            }
            let got = gather(rchecked, i, keys, signatures, n)?;
            let slots = partial
                .get_mut(..n + got)
                .ok_or(BundleError::ScratchTooSmall("partial"))?;
            let mut kept = n;
            for k in n..n + got {
                if once {
                    let key = keys[k];
                    let held = presence(checked, 0, i, &key)?.signed
                        || (0..kept).any(|j| slots[j].input == i && keys[j] == key);
                    if held {
                        continue;
                    }
                    keys[kept] = key;
                    signatures[kept] = signatures[k];
                }
                slots[kept].input = i;
                kept += 1;
            }
            n = kept;
        }
    }
    let keys: &'s [[u8; PUBLIC_KEY_SIZE]] = keys;
    let signatures: &'s [[u8; pskb::SIGNATURE_LEN]] = signatures;
    for k in 0..n {
        partial[k].public_key = &keys[k];
        partial[k].signature = &signatures[k];
        partial[k].derivation = Derivation::Null;
    }
    let sigs: &[PartialSig<'s>] = &partial[..n];
    let needed = text_len(sigs);
    if text.len() < needed {
        return Err(BundleError::ScratchTooSmall("text"));
    }
    let (text, _) = text.split_at_mut(needed);
    let mut e = splices(checked, 0, sigs, text, splices_out)?;
    let redeems: &'s [SuppliedRedeem] = redeems;
    for r in &redeems[..supplied] {
        let at = input_extras(checked, 0, r.input, redeem)?
            .redeem_at
            .ok_or(BundleError::Redeem { input: r.input })?;
        let s = splices_out
            .get_mut(e)
            .ok_or(BundleError::ScratchTooSmall("splices"))?;
        *s = Splice::replace(at, &r.value);
        e += 1;
    }
    let edits = &mut splices_out[..e];
    for i in 1..edits.len() {
        let mut j = i;
        while j > 0 && edits[j - 1].at > edits[j].at {
            edits.swap(j - 1, j);
            j -= 1;
        }
    }
    let doc: &[u8] = checked.doc();
    let need = emitted_len(doc, edits)?;
    let json = json
        .get_mut(..need)
        .ok_or(BundleError::ScratchTooSmall("json"))?;
    emit(doc, edits, json)?;
    Ok(encode_envelope(json, out)?)
}

/// Input `i`'s keys and Schnorr signatures into `keys` and `signatures` from
/// `at` on: how many.
///
/// # Errors
///
/// `Check(BadSignature)` for a member that is not a Schnorr signature; `Edit`
/// for one that does not read; `ScratchTooSmall("signatures")`.
fn gather(
    bundle: Bundle<'_>,
    i: usize,
    keys: &mut [[u8; PUBLIC_KEY_SIZE]],
    signatures: &mut [[u8; pskb::SIGNATURE_LEN]],
    at: usize,
) -> Result<usize, BundleError> {
    let mut n = at;
    let mut trouble = None;
    signers(bundle, 0, i, |key| {
        let held = match presence(bundle, 0, i, &key) {
            Ok(p) => p,
            Err(e) => {
                trouble = Some(BundleError::Edit(e));
                return false;
            }
        };
        let Some(sig) = held.schnorr else {
            trouble = Some(BundleError::Check(check::Error::BadSignature { input: i }));
            return false;
        };
        if n >= keys.len() || n >= signatures.len() {
            trouble = Some(BundleError::ScratchTooSmall("signatures"));
            return false;
        }
        keys[n] = key;
        signatures[n] = sig;
        n += 1;
        true
    })?;
    if let Some(e) = trouble {
        return Err(e);
    }
    Ok(n - at)
}

/// The buffers a bundle is finished in.
pub struct FinalScratch<'s> {
    /// The request's document and transaction, which the reply's is held to.
    pub request_doc: &'s mut [u8],
    pub request_inputs: &'s mut [TransactionInput<'s>],
    pub request_outputs: &'s mut [TransactionOutput<'s>],
    pub request_bytes: &'s mut [u8],
    /// The reply's document and transaction.
    pub doc: &'s mut [u8],
    pub inputs: &'s mut [TransactionInput<'s>],
    pub outputs: &'s mut [TransactionOutput<'s>],
    pub bytes: &'s mut [u8],
    /// Every input's redeem script in turn, `max_redeem` bytes each.
    pub redeems: &'s mut [u8],
    /// One per input: redeem script length, sighash type.
    pub redeem_lens: &'s mut [usize],
    pub sighash: &'s mut [u8],
    /// One per signature across the inputs.
    pub keys: &'s mut [[u8; PUBLIC_KEY_SIZE]],
    pub signature_bytes: &'s mut [[u8; pskb::SIGNATURE_LEN]],
    pub signatures: &'s mut [PositionedSignature<'s>],
    /// One per input.
    pub ranges: &'s mut [(usize, usize)],
    pub spends: &'s mut [Spend<'s>],
    pub finish: FinishScratch<'s, 's>,
}

/// Finish `reply`, a complete reply to `request`, checked as [`read`] checks
/// it, through [`crate::reply::finish`], each signature at its key's position
/// in the script.
///
/// # Errors
///
/// As [`read`]; `Redeem` also for a KCC-3 input with no redeem script supplied;
/// `Finish(Signatures)` for an input short of its threshold; `Finish(Mass)`
/// for a transaction that is not version 0;
/// `ScratchTooSmall("inputs")`; the rest as [`BundleError`] and [`ReplyError`].
pub fn finalize<'s>(
    request: &[u8],
    reply: &[u8],
    profile: &Profile,
    rates: &MassRates,
    scratch: &'s mut FinalScratch<'s>,
) -> Result<Finalized<'s>, BundleError> {
    let FinalScratch {
        request_doc,
        request_inputs,
        request_outputs,
        request_bytes,
        doc,
        inputs,
        outputs,
        bytes,
        redeems,
        redeem_lens,
        sighash,
        keys,
        signature_bytes,
        signatures,
        ranges,
        spends,
        finish: finishing,
    } = scratch;
    let n = decode(reply, doc)?;
    let doc: &'s [u8] = &doc[..n];
    let checked = one(doc)?;
    let filled = pskb_tx::fill(doc, 0, inputs, outputs, bytes)?;
    let (ni, no) = (filled.inputs, filled.outputs);
    let per = profile.max_redeem;
    if ni > profile.max_inputs
        || spends.len() < ni
        || ranges.len() < ni
        || redeem_lens.len() < ni
        || sighash.len() < ni
        || redeems.len() < ni * per
    {
        return Err(BundleError::ScratchTooSmall("inputs"));
    }
    // Pass one: each input's redeem script, sighash type and members.
    let mut k = 0usize;
    for i in 0..ni {
        let extras = input_extras(checked, 0, i, &mut redeems[i * per..(i + 1) * per])?;
        redeem_lens[i] = extras.redeem.len();
        sighash[i] = extras.sighash_type;
        let got = gather(checked, i, keys, signature_bytes, k)?;
        ranges[i] = (k, k + got);
        k += got;
    }
    // Pass two: each signature's position in its script, each input's spend.
    let redeems: &'s [u8] = redeems;
    let signature_bytes: &'s [[u8; pskb::SIGNATURE_LEN]] = signature_bytes;
    let header = pskb_tx::build(&filled.header, &[], &[]);
    // Version 0 only: a bundle has no field for the compute budget a
    // version 1 input commits, so none finishes to a transaction a node
    // takes.
    if header.version != 0 {
        return Err(BundleError::Finish(ReplyError::Mass));
    }
    let tx = pskb_tx::build(&filled.header, &inputs[..ni], &outputs[..no]);
    let (asked, requested) = transaction_of(
        request,
        request_doc,
        request_inputs,
        request_outputs,
        request_bytes,
    )?;
    if tx != requested {
        return Err(BundleError::NotTheRequest);
    }
    for i in 0..ni {
        let redeem = &redeems[i * per..i * per + redeem_lens[i]];
        let spk = tx.inputs[i].utxo_entry.script_public_key;
        // Verified over the request's transaction, as in `read`.
        check::sighash_all(sighash[i], i)?;
        check::pskb_signatures(checked, &tx, i, spk, redeem)?;
        let (from, to) = ranges[i];
        for m in from..to {
            let key = &keys[m];
            // A key the script lacks is refused by the check above; the
            // refusals here are never reached.
            let foreign = BundleError::Check(check::Error::BadSignature { input: i });
            let position = match classify(&spk) {
                ScriptClass::PubKey if spk.script.get(1..33) == Some(&key[1..]) => 0,
                ScriptClass::ScriptHash => schnorr_keys(redeem)
                    .position(|x| x == &key[1..])
                    .ok_or(foreign)?,
                _ => return Err(foreign),
            };
            let slot = signatures
                .get_mut(m)
                .ok_or(BundleError::ScratchTooSmall("signatures"))?;
            *slot = PositionedSignature {
                position: position as u8,
                sighash_type: sighash[i],
                signature: &signature_bytes[m],
            };
        }
        let (need, unsupplied) = needs(&tx, redeem, i)?;
        if unsupplied {
            return Err(BundleError::Redeem { input: i });
        }
        spends[i] = Spend {
            need,
            redeem,
            signatures: &[],
            // The request's entry: the app's own, where a reply's could
            // say anything.
            bound: input_covenant_id(asked, 0, i)?.is_some(),
        };
    }
    let signatures: &'s [PositionedSignature<'s>] = signatures;
    for i in 0..ni {
        let (from, to) = ranges[i];
        spends[i].signatures = &signatures[from..to];
    }
    let outputs: &'s [TransactionOutput<'s>] = &outputs[..no];
    let FinishScratch {
        unlocks,
        unlock_lens,
        cells_in,
        cells_out,
    } = finishing;
    Ok(finish(
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
    )?)
}
