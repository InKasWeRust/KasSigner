// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a unit checks without a key: a request on arrival, a reply when it
//! is read back. The device's policy over level 0's facts, kept here so a
//! companion applies the same rules before a unit sees a request and checks
//! a reply the same way.
//!
//! - [`transaction`]: rusty-kaspa 2.1.0's rules on the whole transaction, in
//!   a node's order: checks in isolation, standard outputs, the fee and the
//!   covenant bindings.
//! - [`multisig`]: at most [`MAX_MULTISIG_KEYS`] keys, a threshold of at
//!   least one and no key twice ([`crate::group::repeated_key`]); Kaspa
//!   allows twenty keys and a threshold of zero. This bounds the keys a
//!   script names, not the signatures an input carries (a profile's
//!   `max_sigs_per_input`): a 2-of-6 is refused.
//! - [`sig_ops`]: the signature operations a version 0 input commits, below.
//! - [`sequence`]: 0 or final (`u64::MAX`) only. Any other is a relative
//!   lock or bits consensus does not read; the signature covers every
//!   input's sequence and no page shows a lock, so it is refused rather than
//!   signed unseen.
//! - [`card`]: a Time-Locked Savings card's lock time and finality.
//! - [`kspt_signatures`], [`pskb_signatures`]: every signature a request
//!   already holds, anyone's, checked against the key the input's script
//!   names before any page is shown. A bundle's key only finds which script
//!   key it is; [`bip340::verify`] refuses one that is not a point.
//! - [`verify_kspt`], [`same_transaction`]: a reply read back against the
//!   transaction from the request, never the reply's own, which would verify
//!   against itself.
//! - [`Signers`]: the count shown beside a multisig reply's frames.
//!
//! # Signature operations
//!
//! In a version 0 transaction a multisig input must commit one signature
//! operation per key, as rusty-kaspa 2.1.0's wallet writes
//! (`wallet/core/src/account/variants/multisig.rs`): the engine spends one
//! per signature check, a failed one included, so with fewer some sets of
//! cosigners can never spend it. A single key's input, or KCC-3's redeem
//! (`<P> OP_CHECKSIG` behind a script hash), must commit one:
//! its check costs a signature operation's units (`consume_sig_op_cost`),
//! and with none it has only the free allowance, one compute-budget unit
//! less one (`free_script_units_per_input`), so it can never be spent.
//!
//! The version 0 signature hash covers the count, so no one can raise it
//! after anyone signed. From version 1 a compute budget the hash does not
//! cover takes its place: nothing to check. Every input is checked, the
//! unit's or not: a transaction with an input that can never be spent can
//! never be accepted.

use kassigner_kaspa::bip32_public::PUBLIC_KEY_SIZE;
use kassigner_kaspa::bip340;
use kassigner_kaspa::constants::MAX_TX_IN_SEQUENCE_NUM;
use kassigner_kaspa::pskb::signature::{presence, signers, EditError};
use kassigner_kaspa::pskb::transaction::{build, fill, input_extras, ReadError};
use kassigner_kaspa::pskb::Checked;
use kassigner_kaspa::script::{
    classify, kcc3_key, multisig_shape, parse_multisig, redeem_matches, schnorr_keys, Disassembler,
    Multisig, ScriptClass,
};
use kassigner_kaspa::sighash::{schnorr_signature_hash, SIG_HASH_ALL};
use kassigner_kaspa::tx::{
    NonStandardError, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput,
    TxRuleError,
};

use crate::card::savings::{Savings, SIG_OP_COUNT};
use crate::group::repeated_key;
use crate::kspt::{self, SIGNATURE_LEN};
use crate::profile::Profile;

/// Most keys in a multisig a unit signs, and the smallest threshold is one.
pub const MAX_MULTISIG_KEYS: usize = 5;

/// Receiving keys the unit derives up front (the bank) to match an input
/// against.
pub const RECEIVE_DEPTH: u32 = 20;

/// Change keys in the bank.
pub const CHANGE_DEPTH: u32 = 5;

/// How far the keyring searches each chain, a key at a time, for an input
/// with no derivation that matches no bank key, before calling it not its
/// own. A rusty-kaspa 2.1.0 wallet's PSKB names no derivation, so with the
/// bank alone a wallet past [`RECEIVE_DEPTH`] addresses or [`CHANGE_DEPTH`]
/// payments would be refused. A full miss on both chains takes some twenty
/// seconds on the S3, ten milliseconds a key; a host can force that per
/// input it sends, for only a refusal.
pub const SEARCH_DEPTH: u32 = 1000;

/// The search alternates chains in batches of this many keys, so it reaches
/// change keys without first going through the whole receive chain.
pub const SEARCH_BATCH: u32 = 100;

const _: () = assert!(RECEIVE_DEPTH <= SEARCH_DEPTH && CHANGE_DEPTH <= SEARCH_DEPTH);

/// Why a multisig is not one a unit signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultisigError {
    /// A threshold of zero, or more than [`MAX_MULTISIG_KEYS`] keys.
    Unsupported { required: u8, keys: u8 },
    /// The key at `position` repeats an earlier one: the M of N counts it
    /// twice, and a unit would sign one of its places but no unit the other.
    /// Refused whether or not the key is the unit's.
    Repeated { position: usize },
    /// A multisig not in the standard form: a number or a key in a longer
    /// push than its shortest, or ended by `OP_CHECKMULTISIGVERIFY`. The
    /// engine runs it anyway, and its threshold, count and repeated keys
    /// would go unread here. Refused whoever's keys it holds.
    NotStandard,
}

/// Why an input fails a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A multisig input of a version 0 transaction commits fewer signature
    /// operations than its redeem script has keys.
    TooFewSigOps { input: usize, count: u8, keys: u8 },
    /// A version 0 input of a single key, KCC-3's redeem or a savings card
    /// commits no signature operation, so its signature can never be
    /// checked.
    NoSigOp { input: usize },
    /// The input asks for a sighash type other than `ALL`.
    SighashNotAll { input: usize },
    /// A signature the request already holds on this input fails: no key
    /// of the input's script for it, a kind this reader cannot check, or
    /// one that does not verify over the input's hash.
    BadSignature { input: usize },
    /// A bundle's signature map could not be read.
    Pskb(EditError),
    /// The input's sequence is neither 0 nor final.
    Sequence { input: usize },
    /// The input spends a Time-Locked Savings card and the transaction's
    /// lock time is before the card's time.
    CardEarly { input: usize },
    /// The input spends a Time-Locked Savings card and is final, which
    /// turns the lock time check off.
    CardFinal { input: usize },
}

impl From<EditError> for Error {
    fn from(e: EditError) -> Self {
        Error::Pskb(e)
    }
}

/// The multisig `redeem` is, when a unit signs it: a threshold of at least
/// one, at most [`MAX_MULTISIG_KEYS`] keys, no key twice, written as every
/// wallet writes one. `Ok(None)` for a script that is not a multisig.
///
/// # Errors
///
/// `Unsupported`, `Repeated`, `NotStandard`.
pub fn multisig(redeem: &[u8]) -> Result<Option<Multisig<'_>>, MultisigError> {
    let Some(ms) = multisig_shape(redeem) else {
        return if runs_a_multisig(redeem) {
            Err(MultisigError::NotStandard)
        } else {
            Ok(None)
        };
    };
    if ms.required == 0 || usize::from(ms.total) > MAX_MULTISIG_KEYS {
        return Err(MultisigError::Unsupported {
            required: ms.required,
            keys: ms.total,
        });
    }
    if let Some(position) = repeated_key(redeem) {
        return Err(MultisigError::Repeated { position });
    }
    Ok(Some(ms))
}

/// Whether `script` is a multisig as the engine runs one, in any push form:
/// a number, 32-byte keys, a number, then `OP_CHECKMULTISIG` or
/// `OP_CHECKMULTISIGVERIFY` (rusty-kaspa 2.1.0 does not hold numbers to their
/// shortest push, `data_stack.rs`). [`multisig_shape`] reads only the
/// standard form. A script with more steps than the largest multisig, or
/// one that does not parse, is not one.
fn runs_a_multisig(script: &[u8]) -> bool {
    const OP_CHECKMULTISIG: u8 = 0xae;
    const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
    // The engine's limit is twenty keys: a number, the keys, a number and
    // the check.
    let mut steps = [(0u8, 0usize); 23];
    let mut len = 0;
    for step in Disassembler::new(script) {
        let Ok(step) = step else {
            return false;
        };
        let Some(slot) = steps.get_mut(len) else {
            return false;
        };
        *slot = (step.opcode, step.data.len());
        len += 1;
    }
    // A push of data, OP_0 and OP_1NEGATE among them, or OP_1 to OP_16.
    let push = |op: u8| op <= 0x4f || (0x51..=0x60).contains(&op);
    let [count, keys @ .., total, check] = &steps[..len] else {
        return false;
    };
    matches!(check.0, OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY)
        && push(count.0)
        && push(total.0)
        && !keys.is_empty()
        && keys.iter().all(|&(op, n)| push(op) && n == 32)
}

/// Input `i` of a version 0 transaction commits the signature operations
/// its script checks, as rusty-kaspa's wallet writes them: one for a single
/// key (Schnorr or ECDSA) or KCC-3's redeem, one per key of a multisig
/// redeem, [`SIG_OP_COUNT`] for a Time-Locked Savings card. Any other script
/// passes, as does any input from version 1. `redeem` is the input's,
/// checked against its script by the caller.
///
/// # Errors
///
/// `NoSigOp` for a single key's, KCC-3's or a card's input that commits
/// none, `TooFewSigOps` for a multisig input committing fewer than its keys.
pub fn sig_ops(tx: &Transaction<'_>, i: usize, redeem: &[u8]) -> Result<(), Error> {
    let Some(input) = tx.inputs.get(i) else {
        return Ok(());
    };
    if tx.version != 0 {
        return Ok(());
    }
    match classify(&input.utxo_entry.script_public_key) {
        ScriptClass::PubKey | ScriptClass::PubKeyEcdsa if input.sig_op_count == 0 => {
            Err(Error::NoSigOp { input: i })
        }
        ScriptClass::ScriptHash => match multisig_shape(redeem) {
            Some(ms) if input.sig_op_count < ms.total => Err(Error::TooFewSigOps {
                input: i,
                count: input.sig_op_count,
                keys: ms.total,
            }),
            None if input.sig_op_count == 0 && kcc3_key(redeem).is_some() => {
                Err(Error::NoSigOp { input: i })
            }
            None if input.sig_op_count < SIG_OP_COUNT && Savings::from_program(redeem).is_ok() => {
                Err(Error::NoSigOp { input: i })
            }
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}

/// The signature operations a version 0 input of `spk` commits, as
/// [`sig_ops`] holds it to: one for a single key (Schnorr or ECDSA) or
/// KCC-3's redeem, one per key of a multisig redeem, [`SIG_OP_COUNT`] for a
/// Time-Locked Savings card. `None` for any other script. `redeem` is the
/// input's, checked against `spk` by the caller. A version 1 input commits
/// the compute budget that buys as much
/// ([`kassigner_kaspa::mass::compute_budget_for`]).
pub fn committed_sig_ops(spk: &ScriptPublicKey<'_>, redeem: &[u8]) -> Option<u8> {
    match classify(spk) {
        ScriptClass::PubKey | ScriptClass::PubKeyEcdsa => Some(1),
        ScriptClass::ScriptHash => match multisig_shape(redeem) {
            Some(ms) => Some(ms.total),
            None if kcc3_key(redeem).is_some() => Some(1),
            None if Savings::from_program(redeem).is_ok() => Some(SIG_OP_COUNT),
            None => None,
        },
        _ => None,
    }
}

/// Input `i`'s sighash type is `ALL`, the one a unit signs.
///
/// # Errors
///
/// `SighashNotAll`.
pub fn sighash_all(sighash_type: u8, i: usize) -> Result<(), Error> {
    if sighash_type == SIG_HASH_ALL.to_u8() {
        Ok(())
    } else {
        Err(Error::SighashNotAll { input: i })
    }
}

/// Why a transaction as a whole is refused ([`transaction`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionError {
    /// A consensus rule: an output's value, an outpoint spent twice, the
    /// version or a field it does not allow, the input or output totals, or
    /// a covenant binding naming an input the transaction does not have.
    Consensus(TxRuleError),
    /// A node's mempool policy: an output under a script version consensus
    /// does not run, or in none of the standard forms.
    NonStandard(NonStandardError),
}

/// `tx` held to the rules on a whole transaction, in a node's order, as a
/// unit applies them on arrival. Its fee when it passes.
///
/// # Errors
///
/// The first rule broken, as [`TransactionError`] says.
pub fn transaction(tx: &Transaction<'_>) -> Result<u64, TransactionError> {
    use TransactionError::{Consensus, NonStandard};
    tx.check_output_value_ranges().map_err(Consensus)?;
    // Upstream's next rule, before the version. On the review a duplicate's
    // amount would count twice in the inputs and the fee.
    tx.check_duplicate_inputs().map_err(Consensus)?;
    tx.check_version_fields().map_err(Consensus)?;
    tx.check_standard_in_isolation().map_err(NonStandard)?;
    // Upstream's two amount rules, in its order: the inputs against the
    // supply, then the outputs against the inputs.
    let fee = tx.fee().map_err(Consensus)?;
    tx.check_covenant_bindings().map_err(Consensus)?;
    Ok(fee)
}

/// Input `i`'s sequence is 0 or final, the two a unit signs.
///
/// # Errors
///
/// `Sequence` for any other.
pub fn sequence(tx: &Transaction<'_>, i: usize) -> Result<(), Error> {
    match tx.inputs.get(i).map(|input| input.sequence) {
        None | Some(0 | MAX_TX_IN_SEQUENCE_NUM) => Ok(()),
        Some(_) => Err(Error::Sequence { input: i }),
    }
}

/// Input `i`, when `redeem` is a Time-Locked Savings card's program, in a
/// transaction the program can accept: a lock time at or past the card's
/// time, and the input not final (that turns the lock time check off). Any
/// other redeem passes. `redeem` is the input's, checked against its script
/// by the caller.
///
/// # Errors
///
/// `CardFinal` for a final input, `CardEarly` for a lock time before the
/// card's time, a DAA score or none among them.
pub fn card(tx: &Transaction<'_>, i: usize, redeem: &[u8]) -> Result<(), Error> {
    let (Some(input), Ok(card)) = (tx.inputs.get(i), Savings::from_program(redeem)) else {
        return Ok(());
    };
    if input.sequence == MAX_TX_IN_SEQUENCE_NUM {
        return Err(Error::CardFinal { input: i });
    }
    if tx.lock_time < card.unlock().ms() {
        return Err(Error::CardEarly { input: i });
    }
    Ok(())
}

/// Every signature input `i` of a KSPT request already holds: the key at
/// its position in the input's script, `SIGHASH_ALL`, and a signature that
/// verifies over the input's hash. Positions are read by [`key_at`], as in
/// [`verify_kspt`].
///
/// # Errors
///
/// `SighashNotAll` for one of another type; `BadSignature` for a position
/// with no key, one that is not 64 bytes, or one that does not verify.
pub fn kspt_signatures(
    tx: &Transaction<'_>,
    i: usize,
    input: &kspt::Input<'_>,
) -> Result<(), Error> {
    if input.signatures().next().is_none() {
        return Ok(());
    }
    let bad = Error::BadSignature { input: i };
    let digest = schnorr_signature_hash(tx, i, SIG_HASH_ALL).ok_or(bad)?;
    for sig in input.signatures() {
        sighash_all(sig.sighash_type, i)?;
        let key = key_at(script_of(input), input.redeem, sig.pubkey_pos).ok_or(bad)?;
        let bytes = <&[u8; SIGNATURE_LEN]>::try_from(sig.bytes).map_err(|_| bad)?;
        if !bip340::verify(&key, &digest, bytes) {
            return Err(bad);
        }
    }
    Ok(())
}

/// Every member of input `i`'s `partialSigs` in a bundle, checked as
/// [`kspt_signatures`] checks a KSPT's: its key one of the input's script's,
/// and a Schnorr signature verifying over the input's hash against that key.
/// `spk` is the input's locking script, `redeem` its redeem script or empty;
/// the caller holds the sighash type to `ALL` first ([`sighash_all`]).
///
/// # Errors
///
/// `BadSignature` for a member that does not check out; `Pskb` for a map that
/// does not read.
pub fn pskb_signatures(
    bundle: Checked<'_>,
    tx: &Transaction<'_>,
    i: usize,
    spk: ScriptPublicKey<'_>,
    redeem: &[u8],
) -> Result<(), Error> {
    let mut any = false;
    signers(bundle, 0, i, |_| {
        any = true;
        false
    })?;
    if !any {
        return Ok(());
    }
    // No key may sign one input twice. A point written in two encodings
    // (compressed, full or hybrid, either hex case) decodes to one key, so a
    // reply cannot pass one signature off as two; a repeat is refused with
    // the same reason the writer gives ([`EditError::SameKeyTwice`]).
    let mut seen = [[0u8; PUBLIC_KEY_SIZE]; MAX_MULTISIG_KEYS];
    let mut count = 0usize;
    let mut repeated = false;
    signers(bundle, 0, i, |key| {
        if seen[..count].contains(&key) {
            repeated = true;
            false
        } else {
            if count < seen.len() {
                seen[count] = key;
                count += 1;
            }
            true
        }
    })?;
    if repeated {
        return Err(Error::Pskb(EditError::SameKeyTwice { input: i }));
    }
    let bad = Error::BadSignature { input: i };
    let digest = schnorr_signature_hash(tx, i, SIG_HASH_ALL).ok_or(bad)?;
    let mut held = Ok(true);
    signers(bundle, 0, i, |key| {
        held = presence(bundle, 0, i, &key).map(|p| {
            p.schnorr
                .zip(script_key(spk, redeem, &key[1..]))
                .is_some_and(|(sig, x)| bip340::verify(&x, &digest, &sig))
        });
        matches!(held, Ok(true))
    })?;
    match held? {
        true => Ok(()),
        false => Err(bad),
    }
}

/// Whether the one transaction of `doc`, a checked bundle's document, reads
/// as `tx`: a unit compares its request before signing and its reply after.
/// `inputs`, `outputs` and `bytes` are the caller's, sized for the document;
/// one they cannot hold is a read error, not a mismatch.
///
/// # Errors
///
/// The reader's, for a document that does not read into the arrays.
pub fn same_transaction<'a>(
    doc: &[u8],
    tx: &Transaction<'_>,
    inputs: &'a mut [TransactionInput<'a>],
    outputs: &'a mut [TransactionOutput<'a>],
    bytes: &'a mut [u8],
) -> Result<bool, ReadError> {
    let filled = fill(doc, 0, inputs, outputs, bytes)?;
    let read = build(
        &filled.header,
        &inputs[..filled.inputs],
        &outputs[..filled.outputs],
    );
    Ok(read == *tx)
}

// ── The signature count ─────────────────────────────────────────────────────

/// How many signatures a reply holds against how many its transaction
/// needs, shown beside a multisig reply's frames.
///
/// An input needs one signature and counts one once it has any; a multisig
/// needs its threshold and counts the keys that signed, up to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signers {
    /// Signatures the reply holds that count.
    pub present: usize,
    /// Signatures the transaction needs.
    pub required: usize,
}

/// The count, an input at a time.
#[derive(Default)]
struct Tally {
    present: usize,
    required: usize,
    multisig: bool,
}

impl Tally {
    /// One input: its locking script, its redeem script (empty when none), a
    /// bit for each key position that signed, and whether anything did. A
    /// multisig counts only as a redeem script its locking script commits
    /// to; a bare one is not standard in Kaspa.
    fn add(&mut self, spk: ScriptPublicKey<'_>, redeem: &[u8], positions: u32, any: bool) {
        let multisig = (classify(&spk) == ScriptClass::ScriptHash && redeem_matches(&spk, redeem))
            .then(|| parse_multisig(redeem))
            .flatten();
        match multisig {
            Some(m) => {
                let keys = 1u32
                    .checked_shl(u32::from(m.total))
                    .map_or(u32::MAX, |b| b - 1);
                let signed = (positions & keys).count_ones() as usize;
                self.multisig = true;
                self.required += usize::from(m.required);
                self.present += signed.min(usize::from(m.required));
            }
            None => {
                self.required += 1;
                self.present += usize::from(any);
            }
        }
    }

    /// The count, only when an input is a multisig: a single signature's
    /// reply shows none.
    fn done(self) -> Option<Signers> {
        self.multisig.then_some(Signers {
            present: self.present,
            required: self.required,
        })
    }
}

/// The count of a KSPT reply, `None` when no input is a multisig or the reply
/// does not read.
pub fn kspt_signers(reply: &[u8], profile: &Profile) -> Option<Signers> {
    let parsed = kspt::parse(reply, profile).ok()?;
    let mut tally = Tally::default();
    for input in parsed.inputs() {
        let (mut positions, mut any) = (0u32, false);
        for s in input.signatures() {
            any = true;
            positions |= 1u32.checked_shl(u32::from(s.pubkey_pos)).unwrap_or(0);
        }
        tally.add(script_of(&input), input.redeem, positions, any);
    }
    tally.done()
}

/// The count of a PSKB reply: `bundle` is its checked document, `tx` the
/// transaction it reads as, `redeem` scratch of the profile's `max_redeem`
/// bytes. A `partialSigs` key matches a multisig position by its 32 bytes
/// after the parity byte.
pub fn pskb_signers(
    bundle: Checked<'_>,
    tx: &Transaction<'_>,
    redeem: &mut [u8],
) -> Option<Signers> {
    let mut tally = Tally::default();
    for (i, tx_in) in tx.inputs.iter().enumerate() {
        let script = input_extras(bundle, 0, i, redeem).ok()?.redeem;
        let (mut positions, mut any) = (0u32, false);
        signers(bundle, 0, i, |key| {
            any = true;
            for (p, k) in schnorr_keys(script).enumerate() {
                if k == &key[1..] {
                    positions |= 1u32.checked_shl(p as u32).unwrap_or(0);
                }
            }
            true
        })
        .ok()?;
        tally.add(tx_in.utxo_entry.script_public_key, script, positions, any);
    }
    tally.done()
}

// ── Reading a reply back ────────────────────────────────────────────────────

/// Why a reply did not check out; such a reply is not shown. Reading it
/// back as the companion will catches a unit that writes one nobody can
/// verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unverified {
    /// The reply does not parse as a KSPT.
    DoesNotParse,
    /// A signature names a position with no key behind it.
    NoKeyAt { input: usize, position: u8 },
    /// A signature is not 64 bytes.
    Malformed { input: usize },
    /// A signature does not verify over the hash for its input.
    Fails { input: usize, position: u8 },
    /// The reply parsed but carries no signature at all.
    Nothing,
    /// A reply does not read as the transaction that was reviewed: a
    /// bundle's, or a KSPT's with another count of inputs or outputs.
    NotTheTransaction,
    /// A bundle reply holds fewer of the unit's signatures than it wrote.
    Missing { wrote: usize, found: usize },
}

/// Read a KSPT reply back and verify every signature on it, the unit's and
/// any cosigner's, against the key its position names and the hash of the
/// transaction the reply was written for. Returns how many verified.
///
/// # Errors
///
/// The first thing wrong, as [`Unverified`].
pub fn verify_kspt(
    reply: &[u8],
    tx: &Transaction<'_>,
    profile: &Profile,
) -> Result<usize, Unverified> {
    let parsed = kspt::parse(reply, profile).map_err(|_| Unverified::DoesNotParse)?;
    verify_parsed(&parsed, tx)
}

/// [`verify_kspt`] for a reply in v1.0.7's single-signature form
/// ([`kspt::legacy::write_signed`]), which a unit writes for a wallet built
/// on that release: read back by the legacy reader, every signature held
/// to the same transaction. No companion of this version takes such a
/// reply; this is the unit's read-back of what it is about to show.
///
/// # Errors
///
/// The first thing wrong, as [`Unverified`].
pub fn verify_kspt_v107(
    reply: &[u8],
    tx: &Transaction<'_>,
    profile: &Profile,
) -> Result<usize, Unverified> {
    let parsed = kspt::legacy::parse(reply, profile).map_err(|_| Unverified::DoesNotParse)?;
    if !matches!(parsed.shape, kspt::Shape::LegacySingleSig { .. }) {
        return Err(Unverified::DoesNotParse);
    }
    verify_parsed(&parsed, tx)
}

fn verify_parsed(parsed: &kspt::Kspt<'_>, tx: &Transaction<'_>) -> Result<usize, Unverified> {
    // A reply of other counts is not this transaction. Checked here, not
    // left to callers: with fewer inputs the loop below would leave the
    // missing ones unread.
    if parsed.num_inputs != tx.inputs.len() || parsed.num_outputs != tx.outputs.len() {
        return Err(Unverified::NotTheTransaction);
    }
    let mut verified = 0usize;
    for (i, input) in parsed.inputs().enumerate() {
        // A reply input the transaction does not have: not the transaction.
        let digest =
            schnorr_signature_hash(tx, i, SIG_HASH_ALL).ok_or(Unverified::NotTheTransaction)?;
        for sig in input.signatures() {
            let key = key_at(script_of(&input), input.redeem, sig.pubkey_pos).ok_or(
                Unverified::NoKeyAt {
                    input: i,
                    position: sig.pubkey_pos,
                },
            )?;
            let bytes = <&[u8; SIGNATURE_LEN]>::try_from(sig.bytes)
                .map_err(|_| Unverified::Malformed { input: i })?;
            if !bip340::verify(&key, &digest, bytes) {
                return Err(Unverified::Fails {
                    input: i,
                    position: sig.pubkey_pos,
                });
            }
            verified += 1;
        }
    }
    if verified == 0 {
        return Err(Unverified::Nothing);
    }
    Ok(verified)
}

// ── Keys a script names ─────────────────────────────────────────────────────

/// A KSPT input's locking script, under the version it carries.
pub fn script_of<'a>(input: &kspt::Input<'a>) -> ScriptPublicKey<'a> {
    ScriptPublicKey {
        version: input.spk_version,
        script: input.spk,
    }
}

/// The script's key equal to `x`, a bundle key less its parity byte, when
/// the input's script holds it: a pay-to-public-key script's key, or a key
/// of the redeem script the input's script commits to. `None` otherwise, an
/// ECDSA script included. The redeem script is held to the input's hash
/// here, so no caller can verify against a key the coin never named.
pub fn script_key(spk: ScriptPublicKey<'_>, redeem: &[u8], x: &[u8]) -> Option<[u8; 32]> {
    let held = match classify(&spk) {
        ScriptClass::PubKey => spk.script.get(1..33) == Some(x),
        ScriptClass::ScriptHash => {
            redeem_matches(&spk, redeem) && schnorr_keys(redeem).any(|k| k == x)
        }
        _ => false,
    };
    held.then(|| <[u8; 32]>::try_from(x).ok()).flatten()
}

/// The key a signature position names: a pay-to-public-key script's key at
/// position 0, or the key at that index among the 32-byte pushes of the
/// redeem script the input's script commits to, as [`script_key`] holds it.
///
/// It must stay the rule the keyring signs by, or a unit signs an input and
/// then refuses its own reply.
pub fn key_at(spk: ScriptPublicKey<'_>, redeem: &[u8], position: u8) -> Option<[u8; 32]> {
    match classify(&spk) {
        ScriptClass::PubKey if position == 0 => <[u8; 32]>::try_from(&spk.script[1..33]).ok(),
        ScriptClass::ScriptHash if redeem_matches(&spk, redeem) => {
            let key = schnorr_keys(redeem).nth(usize::from(position))?;
            <[u8; 32]>::try_from(key).ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kassigner_kaspa::multisig::redeem_script;
    use kassigner_kaspa::script::redeem_hash;
    use kassigner_kaspa::tx::{Outpoint, UtxoEntry};

    const OP_DATA_32: u8 = 0x20;
    const OP_BLAKE2B: u8 = 0xaa;
    const OP_CHECKSIG: u8 = 0xac;
    const OP_EQUAL: u8 = 0x87;

    /// An `M`-of-`N` redeem script over the keys `1..=N`, each key its number
    /// in every byte, as level 0 writes one.
    fn redeem(m: usize, n: usize, out: &mut [u8]) -> usize {
        let mut keys = [[0u8; 32]; MAX_MULTISIG_KEYS + 1];
        for (k, key) in keys.iter_mut().enumerate() {
            key.fill(k as u8 + 1);
        }
        redeem_script(m, &keys[..n], out).unwrap()
    }

    /// The pay-to-script-hash script of `redeem`.
    fn script_hash(redeem: &[u8]) -> [u8; 35] {
        let mut sh = [0u8; 35];
        sh[0] = OP_BLAKE2B;
        sh[1] = OP_DATA_32;
        sh[2..34].copy_from_slice(&redeem_hash(redeem));
        sh[34] = OP_EQUAL;
        sh
    }

    /// A 2-of-5 passes; a 2-of-6, a 0-of-2 and a 2-of-3 whose third key is
    /// its first are refused; a script that is not a multisig is `None`.
    #[test]
    fn a_multisig_is_held_to_the_limit() {
        let mut buf = [0u8; 256];
        let n = redeem(2, MAX_MULTISIG_KEYS, &mut buf);
        assert_eq!(multisig(&buf[..n]).unwrap().map(|m| m.total), Some(5));
        let n = redeem(2, MAX_MULTISIG_KEYS + 1, &mut buf);
        assert_eq!(
            multisig(&buf[..n]),
            Err(MultisigError::Unsupported {
                required: 2,
                keys: 6
            })
        );
        let n = redeem(0, 2, &mut buf);
        assert_eq!(
            multisig(&buf[..n]),
            Err(MultisigError::Unsupported {
                required: 0,
                keys: 2
            })
        );
        let n = redeem(2, 3, &mut buf);
        buf[1 + 2 * 33 + 1..1 + 3 * 33].fill(1);
        assert_eq!(
            multisig(&buf[..n]),
            Err(MultisigError::Repeated { position: 2 })
        );
        assert_eq!(multisig(&[0x20; 34]), Ok(None));
    }

    /// A 2-of-3 holding its first key twice, with its threshold or count
    /// pushed as a byte, its keys pushed with `OP_PUSHDATA1`, or ended by
    /// `OP_CHECKMULTISIGVERIFY`, is `NotStandard`, not passed over. A KCC-3
    /// redeem, a KCC-3 redeem followed by a multisig, and a script that does
    /// not parse are no multisig.
    #[test]
    fn a_multisig_in_another_form_is_refused() {
        const OP_2: u8 = 0x52;
        const OP_3: u8 = 0x53;
        const OP_CHECKMULTISIG: u8 = 0xae;
        const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
        const OP_PUSHDATA1: u8 = 0x4c;
        /// Writes `prefix`, the threshold, three keys (the first twice) each
        /// behind `key`, the count and `check` into `out`; returns the
        /// length.
        fn script(
            out: &mut [u8; 160],
            prefix: &[u8],
            (count, key, total, check): (&[u8], &[u8], &[u8], u8),
        ) -> usize {
            let mut n = 0;
            let mut put = |bytes: &[u8]| {
                out[n..n + bytes.len()].copy_from_slice(bytes);
                n += bytes.len();
            };
            put(prefix);
            put(count);
            for k in [1u8, 1, 2] {
                put(key);
                put(&[k; 32]);
            }
            put(total);
            put(&[check]);
            n
        }
        let mut out = [0u8; 160];
        for (parts, why) in [
            (
                (
                    &[0x01, 0x02][..],
                    &[OP_DATA_32][..],
                    &[OP_3][..],
                    OP_CHECKMULTISIG,
                ),
                "threshold as a byte",
            ),
            (
                (
                    &[OP_2][..],
                    &[OP_PUSHDATA1, 0x20][..],
                    &[OP_3][..],
                    OP_CHECKMULTISIG,
                ),
                "keys by OP_PUSHDATA1",
            ),
            (
                (
                    &[OP_2][..],
                    &[OP_DATA_32][..],
                    &[0x01, 0x03][..],
                    OP_CHECKMULTISIG,
                ),
                "count as a byte",
            ),
            (
                (
                    &[OP_2][..],
                    &[OP_DATA_32][..],
                    &[OP_3][..],
                    OP_CHECKMULTISIGVERIFY,
                ),
                "ended by VERIFY",
            ),
        ] {
            let n = script(&mut out, &[], parts);
            assert_eq!(
                multisig(&out[..n]),
                Err(MultisigError::NotStandard),
                "{why}"
            );
        }

        let mut kcc3 = [OP_CHECKSIG; 34];
        kcc3[0] = OP_DATA_32;
        kcc3[1..33].fill(7);
        assert_eq!(multisig(&kcc3), Ok(None));
        let standard = (
            &[OP_2][..],
            &[OP_DATA_32][..],
            &[OP_3][..],
            OP_CHECKMULTISIG,
        );
        let n = script(&mut out, &kcc3, standard);
        assert_eq!(multisig(&out[..n]), Ok(None), "a multisig inside more");
        assert_eq!(multisig(&[OP_2, OP_DATA_32, 1, 2]), Ok(None), "truncated");
    }

    /// A redeem script names its keys only for the coin that commits to it:
    /// over its own pay-to-script-hash script a 2-of-3's keys are found by
    /// position and by value, over another script's hash none are.
    #[test]
    fn a_redeem_script_names_keys_only_for_its_own_coin() {
        let mut buf = [0u8; 256];
        let n = redeem(2, 3, &mut buf);
        let own = script_hash(&buf[..n]);
        let spk = ScriptPublicKey {
            version: 0,
            script: &own,
        };
        assert_eq!(key_at(spk, &buf[..n], 1), Some([2; 32]));
        assert_eq!(script_key(spk, &buf[..n], &[3; 32]), Some([3; 32]));

        let mut other = [0u8; 256];
        let m = redeem(1, 3, &mut other);
        let elsewhere = script_hash(&other[..m]);
        let spk = ScriptPublicKey {
            version: 0,
            script: &elsewhere,
        };
        assert_eq!(key_at(spk, &buf[..n], 1), None);
        assert_eq!(script_key(spk, &buf[..n], &[3; 32]), None);
    }

    /// An input before it is filled.
    const EMPTY: TransactionInput<'static> = TransactionInput {
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

    /// A version `version` transaction of one input locked by `spk`,
    /// committing `sig_ops` signature operations, with no outputs.
    fn one_input<'a>(
        version: u16,
        spk: &'a [u8],
        sig_ops: u8,
        inputs: &'a mut [TransactionInput<'a>; 1],
    ) -> Transaction<'a> {
        inputs[0] = TransactionInput {
            previous_outpoint: Outpoint {
                transaction_id: [0; 32],
                index: 0,
            },
            sequence: 0,
            sig_op_count: sig_ops,
            compute_budget: 0,
            signature_script: &[],
            utxo_entry: UtxoEntry {
                amount: 1,
                script_public_key: ScriptPublicKey {
                    version: 0,
                    script: spk,
                },
            },
        };
        Transaction {
            version,
            inputs: &inputs[..],
            outputs: &[],
            lock_time: 0,
            subnetwork_id: [0; 20],
            gas: 0,
            payload: &[],
        }
    }

    /// Signature operations are held as the wallet writes them. In version 0
    /// a single key committing none and a 2-of-3 committing two are refused,
    /// a single key committing one and a 2-of-3 committing three pass; in
    /// version 1 a single key committing none passes.
    #[test]
    fn signature_operations_are_held_as_the_wallet_writes_them() {
        let mut pk = [0u8; 34];
        pk[0] = OP_DATA_32;
        pk[33] = OP_CHECKSIG;
        let mut inputs = [EMPTY; 1];
        let tx = one_input(0, &pk, 0, &mut inputs);
        assert_eq!(sig_ops(&tx, 0, &[]), Err(Error::NoSigOp { input: 0 }));
        let mut inputs = [EMPTY; 1];
        let tx = one_input(1, &pk, 0, &mut inputs);
        assert_eq!(sig_ops(&tx, 0, &[]), Ok(()));
        let mut inputs = [EMPTY; 1];
        let tx = one_input(0, &pk, 1, &mut inputs);
        assert_eq!(sig_ops(&tx, 0, &[]), Ok(()));
        assert_eq!(sig_ops(&tx, 1, &[]), Ok(()), "no such input");

        let mut buf = [0u8; 256];
        let n = redeem(2, 3, &mut buf);
        let sh = script_hash(&buf[..n]);
        let mut inputs = [EMPTY; 1];
        let tx = one_input(0, &sh, 2, &mut inputs);
        assert_eq!(
            sig_ops(&tx, 0, &buf[..n]),
            Err(Error::TooFewSigOps {
                input: 0,
                count: 2,
                keys: 3
            })
        );
        let mut inputs = [EMPTY; 1];
        let tx = one_input(0, &sh, 3, &mut inputs);
        assert_eq!(sig_ops(&tx, 0, &buf[..n]), Ok(()));
    }

    /// Only `ALL` is signed.
    #[test]
    fn only_all_is_signed() {
        assert_eq!(sighash_all(SIG_HASH_ALL.to_u8(), 3), Ok(()));
        assert_eq!(sighash_all(0x02, 3), Err(Error::SighashNotAll { input: 3 }));
    }
}
