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

//! The reply: a confirmed session back into the bytes that go out.
//!
//! A KSPT or PSKB request became a [`Session`]. Once it is confirmed, this
//! signs each input a key of ours signs ([`crate::keyring`] finds the key and
//! its position from the input's script, redeem script and, for a KSPT, hint)
//! and writes the request back in its own format: a KSPT of any version as
//! `0x06`, the writer's one shape; a PSKB as the same bundle with the
//! signatures spliced in, byte for byte what rusty-kaspa's signer writes. The
//! caller owns every buffer.
//!
//! A wallet built on v1.0.7 reads neither `0x06` nor this version's frames.
//! For its single-key `0x01` request the flow writes the reply a second time
//! in that release's form, from the signatures made here and nothing else
//! (`flow::reviewing`), and shows that one to a wallet.
//!
//! # Every signature comes from the session
//!
//! Nothing here takes a signature as an argument. Each comes from
//! [`Session::sign_input`], which refuses unless every page was shown and the
//! person confirmed, so a reply cannot carry a signature over anything not
//! reviewed. The stage is checked before the request is read, so an unconfirmed
//! session does no work.
//!
//! # Plan first, before the review
//!
//! [`plan_kspt`] and [`plan_pskb`] make the reply's pass without signing. A
//! flow calls one before the review, so a request is refused before a person
//! approves it, not after, the worst place to fail: one whose signed form the
//! board cannot display, or one that breaks a rule of
//! [`kassigner_protocol::check`]. A companion applies the same rules before
//! showing a request, so the two cannot drift: every signature the request
//! already holds, the signature operations a version 0 input commits, the
//! sighash type (`ALL` only), the sequence, and a Time-Locked Savings card's
//! lock time and finality.
//!
//! An input no key of ours signs is skipped, but one the device already signed
//! (a verifying signature at its own position) is refused, so the reason given
//! is that and not "no key matched". Also refused: a reply with no new
//! signature, and a bundle of more than one transaction. A bundle's map keys
//! are only compared as bytes, to find ours and its place, never used as
//! points.
//!
//! # A redeem script the device supplies
//!
//! A KCC-3 address kassigner.org knows only by its hash arrives with no redeem
//! script; the keyring supplies `<P> OP_CHECKSIG`
//! ([`keyring::Match::supplied`]). Every check reads that redeem, and the reply
//! carries it, in a KSPT's redeem field or in place of a bundle's `null`
//! `redeemScript`: whoever finishes the spend needs it, and P goes public with
//! the spend anyway.

use core::borrow::Borrow;

use kassigner_crypto::wallet::Wallet;
use kassigner_hal::entropy::Entropy;
use kassigner_kaspa::bip32_public::PUBLIC_KEY_SIZE;
use kassigner_kaspa::bip340;
use kassigner_kaspa::pskb::signature::{
    derivations, presence, signers, splices, text_len, Derivation, PartialSig, Presence,
};
use kassigner_kaspa::pskb::transaction::input_extras;
use kassigner_kaspa::pskb::{self, Checked, EmitError, EnvelopeError, Span, Splice};
use kassigner_kaspa::script::{
    classify, kcc3_key, redeem_matches, schnorr_keys, ScriptClass, KCC3_REDEEM_LEN,
};
use kassigner_kaspa::sighash::{schnorr_signature_hash, SIG_HASH_ALL};
use kassigner_kaspa::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutput};
use kassigner_protocol::card::savings::Savings;
use kassigner_protocol::check;
use kassigner_protocol::kspt::{
    self, Hint, InputSignature, Kspt, KsptError, Record, SIGNATURE_LEN,
};
use kassigner_protocol::profile::Profile;

/// Level 1's signature count and KSPT read-back, the ones a companion uses,
/// re-exported for the flow and the tests.
pub use kassigner_protocol::check::{
    kspt_signers, verify_kspt, verify_kspt_v107, Signers, Unverified,
};

use crate::keyring::{
    self, path_of, path_of_account_hint, path_of_hint, path_of_kcc3_hint, Keyring, Match,
};
use crate::session::{self, Session};

/// Why a reply was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The session refused: not confirmed, or signing failed.
    Session(session::Error),
    /// The keyring could not resolve an input.
    Keyring {
        input: usize,
        error: keyring::Error,
    },
    /// The device already signed this input at this key position.
    AlreadySigned {
        input: usize,
        position: u8,
    },
    /// A version 0 multisig input commits fewer signature operations than its
    /// redeem script has keys.
    TooFewSigOps {
        input: usize,
        count: u8,
        keys: u8,
    },
    /// A version 0 single-key or KCC-3 input commits no signature operation, so
    /// its signature can never be checked.
    NoSigOp {
        input: usize,
    },
    /// A signature the request already holds on this input has no key in the
    /// input's script, is of a kind this device cannot check, or does not
    /// verify over the input's hash.
    BadSignature {
        input: usize,
    },
    /// No input is locked to a key in the bank nor, where the request gave no
    /// derivation, within [`crate::limits::SEARCH_DEPTH`] on either chain. A
    /// wallet deeper than that without derivations is at fault; a screen should
    /// state that depth.
    NothingSigned,
    /// Only `signed` of the transaction's `inputs` are the seed's.
    /// [`plan_kspt`] and [`plan_pskb`] count what they can so the flow can
    /// search on; the flow refuses once nothing more can be placed, rather than
    /// sign half a transaction: the amount of an input the device does not sign
    /// is in none of its signatures, so the review's In and Fee would rest on
    /// an unchecked number.
    NotEveryInput {
        signed: usize,
        inputs: usize,
    },
    /// A signed transaction read by itself ([`kspt_itself`],
    /// [`pskb_itself`]) holds signatures, but none on input `input`. A
    /// signature covers its own input's amount and no other's, so that
    /// input's amount is a number nothing checks, and the review's In and
    /// Fee would rest on it: the rule [`Error::NotEveryInput`] keeps for a
    /// request to sign, kept for one only shown.
    InputUnsigned {
        input: usize,
    },
    /// The signed reply would be longer than the board can display.
    TooLargeToShow {
        needed: usize,
        ceiling: usize,
    },
    /// The bundle holds `count` transactions; a reply answers one.
    NotOneTransaction {
        count: usize,
    },
    /// The input asks for a sighash type other than `ALL`.
    SighashNotAll {
        input: usize,
    },
    /// The input's sequence is neither 0 nor final: a relative lock no page
    /// shows ([`check::sequence`]).
    Sequence {
        input: usize,
    },
    /// The input spends a Time-Locked Savings card with a lock time before the
    /// card's, so the card's program refuses the transaction ([`check::card`]).
    CardEarly {
        input: usize,
    },
    /// The input spends a Time-Locked Savings card and is final, which turns
    /// its lock time check off, so the card's program refuses the transaction
    /// ([`check::card`]).
    CardFinal {
        input: usize,
    },
    /// The bundle's transaction is not the one the session reviewed.
    NotTheReviewedTransaction,
    /// A [`Scratch`] array is too small; the field says which.
    ScratchTooSmall(&'static str),
    /// The KSPT writer refused.
    Kspt(KsptError),
    /// The bundle could not be read.
    PskbRead(pskb::transaction::ReadError),
    /// The signature could not be placed in the bundle.
    PskbEdit(pskb::signature::EditError),
    /// The edited bundle could not be assembled or wrapped.
    PskbEmit(EmitError),
    PskbEnvelope(EnvelopeError),
}

impl From<session::Error> for Error {
    fn from(e: session::Error) -> Self {
        Error::Session(e)
    }
}
impl From<check::Error> for Error {
    /// A level 1 check's refusal under this module's name, which the screens
    /// read.
    fn from(e: check::Error) -> Self {
        match e {
            check::Error::TooFewSigOps { input, count, keys } => {
                Error::TooFewSigOps { input, count, keys }
            }
            check::Error::NoSigOp { input } => Error::NoSigOp { input },
            check::Error::SighashNotAll { input } => Error::SighashNotAll { input },
            check::Error::BadSignature { input } => Error::BadSignature { input },
            check::Error::Pskb(e) => Error::PskbEdit(e),
            check::Error::Sequence { input } => Error::Sequence { input },
            check::Error::CardEarly { input } => Error::CardEarly { input },
            check::Error::CardFinal { input } => Error::CardFinal { input },
        }
    }
}
impl From<KsptError> for Error {
    fn from(e: KsptError) -> Self {
        Error::Kspt(e)
    }
}
impl From<pskb::transaction::ReadError> for Error {
    fn from(e: pskb::transaction::ReadError) -> Self {
        Error::PskbRead(e)
    }
}
impl From<pskb::signature::EditError> for Error {
    fn from(e: pskb::signature::EditError) -> Self {
        Error::PskbEdit(e)
    }
}
impl From<EmitError> for Error {
    fn from(e: EmitError) -> Self {
        Error::PskbEmit(e)
    }
}
impl From<EnvelopeError> for Error {
    fn from(e: EnvelopeError) -> Self {
        Error::PskbEnvelope(e)
    }
}

/// What a reply produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Bytes written to `out`.
    pub len: usize,
    /// Inputs signed.
    pub signed: usize,
}

/// What a reply will be, worked out before anything is signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Inputs the device will sign.
    pub signatures: usize,
    /// Inputs in the transaction; more than `signatures` when some are not the
    /// seed's ([`Error::NotEveryInput`]).
    pub inputs: usize,
    /// Bytes the reply will take, at most.
    pub len: usize,
    /// The M of N the review shows when every input the device signs is the
    /// same multisig; `None` otherwise.
    pub group: Option<(u8, u8)>,
    /// Bit `i` set when the device signs input `i` at its script's second key:
    /// for a Time-Locked Savings card, as its recovery wallet, which the card's
    /// page says.
    pub second: u32,
}

/// [`Plan::second`] is a `u32`, one bit an input.
const _: () = assert!(crate::limits::MAX_INPUTS <= u32::BITS as usize);

/// What [`Plan::group`] and [`Plan::second`] say, gathered an input at a
/// time.
#[derive(Clone, Copy)]
struct Shapes {
    group: Option<Option<(u8, u8)>>,
    second: u32,
}

impl Shapes {
    /// No input yet.
    const fn new() -> Self {
        Shapes {
            group: None,
            second: 0,
        }
    }

    /// An input signed under a script of `shape`, `None` for a single key.
    fn add(&mut self, shape: Option<(u8, u8)>) {
        self.group = Some(match self.group {
            None => shape,
            Some(seen) if seen == shape => seen,
            Some(_) => None,
        });
    }

    /// Input `i` signed as `m`: its shape and key position.
    fn signed(&mut self, i: usize, m: &Match) {
        self.add(m.shape);
        self.at(i, m.position);
    }

    /// Input `i` signed at `position` among its script's keys.
    fn at(&mut self, i: usize, position: u8) {
        if position == 1 {
            self.second |= u32::try_from(i)
                .ok()
                .and_then(|i| 1u32.checked_shl(i))
                .unwrap_or(0);
        }
    }

    /// The one shape every input had, if a multisig's.
    const fn group(self) -> Option<(u8, u8)> {
        match self.group {
            Some(group) => group,
            None => None,
        }
    }
}

/// The four bytes of `PSKB` before a bundle's hex.
const ENVELOPE_PREFIX: usize = 4;

fn fits(
    (signatures, inputs): (usize, usize),
    len: usize,
    ceiling: usize,
    shapes: Shapes,
) -> Result<Plan, Error> {
    if len > ceiling {
        return Err(Error::TooLargeToShow {
            needed: len,
            ceiling,
        });
    }
    Ok(Plan {
        signatures,
        inputs,
        len,
        group: shapes.group(),
        second: shapes.second,
    })
}

/// What a walk over the inputs is for, which decides what is done with an input
/// of the seed's that holds its signature.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// To sign: an input of the seed's that already holds its signature is
    /// `AlreadySigned`.
    Sign,
    /// Reading back the device's own reply: an input of the seed's counts when
    /// it holds its signature. The signature-operation and signature checks,
    /// made before signing, are skipped.
    ReadBack,
    /// A transaction the seed already signed, reopened to be shown
    /// ([`signed_kspt`], [`signed_pskb`]): every check made, and an input of
    /// the seed's counts when it holds its signature.
    Signed,
}

// ── KSPT ────────────────────────────────────────────────────────────────────

/// Call `f` for each input of a KSPT the device's keys sign, with its key and
/// position; return how many. [`plan_kspt`] and [`kspt()`] make this one pass,
/// so a plan cannot promise a reply the signing then refuses; [`signed_kspt`]
/// makes it as [`Pass::Signed`].
fn each_kspt_input<W: Borrow<Wallet>>(
    tx: &Transaction<'_>,
    source: &Kspt<'_>,
    keys: &Keyring<W>,
    pass: Pass,
    mut f: impl FnMut(usize, Match) -> Result<(), Error>,
) -> Result<usize, Error> {
    let mut n = 0usize;
    for (i, (tx_in, src_in)) in tx.inputs.iter().zip(source.inputs()).enumerate() {
        let hint = input_hint(source, i).and_then(path_of_hint).or_else(|| {
            source.records().find_map(|r| match r {
                Record::Kcc3InputHint(h) if usize::from(h.index) == i => path_of_kcc3_hint(h),
                Record::AccountInputHint(h) if usize::from(h.index) == i => path_of_account_hint(h),
                _ => None,
            })
        });
        // A sequence no page shows and a card its own program refuses are
        // refused before any key search, which would be wasted on them. A
        // card's program is the input's own redeem, never a supplied one.
        check::sequence(tx, i)?;
        check::card(tx, i, src_in.redeem)?;
        let found = keys
            .resolve(tx_in.utxo_entry.script_public_key, src_in.redeem, hint)
            .map_err(|error| Error::Keyring { input: i, error })?;
        let supplied = found.as_ref().and_then(|m| m.supplied);
        let redeem = supplied.as_ref().map_or(src_in.redeem, |r| &r[..]);
        check::sig_ops(tx, i, redeem)?;
        check::kspt_signatures(tx, i, &src_in)?;
        let Some(m) = found else {
            continue;
        };
        let signed = src_in.signatures().any(|s| s.pubkey_pos == m.position);
        match (pass, signed) {
            (Pass::Sign, true) => {
                return Err(Error::AlreadySigned {
                    input: i,
                    position: m.position,
                })
            }
            (Pass::Signed | Pass::ReadBack, false) => continue,
            _ => {}
        }
        f(i, m)?;
        n += 1;
    }
    if n == 0 {
        return Err(Error::NothingSigned);
    }
    Ok(n)
}

/// The KSPT reply this request will get, signing nothing. Its length is exact:
/// the writer measures before writing, and a signature's bytes do not change
/// it. `ceiling` is what the board displays,
/// [`Capacity::display_bytes`](kassigner_protocol::profile::Capacity::display_bytes);
/// `sigs` is scratch, sized as for [`kspt()`].
///
/// # Errors
///
/// What [`kspt()`] refuses about the request, and `TooLargeToShow`.
pub fn plan_kspt<W: Borrow<Wallet>>(
    session: &Session<'_>,
    source: &Kspt<'_>,
    keys: &Keyring<W>,
    profile: &Profile,
    ceiling: usize,
    sigs: &mut [InputSignature],
) -> Result<Plan, Error> {
    let tx = session.transaction();
    let mut k = 0usize;
    let mut shapes = Shapes::new();
    let n = each_kspt_input(tx, source, keys, Pass::Sign, |i, m| {
        let slot = sigs.get_mut(k).ok_or(Error::ScratchTooSmall("sigs"))?;
        *slot = InputSignature {
            input: i,
            pubkey_pos: m.position,
            sighash_type: SIG_HASH_ALL.to_u8(),
            signature: [0; SIGNATURE_LEN],
            redeem: m.supplied,
        };
        shapes.signed(i, &m);
        k += 1;
        Ok(())
    })?;
    let len = kspt::written_len(source, tx, &sigs[..n], profile)?;
    fits((n, tx.inputs.len()), len, ceiling, shapes)
}

/// Whether a KSPT is one this seed already signed in full, such as one Save to
/// SD kept, reopened to be shown, not signed. Every signature is checked as a
/// request's are, and every input must hold the seed's signature at its
/// position.
///
/// # Errors
///
/// What [`plan_kspt`] refuses bar `AlreadySigned`; `NotEveryInput` for an input
/// not signed by the seed; `NothingSigned` for none.
pub fn signed_kspt<W: Borrow<Wallet>>(
    session: &Session<'_>,
    source: &Kspt<'_>,
    keys: &Keyring<W>,
) -> Result<Reopened, Error> {
    let tx = session.transaction();
    let mut shapes = Shapes::new();
    let n = each_kspt_input(tx, source, keys, Pass::Signed, |i, m| {
        shapes.signed(i, &m);
        Ok(())
    })?;
    reopened(n, tx.inputs.len(), shapes)
}

/// A transaction this seed signed in full, as [`signed_kspt`] and
/// [`signed_pskb`] find it, for its review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reopened {
    /// Inputs, every one the seed's and signed by it.
    pub inputs: usize,
    /// The multisig's M of N, as [`Plan::group`].
    pub group: Option<(u8, u8)>,
    /// Inputs signed at their script's second key, as [`Plan::second`].
    pub second: u32,
}

/// [`Reopened`] when all `inputs` are the seed's and signed by it, else
/// `NotEveryInput`.
fn reopened(signed: usize, inputs: usize, shapes: Shapes) -> Result<Reopened, Error> {
    if signed < inputs {
        return Err(Error::NotEveryInput { signed, inputs });
    }
    Ok(Reopened {
        inputs,
        group: shapes.group(),
        second: shapes.second,
    })
}

/// Answer a KSPT request. `source` is the request the session's transaction was
/// mapped from; `sigs` needs one slot per input the device may sign; `out`
/// needs [`kspt::written_len`] of the result.
///
/// # Errors
///
/// `Session`, before anything is read, unless the session is confirmed; every
/// refusal of [`plan_kspt`]'s pass, as [`Error`] describes;
/// `ScratchTooSmall("sigs")`; `Kspt` for anything the writer refuses, including
/// a source that does not match the session's transaction.
pub fn kspt<W: Borrow<Wallet>, E: Entropy + ?Sized>(
    session: &Session<'_>,
    source: &Kspt<'_>,
    keys: &Keyring<W>,
    profile: &Profile,
    rng: &mut E,
    sigs: &mut [InputSignature],
    out: &mut [u8],
) -> Result<Reply, Error> {
    session.require_confirmed()?;
    let tx = session.transaction();
    let mut k = 0usize;
    let n = each_kspt_input(tx, source, keys, Pass::Sign, |i, m| {
        let slot = sigs.get_mut(k).ok_or(Error::ScratchTooSmall("sigs"))?;
        let signature = session.sign_input(i, m.key.private_key(), rng)?;
        *slot = InputSignature {
            input: i,
            pubkey_pos: m.position,
            sighash_type: SIG_HASH_ALL.to_u8(),
            signature: *signature.as_bytes(),
            redeem: m.supplied,
        };
        k += 1;
        Ok(())
    })?;
    let len = kspt::write(source, tx, &sigs[..n], profile, out)?;
    Ok(Reply { len, signed: n })
}

/// The hint record for input `i`, if the request carries one.
pub(crate) fn input_hint(source: &Kspt<'_>, i: usize) -> Option<Hint> {
    source.records().find_map(|r| match r {
        Record::InputHint(h) if usize::from(h.index) == i => Some(h),
        _ => None,
    })
}

// ── PSKB ────────────────────────────────────────────────────────────────────

/// The caller's buffers for a PSKB reply, sized by [`crate::sizes::Sizes`].
pub struct Scratch<'s> {
    /// One per input of the request.
    pub inputs: &'s mut [TransactionInput<'s>],
    /// One per output of the request.
    pub outputs: &'s mut [TransactionOutput<'s>],
    /// Decoded scripts and payload: a quarter of the envelope's length.
    pub bytes: &'s mut [u8],
    /// A redeem script: the profile's `max_redeem`.
    pub redeem: &'s mut [u8],
    /// One per input of the request.
    pub signatures: &'s mut [[u8; SIGNATURE_LEN]],
    /// One per input of the request.
    pub signed: &'s mut [Signed],
    /// One per input of the request.
    pub partial: &'s mut [PartialSig<'s>],
    /// Three per input of the request: two members, and a redeem script the
    /// device supplies.
    pub splices: &'s mut [Splice<'s>],
    /// The generated members, [`text_len`] of the signatures, and each
    /// supplied redeem script's value.
    pub text: &'s mut [u8],
    /// The edited document: the request's decoded length plus the text.
    pub json: &'s mut [u8],
}

/// An input the device signed, before its member is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signed {
    input: usize,
    public_key: [u8; PUBLIC_KEY_SIZE],
    derivation: Option<Span>,
    /// KCC-3's redeem script, when the device supplies it.
    redeem: Option<[u8; KCC3_REDEEM_LEN]>,
}

impl Signed {
    /// An unused slot, for sizing a [`Scratch`].
    pub const EMPTY: Signed = Signed {
        input: 0,
        public_key: [0; PUBLIC_KEY_SIZE],
        derivation: None,
        redeem: None,
    };
}

/// Length of a supplied `redeemScript` value: the script's hex in quotes,
/// replacing the input's `null`.
const REDEEM_VALUE_LEN: usize = 2 + 2 * KCC3_REDEEM_LEN;

/// Call `f` for each input of a bundle the device's keys sign, with its key,
/// position and what the bundle holds for that key; return how many.
/// [`plan_pskb`] and [`pskb()`] make this one pass as [`Pass::Sign`],
/// [`verify_pskb`] as [`Pass::ReadBack`], [`signed_pskb`] as [`Pass::Signed`].
fn each_pskb_input<W: Borrow<Wallet>>(
    bundle: Checked<'_>,
    tx: &Transaction<'_>,
    keys: &Keyring<W>,
    redeem: &mut [u8],
    pass: Pass,
    mut f: impl FnMut(usize, Match, Presence) -> Result<(), Error>,
) -> Result<usize, Error> {
    let mut n = 0usize;
    for (i, tx_in) in tx.inputs.iter().enumerate() {
        let extras = input_extras(bundle, 0, i, redeem).map_err(|e| match e {
            pskb::transaction::ReadError::BufferTooSmall => Error::ScratchTooSmall("redeem"),
            other => Error::PskbRead(other),
        })?;
        // A sighash type other than ALL, a sequence no page shows and a card
        // its own program refuses are refused before any key search, as in a
        // KSPT.
        check::sighash_all(extras.sighash_type, i)?;
        check::sequence(tx, i)?;
        check::card(tx, i, extras.redeem)?;
        let spk = tx_in.utxo_entry.script_public_key;
        // Each path the bundle records for this input is a hint; the first that
        // resolves wins. Failing that, the bank only if there was a path, as
        // for a KSPT's wrong hint; the search past it only if there was none.
        let mut found = None;
        let mut trouble = None;
        let mut hinted = false;
        derivations(bundle, 0, i, |entry| {
            let Some(path) = entry.source.and_then(|(_, p)| path_of(p)) else {
                return true;
            };
            hinted = true;
            match keys.resolve(spk, extras.redeem, Some(path)) {
                Ok(Some(m)) => {
                    found = Some(m);
                    false
                }
                Ok(None) => true,
                Err(error) => {
                    trouble = Some(Error::Keyring { input: i, error });
                    false
                }
            }
        })?;
        if let Some(e) = trouble {
            return Err(e);
        }
        let found = match found {
            Some(m) => Some(m),
            None if hinted => keys
                .resolve_in_bank(spk, extras.redeem)
                .map_err(|error| Error::Keyring { input: i, error })?,
            None => keys
                .resolve(spk, extras.redeem, None)
                .map_err(|error| Error::Keyring { input: i, error })?,
        };
        if pass != Pass::ReadBack {
            let supplied = found.as_ref().and_then(|m| m.supplied);
            let redeem = supplied.as_ref().map_or(extras.redeem, |r| &r[..]);
            check::sig_ops(tx, i, redeem)?;
            check::pskb_signatures(bundle, tx, i, spk, redeem)?;
        }
        let Some(m) = found else {
            continue;
        };
        let held = presence(bundle, 0, i, m.key.public_key())?;
        if pass != Pass::Sign {
            if held.signed {
                f(i, m, held)?;
                n += 1;
            }
            continue;
        }
        if held.signed {
            return Err(Error::AlreadySigned {
                input: i,
                position: m.position,
            });
        }
        f(i, m, held)?;
        n += 1;
    }
    if n == 0 {
        return Err(Error::NothingSigned);
    }
    Ok(n)
}

/// [`plan_kspt`] for a bundle. The length is an upper bound: each member is
/// counted with a new key and a separating comma, which an entry passed back in
/// place does not need. `redeem` is scratch, the profile's `max_redeem`.
///
/// # Errors
///
/// What [`pskb()`] refuses about the bundle before signing, and
/// `TooLargeToShow`.
pub fn plan_pskb<W: Borrow<Wallet>>(
    session: &Session<'_>,
    doc: &[u8],
    keys: &Keyring<W>,
    ceiling: usize,
    redeem: &mut [u8],
) -> Result<Plan, Error> {
    let bundle = checked(doc)?;
    let count = bundle.transactions();
    if count != 1 {
        return Err(Error::NotOneTransaction { count });
    }
    // The members' bound, one signature at a time: the edit's own measure,
    // over a placeholder signature of the same length.
    let mut text = 0usize;
    let mut shapes = Shapes::new();
    let n = each_pskb_input(
        bundle,
        session.transaction(),
        keys,
        redeem,
        Pass::Sign,
        |i, m, held| {
            shapes.signed(i, &m);
            let one = PartialSig {
                input: i,
                public_key: m.key.public_key(),
                signature: &[0; SIGNATURE_LEN],
                derivation: match held.derivation {
                    Some(span) => Derivation::Value(&doc[span.start..span.end]),
                    None => Derivation::Null,
                },
            };
            text = text.saturating_add(text_len(core::slice::from_ref(&one)));
            if m.supplied.is_some() {
                text = text.saturating_add(REDEEM_VALUE_LEN);
            }
            Ok(())
        },
    )?;
    let edited = doc.len().saturating_add(text);
    let len = edited.saturating_mul(2).saturating_add(ENVELOPE_PREFIX);
    fits(
        (n, session.transaction().inputs.len()),
        len,
        ceiling,
        shapes,
    )
}

/// [`signed_kspt`] for a bundle of one transaction, with the signers it holds.
/// `redeem` is scratch, the profile's `max_redeem`.
///
/// # Errors
///
/// As [`signed_kspt`], with [`plan_pskb`]'s refusals in place of
/// [`plan_kspt`]'s.
pub fn signed_pskb<W: Borrow<Wallet>>(
    session: &Session<'_>,
    doc: &[u8],
    keys: &Keyring<W>,
    redeem: &mut [u8],
) -> Result<(Reopened, Option<Signers>), Error> {
    let bundle = checked(doc)?;
    let count = bundle.transactions();
    if count != 1 {
        return Err(Error::NotOneTransaction { count });
    }
    let tx = session.transaction();
    let mut shapes = Shapes::new();
    let n = each_pskb_input(bundle, tx, keys, redeem, Pass::Signed, |i, m, _| {
        shapes.signed(i, &m);
        Ok(())
    })?;
    let reopened = reopened(n, tx.inputs.len(), shapes)?;
    Ok((reopened, check::pskb_signers(bundle, tx, redeem)))
}

// ── A signed transaction, read by itself ────────────────────────────────────

/// A signed transaction read with no seed's keys, by [`kspt_itself`] and
/// [`pskb_itself`]: anyone may show and broadcast one, including a unit with
/// no seed in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Itself {
    /// Inputs the transaction has.
    pub inputs: usize,
    /// Every input holds the signatures its script needs, so a node takes it as
    /// it is.
    pub complete: bool,
    /// As [`Plan::group`]: the M of N when every input is the same multisig.
    pub group: Option<(u8, u8)>,
    /// Inputs signed at their script's second key, as [`Plan::second`].
    pub second: u32,
}

/// The signatures an input locked by `spk` with `redeem` (empty when none)
/// needs, and a multisig's M of N: M for a multisig; one for a
/// pay-to-public-key script, KCC-3's redeem or a Time-Locked Savings card
/// (either key's is enough); `None` where no signature finishes it: a script
/// hash whose redeem is still to come, or any other redeem.
fn needs(spk: ScriptPublicKey<'_>, redeem: &[u8]) -> (Option<usize>, Option<(u8, u8)>) {
    match classify(&spk) {
        ScriptClass::PubKey => (Some(1), None),
        ScriptClass::ScriptHash if redeem_matches(&spk, redeem) => match check::multisig(redeem) {
            Ok(Some(m)) => (Some(usize::from(m.required)), Some((m.required, m.total))),
            _ if kcc3_key(redeem).is_some() => (Some(1), None),
            _ if Savings::from_program(redeem).is_ok() => (Some(1), None),
            _ => (None, None),
        },
        _ => (None, None),
    }
}

/// [`Itself`]; `NothingSigned` when no input holds a signature, and
/// `InputUnsigned` when some do and `unsigned`, the first without one, does
/// not.
fn itself(
    signed: usize,
    unsigned: Option<usize>,
    inputs: usize,
    complete: bool,
    shapes: Shapes,
) -> Result<Itself, Error> {
    if signed == 0 {
        return Err(Error::NothingSigned);
    }
    if let Some(input) = unsigned {
        return Err(Error::InputUnsigned { input });
    }
    Ok(Itself {
        inputs,
        complete,
        group: shapes.group(),
        second: shapes.second,
    })
}

/// Read a signed KSPT with no seed's keys: each signature checked as a
/// request's are, by the key its position names, and whether every input holds
/// what its script needs. What it pays is the review's to show; each signer
/// reviewed it on their own unit. Every input holds a checked signature at
/// least, so every amount the review adds up is one a signature covers.
///
/// # Errors
///
/// Any refusal of [`kassigner_protocol::check`] a request gets; `NothingSigned`
/// for no signature at all; `InputUnsigned` for an input with none where
/// another has one.
pub fn kspt_itself(session: &Session<'_>, source: &Kspt<'_>) -> Result<Itself, Error> {
    let tx = session.transaction();
    let (mut signed, mut complete, mut shapes) = (0usize, true, Shapes::new());
    let mut unsigned = None;
    for (i, src_in) in source.inputs().enumerate() {
        check::sequence(tx, i)?;
        check::sig_ops(tx, i, src_in.redeem)?;
        check::card(tx, i, src_in.redeem)?;
        check::kspt_signatures(tx, i, &src_in)?;
        let have = src_in.signatures().count();
        let (need, shape) = needs(check::script_of(&src_in), src_in.redeem);
        if have == 0 {
            unsigned = unsigned.or(Some(i));
        }
        signed += have;
        complete &= need.is_some_and(|n| have >= n);
        shapes.add(shape);
        for sig in src_in.signatures() {
            shapes.at(i, sig.pubkey_pos);
        }
    }
    itself(signed, unsigned, tx.inputs.len(), complete, shapes)
}

/// [`kspt_itself`] for a bundle, with the signers it holds. `doc` is the
/// one-transaction bundle the session's transaction was read from; `redeem` is
/// scratch, the profile's `max_redeem`.
///
/// # Errors
///
/// As [`kspt_itself`]; `NotOneTransaction`, and the bundle's own when it does
/// not read.
pub fn pskb_itself(
    session: &Session<'_>,
    doc: &[u8],
    redeem: &mut [u8],
) -> Result<(Itself, Option<Signers>), Error> {
    let bundle = checked(doc)?;
    let count = bundle.transactions();
    if count != 1 {
        return Err(Error::NotOneTransaction { count });
    }
    let tx = session.transaction();
    let (mut signed, mut complete, mut shapes) = (0usize, true, Shapes::new());
    let mut unsigned = None;
    for (i, tx_in) in tx.inputs.iter().enumerate() {
        let extras = input_extras(bundle, 0, i, redeem).map_err(|e| match e {
            pskb::transaction::ReadError::BufferTooSmall => Error::ScratchTooSmall("redeem"),
            other => Error::PskbRead(other),
        })?;
        check::sighash_all(extras.sighash_type, i)?;
        check::sequence(tx, i)?;
        let spk = tx_in.utxo_entry.script_public_key;
        check::sig_ops(tx, i, extras.redeem)?;
        check::card(tx, i, extras.redeem)?;
        check::pskb_signatures(bundle, tx, i, spk, extras.redeem)?;
        // Each signer's position among the script's keys (the first holding its
        // key), as a KSPT states it, so a card signed by its recovery wallet
        // reads as a recovery.
        let mut have = 0usize;
        signers(bundle, 0, i, |key| {
            have += 1;
            if let Some(p) = schnorr_keys(extras.redeem).position(|k| k == &key[1..]) {
                shapes.at(i, u8::try_from(p).unwrap_or(u8::MAX));
            }
            true
        })?;
        let (need, shape) = needs(spk, extras.redeem);
        if have == 0 {
            unsigned = unsigned.or(Some(i));
        }
        signed += have;
        complete &= need.is_some_and(|n| have >= n);
        shapes.add(shape);
    }
    let found = itself(signed, unsigned, tx.inputs.len(), complete, shapes)?;
    Ok((found, check::pskb_signers(bundle, tx, redeem)))
}

/// Answer a PSKB request. `doc` is the decoded one-transaction bundle the
/// session's transaction was read from. `out` receives the envelope, `PSKB` and
/// hex: four bytes plus twice the edited document.
///
/// # Errors
///
/// `Session`, before anything is read, unless the session is confirmed;
/// `NotOneTransaction`; `NotTheReviewedTransaction` if the bundle does not read
/// as the session's transaction; every refusal of [`plan_pskb`]'s pass;
/// `ScratchTooSmall`; and the bundle's own read, edit, emit and envelope
/// errors.
pub fn pskb<'s, W: Borrow<Wallet>, E: Entropy + ?Sized>(
    session: &Session<'_>,
    doc: &'s [u8],
    keys: &Keyring<W>,
    rng: &mut E,
    scratch: &'s mut Scratch<'s>,
    out: &mut [u8],
) -> Result<Reply, Error> {
    session.require_confirmed()?;

    let bundle = checked(doc)?;
    let count = bundle.transactions();
    if count != 1 {
        return Err(Error::NotOneTransaction { count });
    }

    // The bundle must read as what was reviewed: the session's transaction
    // came from this document, and reading it again makes that a checked
    // fact, not a caller's promise.
    let Scratch {
        inputs,
        outputs,
        bytes,
        redeem,
        signatures,
        signed,
        partial,
        splices: edits,
        text,
        json,
    } = scratch;
    let tx = session.transaction();
    let same = check::same_transaction(doc, tx, inputs, outputs, bytes).map_err(|e| match e {
        pskb::transaction::ReadError::TooManyInputs { .. } => Error::ScratchTooSmall("inputs"),
        pskb::transaction::ReadError::TooManyOutputs { .. } => Error::ScratchTooSmall("outputs"),
        pskb::transaction::ReadError::BufferTooSmall => Error::ScratchTooSmall("bytes"),
        other => Error::PskbRead(other),
    })?;
    if !same {
        return Err(Error::NotTheReviewedTransaction);
    }

    let mut k = 0usize;
    let n = each_pskb_input(bundle, tx, keys, redeem, Pass::Sign, |i, m, held| {
        let slot = signatures
            .get_mut(k)
            .ok_or(Error::ScratchTooSmall("signatures"))?;
        *slot = *session.sign_input(i, m.key.private_key(), rng)?.as_bytes();
        let s = signed.get_mut(k).ok_or(Error::ScratchTooSmall("signed"))?;
        *s = Signed {
            input: i,
            public_key: *m.key.public_key(),
            derivation: held.derivation,
            redeem: m.supplied,
        };
        k += 1;
        Ok(())
    })?;

    // The members, borrowing the signatures now that none is being written.
    let signatures: &'s [[u8; SIGNATURE_LEN]] = &signatures[..n];
    if partial.len() < n {
        return Err(Error::ScratchTooSmall("partial"));
    }
    let signed: &'s [Signed] = &signed[..n];
    for (k, (sig, s)) in signatures.iter().zip(signed.iter()).enumerate() {
        partial[k] = PartialSig {
            input: s.input,
            public_key: &s.public_key,
            signature: sig,
            derivation: match s.derivation {
                Some(span) => Derivation::Value(&doc[span.start..span.end]),
                None => Derivation::Null,
            },
        };
    }
    let sigs = &partial[..n];
    let supplied = signed.iter().filter(|s| s.redeem.is_some()).count();
    let members = text_len(sigs);
    if text.len() < members.saturating_add(supplied.saturating_mul(REDEEM_VALUE_LEN)) {
        return Err(Error::ScratchTooSmall("text"));
    }
    if edits.len() < 2 * n + supplied {
        return Err(Error::ScratchTooSmall("splices"));
    }
    let (text, mut values) = text.split_at_mut(members);
    let mut e = splices(bundle, 0, sigs, text, edits)?;
    // Each supplied redeem script replaces its input's `null`; then the edits
    // are sorted into document order.
    for s in signed {
        let Some(redeem) = s.redeem else {
            continue;
        };
        let at = input_extras(bundle, 0, s.input, &mut [])
            .map_err(Error::PskbRead)?
            .redeem_at
            .ok_or(Error::PskbRead(pskb::transaction::ReadError::Malformed {
                scope: pskb::Scope::Input(s.input),
                field: pskb::Field::RedeemScript,
            }))?;
        let (value, rest) = core::mem::take(&mut values).split_at_mut(REDEEM_VALUE_LEN);
        value[0] = b'"';
        crate::text::write_hex(&redeem, &mut value[1..1 + 2 * KCC3_REDEEM_LEN]);
        value[REDEEM_VALUE_LEN - 1] = b'"';
        values = rest;
        edits[e] = Splice::replace(at, value);
        e += 1;
    }
    let edits = &mut edits[..e];
    for i in 1..edits.len() {
        let mut j = i;
        while j > 0 && edits[j - 1].at > edits[j].at {
            edits.swap(j - 1, j);
            j -= 1;
        }
    }
    let need = pskb::emitted_len(doc, edits)?;
    let json = json.get_mut(..need).ok_or(Error::ScratchTooSmall("json"))?;
    pskb::emit(doc, edits, json)?;
    let len = pskb::encode_envelope(json, out)?;
    Ok(Reply { len, signed: n })
}

/// The bundle checked whole, once, for the readers asked once per input.
fn checked(doc: &[u8]) -> Result<Checked<'_>, Error> {
    Ok(pskb::check(doc).map_err(pskb::transaction::ReadError::from)?)
}

// ── Checking our own work ───────────────────────────────────────────────────

/// The caller's buffers [`verify_pskb`] reads a PSKB reply back in, sized as
/// for a PSKB request.
pub struct ReadBack<'a> {
    /// Receives the decoded reply: as long as the reply.
    pub document: &'a mut [u8],
    /// Receives the reply's decoded scripts.
    pub scripts: &'a mut [u8],
    /// A redeem script, scratch: the profile's `max_redeem`.
    pub redeem: &'a mut [u8],
    /// One per input of the request.
    pub inputs: &'a mut [TransactionInput<'a>],
    /// One per output of the request.
    pub outputs: &'a mut [TransactionOutput<'a>],
}

/// Read a PSKB reply back and return its [`Signers`]; `scratch` is the caller's
/// [`ReadBack`].
///
/// Checked, as [`verify_kspt`] checks a KSPT reply: one transaction, byte for
/// byte the reviewed one; the device's keys in `partialSigs` where written; and
/// each of those signatures verified against its key over the reviewed
/// transaction's hash for its input, so a signature a companion could not spend
/// never goes out unreported. A cosigner's signature in the bundle was checked
/// on arrival, in [`plan_pskb`]'s pass, and comes back as it came.
///
/// # Errors
///
/// `DoesNotParse` if the envelope or document does not read;
/// `NotTheTransaction`; `Missing` or `Nothing` for signatures not where
/// written; `Malformed` for one of ours not a Schnorr signature; `Fails` for
/// one that does not verify.
pub fn verify_pskb<W: Borrow<Wallet>>(
    reply: &[u8],
    tx: &Transaction<'_>,
    keys: &Keyring<W>,
    wrote: usize,
    scratch: ReadBack<'_>,
) -> Result<Option<Signers>, Unverified> {
    let ReadBack {
        document,
        scripts,
        redeem,
        inputs,
        outputs,
    } = scratch;
    let n = pskb::decode_envelope(reply, document).map_err(|_| Unverified::DoesNotParse)?;
    let doc = &document[..n];
    let bundle = pskb::check(doc).map_err(|_| Unverified::DoesNotParse)?;
    if bundle.transactions() != 1 {
        return Err(Unverified::DoesNotParse);
    }
    if !check::same_transaction(doc, tx, inputs, outputs, scripts)
        .map_err(|_| Unverified::DoesNotParse)?
    {
        return Err(Unverified::NotTheTransaction);
    }
    // The first of ours that fails, reported as `verify_kspt` reports it; the
    // walk stops on any error, and this is read first.
    let mut bad = None;
    let walked = each_pskb_input(bundle, tx, keys, redeem, Pass::ReadBack, |i, m, held| {
        let Some(sig) = held.schnorr else {
            bad = Some(Unverified::Malformed { input: i });
            return Err(Error::NothingSigned);
        };
        let verifies = schnorr_signature_hash(tx, i, SIG_HASH_ALL)
            .is_some_and(|digest| bip340::verify(&m.key.x_only(), &digest, &sig));
        if !verifies {
            bad = Some(Unverified::Fails {
                input: i,
                position: m.position,
            });
            return Err(Error::NothingSigned);
        }
        Ok(())
    });
    if let Some(why) = bad {
        return Err(why);
    }
    let found = match walked {
        Ok(found) => found,
        Err(Error::NothingSigned) => return Err(Unverified::Nothing),
        Err(_) => return Err(Unverified::DoesNotParse),
    };
    if found < wrote {
        return Err(Unverified::Missing { wrote, found });
    }
    Ok(check::pskb_signers(bundle, tx, redeem))
}
