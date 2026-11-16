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

//! Signing a transaction: review everything, take a deliberate
//! confirmation, draw randomness that cannot silently be absent, sign, and
//! check the signature before it leaves.
//!
//! # Why the whole flow is one type
//!
//! Each step is a security property worth something only in sequence. A
//! confirmation without a completed review authorises something unseen; a
//! signature without a confirmation, nothing anyone agreed to. Randomness
//! that quietly falls back to a deterministic nonce turns two signatures
//! over one message into a private key.
//!
//! Spread across a caller's control flow, a step can be skipped or put out
//! of order. [`Session`] is a state machine whose only way to a signature
//! runs through all of them, in order.
//!
//! # What it does not do
//!
//! It draws nothing and reads no touch: a caller renders a
//! [`crate::review::Page`] and reports what happened. That makes it exactly
//! testable, and keeps the drawing on the board side.

use kassigner_crypto::sign::{self, SignError, Signature};
use kassigner_hal::entropy::{self, Entropy};
use kassigner_kaspa::sighash::{schnorr_signature_hash, SigHashType, SIG_HASH_ALL};
use kassigner_kaspa::tx::{NonStandardError, Transaction, TxRuleError};

use crate::review::{self, Page, Review};
use kassigner_protocol::card::savings::Savings;
use kassigner_protocol::check::{self, TransactionError};

/// Why a session refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The transaction could not be reviewed at all.
    Review(review::Error),
    /// Signing was attempted before every page had been shown: the one this
    /// type exists for.
    NotReviewed { unseen: usize },
    /// Signing was attempted before a confirmation.
    NotConfirmed,
    /// The person declined.
    Declined,
    /// No usable randomness.
    ///
    /// Never a reason to sign anyway: BIP340 takes auxiliary randomness, and a
    /// signer falling back to a deterministic nonce without it is the
    /// differential-fault case: two signatures over one message on a device
    /// an attacker can glitch yield the key.
    NoEntropy(entropy::Error),
    /// The input index is not in the transaction.
    NoSuchInput { index: usize },
    /// A decision had already been made. It is made once, from the one stage
    /// where it can be; the stage carried here is the one that stands.
    AlreadyDecided { stage: Stage },
    /// Signing failed. `kassigner_crypto::sign` verifies every signature
    /// against its own public key before returning it, so this covers a
    /// faulted computation as well as a bad key.
    Sign(SignError),
    /// Consensus refuses the transaction on its own, such as a field its
    /// version does not allow. Refused before a review: it could never be
    /// mined, and a binding shown on version 0 is one its signature would not
    /// cover.
    Consensus(TxRuleError),
    /// A node's mempool refuses the transaction on its own: an output under
    /// a script version consensus does not run, which anyone could spend and
    /// which has no address to show, or one whose script is none of the
    /// standard forms. Refused before a review.
    NonStandard(NonStandardError),
}

impl From<review::Error> for Error {
    fn from(e: review::Error) -> Self {
        Error::Review(e)
    }
}

impl From<entropy::Error> for Error {
    fn from(e: entropy::Error) -> Self {
        Error::NoEntropy(e)
    }
}

impl From<SignError> for Error {
    fn from(e: SignError) -> Self {
        Error::Sign(e)
    }
}

/// What a person decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Go ahead. A caller produces this only on a deliberate release inside
    /// the confirm target, not on a press (`kassigner_hal::input`).
    Confirm,
    /// Do not.
    Decline,
}

/// Where a session is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Pages remain unshown.
    Reviewing,
    /// Everything has been shown; waiting on a decision.
    AwaitingDecision,
    /// Confirmed. Signing is allowed.
    Confirmed,
    /// Declined. Nothing further is allowed, ever ([`Session::decide`]).
    Declined,
}

/// A transaction being taken from arrival to signature.
pub struct Session<'a> {
    tx: Transaction<'a>,
    review: Review<'a>,
    stage: Stage,
}

impl<'a> Session<'a> {
    /// Begin.
    ///
    /// # Errors
    ///
    /// `Consensus` for an output worth nothing, amounts above Kaspa's
    /// supply, an outpoint spent twice, outputs worth more than the inputs, a
    /// version or a field consensus does not allow, or a covenant binding
    /// naming an input the transaction does not have; `NonStandard` for an
    /// output a node's mempool refuses; and whatever [`Review::new`] refuses:
    /// more pages than a review can hold, or fields it cannot show. Checked
    /// in a node's order: the transaction by itself, the mempool's rules,
    /// then what needs the inputs' spent outputs.
    pub fn new(tx: Transaction<'a>) -> Result<Self, Error> {
        Self::with_cards(tx, |_| None)
    }

    /// [`Session::new`] for a transaction whose inputs may spend Time-Locked
    /// Savings cards, `cards` giving the card input `i`'s redeem script reads
    /// as; each card is a page of the review ([`Review::with_cards`]).
    ///
    /// # Errors
    ///
    /// As [`Session::new`].
    pub fn with_cards(
        tx: Transaction<'a>,
        cards: impl FnMut(usize) -> Option<Savings>,
    ) -> Result<Self, Error> {
        Self::with_coins(tx, cards, &[])
    }

    /// [`Session::with_cards`] for a transaction whose inputs may spend coins
    /// bound to a covenant. `coins` is each input's coin's covenant id as the
    /// request gives it (a KSPT's `0x49` records, a bundle's
    /// `utxoEntry.covenantId`), `None` if unbound; an input past its end
    /// counts as unbound. No signature covers a coin's covenant: it is what a
    /// node knows of the coin, taken on the request's word.
    ///
    /// # Errors
    ///
    /// As [`Session::new`], and `Consensus` for an output bound to a covenant
    /// that neither continues its authorizing input's coin's nor has the id a
    /// new covenant makes (upstream's `WrongGenesisCovenantId`).
    pub fn with_coins(
        tx: Transaction<'a>,
        cards: impl FnMut(usize) -> Option<Savings>,
        coins: &[Option<[u8; 32]>],
    ) -> Result<Self, Error> {
        // The rules on the whole transaction, in a node's order, shared with
        // a companion preparing a bundle so the two cannot drift.
        check::transaction(&tx).map_err(|e| match e {
            TransactionError::Consensus(r) => Error::Consensus(r),
            TransactionError::NonStandard(r) => Error::NonStandard(r),
        })?;
        // Then what needs the coins: every binding against them, all of
        // upstream's `CovenantsContext::from_tx`, which a node runs after the
        // amounts (`validate_populated_transaction_and_get_fee`).
        tx.check_covenant_ids(coins).map_err(Error::Consensus)?;
        let review = Review::with_coins(&tx, cards, coins)?;
        Ok(Self {
            tx,
            review,
            stage: Stage::Reviewing,
        })
    }

    /// The signature hash type every signature from this session commits to,
    /// named because the review's guarantee rests on it: every output the
    /// person was shown is one the signature covers ([`Session::sign_input`]).
    pub const HASH_TYPE: SigHashType = SIG_HASH_ALL;

    /// Where this session is.
    pub const fn stage(&self) -> Stage {
        self.stage
    }

    /// The transaction under review.
    pub const fn transaction(&self) -> &Transaction<'a> {
        &self.tx
    }

    /// The next page to draw, or `None` when everything has been shown.
    pub fn next_page(&self) -> Option<(usize, Page<'a>)> {
        let i = self.review.next_unseen()?;
        self.review.page(i).ok().map(|p| (i, p))
    }

    /// Pages still to draw.
    pub fn remaining(&self) -> usize {
        self.review.remaining()
    }

    /// Pages in the review, shown or not.
    pub const fn pages(&self) -> usize {
        self.review.len()
    }

    /// The page at `index`.
    ///
    /// # Errors
    ///
    /// `Review` for an index that does not exist.
    pub fn page(&self, index: usize) -> Result<Page<'a>, Error> {
        Ok(self.review.page(index)?)
    }

    /// Record that a page was drawn. Once the last one is, the session moves
    /// to [`Stage::AwaitingDecision`] on its own, so a caller cannot forget.
    ///
    /// # Errors
    ///
    /// `Review` for an index that does not exist.
    pub fn page_shown(&mut self, index: usize) -> Result<(), Error> {
        self.review.mark_seen(index)?;
        if self.stage == Stage::Reviewing && self.review.may_confirm() {
            self.stage = Stage::AwaitingDecision;
        }
        Ok(())
    }

    /// Record what a person decided.
    ///
    /// # Errors
    ///
    /// `NotReviewed` if pages remain unshown: a decision taken before the
    /// review finished is about something unseen, and is refused rather than
    /// remembered; `AlreadyDecided` after a decision.
    pub fn decide(&mut self, decision: Decision) -> Result<(), Error> {
        // A decision is terminal, enforced here: `sign_input` checks the
        // stage, so a declined session that took a later `Confirm` would
        // sign.
        match self.stage {
            Stage::Reviewing => {
                return Err(Error::NotReviewed {
                    unseen: self.review.remaining(),
                })
            }
            Stage::AwaitingDecision => {}
            Stage::Confirmed | Stage::Declined => {
                return Err(Error::AlreadyDecided { stage: self.stage })
            }
        }
        self.stage = match decision {
            Decision::Confirm => Stage::Confirmed,
            Decision::Decline => Stage::Declined,
        };
        Ok(())
    }

    /// Refuse unless the session is confirmed: what [`Session::sign_input`]
    /// checks first, on its own so a caller about to do work before signing,
    /// such as reading a request for the inputs to sign, can refuse first.
    ///
    /// # Errors
    ///
    /// `NotReviewed` while pages remain, `NotConfirmed` while waiting on a
    /// decision, `Declined` after a decline.
    pub fn require_confirmed(&self) -> Result<(), Error> {
        match self.stage {
            Stage::Confirmed => Ok(()),
            Stage::Declined => Err(Error::Declined),
            Stage::Reviewing => Err(Error::NotReviewed {
                unseen: self.review.remaining(),
            }),
            Stage::AwaitingDecision => Err(Error::NotConfirmed),
        }
    }

    /// Sign one input, under [`Session::HASH_TYPE`]. Draws its own auxiliary
    /// randomness: there is no argument for it and no path that omits it.
    ///
    /// # The signature hash type is not a caller's to choose
    ///
    /// [`crate::review`] lists the outputs on the premise that the signature
    /// commits to them, and `SIGHASH_NONE` or `SIGHASH_SINGLE` commit to
    /// fewer or none: a signature under one would cover the transaction in a
    /// form the person did not review. So it is fixed at the one type
    /// KasSigner emits; another needs a review page first, not a parameter,
    /// so what a person is shown and what they authorise stay the same.
    ///
    /// # Errors
    ///
    /// As [`Session::require_confirmed`]; `NoSuchInput` for an index past the
    /// end, `NoEntropy` if the source is absent or failed its health test,
    /// `Sign` if the signature failed its own verification.
    pub fn sign_input<E: Entropy + ?Sized>(
        &self,
        input_index: usize,
        private_key: &[u8; 32],
        rng: &mut E,
    ) -> Result<Signature, Error> {
        self.require_confirmed()?;

        if input_index >= self.tx.inputs.len() {
            return Err(Error::NoSuchInput { index: input_index });
        }

        // Drawn here, not taken as an argument: a caller cannot supply a
        // constant, and a failed draw refuses the signature instead of
        // producing a deterministic one.
        let aux = rng.aux()?;

        let digest = schnorr_signature_hash(&self.tx, input_index, Self::HASH_TYPE)
            .ok_or(Error::NoSuchInput { index: input_index })?;
        Ok(sign::sign(private_key, &digest, &aux)?)
    }
}
