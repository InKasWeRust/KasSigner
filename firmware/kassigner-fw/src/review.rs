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

//! Reviewing a transaction before signing it.
//!
//! A person cannot confirm what they have not been shown: on a signer, whatever
//! a coordinator sends, this alone stands between a person and authorising
//! something they never read.
//!
//! The signature hash commits to every covenanted output, up to eight, so a
//! confirm screen showing one binding signs up to seven unseen; a screen
//! added for one field would leave the next new field signed and unseen. So
//! [`Review`] lists everything a signature commits to, tracks what has been
//! seen, and refuses to confirm until the two match. It holds no pixels, so it
//! is testable exactly.
//!
//! A page is seen when a caller says so, after drawing it: this guarantees no
//! page was skipped, not that a person looked. Every binding is shown, though
//! this device never builds a transaction spending several covenants: it signs
//! what others build.

use kassigner_kaspa::constants::STORAGE_MASS_PARAMETER;
use kassigner_kaspa::mass::{transaction_storage_mass, BLOCK_STORAGE_MASS_LIMIT};
use kassigner_kaspa::script::{classify, redeem_matches, ScriptClass};
use kassigner_kaspa::tx::Transaction;
use kassigner_protocol::card::savings::Savings;

pub use crate::limits::MAX_PAGES;

/// One thing a person must see: what has to appear, not how a display
/// draws it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page<'a> {
    /// Totals spent and received, and the fee stated outright: an inflated fee
    /// is the classic way to take value from a transaction that otherwise looks
    /// correct.
    ///
    /// The counts are here, not pages of their own: a person can check that
    /// eight outputs promised means eight output pages, and a lie about what
    /// the inputs are worth shows up in the fee.
    Summary {
        spending: u64,
        receiving: u64,
        fee: u64,
        inputs: usize,
        outputs: usize,
    },
    /// One output: how much, and where. The script is carried because the
    /// signature commits to it and an amount with no destination cannot be
    /// checked; the board turns it into an address.
    Output {
        index: usize,
        value: u64,
        script_version: u16,
        script: &'a [u8],
    },
    /// One covenant the transaction touches, apart from [`Page::Output`]: the
    /// signature commits to every binding however ordinary its output looks.
    /// One page a covenant, not one a binding, so a covenant with several
    /// outputs is one id to read.
    ///
    /// Either a covenant some input's UTXO is bound to (`from` is `None`):
    /// `spent` such inputs, and in `outputs` those that continue it, none if
    /// it ends here. Or one that starts here (`from` is its authorizing
    /// input): `outputs` are its first. Which a binding is, is upstream's
    /// rule (`CovenantsContext::from_tx`): it continues the covenant its
    /// authorizing input's UTXO is bound to, and any other id starts one.
    ///
    /// `outputs` has bit `i` set for output `i`; a review holds fewer
    /// outputs than it has bits.
    Covenant {
        id: [u8; 32],
        outputs: u32,
        spent: u16,
        from: Option<u16>,
    },
    /// The earliest the transaction may be included; a page only when set.
    /// `ignored` when every input's sequence is final, so consensus does not
    /// hold the transaction to it ([`Transaction::lock_time_binds`]); the
    /// signature covers it all the same.
    LockTime { value: u64, ignored: bool },
    /// The payload, when there is one: part of the signature hash.
    Payload { bytes: &'a [u8] },
    /// A Time-Locked Savings card the transaction spends: the first input
    /// spending it, and how many do.
    ///
    /// The signature commits to each input's script, which commits to the
    /// program through its hash, so the card's terms are signed: whose it is,
    /// who else may claim it, and from when. One page a card, after the summary
    /// and before the outputs, in the order the inputs first spend each.
    ///
    /// Whoever draws the page reads the card again from input `first`'s redeem
    /// script, in a KSPT or a bundle: a copy here would double every page's
    /// size, on the stack the flow rebuilds its review on at every step.
    Card { first: usize, count: usize },
}

/// [`Page::Covenant`]'s `outputs` is a `u32`, one bit an output.
const _: () = assert!(crate::limits::MAX_OUTPUTS <= u32::BITS as usize);

/// Why a review could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The transaction needs more pages than [`MAX_PAGES`].
    TooManyPages { needed: usize },
    /// The outputs total more than the inputs, or another amount
    /// [`Transaction::fee`] refuses. Not shown as a negative fee: a
    /// transaction with no valid fee is nothing to ask a person about.
    ValueOverflow,
    /// A page index that does not exist.
    NoSuchPage { index: usize },
    /// The subnetwork is not the native one; refused, not paged (see
    /// [`Review::new`]).
    NonNativeSubnetwork,
    /// Gas is set; refused, not paged, for the same reason.
    GasNotZero { gas: u64 },
    /// The storage mass, `mass`, is over the block limit
    /// ([`BLOCK_STORAGE_MASS_LIMIT`]), so a node's mempool refuses the
    /// transaction; refused, not paged.
    StorageMass { mass: u64 },
}

/// A transaction being reviewed, built from the transaction: its inputs
/// carry the UTXOs they spend, amounts included. The covenant a UTXO is
/// bound to is the one thing a transaction does not carry, and is given
/// beside it ([`Review::with_coins`]).
pub struct Review<'a> {
    pages: [Option<Page<'a>>; MAX_PAGES],
    count: usize,
    seen: u32,
}

impl<'a> Review<'a> {
    /// Enumerate everything a signature will commit to. The fee comes from the
    /// transaction, not an argument, so a caller cannot pass a wrong total.
    ///
    /// # Errors
    ///
    /// `ValueOverflow` for whatever [`Transaction::fee`] refuses;
    /// `TooManyPages` past [`MAX_PAGES`]; `NonNativeSubnetwork` or `GasNotZero`
    /// for fields a person cannot check and no ordinary payment carries;
    /// `StorageMass` for a transaction a node refuses for its storage mass.
    pub fn new(tx: &Transaction<'a>) -> Result<Self, Error> {
        Self::with_cards(tx, |_| None)
    }

    /// [`Review::new`] for inputs that may spend Time-Locked Savings cards.
    /// `cards(i)` gives the card input `i`'s redeem script reads as, if any;
    /// only script-hash inputs are asked. A card gets a [`Page::Card`] only if
    /// its program, rebuilt and hashed here, is what the input's script locks
    /// to; inputs locked by the same script share one page. Any other redeem
    /// gets no page; signing under it is the keyring's to refuse.
    ///
    /// # Errors
    ///
    /// As [`Review::new`].
    pub fn with_cards(
        tx: &Transaction<'a>,
        cards: impl FnMut(usize) -> Option<Savings>,
    ) -> Result<Self, Error> {
        Self::with_coins(tx, cards, &[])
    }

    /// [`Review::with_cards`] for inputs that may spend coins bound to a
    /// covenant. `coins` is each input's coin's covenant id as the request
    /// gives it, `None` if unbound; an input past its end counts as unbound.
    /// A bound coin takes more storage, which the storage mass counts
    /// (`kassigner_kaspa::mass::transaction_storage_mass`), and its covenant
    /// gets a page ([`Page::Covenant`]), which also says whether an output's
    /// binding continues it.
    ///
    /// # Errors
    ///
    /// As [`Review::new`].
    pub fn with_coins(
        tx: &Transaction<'a>,
        mut cards: impl FnMut(usize) -> Option<Savings>,
        coins: &[Option<[u8; 32]>],
    ) -> Result<Self, Error> {
        // Refused, not paged: consensus refuses gas on the native subnetwork,
        // allows a non-native one only for transactions no signer of ordinary
        // payments produces, and a twenty-byte identifier is nothing a person
        // can check.
        if !kassigner_kaspa::subnets::is_native(&tx.subnetwork_id) {
            return Err(Error::NonNativeSubnetwork);
        }
        if tx.gas != 0 {
            return Err(Error::GasNotZero { gas: tx.gas });
        }

        // Fee and totals by `kassigner-kaspa`'s consensus rule. Every refusal
        // is an amount consensus refuses, so all map to one error; in a session
        // none arrives, as the session ran the rule first.
        let fee = tx.fee().map_err(|_| Error::ValueOverflow)?;
        let input_total = tx.check_input_amounts().map_err(|_| Error::ValueOverflow)?;
        let receiving = input_total.checked_sub(fee).ok_or(Error::ValueOverflow)?;

        // Refused, not paged: a node's mempool refuses a transaction whose
        // storage mass is over the block limit (upstream's
        // `validate_transaction_limits_in_context`, `RejectStorageMass`), so
        // it could never be mined and is nothing to ask a person to confirm.
        // After the amounts' own rules, as in a node. Where upstream has no
        // number (an amount of zero, an overflow) the rules that own those
        // cases refuse, in a session before any review.
        if let Some(mass) = transaction_storage_mass(tx, coins, STORAGE_MASS_PARAMETER) {
            if mass > BLOCK_STORAGE_MASS_LIMIT {
                return Err(Error::StorageMass { mass });
            }
        }

        let mut pages: [Option<Page<'a>>; MAX_PAGES] = [None; MAX_PAGES];
        let mut count = 0usize;

        let push = |p: Page<'a>, count: &mut usize, pages: &mut [Option<Page<'a>>; MAX_PAGES]| {
            if *count < MAX_PAGES {
                pages[*count] = Some(p);
            }
            *count += 1;
        };

        push(
            Page::Summary {
                spending: input_total,
                receiving,
                fee,
                inputs: tx.inputs.len(),
                outputs: tx.outputs.len(),
            },
            &mut count,
            &mut pages,
        );

        // One page a card, counting the inputs that spend it.
        for (i, input) in tx.inputs.iter().enumerate() {
            let spk = &input.utxo_entry.script_public_key;
            if classify(spk) != ScriptClass::ScriptHash {
                continue;
            }
            let Some(card) = cards(i) else {
                continue;
            };
            if !redeem_matches(spk, &card.program()) {
                continue;
            }
            let held = pages
                .iter_mut()
                .take(count.min(MAX_PAGES))
                .find_map(|p| match p {
                    Some(Page::Card { first, count })
                        if tx
                            .inputs
                            .get(*first)
                            .is_some_and(|f| f.utxo_entry.script_public_key == *spk) =>
                    {
                        Some(count)
                    }
                    _ => None,
                });
            match held {
                Some(n) => *n += 1,
                None => push(Page::Card { first: i, count: 1 }, &mut count, &mut pages),
            }
        }

        for (i, o) in tx.outputs.iter().enumerate() {
            push(
                Page::Output {
                    index: i,
                    value: o.value,
                    script_version: o.script_public_key.version,
                    script: o.script_public_key.script,
                },
                &mut count,
                &mut pages,
            );
        }

        // Transaction-wide, after the outputs; each a page only when set.
        if tx.lock_time != 0 {
            push(
                Page::LockTime {
                    value: tx.lock_time,
                    ignored: !tx.lock_time_binds(),
                },
                &mut count,
                &mut pages,
            );
        }

        // The covenants: every binding is on one of these pages, the
        // signature hash committing to each, so one missed is one signed and
        // not shown. A binding continues the covenant its authorizing
        // input's UTXO is bound to; any other starts one.
        let coin = |i: usize| coins.get(i).copied().flatten();
        let continues = |c: &kassigner_kaspa::tx::CovenantBinding| {
            coin(usize::from(c.authorizing_input)) == Some(c.covenant_id)
        };
        let bit = |i: usize| {
            u32::try_from(i)
                .ok()
                .and_then(|i| 1u32.checked_shl(i))
                .unwrap_or(0)
        };
        // Those the inputs' UTXOs are bound to, in the inputs' order.
        for i in 0..tx.inputs.len() {
            let Some(id) = coin(i) else {
                continue;
            };
            if (0..i).any(|j| coin(j) == Some(id)) {
                continue;
            }
            let spent = (i..tx.inputs.len())
                .filter(|&j| coin(j) == Some(id))
                .count();
            let outputs = tx
                .outputs
                .iter()
                .enumerate()
                .filter(|(_, o)| {
                    o.covenant
                        .is_some_and(|c| c.covenant_id == id && continues(&c))
                })
                .fold(0, |mask, (o, _)| mask | bit(o));
            push(
                Page::Covenant {
                    id,
                    outputs,
                    spent: u16::try_from(spent).unwrap_or(u16::MAX),
                    from: None,
                },
                &mut count,
                &mut pages,
            );
        }
        // Those that start here, in the outputs' order: one for each id and
        // authorizing input, as upstream groups them.
        for (o, output) in tx.outputs.iter().enumerate() {
            let Some(c) = output.covenant.filter(|c| !continues(c)) else {
                continue;
            };
            let same = |other: &kassigner_kaspa::tx::CovenantBinding| {
                other.covenant_id == c.covenant_id
                    && other.authorizing_input == c.authorizing_input
                    && !continues(other)
            };
            if tx.outputs[..o]
                .iter()
                .any(|p| p.covenant.is_some_and(|b| same(&b)))
            {
                continue;
            }
            let outputs = tx
                .outputs
                .iter()
                .enumerate()
                .filter(|(_, p)| p.covenant.is_some_and(|b| same(&b)))
                .fold(0, |mask, (p, _)| mask | bit(p));
            push(
                Page::Covenant {
                    id: c.covenant_id,
                    outputs,
                    spent: 0,
                    from: Some(c.authorizing_input),
                },
                &mut count,
                &mut pages,
            );
        }
        if !tx.payload.is_empty() {
            push(Page::Payload { bytes: tx.payload }, &mut count, &mut pages);
        }

        if count > MAX_PAGES {
            return Err(Error::TooManyPages { needed: count });
        }
        Ok(Self {
            pages,
            count,
            seen: 0,
        })
    }

    /// How many pages there are.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there is nothing to show; never, as a review always has a
    /// summary.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// One page.
    ///
    /// # Errors
    ///
    /// `NoSuchPage` for an index past the end.
    pub fn page(&self, index: usize) -> Result<Page<'a>, Error> {
        self.pages
            .get(index)
            .and_then(|p| *p)
            .ok_or(Error::NoSuchPage { index })
    }

    /// Record that a page was drawn.
    ///
    /// # Errors
    ///
    /// `NoSuchPage` for an index past the end. Marking twice changes nothing.
    pub fn mark_seen(&mut self, index: usize) -> Result<(), Error> {
        if index >= self.count {
            return Err(Error::NoSuchPage { index });
        }
        self.seen |= 1 << index;
        Ok(())
    }

    /// Whether a page has been drawn.
    pub const fn is_seen(&self, index: usize) -> bool {
        index < self.count && (self.seen >> index) & 1 == 1
    }

    /// The first page not yet drawn: draw it, mark it, repeat until `None`.
    pub fn next_unseen(&self) -> Option<usize> {
        (0..self.count).find(|i| !self.is_seen(*i))
    }

    /// How many pages remain unseen, which a person is told so a long review
    /// does not feel like a hang.
    pub fn remaining(&self) -> usize {
        (0..self.count).filter(|i| !self.is_seen(*i)).count()
    }

    /// **Whether confirming is allowed**: only once every page has been
    /// drawn. A caller checks this before acting on a confirm press; it is
    /// why this type exists.
    pub fn may_confirm(&self) -> bool {
        self.count > 0 && self.remaining() == 0
    }
}
