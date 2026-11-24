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

//! The review: a request's pages, CONFIRM SEND?, the signature and reply,
//! and which outputs are our own.

use super::*;

use kassigner_kaspa::derivation::CHANGE;
use kassigner_kaspa::multisig::redeem_script;
use kassigner_kaspa::pskb::signature::derivations;
use kassigner_protocol::group::MAX_REDEEM;

/// Where a request says an output's key is: on the held group's change
/// chain below a cosigner, or on a chain of the seed's single-key account.
#[derive(Clone, Copy)]
pub(super) enum Place {
    Group { cosigner: u32, index: u32 },
    Account { chain: u32, index: u32 },
}

/// How a request's inputs stand against the group held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Inputs {
    /// None spends a multisig.
    Plain,
    /// A group is held, and every input spends its script at a place the
    /// request names for that input.
    Group,
    /// One spends a multisig, and nothing proves them all the held group's:
    /// no group is held, or an input is not its.
    Unchecked,
}

/// Whether an input's redeem script is a multisig's, one the unit signs or
/// not: anything [`check::multisig`] does not call some other script.
fn is_multisig(redeem: &[u8]) -> bool {
    !matches!(check::multisig(redeem), Ok(None))
}

/// [`Flow::read_inputs`]'s count, and the script of the last address made,
/// so that one address's keys are derived once however many inputs spend
/// it.
struct Tally<'g> {
    group: Option<&'g HeldGroup>,
    branches: &'g Branches,
    multisig: usize,
    held: usize,
    plain: usize,
    made: Option<(u32, u32, u32)>,
    script: [u8; MAX_REDEEM],
    len: usize,
}

impl<'g> Tally<'g> {
    fn new(group: Option<&'g HeldGroup>, branches: &'g Branches) -> Self {
        Self {
            group,
            branches,
            multisig: 0,
            held: 0,
            plain: 0,
            made: None,
            script: [0; MAX_REDEEM],
            len: 0,
        }
    }

    /// Whether `redeem` is the held group's script at `place`. Only the
    /// index step where Multisig Address keeps the branch keys; all three
    /// steps from the group's keys where not.
    fn makes(&mut self, redeem: &[u8], place: Path) -> bool {
        let (
            Some(group),
            Path::Multisig {
                cosigner,
                chain,
                index,
            },
        ) = (self.group, place)
        else {
            return false;
        };
        if self.made != Some((cosigner, chain, index)) {
            self.made = None;
            let branches = self.branches;
            let made = if branches.ready() {
                let mut keys = [[0u8; 32]; limits::MAX_MULTISIG_KEYS];
                usize::try_from(cosigner)
                    .ok()
                    .and_then(|c| branches.keys_at(c, chain == CHANGE, index, &mut keys))
                    .and_then(|n| {
                        redeem_script(group.required(), &keys[..n], &mut self.script).ok()
                    })
            } else {
                group.redeem(cosigner, chain, index, &mut self.script).ok()
            };
            let Some(len) = made else {
                return false;
            };
            self.len = len;
            self.made = Some((cosigner, chain, index));
        }
        self.script[..self.len] == *redeem
    }

    /// An input that spends no multisig.
    fn plain(&mut self) {
        self.plain += 1;
    }

    /// An input that spends a multisig: the held group's (`ours`) or not.
    fn spent(&mut self, ours: bool) {
        self.multisig += 1;
        self.held += usize::from(ours);
    }

    const fn inputs(&self) -> Inputs {
        if self.multisig == 0 {
            Inputs::Plain
        } else if self.group.is_some() && self.held == self.multisig && self.plain == 0 {
            Inputs::Group
        } else {
            Inputs::Unchecked
        }
    }
}

impl<'b, const N: usize> Flow<'b, N> {
    /// Read the page on the screen, while [`State::Reviewing`].
    ///
    /// The page borrows the request, so it goes to `f`. `None` with no
    /// review, or a request that no longer parses.
    pub fn page<R>(&self, f: impl FnOnce(&Page<'_>) -> R) -> Option<R> {
        if self.state != State::Reviewing {
            return None;
        }
        let index = self.page;
        self.with_session(|s| s.page(index).ok().map(|p| f(&p)))
            .ok()
            .flatten()
    }

    /// The page on the screen as [`crate::ui::review`] draws it, while
    /// [`State::Reviewing`]: totals, an output, the lock time, a card or a
    /// covenant.
    /// `None` as for [`Flow::page`], and for a page the review does not draw
    /// (a request with one is refused as it arrives).
    pub fn review<R>(&self, f: impl FnOnce(&Shown<'_>) -> R) -> Option<R> {
        let keys = self.keys.as_ref();
        self.page(|p| {
            let shown = match *p {
                Page::Summary {
                    spending,
                    receiving,
                    fee,
                    inputs,
                    outputs,
                } => Shown::Summary {
                    totals: Totals {
                        out: receiving,
                        spent: spending,
                        fee,
                    },
                    inputs,
                    outputs,
                    group: self.group_shown(),
                    unchecked: self.unchecked(),
                },
                Page::Output {
                    index,
                    value,
                    script_version,
                    script,
                } => {
                    let spk = ScriptPublicKey {
                        version: script_version,
                        script,
                    };
                    // A key or a script's hash: the session refused any
                    // other form.
                    let (version, payload) = address_payload(&spk)?;
                    let mut text = [0u8; MAX_ADDRESS_LEN];
                    let n =
                        kaspa_address::encode(Prefix::Mainnet, version, payload, &mut text).ok()?;
                    let address = core::str::from_utf8(&text[..n]).ok()?;
                    // Our own at the place the request named, checked as it
                    // arrived ([`Flow::mark_change`]); else the seed's change
                    // or receive among the keys at hand, or for a script
                    // hash its KCC-3 bank's change.
                    let hinted = self.hinted.get(index).copied().flatten();
                    let change = match (hinted, version) {
                        (Some(own), _) => own,
                        (None, Version::PubKey) => keys
                            .and_then(|k| {
                                let key = <&[u8; 32]>::try_from(payload).ok()?;
                                match (k.change_index(key), k.has_chains()) {
                                    (Some(at), true) => Some(Change::At(at)),
                                    (Some(_), false) => Some(Change::Key),
                                    (None, true) => k.receive_index(key).map(Change::Yours),
                                    (None, false) => None,
                                }
                            })
                            .unwrap_or(Change::No),
                        (None, Version::ScriptHash) => keys
                            .and_then(|k| k.kcc3_change_index(<&[u8; 32]>::try_from(payload).ok()?))
                            .map_or(Change::No, Change::At),
                        (None, Version::PubKeyEcdsa) => Change::No,
                    };
                    return Some(f(&Shown::Output {
                        number: index + 1,
                        value,
                        address,
                        script: version == Version::ScriptHash,
                        change,
                    }));
                }
                Page::LockTime { value, ignored } => Shown::LockTime { value, ignored },
                Page::Covenant {
                    id,
                    outputs,
                    spent,
                    from,
                } => Shown::Covenant {
                    id,
                    spent: usize::from(spent),
                    outputs,
                    from: from.map(usize::from),
                },
                Page::Card { first, count } => {
                    // The card, read again from its first input's redeem
                    // script (the page exists only for one that reads), and
                    // the other key's address: the recovery wallet's when
                    // signing as the owner, else the owner's.
                    let card = self.card_at(first)?;
                    let mut text = [0u8; MAX_ADDRESS_LEN];
                    let n = card.address(&mut text).ok()?;
                    let address = core::str::from_utf8(&text[..n]).ok()?;
                    let recover = u32::try_from(first)
                        .ok()
                        .and_then(|i| self.review_second.checked_shr(i))
                        .is_some_and(|bits| bits & 1 == 1);
                    let other_key = if recover {
                        Some(card.owner())
                    } else {
                        card.recovery()
                    };
                    let mut other = [0u8; MAX_ADDRESS_LEN];
                    let other = match other_key {
                        Some(key) => {
                            let n = kaspa_address::encode(
                                Prefix::Mainnet,
                                Version::PubKey,
                                key,
                                &mut other,
                            )
                            .ok()?;
                            Some(core::str::from_utf8(&other[..n]).ok()?)
                        }
                        None => None,
                    };
                    return Some(f(&Shown::Card {
                        address,
                        unlock: card.unlock().ms(),
                        utxos: count,
                        recover,
                        other,
                    }));
                }
                _ => return None,
            };
            Some(f(&shown))
        })
        .flatten()
    }

    /// The review's three totals, while [`State::Reviewing`],
    /// [`State::Confirming`] or [`State::Signing`]: CONFIRM SEND?'s rows.
    pub fn totals(&self) -> Option<Totals> {
        self.summary().map(|(totals, _)| totals)
    }

    /// TX REVIEW's window, as CONFIRM SEND? draws it, while
    /// [`State::Reviewing`], [`State::Confirming`] or [`State::Signing`]:
    /// the totals, counts and M of N.
    pub fn summary(&self) -> Option<(Totals, Counted)> {
        if !matches!(
            self.state,
            State::Reviewing | State::Confirming | State::Signing
        ) {
            return None;
        }
        self.with_session(|s| match s.page(0) {
            Ok(Page::Summary {
                spending,
                receiving,
                fee,
                inputs,
                outputs,
            }) => Some((
                Totals {
                    out: receiving,
                    spent: spending,
                    fee,
                },
                Counted {
                    inputs,
                    outputs,
                    group: self.group_shown(),
                    unchecked: self.unchecked(),
                },
            )),
            _ => None,
        })
        .ok()
        .flatten()
    }

    /// Whether the request spends a multisig with no group held to check
    /// it against, which TX REVIEW and CONFIRM SEND? both say.
    fn unchecked(&self) -> bool {
        self.review_inputs == Some(Inputs::Unchecked)
    }

    /// The M of N the request's inputs spend; none for a single key's.
    pub(super) fn group_shown(&self) -> Option<(usize, usize)> {
        self.review_group
            .map(|(m, n)| (usize::from(m), usize::from(n)))
    }

    /// Whether the bytes are the ones the review started on, by SHA-256.
    /// Asked at CONFIRM SEND? and at signing, the steps a changed request
    /// must not pass; hashing at every page draw would add nothing to the
    /// signing's check.
    ///
    /// # Errors
    ///
    /// `RequestChanged` when they are not, or no review started.
    pub(super) fn unchanged(&self) -> Result<(), Refusal> {
        unchanged(self.request_digest, self.reviewed())
    }

    /// Marks each output paying our own at the place the request names
    /// ([`Flow::mark_account_change`], [`Flow::mark_group_change`]). The
    /// place is the request's word, the key is made here: a wrong place
    /// gives no mark, never a false one. One derivation per output.
    pub(super) fn mark_change(&mut self) {
        self.hinted = [None; limits::MAX_OUTPUTS];
        let mut places = [None; limits::MAX_OUTPUTS];
        self.change_places(&mut places);
        if places.iter().all(Option::is_none) {
            return;
        }
        self.mark_account_change(&places);
        self.mark_group_change(&places);
    }

    /// Each output to a key the request places on the seed's account,
    /// against the key derived there: CHANGE on the change chain, YOURS on
    /// receive. Not for a raw key, whose one address the bank already marks.
    /// A failed step marks nothing.
    pub(super) fn mark_account_change(&mut self, places: &[Option<Place>; limits::MAX_OUTPUTS]) {
        let Some(keys) = self.keys.as_ref().filter(|k| k.has_chains()) else {
            return;
        };
        let mut paid = [None; limits::MAX_OUTPUTS];
        let read = self.with_session(|s| {
            for (out, key) in s.transaction().outputs.iter().zip(paid.iter_mut()) {
                let spk = &out.script_public_key;
                if classify(spk) == ScriptClass::PubKey {
                    *key = spk
                        .script
                        .get(1..33)
                        .and_then(|k| <[u8; 32]>::try_from(k).ok());
                }
            }
        });
        if read.is_err() {
            return;
        }
        for (i, (place, key)) in places.iter().zip(&paid).enumerate() {
            let (Some(Place::Account { chain, index }), Some(key)) = (*place, key) else {
                continue;
            };
            let (path, own) = match chain {
                0 => (Path::receive(index), Change::Yours(index)),
                1 => (Path::change(index), Change::At(index)),
                _ => continue,
            };
            if keys.address_key(path).is_ok_and(|k| k == *key) {
                self.hinted[i] = Some(own);
            }
        }
    }

    /// In a spend of the held group's M of N, each output to a script
    /// address the request places on the group's change chain, against the
    /// group's address there. No search: searching the change chain took
    /// seconds on the M5. A failed step marks nothing.
    pub(super) fn mark_group_change(&mut self, places: &[Option<Place>; limits::MAX_OUTPUTS]) {
        // Change comes back to where the inputs left: marked only when the
        // inputs are the held group's too.
        if self.group.is_none() || self.inputs_held() != Inputs::Group {
            return;
        }
        let Some(group) = self.group.as_ref() else {
            return;
        };
        let held = (group.required(), group.total());
        if self
            .review_group
            .map(|(m, n)| (usize::from(m), usize::from(n)))
            != Some(held)
        {
            return;
        }
        // The outputs to a script's address, as text.
        let mut wanted = [[0u8; MAX_ADDRESS_LEN]; limits::MAX_OUTPUTS];
        let mut lens = [0usize; limits::MAX_OUTPUTS];
        let read = self.with_session(|s| {
            let outputs = s.transaction().outputs.iter().take(limits::MAX_OUTPUTS);
            for ((out, text), len) in outputs.zip(wanted.iter_mut()).zip(lens.iter_mut()) {
                let spk = &out.script_public_key;
                if classify(spk) != ScriptClass::ScriptHash {
                    continue;
                }
                if let Some(hash) = spk.script.get(2..34) {
                    *len = kaspa_address::encode(Prefix::Mainnet, Version::ScriptHash, hash, text)
                        .unwrap_or(0);
                }
            }
        });
        if read.is_err() {
            return;
        }
        let mut keys = [[0u8; 32]; limits::MAX_MULTISIG_KEYS];
        let mut text = [0u8; MAX_ADDRESS_LEN];
        for (i, ((out, &len), place)) in wanted.iter().zip(&lens).zip(places).enumerate() {
            let (Some(Place::Group { cosigner, index }), true) = (*place, len > 0) else {
                continue;
            };
            // Only the index step where Multisig Address keeps the branch
            // keys; all three steps from the group's keys where not.
            let made = if self.branches.ready() {
                usize::try_from(cosigner)
                    .ok()
                    .and_then(|c| self.branches.keys_at(c, true, index, &mut keys))
                    .and_then(|_| {
                        group
                            .address_of_keys(Prefix::Mainnet, &keys, &mut text)
                            .ok()
                    })
            } else {
                group
                    .address(Prefix::Mainnet, cosigner, 1, index, &mut text)
                    .ok()
            };
            if made.is_some_and(|n| n == len && out[..len] == text[..n]) {
                self.hinted[i] = Some(Change::At(index));
            }
        }
    }

    /// Where the request places each output's keys (a KSPT's output hints, a
    /// bundle's key paths): the group's change chain or the seed's account.
    /// Read as an input's, receive and change only; anything else is none.
    pub(super) fn change_places(&self, places: &mut [Option<Place>; limits::MAX_OUTPUTS]) {
        let on_change = |path: Option<Path>| match path {
            Some(Path::Multisig {
                cosigner,
                chain: 1,
                index,
            }) => Some(Place::Group { cosigner, index }),
            Some(Path::Single { chain, index }) => Some(Place::Account { chain, index }),
            _ => None,
        };
        if let Some(n) = self.document_len {
            let Ok(bundle) = pskb::check(&self.buffers.document[..n]) else {
                return;
            };
            for (i, place) in places.iter_mut().enumerate() {
                let path = pskb::signature::output_path(bundle, 0, i).and_then(keyring::path_of);
                *place = on_change(path);
            }
            return;
        }
        let request = &self.buffers.request[..self.request_len];
        let Ok(parsed) = kspt::legacy::parse_any(request, &self.profile) else {
            return;
        };
        for record in parsed.records() {
            let (index, path) = match record {
                kspt::Record::OutputHint(h) => (h.index, keyring::path_of_hint(h)),
                kspt::Record::AccountOutputHint(h) => (h.index, keyring::path_of_account_hint(h)),
                _ => continue,
            };
            if let Some(place) = places.get_mut(usize::from(index)) {
                *place = on_change(path);
            }
        }
    }

    /// How the held request's inputs stand against the group held
    /// ([`Inputs`]): read once a request, and kept for its review.
    pub(super) fn inputs_held(&mut self) -> Inputs {
        if let Some(known) = self.review_inputs {
            return known;
        }
        let found = self.read_inputs();
        self.review_inputs = Some(found);
        found
    }

    /// [`Flow::inputs_held`]'s reading: each multisig input's redeem script
    /// against the one the held group has at a place the request names for
    /// that input (a KSPT's hint, any of a bundle's key paths). The place is
    /// the request's word, the script is made here: a wrong place proves
    /// nothing. An input that does not read is not proven.
    fn read_inputs(&self) -> Inputs {
        let mut tally = Tally::new(self.group.as_ref(), &self.branches);
        if let Some(n) = self.document_len {
            let doc = &self.buffers.document[..n];
            let (Ok(bundle), Ok((count, _))) = (pskb::check(doc), pskb_tx::counts(doc, 0)) else {
                return Inputs::Unchecked;
            };
            let mut redeem = [0u8; MAX_REDEEM];
            for i in 0..count {
                let script = match pskb_tx::input_extras(bundle, 0, i, &mut redeem) {
                    Ok(extras) if is_multisig(extras.redeem) => extras.redeem,
                    // A script past a multisig's room is none the unit signs.
                    Ok(_) | Err(pskb_tx::ReadError::BufferTooSmall) => {
                        tally.plain();
                        continue;
                    }
                    Err(_) => return Inputs::Unchecked,
                };
                let mut ours = false;
                let read = derivations(bundle, 0, i, |entry| {
                    let place = entry.source.and_then(|(_, p)| keyring::path_of(p));
                    ours = place.is_some_and(|p| tally.makes(script, p));
                    !ours
                });
                tally.spent(ours && read.is_ok());
            }
            return tally.inputs();
        }
        let request = &self.buffers.request[..self.request_len];
        let Ok(parsed) = kspt::legacy::parse_any(request, &self.profile) else {
            return Inputs::Unchecked;
        };
        for (i, input) in parsed.inputs().enumerate() {
            if !is_multisig(input.redeem) {
                tally.plain();
                continue;
            }
            let place = reply::input_hint(&parsed, i).and_then(keyring::path_of_hint);
            let ours = place.is_some_and(|p| tally.makes(input.redeem, p));
            tally.spent(ours);
        }
        tally.inputs()
    }

    /// The pages: the arrows step back and forth, and past the last page,
    /// once every page has been drawn, go to CONFIRM SEND?. Back and Home
    /// cancel. A tap counts only on the target it went down on ([`tapped`]).
    /// A page the panel did not take refuses the review ([`Event::NotDrawn`]).
    pub(super) fn on_reviewing(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        if let Event::NotDrawn = event {
            self.seen &= !(1 << self.page);
            self.refuse(Refusal::NotDrawn);
            return None;
        }
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| {
            review_screen::target(self.scale, false, x, y)
        })? {
            // A transaction signed already, only being shown: left, not
            // declined.
            review_screen::Target::Nav(_) if self.reopened.is_some() => {
                self.drop_request();
                self.state = State::Home;
            }
            review_screen::Target::Nav(_) => self.refuse(Refusal::Declined),
            // An arrow reads the request again, so on the next tick
            // ([`Flow::review_arrow`]). Left on the first page: no click.
            review_screen::Target::Previous if self.page == 0 => {}
            t @ (review_screen::Target::Previous | review_screen::Target::Next) => {
                return self.defer(Work::Review(t));
            }
            _ => {}
        }
        None
    }

    /// A review arrow, on the tick after its tap: the page before or after,
    /// or past the last, once every page has been shown, CONFIRM SEND?.
    pub(super) fn review_arrow(&mut self, target: review_screen::Target) {
        let Ok((pages, deciding)) =
            self.with_session(|s| (s.pages(), s.stage() == Stage::AwaitingDecision))
        else {
            self.refuse(Refusal::NotARequest);
            return;
        };
        let last = self.page + 1 == pages;
        match target {
            review_screen::Target::Previous if self.page > 0 => self.page -= 1,
            review_screen::Target::Next if !last => self.page += 1,
            review_screen::Target::Next if deciding => match (self.unchanged(), self.reopened) {
                (Ok(()), Some(signers)) => self.show_signed(signers),
                (Ok(()), None) => self.state = State::Confirming,
                (Err(why), _) => self.refuse(why),
            },
            _ => {}
        }
    }

    /// A transaction this seed signed already, its review done: SIGNED TX QR
    /// for it as opened, copied to the reply's buffer (refused if larger).
    pub(super) fn show_signed(&mut self, signers: Option<reply::Signers>) {
        let n = self.request_len;
        let Some(reply) = self.buffers.reply.get_mut(..n) else {
            let ceiling = self.buffers.reply.len();
            self.refuse(Refusal::NotSigned(reply::Error::TooLargeToShow {
                needed: n,
                ceiling,
            }));
            return;
        };
        reply.copy_from_slice(&self.buffers.request[..n]);
        self.reply_len = n;
        self.reply_signers = signers;
        self.reply_v107 = 0;
        self.state = State::ReplyFormat;
    }

    /// CONFIRM SEND?: CONFIRM signs on the next tick ([`State::Signing`]);
    /// CANCEL, Back and Home decline; the left arrow goes back to the last
    /// page. A tap counts only on the target it went down on ([`tapped`]), so
    /// a slide from CANCEL signs nothing. If the panel did not take CONFIRM
    /// SEND?, nothing is there to answer: the review is refused
    /// ([`Event::NotDrawn`]).
    pub(super) fn on_confirming(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        if let Event::NotDrawn = event {
            self.refuse(Refusal::NotDrawn);
            return None;
        }
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| {
            review_screen::target(self.scale, true, x, y)
        })? {
            review_screen::Target::Confirm => self.state = State::Signing,
            review_screen::Target::Cancel | review_screen::Target::Nav(_) => {
                self.refuse(Refusal::Declined)
            }
            review_screen::Target::Previous => self.state = State::Reviewing,
            review_screen::Target::Next => {}
        }
        None
    }

    /// Confirm through the session and write the reply.
    ///
    /// Signing, and a bundle's read-back, derive keys: all in a frame of its
    /// own, scrubbed after, as for the plan.
    pub(super) fn sign<E: Entropy + ?Sized>(&mut self, rng: &mut E) {
        let outcome = self.write_signed(rng);
        wipe::scrub_flow();
        match outcome {
            Ok((len, signers, v107)) => {
                self.reply_len = len;
                self.reply_signers = signers;
                self.reply_v107 = v107;
                self.state = State::ReplyFormat;
            }
            Err(why) => {
                // A reply refused after it was written (by its read-back,
                // mostly) holds signatures over a confirmed transaction:
                // they go now, with the request, not whenever something
                // overwrites them. Its length was not kept: the whole buffer.
                wipe::wipe(self.buffers.reply);
                self.buffers.signatures.fill(InputSignature::EMPTY);
                self.refuse(why)
            }
        }
    }

    /// Sign, write and read back the reply, in a frame [`Flow::sign`]'s
    /// scrub can reach. Returns the reply's length, its signature count and
    /// the length of its v1.0.7 form ([`reply_v107`]), zero for none.
    #[inline(never)]
    pub(super) fn write_signed<E: Entropy + ?Sized>(
        &mut self,
        rng: &mut E,
    ) -> Result<(usize, Option<reply::Signers>, usize), Refusal> {
        self.unchanged()?;
        let keys = self.keys.as_ref().ok_or(Refusal::NoWallet)?;
        if let Some(n) = self.document_len {
            return write_reply_pskb(n, self.seen, keys, rng, &mut self.buffers).and_then(
                |(len, wrote)| {
                    // Read back as the companion would, against the request's
                    // transaction, rebuilt in stack scratch: its own scripts
                    // buffer receives the reply's.
                    let mut scripts = [0u8; limits::MAX_PSKB_BYTES];
                    let mut inputs = [BLANK_IN; limits::MAX_INPUTS];
                    let mut outputs = [BLANK_OUT; limits::MAX_OUTPUTS];
                    let mut reread_in = [BLANK_IN; limits::MAX_INPUTS];
                    let mut reread_out = [BLANK_OUT; limits::MAX_OUTPUTS];
                    let session = build_pskb(
                        &self.buffers.document[..n],
                        &mut scripts,
                        &mut inputs,
                        &mut outputs,
                    )?;
                    let signers = reply::verify_pskb(
                        &self.buffers.reply[..len],
                        session.transaction(),
                        keys,
                        wrote,
                        reply::ReadBack {
                            document: self.buffers.edited,
                            scripts: self.buffers.scripts,
                            redeem: self.buffers.redeem,
                            inputs: &mut reread_in,
                            outputs: &mut reread_out,
                        },
                    )
                    .map_err(Refusal::NotVerified)?;
                    Ok((len, signers, 0))
                },
            );
        }
        let request = &self.buffers.request[..self.request_len];
        let (len, signers) = write_reply(
            request,
            &self.profile,
            self.seen,
            keys,
            rng,
            self.buffers.signatures,
            self.buffers.reply,
        )?;
        let v107 = reply_v107(
            request,
            &self.buffers.reply[..len],
            &self.profile,
            self.buffers.edited,
        );
        Ok((len, signers, v107))
    }

    pub(super) fn drop_request(&mut self) {
        if let Some(keys) = self.keys.as_mut() {
            keys.forget_found();
        }
        wipe::wipe(&mut self.buffers.request[..self.request_len]);
        self.request_len = 0;
        self.request_digest = None;
        // A bundle's document and what reading and signing it left: its
        // scripts, the reply's generated members and bundle read back.
        if let Some(n) = self.document_len.take() {
            wipe::wipe(&mut self.buffers.document[..n]);
            wipe::wipe(self.buffers.scripts);
            wipe::wipe(self.buffers.text);
            wipe::wipe(self.buffers.edited);
        }
        // A multisig's redeem script, a bundle's or a KSPT's.
        wipe::wipe(self.buffers.redeem);
        self.seen = 0;
        self.page = 0;
        self.review_group = None;
        self.review_second = 0;
        self.review_signs = (0, 0);
        self.review_inputs = None;
        self.reopened = None;
        self.hinted = [None; limits::MAX_OUTPUTS];
    }

    /// The card input `input` of the held request spends, read from its
    /// redeem script: the bundle's `redeemScript`, or the KSPT's own.
    fn card_at(&self, input: usize) -> Option<Savings> {
        match self.document_len {
            Some(n) => bundle_card(pskb::check(&self.buffers.document[..n]).ok()?, input),
            None => {
                let request = &self.buffers.request[..self.request_len];
                let parsed = kspt::legacy::parse_any(request, &self.profile).ok()?;
                kspt_card(&parsed, input)
            }
        }
    }

    /// Rebuild the session from the held request, replay the pages drawn,
    /// and read something from it.
    pub(super) fn with_session<R>(&self, f: impl FnOnce(&Session<'_>) -> R) -> Result<R, Refusal> {
        let request = &self.buffers.request[..self.request_len];
        let mut inputs = [BLANK_IN; limits::MAX_INPUTS];
        let mut outputs = [BLANK_OUT; limits::MAX_OUTPUTS];
        if let Some(n) = self.document_len {
            let mut scripts = [0u8; limits::MAX_PSKB_BYTES];
            let mut session = build_pskb(
                &self.buffers.document[..n],
                &mut scripts,
                &mut inputs,
                &mut outputs,
            )?;
            replay(&mut session, self.seen);
            return Ok(f(&session));
        }
        let (_, mut session) = build(request, &self.profile, &mut inputs, &mut outputs)?;
        replay(&mut session, self.seen);
        Ok(f(&session))
    }
}

/// Parse a request and build its session over the caller's arrays.
///
/// Any version the device has read: `0x06`, and `0x01` to `0x05` from an
/// older companion. The reply is always `0x06`, a legacy request re-encoded
/// canonically; a single-key `0x01` request gets its v1.0.7 form beside it
/// ([`reply_v107`]).
pub(super) fn build<'a>(
    request: &'a [u8],
    profile: &Profile,
    inputs: &'a mut [TransactionInput<'a>],
    outputs: &'a mut [TransactionOutput<'a>],
) -> Result<(Kspt<'a>, Session<'a>), Refusal> {
    let parsed = kspt::legacy::parse_any(request, profile).map_err(|e| match e {
        // A covenant binding out of range, refused by the parser, is said as
        // the later steps would: an output past the outputs as no
        // transaction, an input past the inputs as consensus refuses it.
        KsptError::RecordIndexOutOfRange { marker: 0x43, .. } => Refusal::NotATransaction,
        KsptError::AuthorizingInputOutOfRange { output, input, .. } => {
            Refusal::NotReviewable(crate::session::Error::Consensus(
                kassigner_kaspa::tx::TxRuleError::AuthInputOutOfBounds(usize::from(output), input),
            ))
        }
        _ => Refusal::NotARequest,
    })?;
    let (ni, no) =
        kspt::transaction::fill(&parsed, inputs, outputs).map_err(|_| Refusal::NotATransaction)?;
    let tx = kspt::transaction::build(&parsed, &inputs[..ni], &outputs[..no]);
    // Each coin's covenant, from the request's `0x49` records.
    let mut coins = [None; limits::MAX_INPUTS];
    kspt::transaction::coins(&parsed, &mut coins[..ni]);
    // The cards the inputs' redeem scripts are, for the review's pages.
    let session = Session::with_coins(tx, |i| kspt_card(&parsed, i), &coins[..ni])
        .map_err(Refusal::NotReviewable)?;
    Ok((parsed, session))
}

/// The card input `i` of a KSPT spends, when its redeem script is one.
fn kspt_card(parsed: &Kspt<'_>, i: usize) -> Option<Savings> {
    Savings::from_program(parsed.inputs().nth(i)?.redeem).ok()
}

/// The card input `i` of a bundle's transaction spends, when its
/// `redeemScript` is one; read into a card program's room, so anything
/// longer is none.
fn bundle_card(bundle: pskb::Checked<'_>, i: usize) -> Option<Savings> {
    let mut program = [0u8; PROGRAM_LEN];
    let extras = pskb_tx::input_extras(bundle, 0, i, &mut program).ok()?;
    Savings::from_program(extras.redeem).ok()
}

/// Rebuild the session over `request`, replay the pages drawn, confirm,
/// write the reply into `out`, and verify it back. Returns its length and
/// its signature count.
///
/// The one place a KSPT reply is signed ([`write_reply_pskb`] signs a
/// bundle), with `Session::decide` the gate. Everything is an argument, so
/// the borrows are visibly disjoint.
pub(super) fn write_reply<E: Entropy + ?Sized>(
    request: &[u8],
    profile: &Profile,
    seen: u32,
    keys: &Keyring,
    rng: &mut E,
    signatures: &mut [InputSignature],
    out: &mut [u8],
) -> Result<(usize, Option<reply::Signers>), Refusal> {
    let mut inputs = [BLANK_IN; limits::MAX_INPUTS];
    let mut outputs = [BLANK_OUT; limits::MAX_OUTPUTS];
    let (parsed, mut session) = build(request, profile, &mut inputs, &mut outputs)?;
    replay(&mut session, seen);
    session
        .decide(Decision::Confirm)
        .map_err(Refusal::NotReviewable)?;
    reply::plan_kspt(&session, &parsed, keys, profile, out.len(), signatures).map_err(planned)?;
    let written = reply::kspt(&session, &parsed, keys, profile, rng, signatures, out)
        .map_err(Refusal::NotSigned)?;
    // Read back as the companion would, against the transaction as the
    // request gave it and the session showed it.
    let reply = &out[..written.len];
    reply::verify_kspt(reply, session.transaction(), profile).map_err(Refusal::NotVerified)?;
    Ok((written.len, reply::kspt_signers(reply, profile)))
}

/// `reply` again as a v1.0.7 unit wrote it, into `out`, returning its
/// length: for a wallet built on that release, which sends a single-key
/// request as KSPT `0x01` and reads only that answer, in that release's
/// frames. It is there for those wallets and goes once they read `0x06`.
///
/// Nothing new is signed: the signatures are `reply`'s, each input's one,
/// put after the request's own bytes ([`kspt::legacy::write_signed`]). What
/// is written is read back by the legacy reader and every signature
/// verified against the request's transaction, as `reply` was: the request
/// is the one reviewed, held to its digest until it was signed
/// ([`Flow::unchanged`]).
///
/// Zero, and `out` left clean, when there is no such answer: a request of
/// another version or with redeem scripts, an input with other than one
/// signature at its script's own key or with a redeem script supplied, a
/// reply past `out` or past v1.0.7's 64 frames, or one that does not read
/// back. A wallet is then shown `reply` as any other.
///
/// In a frame of its own, after the signing's is gone: it rebuilds the
/// transaction on the stack, as the signing did.
#[inline(never)]
fn reply_v107(request: &[u8], reply: &[u8], profile: &Profile, out: &mut [u8]) -> usize {
    let (Ok(asked), Ok(parsed)) = (
        kspt::legacy::parse(request, profile),
        kspt::parse(reply, profile),
    ) else {
        return 0;
    };
    let mut inputs = [BLANK_IN; limits::MAX_INPUTS];
    let mut outputs = [BLANK_OUT; limits::MAX_OUTPUTS];
    let Ok((ni, no)) = kspt::transaction::fill(&asked, &mut inputs, &mut outputs) else {
        return 0;
    };
    let tx = kspt::transaction::build(&asked, &inputs[..ni], &outputs[..no]);
    let mut signatures = [[0u8; SIGNATURE_LEN]; limits::MAX_INPUTS];
    let mut signed = 0;
    for input in parsed.inputs() {
        let mut held = input.signatures();
        let (Some(signature), None) = (held.next(), held.next()) else {
            return 0;
        };
        let (Some(slot), Ok(bytes)) = (
            signatures.get_mut(signed),
            <[u8; SIGNATURE_LEN]>::try_from(signature.bytes),
        ) else {
            return 0;
        };
        if signature.pubkey_pos != 0 || !input.redeem.is_empty() {
            return 0;
        }
        *slot = bytes;
        signed += 1;
    }
    let Ok(len) = kspt::legacy::write_signed(request, profile, &signatures[..signed], out) else {
        return 0;
    };
    let shown = frame::v107::codes(len) <= frame::v107::MAX_FRAMES;
    if shown && reply::verify_kspt_v107(&out[..len], &tx, profile) == Ok(signed) {
        len
    } else {
        wipe::wipe(&mut out[..len]);
        0
    }
}

/// Read a bundle's first transaction and build its session over the caller's
/// arrays. `doc` is the decoded document; `scripts` receives its scripts.
pub(super) fn build_pskb<'a>(
    doc: &[u8],
    scripts: &'a mut [u8],
    inputs: &'a mut [TransactionInput<'a>],
    outputs: &'a mut [TransactionOutput<'a>],
) -> Result<Session<'a>, Refusal> {
    let filled =
        pskb_tx::fill(doc, 0, inputs, outputs, scripts).map_err(|_| Refusal::NotATransaction)?;
    let tx = pskb_tx::build(
        &filled.header,
        &inputs[..filled.inputs],
        &outputs[..filled.outputs],
    );
    // The cards the inputs' `redeemScript`s are, for the review's pages: a
    // card in a bundle is shown and signed as in a KSPT.
    let bundle = pskb::check(doc).ok();
    let cards = |i: usize| bundle.and_then(|b| bundle_card(b, i));
    // Each coin's covenant, from its `utxoEntry.covenantId`. One that does
    // not read is no transaction to review.
    let mut coins = [None; limits::MAX_INPUTS];
    if let Some(b) = bundle {
        for (i, coin) in coins.iter_mut().enumerate().take(filled.inputs) {
            *coin = pskb_tx::input_covenant_id(b, 0, i).map_err(|_| Refusal::NotATransaction)?;
        }
    }
    Session::with_coins(tx, cards, &coins[..filled.inputs]).map_err(Refusal::NotReviewable)
}

/// [`write_reply`] for a bundle, the first `n` bytes of `buffers.document`:
/// the reply bundle goes into `buffers.reply`. Returns its length and how
/// many inputs it signed, for the read-back.
pub(super) fn write_reply_pskb<E: Entropy + ?Sized>(
    n: usize,
    seen: u32,
    keys: &Keyring,
    rng: &mut E,
    buffers: &mut Buffers<'_>,
) -> Result<(usize, usize), Refusal> {
    let Buffers {
        document,
        scripts,
        redeem,
        text,
        edited,
        reply: out,
        ..
    } = buffers;
    let doc = &document[..n];
    let mut inputs = [BLANK_IN; limits::MAX_INPUTS];
    let mut outputs = [BLANK_OUT; limits::MAX_OUTPUTS];
    let mut session = build_pskb(doc, scripts, &mut inputs, &mut outputs)?;
    replay(&mut session, seen);
    session
        .decide(Decision::Confirm)
        .map_err(Refusal::NotReviewable)?;
    reply::plan_pskb(&session, doc, keys, out.len(), redeem).map_err(planned)?;

    // The reply re-reads the bundle into its own arrays, and refuses unless
    // it reads as the session's transaction.
    let mut reread = [0u8; limits::MAX_PSKB_BYTES];
    let mut reread_in = [BLANK_IN; limits::MAX_INPUTS];
    let mut reread_out = [BLANK_OUT; limits::MAX_OUTPUTS];
    let mut signatures = [[0u8; SIGNATURE_LEN]; limits::MAX_INPUTS];
    let mut signed = [reply::Signed::EMPTY; limits::MAX_INPUTS];
    let mut partial = [PartialSig {
        input: 0,
        public_key: &[0; 33],
        signature: &[0; SIGNATURE_LEN],
        derivation: Derivation::Null,
    }; limits::MAX_INPUTS];
    let mut splices = [Splice::insert_at(0, &[]); 3 * limits::MAX_INPUTS];
    let mut scratch = reply::Scratch {
        inputs: &mut reread_in,
        outputs: &mut reread_out,
        bytes: &mut reread,
        redeem,
        signatures: &mut signatures,
        signed: &mut signed,
        partial: &mut partial,
        splices: &mut splices,
        text,
        json: edited,
    };
    let written =
        reply::pskb(&session, doc, keys, rng, &mut scratch, out).map_err(Refusal::NotSigned)?;
    Ok((written.len, written.signed))
}

/// Mark in a fresh session the pages a person has seen.
pub(super) fn replay(session: &mut Session<'_>, seen: u32) {
    for i in 0..limits::MAX_PAGES {
        if seen & (1 << i) != 0 {
            let _ = session.page_shown(i);
        }
    }
}
