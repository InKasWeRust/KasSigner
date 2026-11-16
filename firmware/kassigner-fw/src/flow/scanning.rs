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

//! The scanner, and a request from arrival to review: the search for its
//! keys, its plan, and a signed transaction opened again.

use super::*;

/// Whether `bytes` look like a group's descriptor: `multi_hd45(`, with or
/// without a `#` line over it. Its keys are checked as it is read.
pub(super) fn is_descriptor(bytes: &[u8]) -> bool {
    use kassigner_protocol::descriptor::{strip_header, PREFIX};
    core::str::from_utf8(bytes).is_ok_and(|t| strip_header(t).starts_with(PREFIX))
}

/// The first page of `session` the review does not draw yet, then any
/// input's relative lock, which the signature covers and no page shows
/// ([`check::sequence`]).
pub(super) fn unshown(session: &Session<'_>) -> Result<(), Refusal> {
    for i in 0..session.pages() {
        if let Ok(Page::Payload { .. }) = session.page(i) {
            return Err(Refusal::Unshown(Unshown::Payload));
        }
    }
    let tx = session.transaction();
    if (0..tx.inputs.len()).any(|i| check::sequence(tx, i).is_err()) {
        return Err(Refusal::Unshown(Unshown::RelativeLock));
    }
    Ok(())
}

impl<'b, const N: usize> Flow<'b, N> {
    pub(super) fn on_scanning(&mut self, event: Event<'_>) -> Option<Command> {
        // A group's key: whatever is read is taken as one, or refused.
        if self.adding_keys() {
            match event {
                Event::Payload(bytes) | Event::Code(bytes) | Event::Opaque(bytes) => {
                    self.take_cosigner(bytes);
                    return Some(Command::CameraOff);
                }
                // A code that could be a seed: not what is asked for here.
                Event::LastFrameOrSeed => return None,
                _ => {}
            }
        }
        match event {
            // A transmission began: whatever was held was one of its frames.
            Event::Progress {
                have,
                total,
                received,
            } => {
                self.progress = (have, total);
                self.received = received;
                self.seed_or_frame = None;
                self.seed_hint = false;
                None
            }
            Event::LastFrameOrSeed => {
                let now = self.now_us;
                let first = match self.seed_or_frame {
                    Some((first, last)) if now.saturating_sub(last) <= SEED_GAP_US => first,
                    _ => now,
                };
                self.seed_or_frame = Some((first, now));
                if now.saturating_sub(first) >= SEED_HINT_US {
                    self.seed_hint = true;
                }
                None
            }
            // Only the back button leaves: to KEY k/N while a group wants
            // keys. The viewfinder is not a button.
            Event::Tap { x, y } => {
                if !camera::back(self.scale).contains(x, y) {
                    return None;
                }
                self.state = if self.adding_keys() {
                    State::AddKey
                } else {
                    State::Home
                };
                Some(Command::CameraOff)
            }
            // A group's descriptor, one code or a unit's frames (v1.0.7's
            // too): LOAD MULTISIG?, or why not.
            Event::Payload(bytes) | Event::Opaque(bytes) | Event::Code(bytes)
                if is_descriptor(bytes) =>
            {
                if !self.ask_load(bytes, State::Home) {
                    self.refuse(Refusal::NotADescriptor);
                }
                Some(Command::CameraOff)
            }
            // A covenant card's backup line, one code or frames: SAVINGS
            // CARD, or why not.
            Event::Opaque(bytes) | Event::Code(bytes) if savings::is_card_backup(bytes) => {
                self.scanned_card(bytes);
                Some(Command::CameraOff)
            }
            // A kpub in frames, v1.0.7's or v1.1.0's, or a request.
            Event::Payload(bytes) => {
                match crate::kpub::read(bytes) {
                    Some(public) => self.take_kpub(&public),
                    None => self.take_request(bytes),
                }
                Some(Command::CameraOff)
            }
            // A signed message, opened to be checked. Other text is for Sign
            // Message.
            Event::Opaque(bytes) | Event::Code(bytes)
                if crate::message::read(bytes).is_some()
                    && bytes.len() <= self.buffers.request.len() =>
            {
                self.buffers.request[..bytes.len()].copy_from_slice(bytes);
                self.take_message(bytes.len(), false);
                self.msg_from = State::Home;
                Some(Command::CameraOff)
            }
            // Frames of text that are not a signed message: seed words, or
            // Sign Message's.
            Event::Opaque(bytes) => {
                wipe::begin_depth(self.stack);
                self.take_words(bytes, Refusal::PlainText);
                Some(Command::CameraOff)
            }
            // A kpub as text, or a SeedQR.
            Event::Code(bytes) if bytes.starts_with(b"kpub") => {
                match crate::kpub::read(bytes) {
                    Some(public) => self.take_kpub(&public),
                    None => self.refuse(Refusal::NotAKpub),
                }
                Some(Command::CameraOff)
            }
            Event::Code(bytes) => {
                wipe::begin_depth(self.stack);
                match seed::read_qr(bytes) {
                    Ok((m, _)) => {
                        self.hold_loaded(m);
                        self.state = State::Loading;
                    }
                    Err(seed::ReadError::NotSeedQr) => {
                        self.take_words(bytes, Refusal::NotRecognised)
                    }
                    Err(_) => self.refuse(Refusal::NotASeed),
                }
                Some(Command::CameraOff)
            }
            Event::CameraLost => {
                self.refuse(Refusal::NoCamera);
                Some(Command::CameraOff)
            }
            _ => None,
        }
    }

    /// Seed words from the main scanner (a Plain Words QR): a seed goes to
    /// LOAD SEED?; list words that are no seed are refused unshown; anything
    /// else as `otherwise`. Twelve words are at least 47 characters, never a
    /// compact SeedQR's 16 or 32.
    pub(super) fn take_words(&mut self, bytes: &[u8], otherwise: Refusal) {
        if !crate::text::is_message(bytes) {
            return self.refuse(otherwise);
        }
        match seed::read_words(bytes) {
            seed::Text::Seed(m) => {
                self.hold_loaded(m);
                self.state = State::Loading;
            }
            seed::Text::Invalid => self.refuse(Refusal::NotASeed),
            seed::Text::NotWords => self.refuse(otherwise),
        }
    }

    /// A payload while scanning: held and checked next tick, under CHECKING
    /// ([`State::Checking`]), or refused.
    pub(super) fn take_request(&mut self, bytes: &[u8]) {
        // Only bytes that start with a request's magic reach the request's
        // buffer, PSRAM that survives a reset: anything else (seed words
        // framed as a transaction, say) is refused where it lies.
        let marked = bytes.starts_with(&kspt::MAGIC) || bytes.starts_with(pskb::MAGIC);
        if !marked || bytes.len() > self.buffers.request.len() {
            self.refuse(Refusal::NotARequest);
            return;
        }
        self.buffers.request[..bytes.len()].copy_from_slice(bytes);
        self.state = State::Checking {
            len: bytes.len(),
            card: false,
        };
    }

    /// The request in the request buffer's first `n` bytes, scanned or from
    /// the card (`card`): held and its review started, or refused.
    pub(super) fn start_request(&mut self, n: usize, card: bool) {
        self.request_len = n;
        self.reopened = None;
        self.review_inputs = None;
        self.seen = 0;
        self.page = 0;
        if card && self.open_signed() {
            return;
        }
        // A seed made here with no backup signs nothing until it has one.
        if !self.backed_or_refuse() {
            return;
        }
        // Planned now, so a request that cannot be signed is refused before
        // a person reads it; `reply` makes the same pass at signing, so the
        // two agree.
        //
        // Planning derives a private key per matched input, through HMAC and
        // the curve, which leave copies no type can wipe (see `wipe`): hence
        // a frame of its own, and the scrub after it returns.
        //
        // The plan looks only at the first addresses, keys the sweep found,
        // and hints (further could take minutes). With nothing placed it
        // asks before deriving more keys; with some inputs ours, it does not.
        if let Some(keys) = self.keys.as_mut() {
            keys.forget_found();
        }
        let planned = self.plan_request();
        wipe::scrub_flow();
        // Signed by this seed already, from the card: shown, never signed
        // again, so a saved send can be broadcast later. Scanned, or opened
        // by neither read below, it is refused as already signed.
        let already = matches!(
            planned,
            Err(Refusal::NotSigned(reply::Error::AlreadySigned { .. }))
        );
        if card && already {
            let reopened = self.reopen_request();
            wipe::scrub_flow();
            if let Ok(signers) = reopened {
                return self.show_reopened(signers);
            }
            // Signed by this seed in part: shown by itself, to pass along,
            // unless an input holds no signature at all, whose amount
            // nothing checks.
            match self.read_itself() {
                Ok((found, signers)) => return self.show_itself(found, signers),
                Err(why @ Refusal::NotSigned(reply::Error::InputUnsigned { .. })) => {
                    return self.refuse(why);
                }
                Err(_) => {}
            }
        }
        if planned.is_ok() {
            self.mark_change();
        }
        let misses = self.keys.as_ref().map_or(0, |k| k.misses());
        let kcc3_misses = self.keys.as_ref().map_or(0, |k| k.kcc3_misses());
        let chains = self.keys.as_ref().is_some_and(|k| k.has_chains());
        let nothing = matches!(
            planned,
            Err(Refusal::NotSigned(reply::Error::NothingSigned))
        );
        match planned {
            Ok(()) if misses == 0 && kcc3_misses == 0 => self.review_or_refuse(),
            // Some inputs placed: the pump's keys, without asking. None: the
            // pump's keys, then a question before each batch derived.
            _ if misses > 0 && chains && (planned.is_ok() || nothing) => {
                self.state = State::Searching {
                    next: 0,
                    stop: self.pumped,
                    ask: nothing,
                    kcc3: false,
                };
            }
            // Only KCC-3 inputs unplaced, nothing else to sign: asked before
            // the first batch (no pump derives them ahead).
            _ if kcc3_misses > 0 && nothing => {
                self.state = State::Asking {
                    next: 0,
                    kcc3: true,
                };
            }
            // KCC-3 inputs left beside placed ones: the KCC-3 sweep, asked
            // about, not refused, as they may be ours.
            Ok(()) if kcc3_misses > 0 => {
                self.state = State::Asking {
                    next: 0,
                    kcc3: true,
                };
            }
            Ok(()) => self.review_or_refuse(),
            Err(why) => self.refuse(why),
        }
    }

    /// Derive the pump's next key, if a seed is in use with chains and the
    /// pump is not full. Public keys only: no secret on the stack, no scrub.
    pub(super) fn pump_one(&mut self) -> Result<(), keyring::Error> {
        let Some(keys) = self.keys.as_ref() else {
            return Ok(());
        };
        if self.pumped >= keyring::SWEEP {
            return Ok(());
        }
        if let Some(key) = keys.sweep_key(self.pumped)? {
            self.buffers.pump[self.pumped] = key;
            self.pumped += 1;
        }
        Ok(())
    }

    pub(super) fn on_asking(
        &mut self,
        event: Event<'_>,
        next: usize,
        kcc3: bool,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Accept => {
                let from = if kcc3 { next } else { next.max(self.pumped) };
                self.state = State::Searching {
                    next,
                    stop: (from + BATCH).min(keyring::SWEEP),
                    ask: true,
                    kcc3,
                };
            }
            _ => {
                self.drop_request();
                self.state = State::Home;
            }
        }
        None
    }

    /// The search: the pump's keys a window at a time, a few derived a tick,
    /// the plan run again over each, until every input is placed. At `stop`
    /// it asks to search on or, if inputs of ours are placed, ends with what
    /// it has. Ending goes to the review only with every input placed
    /// ([`Flow::review_or_refuse`]). A failure more keys cannot change is
    /// refused at once. Back ends it.
    ///
    /// `kcc3`: the same over the KCC-3 chains, no pump. At its end a KCC-3
    /// address nothing found is refused as one with no redeem. A
    /// single-signature sweep leaving KCC-3 inputs goes on to it, asking.
    pub(super) fn on_searching(
        &mut self,
        event: Event<'_>,
        next: usize,
        stop: usize,
        ask: bool,
        kcc3: bool,
    ) -> Option<Command> {
        match event {
            Event::Tap { x, y } if camera::back(self.scale).contains(x, y) => {
                self.drop_request();
                self.state = State::Home;
                None
            }
            Event::Tick { .. } => {
                let end = (next + keyring::WINDOW).min(stop).min(keyring::SWEEP);
                if kcc3 {
                    if self.kcc3_window(next, end, SEARCH_PER_TICK).is_err() {
                        self.refuse(Refusal::NotDerived);
                        return None;
                    }
                    if self.keys.as_ref().map_or(0, |k| k.window_len()) < end - next {
                        return None;
                    }
                } else {
                    for _ in 0..SEARCH_PER_TICK {
                        if self.pumped >= end {
                            break;
                        }
                        if self.pump_one().is_err() {
                            self.refuse(Refusal::NotDerived);
                            return None;
                        }
                    }
                    if self.pumped < end {
                        return None;
                    }
                    // The window's keys, and the plan again with them.
                    if let Some(k) = self.keys.as_mut() {
                        for i in next..end {
                            k.window_push(i, self.buffers.pump[i]);
                        }
                    }
                }
                if let Some(k) = self.keys.as_mut() {
                    k.clear_misses();
                }
                let mut planned = self.plan_request();
                wipe::scrub_flow();
                let misses = self.keys.as_ref().map_or(0, |k| k.misses());
                let mut kcc3_misses = self.keys.as_ref().map_or(0, |k| k.kcc3_misses());
                if let Some(k) = self.keys.as_mut() {
                    k.keep_hits();
                }
                let swept = end >= keyring::SWEEP;
                // The KCC-3 sweep's end: what it missed is no longer pending.
                if kcc3 && swept && kcc3_misses > 0 {
                    if let Some(k) = self.keys.as_mut() {
                        k.set_kcc3_swept(true);
                    }
                    planned = self.plan_request();
                    wipe::scrub_flow();
                    kcc3_misses = 0;
                }
                let (left, other) = if kcc3 {
                    (kcc3_misses, misses)
                } else {
                    (misses, kcc3_misses)
                };
                let placed = planned.is_ok() && left == 0;
                let finished = swept || (end >= stop && !ask);
                // Nothing signed is the one failure another window can
                // change; any other is said now, not after asking on.
                let fixable = matches!(
                    planned,
                    Err(Refusal::NotSigned(reply::Error::NothingSigned))
                );
                // Single-signature inputs placed, KCC-3 ones left: the KCC-3
                // sweep, asked about.
                if !kcc3 && left == 0 && other > 0 && (planned.is_ok() || fixable) {
                    self.state = State::Asking {
                        next: 0,
                        kcc3: true,
                    };
                    return None;
                }
                self.state = match planned {
                    _ if placed && other == 0 => State::Reviewing,
                    Ok(()) if placed || finished => State::Reviewing,
                    Err(why) if finished || !fixable => {
                        self.refuse(why);
                        return None;
                    }
                    _ if end >= stop => State::Asking { next: end, kcc3 },
                    _ => State::Searching {
                        next: end,
                        stop,
                        ask,
                        kcc3,
                    },
                };
                if self.state == State::Reviewing {
                    // The outputs marked, as on the way in that needs no
                    // search ([`Flow::start_request`]).
                    self.mark_change();
                    self.review_or_refuse();
                }
                None
            }
            _ => None,
        }
    }

    /// The KCC-3 sweep's keys `next` to `end` into the keyring's window, at
    /// most `per_tick` more: public keys only.
    pub(super) fn kcc3_window(
        &mut self,
        next: usize,
        end: usize,
        per_tick: usize,
    ) -> Result<(), keyring::Error> {
        let Some(keys) = self.keys.as_mut() else {
            return Ok(());
        };
        for _ in 0..per_tick {
            let i = next + keys.window_len();
            if i >= end {
                break;
            }
            match keys.kcc3_sweep_key(i)? {
                Some(key) => {
                    keys.kcc3_window_push(i, key);
                }
                None => break,
            }
        }
        Ok(())
    }

    /// Parse the request held, build its session and plan the reply, in a
    /// frame the scrub after it can reach: run by [`Flow::start_request`] and
    /// [`Flow::on_searching`].
    #[inline(never)]
    pub(super) fn plan_request(&mut self) -> Result<(), Refusal> {
        if self.keys.is_none() {
            return Err(Refusal::NoWallet);
        }
        let mut inputs = [BLANK_IN; limits::MAX_INPUTS];
        let mut outputs = [BLANK_OUT; limits::MAX_OUTPUTS];
        let bundle = self.take_document()?;
        let keys = self.keys.as_ref().ok_or(Refusal::NoWallet)?;
        let request = &self.buffers.request[..self.request_len];
        if let Some(n) = bundle {
            let doc = &self.buffers.document[..n];
            let session = build_pskb(doc, self.buffers.scripts, &mut inputs, &mut outputs)?;
            unshown(&session)?;
            let plan = reply::plan_pskb(
                &session,
                doc,
                keys,
                self.buffers.reply.len(),
                self.buffers.redeem,
            )
            .map_err(planned)?;
            self.review_group = plan.group;
            self.review_second = plan.second;
            self.review_signs = (plan.signatures, plan.inputs);
            return Ok(());
        }
        let (parsed, session) = build(request, &self.profile, &mut inputs, &mut outputs)?;
        unshown(&session)?;
        let plan = reply::plan_kspt(
            &session,
            &parsed,
            keys,
            &self.profile,
            self.buffers.reply.len(),
            self.buffers.signatures,
        )
        .map_err(planned)?;
        self.review_group = plan.group;
        self.review_second = plan.second;
        self.review_signs = (plan.signatures, plan.inputs);
        Ok(())
    }

    /// A bundle's document, decoded once and read from there on: its
    /// length, or `None` for a KSPT.
    pub(super) fn take_document(&mut self) -> Result<Option<usize>, Refusal> {
        let request = &self.buffers.request[..self.request_len];
        if !request.starts_with(pskb::MAGIC) {
            self.document_len = None;
            return Ok(None);
        }
        let n = pskb::decode_envelope(request, self.buffers.document)
            .map_err(|_| Refusal::NotARequest)?;
        // The v1.0.7 companion's name for a covenant binding, and the
        // `payload` it never writes, made upstream's for the reader; the
        // latter can grow the document.
        bundle::upstream_names(&mut self.buffers.document[..n])
            .map_err(|_| Refusal::NotARequest)?;
        let n = bundle::fill_payload(self.buffers.document, n).map_err(|_| Refusal::NotARequest)?;
        self.document_len = Some(n);
        Ok(Some(n))
    }

    /// A transaction file carrying signatures, from the card: anyone's to
    /// show and broadcast. A complete one is shown with any seed or none (as
    /// this seed's reopening if it signed every input); a partly signed one
    /// only with no seed in use, else it goes on as a request. Signs nothing;
    /// returns whether it opened. With no seed, a file that fails to read is
    /// refused for its own reason, not "Load a seed first"; one with no
    /// signatures takes the request's path, which says that.
    pub(super) fn open_signed(&mut self) -> bool {
        let seeded = self.keys.is_some();
        match self.read_itself() {
            Ok((found, signers)) if found.complete || !seeded => {
                if seeded {
                    let own = self.reopen_request();
                    wipe::scrub_flow();
                    if let Ok(mine) = own {
                        self.show_reopened(mine);
                        return true;
                    }
                }
                self.show_itself(found, signers);
                true
            }
            Err(Refusal::NotSigned(reply::Error::NothingSigned)) => false,
            Err(why) if !seeded => {
                self.refuse(why);
                true
            }
            _ => false,
        }
    }

    /// The request read by itself, its signatures verified with no seed's
    /// keys ([`reply::kspt_itself`], [`reply::pskb_itself`]), and its
    /// signers.
    #[inline(never)]
    pub(super) fn read_itself(
        &mut self,
    ) -> Result<(reply::Itself, Option<reply::Signers>), Refusal> {
        let mut inputs = [BLANK_IN; limits::MAX_INPUTS];
        let mut outputs = [BLANK_OUT; limits::MAX_OUTPUTS];
        if let Some(n) = self.take_document()? {
            let doc = &self.buffers.document[..n];
            let session = build_pskb(doc, self.buffers.scripts, &mut inputs, &mut outputs)?;
            unshown(&session)?;
            return reply::pskb_itself(&session, doc, self.buffers.redeem).map_err(planned);
        }
        let request = &self.buffers.request[..self.request_len];
        let (parsed, session) = build(request, &self.profile, &mut inputs, &mut outputs)?;
        unshown(&session)?;
        let found = reply::kspt_itself(&session, &parsed).map_err(planned)?;
        Ok((found, reply::kspt_signers(request, &self.profile)))
    }

    /// A transaction signed already, read by itself: shown as a reopened
    /// one is. Every input holds a checked signature ([`Self::read_itself`]
    /// refuses one that does not), so the review's In and Fee add up
    /// amounts signatures cover.
    pub(super) fn show_itself(&mut self, found: reply::Itself, signers: Option<reply::Signers>) {
        self.review_group = found.group;
        self.review_second = found.second;
        self.review_signs = (found.inputs, found.inputs);
        self.show_reopened(signers);
    }

    /// A transaction signed already, opened to be shown: its review, then
    /// SIGNED TX QR with `signers`, never CONFIRM SEND?.
    pub(super) fn show_reopened(&mut self, signers: Option<reply::Signers>) {
        self.reopened = Some(signers);
        self.mark_change();
        self.review_or_refuse();
    }

    /// Whether this seed signed every input already ([`reply::signed_kspt`],
    /// [`reply::signed_pskb`]), setting the review as a plan does; returns
    /// the signers. Signs nothing; its keys are scrubbed as a plan's.
    #[inline(never)]
    pub(super) fn reopen_request(&mut self) -> Result<Option<reply::Signers>, Refusal> {
        let keys = self.keys.as_ref().ok_or(Refusal::NoWallet)?;
        let mut inputs = [BLANK_IN; limits::MAX_INPUTS];
        let mut outputs = [BLANK_OUT; limits::MAX_OUTPUTS];
        if let Some(n) = self.document_len {
            let doc = &self.buffers.document[..n];
            let session = build_pskb(doc, self.buffers.scripts, &mut inputs, &mut outputs)?;
            let (signed, signers) =
                reply::signed_pskb(&session, doc, keys, self.buffers.redeem).map_err(planned)?;
            self.review_group = signed.group;
            self.review_second = signed.second;
            self.review_signs = (signed.inputs, signed.inputs);
            return Ok(signers);
        }
        let request = &self.buffers.request[..self.request_len];
        let (parsed, session) = build(request, &self.profile, &mut inputs, &mut outputs)?;
        let signed = reply::signed_kspt(&session, &parsed, keys).map_err(planned)?;
        let signers = reply::kspt_signers(request, &self.profile);
        self.review_group = signed.group;
        self.review_second = signed.second;
        self.review_signs = (signed.inputs, signed.inputs);
        Ok(signers)
    }

    /// TX REVIEW, if the plan signs every input; refused otherwise. An
    /// unsigned input's amount is in none of the device's signatures, so TX
    /// REVIEW's In and Fee would be numbers nothing checks. Every way into
    /// the review from a plan comes here.
    ///
    /// With a group held, a request to sign that spends a multisig input not
    /// the group's is refused too ([`Flow::inputs_held`]): the group's change
    /// is change only for the group's own inputs. A transaction signed
    /// already, reopened to be shown, is shown.
    pub(super) fn review_or_refuse(&mut self) {
        let (signed, inputs) = self.review_signs;
        if signed < inputs {
            self.refuse(Refusal::NotSigned(reply::Error::NotEveryInput {
                signed,
                inputs,
            }));
            return;
        }
        let unproven = self.inputs_held() == reviewing::Inputs::Unchecked;
        if unproven && self.group.is_some() && self.reopened.is_none() {
            self.refuse(Refusal::NotTheGroups);
        } else {
            self.request_digest = Some(frame::sha256(self.reviewed()));
            self.state = State::Reviewing;
        }
    }

    /// The bytes the review and signing are built from: a bundle's decoded
    /// document, or the request.
    pub(super) fn reviewed(&self) -> &[u8] {
        match self.document_len {
            Some(n) => &self.buffers.document[..n],
            None => &self.buffers.request[..self.request_len],
        }
    }
}
