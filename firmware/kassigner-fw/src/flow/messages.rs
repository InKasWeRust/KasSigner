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

//! Sign Message: a message typed, scanned or read from the card, signed or
//! checked, and the result shown or saved.

use super::*;

/// Whether `bytes` are a signed message from a valid non-mainnet address
/// ([`crate::checks::decode_expecting`]); a malformed one is left for the
/// check to call invalid.
pub(super) fn another_network(bytes: &[u8]) -> bool {
    use crate::checks::{decode_expecting, AddressCheck};
    let Some(parts) = crate::message::read(bytes) else {
        return false;
    };
    let mut payload = [0u8; 40];
    matches!(
        decode_expecting(Prefix::Mainnet, &bytes[parts.address], &mut payload),
        Err(AddressCheck::WrongNetwork)
    )
}

impl<'b, const N: usize> Flow<'b, N> {
    /// Sign Message's keyboard: OK takes the text, refusing a seed; Back or
    /// Home drops it.
    pub(super) fn on_message_type(&mut self, event: Event<'_>, page: u8) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let key = match keyboard::target(self.scale, page, self.text_keys(), x, y)? {
            keyboard::Target::Nav(nav) => {
                self.typed.clear();
                self.state = match nav {
                    Nav::Home => State::Home,
                    _ => sign_message(),
                };
                return None;
            }
            keyboard::Target::Chip(_) => return None,
            keyboard::Target::Key(key) => key,
        };
        match key {
            keyboard::Key::Char(c) => {
                self.typed.insert(c);
            }
            keyboard::Key::Space => {
                self.typed.insert(b' ');
            }
            keyboard::Key::Ok => {
                let n = self.typed.len();
                if n > 0 && holds_seed(self.typed.as_bytes()) {
                    self.typed.clear();
                    self.refuse(Refusal::SeedNotMessage);
                } else if n > 0 {
                    self.buffers.request[..n].copy_from_slice(self.typed.as_bytes());
                    self.typed.clear();
                    self.take_message(n, false);
                }
            }
            _ => self.edit(key, page, |page| State::MessageType { page }),
        }
        None
    }

    /// Sign Message's camera: text in one code or in `Format::Opaque`
    /// frames.
    pub(super) fn on_message_scan(&mut self, event: Event<'_>) -> Option<Command> {
        match event {
            Event::Progress {
                have,
                total,
                received,
            } => {
                self.progress = (have, total);
                self.received = received;
                None
            }
            Event::Tap { x, y } => {
                if !camera::back(self.scale).contains(x, y) {
                    return None;
                }
                self.state = sign_message();
                Some(Command::CameraOff)
            }
            // Checked before any copy: the request buffer is PSRAM, which
            // survives a reset and whose wipes stay in the cache, so a seed
            // must never reach it. The bytes read sit in internal RAM or the
            // payload buffer, which the binary wipes and writes back after
            // the scan; the seed readers note their depth, so the scrub after
            // the scan runs to the floor.
            Event::Code(bytes) | Event::Opaque(bytes) => {
                wipe::begin_depth(self.stack);
                if bytes.len() > self.buffers.request.len() {
                    self.refuse(Refusal::TooLong);
                } else if !crate::text::is_message(bytes) {
                    self.refuse(Refusal::NotText);
                } else if holds_seed(bytes) {
                    self.refuse(Refusal::SeedNotMessage);
                } else {
                    self.buffers.request[..bytes.len()].copy_from_slice(bytes);
                    self.take_message(bytes.len(), false);
                }
                Some(Command::CameraOff)
            }
            Event::Payload(_) => {
                self.refuse(Refusal::NotText);
                Some(Command::CameraOff)
            }
            Event::CameraLost => {
                self.refuse(Refusal::NoCamera);
                Some(Command::CameraOff)
            }
            _ => None,
        }
    }

    /// The first `n` bytes of the request buffer as the message, shown if
    /// text. Refused and wiped: anything else; a file holding a seed (the card
    /// read it into the buffer before any check; it goes no further); another
    /// network's signed message; a text to sign with a space ending a line or
    /// the text, or a line break ending it, which would be signed but not
    /// shown.
    pub(super) fn take_message(&mut self, n: usize, file: bool) {
        self.msg_from = sign_message();
        let seed = file && {
            wipe::begin_depth(self.stack);
            let seed = holds_seed(&self.buffers.request[..n]);
            wipe::scrub_flow();
            seed
        };
        if seed {
            wipe::wipe(&mut self.buffers.request[..n]);
            self.restore_failed(refusal::SEED_NOT_MESSAGE.0);
        } else if another_network(&self.buffers.request[..n]) {
            // Another network's signed message, however it came: the units
            // are mainnet only.
            wipe::wipe(&mut self.buffers.request[..n]);
            if file {
                self.restore_failed(refusal::NOT_MAINNET.0);
            } else {
                self.refuse(Refusal::NotMainnet);
            }
        } else if crate::text::is_message(&self.buffers.request[..n]) {
            self.msg_held = n;
            self.msg_read = 0;
            self.msg_len = n;
            self.sig_len = 0;
            self.msg_signed = false;
            self.take_record();
            if self.msg_signed || crate::text::is_signable(&self.buffers.request[..n]) {
                self.state = State::MessagePreview { page: 0 };
                return;
            }
            self.msg_held = 0;
            self.msg_len = 0;
            wipe::wipe(&mut self.buffers.request[..n]);
            if file {
                self.restore_failed(refusal::TRAILING_WHITESPACE.0);
            } else {
                self.refuse(Refusal::TrailingWhitespace);
            }
        } else if file {
            wipe::wipe(&mut self.buffers.request[..n]);
            self.restore_failed("Not a text file");
        } else {
            wipe::wipe(&mut self.buffers.request[..n]);
            self.refuse(Refusal::NotText);
        }
    }

    /// Splits a signed message, setting `msg_signed`: its text becomes the
    /// message, its address and signature the result to check.
    pub(super) fn take_record(&mut self) {
        let Some(parts) = crate::message::read(&self.buffers.request[..self.msg_len]) else {
            return;
        };
        let address = &self.buffers.request[parts.address.clone()];
        if address.len() > self.addr_text.len() {
            return;
        }
        self.addr_text[..address.len()].copy_from_slice(address);
        self.addr_len = address.len();
        let sig = &self.buffers.request[parts.signature.clone()];
        self.buffers.reply[..sig.len()].copy_from_slice(sig);
        self.sig_len = sig.len();
        self.buffers.request.copy_within(parts.text.clone(), 0);
        self.msg_len = parts.text.len();
        self.msg_signed = true;
    }

    /// Checks the signed message against its address's key (rusty-kaspa's
    /// personal message hash, BIP340); `None` for an address with no Schnorr
    /// key (ECDSA or script).
    pub(super) fn check_message(&self) -> Option<bool> {
        use kassigner_kaspa::address::{decode, Version};
        let mut key = [0u8; 40];
        let key = match decode(self.address_text().as_bytes(), &mut key) {
            Ok((_, Version::PubKey, 32)) => <[u8; 32]>::try_from(&key[..32]).ok()?,
            Ok(_) => return None,
            Err(_) => return Some(false),
        };
        let mut signature = [0u8; 64];
        if !crate::text::read_hex(self.signature_text().as_bytes(), &mut signature) {
            return Some(false);
        }
        let hash = kassigner_kaspa::sighash::personal_message_hash(self.message_text().as_bytes());
        Some(kassigner_kaspa::bip340::verify(&key, &hash, &signature))
    }

    /// The check: DETAILS shows the signature and address, BACK the text,
    /// Home drops it all.
    pub(super) fn on_message_check(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Accept => self.state = State::MessageResult { page: 0 },
            dialog::Target::Nav(Nav::Home) => self.leave_message(State::Home),
            _ => self.state = State::MessagePreview { page: 0 },
        }
        None
    }

    /// Sign Message's text, for drawing it.
    pub fn message_text(&self) -> &str {
        core::str::from_utf8(&self.buffers.request[..self.msg_len]).unwrap_or("")
    }

    /// The signature, as hex, for drawing it.
    pub fn signature_text(&self) -> &str {
        core::str::from_utf8(&self.buffers.reply[..self.sig_len]).unwrap_or("")
    }

    /// The signed message's code for `frame`, for drawing: one code if the
    /// record fits, else `Format::Opaque` frames (version 9 for a wallet, 3
    /// for another unit).
    pub fn message_frame(&self, frame: u8) -> Option<kassigner_qr::encode::QrMatrix> {
        use kassigner_protocol::frame;
        use kassigner_qr::encode::encode;
        let record = &self.buffers.document[..self.shown_len];
        if self.msg_frames <= 1 {
            return encode(record).ok();
        }
        let mut buf = [0u8; frame::FIRST_HEADER_LEN + MESSAGE_WALLET_BYTES];
        let n =
            frame::write_split(Format::Opaque, record, frame, self.msg_frames, &mut buf).ok()?;
        frame_code(&buf[..n], self.wallet_frames)
    }

    /// The codes the signed message takes, for the cards' hints.
    pub const fn message_frames(&self, wallet: bool) -> usize {
        let len = self.msg_len + self.addr_len + self.sig_len + crate::message::OVERHEAD;
        message_codes(len, wallet)
    }

    /// Whether the signed message fits the reader's `max_frames`; a card
    /// past it is dimmed and does nothing.
    pub const fn message_fits(&self, wallet: bool) -> bool {
        self.message_frames(wallet) <= self.profile.max_frames
    }

    /// MESSAGE QR: Wallet or KasSigner, then Auto Cycle or Manual for
    /// several frames. Makes the record into the document. Back is the
    /// address.
    pub(super) fn on_message_format(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let target = kpub_screen::target(self.scale, x, y)?;
        if let kpub_screen::Target::Nav(nav) = target {
            if nav == Nav::Home {
                self.leave_message(State::Home);
            } else {
                self.state = State::MessageResult { page: 1 };
            }
            return None;
        }
        let wallet = target == kpub_screen::Target::Wallet;
        if !self.message_fits(wallet) {
            return None;
        }
        let Some(n) = self.write_record(false) else {
            self.refuse(Refusal::TooLong);
            return None;
        };
        self.shown_len = n;
        self.wallet_frames = wallet;
        self.frame_us = if wallet {
            limits::WALLET_FRAME_US
        } else {
            limits::KASSIGNER_FRAME_US
        };
        match u8::try_from(message_codes(n, wallet)) {
            Ok(1) => {
                self.msg_frames = 1;
                self.show_message();
            }
            Ok(f) => {
                self.msg_frames = f;
                self.state = State::MessageMode;
            }
            Err(_) => self.refuse(Refusal::TooLong),
        }
        None
    }

    /// QR DISPLAY MODE for the signed message's frames.
    pub(super) fn on_message_mode(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.leave_message(State::Home),
            dialog::Target::Nav(_) => self.state = State::MessageFormat,
            dialog::Target::Cancel => {
                self.manual = false;
                self.show_message();
            }
            dialog::Target::Accept => {
                self.manual = true;
                self.show_message();
            }
        }
        None
    }

    /// The signed message from its first frame.
    pub(super) fn show_message(&mut self) {
        self.frame_since = self.now_us;
        self.state = State::MessageFrames { frame: 0 };
    }

    /// The signed message's codes: Auto Cycle turns frames every
    /// [`WALLET_FRAME_US`](limits::WALLET_FRAME_US) or
    /// [`KASSIGNER_FRAME_US`](limits::KASSIGNER_FRAME_US), Manual one per
    /// tap; any other tap goes to MESSAGE EXPORTED.
    pub(super) fn on_message_frames(&mut self, event: Event<'_>, frame: u8) -> Option<Command> {
        let frames = self.msg_frames;
        match event {
            Event::Tick { now_us } if !self.manual => {
                if let Some(next) = self.turn(now_us, frame, frames) {
                    self.state = State::MessageFrames { frame: next };
                }
            }
            Event::Tap { .. } if self.manual && frame + 1 < frames => {
                self.state = State::MessageFrames { frame: frame + 1 };
            }
            Event::Tap { .. } => self.state = State::MessageDone,
            _ => {}
        }
        None
    }

    /// MESSAGE EXPORTED: Save to SD (`SGnnnn.TXT`) or Back to QR, which
    /// remakes the record, as a sealed save takes the document. Back is
    /// MESSAGE QR.
    pub(super) fn on_message_done(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.leave_message(State::Home),
            dialog::Target::Nav(_) => self.state = State::MessageFormat,
            dialog::Target::Cancel => {
                return self.start_saving(Saving::Signature, State::MessageDone)
            }
            dialog::Target::Accept => match self.write_record(false) {
                Some(n) => {
                    self.shown_len = n;
                    self.show_message();
                }
                None => self.refuse(Refusal::TooLong),
            },
        }
        None
    }

    /// The text, a page at a time; SIGN goes to the signing address. Back
    /// returns to `msg_from`, dropping the text. A page the panel did not
    /// take refuses the message ([`Event::NotDrawn`]).
    pub(super) fn on_message_preview(&mut self, event: Event<'_>, page: usize) -> Option<Command> {
        if let Event::NotDrawn = event {
            self.message_not_drawn();
            return None;
        }
        let Event::Tap { x, y } = event else {
            return None;
        };
        let pages = address_screen::message_pages(self.message_text());
        match address_screen::target(self.scale, false, page == 0, x, y)? {
            address_screen::Target::Nav(Nav::Home) => self.leave_message(State::Home),
            address_screen::Target::Nav(_) => self.leave_message(self.msg_from),
            address_screen::Target::Before => {
                self.state = State::MessagePreview {
                    page: page.saturating_sub(1),
                }
            }
            address_screen::Target::After if page + 1 < pages => {
                self.state = State::MessagePreview { page: page + 1 }
            }
            // The signature checked on the tick after the tap.
            address_screen::Target::Index if self.msg_signed => {
                return self.defer(Work::CheckMessage);
            }
            // SIGN, once the last page has been shown.
            address_screen::Target::Index if self.msg_read + 1 >= pages => self.choose_signer(),
            _ => {}
        }
        None
    }

    /// The signing address, picked on the Address screen; a seed made here
    /// with no checked backup is refused. A raw key's only address goes
    /// straight to SIGN MESSAGE?, resetting the Address modes as
    /// `open_address` does: a Private Key mode left set gives an empty
    /// address.
    pub(super) fn choose_signer(&mut self) {
        if self.keys.is_none() {
            return self.refuse(Refusal::NoWallet);
        }
        if !self.backed_or_refuse() {
            return;
        }
        let chains = self.keys.as_ref().is_some_and(|k| k.has_chains());
        if chains {
            self.open_address(State::MessagePreview { page: 0 }, false);
            self.addr_sign = true;
            return;
        }
        self.addr_key = false;
        self.addr_sign = false;
        self.addr_group = false;
        self.addr_kcc3 = false;
        self.addr_change = false;
        self.addr_index = 0;
        self.address_now();
        self.state = State::MessageConfirm;
    }

    /// SIGN MESSAGE?: SIGN signs on the next tick
    /// ([`State::MessageSigning`]); Cancel or Back returns to the Address
    /// screen, or for a raw key to the text. A touch in its first
    /// [`SETTLE_US`] does nothing. Not taken by the panel, it refuses the
    /// message ([`Event::NotDrawn`]).
    pub(super) fn on_message_confirm(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        if let Event::NotDrawn = event {
            self.message_not_drawn();
            return None;
        }
        let Event::Tap { x, y } = event else {
            return None;
        };
        if self.too_soon() {
            return None;
        }
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Accept => self.state = State::MessageSigning,
            dialog::Target::Nav(Nav::Home) => self.leave_message(State::Home),
            _ => {
                self.state = if self.addr_sign {
                    State::Address
                } else {
                    State::MessagePreview { page: 0 }
                }
            }
        }
        None
    }

    /// Signs rusty-kaspa's way with the chosen address's key (personal
    /// message hash, BIP340 with aux randomness), in a frame of its own, the
    /// stack scrubbed after.
    pub(super) fn sign_message<E: Entropy + ?Sized>(&mut self, rng: &mut E) {
        let Some(keys) = self.keys.as_ref() else {
            return self.refuse(Refusal::NoWallet);
        };
        let path = if self.addr_change {
            Path::change(self.addr_index)
        } else {
            Path::receive(self.addr_index)
        };
        let hash =
            kassigner_kaspa::sighash::personal_message_hash(&self.buffers.request[..self.msg_len]);
        let mut aux = [0u8; 32];
        if rng.fill(&mut aux).is_err() {
            return self.refuse(Refusal::NoEntropy);
        }
        wipe::begin_depth(self.stack);
        let signed = message_signature(keys.wallet(), path, &hash, &aux);
        wipe::scrub_flow();
        wipe::wipe(&mut aux);
        let Some(signature) = signed else {
            return self.refuse(Refusal::MessageNotSigned);
        };
        self.sig_len = crate::text::write_hex(&signature, &mut self.buffers.reply[..]);
        self.state = State::MessageResult { page: 0 };
    }

    /// The signature, then the signing address; SAVE SD writes the
    /// signature. Back returns to `msg_from`.
    pub(super) fn on_message_result(&mut self, event: Event<'_>, page: u8) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match address_screen::target(self.scale, false, page == 0, x, y)? {
            address_screen::Target::Nav(Nav::Home) => self.leave_message(State::Home),
            address_screen::Target::Nav(_) => self.leave_message(self.msg_from),
            address_screen::Target::Before => self.state = State::MessageResult { page: 0 },
            address_screen::Target::After if page == 0 => {
                self.state = State::MessageResult { page: 1 }
            }
            // A tap on the text: signature, then address, then the code.
            address_screen::Target::Address if page == 0 => {
                self.state = State::MessageResult { page: 1 }
            }
            address_screen::Target::Address => self.state = State::MessageFormat,
            address_screen::Target::Index => {
                return self.start_saving(Saving::Signature, State::MessageResult { page: 0 })
            }
            _ => {}
        }
        None
    }

    /// Writes the signed message's record, returning its length: into
    /// [`Buffers::document`] to write plain, or with `to_seal` after the text
    /// in [`Buffers::request`], for sealing.
    pub(super) fn write_record(&mut self, to_seal: bool) -> Option<usize> {
        let (text, after) = self.buffers.request.split_at_mut(self.msg_len);
        let out: &mut [u8] = if to_seal {
            after
        } else {
            &mut *self.buffers.document
        };
        let n = crate::message::write(
            text,
            &self.addr_text[..self.addr_len],
            &self.buffers.reply[..self.sig_len],
            out,
        )?;
        self.record_len = n;
        Some(n)
    }

    /// A page of the message, or SIGN MESSAGE?, that the panel did not take:
    /// the message is dropped and refused, as a transaction is whose review
    /// page was not drawn. We sign what we see: a page counted read, or SIGN
    /// live, behind a panel that does not show it would sign what was not
    /// seen.
    fn message_not_drawn(&mut self) {
        self.leave_message(State::Home);
        self.refuse(Refusal::NotDrawn);
    }

    /// Out of Sign Message, to `next`: the text and the signature dropped.
    pub(super) fn leave_message(&mut self, next: State) {
        self.drop_message();
        self.sig_len = 0;
        self.msg_signed = false;
        self.addr_sign = false;
        self.state = next;
    }

    /// Wipes Sign Message's bytes: in the request buffer the text, the
    /// record or file it came in and a sealed save's record; in the document
    /// the record shown.
    pub(super) fn drop_message(&mut self) {
        let held = self
            .msg_held
            .max(self.msg_len + self.record_len)
            .min(self.buffers.request.len());
        wipe::wipe(&mut self.buffers.request[..held]);
        let shown = self
            .record_len
            .max(self.shown_len)
            .min(self.buffers.document.len());
        wipe::wipe(&mut self.buffers.document[..shown]);
        self.msg_held = 0;
        self.msg_read = 0;
        self.msg_len = 0;
        self.record_len = 0;
        self.shown_len = 0;
    }

    /// Drops a held message once the flow is home or on a menu, however it
    /// got there.
    pub(super) fn keep_message(&mut self) {
        if self.msg_held > 0 && matches!(self.state, State::Home | State::Menu { .. }) {
            self.drop_message();
        }
    }
}

/// A message's signature with the key at `path`: BIP340 over `hash` with
/// `aux`. A frame of its own, for the scrub after it.
#[inline(never)]
pub(super) fn message_signature(
    wallet: &Wallet,
    path: Path,
    hash: &[u8; 32],
    aux: &[u8; 32],
) -> Option<[u8; 64]> {
    let key = wallet.signing_key(path).ok()?;
    kassigner_crypto::sign::sign(key.private_key(), hash, aux)
        .ok()
        .map(|s| *s.as_bytes())
}
