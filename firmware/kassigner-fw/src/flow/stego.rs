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

//! Steganography: a backup hidden in a photo on the card, and one found in a
//! photo and opened.

use super::*;

/// Bytes a payload's rebuilt containers take at most: a v1.0.7 payload's
/// two, each with its seven stripped bytes put back; a v1.1.0 payload's
/// one, with six put back; v1.0.5's base64, three bytes for four.
pub(super) const UNPACKED_MAX: usize = stego_wire::PAYLOAD_MAX + 2 * stego_wire::blob::V2_HEAD;

/// The other carrier: the metadata for the picture, the picture for the
/// metadata.
pub(super) const fn other_carrier(at: Carrier) -> Carrier {
    match at {
        Carrier::Picture => Carrier::Descriptor,
        _ => Carrier::Picture,
    }
}

/// The payload in `photo`'s metadata, if shaped as a unit writes one: what
/// an import opens there, and what Descriptor or Both would overwrite.
pub(super) fn metadata_backup(photo: &[u8]) -> Option<&[u8]> {
    stego_wire::exif::read_payload(photo)
        .filter(|p| p.len() <= stego_wire::PAYLOAD_MAX && stego_wire::blob::shape(p).is_ok())
}

impl<'b, const N: usize> Flow<'b, N> {
    /// STEGANOGRAPHY: a card picks the carrier and lists the photos.
    pub(super) fn on_stego_carrier(&mut self, event: Event<'_>) -> Option<Command> {
        self.stego_live = false;
        let Event::Tap { x, y } = event else {
            return None;
        };
        match stego_screen::target(self.scale, x, y)? {
            stego_screen::Target::Nav(Nav::Home) => self.state = State::Home,
            stego_screen::Target::Nav(_) => {
                self.state = State::Menu {
                    menu: MenuId::Export,
                    page: 0,
                }
            }
            stego_screen::Target::Carrier(i) => {
                self.carrier = Carrier::ALL[i];
                return self.list_photos();
            }
        }
        None
    }

    /// The card's photos listed, for SELECT PHOTO.
    pub(super) fn list_photos(&mut self) -> Option<Command> {
        self.listing = Listing::Photos;
        self.backup_name = self.list_pattern();
        self.card_exit = self.list_exit();
        self.state = State::CardBusy(Job::ListPhotos);
        Some(Command::Card(Job::ListPhotos))
    }

    /// The list's `i`th photo chosen: its 8.3 name, to read and write it by,
    /// and the name the list showed, for the dialogs.
    pub(super) fn photo_chose(&mut self, i: usize) {
        self.photo_name = self.backups[i];
        let mut shown = [0u8; kassigner_fat32::fat32::MAX_LONG_NAME];
        let n = card::long_name(self.long_names(), i).map_or(0, |name| {
            let n = name.len().min(shown.len());
            shown[..n].copy_from_slice(&name.as_bytes()[..n]);
            n
        });
        self.photo_shown = shown;
        self.photo_shown_len = n;
    }

    /// The chosen photo's name as listed, its long name if it has one: for
    /// HIDE BACKUP?, OVERWRITE? and BACKUP HIDDEN.
    pub fn photo_shown(&self) -> &str {
        core::str::from_utf8(&self.photo_shown[..self.photo_shown_len]).unwrap_or("")
    }

    /// The photo list's long names, a [`card::LONG_SLOT`] a row; none for any
    /// other list.
    pub fn long_names(&self) -> &[u8] {
        if self.listing == Listing::Photos {
            &self.buffers.photo_out
                [LONG_AT..LONG_AT + self.listed.min(RESTORE_MAX) * card::LONG_SLOT]
        } else {
            &[]
        }
    }

    /// The photo to hide a backup in, read. Descriptor and Both write its
    /// metadata, so a backup already there is asked about first
    /// ([`State::StegoOverwrite`]); otherwise the descriptor's source next.
    pub(super) fn photo_chosen(&mut self) {
        let writes_metadata = matches!(self.carrier, Carrier::Descriptor | Carrier::Both);
        let n = self.photo_len.min(self.buffers.photo.len());
        self.state = if writes_metadata && metadata_backup(&self.buffers.photo[..n]).is_some() {
            State::StegoOverwrite
        } else {
            State::Menu {
                menu: MenuId::StegoSource,
                page: 0,
            }
        };
    }

    /// OVERWRITE?: OVERWRITE asks the backup's own descriptor; CANCEL and
    /// Back list the photos again.
    pub(super) fn on_stego_overwrite(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Accept => {
                self.forget_descriptor();
                self.state = State::StegoOldKey { page: 0 };
            }
            dialog::Target::Nav(Nav::Home) => {
                self.forget_stego();
                self.state = State::Home;
            }
            dialog::Target::Nav(_) | dialog::Target::Cancel => {
                self.forget_stego();
                return self.list_photos();
            }
        }
        None
    }

    /// OK on the old descriptor: the metadata's backup, the one an overwrite
    /// replaces, opened under it as an import opens one
    /// ([`Flow::on_stego_opening`]).
    pub(super) fn check_old(&mut self) -> Option<Command> {
        let n = self.photo_len.min(self.buffers.photo.len());
        let Some(p) = metadata_backup(&self.buffers.photo[..n]) else {
            self.state = State::Menu {
                menu: MenuId::StegoSource,
                page: 0,
            };
            return None;
        };
        let (from, len) = (stego_wire::PAYLOAD_MAX, p.len());
        self.buffers.photo_out[from..from + len].copy_from_slice(p);
        self.stego_live = true;
        self.unhide = Unhide {
            metadata: u16::try_from(len).ok(),
            at: Carrier::Descriptor,
            ..Unhide::NONE
        };
        self.next_payload()
    }

    /// The old descriptor opened the backup, so it may be overwritten.
    /// Nothing of it is kept; the export goes on to its own descriptor.
    pub(super) fn overwrite_allowed(&mut self) {
        wipe::wipe(&mut self.buffers.photo_out[..2 * stego_wire::PAYLOAD_MAX]);
        self.unhide = Unhide::NONE;
        self.forget_descriptor();
        self.forget_hint();
        self.stego_live = false;
        self.state = State::Menu {
            menu: MenuId::StegoSource,
            page: 0,
        };
    }

    /// A caption file read: its first line is the descriptor, printable
    /// characters, at most 64 to hide a backup, as a unit writes them, and
    /// 128 to open one, as v1.0.7 read them. A sealed file, a longer line or
    /// other bytes are refused by name, back to the source menu. For an
    /// import, the line goes onto its keyboard, to be looked over before OK.
    pub(super) fn caption_read(&mut self, n: usize) {
        use kassigner_protocol::container::parse;
        let n = n.min(self.buffers.request.len());
        self.file_len = 0;
        self.card_exit = State::Menu {
            menu: MenuId::StegoSource,
            page: 0,
        };
        let (most, too_long) = if self.stego_import {
            (stego_wire::DESCRIPTOR_READ_MAX, "Line over 128 characters")
        } else {
            (stego_wire::DESCRIPTOR_WRITE_MAX, "Line over 64 characters")
        };
        let why = {
            let file = &self.buffers.request[..n];
            if parse(file).is_ok() {
                Some("Not a text file")
            } else {
                let text = file.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(file);
                let line = text
                    .split(|&c| c == b'\n' || c == b'\r')
                    .next()
                    .unwrap_or(&[])
                    .trim_ascii();
                if line.is_empty() {
                    Some("Empty file")
                } else if line.len() > most {
                    Some(too_long)
                } else if !line.iter().all(|&c| stego_wire::descriptor_char(c)) {
                    Some("Not plain ASCII text")
                } else {
                    None
                }
            }
        };
        match why {
            Some(why) => {
                wipe::wipe(&mut self.buffers.request[..n]);
                self.restore_failed(why);
            }
            None => {
                let text = self.buffers.request[..n]
                    .strip_prefix(b"\xEF\xBB\xBF")
                    .unwrap_or(&self.buffers.request[..n]);
                let line = text
                    .split(|&c| c == b'\n' || c == b'\r')
                    .next()
                    .unwrap_or(&[])
                    .trim_ascii();
                let mut kept = [0u8; stego_wire::DESCRIPTOR_READ_MAX];
                let k = line.len().min(kept.len());
                kept[..k].copy_from_slice(&line[..k]);
                wipe::wipe(&mut self.buffers.request[..n]);
                self.set_descriptor(&kept[..k]);
                wipe::wipe(&mut kept);
                self.state = if self.stego_import {
                    State::StegoKey { page: 0 }
                } else {
                    State::StegoPreview
                };
            }
        }
    }

    /// ADD HINT?: NO goes to HIDE BACKUP? with none; YES to the presets.
    pub(super) fn on_stego_hint_ask(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => {
                self.forget_stego();
                self.state = State::Home;
            }
            dialog::Target::Nav(_) => self.state = State::StegoPreview,
            dialog::Target::Cancel => {
                self.forget_hint();
                self.state = State::StegoConfirm;
            }
            dialog::Target::Accept => self.state = State::StegoHint,
        }
        None
    }

    /// RECOVERY HINT: a preset is kept as it reads; Custom opens the
    /// keyboard; Back is ADD HINT?.
    pub(super) fn on_stego_hint(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match stego_screen::hint_target(self.scale, x, y)? {
            stego_screen::HintTarget::Nav(Nav::Home) => {
                self.forget_stego();
                self.state = State::Home;
            }
            stego_screen::HintTarget::Nav(_) => self.state = State::StegoHintAsk,
            stego_screen::HintTarget::Row(i) => match stego_screen::HINTS.get(i) {
                Some(hint) => {
                    self.set_hint(hint.as_bytes());
                    self.state = State::StegoConfirm;
                }
                None => {
                    self.typed.clear();
                    self.state = State::StegoHintType { page: 0 };
                }
            },
        }
        None
    }

    /// CUSTOM HINT: text, [`HINT_MAX`] at most; OK with something typed goes
    /// to HIDE BACKUP?; Back is the presets.
    pub(super) fn on_stego_hint_type(&mut self, event: Event<'_>, page: u8) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let key = match keyboard::target(self.scale, page, self.text_keys(), x, y)? {
            keyboard::Target::Nav(Nav::Home) => {
                self.typed.clear();
                self.forget_stego();
                self.state = State::Home;
                return None;
            }
            keyboard::Target::Nav(_) => {
                self.typed.clear();
                self.state = State::StegoHint;
                return None;
            }
            keyboard::Target::Chip(_) => return None,
            keyboard::Target::Key(key) => key,
        };
        let room = !self.typed_full();
        match key {
            keyboard::Key::Char(c) if room && stego_wire::descriptor_char(c) => {
                self.typed.insert(c);
            }
            keyboard::Key::Space if room => {
                self.typed.insert(b' ');
            }
            keyboard::Key::Char(_) | keyboard::Key::Space => {}
            keyboard::Key::Delete => self.typed.backspace(),
            keyboard::Key::Left => self.typed.left(),
            keyboard::Key::Right => self.typed.right(),
            keyboard::Key::Page => {
                self.state = State::StegoHintType {
                    page: keyboard::next_page(page),
                }
            }
            keyboard::Key::Ok => {
                if self.typed.is_empty() {
                    return None;
                }
                let text = core::mem::take(&mut self.typed);
                self.set_hint(text.as_bytes());
                self.state = State::StegoConfirm;
            }
        }
        None
    }

    /// HIDE BACKUP?: CANCEL drops everything and goes back to the carriers;
    /// Back is ADD HINT?; CONFIRM seals the seed and hides it in the photo.
    pub(super) fn on_stego_confirm(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => {
                self.forget_stego();
                self.state = State::Home;
            }
            dialog::Target::Nav(_) => self.state = State::StegoHintAsk,
            dialog::Target::Cancel => {
                self.forget_stego();
                self.state = State::StegoCarrier;
            }
            dialog::Target::Accept => {
                self.stego_live = true;
                self.saving = Saving::Stego;
                self.state = State::StegoSealing { done: 0 };
            }
        }
        None
    }

    /// A tick of sealing: the salt and nonce first, then a batch of PBKDF2
    /// rounds, then the seed and hint sealed under the descriptor and
    /// stripped to the payload, for the next tick to hide.
    pub(super) fn on_stego_sealing<E: Entropy + ?Sized>(
        &mut self,
        event: Event<'_>,
        done: u32,
        rng: &mut E,
    ) -> Option<Command> {
        let Event::Tick { .. } = event else {
            return None;
        };
        if done == 0 {
            if rng.fill(&mut self.salt).is_err() || rng.fill(&mut self.nonce).is_err() {
                return self.stego_failed(Refusal::NoEntropy);
            }
            self.steps = Some(stego_seal::steps(self.desc.as_bytes(), &self.salt));
            self.state = State::StegoSealing { done: 1 };
            return None;
        }
        let Some(steps) = self.steps.as_mut() else {
            return self.stego_failed(Refusal::NotSaved);
        };
        let (done, total) = steps.step(SEAL_ROUNDS);
        if done < total {
            self.state = State::StegoSealing { done };
            return None;
        }
        // A key to seal with, wiped as it drops; steps made for opening
        // give none, and none are made here.
        let Some(key) = steps.sealing_key() else {
            return self.stego_failed(Refusal::NotSaved);
        };
        let Some((_, Slot::Mnemonic { mnemonic, .. })) = self.slots.active() else {
            return self.stego_failed(Refusal::NoPhrase);
        };
        let mut container = [0u8; stego_seal::CONTAINER_MAX];
        let sealed = stego_seal::seal_backup_with_key(
            mnemonic,
            &self.hint[..self.hint_len],
            &key,
            &self.salt,
            &self.nonce,
            &mut container,
        );
        drop(key);
        self.derivation_over();
        let n = match sealed {
            Ok(n) => n,
            Err(_) => {
                wipe::wipe(&mut container);
                return self.stego_failed(Refusal::NotSaved);
            }
        };
        let stripped = stego_wire::blob::strip(&container[..n], &mut self.payload);
        wipe::wipe(&mut container);
        match stripped {
            Ok(k) => self.payload_len = k,
            Err(_) => return self.stego_failed(Refusal::NotSaved),
        }
        // The photo was read when chosen; the payload goes in next tick.
        self.state = State::StegoEmbedding;
        None
    }

    /// The tick after sealing: the payload hidden in the photo by the chosen
    /// carrier, read back from the result, and the result written over the
    /// photo.
    pub(super) fn on_stego_embedding<E: Entropy + ?Sized>(
        &mut self,
        event: Event<'_>,
        rng: &mut E,
    ) -> Option<Command> {
        let Event::Tick { .. } = event else {
            return None;
        };
        let mut random = [0u8; stego_wire::exif::RANDOM];
        if rng.fill(&mut random).is_err() {
            return self.stego_failed(Refusal::NoEntropy);
        }
        let key = stego_seal::walk_key(self.desc.as_bytes());
        let n = self.photo_len.min(self.buffers.photo.len());
        let (filled, changed) = self
            .buffers
            .window_bits
            .split_at_mut(limits::WINDOW_BITS / 2);
        let mut window = Window {
            coefficients: self.buffers.window,
            filled,
            changed,
        };
        let export = stego_wire::Export {
            descriptor: self.desc.as_bytes(),
            payload: &self.payload[..self.payload_len],
            key: &key,
            random: &random,
        };
        let out = stego_wire::export(
            &self.buffers.photo[..n],
            self.carrier,
            &export,
            &mut window,
            self.buffers.jpeg,
            self.buffers.app1,
            self.buffers.photo_out,
        );
        wipe::wipe(self.buffers.app1);
        match out {
            Ok(len) => {
                self.file_len = len;
                self.backup_name = self.photo_name;
                self.card_exit = State::StegoCarrier;
                self.state = State::CardBusy(Job::Write);
                Some(Command::Card(Job::Write))
            }
            Err(e) => self.stego_failed(Refusal::Stego(e)),
        }
    }

    /// BACKUP HIDDEN: DONE is the Export menu; MORE the carriers, for
    /// another photo or carrier.
    pub(super) fn on_stego_done(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Accept => self.state = State::StegoCarrier,
            dialog::Target::Nav(_) | dialog::Target::Cancel => {
                self.state = State::Menu {
                    menu: MenuId::Export,
                    page: 0,
                }
            }
        }
        None
    }

    /// The export stopped: everything it held wiped, and why said, then back
    /// to the carriers.
    pub(super) fn stego_failed(&mut self, why: Refusal) -> Option<Command> {
        self.stego_over();
        // Kept through the refusal, so it comes back to the carriers; the
        // carrier screen clears it.
        self.stego_live = true;
        self.stego_rest = State::StegoCarrier;
        self.refuse(why);
        None
    }

    /// Everything a stego export held, wiped: the payload, the photo and
    /// its copy, the window, the descriptor and the hint.
    pub(super) fn stego_over(&mut self) {
        self.derivation_over();
        wipe::wipe(&mut self.payload);
        self.payload_len = 0;
        let n = self.file_len.min(self.buffers.photo_out.len());
        wipe::wipe(&mut self.buffers.photo_out[..n]);
        self.file_len = 0;
        self.buffers.window.fill(0);
        wipe::wipe(self.buffers.window_bits);
        self.forget_stego();
    }

    /// Keep `text` as the hint, the one before it wiped.
    pub(super) fn set_hint(&mut self, text: &[u8]) {
        self.forget_hint();
        let n = text.len().min(self.hint.len());
        self.hint[..n].copy_from_slice(&text[..n]);
        self.hint_len = n;
    }

    pub(super) fn forget_hint(&mut self) {
        wipe::wipe(&mut self.hint);
        self.hint_len = 0;
    }

    /// Everything the stego screens hold, wiped: the descriptor, the hint,
    /// the photo read to hide a backup in, and the photo list's long names.
    pub(super) fn forget_stego(&mut self) {
        self.forget_descriptor();
        self.forget_hint();
        self.forget_photo();
        wipe::wipe(&mut self.buffers.photo_out[LONG_AT..LONG_AT + LONG_BYTES]);
        self.stego_live = false;
    }

    /// The photo read, wiped.
    pub(super) fn forget_photo(&mut self) {
        let n = self.photo_len.min(self.buffers.photo.len());
        wipe::wipe(&mut self.buffers.photo[..n]);
        self.photo_len = 0;
    }

    /// The hint, for the tests and the confirm screen: never part of a
    /// [`Screen`].
    pub fn hint(&self) -> &str {
        core::str::from_utf8(&self.hint[..self.hint_len]).unwrap_or("")
    }

    /// The photo chosen on SELECT PHOTO, 8.3.
    pub const fn photo_name(&self) -> &[u8; 11] {
        &self.photo_name
    }

    /// IMAGE DESCRIPTOR on the keyboard, up to
    /// [`stego_wire::DESCRIPTOR_WRITE_MAX`] characters: OK with something
    /// typed shows the preview; Back is the source menu, the text wiped.
    pub(super) fn on_stego_descriptor(&mut self, event: Event<'_>, page: u8) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let key = match keyboard::target(self.scale, page, self.text_keys(), x, y)? {
            keyboard::Target::Nav(Nav::Home) => {
                self.typed.clear();
                self.forget_descriptor();
                self.state = State::Home;
                return None;
            }
            keyboard::Target::Nav(_) => {
                self.typed.clear();
                self.state = State::Menu {
                    menu: MenuId::StegoSource,
                    page: 0,
                };
                return None;
            }
            keyboard::Target::Chip(_) => return None,
            keyboard::Target::Key(key) => key,
        };
        let room = !self.typed_full();
        match key {
            keyboard::Key::Char(c) if room && stego_wire::descriptor_char(c) => {
                self.typed.insert(c);
            }
            keyboard::Key::Space if room => {
                self.typed.insert(b' ');
            }
            keyboard::Key::Char(_) | keyboard::Key::Space => {}
            keyboard::Key::Delete => self.typed.backspace(),
            keyboard::Key::Left => self.typed.left(),
            keyboard::Key::Right => self.typed.right(),
            keyboard::Key::Page => {
                self.state = State::StegoDescriptor {
                    page: keyboard::next_page(page),
                }
            }
            keyboard::Key::Ok => {
                if self.typed.is_empty() {
                    return None;
                }
                let text = core::mem::take(&mut self.typed);
                self.set_descriptor(text.as_bytes());
                self.state = State::StegoPreview;
            }
        }
        None
    }

    /// The descriptor's preview: EDIT and Back put it back on the keyboard;
    /// USE goes on to ADD HINT?; Home drops it.
    pub(super) fn on_stego_preview(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => {
                self.forget_descriptor();
                self.state = State::Home;
            }
            dialog::Target::Nav(_) | dialog::Target::Cancel => {
                self.typed.clear();
                for &c in self.desc.as_bytes() {
                    self.typed.insert(c);
                }
                self.state = State::StegoDescriptor { page: 0 };
            }
            dialog::Target::Accept => self.state = State::StegoHintAsk,
        }
        None
    }

    /// Keep `text` as the descriptor, the one before it wiped: printable
    /// characters, as every caller has checked, up to
    /// [`stego_wire::DESCRIPTOR_READ_MAX`].
    pub(super) fn set_descriptor(&mut self, text: &[u8]) {
        self.forget_descriptor();
        for &c in text {
            self.desc.insert(c);
        }
    }

    /// The descriptor wiped: it is the password of the Picture carrier.
    pub(super) fn forget_descriptor(&mut self) {
        self.desc.clear();
    }

    /// The descriptor as typed or read, for its preview: never part of a
    /// [`Screen`], which is printed.
    pub fn descriptor(&self) -> &str {
        self.desc.as_str()
    }

    /// The carrier chosen on STEGANOGRAPHY, or the one Stego Import found
    /// the backup in.
    pub const fn carrier(&self) -> Carrier {
        self.carrier
    }

    /// Stego Import's IMAGE DESCRIPTOR, and OLD DESCRIPTOR before an
    /// overwrite: up to [`stego_wire::DESCRIPTOR_READ_MAX`] printable
    /// characters typed into the descriptor. OK with something typed reads
    /// the photo to open it, or opens the backup already read. Back is the
    /// source menu or OVERWRITE?; Back and Home wipe the descriptor.
    pub(super) fn on_stego_key(&mut self, event: Event<'_>, page: u8) -> Option<Command> {
        let old = matches!(self.state, State::StegoOldKey { .. });
        // Back here after a refusal: from now on a refusal is this screen's
        // own again.
        self.stego_live = false;
        let Event::Tap { x, y } = event else {
            return None;
        };
        let key = match keyboard::target(self.scale, page, self.text_keys(), x, y)? {
            keyboard::Target::Nav(Nav::Home) => {
                self.forget_stego();
                self.state = State::Home;
                return None;
            }
            keyboard::Target::Nav(_) => {
                self.forget_descriptor();
                self.state = if old {
                    State::StegoOverwrite
                } else {
                    State::Menu {
                        menu: MenuId::StegoSource,
                        page: 0,
                    }
                };
                return None;
            }
            keyboard::Target::Chip(_) => return None,
            keyboard::Target::Key(key) => key,
        };
        match key {
            // The descriptor stops taking characters once full.
            keyboard::Key::Char(c) if stego_wire::descriptor_char(c) => {
                self.desc.insert(c);
            }
            keyboard::Key::Space => {
                self.desc.insert(b' ');
            }
            keyboard::Key::Char(_) => {}
            keyboard::Key::Delete => self.desc.backspace(),
            keyboard::Key::Left => self.desc.left(),
            keyboard::Key::Right => self.desc.right(),
            keyboard::Key::Page => {
                let page = keyboard::next_page(page);
                self.state = if old {
                    State::StegoOldKey { page }
                } else {
                    State::StegoKey { page }
                };
            }
            keyboard::Key::Ok if self.desc.is_empty() => {}
            keyboard::Key::Ok if old => return self.check_old(),
            keyboard::Key::Ok => {
                // The photo, into its buffer; a read that fails comes back
                // here, the descriptor kept.
                self.stego_live = true;
                self.listing = Listing::Photos;
                self.backup_name = self.photo_name;
                self.card_exit = State::StegoKey { page: 0 };
                self.state = State::CardBusy(Job::Read);
                return Some(Command::Card(Job::Read));
            }
        }
        None
    }

    /// The tick after the photo is read: both carriers read out (the
    /// picture's along the walk the descriptor keys), the photo wiped, then
    /// the first payload's derivation, the picture's first ([`Unhide`]).
    pub(super) fn on_stego_reading(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tick { .. } = event else {
            return None;
        };
        let key = stego_seal::walk_key(self.desc.as_bytes());
        let n = self.photo_len.min(self.buffers.photo.len());
        let (filled, changed) = self
            .buffers
            .window_bits
            .split_at_mut(limits::WINDOW_BITS / 2);
        let mut window = Window {
            coefficients: self.buffers.window,
            filled,
            changed,
        };
        let (picture, rest) = self.buffers.photo_out.split_at_mut(stego_wire::PAYLOAD_MAX);
        let metadata = &mut rest[..stego_wire::PAYLOAD_MAX];
        let read = stego_wire::extract(
            &self.buffers.photo[..n],
            &key,
            &mut window,
            self.buffers.jpeg,
            picture,
            metadata,
        );
        // Both carriers holding the same bytes, as Both writes them.
        let same = matches!(read, Ok(stego_wire::Extracted {
            picture: Some(p),
            descriptor: Some(d),
        }) if picture[..p] == metadata[..d]);
        // The photo and the window are done with.
        wipe::wipe(&mut self.buffers.photo[..n]);
        self.photo_len = 0;
        self.buffers.window.fill(0);
        wipe::wipe(self.buffers.window_bits);
        let found = match read {
            Ok(found) => found,
            Err(e) => {
                self.unhide_failed(Refusal::Stego(e));
                return None;
            }
        };
        let length = |n: Option<usize>| n.and_then(|n| u16::try_from(n).ok());
        self.unhide = Unhide {
            picture: length(found.picture),
            metadata: if same { None } else { length(found.descriptor) },
            same,
            ..Unhide::NONE
        };
        self.next_payload()
    }

    /// The payload at `at`, as the photo gave it up.
    pub(super) fn unhidden(&self, at: Carrier) -> &[u8] {
        let (from, len) = match at {
            Carrier::Picture => (0, self.unhide.picture),
            _ => (stego_wire::PAYLOAD_MAX, self.unhide.metadata),
        };
        let len = usize::from(len.unwrap_or(0));
        &self.buffers.photo_out[from..from + len]
    }

    /// The salt and purpose a derivation needs for the payload at `at`: its
    /// seed's container's, or with `hint` a v1.0.7 payload's hint's. `None`
    /// if its containers do not rebuild, or rebuild in a layout this unit
    /// does not open.
    pub(super) fn payload_kdf(
        &self,
        at: Carrier,
        hint: bool,
    ) -> Option<([u8; SALT_SIZE], kassigner_protocol::container::Purpose)> {
        let mut rebuilt = [0u8; UNPACKED_MAX];
        let unpacked = stego_wire::blob::unpack(self.unhidden(at), &mut rebuilt).ok()?;
        let range = if hint { unpacked.hint? } else { unpacked.seed };
        stego_seal::kdf_of(&rebuilt[range]).ok()
    }

    /// The derivation for the payload at [`Unhide::at`] if it can be opened,
    /// else the next payload, or with none left the refusal.
    pub(super) fn next_payload(&mut self) -> Option<Command> {
        let at = self.unhide.at;
        let held = match at {
            Carrier::Picture => self.unhide.picture.is_some(),
            _ => self.unhide.metadata.is_some(),
        };
        if held {
            match self.payload_kdf(at, false) {
                Some((salt, purpose)) => {
                    self.steps = Some(Pbkdf2Steps::new(self.desc.as_bytes(), &salt, purpose));
                    self.state = State::StegoOpening { done: 0 };
                    return None;
                }
                None => self.unhide.unknown = true,
            }
        }
        self.after_payload()
    }

    /// The payload after the one just tried: the metadata's after the
    /// picture's; after both, the refusal, most actionable first: a payload
    /// that would not open means a wrong descriptor; one in a layout this
    /// unit cannot open, an unknown format; none at all, no backup (which a
    /// wrong descriptor also gives in the picture).
    pub(super) fn after_payload(&mut self) -> Option<Command> {
        if self.unhide.at == Carrier::Picture {
            self.unhide.at = Carrier::Descriptor;
            return self.next_payload();
        }
        let why = if self.unhide.wrong {
            Refusal::WrongDescriptor
        } else if self.unhide.unknown {
            Refusal::UnknownFormat
        } else {
            Refusal::NoBackup
        };
        self.unhide_failed(why);
        None
    }

    /// A tick of opening: a batch of PBKDF2 rounds; once the key is whole,
    /// the payload's seed opened under it, with its hint for a v1.1.0
    /// payload. A v1.0.7 payload's hint is sealed apart under its own salt:
    /// another derivation after the seed. A seed that does not open moves on
    /// to the other carrier; a hint that does not open is dropped, and the
    /// seed stands.
    pub(super) fn on_stego_opening(&mut self, event: Event<'_>) -> Option<Command> {
        use stego_wire::blob::{unpack, Shape};
        let Event::Tick { .. } = event else {
            return None;
        };
        let Some(steps) = self.steps.as_mut() else {
            self.unhide_failed(Refusal::NotOpened);
            return None;
        };
        let (done, _) = steps.step(SEAL_ROUNDS);
        let Some(key) = steps.key() else {
            self.state = State::StegoOpening { done };
            return None;
        };
        let at = self.unhide.at;
        let mut rebuilt = [0u8; UNPACKED_MAX];
        let mut hint = [0u8; HINT_MAX];
        let unpacked = unpack(self.unhidden(at), &mut rebuilt);
        if self.unhide.hint_next {
            let opened = match &unpacked {
                Ok(u) => match u.hint.clone() {
                    Some(range) => {
                        stego_seal::open_legacy_hint_with_key(&rebuilt[range], &key, &mut hint)
                    }
                    None => Err(stego_seal::StegoError::Malformed),
                },
                Err(_) => Err(stego_seal::StegoError::Malformed),
            };
            drop(key);
            wipe::wipe(&mut rebuilt);
            self.derivation_over();
            if let Ok(h) = opened {
                self.set_hint(&hint[..h]);
            }
            wipe::wipe(&mut hint);
            self.found();
            return None;
        }
        // An import opens the seed. An overwrite's check only proves the
        // descriptor is the backup's, by its tag, on the copy unpacked here,
        // which it leaves wiped: the seed is never opened, as with a sealed
        // file's overwrite.
        let opened = match &unpacked {
            Ok(u) if !self.stego_import => {
                stego_seal::check_backup_with_key(&mut rebuilt[u.seed.clone()], &key).map(|()| None)
            }
            Ok(u) if u.shape == Shape::V3 => {
                stego_seal::open_backup_with_key(&rebuilt[u.seed.clone()], &key, &mut hint)
                    .map(Some)
            }
            Ok(u) => stego_seal::open_legacy_seed_with_key(&rebuilt[u.seed.clone()], &key)
                .map(|m| Some((m, 0))),
            Err(_) => Err(stego_seal::StegoError::Malformed),
        };
        // A v1.0.7 payload with a hint after its seed.
        let hint_apart = matches!(&unpacked, Ok(u) if u.shape != Shape::V3 && u.hint.is_some());
        drop(key);
        wipe::wipe(&mut rebuilt);
        self.derivation_over();
        match opened {
            // An overwrite's check: the descriptor is the backup's.
            Ok(None) => {
                wipe::wipe(&mut hint);
                self.overwrite_allowed();
                None
            }
            Ok(Some((m, h))) => {
                // The seed found before OTHER, if any, drops and wipes itself.
                self.hold_loaded(m);
                self.unhide.other = false;
                self.set_hint(&hint[..h]);
                wipe::wipe(&mut hint);
                if hint_apart {
                    if let Some((salt, purpose)) = self.payload_kdf(at, true) {
                        self.unhide.hint_next = true;
                        self.steps = Some(Pbkdf2Steps::new(self.desc.as_bytes(), &salt, purpose));
                        self.state = State::StegoOpening { done: 0 };
                        return None;
                    }
                }
                self.found();
                None
            }
            Err(e) if self.unhide.other => {
                wipe::wipe(&mut hint);
                self.other_failed(e)
            }
            Err(e) => {
                wipe::wipe(&mut hint);
                match e {
                    stego_seal::StegoError::Container(OpenError::Authentication) => {
                        self.unhide.wrong = true
                    }
                    _ => self.unhide.unknown = true,
                }
                self.after_payload()
            }
        }
    }

    /// A seed opened: the carrier it came from kept for LOAD SEED?; the
    /// payloads and the descriptor let go, unless the photo holds two
    /// backups, when they stay for OTHER until the import ends.
    pub(super) fn found(&mut self) {
        self.unhide.hint_next = false;
        self.unhide.other = false;
        self.carrier = if self.unhide.same {
            Carrier::Both
        } else {
            self.unhide.at
        };
        if !self.unhide.two() {
            wipe::wipe(&mut self.buffers.photo_out[..2 * stego_wire::PAYLOAD_MAX]);
            self.forget_descriptor();
        }
        self.stego_live = false;
        self.state = State::StegoFound;
    }

    /// OTHER on LOAD SEED?: the other carrier's backup opened under the same
    /// descriptor, the seed found waiting. Without it, of two backups under
    /// one descriptor only the picture's, tried first, could be reached.
    pub(super) fn open_other(&mut self) -> Option<Command> {
        let other = other_carrier(self.unhide.at);
        match self.payload_kdf(other, false) {
            Some((salt, purpose)) => {
                self.unhide.at = other;
                self.unhide.other = true;
                self.steps = Some(Pbkdf2Steps::new(self.desc.as_bytes(), &salt, purpose));
                self.state = State::StegoOpening { done: 0 };
            }
            None => self.refuse_other(Refusal::UnknownFormat),
        }
        None
    }

    /// The other backup did not open: back to the seed found, still waiting.
    pub(super) fn other_failed(&mut self, e: stego_seal::StegoError) -> Option<Command> {
        self.unhide.other = false;
        self.unhide.at = other_carrier(self.unhide.at);
        self.refuse_other(match e {
            stego_seal::StegoError::Container(OpenError::Authentication) => {
                Refusal::WrongDescriptor
            }
            _ => Refusal::UnknownFormat,
        });
        None
    }

    /// Why the other backup does not open, said; then LOAD SEED? again, for
    /// the seed found, which nothing wiped.
    pub(super) fn refuse_other(&mut self, why: Refusal) {
        self.stego_live = true;
        self.stego_rest = State::StegoFound;
        self.refuse(why);
    }

    /// LOAD SEED?: LOAD goes to the hint if one came with the seed, else to
    /// the passphrase; CANCEL drops the seed, back to Import. For a photo
    /// holding two backups CANCEL is OTHER, opening the other; Back still
    /// drops.
    pub(super) fn on_stego_found(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Accept if self.hint_len > 0 => self.state = State::StegoHintShown,
            dialog::Target::Accept => self.load_found(),
            dialog::Target::Cancel if self.unhide.two() => return self.open_other(),
            dialog::Target::Nav(Nav::Home) => {
                self.unhide_dropped();
                self.state = State::Home;
            }
            dialog::Target::Nav(_) | dialog::Target::Cancel => {
                self.unhide_dropped();
                self.state = State::Menu {
                    menu: MenuId::Import,
                    page: 0,
                };
            }
        }
        None
    }

    /// RECOVERY HINT: NEXT is the passphrase, the hint wiped; Back is LOAD
    /// SEED?; CANCEL drops the seed, back to Import.
    pub(super) fn on_stego_hint_shown(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Accept => self.load_found(),
            dialog::Target::Nav(Nav::Home) => {
                self.unhide_dropped();
                self.state = State::Home;
            }
            dialog::Target::Nav(_) => self.state = State::StegoFound,
            dialog::Target::Cancel => {
                self.unhide_dropped();
                self.state = State::Menu {
                    menu: MenuId::Import,
                    page: 0,
                };
            }
        }
        None
    }

    /// The seed found goes on to its passphrase; what the import still held
    /// is wiped.
    pub(super) fn load_found(&mut self) {
        self.unhide_end();
        self.ask_passphrase();
    }

    /// The seed found, dropped: it wipes itself, and the hint goes with it.
    pub(super) fn unhide_dropped(&mut self) {
        self.pending = None;
        self.unhide_end();
    }

    /// The import over, its seed loaded or dropped: the payloads kept for
    /// OTHER, the descriptor and everything the stego screens hold, wiped.
    pub(super) fn unhide_end(&mut self) {
        wipe::wipe(&mut self.buffers.photo_out[..2 * stego_wire::PAYLOAD_MAX]);
        self.unhide = Unhide::NONE;
        self.forget_stego();
    }

    /// Everything a stego import held but its descriptor, wiped: the photo,
    /// the window, the payloads, a derivation, a seed or a hint opened.
    pub(super) fn unhide_over(&mut self) {
        self.derivation_over();
        let n = self.photo_len.min(self.buffers.photo.len());
        wipe::wipe(&mut self.buffers.photo[..n]);
        self.photo_len = 0;
        self.buffers.window.fill(0);
        wipe::wipe(self.buffers.window_bits);
        wipe::wipe(&mut self.buffers.photo_out[..2 * stego_wire::PAYLOAD_MAX]);
        self.unhide = Unhide::NONE;
        self.pending = None;
        self.forget_hint();
        self.stego_live = false;
    }

    /// The import stopped: what it held wiped, and why said, then back to the
    /// descriptor's keyboard, the descriptor kept to fix and retry. A
    /// stopped overwrite check goes back to the photo list instead, its
    /// descriptor wiped and nothing written.
    pub(super) fn unhide_failed(&mut self, why: Refusal) {
        self.unhide_over();
        self.stego_live = true;
        self.stego_rest = if self.stego_import {
            State::StegoKey { page: 0 }
        } else {
            self.forget_descriptor();
            State::RestoreList { page: 0 }
        };
        self.refuse(why);
    }
}
