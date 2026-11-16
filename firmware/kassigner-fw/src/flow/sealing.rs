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

//! Writing to the card: a save started and left, a backup's warning, name and
//! password, an old file overwritten, the sealing, and what a save says once
//! written.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    /// The backup's warning: I understand looks at the card for the next
    /// free name.
    pub(super) fn on_backup_warning(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match backup::warning_target(self.scale, x, y)? {
            backup::Target::Nav(Nav::Home) => self.state = State::Home,
            backup::Target::Understand => {
                return self.start_saving(Saving::Backup, self.backup_back)
            }
            // Out of the backup, the name and passwords wiped.
            _ => {
                self.typed.clear();
                self.first.clear();
                self.state = self.backup_back;
            }
        }
        None
    }

    /// The file name: letters and digits, eight at most (8.3); OK asks the
    /// card whether it is taken.
    pub(super) fn on_backup_name(&mut self, event: Event<'_>, page: u8) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let full = self.typed.len() >= NAME_MAX;
        match keyboard::target(self.scale, page, keyboard::Mode::Name { full }, x, y)? {
            keyboard::Target::Nav(_) => self.leave_saving(),
            // No suggestions off a word's keyboard.
            keyboard::Target::Chip(_) => {}
            keyboard::Target::Key(keyboard::Key::Ok) => {
                if self.typed.is_empty() {
                    return None;
                }
                self.backup_name = card::name83(self.typed.as_bytes(), &self.saving.pattern().1);
                self.typed.clear();
                // The result goes back where the save began, whatever a
                // refused overwrite set.
                self.card_exit = self.save_back;
                self.state = State::CardBusy(Job::Exists);
                return Some(Command::Card(Job::Exists));
            }
            keyboard::Target::Key(keyboard::Key::Char(c)) => {
                if c.is_ascii_alphanumeric() && self.typed.len() < NAME_MAX {
                    self.typed.insert(c);
                }
            }
            keyboard::Target::Key(key) => self.edit(key, page, |page| State::BackupName { page }),
        }
        None
    }

    /// The name is taken: Overwrite reads the file first, which a sealed
    /// one's own password must open; Cancel goes back to the name; Home lets
    /// go a card held for its save, as SAVINGS CARD's Home does.
    pub(super) fn on_backup_overwrite(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Accept => {
                self.replacing = true;
                self.file_len = 0;
                self.state = State::CardBusy(Job::Read);
                return Some(Command::Card(Job::Read));
            }
            dialog::Target::Nav(Nav::Home) => self.leave_card(State::Home),
            _ => {
                self.name_again();
                self.state = State::BackupName { page: 0 };
            }
        }
        None
    }

    /// The name on its keyboard again, as it was typed.
    pub(super) fn name_again(&mut self) {
        self.typed.clear();
        for &c in self.backup_name[..8].iter().filter(|&&c| c != b' ') {
            self.typed.insert(c);
        }
    }

    /// The file a save's name is taken by, read, `n` bytes. Sealed, its own
    /// password is asked before it is overwritten; plain, the save goes on.
    /// One this unit cannot open is not overwritten: made on a P4 and read on
    /// an S3, an unknown format, or damaged.
    ///
    /// Whatever fits, as every backup does, is checked in the flow's own file
    /// (internal RAM), so no key is opened in PSRAM; a larger sealed file
    /// whose purpose says it holds a key is not opened at all.
    pub(super) fn start_replacing(&mut self, n: usize) -> Option<Command> {
        use kassigner_protocol::container::{parse, Kdf, Purpose};
        self.file_len = n;
        if n <= FLOW_FILE {
            let read: Option<&mut [u8]> = match self.saving {
                Saving::Signature => Some(&mut *self.buffers.document),
                Saving::Reply | Saving::Descriptor | Saving::Card => {
                    Some(&mut *self.buffers.request)
                }
                Saving::Backup
                | Saving::Kpub(_)
                | Saving::Address
                | Saving::GroupAddress
                | Saving::Stego => None,
            };
            if let Some(read) = read {
                self.file[..n].copy_from_slice(&read[..n]);
                wipe::wipe(&mut read[..n]);
            }
        }
        let file = &*old_file(
            self.saving,
            n,
            &mut self.file,
            &mut *self.buffers.document,
            &mut *self.buffers.request,
        );
        if !sealed(file) {
            self.drop_old_file();
            return self.named();
        }
        let why = match parse(file) {
            Ok(c) if c.kdf == Kdf::Argon2id && self.buffers.kdf.is_none() => {
                Some("Made on a P4: overwrite it on a P4")
            }
            Ok(c)
                if n > FLOW_FILE
                    && !matches!(
                        c.purpose,
                        Purpose::Kspt | Purpose::Text | Purpose::Descriptor
                    ) =>
            {
                Some("File error")
            }
            Ok(_) => None,
            Err(
                ContainerError::Truncated { .. }
                | ContainerError::LengthMismatch { .. }
                | ContainerError::BufferTooSmall,
            ) => Some("File error"),
            Err(_) => Some("Unknown format"),
        };
        if let Some(why) = why {
            self.replace_failed(Outcome::Failed(card::Error::Backup(why)));
            return None;
        }
        self.typed.clear();
        self.first.clear();
        self.state = State::OverwritePassword { page: 0 };
        None
    }

    /// The old file's password, typed once, with no meter and no minimum, as
    /// a delete takes it (v1.0.7 sealed under whatever was typed, nothing
    /// included). OK opens the file; Back leaves the save, the file untouched.
    pub(super) fn on_overwrite_password(&mut self, event: Event<'_>, page: u8) -> Option<Command> {
        use kassigner_crypto::container::KdfParams;
        use kassigner_protocol::container::parse;
        let Event::Tap { x, y } = event else {
            return None;
        };
        match keyboard::target(self.scale, page, keyboard::Mode::Text, x, y)? {
            keyboard::Target::Nav(_) => {
                self.drop_old_file();
                self.leave_saving();
            }
            keyboard::Target::Chip(_) => {}
            keyboard::Target::Key(keyboard::Key::Ok) => {
                self.first = core::mem::take(&mut self.typed);
                let n = self.file_len;
                let file = &*old_file(
                    self.saving,
                    n,
                    &mut self.file,
                    &mut *self.buffers.document,
                    &mut *self.buffers.request,
                );
                let params = parse(file).map(|c| (KdfParams::of(&c), c.purpose));
                let done = match params {
                    Ok((Ok(KdfParams::Pbkdf2Sha256 { salt }), purpose)) => {
                        self.steps = Some(Pbkdf2Steps::new(self.first.as_bytes(), salt, purpose));
                        1
                    }
                    Ok((Ok(KdfParams::Pbkdf2Sha256Fixed), _)) => {
                        self.steps = Some(Pbkdf2Steps::fixed(self.first.as_bytes()));
                        1
                    }
                    Ok((Ok(KdfParams::Argon2id { .. }), _)) => ARGON2_HELD,
                    _ => {
                        self.replace_failed(Outcome::Failed(card::Error::Backup("File error")));
                        return None;
                    }
                };
                self.state = State::OverwriteOpening { done };
            }
            keyboard::Target::Key(keyboard::Key::Char(c)) => {
                self.typed.insert(c);
            }
            keyboard::Target::Key(keyboard::Key::Space) => {
                self.typed.insert(b' ');
            }
            keyboard::Target::Key(key) => {
                self.edit(key, page, |page| State::OverwritePassword { page })
            }
        }
        None
    }

    /// A tick of opening the old file: a batch of PBKDF2 rounds, or Argon2id
    /// whole, then its tag checked in place and the file wiped. Opened, the
    /// save goes on; not, nothing is written.
    pub(super) fn on_overwrite_opening(&mut self, event: Event<'_>, done: u32) -> Option<Command> {
        use kassigner_crypto::container::{check_with_key, derive_key, KdfParams};
        use kassigner_protocol::container::parse;
        let Event::Tick { .. } = event else {
            return None;
        };
        let file = old_file(
            self.saving,
            self.file_len,
            &mut self.file,
            &mut *self.buffers.document,
            &mut *self.buffers.request,
        );
        let checked = match (self.steps.as_mut(), self.buffers.kdf.as_deref_mut()) {
            (Some(steps), _) => {
                let (now, _) = steps.step(SEAL_ROUNDS);
                let Some(mut key) = steps.key() else {
                    self.state = State::OverwriteOpening { done: now };
                    return None;
                };
                let r = check_with_key(file, &key);
                wipe::wipe(&mut key);
                r
            }
            (None, Some(memory)) if done > 0 => {
                let first = &self.first;
                let key = parse(file).map_err(OpenError::Framing).and_then(|c| {
                    derive_key(
                        KdfParams::of(&c)?,
                        first.as_bytes(),
                        c.purpose,
                        Some(memory),
                    )
                });
                key.and_then(|mut key| {
                    let r = check_with_key(file, &key);
                    wipe::wipe(&mut key);
                    r
                })
            }
            _ => Err(OpenError::Authentication),
        };
        self.derivation_over();
        self.first.clear();
        self.drop_old_file();
        match checked {
            Ok(_) => return self.named(),
            Err(OpenError::Authentication) => self.replace_failed(Outcome::Failed(
                card::Error::Backup("Wrong password or damaged file"),
            )),
            Err(_) => self.replace_failed(Outcome::Failed(card::Error::Backup("File error"))),
        }
        None
    }

    /// Wipes the old file, read to be checked, wherever it is: not needed once
    /// it opens, is plain, or is not to be overwritten.
    pub(super) fn drop_old_file(&mut self) {
        let file = old_file(
            self.saving,
            self.file_len,
            &mut self.file,
            &mut *self.buffers.document,
            &mut *self.buffers.request,
        );
        wipe::wipe(file);
        self.file_len = 0;
    }

    /// The file a save's name is taken by is not overwritten: why, said as a
    /// save's failure, then the name again to keep or change. Nothing was
    /// written.
    pub(super) fn replace_failed(&mut self, outcome: Outcome) {
        self.derivation_over();
        self.first.clear();
        self.drop_old_file();
        self.name_again();
        self.card_exit = State::BackupName { page: 0 };
        self.since_us = self.now_us;
        self.state = State::CardDone {
            job: Job::Write,
            outcome,
        };
    }

    /// The password, typed twice: the first OK only once it passes the
    /// policy, the second only if it matches; a mismatch starts both again.
    pub(super) fn on_backup_password(
        &mut self,
        event: Event<'_>,
        page: u8,
        again: bool,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let target = keyboard::target(self.scale, page, keyboard::Mode::Text, x, y)?;
        if let keyboard::Target::Key(_) = target {
            self.mismatch = false;
        }
        match target {
            keyboard::Target::Nav(_) => self.leave_saving(),
            keyboard::Target::Chip(_) => {}
            keyboard::Target::Key(keyboard::Key::Ok) if !again => {
                if password::check(self.typed.as_bytes()).is_ok() {
                    self.first = core::mem::take(&mut self.typed);
                    self.state = State::BackupPassword { page, again: true };
                }
            }
            keyboard::Target::Key(keyboard::Key::Ok) => {
                if self.typed.as_bytes() == self.first.as_bytes() {
                    self.typed.clear();
                    self.steps = None;
                    self.state = State::BackupSealing { done: 0 };
                } else {
                    self.typed.clear();
                    self.first.clear();
                    self.mismatch = true;
                    self.state = State::BackupPassword { page, again: false };
                }
            }
            keyboard::Target::Key(keyboard::Key::Char(c)) => {
                self.typed.insert(c);
            }
            keyboard::Target::Key(keyboard::Key::Space) => {
                self.typed.insert(b' ');
            }
            keyboard::Target::Key(key) => {
                self.edit(key, page, |page| State::BackupPassword { page, again })
            }
        }
        None
    }

    /// Seal the seed in use under the password, a tick at a time, then write
    /// the file. The first tick takes the salt and nonce. On the P4, whose
    /// memory Argon2id uses, the next tick seals; elsewhere PBKDF2 runs
    /// [`SEAL_ROUNDS`] a tick and the last seals with the key. The password,
    /// rounds and key are wiped once sealed, or on any failure.
    pub(super) fn on_backup_sealing<E: Entropy + ?Sized>(
        &mut self,
        event: Event<'_>,
        done: u32,
        rng: &mut E,
    ) -> Option<Command> {
        let Event::Tick { .. } = event else {
            return None;
        };
        let argon = self.buffers.kdf.is_some();
        if !matches!(self.saving, Saving::Backup) {
            return self.seal_text(done, argon, rng);
        }
        let Some((_, slot)) = self.slots.active() else {
            return self.seal_failed(Refusal::NoWallet);
        };
        if done == 0 {
            if rng.fill(&mut self.salt).is_err() || rng.fill(&mut self.nonce).is_err() {
                return self.seal_failed(Refusal::NoEntropy);
            }
            // Argon2id is one call, with nothing drawn during it: the bar
            // goes to half first, and the seal is the next tick's.
            if argon {
                self.state = State::BackupSealing { done: ARGON2_HELD };
                return None;
            }
            let Ok(purpose) = purpose_of(slot) else {
                return self.seal_failed(Refusal::NoPhrase);
            };
            // The keyboard took no password the policy refuses; the steps
            // check it again where the key is made.
            let Ok(steps) = Pbkdf2Steps::sealing(self.first.as_bytes(), &self.salt, purpose) else {
                return self.seal_failed(Refusal::NotSaved);
            };
            self.steps = Some(steps);
            self.state = State::BackupSealing { done: 1 };
            return None;
        }
        if argon {
            let sealed = match self.buffers.kdf.as_deref_mut() {
                Some(memory) => seal_slot(
                    slot,
                    self.first.as_bytes(),
                    &self.salt,
                    &self.nonce,
                    SealKdf::Argon2id(memory),
                    &mut self.file,
                ),
                None => return self.seal_failed(Refusal::NotSaved),
            };
            return self.sealed(sealed);
        }
        let Some(steps) = self.steps.as_mut() else {
            return self.seal_failed(Refusal::NotSaved);
        };
        let (done, total) = steps.step(SEAL_ROUNDS);
        if done < total {
            self.state = State::BackupSealing { done };
            return None;
        }
        // A key to seal with, wiped as it drops; steps made for opening
        // give none, and none are made here.
        let Some(key) = steps.sealing_key() else {
            return self.seal_failed(Refusal::NotSaved);
        };
        let sealed = seal_slot_with_key(slot, &key, &self.salt, &self.nonce, &mut self.file);
        drop(key);
        self.sealed(sealed)
    }

    /// Seal what a save other than a backup writes: a kpub (KSPT purpose, or
    /// the cosigner's for a `.K45`) or an address (text) into the file; a
    /// signed message (text) into the document; a signed transaction (KSPT),
    /// a descriptor (its own) or a card's line (text) into the request's
    /// buffer. Salt and nonce first, then the rounds in batches, or Argon2id
    /// whole.
    pub(super) fn seal_text<E: Entropy + ?Sized>(
        &mut self,
        done: u32,
        argon: bool,
        rng: &mut E,
    ) -> Option<Command> {
        use kassigner_crypto::container::{seal, seal_with_key};
        use kassigner_protocol::container::{Kdf, Purpose};
        let mut origin = [0u8; crate::kpub::COSIGNER_MAX];
        let mut group_text = [0u8; DESCRIPTOR_FILE_MAX];
        let signature = self.saving == Saving::Signature;
        let cosigner = self.saving == Saving::Kpub(KpubKey::Cosigner);
        let address = matches!(self.saving, Saving::Address | Saving::GroupAddress);
        let descriptor = self.saving == Saving::Descriptor;
        let card = self.saving == Saving::Card;
        let purpose = if signature || address || card {
            Purpose::Text
        } else if cosigner {
            Purpose::Cosigner
        } else if descriptor {
            Purpose::Descriptor
        } else {
            Purpose::Kspt
        };
        if done == 0 {
            if rng.fill(&mut self.salt).is_err() || rng.fill(&mut self.nonce).is_err() {
                return self.seal_failed(Refusal::NoEntropy);
            }
            if signature && self.write_record(true).is_none() {
                return self.seal_failed(Refusal::TooLong);
            }
            if argon {
                self.state = State::BackupSealing { done: ARGON2_HELD };
                return None;
            }
            let Ok(steps) = Pbkdf2Steps::sealing(self.first.as_bytes(), &self.salt, purpose) else {
                return self.seal_failed(Refusal::NotSaved);
            };
            self.steps = Some(steps);
            self.state = State::BackupSealing { done: 1 };
            return None;
        }
        let (text, out): (&[u8], &mut [u8]) = if signature {
            let at = self.msg_len;
            (
                &self.buffers.request[at..at + self.record_len],
                &mut *self.buffers.document,
            )
        } else if self.saving == Saving::Reply {
            (
                &self.buffers.reply[..self.reply_len],
                &mut *self.buffers.request,
            )
        } else if address {
            (&self.addr_text[..self.addr_len], &mut self.file)
        } else if descriptor || card {
            // A card's line in the descriptor's room, the longest.
            let made = if card {
                self.card_line(&mut group_text)
            } else {
                self.descriptor_file(&mut group_text)
            };
            let Some(n) = made else {
                return self.seal_failed(Refusal::NotSaved);
            };
            (&group_text[..n], &mut *self.buffers.request)
        } else if cosigner {
            let Some(fingerprint) = self.fingerprint() else {
                return self.seal_failed(Refusal::NotSaved);
            };
            let kpub = &self.kpub[..self.kpub_len];
            let Some(n) = crate::kpub::write_cosigner(fingerprint, kpub, &mut origin) else {
                return self.seal_failed(Refusal::NotSaved);
            };
            (&origin[..n], &mut self.file)
        } else {
            (&self.kpub[..self.kpub_len], &mut self.file)
        };
        if argon {
            let sealed = match self.buffers.kdf.as_deref_mut() {
                Some(memory) => seal(
                    purpose,
                    text,
                    self.first.as_bytes(),
                    &self.salt,
                    &self.nonce,
                    SealKdf::Argon2id(memory),
                    out,
                ),
                None => return self.seal_failed(Refusal::NotSaved),
            };
            return self.sealed(sealed);
        }
        let Some(steps) = self.steps.as_mut() else {
            return self.seal_failed(Refusal::NotSaved);
        };
        let (done, total) = steps.step(SEAL_ROUNDS);
        if done < total {
            self.state = State::BackupSealing { done };
            return None;
        }
        // A key to seal with, wiped as it drops; steps made for opening
        // give none, and none are made here.
        let Some(key) = steps.sealing_key() else {
            return self.seal_failed(Refusal::NotSaved);
        };
        let sealed = seal_with_key(
            purpose,
            text,
            &key,
            Kdf::Pbkdf2Sha256,
            &self.salt,
            &self.nonce,
            out,
        );
        drop(key);
        self.sealed(sealed)
    }

    /// Sealed, or not: the password and the rounds wiped either way, then
    /// the write, or the refusal.
    pub(super) fn sealed<T>(&mut self, sealed: Result<usize, T>) -> Option<Command> {
        self.first.clear();
        self.derivation_over();
        match sealed {
            Ok(n) => {
                self.file_len = n;
                self.state = State::CardBusy(Job::Write);
                Some(Command::Card(Job::Write))
            }
            Err(_) => self.seal_failed(Refusal::NotSaved),
        }
    }

    /// Sealing stopped: everything it held wiped, and why said.
    pub(super) fn seal_failed(&mut self, why: Refusal) -> Option<Command> {
        self.first.clear();
        self.derivation_over();
        wipe::wipe(&mut self.file);
        self.file_len = 0;
        self.refuse(why);
        None
    }

    /// The name is settled: a backup's password next, ENCRYPT FILE? for the
    /// rest.
    pub(super) fn named(&mut self) -> Option<Command> {
        match self.saving {
            Saving::Backup => self.start_password(),
            Saving::Kpub(_) => self.state = State::KpubEncrypt,
            Saving::Signature
            | Saving::Reply
            | Saving::Address
            | Saving::GroupAddress
            | Saving::Descriptor
            | Saving::Card => self.state = State::KpubEncrypt,
            // Never named: the photo is written over itself.
            Saving::Stego => {}
        }
        None
    }

    /// The password's keyboard, empty, the first time.
    pub(super) fn start_password(&mut self) {
        self.typed.clear();
        self.first.clear();
        self.mismatch = false;
        self.state = State::BackupPassword {
            page: 0,
            again: false,
        };
    }

    /// What the keyboard's line says beside the text: a password's strength,
    /// to type it or a passphrase again, or no match; or a count of
    /// characters typed.
    pub fn keyboard_note(&self) -> Option<keyboard::Note> {
        match self.state {
            State::BackupPassword { again: false, .. } if self.mismatch => {
                Some(keyboard::Note::NoMatch)
            }
            State::BackupPassword { again: false, .. } => {
                Some(match password::check(self.typed.as_bytes()) {
                    Err(password::Weakness::TooShort { .. }) => keyboard::Note::TooShort,
                    Err(_) => keyboard::Note::Weak,
                    Ok(password::Strength::Fair) => keyboard::Note::Fair,
                    Ok(password::Strength::Good) => keyboard::Note::Good,
                    Ok(password::Strength::Strong) => keyboard::Note::Strong,
                })
            }
            State::BackupPassword { again: true, .. } => Some(keyboard::Note::Again),
            State::Passphrase { .. } if self.mismatch => Some(keyboard::Note::NoMatch),
            State::PassphraseAgain { .. } => Some(keyboard::Note::Again),
            State::BackupName { .. } => Some(keyboard::Note::Count {
                used: u8::try_from(self.typed.len()).unwrap_or(u8::MAX),
                of: NAME_MAX as u8,
            }),
            State::RawKey => Some(keyboard::Note::Count {
                used: u8::try_from(self.typed.len()).unwrap_or(u8::MAX),
                of: RAW_KEY_HEX as u8,
            }),
            State::StegoDescriptor { .. } => Some(keyboard::Note::Count {
                used: u8::try_from(self.typed.len()).unwrap_or(u8::MAX),
                of: stego_wire::DESCRIPTOR_WRITE_MAX as u8,
            }),
            State::StegoHintType { .. } => Some(keyboard::Note::Count {
                used: u8::try_from(self.typed.len()).unwrap_or(u8::MAX),
                of: HINT_MAX as u8,
            }),
            State::StegoKey { .. } | State::StegoOldKey { .. } => Some(keyboard::Note::Count {
                used: u8::try_from(self.desc.len()).unwrap_or(u8::MAX),
                of: stego_wire::DESCRIPTOR_READ_MAX as u8,
            }),
            _ => None,
        }
    }

    /// Start saving `what`: the card asked for its next free name, and the
    /// save's and the result's way back set to `back`.
    pub(super) fn start_saving(&mut self, what: Saving, back: State) -> Option<Command> {
        self.saving = what;
        self.save_back = back;
        let (letters, ext) = what.pattern();
        self.backup_name = card::name83(&letters, &ext);
        self.card_exit = back;
        self.state = State::CardBusy(Job::NextName);
        Some(Command::Card(Job::NextName))
    }

    /// Where a save goes back to: the screen it was asked from.
    pub(super) const fn saving_from(&self) -> State {
        self.save_back
    }

    /// Leave a save from its keyboards: everything typed wiped.
    pub(super) fn leave_saving(&mut self) {
        self.typed.clear();
        self.first.clear();
        self.state = self.saving_from();
    }

    /// What a save says once written.
    pub const fn saved_text(&self) -> &'static str {
        match self.saving {
            Saving::Backup => "!! Backup Saved !!",
            Saving::Kpub(_) => "!! kpub Saved !!",
            Saving::Signature => "!! Signature Saved !!",
            Saving::Reply => "!! Signed TX Saved !!",
            Saving::Address | Saving::GroupAddress => "!! Address Saved !!",
            Saving::Descriptor => "!! Descriptor Saved !!",
            Saving::Card => "!! Card Saved !!",
            Saving::Stego => "!! Backup Hidden !!",
        }
    }
}

/// Whether a file is sealed, by its first bytes: `KAS` and a layout byte
/// below 0x20, a control byte that text rarely puts there. This firmware
/// opens `\x03`, `\x04` and `\x06`; v1.0.5's `\x01` and `\x02`, and layouts
/// to come, it does not, but they count as sealed. Text starting `KASPA` is
/// not.
pub(super) fn sealed(file: &[u8]) -> bool {
    file.len() >= 4 && file[..3] == *b"KAS" && file[3] < 0x20
}

/// Where the file a save's name is taken by sits once read, `n` bytes: the
/// flow's own file (internal RAM) when it fits, as every backup does; else
/// the buffer the save writes from. No other save reads a larger file.
pub(super) fn old_file<'a>(
    saving: Saving,
    n: usize,
    file: &'a mut [u8; FLOW_FILE],
    document: &'a mut [u8],
    request: &'a mut [u8],
) -> &'a mut [u8] {
    let at: &'a mut [u8] = match saving {
        _ if n <= FLOW_FILE => file,
        Saving::Signature => document,
        Saving::Reply | Saving::Descriptor | Saving::Card => request,
        Saving::Backup
        | Saving::Kpub(_)
        | Saving::Address
        | Saving::GroupAddress
        | Saving::Stego => file,
    };
    let n = n.min(at.len());
    &mut at[..n]
}
