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

//! The card's files: the list, a file's delete and password, and backups,
//! kpubs, descriptors, addresses, text and transactions opened from it.

use super::*;

/// A file that opened to something other than a mainnet multisig address.
pub(super) const NOT_GROUP_ADDRESS: &str = "Not a multisig address";
/// A `.KSP` file sealed under a purpose other than a transaction's.
pub(super) const NOT_TRANSACTION: &str = "Not a transaction";
/// A file that opened to something not a descriptor, in the scanner's words.
pub(super) const NOT_DESCRIPTOR: &str = refusal::NOT_A_DESCRIPTOR.0;

/// Bytes of a sealed text file opened and checked for a seed on the stack
/// (internal RAM), so that no seed reaches PSRAM: more than 24 words or a
/// SeedQR take. Longer text opens into the document.
pub(super) const TEXT_ON_STACK: usize = 1024;

/// What opening a sealed text file came to: [`Flow::open_text`].
pub(super) enum TextOpened {
    /// The text, its length, over the file in the request's buffer.
    Text(usize),
    /// Opened under its password, for a delete: nothing of it kept.
    Checked,
    /// A seed, kept nowhere.
    Seed,
    Failed(OpenError),
}

/// A `.K45` file that does not hold a cosigner's kpub as a unit writes one.
pub(super) const NOT_COSIGNER: &str = "Not a 45' kpub file";

impl<'b, const N: usize> Flow<'b, N> {
    /// SELECT BACKUP: a row asks for its password; the arrows turn the page.
    pub(super) fn on_restore_list(&mut self, event: Event<'_>, page: usize) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let pick = backup::pick_in(self.scale, self.listed, page, self.list_trash(), x, y)?;
        match pick {
            backup::Pick::Nav(Nav::Home) => self.state = State::Home,
            backup::Pick::Nav(Nav::PageUp) => {
                self.state = State::RestoreList {
                    page: page.saturating_sub(1),
                }
            }
            backup::Pick::Nav(Nav::PageDown) => self.state = State::RestoreList { page: page + 1 },
            // Back where the list was asked from.
            backup::Pick::Nav(_) => self.state = self.list_exit(),
            // A photo to open: the descriptor next, typed or from a file.
            backup::Pick::Row(i) if self.listing == Listing::Photos && self.stego_import => {
                self.photo_chose(i);
                self.state = State::Menu {
                    menu: MenuId::StegoSource,
                    page: 0,
                };
            }
            // A photo to hide a backup in: read now, to see whether its
            // metadata holds one already. An earlier choice's leftovers go;
            // the long names stay, for the list shown again if an overwrite
            // is refused.
            backup::Pick::Row(i) if self.listing == Listing::Photos => {
                self.forget_descriptor();
                self.forget_hint();
                self.forget_photo();
                self.photo_chose(i);
                self.backup_name = self.photo_name;
                self.card_exit = State::RestoreList { page: 0 };
                self.state = State::CardBusy(Job::Read);
                return Some(Command::Card(Job::Read));
            }
            // A caption file: read as it is, no password.
            backup::Pick::Row(i) if self.listing == Listing::Captions => {
                self.backup_name = self.backups[i];
                self.card_exit = State::Menu {
                    menu: MenuId::StegoSource,
                    page: 0,
                };
                self.state = State::CardBusy(Job::Read);
                return Some(Command::Card(Job::Read));
            }
            // A row restores; its trash deletes, but only once the backup's
            // own password opens it, so nobody else holding the unit can.
            backup::Pick::Row(i) | backup::Pick::Trash(i) => {
                self.deleting = matches!(pick, backup::Pick::Trash(_));
                self.backup_name = self.backups[i];
                self.typed.clear();
                self.first.clear();
                self.state = State::RestorePassword { page: 0 };
            }
        }
        None
    }

    /// Delete a backup: a tap on DELETE arms it, a finger held for
    /// [`HOLD_US`] deletes it, lifting or sliding off first cancels.
    pub(super) fn on_restore_delete(
        &mut self,
        event: Event<'_>,
        page: usize,
        armed: bool,
        held_since: Option<u64>,
    ) -> Option<Command> {
        let at = |armed, held_since| State::RestoreDelete {
            page,
            armed,
            held_since,
        };
        match self.hold(event, armed, held_since) {
            Hold::Nothing => {}
            Hold::Cancel => self.state = State::RestoreList { page },
            Hold::Home => self.state = State::Home,
            Hold::Arm => self.state = at(true, None),
            Hold::Down => self.state = at(armed, Some(self.now_us)),
            Hold::Done => {
                self.card_exit = State::RestoreList { page: 0 };
                self.state = State::CardBusy(Job::Delete);
                return Some(Command::Card(Job::Delete));
            }
        }
        None
    }

    /// The backup's password, typed once, with no meter and no minimum: those
    /// are for sealing, and a v1.0.x backup may have a shorter one. Nothing
    /// typed is a password too: v1.0.7 sealed under whatever was typed,
    /// nothing included, and those backups must still open and be deleted.
    /// Each still has to open under what is typed.
    pub(super) fn on_restore_password(&mut self, event: Event<'_>, page: u8) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match keyboard::target(self.scale, page, keyboard::Mode::Text, x, y)? {
            keyboard::Target::Nav(_) => {
                self.typed.clear();
                self.state = State::RestoreList { page: 0 };
            }
            keyboard::Target::Chip(_) => {}
            keyboard::Target::Key(keyboard::Key::Ok) => {
                self.first = core::mem::take(&mut self.typed);
                self.card_exit = State::RestoreList { page: 0 };
                self.state = State::CardBusy(Job::Read);
                return Some(Command::Card(Job::Read));
            }
            keyboard::Target::Key(keyboard::Key::Char(c)) => {
                self.typed.insert(c);
            }
            keyboard::Target::Key(keyboard::Key::Space) => {
                self.typed.insert(b' ');
            }
            keyboard::Target::Key(key) => {
                self.edit(key, page, |page| State::RestorePassword { page })
            }
        }
        None
    }

    /// The file is read: its header decides how it opens, or why not, before
    /// the password is used.
    pub(super) fn start_opening(&mut self) {
        if matches!(self.listing, Listing::Kpubs | Listing::Cosigners) {
            return self.start_kpub_open();
        }
        if matches!(self.listing, Listing::Groups | Listing::Cards) {
            return self.start_buffered_open();
        }
        if self.listing == Listing::Addresses {
            return self.start_address_open();
        }
        if self.listing == Listing::Messages {
            return self.start_message_open();
        }
        if self.listing == Listing::Transactions {
            return self.start_tx_open();
        }
        let file = &self.file[..self.file_len.min(FLOW_FILE)];
        match backup_kdf(file) {
            Ok(BackupKdf::Argon2id) if self.buffers.kdf.is_none() => {
                self.restore_failed(self.made_on_p4())
            }
            Ok(BackupKdf::Argon2id) => self.state = State::RestoreOpening { done: ARGON2_HELD },
            Ok(BackupKdf::Pbkdf2 { salt, purpose }) => {
                self.steps = Some(Pbkdf2Steps::new(self.first.as_bytes(), &salt, purpose));
                self.state = State::RestoreOpening { done: 1 };
            }
            Err(BackupError::Container(OpenError::Framing(ContainerError::UnsupportedKdf(_)))) => {
                self.restore_failed("Unknown format")
            }
            Err(_) => self.restore_failed("File error"),
        }
    }

    /// A tick of opening: a batch of PBKDF2 rounds, or Argon2id whole; then
    /// the slot: a seed goes on to its passphrase, an xprv is stored.
    pub(super) fn on_restore_opening(&mut self, event: Event<'_>, done: u32) -> Option<Command> {
        let Event::Tick { .. } = event else {
            return None;
        };
        if matches!(self.listing, Listing::Kpubs | Listing::Cosigners) {
            return self.on_kpub_opening(done);
        }
        if matches!(self.listing, Listing::Groups | Listing::Cards) {
            return self.on_buffered_opening(done);
        }
        if self.listing == Listing::Addresses {
            return self.on_address_opening(done);
        }
        if self.listing == Listing::Messages {
            return self.on_message_opening(done);
        }
        if self.listing == Listing::Transactions {
            return self.on_tx_opening(done);
        }
        let file = &self.file[..self.file_len.min(FLOW_FILE)];
        let opened = match (self.steps.as_mut(), self.buffers.kdf.as_deref_mut()) {
            (Some(steps), _) => {
                let (now, _) = steps.step(SEAL_ROUNDS);
                let Some(mut key) = steps.key() else {
                    self.state = State::RestoreOpening { done: now };
                    return None;
                };
                let r = open_slot_with_key(file, &key, b"");
                wipe::wipe(&mut key);
                r
            }
            (None, Some(memory)) if done > 0 => {
                open_slot(file, self.first.as_bytes(), b"", Some(memory))
            }
            _ => Err(BackupError::Malformed),
        };
        self.derivation_over();
        self.first.clear();
        wipe::wipe(&mut self.file);
        self.file_len = 0;
        match opened {
            // Opened, so the password is the backup's: what it held is
            // dropped, wiping itself, and the delete is asked.
            Ok(_) if self.deleting => {
                self.state = State::RestoreDelete {
                    page: 0,
                    armed: false,
                    held_since: None,
                };
            }
            Ok(Slot::Mnemonic { mnemonic, .. }) => {
                self.hold_loaded(mnemonic);
                self.ask_passphrase();
            }
            Ok(slot @ Slot::Xprv(_)) => match self.slots.store(slot) {
                Ok(index) => self.use_slot_always(index),
                Err(SlotError::Full) => self.refuse(Refusal::SlotsFull),
                Err(_) => self.refuse(Refusal::NotOpened),
            },
            Ok(_) => self.restore_failed("File error"),
            Err(BackupError::Container(OpenError::Authentication)) => {
                self.restore_failed("Wrong password or damaged file")
            }
            Err(_) => self.restore_failed("File error"),
        }
        None
    }

    /// A kpub file read: plain, which opens only to nothing typed, or sealed
    /// under the KSPT purpose. The oldest layout, `KAS\x03`, has no salt: its
    /// rounds use the fixed one. A cosigner's `.K45` file is read only as
    /// one: plain with the seed and path in front, or sealed under the
    /// cosigner purpose, checked before the password is used.
    pub(super) fn start_kpub_open(&mut self) {
        use kassigner_protocol::container::{parse, Kdf, Purpose};
        let cosigner = self.cosigner_file();
        let file = &self.file[..self.file_len.min(FLOW_FILE)];
        let plain = if cosigner {
            crate::kpub::read_cosigner(file)
        } else {
            crate::kpub::read(file)
        };
        if let Some(key) = plain {
            if self.first.is_empty() {
                return self.kpub_opened(&key);
            }
            return self.restore_failed("Wrong password or damaged file");
        }
        let (purpose, not_one) = if cosigner {
            (Purpose::Cosigner, NOT_COSIGNER)
        } else {
            (Purpose::Kspt, "Not a valid kpub")
        };
        match parse(file) {
            Ok(c) if c.purpose == purpose => match (c.kdf, c.salt) {
                (Kdf::Argon2id, Some(_)) if self.buffers.kdf.is_none() => {
                    self.restore_failed(self.made_on_p4())
                }
                (Kdf::Argon2id, Some(_)) => {
                    self.state = State::RestoreOpening { done: ARGON2_HELD }
                }
                (Kdf::Pbkdf2Sha256, Some(salt)) => {
                    self.steps = Some(Pbkdf2Steps::new(self.first.as_bytes(), salt, purpose));
                    self.state = State::RestoreOpening { done: 1 };
                }
                (Kdf::Pbkdf2Sha256Fixed, None) => {
                    self.steps = Some(Pbkdf2Steps::fixed(self.first.as_bytes()));
                    self.state = State::RestoreOpening { done: 1 };
                }
                _ => self.restore_failed("File error"),
            },
            Err(ContainerError::UnsupportedKdf(_)) => self.restore_failed("Unknown format"),
            _ => self.restore_failed(not_one),
        }
    }

    /// A tick of opening a sealed kpub file: a batch of rounds, or Argon2id
    /// whole; then what it holds read as a kpub.
    pub(super) fn on_kpub_opening(&mut self, done: u32) -> Option<Command> {
        use kassigner_crypto::container::{open, open_with_key};
        use kassigner_protocol::container::parse;
        let mut plain = [0u8; crate::kpub::COSIGNER_MAX];
        let cosigner = self.cosigner_file();
        let file = &self.file[..self.file_len.min(FLOW_FILE)];
        let opened = match (self.steps.as_mut(), self.buffers.kdf.as_deref_mut()) {
            (Some(steps), _) => {
                let (now, _) = steps.step(SEAL_ROUNDS);
                let Some(mut key) = steps.key() else {
                    self.state = State::RestoreOpening { done: now };
                    return None;
                };
                let r = parse(file)
                    .map_err(OpenError::Framing)
                    .and_then(|c| open_with_key(&c, &key, &mut plain));
                wipe::wipe(&mut key);
                r
            }
            (None, Some(memory)) if done > 0 => {
                open(file, self.first.as_bytes(), &mut plain, Some(memory))
            }
            _ => Err(OpenError::Authentication),
        };
        self.derivation_over();
        self.first.clear();
        wipe::wipe(&mut self.file);
        self.file_len = 0;
        let key = opened.map(|o| {
            let text = &plain[..o.len];
            if cosigner {
                crate::kpub::read_cosigner(text)
            } else {
                crate::kpub::read(text)
            }
        });
        wipe::wipe(&mut plain);
        match key {
            Ok(Some(key)) => self.kpub_opened(&key),
            Ok(None) if cosigner => self.restore_failed(NOT_COSIGNER),
            Ok(None) => self.restore_failed("Not a valid kpub"),
            Err(OpenError::Authentication) => self.restore_failed("Wrong password or damaged file"),
            Err(_) => self.restore_failed("File error"),
        }
        None
    }

    /// A kpub file opened under its password: the delete asked, a group's
    /// next key, or the kpub shown.
    pub(super) fn kpub_opened(&mut self, key: &ExtendedPublicKey) {
        if self.deleting {
            self.state = State::RestoreDelete {
                page: 0,
                armed: false,
                held_since: None,
            };
            return;
        }
        // A cosigner's: the group's next key, as a scanned one is.
        if self.listing == Listing::Cosigners {
            return self.add_cosigner(*key, None);
        }
        if let Err(why) = self.set_kpub(key) {
            return self.refuse(why);
        }
        self.kpub_key = KpubKey::Single;
        self.kpub_exit = State::RestoreList { page: 0 };
        self.state = State::KpubFormat;
    }

    /// Why a file sealed under Argon2id does not open here: only the P4 has
    /// the memory to open or delete one.
    pub(super) const fn made_on_p4(&self) -> &'static str {
        if self.deleting {
            "Made on a P4: delete it on a P4"
        } else {
            "Made on a P4: open it on a P4"
        }
    }

    /// A descriptor or card file read into the request's buffer: plain,
    /// which opens only to nothing typed, or sealed under its own purpose.
    pub(super) fn start_buffered_open(&mut self) {
        use kassigner_protocol::container::{parse, Kdf};
        let purpose = self.buffered_purpose();
        let n = self.file_len.min(self.buffers.request.len());
        match parse(&self.buffers.request[..n]) {
            Ok(c) if c.purpose == purpose => match (c.kdf, c.salt) {
                (Kdf::Argon2id, Some(_)) if self.buffers.kdf.is_none() => {
                    self.buffered_failed(self.made_on_p4())
                }
                (Kdf::Argon2id, Some(_)) => {
                    self.state = State::RestoreOpening { done: ARGON2_HELD }
                }
                (Kdf::Pbkdf2Sha256, Some(salt)) => {
                    self.steps = Some(Pbkdf2Steps::new(self.first.as_bytes(), salt, purpose));
                    self.state = State::RestoreOpening { done: 1 };
                }
                _ => self.buffered_failed("File error"),
            },
            Ok(_) => self.buffered_failed(self.buffered_not_one()),
            Err(_) if !self.first.is_empty() => {
                self.buffered_failed("Wrong password or damaged file")
            }
            Err(_) => {
                let mut text = [0u8; GROUP_FILE_MAX];
                let n = n.min(GROUP_FILE_MAX);
                text[..n].copy_from_slice(&self.buffers.request[..n]);
                self.drop_buffered_file();
                self.buffered_text(&text[..n]);
                wipe::wipe(&mut text);
            }
        }
    }

    /// The purpose a card's line (text) or a descriptor (its own) is sealed
    /// under.
    fn buffered_purpose(&self) -> kassigner_protocol::container::Purpose {
        use kassigner_protocol::container::Purpose;
        if self.listing == Listing::Cards {
            Purpose::Text
        } else {
            Purpose::Descriptor
        }
    }

    /// What a file sealed under another purpose is said to be not.
    const fn buffered_not_one(&self) -> &'static str {
        match self.listing {
            Listing::Cards => refusal::BACKUP_NOT_ONE,
            _ => NOT_DESCRIPTOR,
        }
    }

    /// A file read into the request's buffer, its text opened: a card's
    /// line, or a descriptor.
    fn buffered_text(&mut self, text: &[u8]) {
        if self.listing == Listing::Cards {
            self.card_text(text);
        } else {
            self.group_text(text);
        }
    }

    /// A tick of opening a sealed descriptor or card file: a batch of
    /// rounds, or Argon2id whole; then its text read.
    pub(super) fn on_buffered_opening(&mut self, done: u32) -> Option<Command> {
        use kassigner_crypto::container::{open, open_with_key};
        use kassigner_protocol::container::parse;
        let mut text = [0u8; GROUP_FILE_MAX];
        let n = self.file_len.min(self.buffers.request.len());
        let file = &self.buffers.request[..n];
        let opened = match (self.steps.as_mut(), self.buffers.kdf.as_deref_mut()) {
            (Some(steps), _) => {
                let (now, _) = steps.step(SEAL_ROUNDS);
                let Some(mut key) = steps.key() else {
                    self.state = State::RestoreOpening { done: now };
                    return None;
                };
                let r = parse(file)
                    .map_err(OpenError::Framing)
                    .and_then(|c| open_with_key(&c, &key, &mut text));
                wipe::wipe(&mut key);
                r
            }
            (None, Some(memory)) if done > 0 => {
                open(file, self.first.as_bytes(), &mut text, Some(memory))
            }
            _ => Err(OpenError::Authentication),
        };
        self.derivation_over();
        self.first.clear();
        self.drop_buffered_file();
        match opened {
            Ok(o) => self.buffered_text(&text[..o.len]),
            Err(OpenError::Authentication) => self.restore_failed("Wrong password or damaged file"),
            Err(_) => self.restore_failed("File error"),
        }
        wipe::wipe(&mut text);
        None
    }

    /// A descriptor file's text: the delete asked, LOAD MULTISIG?, or why
    /// not.
    pub(super) fn group_text(&mut self, text: &[u8]) {
        if self.deleting {
            self.state = State::RestoreDelete {
                page: 0,
                armed: false,
                held_since: None,
            };
            return;
        }
        if !self.ask_load(text, State::RestoreList { page: 0 }) {
            self.restore_failed(NOT_DESCRIPTOR);
        }
    }

    /// `text` read as a group and LOAD MULTISIG? asked, CANCEL going to
    /// `from`. The seed in use's place among its keys is found now, so the
    /// answer's tap has no work behind it. `false`, nothing changed, if it is
    /// not a group.
    pub(super) fn ask_load(&mut self, text: &[u8], from: State) -> bool {
        let read = core::str::from_utf8(text)
            .ok()
            .and_then(|t| HeldGroup::from_descriptor(t).ok());
        let Some(group) = read else {
            return false;
        };
        self.load_seed = match (self.keys.is_some(), self.position_in(&group)) {
            (false, _) => multisig_screen::SeedIn::NoSeed,
            (true, Some(i)) => multisig_screen::SeedIn::Cosigner(i),
            (true, None) => multisig_screen::SeedIn::Not,
        };
        self.loading = Some(group);
        self.load_from = from;
        self.state = State::LoadGroup;
        true
    }

    /// Wipes the descriptor or card file read into the request's buffer.
    pub(super) fn drop_buffered_file(&mut self) {
        let read = core::mem::take(&mut self.file_len);
        let end = read.min(self.buffers.request.len());
        wipe::wipe(&mut self.buffers.request[..end]);
    }

    /// A descriptor or card file that does not open: what was read wiped,
    /// and why said.
    pub(super) fn buffered_failed(&mut self, why: &'static str) {
        self.drop_buffered_file();
        self.restore_failed(why);
    }

    /// LOAD MULTISIG?: LOAD holds the group, replacing any, and shows its
    /// DESCRIPTOR, the seed in use's key marked; the group already held
    /// keeps its worked-out keys. CANCEL, Back and Home drop it: the card's
    /// list again, or home after a scan.
    pub(super) fn on_load_group(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let answer = tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))?;
        match (answer, self.loading.take()) {
            (dialog::Target::Accept, Some(group)) => {
                if self.group.as_ref() != Some(&group) {
                    self.group = Some(group);
                    self.group_from = [None; limits::MAX_MULTISIG_KEYS];
                    // What was kept was the last group's.
                    self.branches.clear();
                }
                self.desc_own = match self.load_seed {
                    multisig_screen::SeedIn::Cosigner(i) => u8::try_from(i).ok(),
                    _ => None,
                };
                self.state = State::Descriptor;
            }
            _ => self.state = self.load_from,
        }
        None
    }

    /// An address file read into the flow's own file: plain, which opens
    /// only to nothing typed, or sealed under the text purpose.
    pub(super) fn start_address_open(&mut self) {
        use kassigner_protocol::container::{parse, Kdf, Purpose};
        let n = self.file_len.min(FLOW_FILE);
        let file = &self.file[..n];
        match parse(file) {
            Ok(c) if c.purpose == Purpose::Text => match (c.kdf, c.salt) {
                (Kdf::Argon2id, Some(_)) if self.buffers.kdf.is_none() => {
                    self.restore_failed(self.made_on_p4())
                }
                (Kdf::Argon2id, Some(_)) => {
                    self.state = State::RestoreOpening { done: ARGON2_HELD }
                }
                (Kdf::Pbkdf2Sha256, Some(salt)) => {
                    self.steps = Some(Pbkdf2Steps::new(self.first.as_bytes(), salt, Purpose::Text));
                    self.state = State::RestoreOpening { done: 1 };
                }
                _ => self.restore_failed("File error"),
            },
            Ok(_) => self.restore_failed(NOT_GROUP_ADDRESS),
            Err(_) if !self.first.is_empty() => {
                self.restore_failed("Wrong password or damaged file")
            }
            Err(_) => {
                let mut text = [0u8; FLOW_FILE];
                text[..n].copy_from_slice(file);
                wipe::wipe(&mut self.file);
                self.file_len = 0;
                self.address_read(&text[..n]);
                wipe::wipe(&mut text);
            }
        }
    }

    /// A tick of opening a sealed address file: a batch of rounds, or
    /// Argon2id whole; then what it holds read as an address.
    pub(super) fn on_address_opening(&mut self, done: u32) -> Option<Command> {
        use kassigner_crypto::container::{open, open_with_key};
        use kassigner_protocol::container::parse;
        let mut text = [0u8; FLOW_FILE];
        let file = &self.file[..self.file_len.min(FLOW_FILE)];
        let opened = match (self.steps.as_mut(), self.buffers.kdf.as_deref_mut()) {
            (Some(steps), _) => {
                let (now, _) = steps.step(SEAL_ROUNDS);
                let Some(mut key) = steps.key() else {
                    self.state = State::RestoreOpening { done: now };
                    return None;
                };
                let r = parse(file)
                    .map_err(OpenError::Framing)
                    .and_then(|c| open_with_key(&c, &key, &mut text));
                wipe::wipe(&mut key);
                r
            }
            (None, Some(memory)) if done > 0 => {
                open(file, self.first.as_bytes(), &mut text, Some(memory))
            }
            _ => Err(OpenError::Authentication),
        };
        self.derivation_over();
        self.first.clear();
        wipe::wipe(&mut self.file);
        self.file_len = 0;
        match opened {
            Ok(o) => self.address_read(&text[..o.len]),
            Err(OpenError::Authentication) => self.restore_failed("Wrong password or damaged file"),
            Err(_) => self.restore_failed("File error"),
        }
        wipe::wipe(&mut text);
        None
    }

    /// An address file's text: the delete asked, a mainnet multisig address
    /// kept for MULTISIG ADDRESS, or a refusal.
    pub(super) fn address_read(&mut self, text: &[u8]) {
        if self.deleting {
            self.state = State::RestoreDelete {
                page: 0,
                armed: false,
                held_since: None,
            };
            return;
        }
        let text = text.trim_ascii();
        let mut payload = [0u8; 33];
        // The shared address check, as for a signed message's.
        match crate::checks::decode_expecting(Prefix::Mainnet, text, &mut payload) {
            Ok((Version::ScriptHash, _)) if text.len() <= MAX_ADDRESS_LEN => {
                self.file_addr[..text.len()].copy_from_slice(text);
                self.file_addr_len = text.len();
                self.state = State::FileAddress;
            }
            _ => self.restore_failed(NOT_GROUP_ADDRESS),
        }
    }

    /// MULTISIG ADDRESS, from a file: a tap on the address is its code;
    /// Back is the list again, Home is home.
    pub(super) fn on_file_address(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match address_screen::target(self.scale, true, true, x, y)? {
            address_screen::Target::Nav(Nav::Home) => self.state = State::Home,
            address_screen::Target::Nav(_) => self.state = State::RestoreList { page: 0 },
            address_screen::Target::Address => self.state = State::FileAddressQr,
            _ => {}
        }
        None
    }

    /// The address read from a file, for MULTISIG ADDRESS and its code.
    pub fn file_address(&self) -> &str {
        core::str::from_utf8(&self.file_addr[..self.file_addr_len]).unwrap_or("")
    }

    /// What the card's list looks for: `.KAS` backups, `.TXT` kpubs (the
    /// `.K45` cosigners' files among them) or text, `.K45` alone for a
    /// group's key, `.KSP` transactions, `.JPG` photos.
    pub(super) fn list_pattern(&self) -> [u8; 11] {
        match self.listing {
            Listing::Transactions => {
                let (_, ext) = Saving::Reply.pattern();
                card::name83(b"", &ext)
            }
            Listing::Backups => card::name83(b"", &card::BACKUP_EXT),
            Listing::Kpubs | Listing::Messages | Listing::Groups => card::name83(b"", b"TXT"),
            Listing::Cosigners => card::name83(b"", &card::COSIGNER_EXT),
            Listing::Photos => card::name83(b"", b"JPG"),
            Listing::Captions => card::name83(b"", b"TXT"),
            // A group's address or a card's line, as Save to SD names it.
            Listing::Addresses => {
                let (letters, ext) = Saving::GroupAddress.pattern();
                card::name83(&letters, &ext)
            }
            Listing::Cards => {
                let (letters, ext) = Saving::Card.pattern();
                card::name83(&letters, &ext)
            }
        }
    }

    /// The card job that lists files of the list's kind.
    pub(super) const fn list_job(&self) -> Job {
        match self.listing {
            Listing::Messages | Listing::Captions | Listing::Transactions => Job::ListText,
            Listing::Groups => Job::ListGroups,
            Listing::Addresses => Job::ListAddresses,
            Listing::Cards => Job::ListCards,
            Listing::Photos => Job::ListPhotos,
            Listing::Backups | Listing::Kpubs | Listing::Cosigners => Job::List,
        }
    }

    /// Whether the chosen file is a cosigner's `.K45`: read only as one, and
    /// sealed only under its own purpose.
    pub(super) fn cosigner_file(&self) -> bool {
        self.backup_name[8..] == card::COSIGNER_EXT
    }

    /// Where the card's list goes back to, as does a list that came back
    /// empty or unread: where it was asked from.
    pub(super) const fn list_exit(&self) -> State {
        match self.listing {
            Listing::Backups | Listing::Kpubs => State::Menu {
                menu: MenuId::ImportSd,
                page: 0,
            },
            // The page with each one's row.
            Listing::Transactions => State::Menu {
                menu: MenuId::ImportSd,
                page: TRANSACTIONS_ROW / menu::LIST.rows,
            },
            Listing::Addresses => State::Menu {
                menu: MenuId::ImportSd,
                page: ADDRESSES_ROW / menu::LIST.rows,
            },
            Listing::Groups => State::Menu {
                menu: MenuId::ImportSd,
                page: GROUPS_ROW / menu::LIST.rows,
            },
            Listing::Messages => sign_message(),
            // Import's row, or Import from SD's, whichever opened it.
            Listing::Cards => self.cards_from,
            Listing::Cosigners => State::AddKey,
            // Stego Import's row is on Import's first page.
            Listing::Photos if self.stego_import => State::Menu {
                menu: MenuId::Import,
                page: 0,
            },
            Listing::Photos => State::StegoCarrier,
            Listing::Captions => State::Menu {
                menu: MenuId::StegoSource,
                page: 0,
            },
        }
    }

    /// Whether the list's rows have a delete button: not for photos and
    /// captions.
    pub fn list_trash(&self) -> bool {
        !matches!(self.listing, Listing::Photos | Listing::Captions)
    }

    /// The icon on the list's rows: a page for photos and captions, the
    /// floppy disk for the rest.
    pub fn list_icon(&self) -> crate::ui::gen::Icon {
        match self.listing {
            Listing::Photos | Listing::Captions => crate::ui::gen::Icon::Page,
            _ => crate::ui::gen::Icon::FloppyDisk,
        }
    }

    /// What the SD Card's result screen says: what a write saved, what an
    /// empty list says, and a failure's title.
    pub const fn card_said(&self) -> sd_card::Said {
        let empty = match self.listing {
            Listing::Backups => ("NO BACKUPS", "No backups on the card"),
            Listing::Kpubs | Listing::Messages | Listing::Captions => ("No .TXT files found", ""),
            Listing::Transactions => ("No .KSP files found", ""),
            Listing::Cosigners => ("No .K45 files found", ""),
            Listing::Groups => ("No descriptors found", ""),
            Listing::Addresses => ("No addresses found", ""),
            Listing::Cards => ("No card backups found", ""),
            Listing::Photos => ("No photos found", "No .JPG files on the card"),
        };
        sd_card::Said {
            saved: self.saved_text(),
            failed: self.failed_text(),
            empty,
        }
    }

    /// A failure's title on the result screen: what was being done, never
    /// the card job alone. A save's first steps fail as that save, a list as
    /// the load it is for; a read for a delete fails as the delete
    /// (`restore_failed`), and a read of the file a save would overwrite as
    /// that save (`replace_failed`).
    /// Off the result screen the test's title stands in.
    pub(super) const fn failed_text(&self) -> &'static str {
        let job = match self.state {
            State::CardDone { job, .. } => job,
            _ => Job::Test,
        };
        match job {
            Job::NextName | Job::Exists | Job::Write => match self.saving {
                Saving::Backup => sd_card::BACKUP_FAILED,
                Saving::Kpub(_) => sd_card::KPUB_SAVE_FAILED,
                Saving::Signature => sd_card::SIGNATURE_SAVE_FAILED,
                Saving::Reply => sd_card::TX_SAVE_FAILED,
                Saving::Address | Saving::GroupAddress => sd_card::ADDRESS_SAVE_FAILED,
                Saving::Descriptor => sd_card::DESCRIPTOR_SAVE_FAILED,
                Saving::Card => sd_card::CARD_SAVE_FAILED,
                Saving::Stego => sd_card::STEGO_FAILED,
            },
            Job::List
            | Job::ListText
            | Job::ListGroups
            | Job::ListAddresses
            | Job::ListCards
            | Job::Read => match self.listing {
                Listing::Backups => sd_card::RESTORE_FAILED,
                Listing::Kpubs | Listing::Cosigners => sd_card::KPUB_LOAD_FAILED,
                Listing::Messages => sd_card::MESSAGE_LOAD_FAILED,
                Listing::Transactions => sd_card::TX_LOAD_FAILED,
                Listing::Groups => sd_card::DESCRIPTOR_LOAD_FAILED,
                Listing::Addresses => sd_card::ADDRESS_LOAD_FAILED,
                Listing::Cards => sd_card::CARD_LOAD_FAILED,
                Listing::Photos => sd_card::PHOTO_LOAD_FAILED,
                Listing::Captions => sd_card::DESCRIPTOR_LOAD_FAILED,
            },
            Job::ListPhotos => sd_card::PHOTO_LOAD_FAILED,
            Job::Delete => sd_card::DELETE_FAILED,
            Job::Format => sd_card::FORMAT_FAILED,
            // A probe answers on the SD Card screen, never here.
            Job::Test | Job::Probe => sd_card::TEST_FAILED,
        }
    }

    /// A restore that stops here: what it held wiped, the reason shown,
    /// then back where it was started from.
    pub(super) fn restore_failed(&mut self, why: &'static str) {
        // Reading or opening for a delete fails as a delete.
        let job = if self.deleting {
            Job::Delete
        } else {
            Job::Read
        };
        self.derivation_over();
        self.first.clear();
        wipe::wipe(&mut self.file);
        self.file_len = 0;
        self.since_us = self.now_us;
        self.state = State::CardDone {
            job,
            outcome: Outcome::Failed(card::Error::Backup(why)),
        };
    }

    /// The list's title: SELECT CARD for covenant cards' backups, SELECT
    /// PHOTO for photos, SELECT FILE for text, transaction, descriptor,
    /// address and caption files, SELECT BACKUP for backups and kpub files.
    pub const fn list_title(&self) -> &'static str {
        match self.listing {
            Listing::Cards => "SELECT CARD",
            Listing::Messages
            | Listing::Transactions
            | Listing::Groups
            | Listing::Addresses
            | Listing::Captions => "SELECT FILE",
            Listing::Photos => "SELECT PHOTO",
            _ => "SELECT BACKUP",
        }
    }

    /// The backups the card listed, for SELECT BACKUP's rows.
    pub fn backups(&self) -> &[[u8; 11]] {
        &self.backups[..self.listed]
    }

    /// A text file read: plain, which opens only to nothing typed, or sealed
    /// under the text purpose.
    pub(super) fn start_message_open(&mut self) {
        use kassigner_protocol::container::{parse, Kdf, Purpose};
        let n = self.file_len;
        match parse(&self.buffers.request[..n]) {
            Ok(c) if c.purpose == Purpose::Text => match (c.kdf, c.salt) {
                (Kdf::Argon2id, Some(_)) if self.buffers.kdf.is_none() => {
                    self.restore_failed(self.made_on_p4())
                }
                (Kdf::Argon2id, Some(_)) => {
                    self.state = State::RestoreOpening { done: ARGON2_HELD }
                }
                (Kdf::Pbkdf2Sha256, Some(salt)) => {
                    self.steps = Some(Pbkdf2Steps::new(self.first.as_bytes(), salt, Purpose::Text));
                    self.state = State::RestoreOpening { done: 1 };
                }
                _ => self.restore_failed("File error"),
            },
            Ok(_) => self.restore_failed("Not a text file"),
            Err(_) if !self.first.is_empty() => {
                self.restore_failed("Wrong password or damaged file")
            }
            Err(_) => self.file_opened(n),
        }
    }

    /// A tick of opening a sealed text file: a batch of rounds, or Argon2id
    /// whole; then [`Flow::open_text`], and the message taken or refused.
    pub(super) fn on_message_opening(&mut self, done: u32) -> Option<Command> {
        use kassigner_crypto::container::{derive_key, KdfParams};
        use kassigner_protocol::container::parse;
        let key = match (self.steps.as_mut(), self.buffers.kdf.as_deref_mut()) {
            (Some(steps), _) => {
                let (now, _) = steps.step(SEAL_ROUNDS);
                let Some(key) = steps.key() else {
                    self.state = State::RestoreOpening { done: now };
                    return None;
                };
                Ok(key)
            }
            (None, Some(memory)) if done > 0 => {
                let first = &self.first;
                parse(&self.buffers.request[..self.file_len.min(self.buffers.request.len())])
                    .map_err(OpenError::Framing)
                    .and_then(|c| {
                        derive_key(
                            KdfParams::of(&c)?,
                            first.as_bytes(),
                            c.purpose,
                            Some(memory),
                        )
                    })
            }
            _ => Err(OpenError::Authentication),
        };
        self.derivation_over();
        self.first.clear();
        let opened = match key {
            Ok(mut key) => {
                wipe::begin_depth(self.stack);
                let opened = self.open_text(&key);
                wipe::wipe(&mut key);
                wipe::scrub_flow();
                opened
            }
            Err(e) => TextOpened::Failed(e),
        };
        match opened {
            TextOpened::Text(n) => self.file_opened(n),
            TextOpened::Checked => self.file_opened(0),
            TextOpened::Seed => self.restore_failed(refusal::SEED_NOT_MESSAGE.0),
            TextOpened::Failed(OpenError::Authentication) => {
                self.restore_failed("Wrong password or damaged file")
            }
            TextOpened::Failed(_) => self.restore_failed("File error"),
        }
        None
    }

    /// The sealed text in the request's buffer opened under `key`, in a
    /// frame of its own for the stack scrub after it. Up to
    /// [`TEXT_ON_STACK`] bytes it opens on the stack (internal RAM) and is
    /// checked there: a seed goes no further, as a scanned one does not, nor
    /// a text opened only for a delete; any other is copied over the file as
    /// the message, the rest of the file wiped. Longer text opens into the
    /// document (PSRAM), and that copy is wiped once taken.
    #[inline(never)]
    pub(super) fn open_text(
        &mut self,
        key: &[u8; kassigner_crypto::container::KEY_SIZE],
    ) -> TextOpened {
        use kassigner_crypto::container::open_with_key;
        use kassigner_protocol::container::parse;
        let read = self.file_len;
        let c = match parse(&self.buffers.request[..read]) {
            Ok(c) => c,
            Err(e) => return TextOpened::Failed(OpenError::Framing(e)),
        };
        let mut stack = [0u8; TEXT_ON_STACK];
        let small = c.len <= TEXT_ON_STACK;
        let plain: &mut [u8] = if small {
            &mut stack
        } else {
            &mut *self.buffers.document
        };
        let n = match open_with_key(&c, key, plain) {
            Ok(o) => o.len,
            Err(e) => {
                wipe::wipe(&mut stack);
                return TextOpened::Failed(e);
            }
        };
        let text: &[u8] = if small {
            &stack[..n]
        } else {
            &self.buffers.document[..n]
        };
        let opened = if self.deleting {
            TextOpened::Checked
        } else if holds_seed(text) {
            TextOpened::Seed
        } else {
            self.buffers.request[..n].copy_from_slice(text);
            wipe::wipe(&mut self.buffers.request[n..read]);
            TextOpened::Text(n)
        };
        wipe::wipe(&mut stack);
        if !small {
            wipe::wipe(&mut self.buffers.document[..n]);
        }
        opened
    }

    /// A text or transaction file opened under its password: for a delete,
    /// what the card read is wiped and the delete asked; else the text is
    /// taken as the message, or the transaction as a scanned request.
    pub(super) fn file_opened(&mut self, n: usize) {
        let read = core::mem::take(&mut self.file_len);
        self.first.clear();
        if self.deleting {
            wipe::wipe(&mut self.buffers.request[..read.max(n)]);
            self.state = State::RestoreDelete {
                page: 0,
                armed: false,
                held_since: None,
            };
            return;
        }
        if self.listing == Listing::Transactions {
            self.state = State::Checking { len: n, card: true };
        } else {
            self.take_message(n, true);
        }
    }

    /// A transaction file read into the request's buffer: sealed under the
    /// KSPT purpose, or the request itself (KSPT or a bundle), which opens
    /// only to nothing typed. The review judges what it holds.
    pub(super) fn start_tx_open(&mut self) {
        use kassigner_protocol::container::{parse, Kdf, Purpose};
        let n = self.file_len;
        match parse(&self.buffers.request[..n]) {
            Ok(c) if c.purpose == Purpose::Kspt => match (c.kdf, c.salt) {
                (Kdf::Argon2id, Some(_)) if self.buffers.kdf.is_none() => {
                    self.tx_failed(self.made_on_p4())
                }
                (Kdf::Argon2id, Some(_)) => {
                    self.state = State::RestoreOpening { done: ARGON2_HELD }
                }
                (Kdf::Pbkdf2Sha256, Some(salt)) => {
                    self.steps = Some(Pbkdf2Steps::new(self.first.as_bytes(), salt, Purpose::Kspt));
                    self.state = State::RestoreOpening { done: 1 };
                }
                _ => self.tx_failed("File error"),
            },
            Ok(_) => self.tx_failed(NOT_TRANSACTION),
            Err(_) if !self.first.is_empty() => self.tx_failed("Wrong password or damaged file"),
            Err(_) => self.file_opened(n),
        }
    }

    /// A tick of opening a sealed transaction file: a batch of rounds, or
    /// Argon2id whole; then the transaction opened into the reply's buffer,
    /// empty while a file is chosen, and moved over the file in the
    /// request's.
    pub(super) fn on_tx_opening(&mut self, done: u32) -> Option<Command> {
        use kassigner_crypto::container::{open, open_with_key};
        use kassigner_protocol::container::parse;
        let read = self.file_len.min(self.buffers.request.len());
        let file = &self.buffers.request[..read];
        let opened = match (self.steps.as_mut(), self.buffers.kdf.as_deref_mut()) {
            (Some(steps), _) => {
                let (now, _) = steps.step(SEAL_ROUNDS);
                let Some(mut key) = steps.key() else {
                    self.state = State::RestoreOpening { done: now };
                    return None;
                };
                let r = parse(file)
                    .map_err(OpenError::Framing)
                    .and_then(|c| open_with_key(&c, &key, self.buffers.reply));
                wipe::wipe(&mut key);
                r
            }
            (None, Some(memory)) if done > 0 => open(
                file,
                self.first.as_bytes(),
                self.buffers.reply,
                Some(memory),
            ),
            _ => Err(OpenError::Authentication),
        };
        self.derivation_over();
        self.first.clear();
        match opened {
            // It fits where its file was; the rest of the file, and the
            // copy, wiped.
            Ok(o) if o.len <= read => {
                let n = o.len;
                self.buffers.request[..n].copy_from_slice(&self.buffers.reply[..n]);
                wipe::wipe(&mut self.buffers.request[n..read]);
                wipe::wipe(&mut self.buffers.reply[..n]);
                self.file_opened(n);
            }
            Ok(o) => {
                wipe::wipe(&mut self.buffers.reply[..o.len]);
                self.tx_failed("File error");
            }
            Err(OpenError::Authentication) => self.tx_failed("Wrong password or damaged file"),
            Err(_) => self.tx_failed("File error"),
        }
        None
    }

    /// A transaction file that stops here: what the card read is wiped from
    /// the request's buffer, then the reason shown.
    pub(super) fn tx_failed(&mut self, why: &'static str) {
        let read = core::mem::take(&mut self.file_len).min(self.buffers.request.len());
        wipe::wipe(&mut self.buffers.request[..read]);
        self.restore_failed(why);
    }
}
