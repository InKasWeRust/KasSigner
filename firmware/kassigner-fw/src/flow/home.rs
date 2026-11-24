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

//! Boot, Home, the menus, and the wipe of everything the unit holds.

use super::*;

/// CREATE MULTISIG as it opens: 2 of 3.
pub(super) const CREATE_MULTISIG: State = State::CreateMultisig { m: 2, n: 3 };

/// MULTISIG's rows for a held group (Multisig Address and Multisig
/// Descriptor), as bits for [`menu::draw_dimmed`].
pub(super) const GROUP_ROWS: u32 = 0b110;

/// The submenu a menu's row leads to, if any.
pub(super) const fn menu_under(id: MenuId, row: usize) -> Option<MenuId> {
    match (id, row) {
        (MenuId::Import, 0) => Some(MenuId::ImportSd),
        (MenuId::Export, 0) => Some(MenuId::SeedBackup),
        (MenuId::Export, 1) => Some(MenuId::WatchOnly),
        (MenuId::Export, 2) => Some(MenuId::SigningKeys),
        (MenuId::SeedBackup, 1) => Some(MenuId::QrExport),
        (MenuId::Tools, 2) => Some(MenuId::SignMessage),
        (MenuId::Tools, 3) => Some(MenuId::Multisig),
        _ => None,
    }
}

impl<'b, const N: usize> Flow<'b, N> {
    // ── Transitions ─────────────────────────────────────────────────────

    pub(super) fn on_boot(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Booted {
            provisioning,
            image_read,
            checks_ok,
        } = event
        else {
            return None;
        };
        self.check = brand::Check {
            verdict: provisioning,
            image_read,
        };
        self.state = if checks_ok {
            self.since_us = self.now_us;
            State::Verified(self.check)
        } else {
            State::Halted(Halt::SelfTest)
        };
        None
    }

    /// A screen that stays for `hold` and then rests; true on the tick that
    /// ends it.
    pub(super) fn on_timed(&mut self, event: Event<'_>, hold: u64) -> bool {
        if let Event::Tick { now_us } = event {
            if now_us.saturating_sub(self.since_us) >= hold {
                self.state = self.home();
                return true;
            }
        }
        false
    }

    /// Where a timed screen rests: [`Flow::stego_rest`] in steganography,
    /// KEY k/N while a group still wants keys, SIGNED TX while a reply is
    /// held (so a failed save returns to it), else Home.
    pub(super) fn home(&self) -> State {
        if self.stego_live {
            self.stego_rest
        } else if self.adding_keys() {
            State::AddKey
        } else if self.reply_len > 0 {
            State::ReplyDone
        } else {
            State::Home
        }
    }

    pub(super) fn on_home(&mut self, event: Event<'_>) -> Option<Command> {
        // The logo held wipes everything, silently; lifting or sliding off
        // before the time does nothing.
        let scale = self.scale;
        let on_logo = |x, y| brand::target(scale, x, y) == Some(brand::Target::Logo);
        match event {
            Event::Press { x, y } if on_logo(x, y) => {
                self.logo_since = Some(self.now_us);
                return None;
            }
            Event::Drag { x, y } if !on_logo(x, y) => {
                self.logo_since = None;
                return None;
            }
            Event::Tick { now_us }
                if self
                    .logo_since
                    .is_some_and(|t| now_us.saturating_sub(t) >= WIPE_HOLD_US) =>
            {
                self.wipe_everything();
                self.since_us = now_us;
                self.state = State::Wiped;
                return None;
            }
            _ => {}
        }
        let Event::Tap { x, y } = event else {
            return None;
        };
        self.logo_since = None;
        match brand::target(self.scale, x, y)? {
            brand::Target::Card(0) => {
                self.progress = (0, 0);
                self.received = 0;
                self.seed_or_frame = None;
                self.seed_hint = false;
                self.state = State::Scanning;
                return Some(Command::CameraOn);
            }
            brand::Target::Card(1) => self.state = State::Seeds { page: 0 },
            brand::Target::Card(2) => {
                self.state = State::Menu {
                    menu: MenuId::Tools,
                    page: 0,
                }
            }
            brand::Target::Card(_) => {
                self.state = State::Menu {
                    menu: MenuId::Settings,
                    page: 0,
                }
            }
            brand::Target::Header | brand::Target::Logo => {}
        }
        None
    }

    /// Whether anything of a seed is held: a slot, a wallet, a seed waiting
    /// or being made, a raw key.
    pub(super) fn holds_seed(&self) -> bool {
        self.slots.count() > 0
            || self.keys.is_some()
            || self.opening.is_some()
            || self.pending.is_some()
            || self.collector.is_some()
            || self.raw_key.is_some()
    }

    /// Whether anything the idle wipe takes is held: a seed, or anything
    /// typed or rolled towards a seed or key, even with no seed loaded.
    /// Public for the P4's binary, whose reset button cuts the power while
    /// this holds.
    pub fn holds_secret(&self) -> bool {
        self.holds_seed()
            || !self.typed.is_empty()
            || !self.first.is_empty()
            || self.word_filled > 0
            || self.rolled > 0
            // A descriptor or a hint: Stego Import holds them with no seed.
            || !self.desc.is_empty()
            || self.hint_len > 0
    }

    /// Whether a job runs across ticks; the idle wipe lets it finish.
    pub(super) const fn busy(&self) -> bool {
        matches!(
            self.state,
            State::Opening { .. }
                | State::BackupSealing { .. }
                | State::RestoreOpening { .. }
                | State::OverwriteOpening { .. }
                | State::StegoSealing { .. }
                | State::StegoEmbedding
                | State::StegoReading
                | State::StegoOpening { .. }
                | State::CardBusy(_)
                | State::Searching { .. }
                | State::SavingsSearching { .. }
                | State::KprvDeriving
                | State::KeyDeriving
                | State::GroupDeriving
                | State::Bip85Deriving
                | State::Checking { .. }
                | State::Signing
                | State::MessageSigning
        )
    }

    /// Wipe everything a seed left: slots, wallet and keys, anything waiting,
    /// typed or rolled, every lent buffer whole, a message, a file, a key,
    /// address or kpub on show; a request through [`Flow::drop_request`].
    /// The stack is scrubbed last; the caller sets the state.
    pub(super) fn wipe_everything(&mut self) {
        self.slots.wipe_all();
        self.unbacked = [false; N];
        self.uneven = (0, 0);
        self.made_later = false;
        self.checks.clear();
        self.drop_request();
        self.keys = None;
        self.opening.zeroize();
        self.pending = None;
        self.collector = None;
        self.raw_key = None;
        self.typed.clear();
        self.first.clear();
        // What stego holds (payloads, the photo's copy, the window), as its
        // screens wipe it when they end: an idle wipe can come while one
        // waits on CONFIRM or FOUND. Before `file_len` is reset, which
        // bounds the photo copy's wipe.
        self.stego_over();
        self.unhide_over();
        self.phrase.zeroize();
        self.word_pos = 0;
        self.word_filled = 0;
        self.word_invalid = false;
        self.leave_dice();
        wipe::wipe(&mut self.key_text);
        self.key_len = 0;
        wipe::wipe(&mut self.addr_text);
        self.addr_len = 0;
        wipe::wipe(&mut self.kpub);
        wipe::wipe(&mut self.kpub_raw);
        self.kpub_len = 0;
        wipe::wipe(&mut self.file);
        self.file_len = 0;
        for buffer in [
            &mut *self.buffers.request,
            &mut *self.buffers.reply,
            &mut *self.buffers.document,
            &mut *self.buffers.scripts,
            &mut *self.buffers.redeem,
            &mut *self.buffers.text,
            &mut *self.buffers.edited,
        ] {
            wipe::wipe(buffer);
        }
        self.buffers.signatures.fill(InputSignature::EMPTY);
        for key in self.buffers.pump.iter_mut() {
            wipe::wipe(key);
        }
        self.pumped = 0;
        self.reply_len = 0;
        self.reply_signers = None;
        self.reply_v107 = 0;
        self.reply_wallet = true;
        self.msg_held = 0;
        self.msg_read = 0;
        self.msg_len = 0;
        self.forming = None;
        self.group = None;
        self.loading = None;
        wipe::wipe(&mut self.file_addr);
        self.file_addr_len = 0;
        self.savings = None;
        // A BIP85 child's index and the keypad's digits are secrets too.
        self.bip85_index = 0;
        wipe::wipe(&mut self.pad);
        self.pad_len = 0;
        self.branches.clear();
        self.deferred = None;
        self.group_from = [None; limits::MAX_MULTISIG_KEYS];
        self.open_for_group = false;
        self.addr_group = false;
        self.addr_kcc3 = false;
        self.sig_len = 0;
        self.record_len = 0;
        self.shown_len = 0;
        self.logo_since = None;
        self.pressed_in = None;
        self.pressed_at = None;
        self.derivation_over();
    }

    pub(super) fn on_menu(&mut self, event: Event<'_>, id: MenuId, page: usize) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let m = self.menu(id);
        match menu::target(self.scale, m, page, x, y)? {
            // Back relists the photos: a caption list may have replaced them.
            menu::Target::Nav(Nav::Back) if id == MenuId::StegoSource => {
                return self.list_photos();
            }
            menu::Target::Nav(Nav::Back) => {
                let parent = |menu| State::Menu { menu, page: 0 };
                self.state = match id {
                    MenuId::SeedTools => parent(MenuId::Tools),
                    MenuId::Import => State::ImportExport,
                    // Back where Export was opened from.
                    MenuId::Export => self.export_from,
                    MenuId::ImportSd => parent(MenuId::Import),
                    MenuId::SeedBackup | MenuId::WatchOnly | MenuId::SigningKeys => {
                        parent(MenuId::Export)
                    }
                    MenuId::QrExport => parent(MenuId::SeedBackup),
                    MenuId::SignMessage | MenuId::Multisig => parent(MenuId::Tools),
                    MenuId::StegoSource => State::StegoCarrier,
                    MenuId::Tools | MenuId::Settings => State::Home,
                }
            }
            menu::Target::Nav(Nav::Home) => self.state = State::Home,
            menu::Target::Nav(Nav::PageUp) => {
                self.state = State::Menu {
                    menu: id,
                    page: page.saturating_sub(1),
                }
            }
            menu::Target::Nav(Nav::PageDown) => {
                self.state = State::Menu {
                    menu: id,
                    page: page + 1,
                }
            }
            // Seed Tools, under Tools.
            menu::Target::Item(0) if id == MenuId::Tools => {
                self.state = State::Menu {
                    menu: MenuId::SeedTools,
                    page: 0,
                }
            }
            // New Seed: the count first, then the unit's own sources.
            menu::Target::Item(0) if id == MenuId::SeedTools => {
                self.state = State::WordCount {
                    action: CountFor::NewSeed,
                }
            }
            // Import Words: the count first.
            menu::Target::Item(2) if id == MenuId::SeedTools => {
                self.state = State::WordCount {
                    action: CountFor::Words(WordsFor::Import),
                }
            }
            // Dice Seed: the count first.
            menu::Target::Item(1) if id == MenuId::SeedTools => {
                self.state = State::WordCount {
                    action: CountFor::Dice,
                }
            }
            // KCC-3 Address, for the seed in use.
            menu::Target::Item(KCC3_ROW) if id == MenuId::SeedTools => self.open_kcc3_address(),
            // BIP85 Child: from the seed in use, if words and backed up.
            menu::Target::Item(5) if id == MenuId::SeedTools => match self.slots.active() {
                Some(_) if self.in_use_unbacked() => self.refuse(Refusal::NotBackedUp),
                Some((_, Slot::Mnemonic { .. })) => {
                    self.state = State::WordCount {
                        action: CountFor::Bip85,
                    }
                }
                Some(_) => self.refuse(Refusal::NoPhrase),
                None => self.refuse(Refusal::NoWallet),
            },
            // Address, for the seed in use.
            menu::Target::Item(3) if id == MenuId::SeedTools => self.open_address(
                State::Menu {
                    menu: MenuId::SeedTools,
                    page: 0,
                },
                false,
            ),
            // Calc Last Word: the count first.
            menu::Target::Item(6) if id == MenuId::SeedTools => {
                self.state = State::WordCount {
                    action: CountFor::Words(WordsFor::LastWord),
                }
            }
            // Import / Export, under Tools.
            menu::Target::Item(1) if id == MenuId::Tools => self.state = State::ImportExport,
            // Create Multisig: M and N first, 2 of 3 as it opens.
            menu::Target::Item(0) if id == MenuId::Multisig => {
                self.forming = None;
                self.state = CREATE_MULTISIG;
            }
            // Multisig Address and Descriptor need a held group; without
            // one their rows are dimmed and do nothing.
            menu::Target::Item(1) if id == MenuId::Multisig && self.group.is_some() => {
                return self.defer(Work::GroupAddress);
            }
            // Multisig Descriptor, on the tick after the tap.
            menu::Target::Item(2) if id == MenuId::Multisig && self.group.is_some() => {
                return self.defer(Work::Descriptor);
            }
            menu::Target::Item(2) if id == MenuId::Multisig => {}
            // The submenus that lead on.
            menu::Target::Item(i) if menu_under(id, i).is_some() => {
                if let Some(next) = menu_under(id, i) {
                    self.state = State::Menu {
                        menu: next,
                        page: 0,
                    }
                }
            }
            // Import from SD's file rows: the card's files of that kind.
            menu::Target::Item(row @ (0 | TRANSACTIONS_ROW | 2 | ADDRESSES_ROW | GROUPS_ROW))
                if id == MenuId::ImportSd =>
            {
                self.listing = match row {
                    0 => Listing::Backups,
                    TRANSACTIONS_ROW => Listing::Transactions,
                    2 => Listing::Kpubs,
                    ADDRESSES_ROW => Listing::Addresses,
                    _ => Listing::Groups,
                };
                self.backup_name = self.list_pattern();
                self.card_exit = self.list_exit();
                let list = self.list_job();
                self.state = State::CardBusy(list);
                return Some(Command::Card(list));
            }
            // Covenant Restore, under Import or Import from SD: the card's
            // covenant backups, returning to that menu.
            menu::Target::Item(row)
                if (id == MenuId::Import && row == COVENANT_ROW)
                    || (id == MenuId::ImportSd && row == SD_COVENANT_ROW) =>
            {
                self.cards_from = State::Menu {
                    menu: id,
                    page: row / menu::LIST.rows,
                };
                self.listing = Listing::Cards;
                self.backup_name = self.list_pattern();
                self.card_exit = self.list_exit();
                let list = self.list_job();
                self.state = State::CardBusy(list);
                return Some(Command::Card(list));
            }
            // Show Seed Words, one at a time; an xprv or raw key is refused.
            menu::Target::Item(0) if id == MenuId::SeedBackup => match self.slots.active() {
                Some((_, Slot::Mnemonic { mnemonic, .. })) => {
                    self.word_count = mnemonic.len();
                    self.after_words = AfterWords::SeedBackup;
                    self.state = State::ShowWords { pos: 0 };
                }
                Some(_) => self.refuse(Refusal::NoPhrase),
                None => self.refuse(Refusal::NoWallet),
            },
            // Sign Message: typed, from the card, or scanned. A wallet is
            // needed only to sign, not to check a signed message.
            menu::Target::Item(row @ 0..=2) if id == MenuId::SignMessage => match row {
                0 => {
                    self.typed.clear();
                    self.state = State::MessageType { page: 0 };
                }
                1 => {
                    self.listing = Listing::Messages;
                    self.backup_name = self.list_pattern();
                    self.card_exit = sign_message();
                    self.state = State::CardBusy(Job::ListText);
                    return Some(Command::Card(Job::ListText));
                }
                _ => {
                    self.progress = (0, 0);
                    self.received = 0;
                    self.state = State::MessageScan;
                    return Some(Command::CameraOn);
                }
            },
            // Stego Import: a backup in a photo on the card; no seed needed.
            menu::Target::Item(1) if id == MenuId::Import => {
                self.forget_stego();
                self.stego_import = true;
                return self.list_photos();
            }
            // Import Raw Key: a lone private key, for a wallet with no seed.
            menu::Target::Item(2) if id == MenuId::Import => {
                self.typed.clear();
                self.state = State::RawKey;
            }
            // Signing Keys: kprv Master, kprv Account, Private Key, shown.
            menu::Target::Item(0) if id == MenuId::SigningKeys => self.open_master(),
            menu::Target::Item(1) if id == MenuId::SigningKeys => self.open_account(),
            menu::Target::Item(2) if id == MenuId::SigningKeys => self.open_address(
                State::Menu {
                    menu: MenuId::SigningKeys,
                    page: 0,
                },
                true,
            ),
            // Watch-Only's three kpub rows, on the tick after the tap
            // ([`Flow::kpub_row`]).
            menu::Target::Item(row @ 0..=2) if id == MenuId::WatchOnly => {
                return self.defer(Work::Kpub { row });
            }
            // QR Export: CompactSeedQR, Standard SeedQR, Plain Text QR, for a
            // seed with words.
            menu::Target::Item(row @ 0..=2) if id == MenuId::QrExport => {
                match self.slots.active() {
                    Some((_, Slot::Mnemonic { .. })) => {
                        self.state = match row {
                            0 => State::SeedQr { compact: true },
                            1 => State::SeedQr { compact: false },
                            _ => State::PlainFormat,
                        }
                    }
                    Some(_) => self.refuse(Refusal::NoPhrase),
                    None => self.refuse(Refusal::NoWallet),
                }
            }
            // Steganography: the seed in use's words into a photo.
            menu::Target::Item(3) if id == MenuId::Export => match self.slots.active() {
                Some((_, Slot::Mnemonic { .. })) => {
                    self.stego_import = false;
                    self.state = State::StegoCarrier
                }
                Some(_) => self.refuse(Refusal::NoPhrase),
                None => self.refuse(Refusal::NoWallet),
            },
            // IMAGE DESCRIPTOR: typed, or a .TXT's first line. An import
            // types into the descriptor itself.
            menu::Target::Item(0) if id == MenuId::StegoSource && self.stego_import => {
                self.forget_descriptor();
                self.state = State::StegoKey { page: 0 };
            }
            menu::Target::Item(0) if id == MenuId::StegoSource => {
                self.typed.clear();
                self.state = State::StegoDescriptor { page: 0 };
            }
            menu::Target::Item(1) if id == MenuId::StegoSource => {
                self.listing = Listing::Captions;
                self.backup_name = self.list_pattern();
                self.card_exit = self.list_exit();
                self.state = State::CardBusy(Job::ListText);
                return Some(Command::Card(Job::ListText));
            }

            // Backup to SD: the seed in use, if it is words.
            menu::Target::Item(2) if id == MenuId::SeedBackup => match self.slots.active() {
                Some((_, Slot::Mnemonic { .. })) => {
                    self.backup_back = seed_backup();
                    self.state = State::BackupWarning
                }
                Some(_) => self.refuse(Refusal::NoPhrase),
                None => self.refuse(Refusal::NoWallet),
            },
            // A setting by what the row is, not where: rows differ by unit.
            menu::Target::Item(i) if id == MenuId::Settings => match m.items[i].setting {
                Some(Setting::Display) => self.state = State::Display,
                Some(Setting::Audio) => self.state = State::Audio,
                Some(Setting::About) => self.state = State::About,
                Some(Setting::Camera) if !self.knobs.is_empty() => {
                    // The board's lead setting first, the most often moved.
                    let knob = self.knobs.iter().position(|k| k.lead).unwrap_or(0);
                    self.state = State::CameraTune { knob };
                    return Some(Command::TuneOn);
                }
                // Probed on opening: a card can come and go at any time.
                Some(Setting::SdCard) => {
                    self.card = card::Status::Checking;
                    self.card_exit = State::Card;
                    self.state = State::Card;
                    return Some(Command::Card(Job::Probe));
                }
                // A unit with no knobs.
                Some(Setting::Camera) | None => {}
            },
            // The rest lead nowhere yet.
            menu::Target::Item(_) => {}
        }
        None
    }

    /// Tools' Import / Export: Import, and Export when a seed is in use.
    pub(super) fn on_import_export(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let to = |menu| State::Menu { menu, page: 0 };
        match backup::target(self.scale, x, y)? {
            backup::Target::Nav(Nav::Home) => self.state = State::Home,
            backup::Target::Nav(_) => self.state = to(MenuId::Tools),
            backup::Target::Import => self.state = to(MenuId::Import),
            backup::Target::Export if self.slots.active().is_some() => {
                self.export_from = State::ImportExport;
                self.state = to(MenuId::Export)
            }
            backup::Target::Export => self.refuse(Refusal::NoWallet),
            backup::Target::Understand => {}
        }
        None
    }

    /// A list menu's rows.
    pub fn menu(&self, id: MenuId) -> &'static menu::Menu {
        match id {
            MenuId::Tools => &menu::TOOLS,
            MenuId::SeedTools => &menu::SEED_TOOLS,
            MenuId::Import => &menu::IMPORT,
            MenuId::ImportSd => &menu::IMPORT_SD,
            MenuId::Export => &menu::EXPORT,
            MenuId::SeedBackup => &menu::SEED_BACKUP,
            MenuId::QrExport => &menu::QR_EXPORT,
            MenuId::WatchOnly => &menu::WATCH_ONLY,
            MenuId::SigningKeys => &menu::SIGNING_KEYS,
            MenuId::SignMessage => &menu::SIGN_MESSAGE,
            MenuId::Multisig => &menu::MULTISIG,
            MenuId::StegoSource => &menu::DESCRIPTOR_SOURCE,
            MenuId::Settings => self.settings,
        }
    }

    /// A list menu's dimmed rows, as bits for [`menu::draw_dimmed`].
    pub fn dimmed(&self, id: MenuId) -> u32 {
        match id {
            MenuId::Multisig if self.group.is_none() => GROUP_ROWS,
            _ => 0,
        }
    }
}
