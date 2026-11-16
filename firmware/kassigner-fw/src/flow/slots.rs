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

//! Seeds and their slots: made or loaded, stored, opened and deleted.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    /// Start making a seed from every source the unit has.
    pub(super) fn start_seed(&mut self) -> Option<Command> {
        let mut have = [Source::Camera; 4];
        let mut n = 0;
        for s in self.sources.iter().flatten() {
            have[n] = *s;
            n += 1;
        }
        wipe::begin_depth(self.stack);
        self.collector = Some(Collector::new(&have[..n]));
        self.state = State::Generating;
        Some(Command::SamplesOn)
    }

    pub(super) fn on_seeds(&mut self, event: Event<'_>, page: usize) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let (rows, n) = self.seed_rows();
        let rows = &rows[..n];
        match seed_rows::target(self.scale, rows, N, page, x, y)? {
            seed_rows::Target::Nav(Nav::PageUp) => {
                self.state = State::Seeds {
                    page: page.saturating_sub(1),
                }
            }
            seed_rows::Target::Nav(Nav::PageDown) => self.state = State::Seeds { page: page + 1 },
            seed_rows::Target::Nav(_) => self.state = State::Home,
            // Export: the Export menu, for the seed in use.
            seed_rows::Target::Export if self.slots.active().is_some() => {
                self.export_from = State::Seeds { page };
                self.state = State::Menu {
                    menu: MenuId::Export,
                    page: 0,
                }
            }
            seed_rows::Target::Export => self.refuse(Refusal::NoWallet),
            // Dimmed and doing nothing while the seed in use is marked.
            seed_rows::Target::Address if self.in_use_unbacked() => {}
            seed_rows::Target::Address => self.open_address(State::Seeds { page }, false),
            seed_rows::Target::Row(r) => {
                let row = page * seed_rows::ROWS + r;
                match self.slot_of(row) {
                    Some(index) => self.use_slot(index),
                    // A `+`: to Tools, where seeds are made.
                    None => {
                        self.state = State::Menu {
                            menu: MenuId::Tools,
                            page: 0,
                        }
                    }
                }
            }
            seed_rows::Target::Delete(r) => {
                if let Some(index) = self.slot_of(page * seed_rows::ROWS + r) {
                    self.state = State::Deleting {
                        slot: index,
                        armed: false,
                        held_since: None,
                    };
                }
            }
        }
        None
    }

    /// Make a stored seed the one in use, opening its wallet
    /// ([`Flow::on_opening`]); one already in use is left as it is.
    pub(super) fn use_slot(&mut self, index: usize) {
        if self.slots.active().map(|(i, _)| i) == Some(index) && self.keys.is_some() {
            return;
        }
        if self.slots.activate(index).is_err() {
            self.refuse(Refusal::NotOpened);
            return;
        }
        self.keys = None;
        self.opening.zeroize();
        wipe::begin_depth(self.stack);
        self.state = State::Opening { slot: index };
    }

    /// One step of opening a wallet each tick: the seed first, the longest
    /// step, then a bank key at a time, each in a frame of its own, scrubbed
    /// after.
    pub(super) fn on_opening(&mut self, event: Event<'_>, index: usize) -> Option<Command> {
        let Event::Tick { .. } = event else {
            return None;
        };
        let stepped = open_step(&mut self.slots, index, &mut self.opening);
        wipe::scrub_flow();
        match stepped {
            Ok(Some(keys)) => {
                self.keys = Some(keys);
                // A new seed in use: the pump starts again.
                self.pumped = 0;
                // For SELECT SEED, its cosigner key is the group's next.
                if core::mem::take(&mut self.open_for_group) {
                    self.add_own_cosigner();
                } else {
                    self.state = State::Seeds {
                        page: self.row_of(index) / seed_rows::ROWS,
                    };
                }
            }
            Ok(None) => {}
            Err(_) => {
                self.opening.zeroize();
                self.keys = None;
                self.open_for_group = false;
                self.refuse(Refusal::NotOpened);
            }
        }
        None
    }

    /// Delete asks twice: a tap arms it, then a finger held for [`HOLD_US`]
    /// wipes the slot. Lifting or sliding off before then cancels.
    pub(super) fn on_deleting(
        &mut self,
        event: Event<'_>,
        index: usize,
        armed: bool,
        held_since: Option<u64>,
    ) -> Option<Command> {
        let cancel = State::Seeds { page: 0 };
        match self.hold(event, armed, held_since) {
            Hold::Nothing => {}
            Hold::Cancel => self.state = cancel,
            Hold::Home => self.state = State::Home,
            Hold::Arm => {
                self.state = State::Deleting {
                    slot: index,
                    armed: true,
                    held_since: None,
                }
            }
            Hold::Down => {
                self.state = State::Deleting {
                    slot: index,
                    armed,
                    held_since: Some(self.now_us),
                }
            }
            // Held for the time: the slot goes, and its wallet if in use.
            Hold::Done => {
                if self.slots.active().map(|(i, _)| i) == Some(index) {
                    self.keys = None;
                }
                self.slots.delete(index);
                self.unbacked[index] = false;
                self.state = cancel;
            }
        }
        None
    }

    pub(super) fn on_generating<E: Entropy + ?Sized>(
        &mut self,
        event: Event<'_>,
        rng: &mut E,
    ) -> Option<Command> {
        let seed_tools = State::Menu {
            menu: MenuId::SeedTools,
            page: 0,
        };
        let Some(col) = self.collector.as_mut() else {
            self.state = seed_tools;
            return Some(Command::SamplesOff);
        };
        match event {
            // Only the back button leaves: every other touch feeds the seed.
            Event::Tap { x, y } => {
                if !camera::back(self.scale).contains(x, y) {
                    return None;
                }
                self.collector = None;
                self.state = seed_tools;
                return Some(Command::SamplesOff);
            }
            Event::CameraSample(delta) => {
                col.absorb_camera(delta);
            }
            Event::ImuSample(samples) => {
                col.absorb_imu(samples);
            }
            Event::TouchMoved { x, y, since_us } => {
                col.absorb_touch(x, y, since_us);
            }
            // The seed is made from every source or not at all.
            Event::CameraLost => {
                self.collector = None;
                self.refuse(Refusal::NoCamera);
                return Some(Command::SamplesOff);
            }
            _ => return None,
        }
        if !col.is_enough() {
            return None;
        }
        // The generator last, credited nothing, then the seed.
        let mut scratch = [0u8; 64];
        let drawn = col.absorb_generator(rng, &mut scratch);
        let col = self.collector.take().expect("held above");
        if drawn.is_err() {
            drop(col);
            self.refuse(Refusal::NoEntropy);
            return Some(Command::SamplesOff);
        }
        // Its words, then the backup check, as for every seed made here.
        match col.finish(self.words) {
            Ok(m) => self.show_new_words(m, AfterWords::NewSeed),
            // Cannot happen after `is_enough`; taken as a failing generator.
            Err(_) => self.refuse(Refusal::NoEntropy),
        }
        Some(Command::SamplesOff)
    }

    pub(super) fn on_loading(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            // The passphrase next; the seed waits.
            dialog::Target::Accept => self.ask_passphrase(),
            // Cancelled: the words are dropped and wipe themselves.
            _ => {
                self.pending = None;
                self.state = State::Home;
            }
        }
        None
    }

    /// The passphrase's keyboard, empty, the first time, for the seed
    /// waiting in [`Flow::pending`].
    pub(super) fn ask_passphrase(&mut self) {
        self.typed.clear();
        self.first.clear();
        self.mismatch = false;
        self.state = State::Passphrase { page: 0 };
    }

    /// The passphrase, typed twice, as a backup's password is, so a key hit
    /// by mistake cannot open another wallet: OK with nothing typed stores
    /// the waiting seed with none; typed, the first OK asks for it `again`,
    /// and the second stores the seed only if both match; a mismatch starts
    /// both again. Back or Home drops the seed and both, wiped.
    pub(super) fn on_passphrase(
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
        let key = match target {
            keyboard::Target::Nav(_) => {
                self.pending = None;
                self.typed.clear();
                self.first.clear();
                self.mismatch = false;
                self.state = State::Home;
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
            keyboard::Key::Delete => self.typed.backspace(),
            keyboard::Key::Left => self.typed.left(),
            keyboard::Key::Right => self.typed.right(),
            keyboard::Key::Page => {
                let page = keyboard::next_page(page);
                self.state = if again {
                    State::PassphraseAgain { page }
                } else {
                    State::Passphrase { page }
                };
            }
            keyboard::Key::Ok if !again && !self.typed.is_empty() => {
                self.first = core::mem::take(&mut self.typed);
                self.state = State::PassphraseAgain { page };
            }
            keyboard::Key::Ok if again && self.typed.as_bytes() != self.first.as_bytes() => {
                self.typed.clear();
                self.first.clear();
                self.mismatch = true;
                self.state = State::Passphrase { page };
            }
            // Nothing typed the first time, or the same twice.
            keyboard::Key::Ok => {
                self.first.clear();
                let mut passphrase = core::mem::take(&mut self.typed);
                if let Some(mut m) = self.pending.take() {
                    self.store(&mut m, passphrase.as_bytes());
                } else {
                    self.state = State::Home;
                }
                passphrase.clear();
            }
        }
        None
    }

    /// What the keyboard has typed and its cursor, for drawing: never part
    /// of a [`Screen`], which is printed. Stego Import types into its
    /// descriptor.
    pub fn typed(&self) -> (&str, usize) {
        match self.state {
            State::StegoKey { .. } | State::StegoOldKey { .. } => {
                (self.desc.as_str(), self.desc.cursor())
            }
            _ => (self.typed.as_str(), self.typed.cursor()),
        }
    }

    /// Put a mnemonic in a slot with `passphrase` and open its wallet; the
    /// caller's copy is cleared. A refused store changes nothing.
    ///
    /// A seed made here whose check was put off goes in marked, unless
    /// already in a slot, which keeps what it had. Any other (loaded, or
    /// checked) has a backup, so it clears the same seed's mark.
    pub(super) fn store(&mut self, m: &mut Mnemonic, passphrase: &[u8]) {
        let held: [bool; N] = core::array::from_fn(|i| self.slots.get(i).is_ok());
        let later = core::mem::take(&mut self.made_later);
        match self.slots.store_mnemonic(m, passphrase) {
            Ok(index) => {
                if !later {
                    self.unbacked[index] = false;
                } else if !held[index] {
                    self.unbacked[index] = true;
                }
                self.use_slot_always(index)
            }
            Err(SlotError::Full) => self.refuse(Refusal::SlotsFull),
            Err(_) => self.refuse(Refusal::NotOpened),
        }
    }

    /// A seed read from outside, waiting for its passphrase. It came from a
    /// backup, so it goes in unmarked even if an earlier seed was put off.
    pub(super) fn hold_loaded(&mut self, m: Mnemonic) {
        self.made_later = false;
        self.pending = Some(m);
    }

    /// Open a slot's wallet even if in use: a seed stored again is reopened,
    /// recording its fingerprint.
    pub(super) fn use_slot_always(&mut self, index: usize) {
        self.keys = None;
        self.use_slot(index);
    }

    /// How many seeds the unit holds.
    pub fn seed_count(&self) -> usize {
        self.slots.count()
    }

    /// The seeds screen's row `row` (filled slots, in order): only public
    /// facts, a fingerprint and a kind.
    pub fn seed(&self, row: usize) -> Option<Seed> {
        let index = self.slot_of(row)?;
        let slot = self.slots.get(index).ok()?;
        let (kind, passphrase) = match slot {
            Slot::Mnemonic {
                mnemonic,
                passphrase,
            } => (
                if mnemonic.len() > 12 {
                    Kind::Words24
                } else {
                    Kind::Words12
                },
                !passphrase.is_empty(),
            ),
            Slot::Xprv(_) => (Kind::Xprv, false),
            Slot::RawKey(_) => (Kind::Key, false),
            Slot::Empty => return None,
        };
        Some(Seed {
            fingerprint: self.slots.fingerprint(index).unwrap_or([0; 4]),
            kind,
            passphrase,
            active: self.slots.active().map(|(i, _)| i) == Some(index),
            backed: !self.unbacked[index],
        })
    }

    /// The slot index behind row `row`.
    pub(super) fn slot_of(&self, row: usize) -> Option<usize> {
        (0..N)
            .filter(|&i| self.slots.get(i).is_ok_and(|s| !s.is_empty()))
            .nth(row)
    }

    /// The row a slot index shows as.
    pub(super) fn row_of(&self, index: usize) -> usize {
        (0..index)
            .filter(|&i| self.slots.get(i).is_ok_and(|s| !s.is_empty()))
            .count()
    }

    /// The seeds, as the seeds screen's rows, and how many.
    pub fn seed_rows(&self) -> ([Seed; N], usize) {
        let blank = Seed {
            fingerprint: [0; 4],
            kind: Kind::Key,
            passphrase: false,
            active: false,
            backed: true,
        };
        let mut rows = [blank; N];
        let mut n = 0;
        while let Some(seed) = self.seed(n) {
            rows[n] = seed;
            n += 1;
        }
        (rows, n)
    }
}

/// One step of opening slot `index`'s wallet, in a frame the scrub after it
/// can reach: the seed first, then one bank key per step (and the KCC-3
/// bank's, if any). When the bank is full, the keyring, the slot's
/// fingerprint recorded.
#[inline(never)]
pub(super) fn open_step<const N: usize>(
    slots: &mut Slots<N>,
    index: usize,
    opening: &mut Option<Opening>,
) -> Result<Option<Keyring>, StoreError> {
    let Some(o) = opening.as_mut() else {
        let slot: &Slot = slots.get(index).map_err(StoreError::Slot)?;
        let mut scratch = [0u8; 128];
        let wallet = Wallet::open(slot, &mut scratch).map_err(StoreError::Wallet);
        wipe::wipe(&mut scratch);
        let wallet = wallet?;
        // The chains' public keys once; every address comes from them.
        let chains = keyring::chain_keys(&wallet).map_err(StoreError::Keyring)?;
        let kcc3_chains = keyring::kcc3_chain_keys(&wallet).map_err(StoreError::Keyring)?;
        *opening = Some(Opening {
            wallet,
            chains,
            bank: [(Path::receive(0), [0u8; 32]); keyring::BANK],
            kcc3_chains,
            kcc3: [[0u8; 32]; keyring::KCC3_BANK],
            done: 0,
        });
        return Ok(None);
    };
    if o.done < keyring::BANK {
        o.bank[o.done] =
            keyring::bank_key(&o.wallet, o.chains.as_ref(), o.done).map_err(StoreError::Keyring)?;
        if let Some(c) = o.kcc3_chains.as_ref() {
            o.kcc3[o.done] = keyring::kcc3_bank_key(c, o.done).map_err(StoreError::Keyring)?;
        }
        o.done += 1;
        return Ok(None);
    }
    let Opening {
        wallet,
        chains,
        bank,
        kcc3_chains,
        kcc3,
        ..
    } = opening.take().expect("held above");
    // Clear the bytes the values were moved out of, the wallet's secret
    // among them, so the keyring holds the only copy.
    opening.zeroize();
    let mut keys = Keyring::from_bank(wallet, bank, chains);
    if let Some(c) = kcc3_chains {
        keys = keys.with_kcc3(kcc3, c);
    }
    // The flow searches past the bank itself, a window at a time.
    keys.set_search(false);
    slots
        .set_fingerprint(index, keys.wallet().fingerprint())
        .map_err(StoreError::Slot)?;
    Ok(Some(keys))
}
