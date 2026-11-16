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

//! Multisig groups: made key by key, held, and their descriptor shown and
//! exported.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    /// CREATE MULTISIG: "-" and "+" step M (1 to N) or N (1 to
    /// [`limits::MAX_MULTISIG_KEYS`]); N below M takes M down. NEXT starts
    /// the group at KEY 1/N.
    pub(super) fn on_create_multisig(&mut self, event: Event<'_>, m: u8, n: u8) -> Option<Command> {
        use multisig_screen::{Row, Target};
        let Event::Tap { x, y } = event else {
            return None;
        };
        let (m, n) = match multisig_screen::target(self.scale, x, y)? {
            Target::Nav(Nav::Home) => {
                self.state = State::Home;
                return None;
            }
            Target::Nav(_) => {
                self.state = MULTISIG_MENU;
                return None;
            }
            Target::Next => {
                self.forming = Some(Forming::new(m, n));
                self.state = State::AddKey;
                return None;
            }
            Target::Minus(Row::Required) => (m.saturating_sub(1).max(1), n),
            Target::Plus(Row::Required) => ((m + 1).min(n), n),
            Target::Minus(Row::Total) => {
                let n = n.saturating_sub(1).max(1);
                (m.min(n), n)
            }
            Target::Plus(Row::Total) => (m, (n + 1).min(limits::MAX_MULTISIG_KEYS as u8)),
        };
        self.state = State::CreateMultisig { m, n };
        None
    }

    /// KEY k/N: a key scanned, from a seed held, or from the card. Back
    /// removes the last key, or at the first returns to CREATE MULTISIG;
    /// Home leaves the group.
    pub(super) fn on_add_key(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let Some(forming) = self.forming.as_mut() else {
            self.state = State::Home;
            return None;
        };
        let (key, of) = (usize::from(forming.added) + 1, usize::from(forming.total));
        let rows = multisig_screen::add_key(key, of);
        match menu::target(self.scale, &rows, 0, x, y)? {
            menu::Target::Nav(Nav::Home) => self.state = State::Home,
            menu::Target::Nav(Nav::Back) if forming.added == 0 => {
                self.state = State::CreateMultisig {
                    m: forming.required,
                    n: forming.total,
                };
                self.forming = None;
            }
            menu::Target::Nav(Nav::Back) => forming.drop_last(),
            menu::Target::Item(0) => self.state = State::CosignerKey,
            // Use Loaded Seed, if there is a seed to pick.
            menu::Target::Item(1) if self.slots.count() == 0 => self.refuse(Refusal::NoWallet),
            menu::Target::Item(1) => self.state = State::SelectSeed { page: 0 },
            // Load kpub from SD: the card's cosigner kpubs, listed.
            menu::Target::Item(2) => {
                self.listing = Listing::Cosigners;
                self.backup_name = self.list_pattern();
                self.card_exit = State::AddKey;
                self.state = State::CardBusy(Job::List);
                return Some(Command::Card(Job::List));
            }
            menu::Target::Nav(_) | menu::Target::Item(_) => {}
        }
        None
    }

    /// DESCRIPTOR: Save to SD (`MDnnnn.TXT`) or Show QR; Back is MULTISIG.
    pub(super) fn on_descriptor(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match dialog::target(self.scale, x, y)? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Nav(_) => self.state = MULTISIG_MENU,
            dialog::Target::Accept => self.state = State::DescriptorFormat,
            dialog::Target::Cancel => {
                return self.start_saving(Saving::Descriptor, State::Descriptor)
            }
        }
        None
    }

    /// The held group's descriptor file into `out`, returning its length:
    /// v1.0.7's comment line (`# KasSigner multisig, 45' coordinated,
    /// 2-of-3`), which readers skip, ours and v1.0.7's, then the descriptor.
    /// `None` with no group or too small an `out`.
    pub(super) fn descriptor_file(&self, out: &mut [u8]) -> Option<usize> {
        use crate::ui::camera::Part;
        let group = self.group.as_ref()?;
        let mut head = [0u8; DESCRIPTOR_HEAD_MAX];
        let mut k = Part::Text(DESCRIPTOR_COMMENT).write(&mut head, 0);
        k = Part::Number(group.required()).write(&mut head, k);
        k = Part::Text("-of-").write(&mut head, k);
        k = Part::Number(group.total()).write(&mut head, k);
        k = Part::Text("\n").write(&mut head, k);
        out.get_mut(..k)?.copy_from_slice(&head[..k]);
        let n = group.write_descriptor(out.get_mut(k..)?).ok()?;
        Some(k + n)
    }

    /// The descriptor's length, for its codes: with fewer than ten keys
    /// `max_len` is exact, so no key's text is made to know it.
    pub(super) fn descriptor_len(&self) -> usize {
        self.group
            .as_ref()
            .map_or(0, |g| kassigner_protocol::descriptor::max_len(g.total()))
    }

    /// How many codes the descriptor takes, for a wallet or another unit:
    /// one if it fits, else its frames.
    pub fn descriptor_codes(&self, wallet: bool) -> usize {
        match self.descriptor_len() {
            0 => 0,
            len => message_codes(len, wallet),
        }
    }

    /// Whether the descriptor's frames are no more than a reader
    /// reassembles; a card past it is dimmed and does nothing.
    pub fn descriptor_fits(&self, wallet: bool) -> bool {
        self.descriptor_codes(wallet) <= self.profile.max_frames
    }

    /// The descriptor's code for frame `frame`, for drawing: its bare text if
    /// it fits one code (any wallet reads that), else `Format::Descriptor`
    /// frames.
    pub fn descriptor_frame(&self, frame: u8) -> Option<kassigner_qr::encode::QrMatrix> {
        use kassigner_protocol::frame;
        use kassigner_qr::encode::encode;
        const MAX: usize = kassigner_protocol::descriptor::max_len(limits::MAX_MULTISIG_KEYS);
        let mut text = [0u8; MAX];
        let n = self.group.as_ref()?.write_descriptor(&mut text).ok()?;
        if self.desc_frames <= 1 {
            return encode(&text[..n]).ok();
        }
        let mut buf = [0u8; frame::FIRST_HEADER_LEN + MAX];
        let m = frame::write_split(
            Format::Descriptor,
            &text[..n],
            frame,
            self.desc_frames,
            &mut buf,
        )
        .ok()?;
        frame_code(&buf[..m], self.wallet_frames)
    }

    /// DESCRIPTOR QR: Wallet in version-9 frames or KasSigner in version-3
    /// ones, QR DISPLAY MODE for more than one code. A card past what a
    /// reader reassembles does nothing.
    pub(super) fn on_descriptor_format(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let wallet = match kpub_screen::target(self.scale, x, y)? {
            kpub_screen::Target::Nav(Nav::Home) => {
                self.state = State::Home;
                return None;
            }
            kpub_screen::Target::Nav(_) => {
                self.state = State::Descriptor;
                return None;
            }
            kpub_screen::Target::Wallet => true,
            kpub_screen::Target::KasSigner => false,
        };
        if !self.descriptor_fits(wallet) {
            return None;
        }
        self.wallet_frames = wallet;
        self.frame_us = if wallet {
            limits::WALLET_FRAME_US
        } else {
            limits::KASSIGNER_FRAME_US
        };
        match u8::try_from(self.descriptor_codes(wallet)) {
            Ok(0) => self.state = MULTISIG_MENU,
            Ok(1) => {
                self.desc_frames = 1;
                self.show_descriptor();
            }
            Ok(f) => {
                self.desc_frames = f;
                self.state = State::DescriptorMode;
            }
            Err(_) => self.refuse(Refusal::TooLong),
        }
        None
    }

    /// QR DISPLAY MODE for the descriptor's frames.
    pub(super) fn on_descriptor_mode(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Nav(_) => self.state = State::DescriptorFormat,
            dialog::Target::Cancel => {
                self.manual = false;
                self.show_descriptor();
            }
            dialog::Target::Accept => {
                self.manual = true;
                self.show_descriptor();
            }
        }
        None
    }

    /// The descriptor from its first frame.
    pub(super) fn show_descriptor(&mut self) {
        self.frame_since = self.now_us;
        self.state = State::DescriptorFrames { frame: 0 };
    }

    /// The descriptor shown: Auto Cycle turns its frames on the clock, Manual
    /// a tap at a time. A tap in Auto Cycle, or on the last frame, is
    /// DESCRIPTOR.
    pub(super) fn on_descriptor_frames(&mut self, event: Event<'_>, frame: u8) -> Option<Command> {
        let frames = self.desc_frames;
        match event {
            Event::Tick { now_us } if !self.manual => {
                if let Some(next) = self.turn(now_us, frame, frames) {
                    self.state = State::DescriptorFrames { frame: next };
                }
            }
            Event::Tap { .. } if self.manual && frame + 1 < frames => {
                self.state = State::DescriptorFrames { frame: frame + 1 };
            }
            Event::Tap { .. } => self.state = State::Descriptor,
            _ => {}
        }
        None
    }

    /// Watch-Only's row `row`, on the tick after its tap: the seed's kpub
    /// (row 2: its cosigner kpub) shown, or for row 1 saved. Refused without
    /// a seed that has one.
    pub(super) fn kpub_row(&mut self, row: usize) -> Option<Command> {
        if !self.backed_or_refuse() {
            return None;
        }
        let key = if row == 2 {
            KpubKey::Cosigner
        } else {
            KpubKey::Single
        };
        if let Err(why) = self.make_kpub(key) {
            self.refuse(why);
        } else if row == 1 {
            return self.start_saving(Saving::Kpub(key), self.kpub_exit);
        } else {
            self.state = State::KpubFormat;
        }
        None
    }

    /// SELECT SEED: the seed tapped is put in use (opened if need be) and its
    /// cosigner key, worked out on the next tick, is the group's next.
    pub(super) fn on_select_seed(&mut self, event: Event<'_>, page: usize) -> Option<Command> {
        use seed_rows::Pick;
        let Event::Tap { x, y } = event else {
            return None;
        };
        let n = self.slots.count();
        match seed_rows::pick_target(self.scale, n, page, x, y)? {
            Pick::Nav(Nav::Home) => self.state = State::Home,
            Pick::Nav(Nav::PageUp) => {
                self.state = State::SelectSeed {
                    page: page.saturating_sub(1),
                }
            }
            Pick::Nav(Nav::PageDown) => self.state = State::SelectSeed { page: page + 1 },
            Pick::Nav(Nav::Back) => self.state = State::AddKey,
            Pick::Row(r) => {
                if let Some(index) = self.slot_of(page * seed_rows::ROWS + r) {
                    let in_use = self.slots.active().map(|(i, _)| i) == Some(index);
                    if in_use && self.keys.is_some() {
                        return self.defer(Work::OwnCosigner);
                    } else {
                        self.use_slot(index);
                        self.open_for_group = matches!(self.state, State::Opening { .. });
                    }
                }
            }
        }
        None
    }

    /// The seed in use's cosigner key, `m/45'/111111'/0'`, as the group's
    /// next. A raw key or an account xprv has none and is refused.
    pub(super) fn add_own_cosigner(&mut self) {
        if !self.backed_or_refuse() {
            return;
        }
        let Some(Wallet::Hd {
            multisig: Some(account),
            ..
        }) = self.keys.as_ref().map(|k| k.wallet())
        else {
            self.refuse(Refusal::NoCosignerKey);
            return;
        };
        wipe::begin_depth(self.stack);
        let public = public_of(account);
        wipe::scrub_flow();
        let from = self
            .slots
            .active()
            .and_then(|(i, _)| self.slots.fingerprint(i));
        self.add_cosigner(public, from);
    }

    /// COSIGNER KEY: SCAN opens the camera; CANCEL and Back return to KEY
    /// k/N.
    pub(super) fn on_cosigner_key(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Accept => {
                self.progress = (0, 0);
                self.received = 0;
                self.seed_or_frame = None;
                self.seed_hint = false;
                self.state = State::Scanning;
                return Some(Command::CameraOn);
            }
            dialog::Target::Nav(_) | dialog::Target::Cancel => self.state = State::AddKey,
        }
        None
    }

    /// What the scanner read while a group wants keys: a kpub (v1.0.7's or
    /// v1.1.0's frames too) is its next key ([`Flow::add_cosigner`]);
    /// anything else is refused.
    pub(super) fn take_cosigner(&mut self, bytes: &[u8]) {
        let Some(forming) = self.forming.as_mut() else {
            self.state = State::Home;
            return;
        };
        if forming.complete() {
            return;
        }
        match crate::kpub::read(bytes) {
            Some(key) => self.add_cosigner(key, None),
            None => self.refuse(Refusal::NotAKpub),
        }
    }

    /// `key` as the group's next, `from` the fingerprint of its seed if the
    /// unit holds it; a repeated key is refused. The last key makes the group
    /// in rusty-kaspa's order, replacing any held, its keys' seeds kept.
    pub(super) fn add_cosigner(&mut self, key: ExtendedPublicKey, from: Option<[u8; 4]>) {
        let Some(forming) = self.forming.as_mut() else {
            self.state = State::Home;
            return;
        };
        if forming.holds(&key) {
            self.refuse(Refusal::KeyAdded);
            return;
        }
        forming.add(key, from);
        if !forming.complete() {
            self.state = State::AddKey;
            return;
        }
        let made = HeldGroup::new(forming.required(), forming.keys());
        let forming = self.forming.take();
        match (made, forming) {
            (Ok(group), Some(forming)) => {
                self.group_from = [None; limits::MAX_MULTISIG_KEYS];
                for (seed, key) in self.group_from.iter_mut().zip(group.keys()) {
                    *seed = forming.seed_of(key);
                }
                self.group = Some(group);
                // What was kept was the last group's.
                self.branches.clear();
                self.state = MULTISIG_MENU;
            }
            _ => self.refuse(Refusal::GroupNotMade),
        }
    }

    /// A group being made is dropped once the unit is home. A refusal while
    /// it wants keys returns to KEY k/N ([`Flow::home`]), so only Home drops
    /// it.
    pub(super) fn keep_forming(&mut self) {
        if self.state == State::Home && self.adding_keys() {
            self.forming = None;
        }
    }

    /// The group the unit holds, if one has been made.
    pub fn group(&self) -> Option<&HeldGroup> {
        self.group.as_ref()
    }

    /// The held group's key at position `i`, as a kpub's text, into `out`.
    pub fn group_key_text<'o>(&self, i: usize, out: &'o mut [u8]) -> Option<&'o str> {
        let key = self.group.as_ref()?.keys().get(i)?;
        let n = key.to_text(KeyPrefix::Kpub, out).ok()?;
        core::str::from_utf8(&out[..n]).ok()
    }

    /// The fingerprint of the seed the group's key `i` came from, if the
    /// unit holds it.
    pub fn group_seed(&self, i: usize) -> Option<[u8; 4]> {
        self.group.as_ref()?;
        self.group_from.get(i).copied().flatten()
    }

    /// KEY k/N's and SELECT SEED's `k` and `N`: the next key's number, and
    /// how many the group will have.
    pub(super) fn next_key(&self) -> (u8, u8) {
        self.forming
            .as_ref()
            .map_or((1, 1), |f| ((f.added + 1).min(f.total), f.total))
    }

    /// The position in the held group of the seed in use's cosigner key,
    /// `m/45'/111111'/0'`: the cosigner index its addresses are derived at.
    pub fn group_position(&self) -> Option<usize> {
        self.position_in(self.group.as_ref()?)
    }

    /// [`Flow::group_position`] in `group`.
    pub(super) fn position_in(&self, group: &HeldGroup) -> Option<usize> {
        let Wallet::Hd {
            multisig: Some(account),
            ..
        } = self.keys.as_ref()?.wallet()
        else {
            return None;
        };
        wipe::begin_depth(self.stack);
        let public = public_of(account);
        wipe::scrub_flow();
        group.position(&public)
    }

    /// The group being made: its M of N and the keys added so far.
    pub fn forming(&self) -> Option<&Forming> {
        self.forming.as_ref()
    }

    /// Whether the group being made still wants keys: a refusal then
    /// returns to KEY k/N.
    pub(super) fn adding_keys(&self) -> bool {
        self.forming.as_ref().is_some_and(|f| !f.complete())
    }
}
