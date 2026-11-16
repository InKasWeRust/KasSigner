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

//! A covenant card read from its backup line: SAVINGS CARD, its codes, and
//! its save to the SD card.
//!
//! The line, `savings_v1(...)`, is scanned on Home or read from a
//! `CVnnnn.TXT` file listed under either Covenant Restore. It is taken only
//! if it rebuilds its card and the card is the address it names
//! ([`kassigner_protocol::card::backup::read`]). Nothing in it is secret or
//! signs: the review reads a card from the request.
//!
//! The line names its keys, not their place in a seed: that is looked for
//! among the receive keys at hand as the card is read, then on a key's page
//! when asked, [`BATCH`] keys a tap, up to [`limits::SEARCH_DEPTH`]. The
//! keys derived are public and kept nowhere.

use super::*;

use crate::ui::savings::{self as savings_screen, Seen};
use kassigner_protocol::card::backup::{self as card_backup, BackupError as CardBackupError};
use kassigner_qr::encode::QrMatrix;

/// Whether `bytes` are a covenant card's backup line, by its name
/// (`savings_v1(`, a Time-Locked Savings card's). Whether the rest rebuilds
/// the card is found when it is read.
pub(super) fn is_card_backup(bytes: &[u8]) -> bool {
    bytes
        .trim_ascii()
        .starts_with(card_backup::SAVINGS_V1.as_bytes())
}

/// The card SAVINGS CARD shows, where its keys are in the seed in use, and
/// whether it came from a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct HeldCard {
    card: Savings,
    owner: Seen,
    recovery: Seen,
    file: bool,
}

impl HeldCard {
    /// Where the key on `page` is: the owner's on the second, the recovery
    /// wallet's on the third for a card with one; none on the first.
    fn on_page(&self, page: u8) -> Option<Seen> {
        match page {
            1 => Some(self.owner),
            2 if self.card.recovery().is_some() => Some(self.recovery),
            _ => None,
        }
    }
}

/// A key missed among the receive keys before `reach`: searchable past
/// them, or not in the seed at [`limits::SEARCH_DEPTH`], where every search
/// stops.
fn missed(reach: u32) -> Seen {
    if reach >= limits::SEARCH_DEPTH {
        Seen::NotFound
    } else {
        Seen::Missed(reach)
    }
}

/// The index of a receive key's path; `None` for any other.
fn receive_at(path: Path) -> Option<u32> {
    match path {
        Path::Single { index, .. } if path == Path::receive(index) => Some(index),
        _ => None,
    }
}

/// `seen` set to found at `at` if still missed and `key` is `wanted`.
fn hit(seen: &mut Seen, wanted: Option<&[u8; 32]>, (key, at): (&[u8; 32], u32)) {
    if matches!(seen, Seen::Missed(_)) && wanted == Some(key) {
        *seen = Seen::At(at);
    }
}

impl<'b, const N: usize> Flow<'b, N> {
    /// `text` read as a card's backup line, from a file when `file`: SAVINGS
    /// CARD on its first page, its keys' places in the seed in use found now
    /// so that no tap has work behind it.
    ///
    /// # Errors
    ///
    /// Why the line does not rebuild its card; nothing held changes.
    pub(super) fn take_card(&mut self, text: &[u8], file: bool) -> Result<(), CardBackupError> {
        let card = card_backup::read(text)?;
        self.savings = Some(HeldCard {
            card,
            owner: self.seen(card.owner()),
            recovery: card.recovery().map_or(Seen::NoSeed, |k| self.seen(k)),
            file,
        });
        self.state = State::Savings { page: 0 };
        Ok(())
    }

    /// Where `key` is among the seed in use's receive keys at hand, nothing
    /// derived: the bank's and a request's search's, as the review's YOURS
    /// looks, then the idle pump's run past the bank. Not among them, it is
    /// missed as far as those reach. A raw key has one key at one place, and
    /// nothing past it to search.
    fn seen(&self, key: &[u8; 32]) -> Seen {
        let Some(keys) = self.keys.as_ref() else {
            return Seen::NoSeed;
        };
        if !keys.has_chains() {
            return keys
                .address_key(Path::receive(0))
                .ok()
                .filter(|k| k == key)
                .map_or(Seen::NotFound, |_| Seen::At(0));
        }
        if let Some(i) = keys.receive_index(key) {
            return Seen::At(i);
        }
        // The pump derives in the sweep's order, a window of receive keys,
        // then one of change, and on: its receive keys run unbroken from the
        // bank's end.
        let mut reach = limits::RECEIVE_DEPTH;
        for (i, pumped) in self.buffers.pump[..self.pumped].iter().enumerate() {
            let Some(index) = keyring::sweep_path(i).and_then(receive_at) else {
                continue;
            };
            if pumped == key {
                return Seen::At(index);
            }
            reach = reach.max(index + 1);
        }
        missed(reach)
    }

    /// A scanned line: SAVINGS CARD, or the ERROR screen saying why not.
    pub(super) fn scanned_card(&mut self, text: &[u8]) {
        if let Err(e) = self.take_card(text, false) {
            self.refuse(Refusal::CardBackup(e));
        }
    }

    /// A card file's text: the delete asked, SAVINGS CARD, or why not under
    /// Card Load Failed.
    pub(super) fn card_text(&mut self, text: &[u8]) {
        if self.deleting {
            self.state = State::RestoreDelete {
                page: 0,
                armed: false,
                held_since: None,
            };
            return;
        }
        if let Err(e) = self.take_card(text, true) {
            self.restore_failed(refusals::card_backup(e));
        }
    }

    /// SAVINGS CARD at `page`: the arrows turn pages; the address on the
    /// first is its code; Save to SD saves the line and comes back; Show QR
    /// is SAVINGS CARD QR. Back is the list for a card from a file, else
    /// home; leaving lets the card go. A tap counts only when pressed and
    /// lifted on its target.
    pub(super) fn on_savings(
        &mut self,
        event: Event<'_>,
        page: u8,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        use savings_screen::Target;
        let Event::Tap { x, y } = event else {
            return None;
        };
        let Some(held) = self.savings else {
            self.state = State::Home;
            return None;
        };
        let pages = savings_screen::pages(held.card.recovery().is_some());
        let at = (usize::from(page), held.file);
        match tapped(pressed_at, (x, y), |x, y| {
            savings_screen::target(self.scale, at, x, y)
        })? {
            Target::Nav(nav) => self.card_nav(nav, held.file),
            Target::Previous if page > 0 => self.state = State::Savings { page: page - 1 },
            Target::Next if usize::from(page) + 1 < pages => {
                self.state = State::Savings { page: page + 1 }
            }
            Target::Previous | Target::Next => {}
            Target::Address => self.state = State::SavingsAddressQr,
            Target::Save => return self.start_saving(Saving::Card, State::Savings { page }),
            Target::Show => self.state = State::SavingsFormat { page },
            Target::Search => {
                if let Some(Seen::Missed(from)) = held.on_page(page) {
                    let stop = from.saturating_add(BATCH as u32);
                    self.state = State::SavingsSearching {
                        page,
                        next: from,
                        stop: stop.min(limits::SEARCH_DEPTH),
                    };
                }
            }
        }
        None
    }

    /// SAVINGS CARD searching the seed in use's receive keys from `next` to
    /// `stop` for the key on `page`: [`SEARCH_PER_TICK`] a tick, each
    /// compared with both card keys still missed. It ends at `stop` or once
    /// the page's key is found, back on the page, a key still missed marked
    /// missed as far as it went, or not in the seed at
    /// [`limits::SEARCH_DEPTH`]. Only Back and Home act meanwhile, as on the
    /// page.
    pub(super) fn on_savings_searching(
        &mut self,
        event: Event<'_>,
        (page, next, stop): (u8, u32, u32),
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        use savings_screen::Target;
        let Some(mut held) = self.savings else {
            self.state = State::Home;
            return None;
        };
        match event {
            Event::Tap { x, y } => {
                let at = (usize::from(page), held.file);
                let tap = tapped(pressed_at, (x, y), |x, y| {
                    savings_screen::target(self.scale, at, x, y)
                });
                if let Some(Target::Nav(nav)) = tap {
                    self.card_nav(nav, held.file);
                }
            }
            Event::Tick { .. } => {
                let Some(keys) = self.keys.as_ref() else {
                    self.leave_card(State::Home);
                    return None;
                };
                let found = |held: &HeldCard| matches!(held.on_page(page), Some(Seen::At(_)));
                let mut next = next;
                for _ in 0..SEARCH_PER_TICK {
                    if next >= stop || found(&held) {
                        break;
                    }
                    let Ok(key) = keys.address_key(Path::receive(next)) else {
                        self.savings = None;
                        self.refuse(Refusal::NotDerived);
                        return None;
                    };
                    let card = held.card;
                    hit(&mut held.owner, Some(card.owner()), (&key, next));
                    hit(&mut held.recovery, card.recovery(), (&key, next));
                    next += 1;
                }
                if next >= stop || found(&held) {
                    for seen in [&mut held.owner, &mut held.recovery] {
                        if let Seen::Missed(_) = seen {
                            *seen = missed(next);
                        }
                    }
                    self.state = State::Savings { page };
                } else {
                    self.state = State::SavingsSearching { page, next, stop };
                }
                self.savings = Some(held);
            }
            _ => {}
        }
        None
    }

    /// SAVINGS CARD's Back or Home: the card let go, then home, or the list
    /// for Back on a card from a file.
    fn card_nav(&mut self, nav: Nav, file: bool) {
        match nav {
            Nav::Home => self.leave_card(State::Home),
            _ if file => self.leave_card(State::RestoreList { page: 0 }),
            _ => self.leave_card(State::Home),
        }
    }

    /// The card let go, and `to`: from SAVINGS CARD, and from Home on a
    /// save's ENCRYPT FILE? or overwrite question.
    pub(super) fn leave_card(&mut self, to: State) {
        self.savings = None;
        self.state = to;
    }

    /// SAVINGS CARD's view of the held card, its addresses (the card's, the
    /// owner's, the recovery wallet's) written into `out`; `None` with no card
    /// held.
    pub fn savings_shown<'o>(
        &self,
        out: &'o mut savings_screen::Texts,
    ) -> Option<savings_screen::Shown<'o>> {
        let held = self.savings?;
        let key = |key: &[u8; 32], out: &'o mut [u8; MAX_ADDRESS_LEN]| {
            let n = kaspa_address::encode(Prefix::Mainnet, Version::PubKey, key, out).ok()?;
            let out: &'o [u8] = out;
            core::str::from_utf8(&out[..n]).ok()
        };
        let [card, owner, recovery] = out;
        let n = held.card.address(card).ok()?;
        let card: &'o [u8] = card;
        let recovery = match held.card.recovery() {
            Some(k) => Some(key(k, recovery)?),
            None => None,
        };
        // A key still missed while a search runs is being searched for:
        // both are looked for in every key derived.
        let seen = |s: Seen| match (s, self.state) {
            (Seen::Missed(_), State::SavingsSearching { next, .. }) => Seen::Searching(next),
            _ => s,
        };
        Some(savings_screen::Shown {
            address: core::str::from_utf8(&card[..n]).ok()?,
            unlock: held.card.unlock().ms(),
            owner: key(held.card.owner(), owner)?,
            recovery,
            owner_seen: seen(held.owner),
            recovery_seen: seen(held.recovery),
            file: held.file,
        })
    }

    /// The card held's address as its code, one code. For drawing.
    pub fn savings_address_code(&self) -> Option<QrMatrix> {
        let held = self.savings?;
        let mut text = [0u8; MAX_ADDRESS_LEN];
        let n = held.card.address(&mut text).ok()?;
        kassigner_qr::encode::encode(&text[..n]).ok()
    }

    /// How many codes the held card's line takes for a wallet or a unit: one
    /// if it fits, else its frames; 0 with no card held.
    pub fn savings_codes(&self, wallet: bool) -> usize {
        let mut text = [0u8; card_backup::MAX_LEN];
        self.card_line(&mut text)
            .map_or(0, |n| message_codes(n, wallet))
    }

    /// The line's code for frame `frame`: one code if it fits, which any
    /// wallet reads, or `Format::Opaque` frames, version 9 for a wallet,
    /// version 3 for a unit, whose home scanner takes the line from them.
    /// Written from the held card as drawn.
    pub fn savings_frame(&self, frame: u8) -> Option<QrMatrix> {
        use kassigner_qr::encode::encode;
        let mut text = [0u8; card_backup::MAX_LEN];
        let n = self.card_line(&mut text)?;
        if self.card_frames <= 1 {
            return encode(&text[..n]).ok();
        }
        let mut buf = [0u8; frame::FIRST_HEADER_LEN + card_backup::MAX_LEN];
        let m = frame::write_split(
            Format::Opaque,
            &text[..n],
            frame,
            self.card_frames,
            &mut buf,
        )
        .ok()?;
        frame_code(&buf[..m], self.wallet_frames)
    }

    /// SAVINGS CARD QR, as DESCRIPTOR QR: Wallet shows one code, or
    /// version-9 frames past it; KasSigner version-3 frames; Auto Cycle or
    /// Manual asked when there are several. Back is SAVINGS CARD at `page`;
    /// Home lets the card go.
    pub(super) fn on_savings_format(&mut self, event: Event<'_>, page: u8) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let wallet = match kpub_screen::target(self.scale, x, y)? {
            kpub_screen::Target::Nav(Nav::Home) => {
                self.leave_card(State::Home);
                return None;
            }
            kpub_screen::Target::Nav(_) => {
                self.state = State::Savings { page };
                return None;
            }
            kpub_screen::Target::Wallet => true,
            kpub_screen::Target::KasSigner => false,
        };
        self.wallet_frames = wallet;
        self.frame_us = if wallet {
            limits::WALLET_FRAME_US
        } else {
            limits::KASSIGNER_FRAME_US
        };
        match u8::try_from(self.savings_codes(wallet)) {
            Ok(0) => self.leave_card(State::Home),
            Ok(1) => {
                self.card_frames = 1;
                self.show_card_line(page);
            }
            Ok(f) => {
                self.card_frames = f;
                self.state = State::SavingsMode { page };
            }
            Err(_) => self.refuse(Refusal::TooLong),
        }
        None
    }

    /// QR DISPLAY MODE for the line's frames.
    pub(super) fn on_savings_mode(
        &mut self,
        event: Event<'_>,
        page: u8,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.leave_card(State::Home),
            dialog::Target::Nav(_) => self.state = State::SavingsFormat { page },
            dialog::Target::Cancel => {
                self.manual = false;
                self.show_card_line(page);
            }
            dialog::Target::Accept => {
                self.manual = true;
                self.show_card_line(page);
            }
        }
        None
    }

    /// The line from its first frame.
    fn show_card_line(&mut self, page: u8) {
        self.frame_since = self.now_us;
        self.state = State::SavingsFrames { page, frame: 0 };
    }

    /// The line shown, as a descriptor is: Auto Cycle or a tap at a time; a
    /// tap on one code, on cycling frames, or past the last is SAVINGS CARD
    /// at `page` again.
    pub(super) fn on_savings_frames(
        &mut self,
        event: Event<'_>,
        page: u8,
        frame: u8,
    ) -> Option<Command> {
        let frames = self.card_frames;
        match event {
            Event::Tick { now_us } if !self.manual => {
                if let Some(next) = self.turn(now_us, frame, frames) {
                    self.state = State::SavingsFrames { page, frame: next };
                }
            }
            Event::Tap { .. } if self.manual && frame + 1 < frames => {
                self.state = State::SavingsFrames {
                    page,
                    frame: frame + 1,
                };
            }
            Event::Tap { .. } => self.state = State::Savings { page },
            _ => {}
        }
        None
    }

    /// The held card's line into `out`, as its file holds it; its length, or
    /// `None` with no card held or `out` too small.
    pub(super) fn card_line(&self, out: &mut [u8]) -> Option<usize> {
        let held = self.savings?;
        card_backup::write(&held.card, out).ok()
    }
}

// A line fits, sealed, the part of the request's buffer a card file is read
// into, and plain, the descriptor's room it is written from.
const _: () = assert!(
    kassigner_protocol::container::file_size(card_backup::MAX_LEN) <= GROUP_FILE_MAX,
    "a card's line, sealed, is read"
);
const _: () = assert!(
    card_backup::MAX_LEN <= DESCRIPTOR_FILE_MAX,
    "a card's line is written"
);
