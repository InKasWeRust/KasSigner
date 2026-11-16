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

//! Signing Keys: the master key, an account's kprv, a raw key imported, and
//! each wiped once its screens are left.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    /// Signing Keys' kprv Master: the master key `m`, from the words (the
    /// BIP39 stretch, next tick) or a master xprv. Refused for an account
    /// xprv or a raw key, which have no `m`, and with no seed in use.
    pub(super) fn open_master(&mut self) {
        if !self.backed_or_refuse() {
            return;
        }
        match self.slots.active() {
            Some((_, Slot::Mnemonic { .. })) => self.state = State::KprvDeriving,
            Some((_, Slot::Xprv(k))) if k.depth() == 0 => self.state = State::KprvDeriving,
            Some(_) => self.refuse(Refusal::NoPhrase),
            None => self.refuse(Refusal::NoWallet),
        }
    }

    /// The tick after kprv Master's DERIVING is up: the master key as text.
    pub(super) fn on_kprv_deriving(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tick { .. } = event else {
            return None;
        };
        let made = match self.slots.active() {
            Some((_, slot)) => {
                wipe::begin_depth(self.stack);
                let made = master_text(slot, &mut self.key_text);
                wipe::scrub_flow();
                made
            }
            None => Err(Refusal::NoWallet),
        };
        match made {
            Ok(n) => {
                self.key_len = n;
                self.state = State::Kprv { master: true };
            }
            Err(why) => self.refuse(why),
        }
        None
    }

    /// Signing Keys' kprv Account: the wallet's single-signature account,
    /// `m/44'/111111'/0'`, as text. A raw key has none.
    pub(super) fn open_account(&mut self) {
        if !self.backed_or_refuse() {
            return;
        }
        let Some(keys) = self.keys.as_ref() else {
            self.refuse(Refusal::NoWallet);
            return;
        };
        wipe::begin_depth(self.stack);
        let made = account_text(keys.wallet(), &mut self.key_text);
        wipe::scrub_flow();
        match made {
            Ok(n) => {
                self.key_len = n;
                self.state = State::Kprv { master: false };
            }
            Err(why) => self.refuse(why),
        }
    }

    /// A kprv's text: a tap on it for its code; Back to Signing Keys.
    pub(super) fn on_kprv(&mut self, event: Event<'_>, master: bool) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match address_screen::target(self.scale, true, true, x, y)? {
            address_screen::Target::Nav(Nav::Home) => self.state = State::Home,
            address_screen::Target::Nav(_) => {
                self.state = State::Menu {
                    menu: MenuId::SigningKeys,
                    page: 0,
                }
            }
            address_screen::Target::Address => self.state = State::KprvQr { master },
            _ => {}
        }
        None
    }

    /// Import Raw Key's keyboard: hex digits, lower case as rusty-kaspa
    /// writes a key; OK at 64. Back or Home wipes the text.
    pub(super) fn on_raw_key(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let mode = Typing::RawKey.mode(self.typed.len());
        let key = match keyboard::target(self.scale, keyboard::HEX_PAGE, mode, x, y)? {
            keyboard::Target::Nav(nav) => {
                self.typed.clear();
                self.state = match nav {
                    Nav::Home => State::Home,
                    _ => State::Menu {
                        menu: MenuId::Import,
                        page: 0,
                    },
                };
                return None;
            }
            keyboard::Target::Chip(_) => return None,
            keyboard::Target::Key(key) => key,
        };
        match key {
            keyboard::Key::Char(c) => {
                self.typed.insert(c.to_ascii_lowercase());
            }
            // The key's address on the tick after the tap.
            keyboard::Key::Ok => return self.defer(Work::RawKey),
            _ => self.edit(key, keyboard::HEX_PAGE, |_| State::RawKey),
        }
        None
    }

    /// OK on the typed key: not a key, zero or past the curve's order is
    /// refused and the text wiped; else held and its address shown to
    /// confirm, the text kept for a typo. Read and multiplied in a frame of
    /// its own, scrubbed after.
    pub(super) fn import_raw_key(&mut self) {
        wipe::begin_depth(self.stack);
        let public = raw_key_into(self.typed.as_bytes(), &mut self.raw_key);
        wipe::scrub_flow();
        let Some(public) = public else {
            self.typed.clear();
            return self.refuse(Refusal::NotAKey);
        };
        self.address_of(&public);
        self.state = State::RawKeyConfirm;
    }

    /// The key's address answered: IMPORT stores and uses it; Cancel or Back
    /// returns to the text; Home drops it. A touch in the first
    /// [`SETTLE_US`] answers nothing.
    pub(super) fn on_raw_key_confirm(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        if self.too_soon() {
            return None;
        }
        let answer = tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))?;
        let key = self.raw_key.take();
        self.addr_len = 0;
        match answer {
            dialog::Target::Accept => {
                self.typed.clear();
                if let Some(key) = key {
                    self.store_raw_key(key);
                }
            }
            dialog::Target::Nav(Nav::Home) => {
                self.typed.clear();
                self.state = State::Home;
            }
            _ => self.state = State::RawKey,
        }
        None
    }

    /// A raw key into a slot and in use, as a seed is.
    pub(super) fn store_raw_key(&mut self, key: RawKey) {
        match self.slots.store(Slot::RawKey(key)) {
            Ok(index) => self.use_slot_always(index),
            Err(SlotError::Full) => self.refuse(Refusal::SlotsFull),
            Err(_) => self.refuse(Refusal::NotOpened),
        }
    }

    /// Whether a Signing Keys screen is up, the ones its key is held for.
    pub(super) const fn showing_key(&self) -> bool {
        match self.state {
            State::Kprv { .. } | State::KprvQr { .. } => true,
            State::Address | State::AddressQr | State::AddressIndex => self.addr_key,
            _ => false,
        }
    }

    /// Wipe Signing Keys' key once none of its screens is up, and Import Raw
    /// Key's once its address is not asked: one check after every step, not
    /// one per way out.
    pub(super) fn keep_key(&mut self) {
        if self.key_len > 0 && !self.showing_key() {
            wipe::wipe(&mut self.key_text);
            self.key_len = 0;
        }
        if self.state != State::RawKeyConfirm {
            self.raw_key = None;
        }
    }

    /// Signing Keys' key on the screen, as text, for drawing; never in a
    /// [`Screen`].
    pub fn key_text(&self) -> Option<&str> {
        if !self.showing_key() || self.key_len == 0 {
            return None;
        }
        core::str::from_utf8(&self.key_text[..self.key_len]).ok()
    }

    /// Signing Keys' key as a code, for drawing it. The code wipes itself
    /// when dropped.
    pub fn key_code(&self) -> Option<kassigner_qr::encode::QrMatrix> {
        kassigner_qr::encode::encode(self.key_text()?.as_bytes()).ok()
    }
}

/// A typed raw key into `held`, returning its public key; `None`, nothing
/// held, if it is not a valid key. Multiplied twice (checked by
/// `RawKey::new`, then its address) and its bytes wiped, in a frame of its
/// own so what the arithmetic leaves is below the caller for the scrub. The
/// key goes into `held` directly, never through the caller's frame.
#[inline(never)]
pub(super) fn raw_key_into(typed: &[u8], held: &mut Option<RawKey>) -> Option<[u8; 32]> {
    let mut bytes = [0u8; PRIVATE_KEY_SIZE];
    let read = crate::text::read_hex(typed, &mut bytes);
    let key = if read { RawKey::new(&bytes).ok() } else { None };
    let public = key
        .as_ref()
        .and_then(|_| kassigner_crypto::sign::public_key(&bytes).ok());
    wipe::wipe(&mut bytes);
    let public = public?;
    *held = key;
    Some(public)
}

/// kprv Master's text into `out`, returning its length; only words or a
/// master xprv have an `m`. A frame of its own, for the scrub.
#[inline(never)]
pub(super) fn master_text(slot: &Slot, out: &mut [u8; XPRV_TEXT_MAX]) -> Result<usize, Refusal> {
    let master = match slot {
        Slot::Mnemonic {
            mnemonic,
            passphrase,
        } => master_of(mnemonic, passphrase.as_str())?,
        Slot::Xprv(k) if k.depth() == 0 => k.clone(),
        _ => return Err(Refusal::NoPhrase),
    };
    master
        .to_text(PrivatePrefix::Kprv, out)
        .map_err(|_| Refusal::NotDerived)
}

/// kprv Account's text into `out`, returning its length: the wallet's `44'`
/// account node with its origin (a raw key has none). A frame of its own,
/// for the scrub.
#[inline(never)]
pub(super) fn account_text(
    wallet: &Wallet,
    out: &mut [u8; XPRV_TEXT_MAX],
) -> Result<usize, Refusal> {
    match wallet {
        Wallet::Hd { single, .. } => single
            .to_text(PrivatePrefix::Kprv, out)
            .map_err(|_| Refusal::NotDerived),
        Wallet::Raw(_) => Err(Refusal::NoPhrase),
    }
}
