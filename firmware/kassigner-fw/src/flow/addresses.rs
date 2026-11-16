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

//! Addresses: the seed's own, KCC-3's and a group's.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    /// The Address screen for the seed in use, from receive address 0, Back
    /// going to `from`; refused with no seed or no backup. With `key`,
    /// Private Key: each address's private key instead.
    pub(super) fn open_address(&mut self, from: State, key: bool) {
        if self.keys.is_none() {
            self.refuse(Refusal::NoWallet);
            return;
        }
        if !self.backed_or_refuse() {
            return;
        }
        self.addr_from = from;
        self.addr_key = key;
        self.addr_sign = false;
        self.addr_group = false;
        self.addr_kcc3 = false;
        self.addr_change = false;
        self.addr_index = 0;
        self.show_address();
    }

    /// KCC-3 Address: the seed's `kaspa:p...` addresses, each the hash of
    /// `<P> OP_CHECKSIG`, all a companion needs to watch and spend it while
    /// P's key stays here. Refused with no seed, no `22'` tree or no backup.
    pub(super) fn open_kcc3_address(&mut self) {
        let Some(keys) = self.keys.as_ref() else {
            self.refuse(Refusal::NoWallet);
            return;
        };
        if !keys.has_kcc3() {
            self.refuse(Refusal::NoKcc3Key);
            return;
        }
        if !self.backed_or_refuse() {
            return;
        }
        self.open_address(
            State::Menu {
                menu: MenuId::SeedTools,
                page: KCC3_ROW / menu::LIST.rows,
            },
            false,
        );
        self.addr_kcc3 = true;
        self.address_now();
    }

    /// Multisig Address, on the tick after its tap: the held group's receive
    /// address 0 at the seed in use's branch, or the first cosigner's. The
    /// first time for a group, DERIVING ([`State::GroupDeriving`]) works its
    /// keys down to every branch and chain first.
    pub(super) fn settle_group_address(&mut self) {
        let Some(n) = self.group.as_ref().map(|g| g.total()) else {
            return;
        };
        let own = self.group_position().filter(|&p| p < n).unwrap_or(0);
        self.addr_from = MULTISIG_MENU;
        self.addr_key = false;
        self.addr_sign = false;
        self.addr_group = true;
        self.addr_kcc3 = false;
        let at = AddressAt {
            change: false,
            index: 0,
            cosigner: own as u8,
        };
        if self.branches.ready() {
            return self.settle_address(at);
        }
        self.branches.start(n);
        self.deferred = Some(Work::Address(at));
        self.state = State::GroupDeriving;
    }

    /// The address a tap asked for, on the Address screen.
    pub(super) fn settle_address(&mut self, at: AddressAt) {
        self.addr_change = at.change;
        self.addr_index = at.index;
        self.addr_cosigner = at.cosigner;
        self.address_now();
        self.state = State::Address;
    }

    /// Multisig Address's DERIVING: a branch key each tick, then the
    /// address. A finger pressed meanwhile does not tap the address after.
    pub(super) fn on_group_deriving(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tick { .. } = event else {
            return None;
        };
        let Some(group) = self.group.as_ref() else {
            self.deferred = None;
            self.state = self.addr_from;
            return None;
        };
        if self.branches.step(group).is_err() {
            self.branches.clear();
            self.deferred = None;
            self.refuse(Refusal::NotDerived);
            return None;
        }
        if self.branches.ready() {
            if let Some(Work::Address(at)) = self.deferred {
                self.deferred = None;
                self.settle_address(at);
            }
        }
        None
    }

    /// The Address screen at the set chain and index. A private key shows
    /// DERIVING ([`State::KeyDeriving`]) for a tick first: it takes long
    /// enough to look like a tap that did nothing.
    pub(super) fn show_address(&mut self) {
        if self.addr_key {
            wipe::wipe(&mut self.key_text);
            self.key_len = 0;
            self.state = State::KeyDeriving;
        } else {
            self.address_now();
            self.state = State::Address;
        }
    }

    /// Private Key's DERIVING, on the next tick: the key, shown.
    pub(super) fn on_key_deriving(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tick { .. } = event else {
            return None;
        };
        self.address_now();
        self.state = State::Address;
        None
    }

    /// The address at the set chain and index as text, or for Private Key
    /// its private key in hex, in a frame of its own, the stack scrubbed
    /// after.
    pub(super) fn address_now(&mut self) {
        self.addr_len = 0;
        wipe::wipe(&mut self.key_text);
        self.key_len = 0;
        // A group's P2SH address from its keys at the cosigner's branch,
        // chain and index: one step from the kept keys once worked out, else
        // all three.
        if self.addr_group {
            if let Some(group) = self.group.as_ref() {
                let (cosigner, change, index) =
                    (self.addr_cosigner, self.addr_change, self.addr_index);
                let mut keys = [[0u8; 32]; limits::MAX_MULTISIG_KEYS];
                let made = match self
                    .branches
                    .keys_at(cosigner.into(), change, index, &mut keys)
                {
                    Some(_) => group.address_of_keys(Prefix::Mainnet, &keys, &mut self.addr_text),
                    None => group.address(
                        Prefix::Mainnet,
                        cosigner.into(),
                        change.into(),
                        index,
                        &mut self.addr_text,
                    ),
                };
                self.addr_len = made.unwrap_or(0);
            }
            return;
        }
        let Some(keys) = self.keys.as_ref() else {
            return;
        };
        // KCC-3's: the hash of `<P> OP_CHECKSIG`, as a script-hash address.
        if self.addr_kcc3 {
            let path = Path::Kcc3 {
                chain: u32::from(self.addr_change),
                index: self.addr_index,
            };
            if let Ok(key) = keys.kcc3_address_key(path) {
                self.addr_len = kaspa_address::encode(
                    Prefix::Mainnet,
                    Version::ScriptHash,
                    &kcc3_script_hash(&key),
                    &mut self.addr_text,
                )
                .unwrap_or(0);
            }
            return;
        }
        let path = if self.addr_change {
            Path::change(self.addr_index)
        } else {
            Path::receive(self.addr_index)
        };
        if self.addr_key {
            wipe::begin_depth(self.stack);
            self.key_len = private_key_hex(keys.wallet(), path, &mut self.key_text);
            wipe::scrub_flow();
            return;
        }
        if let Ok(key) = keys.address_key(path) {
            self.address_of(&key);
        }
    }

    /// The address of public key `key`, as the Address tool's text.
    pub(super) fn address_of(&mut self, key: &[u8; 32]) {
        self.addr_len =
            kaspa_address::encode(Prefix::Mainnet, Version::PubKey, key, &mut self.addr_text)
                .unwrap_or(0);
    }

    /// The Address screen: Receive or Change switches chain (back to index
    /// 0), "<" and ">" step, the index opens the keypad, the address its code
    /// (SIGN MESSAGE? when signing). A group's "-" and "+" wrap the
    /// cosigner. A move is worked out on the next tick ([`Flow::defer`]).
    pub(super) fn on_address(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let single = !self.keys.as_ref().is_some_and(|k| k.has_chains());
        let first = self.addr_index == 0;
        let hit = if self.addr_group {
            address_screen::group_target(self.scale, first, x, y)
        } else {
            address_screen::target(self.scale, single, first, x, y)
        };
        let (change, index, cosigner) = (self.addr_change, self.addr_index, self.addr_cosigner);
        let at = match hit? {
            address_screen::Target::Nav(Nav::Home) => {
                self.state = State::Home;
                return None;
            }
            address_screen::Target::Nav(_) => {
                self.state = self.addr_from;
                return None;
            }
            address_screen::Target::Address if self.addr_sign => {
                self.state = State::MessageConfirm;
                return None;
            }
            address_screen::Target::Address => {
                self.state = State::AddressQr;
                return None;
            }
            address_screen::Target::Index => {
                self.pad_len = 0;
                self.state = State::AddressIndex;
                return None;
            }
            address_screen::Target::Chain => AddressAt {
                change: !change,
                index: 0,
                cosigner,
            },
            address_screen::Target::Before => AddressAt {
                change,
                index: index.saturating_sub(1),
                cosigner,
            },
            address_screen::Target::After => AddressAt {
                change,
                index: (index + 1).min(INDEX_MAX),
                cosigner,
            },
            // The cosigner, wrapping round.
            t
            @ (address_screen::Target::CosignerBefore | address_screen::Target::CosignerAfter) => {
                let n = self.group.as_ref().map_or(1, |g| g.total()) as u8;
                let step = if t == address_screen::Target::CosignerAfter {
                    1
                } else {
                    n - 1
                };
                AddressAt {
                    change,
                    index,
                    cosigner: (cosigner % n + step) % n,
                }
            }
        };
        if !self.addr_key {
            return self.defer(Work::Address(at));
        }
        self.addr_change = at.change;
        self.addr_index = at.index;
        self.show_address();
        None
    }

    /// The keypad: up to five digits; C clears; GO goes to the index.
    pub(super) fn on_address_index(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match keypad::target(self.scale, x, y)? {
            keypad::Target::Nav(Nav::Home) => self.state = State::Home,
            keypad::Target::Nav(_) => self.state = State::Address,
            keypad::Target::Key(keypad::Key::Digit(d)) => {
                if self.pad_len < INDEX_DIGITS {
                    self.pad[self.pad_len] = b'0' + d;
                    self.pad_len += 1;
                }
            }
            keypad::Target::Key(keypad::Key::Clear) => self.pad_len = 0,
            keypad::Target::Key(keypad::Key::Go) => {
                if self.pad_len > 0 {
                    let index = self.pad[..self.pad_len]
                        .iter()
                        .fold(0u32, |n, &c| n * 10 + u32::from(c - b'0'));
                    // The keypad stays up until the address is worked out.
                    if !self.addr_key {
                        return self.defer(Work::Address(AddressAt {
                            change: self.addr_change,
                            index,
                            cosigner: self.addr_cosigner,
                        }));
                    }
                    self.addr_index = index;
                    self.show_address();
                }
            }
        }
        None
    }

    /// The address shown, as text, for drawing it and its code.
    pub fn address_text(&self) -> &str {
        core::str::from_utf8(&self.addr_text[..self.addr_len]).unwrap_or("")
    }

    /// ADDRESS EXPORTED: Save to SD (`ADnnnn.TXT`) or Back to QR.
    pub(super) fn on_address_done(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Nav(_) => self.state = State::Address,
            dialog::Target::Cancel => {
                let what = if self.addr_group {
                    Saving::GroupAddress
                } else {
                    Saving::Address
                };
                return self.start_saving(what, State::AddressDone);
            }
            dialog::Target::Accept => self.state = State::AddressQr,
        }
        None
    }
}

/// The private key at `path` into `out` as lower-case hex, as rusty-kaspa
/// writes it, returning its length (0 if not derived); a raw key's for any
/// path. A frame of its own, for the scrub after it.
#[inline(never)]
pub(super) fn private_key_hex(wallet: &Wallet, path: Path, out: &mut [u8; XPRV_TEXT_MAX]) -> usize {
    match wallet.signing_key(path) {
        Ok(key) => crate::text::write_hex(key.private_key(), out),
        Err(_) => 0,
    }
}
