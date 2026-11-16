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

//! A slot turned into keys, along `kassigner_kaspa::derivation`'s paths.
//! Opening a mnemonic runs the BIP39 stretch and the hardened steps once,
//! to the `44'`, `45'` and KCC-3 `22'` account nodes, and keeps them, wiped
//! on drop: every signing key is a cheap non-hardened child of one.
//!
//! - A mnemonic, or an xprv at depth 0 (a master key): every path.
//! - An xprv at depth 3, account `0'`: the `44'` account node, where v1.0.7
//!   imports it; single-signature paths only, with no seed for the `45'`
//!   and `22'` branches. Any other xprv is refused.
//! - A raw key: one key, for every path.
//!
//! The fingerprint is BIP32's, of the highest key held (see `slot`'s
//! "Fingerprints"), known once the wallet is open.

use zeroize::Zeroize;

use crate::bip32::{compressed_public_key, Bip32Error, ExtendedPrivateKey, PRIVATE_KEY_SIZE};
use crate::bip39::{self, Bip39Error};
use crate::slot::{RawKey, Slot, FINGERPRINT_LEN};
use kassigner_kaspa::bip32_public::{ChildNumber, ExtendedPublicKey, PUBLIC_KEY_SIZE};
use kassigner_kaspa::derivation::{
    Path, ACCOUNT_LEVELS, KCC3_ACCOUNT, MAX_BELOW_ACCOUNT, MULTISIG_ACCOUNT, SINGLE_ACCOUNT,
};

/// Why a wallet could not be opened or a key not derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletError {
    /// The slot is empty.
    EmptySlot,
    /// A multisig path was asked of an account xprv slot.
    NoMultisigTree,
    /// A KCC-3 path was asked of an account xprv slot.
    NoKcc3Tree,
    /// The xprv is neither a master key nor an account node. Taken as the
    /// account node, it would sign for keys that hold nothing, which looks
    /// like a broken backup.
    XprvDepth {
        depth: u8,
    },
    /// An xprv at account depth whose child number, `child`, is not `0'`.
    /// The `44'` and `111111'` above it are not in the key: taken on trust.
    XprvAccount {
        child: u32,
    },
    /// A chain other than receive (0) and change (1): any other, hardened
    /// ones included, derives a node no address is on.
    Chain {
        chain: u32,
    },
    Bip39(Bip39Error),
    Bip32(Bip32Error),
}

impl From<Bip39Error> for WalletError {
    fn from(e: Bip39Error) -> Self {
        WalletError::Bip39(e)
    }
}
impl From<Bip32Error> for WalletError {
    fn from(e: Bip32Error) -> Self {
        WalletError::Bip32(e)
    }
}

/// A key ready to sign with: the private key and its compressed public key.
/// Zeroizes on drop.
#[derive(Clone)]
pub struct SigningKey {
    private: [u8; PRIVATE_KEY_SIZE],
    public: [u8; PUBLIC_KEY_SIZE],
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigningKey(redacted)")
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl SigningKey {
    pub const fn private_key(&self) -> &[u8; PRIVATE_KEY_SIZE] {
        &self.private
    }

    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.public
    }

    /// The x-only public key, what a Kaspa script holds.
    pub fn x_only(&self) -> [u8; 32] {
        let mut x = [0u8; 32];
        x.copy_from_slice(&self.public[1..]);
        x
    }
}

/// The keys behind one slot.
pub enum Wallet {
    /// A tree: the `44'` account node, and the `45'` and KCC-3 `22'` ones
    /// when there is a seed to reach them from.
    Hd {
        single: ExtendedPrivateKey,
        multisig: Option<ExtendedPrivateKey>,
        kcc3: Option<ExtendedPrivateKey>,
        /// The fingerprint of the highest key this wallet came from, taken
        /// when it opened: `m`'s for a mnemonic, which is not kept.
        fingerprint: [u8; FINGERPRINT_LEN],
    },
    /// One key.
    Raw(RawKey),
}

impl core::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Wallet::Hd { multisig, kcc3, .. } => write!(
                f,
                "Wallet::Hd(multisig: {}, kcc3: {}, redacted)",
                multisig.is_some(),
                kcc3.is_some()
            ),
            Wallet::Raw(_) => write!(f, "Wallet::Raw(redacted)"),
        }
    }
}

impl Wallet {
    /// Open the wallet a slot holds.
    ///
    /// `scratch` is what [`bip39::to_seed`] needs for a mnemonic:
    /// [`bip39::scratch_for`] of the passphrase length, and
    /// `scratch_for(PASSPHRASE_MAX)` covers every slot. Wiped before return.
    ///
    /// `inline(never)` is load-bearing: this holds the BIP39 seed, the
    /// master key and every node to the accounts, and a move leaves copies
    /// no `Drop` reaches. In a frame of their own they sit below the caller,
    /// where a scrub after the return covers them; inlined, they would sit
    /// in the caller's frame, out of its scrubs' reach.
    ///
    /// # Errors
    ///
    /// `EmptySlot`; `Bip39` from the stretch; `Bip32` from the hardened
    /// steps; `XprvDepth` and `XprvAccount` for an xprv that is neither a
    /// master key nor account `0'`.
    #[inline(never)]
    pub fn open(slot: &Slot, scratch: &mut [u8]) -> Result<Self, WalletError> {
        match slot {
            Slot::Empty => Err(WalletError::EmptySlot),
            Slot::Mnemonic {
                mnemonic,
                passphrase,
            } => {
                let seed = bip39::to_seed(mnemonic, passphrase.as_str(), scratch);
                scratch.zeroize();
                let seed = seed?;
                let master = ExtendedPrivateKey::from_seed(seed.as_bytes())?;
                let single = master.derive_path(&SINGLE_ACCOUNT)?;
                let multisig = master.derive_path(&MULTISIG_ACCOUNT)?;
                let kcc3 = master.derive_path(&KCC3_ACCOUNT)?;
                Ok(Wallet::Hd {
                    single,
                    multisig: Some(multisig),
                    kcc3: Some(kcc3),
                    fingerprint: master.fingerprint(),
                })
            }
            Slot::Xprv(k) => match k.depth() {
                // A master key: what a seed gives, without the stretch.
                0 => Ok(Wallet::Hd {
                    single: k.derive_path(&SINGLE_ACCOUNT)?,
                    multisig: Some(k.derive_path(&MULTISIG_ACCOUNT)?),
                    kcc3: Some(k.derive_path(&KCC3_ACCOUNT)?),
                    fingerprint: k.fingerprint(),
                }),
                // The `44'` account node, as v1.0.7 imports it: account 0'.
                d if usize::from(d) == ACCOUNT_LEVELS
                    && k.child_number() == SINGLE_ACCOUNT[ACCOUNT_LEVELS - 1] =>
                {
                    Ok(Wallet::Hd {
                        single: k.clone(),
                        multisig: None,
                        kcc3: None,
                        fingerprint: k.fingerprint(),
                    })
                }
                d if usize::from(d) == ACCOUNT_LEVELS => Err(WalletError::XprvAccount {
                    child: k.child_number().0,
                }),
                depth => Err(WalletError::XprvDepth { depth }),
            },
            Slot::RawKey(k) => Ok(Wallet::Raw(k.clone())),
        }
    }

    /// The extended public key of the single-key account's chain `chain`,
    /// 0 for receiving and 1 for change, or `None` for a raw key.
    ///
    /// For a chain's public keys without its private ones: one curve
    /// multiplication an address, where [`Wallet::signing_key`] does five.
    ///
    /// # Errors
    ///
    /// `Chain` for a chain other than 0 and 1; `Bip32` if the derivation
    /// fails.
    pub fn chain_public(&self, chain: u32) -> Result<Option<ExtendedPublicKey>, WalletError> {
        if chain > 1 {
            return Err(WalletError::Chain { chain });
        }
        match self {
            Wallet::Hd { single, .. } => {
                let node = single.derive_child(ChildNumber(chain))?;
                Ok(Some(node.to_extended_public_key()))
            }
            Wallet::Raw(_) => Ok(None),
        }
    }

    /// The extended public key of the KCC-3 account's chain `chain`, as
    /// [`Wallet::chain_public`], or `None` for an account xprv or a raw key.
    ///
    /// # Errors
    ///
    /// `Chain` for a chain other than 0 and 1; `Bip32` if the derivation
    /// fails.
    pub fn kcc3_chain_public(&self, chain: u32) -> Result<Option<ExtendedPublicKey>, WalletError> {
        if chain > 1 {
            return Err(WalletError::Chain { chain });
        }
        match self {
            Wallet::Hd {
                kcc3: Some(account),
                ..
            } => {
                let node = account.derive_child(ChildNumber(chain))?;
                Ok(Some(node.to_extended_public_key()))
            }
            _ => Ok(None),
        }
    }

    /// The wallet's BIP32 fingerprint: its master key's for a mnemonic.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        match self {
            Wallet::Hd { fingerprint, .. } => *fingerprint,
            Wallet::Raw(k) => k.fingerprint(),
        }
    }

    /// True when multisig paths can be derived.
    pub const fn has_multisig(&self) -> bool {
        matches!(
            self,
            Wallet::Hd {
                multisig: Some(_),
                ..
            }
        )
    }

    /// True when KCC-3 paths can be derived: a mnemonic or a master xprv.
    pub const fn has_kcc3(&self) -> bool {
        matches!(self, Wallet::Hd { kcc3: Some(_), .. })
    }

    /// The key at `path`.
    ///
    /// # Errors
    ///
    /// `Chain` for a chain other than receive (0) and change (1), on any
    /// account, as [`Wallet::chain_public`]. `NoMultisigTree` or
    /// `NoKcc3Tree` for a multisig or KCC-3 path on an account xprv. `Bip32`
    /// for a hardened number below the account, or a step that yields an
    /// invalid key (negligible odds).
    pub fn signing_key(&self, path: Path) -> Result<SigningKey, WalletError> {
        let (Path::Single { chain, .. } | Path::Multisig { chain, .. } | Path::Kcc3 { chain, .. }) =
            path;
        if chain > 1 {
            return Err(WalletError::Chain { chain });
        }
        let mut below = [ChildNumber(0); MAX_BELOW_ACCOUNT];
        let node = match (self, path) {
            (Wallet::Raw(k), _) => {
                let public = compressed_public_key(k.as_bytes())?;
                return Ok(SigningKey {
                    private: *k.as_bytes(),
                    public,
                });
            }
            (Wallet::Hd { single, .. }, Path::Single { .. }) => {
                single.derive_path(path.children(&mut below).map_err(Bip32Error::from)?)?
            }
            (Wallet::Hd { multisig, .. }, Path::Multisig { .. }) => multisig
                .as_ref()
                .ok_or(WalletError::NoMultisigTree)?
                .derive_path(path.children(&mut below).map_err(Bip32Error::from)?)?,
            (Wallet::Hd { kcc3, .. }, Path::Kcc3 { .. }) => kcc3
                .as_ref()
                .ok_or(WalletError::NoKcc3Tree)?
                .derive_path(path.children(&mut below).map_err(Bip32Error::from)?)?,
        };
        Ok(SigningKey {
            private: *node.private_key(),
            public: node.public_key(),
        })
    }
}
