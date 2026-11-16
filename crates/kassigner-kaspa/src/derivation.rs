// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Kaspa's derivation scheme (upstream: `build_derivate_path` in
//! `wallet/keys/src/derivation/gen1/hd.rs`): `m/<purpose>'/111111'/<account>'`,
//! a cosigner level for multisig, then the address type, 0 receive and 1
//! change. Purpose 44 for single keys, 45 for multisig; nothing below the
//! account is hardened. There is no 44' multisig: BIP44 has no cosigner
//! level to say which slot in a key set is yours.
//!
//! A third purpose is KCC-3's, "Pay-to-Public-Key-Hash via P2SH"
//! (`kaspanet/kccs` pull request 37): keys behind a script hash,
//! `<P> OP_CHECKSIG`, off the chain until they spend, with accounts as
//! BIP44's under the same coin type on every network. A wallet convention,
//! not consensus; rusty-kaspa 2.1.0's wallet does not derive it yet.
//!
//! The paths are Kaspa's, so they live here: a wrong number gives another
//! address. The key-holding crate and every public-key integrator derive
//! through the same ones.

use crate::bip32_public::{Bip32Error, ChildNumber, HARDENED_OFFSET};

/// Kaspa's coin type.
pub const COIN_TYPE: u32 = 111_111;

/// Purpose for single-signature keys.
pub const PURPOSE_SINGLE: u32 = 44;

/// Purpose for multisig keys.
pub const PURPOSE_MULTISIG: u32 = 45;

/// Purpose for KCC-3's keys. The draft leaves it `XXXX'` until a number is
/// fixed; 22 is the number it was published under, as KIP-22. Changing it
/// changes every KCC-3 key, so nothing receives on them before the KCC and
/// rusty-kaspa's wallet agree.
pub const PURPOSE_KCC3: u32 = 22;

/// The receiving chain, upstream's `AddressType::Receive`.
pub const RECEIVE: u32 = 0;

/// The change chain, upstream's `AddressType::Change`.
pub const CHANGE: u32 = 1;

/// Levels in an account path.
pub const ACCOUNT_LEVELS: usize = 3;

/// Most levels below an account: cosigner, chain and index.
pub const MAX_BELOW_ACCOUNT: usize = 3;

const fn hardened(n: u32) -> ChildNumber {
    ChildNumber(n | HARDENED_OFFSET)
}

/// `m/44'/111111'/<account>'`.
pub const fn single_account(account: u32) -> [ChildNumber; ACCOUNT_LEVELS] {
    [
        hardened(PURPOSE_SINGLE),
        hardened(COIN_TYPE),
        hardened(account),
    ]
}

/// `m/45'/111111'/<account>'`.
pub const fn multisig_account(account: u32) -> [ChildNumber; ACCOUNT_LEVELS] {
    [
        hardened(PURPOSE_MULTISIG),
        hardened(COIN_TYPE),
        hardened(account),
    ]
}

/// `m/22'/111111'/<account>'`, KCC-3's.
pub const fn kcc3_account(account: u32) -> [ChildNumber; ACCOUNT_LEVELS] {
    [
        hardened(PURPOSE_KCC3),
        hardened(COIN_TYPE),
        hardened(account),
    ]
}

/// `m/44'/111111'/0'`, the first account.
pub const SINGLE_ACCOUNT: [ChildNumber; ACCOUNT_LEVELS] = single_account(0);

/// `m/45'/111111'/0'`.
pub const MULTISIG_ACCOUNT: [ChildNumber; ACCOUNT_LEVELS] = multisig_account(0);

/// `m/22'/111111'/0'`.
pub const KCC3_ACCOUNT: [ChildNumber; ACCOUNT_LEVELS] = kcc3_account(0);

/// A key below an account node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// `<single account>/chain/index`.
    Single { chain: u32, index: u32 },
    /// `<multisig account>/cosigner/chain/index`.
    Multisig {
        cosigner: u32,
        chain: u32,
        index: u32,
    },
    /// `<KCC-3 account>/chain/index`.
    Kcc3 { chain: u32, index: u32 },
}

impl Path {
    /// A receiving key.
    pub const fn receive(index: u32) -> Self {
        Path::Single {
            chain: RECEIVE,
            index,
        }
    }

    /// A change key.
    pub const fn change(index: u32) -> Self {
        Path::Single {
            chain: CHANGE,
            index,
        }
    }

    /// A KCC-3 receiving key.
    pub const fn kcc3_receive(index: u32) -> Self {
        Path::Kcc3 {
            chain: RECEIVE,
            index,
        }
    }

    /// A KCC-3 change key.
    pub const fn kcc3_change(index: u32) -> Self {
        Path::Kcc3 {
            chain: CHANGE,
            index,
        }
    }

    /// True for a path under the multisig account.
    pub const fn is_multisig(&self) -> bool {
        matches!(self, Path::Multisig { .. })
    }

    /// True for a path under the KCC-3 account.
    pub const fn is_kcc3(&self) -> bool {
        matches!(self, Path::Kcc3 { .. })
    }

    /// The account this path hangs from, for `account` zero.
    pub const fn account(&self) -> [ChildNumber; ACCOUNT_LEVELS] {
        match self {
            Path::Single { .. } => SINGLE_ACCOUNT,
            Path::Multisig { .. } => MULTISIG_ACCOUNT,
            Path::Kcc3 { .. } => KCC3_ACCOUNT,
        }
    }

    /// The levels below the account, written into `out`.
    ///
    /// # Errors
    ///
    /// `InvalidChild` for a hardened number: none is below an account.
    pub fn children<'a>(
        &self,
        out: &'a mut [ChildNumber; MAX_BELOW_ACCOUNT],
    ) -> Result<&'a [ChildNumber], Bip32Error> {
        let levels: &[u32] = match self {
            Path::Single { chain, index } | Path::Kcc3 { chain, index } => &[*chain, *index],
            Path::Multisig {
                cosigner,
                chain,
                index,
            } => &[*cosigner, *chain, *index],
        };
        for (slot, &n) in out.iter_mut().zip(levels) {
            if n >= HARDENED_OFFSET {
                return Err(Bip32Error::InvalidChild);
            }
            *slot = ChildNumber(n);
        }
        Ok(&out[..levels.len()])
    }
}
