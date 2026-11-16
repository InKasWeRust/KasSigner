// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KCC-2, "Authority Schemes", Final: who may approve what a covenant does.
//! For the cards to come: nothing on a unit calls this yet. Source and
//! vectors as in [`crate::kcc`].
//!
//! An authority is a key, a key's hash, one exact program or a covenant
//! lineage: a 32-byte value in a program's state or arguments, and a byte
//! naming its scheme. Its role is the convention's to say (2.4).
//!
//! This tells a signer whether a key is the authority; the approving
//! signature, over a message the convention chooses (6), is its own work.
//! For a program or a lineage it tells whether a spent input takes part,
//! from what consensus authenticates: the inputs' scripts and covenant ids.

use super::abi::Type;
use super::hash::{hash, HASH_LEN};
use super::value::Value;
use crate::script::pay_to_script_hash;
use crate::tx::ScriptPublicKey;

/// Length of every standard scheme's authority value.
pub const VALUE_LEN: usize = 32;

/// The five standard schemes (2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `0x00`, `p2pk-schnorr/v1`: the 32-byte Schnorr key itself.
    P2pkSchnorr,
    /// `0x01`, `p2pkh-schnorr/v1`: `Hash(pubkey)` of a 32-byte Schnorr key.
    P2pkhSchnorr,
    /// `0x02`, `p2pkh-ecdsa/v1`: `Hash(pubkey)` of a compressed 33-byte
    /// ECDSA key.
    P2pkhEcdsa,
    /// `0x03`, `p2sh/v1`: the P2SH commitment to one exact program.
    P2sh,
    /// `0x04`, `covenant-id/v1`: one continuing covenant lineage, by its
    /// KIP-20 Covenant ID.
    CovenantId,
}

/// What a scheme byte names (2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registered {
    /// `0x00` to `0x04`.
    Standard(Scheme),
    /// `0x80` to `0xff`: a scheme defined outside KCC-2, read only by its
    /// convention.
    Custom(u8),
}

/// Why an authority was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    /// `0x05` to `0x7f`: reserved, and to be rejected (2.1).
    Unassigned,
    /// `0x80` to `0xff`: a custom scheme, which this crate does not read.
    Custom,
    /// A value of another KCC-1 type than its scheme's.
    WrongType,
    /// A value, or a key, of another length than its scheme's (2.1, 2.2).
    WrongLength,
    /// A key asked of a scheme that names no key: `p2sh/v1`,
    /// `covenant-id/v1`.
    NotAKeyScheme,
}

impl Registered {
    /// What `byte` names.
    ///
    /// # Errors
    ///
    /// [`AuthorityError::Unassigned`] for `0x05` to `0x7f`.
    pub const fn of(byte: u8) -> Result<Self, AuthorityError> {
        match byte {
            0x00 => Ok(Self::Standard(Scheme::P2pkSchnorr)),
            0x01 => Ok(Self::Standard(Scheme::P2pkhSchnorr)),
            0x02 => Ok(Self::Standard(Scheme::P2pkhEcdsa)),
            0x03 => Ok(Self::Standard(Scheme::P2sh)),
            0x04 => Ok(Self::Standard(Scheme::CovenantId)),
            0x05..=0x7f => Err(AuthorityError::Unassigned),
            custom => Ok(Self::Custom(custom)),
        }
    }
}

impl Scheme {
    /// The standard scheme `byte` names.
    ///
    /// # Errors
    ///
    /// [`AuthorityError::Unassigned`], [`AuthorityError::Custom`].
    pub const fn of(byte: u8) -> Result<Self, AuthorityError> {
        match Registered::of(byte) {
            Ok(Registered::Standard(s)) => Ok(s),
            Ok(Registered::Custom(_)) => Err(AuthorityError::Custom),
            Err(e) => Err(e),
        }
    }

    /// Its byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::P2pkSchnorr => 0x00,
            Self::P2pkhSchnorr => 0x01,
            Self::P2pkhEcdsa => 0x02,
            Self::P2sh => 0x03,
            Self::CovenantId => 0x04,
        }
    }

    /// Its name and version.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::P2pkSchnorr => "p2pk-schnorr/v1",
            Self::P2pkhSchnorr => "p2pkh-schnorr/v1",
            Self::P2pkhEcdsa => "p2pkh-ecdsa/v1",
            Self::P2sh => "p2sh/v1",
            Self::CovenantId => "covenant-id/v1",
        }
    }

    /// The KCC-1 type of its value.
    #[must_use]
    pub const fn value_type(self) -> Type<'static> {
        match self {
            Self::P2pkSchnorr => Type::Pubkey,
            _ => Type::Array(&Type::Byte, VALUE_LEN),
        }
    }

    /// A key's length under it, `None` for a scheme that names no key.
    #[must_use]
    pub const fn key_len(self) -> Option<usize> {
        match self {
            Self::P2pkSchnorr | Self::P2pkhSchnorr => Some(32),
            Self::P2pkhEcdsa => Some(33),
            Self::P2sh | Self::CovenantId => None,
        }
    }
}

/// An authority: its scheme and its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authority {
    /// Its scheme.
    pub scheme: Scheme,
    /// Its value.
    pub value: [u8; VALUE_LEN],
}

impl Authority {
    /// The authority a program holds: its scheme byte, and its value as
    /// [`super::value`] read it, of type `ty`, which must be the scheme's, of
    /// its exact length (2.1).
    ///
    /// # Errors
    ///
    /// [`Scheme::of`]'s, [`AuthorityError::WrongType`],
    /// [`AuthorityError::WrongLength`].
    pub fn read(scheme_byte: u8, ty: &Type<'_>, value: Value<'_>) -> Result<Self, AuthorityError> {
        let scheme = Scheme::of(scheme_byte)?;
        if *ty != scheme.value_type() {
            return Err(AuthorityError::WrongType);
        }
        let Value::Bytes(b) = value else {
            return Err(AuthorityError::WrongType);
        };
        let value = b.try_into().map_err(|_| AuthorityError::WrongLength)?;
        Ok(Self { scheme, value })
    }

    /// The authority `key` is under `scheme`: the key, or `Hash(key)` (2.2).
    ///
    /// # Errors
    ///
    /// [`AuthorityError::NotAKeyScheme`], [`AuthorityError::WrongLength`]
    /// for a key of another length, or an ECDSA key not compressed.
    pub fn of_key(scheme: Scheme, key: &[u8]) -> Result<Self, AuthorityError> {
        let len = scheme.key_len().ok_or(AuthorityError::NotAKeyScheme)?;
        let compressed =
            !matches!(scheme, Scheme::P2pkhEcdsa) || matches!(key.first(), Some(0x02 | 0x03));
        if key.len() != len || !compressed {
            return Err(AuthorityError::WrongLength);
        }
        let value: [u8; HASH_LEN] = match scheme {
            Scheme::P2pkSchnorr => key.try_into().map_err(|_| AuthorityError::WrongLength)?,
            _ => hash(key),
        };
        Ok(Self { scheme, value })
    }

    /// Whether `key` is this authority's key (2.2); the signature is not
    /// checked here. `false` for a key of another length or a keyless scheme.
    #[must_use]
    pub fn names_key(&self, key: &[u8]) -> bool {
        Self::of_key(self.scheme, key).is_ok_and(|a| a == *self)
    }

    /// Whether one of `inputs`, the spent coins' scripts, is this `p2sh/v1`
    /// authority's program under version 0 (2.3.1); `false` under another
    /// scheme.
    pub fn p2sh_takes_part<'s>(
        &self,
        inputs: impl IntoIterator<Item = ScriptPublicKey<'s>>,
    ) -> bool {
        let lock = pay_to_script_hash(&self.value);
        self.scheme == Scheme::P2sh
            && inputs
                .into_iter()
                .any(|spk| spk.version == 0 && spk.script == lock)
    }

    /// Whether one of `inputs`, the spent coins' covenant ids, belongs to this
    /// `covenant-id/v1` lineage (2.3.2); `false` under another scheme. Outputs
    /// do not count.
    pub fn covenant_takes_part<'c>(
        &self,
        inputs: impl IntoIterator<Item = Option<&'c [u8; VALUE_LEN]>>,
    ) -> bool {
        self.scheme == Scheme::CovenantId && inputs.into_iter().any(|id| id == Some(&self.value))
    }
}
