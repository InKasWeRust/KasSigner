// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a unit hands an app, read from one code, file or pasted text:
//!
//! | What                | How it looks                                  |
//! |---------------------|-----------------------------------------------|
//! | a `44'` kpub        | `kpub...`, or v1.0.7's raw form, `0x01` + body |
//! | a cosigner's file   | `[fingerprint/45'/111111'/0']kpub...`          |
//! | a descriptor        | `multi_hd45(M,kpub...,kpub...)`                |
//! | a `22'` address     | `kaspa:p...`                                  |
//! | a signed message    | `-----BEGIN KASPA SIGNED MESSAGE-----` ...    |
//!
//! [`read`] tells them apart by the bytes, as a unit's scanner does. A bare
//! kpub is a `44'` account: a cosigner's `45'` kpub is the same bytes, and only
//! its file says so. Every key is checked: a kpub must be one a child derives
//! from ([`kassigner_protocol::kpub::read`]), and a descriptor holds at most
//! [`MAX_MULTISIG_KEYS`](kassigner_protocol::check::MAX_MULTISIG_KEYS) keys,
//! none twice.

use kassigner_kaspa::bip32_public::ExtendedPublicKey;
use kassigner_protocol::descriptor::{strip_header, PREFIX};
use kassigner_protocol::group::GroupError;
use kassigner_protocol::{kpub, message};

use crate::watch::{Account, Group, Kcc3Address, WatchError};

/// What a unit handed over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Import<'a> {
    /// A `44'` account's kpub, text or raw form.
    Account(Account),
    /// A cosigner's kpub, `m/45'/111111'/0'`, with its seed's fingerprint.
    Cosigner {
        fingerprint: [u8; 4],
        key: ExtendedPublicKey,
    },
    /// A descriptor line, header stripped, that reads as a group
    /// ([`Group::from_descriptor`]).
    Descriptor(&'a str),
    /// A `22'` address.
    Kcc3Address(Kcc3Address),
    /// A signed message, not yet verified ([`crate::message::verify`]): where
    /// its parts are in the bytes.
    SignedMessage(message::Parts),
}

/// Why bytes were not read as an import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// None of the five, a kpub or address that does not read included.
    NotRecognised,
    /// A descriptor that is not a group a unit signs: a key that is not a kpub
    /// or comes twice, too many keys, no threshold.
    Descriptor(GroupError),
    /// Text opening with `[` that is not a cosigner's file, or whose key is not
    /// at its path's depth.
    Cosigner,
    /// An address that is not a mainnet script hash's.
    Address(WatchError),
}

/// Which of the five `bytes` are, as they came: whitespace around text and a
/// descriptor's `#` header line are passed over.
///
/// # Errors
///
/// `Cosigner` or `Descriptor` for one that does not read; `Address` for an
/// address not a mainnet script hash's; `NotRecognised` for anything else.
pub fn read(bytes: &[u8]) -> Result<Import<'_>, ImportError> {
    if kpub::starts_raw(bytes) {
        return kpub::read(bytes)
            .map(|k| Import::Account(Account::new(k)))
            .ok_or(ImportError::NotRecognised);
    }
    if let Some(parts) = message::read(bytes) {
        return Ok(Import::SignedMessage(parts));
    }
    let Ok(text) = core::str::from_utf8(bytes) else {
        return Err(ImportError::NotRecognised);
    };
    let text = text.trim();
    if text.starts_with("kpub") {
        return kpub::read(text.as_bytes())
            .map(|k| Import::Account(Account::new(k)))
            .ok_or(ImportError::NotRecognised);
    }
    if let Some(origin) = text.strip_prefix('[') {
        let key = kpub::read_cosigner(text.as_bytes()).ok_or(ImportError::Cosigner)?;
        let mut fingerprint = [0u8; 4];
        for (i, b) in fingerprint.iter_mut().enumerate() {
            *b = u8::from_str_radix(
                origin.get(2 * i..2 * i + 2).ok_or(ImportError::Cosigner)?,
                16,
            )
            .map_err(|_| ImportError::Cosigner)?;
        }
        return Ok(Import::Cosigner { fingerprint, key });
    }
    let line = strip_header(text);
    if line.starts_with(PREFIX) {
        return Group::from_descriptor(line)
            .map(|_| Import::Descriptor(line))
            .map_err(ImportError::Descriptor);
    }
    if text.contains(':') {
        return Kcc3Address::read(text.as_bytes())
            .map(Import::Kcc3Address)
            .map_err(|e| match e {
                WatchError::NotAnAddress(_) => ImportError::NotRecognised,
                other => ImportError::Address(other),
            });
    }
    Err(ImportError::NotRecognised)
}
