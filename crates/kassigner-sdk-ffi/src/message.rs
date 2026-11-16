// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Signed messages: [`kassigner_sdk_host::message`] over the C ABI.

use kassigner_sdk_host::message as host;

use crate::transport::Codes;
use crate::{Fault, Profile};

/// A signed message record's three parts, as text.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Record {
    /// The text signed.
    pub text: String,
    /// The address that signed.
    pub address: String,
    /// The signature, hex.
    pub signature: String,
}

impl From<host::Record> for Record {
    fn from(r: host::Record) -> Self {
        Record {
            text: r.text,
            address: r.address,
            signature: r.signature,
        }
    }
}

/// A verified record, and the key of the mainnet address that signed.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Verified {
    pub record: Record,
    /// The address's x-only key, hex, which the signature verified
    /// against.
    pub key: String,
}

impl From<host::Verified> for Verified {
    fn from(v: host::Verified) -> Self {
        Verified {
            record: v.record.into(),
            key: v.key,
        }
    }
}

/// Whether a unit signs `text`: not empty, every character one its screen
/// shows, and no space ending a line or the text, nor a final line break,
/// which the screen would not show.
#[uniffi::export]
pub fn is_text(text: String) -> bool {
    host::is_text(&text)
}

/// The codes showing `text` to a unit of `profile`, for Sign Message.
///
/// # Errors
///
/// `NotText` or `TrailingWhitespace` for a text [`is_text`] refuses,
/// `Transport` for one past the unit's frames.
#[uniffi::export]
pub fn message_codes(text: String, profile: &Profile) -> Result<Codes, Fault> {
    Ok(Codes::over(host::message_codes(&text, profile.inner())?))
}

/// Read `bytes` as a signed message record and verify its signature
/// against its address's key.
///
/// # Errors
///
/// `NotARecord`, `NotAKeyAddress`, `NotMainnet(..)`, `Fails`.
#[uniffi::export]
pub fn verify_message(bytes: Vec<u8>) -> Result<Verified, Fault> {
    Ok(host::verify_message(&bytes)?.into())
}

/// [`verify_message`], also checking the text is `text` and the address
/// `address`, as for a login or a proof of ownership.
///
/// # Errors
///
/// As [`verify_message`]; `OtherText`, `OtherAddress`.
#[uniffi::export]
pub fn verify_message_against(
    bytes: Vec<u8>,
    text: String,
    address: String,
) -> Result<Verified, Fault> {
    Ok(host::verify_message_against(&bytes, &text, &address)?.into())
}
