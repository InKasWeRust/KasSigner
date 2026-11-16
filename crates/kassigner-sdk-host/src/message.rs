// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A message signed by a unit: [`kassigner_sdk::message`] over owned values.
//! The text's codes out, the signed record back and verified.

use kassigner_protocol::message::Parts;
use kassigner_sdk::message;

use crate::transport::Codes;
use crate::watch::text;
use crate::{hex, Fault, Profile};

/// A signed message record's three parts, as text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The text signed.
    pub text: String,
    /// The address that signed.
    pub address: String,
    /// The signature, hex.
    pub signature: String,
}

impl Record {
    /// The text signed.
    pub fn text(&self) -> String {
        self.text.clone()
    }

    /// The address that signed.
    pub fn address(&self) -> String {
        self.address.clone()
    }

    /// The signature, hex.
    pub fn signature(&self) -> String {
        self.signature.clone()
    }
}

impl Record {
    /// The parts of `bytes` that `parts` names.
    pub fn of(bytes: &[u8], parts: &Parts) -> Record {
        Record {
            text: text(&bytes[parts.text.clone()]),
            address: text(&bytes[parts.address.clone()]),
            signature: text(&bytes[parts.signature.clone()]),
        }
    }
}

/// A verified record: its parts, and the key of the mainnet address that
/// signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub record: Record,
    /// The x-only key the address carries and the signature verified
    /// against, hex.
    pub key: String,
}

/// Whether a unit signs `text`: not empty, every character one its screen
/// shows, and no space ending a line nor line break ending the text, which
/// would show as nothing.
pub fn is_text(text: &str) -> bool {
    message::is_signable(text.as_bytes())
}

/// The codes that show `text` to a unit of `profile`, for its Sign
/// Message.
///
/// # Errors
///
/// `NotText` for a text the unit refuses; `TrailingWhitespace` for one it
/// refuses to sign; `Transport(TooManyFrames { .. })` for one past its
/// frames.
pub fn message_codes(text: &str, profile: &Profile) -> Result<Codes, Fault> {
    let plan = message::codes(text.as_bytes(), profile.inner()).map_err(Fault::of)?;
    Ok(Codes::over(plan, message::FORMAT, text.as_bytes().to_vec()))
}

/// Read `bytes` as a signed message record and verify its signature over
/// its text against its address's key.
///
/// # Errors
///
/// `NotARecord`, `NotAKeyAddress`, `NotMainnet(..)`, `Fails`.
pub fn verify_message(bytes: &[u8]) -> Result<Verified, Fault> {
    let v = message::verify(bytes).map_err(Fault::of)?;
    Ok(verified(bytes, v))
}

/// [`verify_message`], and the record's text is `text` and its address
/// `address`, as for a login.
///
/// # Errors
///
/// As [`verify_message`]; `OtherText`, `OtherAddress`.
pub fn verify_message_against(bytes: &[u8], text: &str, address: &str) -> Result<Verified, Fault> {
    let v =
        message::verify_against(bytes, text.as_bytes(), address.as_bytes()).map_err(Fault::of)?;
    Ok(verified(bytes, v))
}

fn verified(bytes: &[u8], v: message::Verified) -> Verified {
    Verified {
        record: Record::of(bytes, &v.parts),
        key: hex(&v.key),
    }
}
