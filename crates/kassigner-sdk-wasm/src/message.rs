// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A message signed by a unit: [`kassigner_sdk_host::message`] for
//! JavaScript.

use wasm_bindgen::prelude::*;

use kassigner_sdk_host::message as host;

use crate::transport::Codes;
use crate::{Fault, Profile};

/// A signed message record's three parts, as text.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    inner: host::Record,
}

#[wasm_bindgen]
impl Record {
    /// The text signed.
    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.inner.text.clone()
    }

    /// The address that signed.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.inner.address.clone()
    }

    /// The signature, hex.
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> String {
        self.inner.signature.clone()
    }
}

impl Record {
    pub(crate) const fn over(inner: host::Record) -> Record {
        Record { inner }
    }
}

/// A verified record: its parts, and the key of the mainnet address that
/// signed.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    inner: host::Verified,
}

#[wasm_bindgen]
impl Verified {
    /// The record.
    #[wasm_bindgen(getter)]
    pub fn record(&self) -> Record {
        Record::over(self.inner.record.clone())
    }

    /// The x-only key the address carries, hex, which the signature
    /// verified against.
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> String {
        self.inner.key.clone()
    }
}

/// Whether a unit signs `text`: not empty, every character one its screen
/// shows, and no trailing space on a line or trailing line break, which
/// the screen would not show.
#[wasm_bindgen(js_name = isText)]
pub fn is_text(text: &str) -> bool {
    host::is_text(text)
}

/// The codes that show `text` to a unit of `profile`, for its Sign
/// Message.
///
/// Throws `NotText` for a text the unit refuses, `TrailingWhitespace` for
/// one it refuses to sign, `Transport` for one past its frames.
#[wasm_bindgen(js_name = messageCodes)]
pub fn message_codes(text: &str, profile: &Profile) -> Result<Codes, Fault> {
    Ok(Codes::over(host::message_codes(text, profile.inner())?))
}

/// Read `bytes` as a signed message record and verify its signature over
/// its text against its address's key.
///
/// Throws `NotARecord`, `NotAKeyAddress`, `NotMainnet(...)`, `Fails`.
#[wasm_bindgen(js_name = verifyMessage)]
pub fn verify_message(bytes: &[u8]) -> Result<Verified, Fault> {
    Ok(Verified {
        inner: host::verify_message(bytes)?,
    })
}

/// [`verify_message`], and the record's text is `text` and its address
/// `address`, as a login or a proof of ownership checks.
///
/// Throws as [`verify_message`]; `OtherText`, `OtherAddress`.
#[wasm_bindgen(js_name = verifyMessageAgainst)]
pub fn verify_message_against(bytes: &[u8], text: &str, address: &str) -> Result<Verified, Fault> {
    Ok(Verified {
        inner: host::verify_message_against(bytes, text, address)?,
    })
}
