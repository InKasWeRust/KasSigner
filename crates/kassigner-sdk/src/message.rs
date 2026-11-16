// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A message signed by a unit: the text out, the record of text, address and
//! signature back ([`kassigner_protocol::message`]), checked as rusty-kaspa
//! signs it, BIP340 over `personal_message_hash`
//! (`wallet/core/src/message.rs`).
//!
//! The text goes as one bare code, or as frames of [`Format::Opaque`], which a
//! unit takes as text ([`codes`]). [`is_signable`] says whether a unit signs
//! it: no space ends a line or the text, and no line break ends it, which a
//! screen shows as nothing.
//!
//! [`verify`] checks a record; [`verify_against`] also holds it to the text
//! sent and the address expected, as a login needs. A record from another
//! network is refused, as on a unit.

use kassigner_kaspa::address::{self, Version};
use kassigner_kaspa::bip340;
use kassigner_kaspa::sighash::personal_message_hash;
use kassigner_protocol::frame::Format;
use kassigner_protocol::message::{self as record, read_hex, Parts};
use kassigner_protocol::profile::Profile;

use crate::transport::{Codes, TransportError};
use crate::Network;

pub use kassigner_protocol::message::{is_signable, is_text};

/// The format a text's frames carry.
pub const FORMAT: Format = Format::Opaque;

/// Why a record did not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageError {
    /// Not a text a unit signs: empty, or a character its screen does not
    /// show.
    NotText,
    /// A space ends a line or the text, or a line break ends it: a unit does
    /// not sign what its screen shows as nothing.
    TrailingWhitespace,
    /// Not a signed message record.
    NotARecord,
    /// The record's address does not read, or is not a Schnorr key's.
    NotAKeyAddress,
    /// The record's address is off mainnet: the network it names.
    NotMainnet(Network),
    /// The signature does not verify over the text against the address's key.
    Fails,
    /// The text signed is not the one expected.
    OtherText,
    /// The address is not the one expected.
    OtherAddress,
    /// The text could not be shown, as [`TransportError`] says.
    Transport(TransportError),
}

impl From<TransportError> for MessageError {
    fn from(e: TransportError) -> Self {
        MessageError::Transport(e)
    }
}

/// How `text` is shown to a unit of `profile`.
///
/// # Errors
///
/// `NotText`; `TrailingWhitespace`; `Transport` for too many frames.
pub fn codes(text: &[u8], profile: &Profile) -> Result<Codes, MessageError> {
    if !is_text(text) {
        return Err(MessageError::NotText);
    }
    if !is_signable(text) {
        return Err(MessageError::TrailingWhitespace);
    }
    Ok(Codes::plan(text.len(), profile)?)
}

/// A verified record: its parts, and the signing address's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub parts: Parts,
    /// The x-only key the address carries, which verified the signature.
    pub key: [u8; 32],
}

/// Read `bytes` as a record and verify its signature.
///
/// # Errors
///
/// `NotARecord`, `NotAKeyAddress`, `NotMainnet`, `Fails`.
pub fn verify(bytes: &[u8]) -> Result<Verified, MessageError> {
    let parts = record::read(bytes).ok_or(MessageError::NotARecord)?;
    let mut payload = [0u8; 33];
    let (network, version, n) = address::decode(&bytes[parts.address.clone()], &mut payload)
        .map_err(|_| MessageError::NotAKeyAddress)?;
    if version != Version::PubKey || n != 32 {
        return Err(MessageError::NotAKeyAddress);
    }
    if network != Network::Mainnet {
        return Err(MessageError::NotMainnet(network));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&payload[..32]);
    // 128 hex digits, by `record::read`'s check: this always reads.
    let mut signature = [0u8; 64];
    if !read_hex(&bytes[parts.signature.clone()], &mut signature) {
        return Err(MessageError::NotARecord);
    }
    let hash = personal_message_hash(&bytes[parts.text.clone()]);
    if !bip340::verify(&key, &hash, &signature) {
        return Err(MessageError::Fails);
    }
    Ok(Verified { parts, key })
}

/// [`verify`], and the record's text is `text` and its address `address`,
/// trimmed.
///
/// # Errors
///
/// As [`verify`]; `OtherText`, `OtherAddress`.
pub fn verify_against(bytes: &[u8], text: &[u8], address: &[u8]) -> Result<Verified, MessageError> {
    let v = verify(bytes)?;
    if &bytes[v.parts.text.clone()] != text {
        return Err(MessageError::OtherText);
    }
    if &bytes[v.parts.address.clone()] != address.trim_ascii() {
        return Err(MessageError::OtherAddress);
    }
    Ok(v)
}
