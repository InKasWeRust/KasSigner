// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A PSKB bundle as KasSigner's own companion has written it. The format is
//! upstream's, and `kassigner-kaspa` reads it as upstream does; what is ours
//! is turning bundles from kassigner.org, the companion of KasSigner v1.0.7,
//! which writes them by hand (`kassee/src/kspt/mod.rs`), into upstream's.
//!
//! # `covenantBinding`
//!
//! Upstream names an output's covenant binding `covenant`
//! (`wallet/pskt/src/output.rs`); the v1.0.7 companion wrote
//! `covenantBinding`, which upstream skips as unknown, leaving the binding
//! out of the review and the signature. [`upstream_names`] renames each such
//! key in place, the seven bytes saved becoming spaces before the colon.
//! Only keys are touched, found with the reader's lexer; on an input or at
//! the top level the key is unknown under either name. A bundle with both
//! names ends up with the key twice, which the reader refuses.
//!
//! # No `payload`
//!
//! Upstream 2.1.0's `Global` requires `payload`, `null` for none, as does
//! this device's reader; kassigner.org 1.0.7 never writes it.
//! [`fill_payload`] adds `"payload":null` to every global map without one,
//! growing the document by up to 15 bytes a map within its buffer. Its
//! `txPayload` on a covenant bundle is not taken for a payload: those
//! bundles are version 0, and a payload counts only from version 1.

use kassigner_kaspa::pskb::lexer::{decode_key, KEY_ROOM};
use kassigner_kaspa::pskb::{LexError, Lexer, Token};

/// The v1.0.7 companion's name for an output's covenant binding.
pub const LEGACY_COVENANT: &[u8] = b"covenantBinding";

/// Upstream's name for it.
pub const COVENANT: &[u8] = b"covenant";

/// Rename every key [`LEGACY_COVENANT`] in a decoded bundle document to
/// [`COVENANT`], in place, without changing its length. Returns how many were
/// renamed.
///
/// # Errors
///
/// The lexer's, for a document that does not tokenize. Nothing is renamed
/// past the point it stopped; the reader refuses the document anyway.
pub fn upstream_names(doc: &mut [u8]) -> Result<usize, LexError> {
    let mut renamed = 0usize;
    let mut from = 0usize;
    // One key per pass: the lexer borrows the document, so each rename comes
    // after it lets go, and the next pass resumes there.
    while let Some((start, end)) = next_legacy_key(doc, from)? {
        // `end` is the closing quote. The shorter name, its quote, then
        // spaces up to and over where the old quote was.
        let quote = start + COVENANT.len();
        doc[start..quote].copy_from_slice(COVENANT);
        doc[quote] = b'"';
        for b in &mut doc[quote + 1..=end] {
            *b = b' ';
        }
        renamed += 1;
        from = end + 1;
    }
    Ok(renamed)
}

/// The next key [`LEGACY_COVENANT`] at or after `from`: where its characters
/// start, and its closing quote.
///
/// Keys are compared decoded, escapes and all, as serde_json and the reader
/// read them. An escaped key is only longer, so the shorter name still fits.
fn next_legacy_key(doc: &[u8], from: usize) -> Result<Option<(usize, usize)>, LexError> {
    let mut lexer = Lexer::new(doc);
    lexer.seek(from);
    // The last string read; a key once a colon follows it, and decoded only
    // then, so a value is never read as a name.
    let mut pending: Option<(&[u8], usize, usize)> = None;
    while let Some(token) = lexer.next_token() {
        match token? {
            Token::Colon => {
                if let Some((raw, start, end)) = pending {
                    let mut room = [0u8; KEY_ROOM];
                    if decode_key(raw, start, &mut room)? == Some(LEGACY_COVENANT) {
                        return Ok(Some((start, end)));
                    }
                }
            }
            Token::String { raw, start, end } => {
                pending = Some((raw, start, end));
                continue;
            }
            _ => {}
        }
        pending = None;
    }
    Ok(None)
}

/// Upstream's name for a global map's payload.
pub const PAYLOAD: &[u8] = b"payload";

/// What [`fill_payload`] puts in a global map with no payload: before its
/// first member, or alone, less the comma, in an empty map.
const NULL_PAYLOAD: &[u8] = b"\"payload\":null,";

/// Why [`fill_payload`] could not finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillError {
    /// The document does not tokenize.
    Lex(LexError),
    /// The buffer has no room for the `payload` a global map lacks.
    NoRoom { needed: usize },
}

impl From<LexError> for FillError {
    fn from(e: LexError) -> Self {
        FillError::Lex(e)
    }
}

/// Add `"payload":null` to every global map of the decoded bundle document in
/// `buf[..len]` that has no `payload`, and return the document's length after.
///
/// Keys are matched decoded, as the reader matches them. A document not
/// shaped as a bundle is left as is from where that shows; the reader
/// refuses it.
///
/// # Errors
///
/// The lexer's, and `NoRoom` when `buf` cannot take the 15 bytes; the maps
/// before that one have been filled.
pub fn fill_payload(buf: &mut [u8], mut len: usize) -> Result<usize, FillError> {
    let mut from = 0usize;
    while let Some((at, empty)) = next_global_without_payload(&buf[..len], from)? {
        // In an empty map the member stands alone, with no comma after it.
        let text = if empty {
            &NULL_PAYLOAD[..NULL_PAYLOAD.len() - 1]
        } else {
            NULL_PAYLOAD
        };
        let needed = len + text.len();
        if needed > buf.len() {
            return Err(FillError::NoRoom { needed });
        }
        buf.copy_within(at..len, at + text.len());
        buf[at..at + text.len()].copy_from_slice(text);
        len = needed;
        from = at + text.len();
    }
    Ok(len)
}

/// The next global map whose value starts at or after `from` with no
/// `payload`: where its members begin, just past its `{`, and whether it is
/// empty.
fn next_global_without_payload(doc: &[u8], from: usize) -> Result<Option<(usize, bool)>, LexError> {
    let mut lex = Lexer::new(doc);
    // The bundle's array, then its transactions, each an object.
    if !matches!(lex.next_token().transpose()?, Some(Token::ArrayStart)) {
        return Ok(None);
    }
    loop {
        match lex.next_token().transpose()? {
            Some(Token::ObjectStart) => {}
            Some(Token::Comma) => continue,
            _ => return Ok(None),
        }
        // One transaction's members, up to its `}`.
        loop {
            let (raw, at) = match lex.next_token().transpose()? {
                Some(Token::String { raw, start, .. }) => (raw, start),
                Some(Token::Comma) => continue,
                _ => break,
            };
            if !matches!(lex.next_token().transpose()?, Some(Token::Colon)) {
                return Ok(None);
            }
            let mut room = [0u8; KEY_ROOM];
            let global = decode_key(raw, at, &mut room)? == Some(b"global".as_slice());
            let value = lex.offset();
            if global && value >= from {
                if let Some(found) = without_payload(doc, value)? {
                    return Ok(Some(found));
                }
            }
            lex.skip_value()?;
        }
    }
}

/// The global map whose value starts at `value`, when it has no `payload`:
/// where its members begin and whether it is empty. `None` when it has one,
/// or is not a map.
fn without_payload(doc: &[u8], value: usize) -> Result<Option<(usize, bool)>, LexError> {
    let mut lex = Lexer::new(doc);
    lex.seek(value);
    if !matches!(lex.next_token().transpose()?, Some(Token::ObjectStart)) {
        return Ok(None);
    }
    let members = lex.offset();
    let mut empty = true;
    loop {
        let (raw, at) = match lex.next_token().transpose()? {
            Some(Token::String { raw, start, .. }) => (raw, start),
            Some(Token::Comma) => continue,
            Some(Token::ObjectEnd) => return Ok(Some((members, empty))),
            _ => return Ok(None),
        };
        empty = false;
        let mut room = [0u8; KEY_ROOM];
        if decode_key(raw, at, &mut room)? == Some(PAYLOAD) {
            return Ok(None);
        }
        if !matches!(lex.next_token().transpose()?, Some(Token::Colon)) {
            return Ok(None);
        }
        lex.skip_value()?;
    }
}
