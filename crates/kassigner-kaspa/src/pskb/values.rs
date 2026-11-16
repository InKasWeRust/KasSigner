// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Every value of a bundle's global map, inputs and outputs, held to what
//! upstream reads it as: upstream deserializes every field in every
//! transaction, so it refuses an `inputCount` of `-1`, a `finalScriptSig`
//! not hex, a `partialSigs` key not a point.
//!
//! A member upstream keeps as a value (`proprietaries` entries, and unknown
//! members of a global map, input or output, its flattened `unknowns`) is
//! read into a `serde_value::Value`: numbers must fit a double, strings be
//! text. What upstream skips (a transaction's unknown members, a
//! `utxoEntry`'s or key source's extra ones) needs only JSON's grammar,
//! which the lexer holds. A conformance test checks these against upstream.

use super::lexer::{ascii, decode_key, Lexer, Token};
use super::schema::{Field, Scope, Span};
use super::transaction::{
    char_count, covenant, entry, hash, hex_into, is_hex, members, number, optional_number,
    outpoint, scalar, MAX_BUNDLE_VERSION,
};
use crate::bip32_public::{is_path, is_public_key, is_xpub_text};

/// Whether a member in `scope` keyed `field` (`None` for one upstream does
/// not know there) has a value upstream reads; fields the reader reads are
/// held as it holds them.
pub(crate) fn sound(doc: &[u8], scope: Scope, field: Option<Field>, value: Span) -> bool {
    use Field as F;
    use Scope as S;
    match (scope, field) {
        // `Global`.
        (S::Global, Some(F::Version)) => {
            number(doc, value).is_some_and(|v| v <= MAX_BUNDLE_VERSION)
        }
        (S::Global, Some(F::TxVersion)) => {
            number(doc, value).is_some_and(|v| u16::try_from(v).is_ok())
        }
        (S::Global, Some(F::FallbackLockTime)) => optional_number(doc, value).is_some(),
        (S::Global, Some(F::InputsModifiable | F::OutputsModifiable)) => boolean(doc, value),
        // Not held to the arrays' lengths, as upstream does not hold them.
        (S::Global, Some(F::InputCount | F::OutputCount)) => number(doc, value).is_some(),
        (S::Global, Some(F::Xpubs)) => {
            map(doc, value, |key, v| is_xpub_text(key) && key_source(doc, v))
        }
        (S::Global, Some(F::Id)) => null(doc, value) || hash_text(doc, value),
        (S::Global, Some(F::Payload)) => bytes(doc, value),

        // `Input`.
        (S::Input(_), Some(F::PreviousOutpoint)) => outpoint(doc, value).is_some(),
        // Optional upstream; the reader refuses `null`, as the hash needs the
        // amount and script.
        (S::Input(_), Some(F::UtxoEntry)) => {
            null(doc, value) || entry(doc, value).is_some_and(|e| script_text(e.script))
        }
        (S::Input(_), Some(F::Sequence | F::MinTime)) => optional_number(doc, value).is_some(),
        (S::Input(_), Some(F::SigOpCount)) => {
            optional_number(doc, value).is_some_and(|n| n.is_none_or(|n| n <= 0xFF))
        }
        (S::Input(_), Some(F::PartialSigs)) => map(doc, value, |key, v| {
            public_key_text(key) && signature(doc, v)
        }),
        // A `SigHashType`, a `u8`; its kind is checked only when used.
        (S::Input(_), Some(F::SighashType)) => number(doc, value).is_some_and(|n| n <= 0xFF),
        (S::Input(_), Some(F::FinalScriptSig)) => bytes(doc, value),
        // A `PhantomData<()>`, which serde reads only from `null`.
        (S::Input(_), Some(F::Hidden)) => null(doc, value),

        // `Output`.
        (S::Output(_), Some(F::Amount)) => number(doc, value).is_some(),
        (S::Output(_), Some(F::ScriptPublicKey)) => {
            matches!(scalar(doc, value), Some(Token::String { raw, .. }) if script_text(raw))
        }
        (S::Output(_), Some(F::Covenant)) => covenant(doc, value).is_some(),

        // Both.
        (S::Input(_) | S::Output(_), Some(F::RedeemScript)) => bytes(doc, value),
        (S::Input(_) | S::Output(_), Some(F::Bip32Derivations)) => map(doc, value, |key, v| {
            public_key_text(key) && (null(doc, v) || key_source(doc, v))
        }),

        // Every level's `proprietaries`: a map of values upstream keeps.
        (_, Some(F::Proprietaries)) => map(doc, value, |_, _| true) && kept(doc, value),

        // The rest is upstream's `unknowns`, kept as values: keys it does not
        // know there, a key named `unknowns` and another level's names too.
        _ => kept(doc, value),
    }
}

/// Whether the value at `span` reads as a `serde_value::Value`: every number
/// a finite double, every string text with its escapes paired. The walk has
/// held its shape to JSON's.
fn kept(doc: &[u8], span: Span) -> bool {
    let Some(src) = doc.get(span.start..span.end) else {
        return false;
    };
    let mut lex = Lexer::new(src);
    while let Some(token) = lex.next_token() {
        let sound = match token {
            Ok(Token::String { raw, start, .. }) => {
                decode_key(raw, span.start + start, &mut []).is_ok()
            }
            Ok(Token::Number { raw }) => finite(raw),
            Ok(_) => true,
            Err(_) => false,
        };
        if !sound {
            return false;
        }
    }
    true
}

/// A JSON number as serde_json reads one into a value: an integer that fits
/// `u64` or `i64` as is, anything else as a double, refused past its range.
fn finite(raw: &[u8]) -> bool {
    core::str::from_utf8(raw)
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .is_some_and(f64::is_finite)
}

fn boolean(doc: &[u8], span: Span) -> bool {
    matches!(scalar(doc, span), Some(Token::True | Token::False))
}

fn null(doc: &[u8], span: Span) -> bool {
    matches!(scalar(doc, span), Some(Token::Null))
}

/// A 32-byte hash: exactly 64 hex characters. Upstream's `Hash` is looser,
/// decoding the first 64 of a longer even run and dropping the rest; this
/// refuses the longer form on purpose, as the safe JSON reader does.
fn hash_text(doc: &[u8], span: Span) -> bool {
    matches!(scalar(doc, span), Some(Token::String { raw, .. }) if hash(raw).is_some())
}

/// `null` or hex, as `serde_bytes_optional` reads a `Vec<u8>`: an even
/// number, zero included, of hex characters in either case.
fn bytes(doc: &[u8], span: Span) -> bool {
    match scalar(doc, span) {
        Some(Token::Null) => true,
        Some(Token::String { raw, .. }) => is_hex(raw),
        _ => false,
    }
}

/// A script public key's text: its version as four hex characters, then the
/// script's hex.
fn script_text(hex: &[u8]) -> bool {
    char_count(hex) >= 4 && is_hex(hex)
}

/// A public key's text as `secp256k1::PublicKey::from_str` reads it: 66 or
/// 130 hex characters in either case, a point either way.
fn public_key_text(text: &[u8]) -> bool {
    let mut key = [0u8; 65];
    let n = text.len() / 2;
    (text.len() == 66 || text.len() == 130)
        && decode(text, &mut key[..n])
        && is_public_key(&key[..n])
}

/// A `partialSigs` signature, upstream's `Signature`: one member, `schnorr`
/// and 64 bytes of hex, or `eCDSA` and a DER signature.
fn signature(doc: &[u8], span: Span) -> bool {
    let mut seen = 0usize;
    map(doc, span, |key, v| {
        seen += 1;
        match (key, scalar(doc, v)) {
            (b"schnorr", Some(Token::String { raw, .. })) => char_count(raw) == 128 && is_hex(raw),
            (b"eCDSA", Some(Token::String { raw, .. })) => der_text(raw),
            _ => false,
        }
    }) && seen == 1
}

/// A key source, upstream's `KeySource`: `keyFingerprint`, eight hex
/// characters, and `derivationPath`, a path, each once; other members are
/// skipped, as serde skips them.
fn key_source(doc: &[u8], span: Span) -> bool {
    let (mut fingerprint, mut path) = (false, false);
    map(doc, span, |key, v| {
        let text = match scalar(doc, v) {
            Some(Token::String { raw, .. }) => Some(raw),
            _ => None,
        };
        match key {
            b"keyFingerprint" if !fingerprint => {
                fingerprint = true;
                text.is_some_and(|t| char_count(t) == 8 && is_hex(t))
            }
            b"derivationPath" if !path => {
                path = true;
                text.is_some_and(|t| is_path(ascii(t)))
            }
            b"keyFingerprint" | b"derivationPath" => false,
            _ => true,
        }
    }) && fingerprint
        && path
}

/// Whether the value at `span` is an object `f` takes every member of, its
/// key decoded as serde_json decodes it. A key too long to be read here is
/// handed over empty.
fn map(doc: &[u8], span: Span, mut f: impl FnMut(&[u8], Span) -> bool) -> bool {
    members(doc, span, |key, v| f(key.unwrap_or(&[]), v).then_some(())).is_some()
}

/// A map key's hex decoded into `out`, exactly half as long; false for a
/// character that is not hex.
fn decode(hex: &[u8], out: &mut [u8]) -> bool {
    let nibble = crate::hex::nibble;
    hex.len() == 2 * out.len()
        && out.iter_mut().zip(hex.chunks_exact(2)).all(|(o, pair)| {
            match (nibble(pair[0]), nibble(pair[1])) {
                (Some(hi), Some(lo)) => {
                    *o = hi << 4 | lo;
                    true
                }
                _ => false,
            }
        })
}

/// An ECDSA signature's text as `secp256k1::ecdsa::Signature::from_str`
/// reads it: hex of at most 72 bytes that
/// `secp256k1_ecdsa_signature_parse_der` takes.
fn der_text(hex: &[u8]) -> bool {
    let mut der = [0u8; 72];
    let len = char_count(hex);
    let n = len / 2;
    len <= 144 && hex_into(hex, &mut der[..n]) && der_signature(&der[..n])
}

/// `secp256k1_ecdsa_sig_parse`'s answer for `sig`: a DER sequence of exactly
/// two integers and nothing after. Values past the curve's order or negative
/// still parse (it keeps a zero).
fn der_signature(sig: &[u8]) -> bool {
    let Some((&0x30, rest)) = sig.split_first() else {
        return false;
    };
    let Some((len, body)) = der_len(rest) else {
        return false;
    };
    if len != body.len() as u64 {
        return false;
    }
    der_integer(body)
        .and_then(der_integer)
        .is_some_and(<[u8]>::is_empty)
}

/// A DER length at the front of `s`, and what follows it:
/// `secp256k1_der_read_len`, whose `size_t` is 64 bits where upstream runs.
fn der_len(s: &[u8]) -> Option<(u64, &[u8])> {
    let (&b1, mut rest) = s.split_first()?;
    if b1 == 0xFF || b1 == 0x80 {
        return None;
    }
    if b1 & 0x80 == 0 {
        return Some((u64::from(b1), rest));
    }
    let left = usize::from(b1 & 0x7F);
    if left > rest.len() || rest[0] == 0 || left > 8 {
        return None;
    }
    let mut len = 0u64;
    for &b in &rest[..left] {
        len = (len << 8) | u64::from(b);
    }
    rest = &rest[left..];
    if len > rest.len() as u64 || len < 128 {
        return None;
    }
    Some((len, rest))
}

/// A DER integer at the front of `s`, and what follows it:
/// `secp256k1_der_parse_integer`, which refuses only its form.
fn der_integer(s: &[u8]) -> Option<&[u8]> {
    let (&0x02, rest) = s.split_first()? else {
        return None;
    };
    let (len, rest) = der_len(rest)?;
    let len = usize::try_from(len).ok()?;
    if len == 0 || len > rest.len() {
        return None;
    }
    if len > 1 && rest[0] == 0x00 && rest[1] & 0x80 == 0 {
        return None;
    }
    if len > 1 && rest[0] == 0xFF && rest[1] & 0x80 == 0x80 {
        return None;
    }
    Some(&rest[len..])
}
