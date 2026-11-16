// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Putting a signature into a bundle, as upstream's
//! `PSKT<Signer>::pass_signature_sync` (`wallet/pskt/src/pskt.rs`) does: for
//! each signed input, the signer's key and key source into
//! `bip32Derivations`, the key and signature into `partialSigs`.
//!
//! Both are `BTreeMap`s by compressed public key: a new key goes in at its
//! place in key order, a key already there has its value replaced. The key
//! source is the caller's, written as given ([`Derivation`]).
//!
//! Upstream parses each map key (hex, either case) into a
//! `secp256k1::PublicKey` and orders by compressed bytes, so a key is placed
//! by what it encodes: 66 hex characters, or 130 uncompressed or hybrid. Of
//! a key written twice upstream keeps the later value, the one read and
//! replaced here. A [`Checked`] bundle's keys are on the curve; here they
//! are only compared.
//!
//! [`splices`] returns edits for [`emit`](super::emit()) to apply, their
//! text in a caller's buffer of [`text_len`] bytes.

use super::emit::{
    write_key_prefix, write_schnorr_value, Splice, KEY_PREFIX_LEN, SCHNORR_VALUE_LEN, SIGNATURE_LEN,
};
use super::lexer::{Lexer, Token};
use super::schema::{walk, Checked, Field, ParseError, Scope, Span, Visitor};
use super::transaction::{char_count, hex_into, members, scalar};
use crate::bip32_public::PUBLIC_KEY_SIZE;

/// The key source written for a signer's key under `bip32Derivations`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Derivation<'s> {
    /// `null`: the signer has no key source to give.
    Null,
    /// A JSON value, written exactly as given.
    Value(&'s [u8]),
}

impl Derivation<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Derivation::Null => b"null",
            Derivation::Value(v) => v,
        }
    }
}

/// One signature to put into a bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialSig<'s> {
    /// The input it signs.
    pub input: usize,
    /// The signer's compressed public key.
    pub public_key: &'s [u8; PUBLIC_KEY_SIZE],
    /// The Schnorr signature, with no sighash byte.
    pub signature: &'s [u8; SIGNATURE_LEN],
    /// What to write for the key under `bip32Derivations`.
    pub derivation: Derivation<'s>,
}

/// Why the edits could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditError {
    /// The document is not shaped like a bundle.
    Parse(ParseError),
    /// The bundle holds no transaction at `index`.
    NoSuchTransaction { index: usize, count: usize },
    /// A transaction lists its global map, its inputs or its outputs twice.
    RepeatedSection,
    /// The transaction has no input at `index`.
    NoSuchInput { index: usize },
    /// The input lacks a field upstream requires (the first in its order),
    /// or the `partialSigs` or `bip32Derivations` to write into.
    Missing { input: usize, field: Field },
    /// That field is repeated, not an object, or has a key that is not a
    /// public key's hex; or an input value upstream does not read, `field`
    /// [`Field::Unknowns`] for a member it keeps as unknown.
    Malformed { input: usize, field: Field },
    /// The call carries two signatures for one key on one input.
    SameKeyTwice { input: usize },
    /// A [`Derivation::Value`] is not exactly one JSON value.
    BadDerivation { input: usize },
    /// The text buffer is shorter than [`text_len`].
    TextTooSmall,
    /// The splice buffer holds fewer than two per signature.
    SplicesTooSmall,
}

impl From<ParseError> for EditError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::RepeatedSection => EditError::RepeatedSection,
            ParseError::MissingField {
                scope: Scope::Input(input),
                field,
            } => EditError::Missing { input, field },
            ParseError::Malformed {
                scope: Scope::Input(input),
                field,
            }
            | ParseError::Duplicate {
                scope: Scope::Input(input),
                field,
            } => EditError::Malformed { input, field },
            e => EditError::Parse(e),
        }
    }
}

/// What an input already holds for one key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Presence {
    /// The key has a signature in `partialSigs`.
    pub signed: bool,
    /// That signature's 64 bytes if Schnorr; `None` for ECDSA or none. Lets
    /// a signer reading back its reply verify what it wrote.
    pub schnorr: Option<[u8; SIGNATURE_LEN]>,
    /// The span of the key's value in `bip32Derivations`, when it has one.
    pub derivation: Option<Span>,
}

/// What input `input` of transaction `index` already holds for
/// `public_key`: whether it has signed, and its key source. A signer asks
/// before signing and hands the derivation span back to [`splices`] as
/// [`Derivation::Value`], so the coordinator's entry survives.
///
/// # Errors
///
/// Everything [`splices`] refuses about locating the maps.
pub fn presence(
    bundle: Checked<'_>,
    index: usize,
    input: usize,
    public_key: &[u8; PUBLIC_KEY_SIZE],
) -> Result<Presence, EditError> {
    let doc = bundle.doc();
    let (partial, derivations) = locate(doc, index, input)?;
    let (signed, schnorr) = match place(doc, partial, public_key).ok_or(EditError::Malformed {
        input,
        field: Field::PartialSigs,
    })? {
        Place::Replace(span) => (true, schnorr_of(doc, span)),
        _ => (false, None),
    };
    let derivation = match place(doc, derivations, public_key).ok_or(EditError::Malformed {
        input,
        field: Field::Bip32Derivations,
    })? {
        Place::Replace(span) => Some(span),
        _ => None,
    };
    Ok(Presence {
        signed,
        schnorr,
        derivation,
    })
}

/// A `partialSigs` value's Schnorr signature, `{"schnorr":"<128 hex>"}`
/// (upstream's `Signature::Schnorr`), escapes decoded; `None` for ECDSA. A
/// [`Checked`] bundle's value is one of the two shapes.
fn schnorr_of(doc: &[u8], span: Span) -> Option<[u8; SIGNATURE_LEN]> {
    let mut sig = None;
    members(doc, span, |key, v| {
        if key == Some(b"schnorr".as_slice()) {
            let mut bytes = [0u8; SIGNATURE_LEN];
            match scalar(doc, v)? {
                Token::String { raw, .. } if hex_into(raw, &mut bytes) => sig = Some(bytes),
                _ => return None,
            }
        }
        Some(())
    })?;
    sig
}

/// One entry of an input's `bip32Derivations`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivationEntry<'d> {
    /// The compressed public key the entry is for, however it was written.
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    /// The `keyFingerprint` hex and `derivationPath` text, as written,
    /// escapes and all, unless the entry is `null`. Read the path through
    /// [`parse_path_chars`] over [`ascii`](super::lexer::ascii), decoded as
    /// upstream reads it.
    ///
    /// [`parse_path_chars`]: crate::bip32_public::parse_path_chars
    pub source: Option<(&'d [u8], &'d [u8])>,
}

/// Call `f` with each entry of the input's `bip32Derivations`, in written
/// order, until it returns `false`.
///
/// # Errors
///
/// Everything [`splices`] refuses about locating the map, and `Malformed`
/// for an entry that is not `null` or a key source.
pub fn derivations<'d>(
    bundle: Checked<'d>,
    index: usize,
    input: usize,
    mut f: impl FnMut(DerivationEntry<'d>) -> bool,
) -> Result<(), EditError> {
    let doc = bundle.doc();
    let (_, map) = locate(doc, index, input)?;
    let malformed = EditError::Malformed {
        input,
        field: Field::Bip32Derivations,
    };
    each_member(doc, map, malformed, |public_key, value| {
        let source = if matches!(scalar(doc, value), Some(Token::Null)) {
            None
        } else {
            Some(key_source(doc, value).ok_or(malformed)?)
        };
        Ok(f(DerivationEntry { public_key, source }))
    })
}

/// The `derivationPath` of the first key source in output `output`'s
/// `bip32Derivations`, as written (read it as [`derivations`]' paths are):
/// a device rebuilds a change output's script from it. `None` for no such
/// transaction, output, map or key source.
pub fn output_path(bundle: Checked<'_>, index: usize, output: usize) -> Option<&[u8]> {
    let doc = bundle.doc();
    let mut l = OutputLocator {
        target: index,
        output,
        current: None,
        map: None,
    };
    walk(doc, &mut l).ok()?;
    let map = l.map?;
    let malformed = EditError::Malformed {
        input: output,
        field: Field::Bip32Derivations,
    };
    let mut path = None;
    each_member(doc, map, malformed, |_, value| {
        path = key_source(doc, value).map(|(_, p)| p);
        Ok(path.is_none())
    })
    .ok()?;
    path
}

/// Finds output `output`'s `bip32Derivations` in transaction `target`.
struct OutputLocator {
    target: usize,
    output: usize,
    current: Option<usize>,
    map: Option<Span>,
}

impl Visitor for OutputLocator {
    fn transaction(&mut self, index: usize) -> Result<(), ParseError> {
        self.current = Some(index);
        Ok(())
    }

    fn field(&mut self, scope: Scope, field: Field, value: Span) -> Result<(), ParseError> {
        if self.current == Some(self.target)
            && scope == Scope::Output(self.output)
            && field == Field::Bip32Derivations
            && self.map.is_none()
        {
            self.map = Some(value);
        }
        Ok(())
    }

    fn holds_values(&self) -> bool {
        false
    }
}

/// Call `f` with the key of each entry of the input's `partialSigs`, who
/// has signed it, in written order until it returns `false`. Values are not
/// read; [`presence`] reads a signature back.
///
/// # Errors
///
/// Everything [`splices`] refuses about locating the map, and `Malformed`
/// for a key that is not a public key's hex.
pub fn signers(
    bundle: Checked<'_>,
    index: usize,
    input: usize,
    mut f: impl FnMut([u8; PUBLIC_KEY_SIZE]) -> bool,
) -> Result<(), EditError> {
    let doc = bundle.doc();
    let (map, _) = locate(doc, index, input)?;
    let malformed = EditError::Malformed {
        input,
        field: Field::PartialSigs,
    };
    each_member(doc, map, malformed, |public_key, _| Ok(f(public_key)))
}

/// Call `f` with each member of the map at `map`, its key decoded and its
/// value's span, until it returns `Ok(false)`; anything but a map of public
/// keys' hex is `malformed`.
fn each_member(
    doc: &[u8],
    map: Span,
    malformed: EditError,
    mut f: impl FnMut([u8; PUBLIC_KEY_SIZE], Span) -> Result<bool, EditError>,
) -> Result<(), EditError> {
    let src = doc.get(map.start..map.end).ok_or(malformed)?;
    let mut lex = Lexer::new(src);
    if !matches!(
        lex.next_token().ok_or(malformed)?.ok().ok_or(malformed)?,
        Token::ObjectStart
    ) {
        return Err(malformed);
    }
    loop {
        match lex.next_token().ok_or(malformed)?.ok().ok_or(malformed)? {
            Token::ObjectEnd => return Ok(()),
            Token::Comma => {}
            Token::String { raw, .. } => {
                let public_key = decode_key(raw).ok_or(malformed)?;
                if !matches!(
                    lex.next_token().ok_or(malformed)?.ok().ok_or(malformed)?,
                    Token::Colon
                ) {
                    return Err(malformed);
                }
                let (vs, ve) = lex.skip_value().map_err(|_| malformed)?;
                let value = Span {
                    start: map.start + vs,
                    end: map.start + ve,
                };
                if !f(public_key, value)? {
                    return Ok(());
                }
            }
            _ => return Err(malformed),
        }
    }
}

/// The two strings of a key source, as written; other members are skipped,
/// whatever their values, as upstream's `KeySource` skips them.
fn key_source(doc: &[u8], span: Span) -> Option<(&[u8], &[u8])> {
    let mut fingerprint = None;
    let mut path = None;
    let text = |v: Span| match scalar(doc, v)? {
        Token::String { raw, .. } => Some(raw),
        _ => None,
    };
    members(doc, span, |key, v| {
        match key {
            Some(b"keyFingerprint") if fingerprint.is_none() => fingerprint = Some(text(v)?),
            Some(b"derivationPath") if path.is_none() => path = Some(text(v)?),
            Some(b"keyFingerprint" | b"derivationPath") => return None,
            _ => {}
        }
        Some(())
    })?;
    Some((fingerprint?, path?))
}

/// Bytes of generated text [`splices`] may need for `sigs`: a member in two
/// maps per signature, each with room for a comma.
pub fn text_len(sigs: &[PartialSig<'_>]) -> usize {
    sigs.iter().fold(0usize, |total, s| {
        total
            .saturating_add(2 * (1 + KEY_PREFIX_LEN) + SCHNORR_VALUE_LEN)
            .saturating_add(s.derivation.bytes().len())
    })
}

/// The edits that put `sigs` into transaction `index`: up to two splices a
/// signature, written to `out` sorted for [`emit`](super::emit()); returns
/// how many.
///
/// # Errors
///
/// `TextTooSmall` or `SplicesTooSmall` before anything is looked at. Otherwise
/// the first refusal found, input by input.
pub fn splices<'t>(
    bundle: Checked<'_>,
    index: usize,
    sigs: &[PartialSig<'_>],
    text: &'t mut [u8],
    out: &mut [Splice<'t>],
) -> Result<usize, EditError> {
    if text.len() < text_len(sigs) {
        return Err(EditError::TextTooSmall);
    }
    if out.len() < sigs.len().saturating_mul(2) {
        return Err(EditError::SplicesTooSmall);
    }
    let doc = bundle.doc();
    let mut e = Edit {
        doc,
        free: text,
        out,
        n: 0,
    };

    // Input by input, then key by key, ascending: upstream's map order.
    let mut last_input: Option<usize> = None;
    while let Some(input) = sigs
        .iter()
        .map(|s| s.input)
        .filter(|&i| last_input.is_none_or(|l| i > l))
        .min()
    {
        last_input = Some(input);
        let (partial, derivations) = locate(doc, index, input)?;
        let mut last_key: Option<&[u8; PUBLIC_KEY_SIZE]> = None;
        let mut empty = [false; 2];
        loop {
            let mut next: Option<&PartialSig<'_>> = None;
            let mut ties = 0usize;
            for s in sigs.iter().filter(|s| s.input == input) {
                if last_key.is_some_and(|k| s.public_key <= k) {
                    continue;
                }
                match next {
                    Some(b) if s.public_key > b.public_key => {}
                    Some(b) if s.public_key == b.public_key => ties += 1,
                    _ => {
                        next = Some(s);
                        ties = 1;
                    }
                }
            }
            let Some(s) = next else {
                break;
            };
            if ties > 1 {
                return Err(EditError::SameKeyTwice { input });
            }
            if let Derivation::Value(v) = s.derivation {
                if !one_value(v) {
                    return Err(EditError::BadDerivation { input });
                }
            }
            let member = Member {
                input,
                key: s.public_key,
            };
            e.put(
                Map {
                    span: partial,
                    field: Field::PartialSigs,
                },
                member,
                Value::Schnorr(s.signature),
                &mut empty[0],
            )?;
            e.put(
                Map {
                    span: derivations,
                    field: Field::Bip32Derivations,
                },
                member,
                Value::Raw(s.derivation.bytes()),
                &mut empty[1],
            )?;
            last_key = Some(s.public_key);
        }
    }

    // Stable, so members inserted at one place keep their key order.
    let out = &mut e.out[..e.n];
    for i in 1..out.len() {
        let mut j = i;
        while j > 0 && out[j - 1].at > out[j].at {
            out.swap(j - 1, j);
            j -= 1;
        }
    }
    Ok(e.n)
}

/// A derivation to write for an input's key, with no signature: a hint for
/// the signer. `derivation` is the member's JSON value, as
/// [`super::write::key_source`] writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hint<'s> {
    pub input: usize,
    pub public_key: &'s [u8; PUBLIC_KEY_SIZE],
    pub derivation: &'s [u8],
}

/// Bytes [`hint_splices`] needs in `text` for `hints`.
pub fn hint_text_len(hints: &[Hint<'_>]) -> usize {
    hints.iter().fold(0usize, |total, h| {
        total
            .saturating_add(1 + KEY_PREFIX_LEN)
            .saturating_add(h.derivation.len())
    })
}

/// Splices writing `hints` into their inputs' `bip32Derivations` as
/// [`splices`] writes a signature's derivation, to `out`, their text in
/// `text`, sorted for [`emit`](super::emit::emit); returns how many.
///
/// # Errors
///
/// As [`splices`]: `TextTooSmall`, `SplicesTooSmall`, `SameKeyTwice`,
/// `BadDerivation` for a value that is not one JSON value, and the bundle's
/// own faults.
pub fn hint_splices<'t>(
    bundle: Checked<'_>,
    index: usize,
    hints: &[Hint<'_>],
    text: &'t mut [u8],
    out: &mut [Splice<'t>],
) -> Result<usize, EditError> {
    if text.len() < hint_text_len(hints) {
        return Err(EditError::TextTooSmall);
    }
    if out.len() < hints.len() {
        return Err(EditError::SplicesTooSmall);
    }
    let doc = bundle.doc();
    let mut e = Edit {
        doc,
        free: text,
        out,
        n: 0,
    };
    let mut last_input: Option<usize> = None;
    while let Some(input) = hints
        .iter()
        .map(|h| h.input)
        .filter(|&i| last_input.is_none_or(|l| i > l))
        .min()
    {
        last_input = Some(input);
        let (_, derivations) = locate(doc, index, input)?;
        let mut last_key: Option<&[u8; PUBLIC_KEY_SIZE]> = None;
        let mut empty = false;
        loop {
            let mut next: Option<&Hint<'_>> = None;
            let mut ties = 0usize;
            for h in hints.iter().filter(|h| h.input == input) {
                if last_key.is_some_and(|k| h.public_key <= k) {
                    continue;
                }
                match next {
                    Some(b) if h.public_key > b.public_key => {}
                    Some(b) if h.public_key == b.public_key => ties += 1,
                    _ => {
                        next = Some(h);
                        ties = 1;
                    }
                }
            }
            let Some(h) = next else {
                break;
            };
            if ties > 1 {
                return Err(EditError::SameKeyTwice { input });
            }
            if !one_value(h.derivation) {
                return Err(EditError::BadDerivation { input });
            }
            e.put(
                Map {
                    span: derivations,
                    field: Field::Bip32Derivations,
                },
                Member {
                    input,
                    key: h.public_key,
                },
                Value::Raw(h.derivation),
                &mut empty,
            )?;
            last_key = Some(h.public_key);
        }
    }
    let out = &mut e.out[..e.n];
    for i in 1..out.len() {
        let mut j = i;
        while j > 0 && out[j - 1].at > out[j].at {
            out.swap(j - 1, j);
            j -= 1;
        }
    }
    Ok(e.n)
}

/// Where the generated text goes, and the edits made so far.
struct Edit<'d, 't, 'o> {
    doc: &'d [u8],
    free: &'t mut [u8],
    out: &'o mut [Splice<'t>],
    n: usize,
}

#[derive(Clone, Copy)]
struct Map {
    span: Span,
    field: Field,
}

#[derive(Clone, Copy)]
struct Member<'k> {
    input: usize,
    key: &'k [u8; PUBLIC_KEY_SIZE],
}

enum Value<'v> {
    Schnorr(&'v [u8; SIGNATURE_LEN]),
    Raw(&'v [u8]),
}

impl Value<'_> {
    fn size(&self) -> usize {
        match self {
            Value::Schnorr(_) => SCHNORR_VALUE_LEN,
            Value::Raw(v) => v.len(),
        }
    }

    fn write(&self, out: &mut [u8]) -> usize {
        match self {
            Value::Schnorr(s) => write_schnorr_value(s, out),
            Value::Raw(v) => {
                out[..v.len()].copy_from_slice(v);
                v.len()
            }
        }
    }
}

/// Where a key goes in a map.
enum Place {
    /// The key is there: replace its value.
    Replace(Span),
    /// Insert before the member starting here, the first with a greater key.
    Before(usize),
    /// Insert after the last member, which ends here.
    After(usize),
    /// The map is empty: insert just after its opening brace.
    Empty(usize),
}

impl<'t> Edit<'_, 't, '_> {
    fn put(
        &mut self,
        map: Map,
        member: Member<'_>,
        value: Value<'_>,
        empty_used: &mut bool,
    ) -> Result<(), EditError> {
        let place = place(self.doc, map.span, member.key).ok_or(EditError::Malformed {
            input: member.input,
            field: map.field,
        })?;
        // A comma after a member put before another, before one put after
        // the last, and before every member but the first in an empty map.
        let (at, len, lead, key, trail) = match place {
            Place::Replace(span) => (span.start, span.end - span.start, false, false, false),
            Place::Before(at) => (at, 0, false, true, true),
            Place::After(at) => (at, 0, true, true, false),
            Place::Empty(at) => {
                let lead = *empty_used;
                *empty_used = true;
                (at, 0, lead, true, false)
            }
        };
        let size = usize::from(lead)
            + if key { KEY_PREFIX_LEN } else { 0 }
            + value.size()
            + usize::from(trail);
        if self.free.len() < size {
            return Err(EditError::TextTooSmall);
        }
        let (head, tail) = core::mem::take(&mut self.free).split_at_mut(size);
        self.free = tail;
        let mut w = 0;
        if lead {
            head[w] = b',';
            w += 1;
        }
        if key {
            w += write_key_prefix(member.key, &mut head[w..]);
        }
        w += value.write(&mut head[w..]);
        if trail {
            head[w] = b',';
        }
        let slot = self.out.get_mut(self.n).ok_or(EditError::SplicesTooSmall)?;
        *slot = Splice {
            at,
            len,
            insert: head,
        };
        self.n += 1;
        Ok(())
    }
}

/// Where `key` belongs in the map at `span`; `None` when it is not an
/// object or a key in it is not a public key's hex.
fn place(doc: &[u8], span: Span, key: &[u8; PUBLIC_KEY_SIZE]) -> Option<Place> {
    let src = doc.get(span.start..span.end)?;
    let mut lex = Lexer::new(src);
    if !matches!(lex.next_token()?.ok()?, Token::ObjectStart) {
        return None;
    }
    let open = span.start + lex.offset();
    let mut replace = None;
    let mut before = None;
    let mut last_end = None;
    loop {
        match lex.next_token()?.ok()? {
            Token::ObjectEnd => break,
            Token::Comma => {}
            Token::String { raw, start, .. } => {
                let here = decode_key(raw)?;
                if !matches!(lex.next_token()?.ok()?, Token::Colon) {
                    return None;
                }
                let (vs, ve) = lex.skip_value().ok()?;
                if here == *key {
                    // The later of two is the one upstream keeps.
                    replace = Some(Span {
                        start: span.start + vs,
                        end: span.start + ve,
                    });
                } else if before.is_none() && here > *key {
                    // `start` is just past the opening quote.
                    before = Some(span.start + start - 1);
                }
                last_end = Some(span.start + ve);
            }
            _ => return None,
        }
    }
    if lex.next_token().is_some() {
        return None;
    }
    Some(match (replace, before, last_end) {
        (Some(s), _, _) => Place::Replace(s),
        (None, Some(at), _) => Place::Before(at),
        (None, None, Some(end)) => Place::After(end),
        (None, None, None) => Place::Empty(open),
    })
}

/// A map key as upstream's `PublicKey` reads it, compressed: 66 hex
/// characters, or 130 uncompressed or hybrid (`x` and `y`'s parity), either
/// case, escapes decoded. A [`Checked`] bundle's key is a point already;
/// only the tag is looked at.
fn decode_key(raw: &[u8]) -> Option<[u8; PUBLIC_KEY_SIZE]> {
    let mut bytes = [0u8; 65];
    let n = char_count(raw) / 2;
    if !matches!(n, PUBLIC_KEY_SIZE | 65) || !hex_into(raw, &mut bytes[..n]) {
        return None;
    }
    let mut key = [0u8; PUBLIC_KEY_SIZE];
    match bytes[0] {
        2 | 3 if n == PUBLIC_KEY_SIZE => key.copy_from_slice(&bytes[..PUBLIC_KEY_SIZE]),
        4 | 6 | 7 if n == 65 => {
            key[0] = 2 | (bytes[64] & 1);
            key[1..].copy_from_slice(&bytes[1..PUBLIC_KEY_SIZE]);
        }
        _ => return None,
    }
    Some(key)
}

/// True when `v` is one complete JSON value and nothing else.
fn one_value(v: &[u8]) -> bool {
    let mut lex = Lexer::new(v);
    lex.skip_value().is_ok() && lex.next_token().is_none()
}

/// The spans of one input's `partialSigs` and `bip32Derivations` in a
/// bundle already checked whole.
fn locate(doc: &[u8], index: usize, input: usize) -> Result<(Span, Span), EditError> {
    let mut l = Locator {
        target: index,
        input,
        current: None,
        inputs: 0,
        partial: None,
        derivations: None,
        trouble: None,
    };
    let walked = walk(doc, &mut l);
    if let Some(e) = l.trouble {
        return Err(e);
    }
    let count = walked?;
    if index >= count {
        return Err(EditError::NoSuchTransaction { index, count });
    }
    if input >= l.inputs {
        return Err(EditError::NoSuchInput { index: input });
    }
    let partial = l.partial.ok_or(EditError::Missing {
        input,
        field: Field::PartialSigs,
    })?;
    let derivations = l.derivations.ok_or(EditError::Missing {
        input,
        field: Field::Bip32Derivations,
    })?;
    Ok((partial, derivations))
}

struct Locator {
    target: usize,
    input: usize,
    current: Option<usize>,
    inputs: usize,
    partial: Option<Span>,
    derivations: Option<Span>,
    trouble: Option<EditError>,
}

impl Visitor for Locator {
    fn transaction(&mut self, index: usize) -> Result<(), ParseError> {
        self.current = Some(index);
        Ok(())
    }

    fn object(&mut self, scope: Scope) -> Result<(), ParseError> {
        if self.current != Some(self.target) {
            return Ok(());
        }
        if let Scope::Input(i) = scope {
            if i != self.inputs {
                self.trouble = Some(EditError::RepeatedSection);
                return Err(ParseError::Rejected);
            }
            self.inputs += 1;
        }
        Ok(())
    }

    fn field(&mut self, scope: Scope, field: Field, value: Span) -> Result<(), ParseError> {
        if self.current != Some(self.target) || scope != Scope::Input(self.input) {
            return Ok(());
        }
        let slot = match field {
            Field::PartialSigs => &mut self.partial,
            Field::Bip32Derivations => &mut self.derivations,
            _ => return Ok(()),
        };
        if slot.is_some() {
            self.trouble = Some(EditError::Malformed {
                input: self.input,
                field,
            });
            return Err(ParseError::Rejected);
        }
        *slot = Some(value);
        Ok(())
    }

    fn holds_values(&self) -> bool {
        false
    }
}
