// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Walking a PSKB document (upstream `wallet/pskt/src/pskt.rs` `Inner`,
//! `global.rs`, `input.rs`, `output.rs`; serde's `camelCase` names).
//!
//! The walk reports to a [`Visitor`] and returns no document, whose memory
//! is the caller's choice. A key it does not know is reported, never
//! skipped silently: a device must not sign what it cannot show, and
//! output copies the document through ([`emit`](super::emit::emit)), so
//! another role's fields come back as written.
//!
//! It refuses what upstream's serde refuses, in every transaction:
//!
//! - keys are matched decoded ([`decode_key`]): `"seq\u0075ence"` is the
//!   sequence;
//! - `global`, `inputs` and `outputs` appear exactly once
//!   ([`ParseError::RepeatedSection`], [`ParseError::MissingSection`]);
//! - a field with no serde default (every non-`Option`, and the
//!   `serde_bytes_optional` ones such as `payload` and `redeemScript`) is
//!   required, [`ParseError::MissingField`] naming the first in upstream's
//!   order;
//! - a struct field written twice is [`ParseError::Duplicate`]; a member
//!   upstream keeps among its unknowns may repeat, the last kept (a key
//!   named `unknowns`, `redeemScript` or `bip32Derivations` on the global
//!   map);
//! - every value is held to what upstream reads (`values`), else
//!   [`ParseError::Malformed`]. A reader of a [`Checked`] bundle, which
//!   only [`check`] makes, opts out through [`Visitor::holds_values`].

use super::lexer::{decode_key, LexError, Lexer, Token, KEY_ROOM};
use super::values;

/// Where a field was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Global,
    /// Input at this index.
    Input(usize),
    /// Output at this index.
    Output(usize),
}

/// A field's raw value: its span in the document, undecoded; the caller
/// converts only what it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn of<'a>(&self, doc: &'a [u8]) -> &'a [u8] {
        &doc[self.start..self.end]
    }
}

/// Recognised keys. Anything else arrives through `unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    // Global
    Version,
    TxVersion,
    FallbackLockTime,
    InputsModifiable,
    OutputsModifiable,
    InputCount,
    OutputCount,
    Xpubs,
    Id,
    Payload,
    // Input
    UtxoEntry,
    PreviousOutpoint,
    Sequence,
    MinTime,
    PartialSigs,
    SighashType,
    SigOpCount,
    Bip32Derivations,
    FinalScriptSig,
    /// Upstream's `hidden`, a `PhantomData<()>` it never writes, reads only
    /// as `null` and refuses twice; held here to the same.
    Hidden,
    // Output
    Amount,
    ScriptPublicKey,
    Covenant,
    // Both inputs and outputs
    RedeemScript,
    // Both, and carried through untouched
    Proprietaries,
    Unknowns,
}

fn field_for(scope: Scope, key: &[u8]) -> Option<Field> {
    // Names more than one scope uses first. On the global map,
    // `redeemScript` and `bip32Derivations` are upstream's unknowns
    // (`one_of_upstreams`).
    match key {
        b"redeemScript" => return Some(Field::RedeemScript),
        b"proprietaries" => return Some(Field::Proprietaries),
        b"unknowns" => return Some(Field::Unknowns),
        b"bip32Derivations" => return Some(Field::Bip32Derivations),
        _ => {}
    }
    match scope {
        Scope::Global => match key {
            b"version" => Some(Field::Version),
            b"txVersion" => Some(Field::TxVersion),
            b"fallbackLockTime" => Some(Field::FallbackLockTime),
            b"inputsModifiable" => Some(Field::InputsModifiable),
            b"outputsModifiable" => Some(Field::OutputsModifiable),
            b"inputCount" => Some(Field::InputCount),
            b"outputCount" => Some(Field::OutputCount),
            b"xpubs" => Some(Field::Xpubs),
            b"id" => Some(Field::Id),
            b"payload" => Some(Field::Payload),
            _ => None,
        },
        Scope::Input(_) => match key {
            b"utxoEntry" => Some(Field::UtxoEntry),
            b"previousOutpoint" => Some(Field::PreviousOutpoint),
            b"sequence" => Some(Field::Sequence),
            b"minTime" => Some(Field::MinTime),
            b"partialSigs" => Some(Field::PartialSigs),
            b"sighashType" => Some(Field::SighashType),
            b"sigOpCount" => Some(Field::SigOpCount),
            b"finalScriptSig" => Some(Field::FinalScriptSig),
            b"hidden" => Some(Field::Hidden),
            _ => None,
        },
        Scope::Output(_) => match key {
            b"amount" => Some(Field::Amount),
            b"scriptPublicKey" => Some(Field::ScriptPublicKey),
            b"covenant" => Some(Field::Covenant),
            _ => None,
        },
    }
}

/// The fields upstream's `Global` requires, in the order it declares them.
const REQUIRED_GLOBAL: [Field; 9] = [
    Field::Version,
    Field::TxVersion,
    Field::InputsModifiable,
    Field::OutputsModifiable,
    Field::InputCount,
    Field::OutputCount,
    Field::Xpubs,
    Field::Proprietaries,
    Field::Payload,
];

/// The fields upstream's `Input` requires, in the order it declares them.
/// `utxoEntry`, `sequence`, `minTime` and `sigOpCount` are optional.
const REQUIRED_INPUT: [Field; 7] = [
    Field::PreviousOutpoint,
    Field::PartialSigs,
    Field::SighashType,
    Field::RedeemScript,
    Field::Bip32Derivations,
    Field::FinalScriptSig,
    Field::Proprietaries,
];

/// The fields upstream's `Output` requires, in the order it declares them.
/// `covenant` is optional.
const REQUIRED_OUTPUT: [Field; 5] = [
    Field::Amount,
    Field::ScriptPublicKey,
    Field::RedeemScript,
    Field::Bip32Derivations,
    Field::Proprietaries,
];

/// What an object in `scope` has to carry.
fn required(scope: Scope) -> &'static [Field] {
    match scope {
        Scope::Global => &REQUIRED_GLOBAL,
        Scope::Input(_) => &REQUIRED_INPUT,
        Scope::Output(_) => &REQUIRED_OUTPUT,
    }
}

/// `field`'s bit in a set of fields.
pub(crate) const fn bit(field: Field) -> u32 {
    1 << (field as u32)
}

/// Whether `field` in `scope` is a field of upstream's struct there, which
/// serde refuses twice, rather than a member it keeps among its unknowns.
fn one_of_upstreams(scope: Scope, field: Field) -> bool {
    !matches!(
        (scope, field),
        (_, Field::Unknowns) | (Scope::Global, Field::RedeemScript | Field::Bip32Derivations)
    )
}

/// What a caller implements to receive the walk. Every method defaults to
/// nothing; returning `Err` stops the walk with that error, which is how a
/// caller enforces its own limits.
pub trait Visitor {
    /// A transaction in the bundle begins.
    fn transaction(&mut self, _index: usize) -> Result<(), ParseError> {
        Ok(())
    }
    /// An object begins: the global map, an input or an output, reported
    /// even when empty so a caller can count it.
    fn object(&mut self, _scope: Scope) -> Result<(), ParseError> {
        Ok(())
    }
    /// A recognised field, with the span of its value.
    fn field(&mut self, _scope: Scope, _field: Field, _value: Span) -> Result<(), ParseError> {
        Ok(())
    }
    /// A key this parser does not know, with its value's span: not an
    /// error, but another role's, to survive the round trip.
    fn unknown(&mut self, _scope: Scope, _key: Span, _value: Span) -> Result<(), ParseError> {
        Ok(())
    }
    /// Whether the walk holds every value to what upstream reads before
    /// handing it over ([`ParseError::Malformed`] otherwise). False only for
    /// a reader of a [`Checked`] bundle: holding checks every public key on
    /// the curve, not to be repeated per input.
    fn holds_values(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Lex(LexError),
    /// The document is not shaped like a bundle.
    Unexpected {
        offset: usize,
    },
    /// Ended mid-structure.
    Truncated,
    /// A caller's visitor stopped the walk.
    Rejected,
    /// A transaction names its `global`, `inputs` or `outputs` twice.
    RepeatedSection,
    /// A transaction leaves out its `global`, its `inputs` or its `outputs`.
    MissingSection,
    /// An object leaves out a field upstream requires of it: the first in
    /// upstream's order.
    MissingField {
        scope: Scope,
        field: Field,
    },
    /// The first value, in document order, upstream does not read there;
    /// `field` is [`Field::Unknowns`] for a member it keeps as unknown.
    Malformed {
        scope: Scope,
        field: Field,
    },
    /// An object writes one of upstream's fields twice.
    Duplicate {
        scope: Scope,
        field: Field,
    },
}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        ParseError::Lex(e)
    }
}

/// Walk a decoded bundle document (`decode_envelope`'s JSON, an array of
/// transactions): their count. JSON as upstream reads it: commas only
/// between elements, nothing but whitespace after the closing bracket.
pub fn walk(doc: &[u8], v: &mut impl Visitor) -> Result<usize, ParseError> {
    let mut lex = Lexer::new(doc);
    expect(&mut lex, Token::ArrayStart)?;

    let mut count = 0usize;
    if !closes_at_once(&mut lex, Token::ArrayEnd)? {
        loop {
            v.transaction(count)?;
            walk_transaction(&mut lex, doc, v)?;
            count += 1;
            if !comma_or_close(&mut lex, Token::ArrayEnd)? {
                break;
            }
        }
    }
    match lex.next_token() {
        None => Ok(count),
        Some(Err(e)) => Err(e.into()),
        Some(Ok(_)) => Err(ParseError::Unexpected {
            offset: lex.offset(),
        }),
    }
}

/// A bundle [`check`] has walked whole, held to all upstream holds it to.
/// Readers asked once per input take one, so the holding is done once and
/// none is handed a bundle nobody held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checked<'d> {
    doc: &'d [u8],
    transactions: usize,
}

impl<'d> Checked<'d> {
    /// The document checked.
    pub fn doc(&self) -> &'d [u8] {
        self.doc
    }

    /// How many transactions the bundle holds.
    pub fn transactions(&self) -> usize {
        self.transactions
    }
}

/// Walk `doc` whole, holding it to everything upstream holds a bundle to.
///
/// # Errors
///
/// Whatever [`walk`] refuses.
pub fn check(doc: &[u8]) -> Result<Checked<'_>, ParseError> {
    struct Whole;
    impl Visitor for Whole {}
    let transactions = walk(doc, &mut Whole)?;
    Ok(Checked { doc, transactions })
}

/// Straight after an opening bracket: true, consuming it, when the close
/// comes next.
fn closes_at_once(lex: &mut Lexer, close: Token<'static>) -> Result<bool, ParseError> {
    match peek(lex)? {
        Some(t) if t == close => {
            let _ = lex.next_token();
            Ok(true)
        }
        Some(_) => Ok(false),
        None => Err(ParseError::Truncated),
    }
}

/// After an element: true for a comma, false for the container's close,
/// an error for anything else.
fn comma_or_close(lex: &mut Lexer, close: Token<'static>) -> Result<bool, ParseError> {
    match next(lex)? {
        Token::Comma => Ok(true),
        t if t == close => Ok(false),
        _ => Err(ParseError::Unexpected {
            offset: lex.offset(),
        }),
    }
}

/// A member's key, where one has to be.
fn key(lex: &mut Lexer) -> Result<Span, ParseError> {
    match next(lex)? {
        Token::String { start, end, .. } => Ok(Span { start, end }),
        _ => Err(ParseError::Unexpected {
            offset: lex.offset(),
        }),
    }
}

/// The key at `key`, decoded; `None` when too long to be a name here.
fn name<'o>(
    doc: &[u8],
    key: Span,
    room: &'o mut [u8; KEY_ROOM],
) -> Result<Option<&'o [u8]>, ParseError> {
    Ok(decode_key(key.of(doc), key.start, room)?)
}

fn walk_transaction(lex: &mut Lexer, doc: &[u8], v: &mut impl Visitor) -> Result<(), ParseError> {
    expect(lex, Token::ObjectStart)?;
    // `global`, `inputs` and `outputs` met so far, in that order.
    let mut met = [false; 3];
    if !closes_at_once(lex, Token::ObjectEnd)? {
        loop {
            let key = key(lex)?;
            expect(lex, Token::Colon)?;

            let mut room = [0u8; KEY_ROOM];
            let section = match name(doc, key, &mut room)? {
                Some(b"global") => Some(0),
                Some(b"inputs") => Some(1),
                Some(b"outputs") => Some(2),
                _ => None,
            };
            if let Some(i) = section {
                if met[i] {
                    return Err(ParseError::RepeatedSection);
                }
                met[i] = true;
            }
            match section {
                Some(0) => walk_object(lex, doc, Scope::Global, v)?,
                Some(i) => walk_array(lex, doc, i == 1, v)?,
                // A transaction-level key not known here: reported.
                None => {
                    let (s, e) = lex.skip_value()?;
                    v.unknown(Scope::Global, key, Span { start: s, end: e })?;
                }
            }
            if !comma_or_close(lex, Token::ObjectEnd)? {
                break;
            }
        }
    }
    // All three, as upstream's `Inner` requires: none has a default.
    if met.contains(&false) {
        return Err(ParseError::MissingSection);
    }
    Ok(())
}

fn walk_array(
    lex: &mut Lexer,
    doc: &[u8],
    is_input: bool,
    v: &mut impl Visitor,
) -> Result<(), ParseError> {
    expect(lex, Token::ArrayStart)?;
    if closes_at_once(lex, Token::ArrayEnd)? {
        return Ok(());
    }
    let mut index = 0usize;
    loop {
        let scope = if is_input {
            Scope::Input(index)
        } else {
            Scope::Output(index)
        };
        walk_object(lex, doc, scope, v)?;
        index += 1;
        if !comma_or_close(lex, Token::ArrayEnd)? {
            return Ok(());
        }
    }
}

fn walk_object(
    lex: &mut Lexer,
    doc: &[u8],
    scope: Scope,
    v: &mut impl Visitor,
) -> Result<(), ParseError> {
    expect(lex, Token::ObjectStart)?;
    v.object(scope)?;
    // The recognised fields met, one bit each.
    let mut met = 0u32;
    if !closes_at_once(lex, Token::ObjectEnd)? {
        loop {
            let key = key(lex)?;
            expect(lex, Token::Colon)?;
            let (s, e) = lex.skip_value()?;
            let value = Span { start: s, end: e };

            let mut room = [0u8; KEY_ROOM];
            let field = name(doc, key, &mut room)?.and_then(|n| field_for(scope, n));
            if let Some(f) = field {
                if met & bit(f) != 0 && one_of_upstreams(scope, f) {
                    return Err(ParseError::Duplicate { scope, field: f });
                }
            }
            if v.holds_values() && !values::sound(doc, scope, field, value) {
                let field = field.unwrap_or(Field::Unknowns);
                return Err(ParseError::Malformed { scope, field });
            }
            match field {
                Some(f) => {
                    met |= bit(f);
                    v.field(scope, f, value)?;
                }
                None => v.unknown(scope, key, value)?,
            }
            if !comma_or_close(lex, Token::ObjectEnd)? {
                break;
            }
        }
    }
    match required(scope).iter().find(|&&f| met & bit(f) == 0) {
        Some(&field) => Err(ParseError::MissingField { scope, field }),
        None => Ok(()),
    }
}

fn next(lex: &mut Lexer) -> Result<Token<'static>, ParseError> {
    match lex.next_token() {
        None => Err(ParseError::Truncated),
        Some(Err(e)) => Err(e.into()),
        // Re-created without the borrow: only the offsets are needed.
        Some(Ok(t)) => Ok(match t {
            Token::String { start, end, .. } => Token::String {
                raw: &[],
                start,
                end,
            },
            Token::Number { .. } => Token::Number { raw: &[] },
            Token::ObjectStart => Token::ObjectStart,
            Token::ObjectEnd => Token::ObjectEnd,
            Token::ArrayStart => Token::ArrayStart,
            Token::ArrayEnd => Token::ArrayEnd,
            Token::Colon => Token::Colon,
            Token::Comma => Token::Comma,
            Token::True => Token::True,
            Token::False => Token::False,
            Token::Null => Token::Null,
        }),
    }
}

fn peek(lex: &mut Lexer) -> Result<Option<Token<'static>>, ParseError> {
    let save = lex.offset();
    let r = match lex.next_token() {
        None => None,
        Some(Err(e)) => return Err(e.into()),
        // No wildcard: a variant added to `Token` is a compile error here,
        // not a panic on a crafted request.
        Some(Ok(t)) => Some(match t {
            Token::String { start, end, .. } => Token::String {
                raw: &[],
                start,
                end,
            },
            Token::Number { .. } => Token::Number { raw: &[] },
            Token::ObjectStart => Token::ObjectStart,
            Token::ObjectEnd => Token::ObjectEnd,
            Token::ArrayStart => Token::ArrayStart,
            Token::ArrayEnd => Token::ArrayEnd,
            Token::Colon => Token::Colon,
            Token::Comma => Token::Comma,
            Token::True => Token::True,
            Token::False => Token::False,
            Token::Null => Token::Null,
        }),
    };
    lex.seek(save);
    Ok(r)
}

fn expect(lex: &mut Lexer, want: Token<'static>) -> Result<(), ParseError> {
    let got = next(lex)?;
    if core::mem::discriminant(&got) == core::mem::discriminant(&want) {
        Ok(())
    } else {
        Err(ParseError::Unexpected {
            offset: lex.offset(),
        })
    }
}
