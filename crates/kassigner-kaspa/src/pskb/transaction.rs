// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Reading one transaction out of a bundle, as upstream's `unsigned_tx` and
//! `determine_lock_time` (`wallet/pskt/src/pskt.rs`) build the one its
//! signer hashes: `txVersion`; inputs of `previousOutpoint`, `sequence`
//! (final if absent), `sigOpCount` (zero if absent), no unlocking script
//! and no compute budget; outputs of `amount`, `scriptPublicKey` and
//! `covenant`; the largest `minTime` as lock time, zero if none, or
//! `fallbackLockTime` with no inputs at all; native subnetwork, no gas; the
//! payload only from bundle `version` One. The walk holds every other value
//! ([`super::schema`]).
//!
//! An input with no `utxoEntry` stops the read with an error, where
//! upstream's `SignableTransaction::with_entries` would panic.
//!
//! Scripts and the payload are decoded from hex, either case as upstream's
//! `faster_hex` reads it, into the caller's buffer, never borrowing the
//! document. A quarter of the envelope's length always suffices: each byte
//! is two characters of the document, which is half the envelope.

use super::lexer::{ascii, decode_key, Lexer, Token};
use super::schema::{bit, walk, Checked, Field, ParseError, Scope, Span, Visitor};
use crate::hex::nibble;
use crate::tx::{
    CovenantBinding, Outpoint, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput,
    UtxoEntry, SUBNETWORK_ID_NATIVE,
};

/// The bundle version from which the payload is carried: `Version::One`.
const PAYLOAD_FROM_VERSION: u64 = 1;

/// The highest bundle version upstream defines, `Version::Two`; its
/// `Deserialize_repr` refuses any other number.
pub(crate) const MAX_BUNDLE_VERSION: u64 = 2;

/// Why a bundle's transaction could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The document is not shaped like a bundle.
    Parse(ParseError),
    /// The bundle holds no transaction at `index`.
    NoSuchTransaction { index: usize, count: usize },
    /// A transaction lists its inputs, its outputs or its global map twice.
    RepeatedSection,
    /// The caller's input array is too small; nothing is written.
    TooManyInputs { needed: usize, room: usize },
    /// The caller's output array is too small; nothing is written.
    TooManyOutputs { needed: usize, room: usize },
    /// The caller's byte buffer cannot hold the decoded scripts and payload.
    BufferTooSmall,
    /// A field upstream requires, or the extraction needs, is absent: the
    /// first in upstream's order.
    Missing { scope: Scope, field: Field },
    /// A field of upstream's appears twice in one object, in any transaction,
    /// as serde refuses.
    Duplicate { scope: Scope, field: Field },
    /// A value upstream does not read there; `field` is [`Field::Unknowns`]
    /// for a member it keeps as unknown.
    Malformed { scope: Scope, field: Field },
    /// An input carries no `utxoEntry`.
    NoUtxoEntry { input: usize },
    /// The transaction has no input at `input`.
    NoSuchInput { input: usize },
}

impl From<ParseError> for ReadError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::RepeatedSection => ReadError::RepeatedSection,
            ParseError::MissingField { scope, field } => ReadError::Missing { scope, field },
            ParseError::Malformed { scope, field } => ReadError::Malformed { scope, field },
            ParseError::Duplicate { scope, field } => ReadError::Duplicate { scope, field },
            e => ReadError::Parse(e),
        }
    }
}

/// What a transaction takes from the bundle besides its inputs and outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub version: u16,
    pub lock_time: u64,
    pub payload: &'a [u8],
}

/// What an input carries for the party signing it, beyond the transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extras<'a> {
    /// `sighashType`, the byte upstream holds it in (`SigHashType(u8)`).
    /// Required upstream and held to a byte in a [`Checked`] bundle, so not
    /// an `Option`. Which types to accept is the signer's policy; upstream
    /// refuses unknown ones only when it signs.
    pub sighash_type: u8,
    /// `redeemScript`, decoded. Empty when absent.
    pub redeem: &'a [u8],
    /// `redeemScript`'s value in the document, for a signer that writes one
    /// over a `null`.
    pub redeem_at: Option<Span>,
    /// The covenant the spent coin is bound to, from its `utxoEntry`'s
    /// `covenantId`: `None` for `null`, or with no `utxoEntry`.
    pub covenant_id: Option<[u8; 32]>,
}

/// What [`fill`] wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Filled<'a> {
    /// Entries used in the caller's input array.
    pub inputs: usize,
    /// Entries used in the caller's output array.
    pub outputs: usize,
    pub header: Header<'a>,
}

/// How many inputs and outputs the transaction at `index` has.
///
/// # Errors
///
/// `Parse` for a document that is not a bundle; `Missing`, `Malformed`,
/// `Duplicate` and `RepeatedSection` in any transaction, as upstream refuses
/// the whole bundle; `NoSuchTransaction` past the end.
pub fn counts(doc: &[u8], index: usize) -> Result<(usize, usize), ReadError> {
    let mut c = Counter {
        target: index,
        current: None,
        inputs: 0,
        outputs: 0,
        repeated: false,
    };
    let walked = walk(doc, &mut c);
    if c.repeated {
        return Err(ReadError::RepeatedSection);
    }
    let count = walked?;
    if index >= count {
        return Err(ReadError::NoSuchTransaction { index, count });
    }
    Ok((c.inputs, c.outputs))
}

/// Read the transaction at `index` into the caller's arrays and buffer: the
/// entries used and the header [`build`] needs.
///
/// # Errors
///
/// Everything [`counts`] refuses. `TooManyInputs` or `TooManyOutputs` before
/// anything is written. `BufferTooSmall`, `Missing`, `Duplicate`, `Malformed`
/// and `NoUtxoEntry` as the walk finds them, leaving the arrays partly written.
pub fn fill<'a>(
    doc: &[u8],
    index: usize,
    inputs: &mut [TransactionInput<'a>],
    outputs: &mut [TransactionOutput<'a>],
    bytes: &'a mut [u8],
) -> Result<Filled<'a>, ReadError> {
    let (ni, no) = counts(doc, index)?;
    if ni > inputs.len() {
        return Err(ReadError::TooManyInputs {
            needed: ni,
            room: inputs.len(),
        });
    }
    if no > outputs.len() {
        return Err(ReadError::TooManyOutputs {
            needed: no,
            room: outputs.len(),
        });
    }
    let mut r = Reader {
        doc,
        target: index,
        current: None,
        inputs,
        outputs,
        free: bytes,
        error: None,
        open: None,
        seen: 0,
        global_seen: 0,
        version: 0,
        tx_version: 0,
        fallback: None,
        payload: None,
        min_time: None,
        n_inputs: 0,
        n_outputs: 0,
    };
    let walked = walk(doc, &mut r);
    r.finish(walked)
}

/// What input `input` of transaction `index` carries for a signer: its
/// `sighashType`, its `redeemScript` decoded into `bytes`, and its coin's
/// covenant id.
///
/// # Errors
///
/// `NoSuchTransaction` past the end, `NoSuchInput` past the last input;
/// `Malformed` and `BufferTooSmall` for the fields read; `Missing` for an
/// input without `sighashType`, which a [`Checked`] bundle never has.
pub fn input_extras<'a>(
    bundle: Checked<'_>,
    index: usize,
    input: usize,
    bytes: &'a mut [u8],
) -> Result<Extras<'a>, ReadError> {
    let doc = bundle.doc();
    let mut x = ExtrasReader {
        target: index,
        input,
        current: None,
        inputs: 0,
        sighash: None,
        redeem: None,
        entry: None,
        trouble: None,
    };
    let walked = walk(doc, &mut x);
    if let Some(e) = x.trouble {
        return Err(e);
    }
    let count = walked?;
    if index >= count {
        return Err(ReadError::NoSuchTransaction { index, count });
    }
    if input >= x.inputs {
        return Err(ReadError::NoSuchInput { input });
    }
    let scope = Scope::Input(input);
    let sighash_type =
        match x.sighash {
            None => {
                return Err(ReadError::Missing {
                    scope,
                    field: Field::SighashType,
                })
            }
            Some(span) => number(doc, span).and_then(|n| u8::try_from(n).ok()).ok_or(
                ReadError::Malformed {
                    scope,
                    field: Field::SighashType,
                },
            )?,
        };
    let redeem: &'a [u8] = match x.redeem {
        None => &[],
        Some(span) => match scalar(doc, span) {
            Some(Token::Null) => &[],
            Some(Token::String { raw, .. }) => decode_hex(raw, bytes).map_err(|b| match b {
                Bad::Malformed => ReadError::Malformed {
                    scope,
                    field: Field::RedeemScript,
                },
                Bad::Buffer => ReadError::BufferTooSmall,
            })?,
            _ => {
                return Err(ReadError::Malformed {
                    scope,
                    field: Field::RedeemScript,
                })
            }
        },
    };
    let covenant_id = coin_covenant(doc, x.entry, input)?;
    Ok(Extras {
        sighash_type,
        redeem,
        redeem_at: x.redeem,
        covenant_id,
    })
}

/// The covenant the coin input `input` of transaction `index` spends is
/// bound to, from its `utxoEntry`'s `covenantId`: `None` for `null`, or with
/// no `utxoEntry`. [`input_extras`]'s, for a caller with no room for a
/// redeem script.
///
/// # Errors
///
/// `NoSuchTransaction` past the end, `NoSuchInput` past the last input;
/// `Malformed` for a `utxoEntry` that does not read.
pub fn input_covenant_id(
    bundle: Checked<'_>,
    index: usize,
    input: usize,
) -> Result<Option<[u8; 32]>, ReadError> {
    let doc = bundle.doc();
    let mut x = ExtrasReader {
        target: index,
        input,
        current: None,
        inputs: 0,
        sighash: None,
        redeem: None,
        entry: None,
        trouble: None,
    };
    let walked = walk(doc, &mut x);
    if let Some(e) = x.trouble {
        return Err(e);
    }
    let count = walked?;
    if index >= count {
        return Err(ReadError::NoSuchTransaction { index, count });
    }
    if input >= x.inputs {
        return Err(ReadError::NoSuchInput { input });
    }
    coin_covenant(doc, x.entry, input)
}

/// The covenant id in an input's `utxoEntry` at `span`, if it has one.
fn coin_covenant(
    doc: &[u8],
    span: Option<Span>,
    input: usize,
) -> Result<Option<[u8; 32]>, ReadError> {
    match span {
        Some(span) if !matches!(scalar(doc, span), Some(Token::Null)) => Ok(entry(doc, span)
            .ok_or(ReadError::Malformed {
                scope: Scope::Input(input),
                field: Field::UtxoEntry,
            })?
            .covenant_id),
        _ => Ok(None),
    }
}

struct ExtrasReader {
    target: usize,
    input: usize,
    current: Option<usize>,
    inputs: usize,
    sighash: Option<Span>,
    redeem: Option<Span>,
    entry: Option<Span>,
    trouble: Option<ReadError>,
}

impl Visitor for ExtrasReader {
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
                self.trouble = Some(ReadError::RepeatedSection);
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
            Field::SighashType => &mut self.sighash,
            Field::RedeemScript => &mut self.redeem,
            Field::UtxoEntry => &mut self.entry,
            _ => return Ok(()),
        };
        if slot.is_some() {
            self.trouble = Some(ReadError::Duplicate { scope, field });
            return Err(ParseError::Rejected);
        }
        *slot = Some(value);
        Ok(())
    }

    fn holds_values(&self) -> bool {
        false
    }
}

/// Build a transaction over what [`fill`] wrote: separate, as the arrays
/// cannot be borrowed while being written.
pub fn build<'a>(
    header: &Header<'a>,
    inputs: &'a [TransactionInput<'a>],
    outputs: &'a [TransactionOutput<'a>],
) -> Transaction<'a> {
    Transaction {
        version: header.version,
        inputs,
        outputs,
        lock_time: header.lock_time,
        subnetwork_id: SUBNETWORK_ID_NATIVE,
        gas: 0,
        payload: header.payload,
    }
}

struct Counter {
    target: usize,
    current: Option<usize>,
    inputs: usize,
    outputs: usize,
    repeated: bool,
}

impl Visitor for Counter {
    fn transaction(&mut self, index: usize) -> Result<(), ParseError> {
        self.current = Some(index);
        Ok(())
    }

    fn object(&mut self, scope: Scope) -> Result<(), ParseError> {
        if self.current != Some(self.target) {
            return Ok(());
        }
        // Numbered from zero in each array, so a second array under the same
        // key starts again at zero.
        let (count, i) = match scope {
            Scope::Global => return Ok(()),
            Scope::Input(i) => (&mut self.inputs, i),
            Scope::Output(i) => (&mut self.outputs, i),
        };
        if i != *count {
            self.repeated = true;
            return Err(ParseError::Rejected);
        }
        *count += 1;
        Ok(())
    }
}

/// Why a value could not be taken.
enum Bad {
    Malformed,
    Buffer,
}

struct Reader<'r, 'a> {
    doc: &'r [u8],
    target: usize,
    current: Option<usize>,
    inputs: &'r mut [TransactionInput<'a>],
    outputs: &'r mut [TransactionOutput<'a>],
    free: &'a mut [u8],
    error: Option<ReadError>,
    /// The object being read, and the fields seen in it so far.
    open: Option<Scope>,
    seen: u32,
    /// Fields seen in the global map, kept for the checks at the end.
    global_seen: u32,
    version: u64,
    tx_version: u16,
    fallback: Option<u64>,
    payload: Option<Span>,
    min_time: Option<u64>,
    n_inputs: usize,
    n_outputs: usize,
}

const fn blank_input<'a>() -> TransactionInput<'a> {
    TransactionInput {
        previous_outpoint: Outpoint {
            transaction_id: [0; 32],
            index: 0,
        },
        // What upstream uses when the bundle states none.
        sequence: u64::MAX,
        sig_op_count: 0,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: UtxoEntry {
            amount: 0,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: &[],
            },
        },
    }
}

const fn blank_output<'a>() -> TransactionOutput<'a> {
    TransactionOutput {
        value: 0,
        script_public_key: ScriptPublicKey {
            version: 0,
            script: &[],
        },
        covenant: None,
    }
}

impl<'a> Reader<'_, 'a> {
    fn fail(&mut self, e: ReadError) -> Result<(), ParseError> {
        self.error = Some(e);
        Err(ParseError::Rejected)
    }

    /// Check the object read has what the extraction needs.
    fn close(&mut self) -> Result<(), ReadError> {
        let Some(scope) = self.open.take() else {
            return Ok(());
        };
        let has = |f: Field| self.seen & bit(f) != 0;
        match scope {
            Scope::Global => self.global_seen = self.seen,
            Scope::Input(i) => {
                if !has(Field::PreviousOutpoint) {
                    return Err(ReadError::Missing {
                        scope,
                        field: Field::PreviousOutpoint,
                    });
                }
                if !has(Field::UtxoEntry) {
                    return Err(ReadError::NoUtxoEntry { input: i });
                }
            }
            Scope::Output(_) => {
                for field in [Field::Amount, Field::ScriptPublicKey] {
                    if !has(field) {
                        return Err(ReadError::Missing { scope, field });
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(mut self, walked: Result<usize, ParseError>) -> Result<Filled<'a>, ReadError> {
        let count = match walked {
            Ok(n) => n,
            Err(e) => return Err(self.error.take().unwrap_or(ReadError::from(e))),
        };
        if self.target >= count {
            return Err(ReadError::NoSuchTransaction {
                index: self.target,
                count,
            });
        }
        if self.current == Some(self.target) {
            self.close()?;
        }
        for field in [Field::Version, Field::TxVersion] {
            if self.global_seen & bit(field) == 0 {
                return Err(ReadError::Missing {
                    scope: Scope::Global,
                    field,
                });
            }
        }

        let lock_time = if self.n_inputs == 0 {
            self.fallback.unwrap_or(0)
        } else {
            self.min_time.unwrap_or(0)
        };

        let payload: &'a [u8] = match self.payload {
            None => &[],
            Some(span) => {
                let bad = |b: Bad| match b {
                    Bad::Malformed => ReadError::Malformed {
                        scope: Scope::Global,
                        field: Field::Payload,
                    },
                    Bad::Buffer => ReadError::BufferTooSmall,
                };
                let hex = string(self.doc, span).ok_or(Bad::Malformed).map_err(bad)?;
                if self.version >= PAYLOAD_FROM_VERSION {
                    self.decode(hex).map_err(bad)?
                } else {
                    // Not carried, but still held to what upstream reads.
                    if !is_hex(hex) {
                        return Err(bad(Bad::Malformed));
                    }
                    &[]
                }
            }
        };

        Ok(Filled {
            inputs: self.n_inputs,
            outputs: self.n_outputs,
            header: Header {
                version: self.tx_version,
                lock_time,
                payload,
            },
        })
    }

    /// Decode a string's hex into the next stretch of the caller's buffer.
    fn decode(&mut self, hex: &[u8]) -> Result<&'a [u8], Bad> {
        self.decode_text(ascii(hex))
    }

    /// Decode hex characters into the next stretch of the caller's buffer.
    fn decode_text(&mut self, chars: impl Iterator<Item = u8> + Clone) -> Result<&'a [u8], Bad> {
        let n = chars.clone().count();
        if !n.is_multiple_of(2) {
            return Err(Bad::Malformed);
        }
        let n = n / 2;
        if self.free.len() < n {
            return Err(Bad::Buffer);
        }
        let (head, tail) = core::mem::take(&mut self.free).split_at_mut(n);
        self.free = tail;
        decode_chars(chars, head)?;
        Ok(head)
    }

    /// Upstream's script form: one hex string, the version as two
    /// big-endian bytes, then the script.
    fn script(&mut self, hex: &[u8]) -> Result<ScriptPublicKey<'a>, Bad> {
        if ascii(hex).count() < 4 {
            return Err(Bad::Malformed);
        }
        let mut version = [0u8; 2];
        decode_chars(ascii(hex).take(4), &mut version)?;
        Ok(ScriptPublicKey {
            version: u16::from_be_bytes(version),
            script: self.decode_text(ascii(hex).skip(4))?,
        })
    }

    fn global(&mut self, field: Field, value: Span) -> Result<(), Bad> {
        let doc = self.doc;
        match field {
            Field::Version => {
                let v = number(doc, value).ok_or(Bad::Malformed)?;
                if v > MAX_BUNDLE_VERSION {
                    return Err(Bad::Malformed);
                }
                self.version = v;
            }
            Field::TxVersion => {
                let v = number(doc, value).ok_or(Bad::Malformed)?;
                self.tx_version = u16::try_from(v).map_err(|_| Bad::Malformed)?;
            }
            Field::FallbackLockTime => {
                self.fallback = optional_number(doc, value).ok_or(Bad::Malformed)?;
            }
            Field::Payload => {
                self.payload = match scalar(doc, value) {
                    Some(Token::Null) => None,
                    Some(Token::String { .. }) => Some(value),
                    _ => return Err(Bad::Malformed),
                };
            }
            _ => {}
        }
        Ok(())
    }

    fn input(&mut self, i: usize, field: Field, value: Span) -> Result<(), ReadError> {
        let doc = self.doc;
        let scope = Scope::Input(i);
        let bad = |b: Bad| match b {
            Bad::Malformed => ReadError::Malformed { scope, field },
            Bad::Buffer => ReadError::BufferTooSmall,
        };
        match field {
            Field::PreviousOutpoint => {
                let op = outpoint(doc, value).ok_or(bad(Bad::Malformed))?;
                self.inputs[i].previous_outpoint = op;
            }
            Field::UtxoEntry => {
                if matches!(scalar(doc, value), Some(Token::Null)) {
                    return Err(ReadError::NoUtxoEntry { input: i });
                }
                let e = entry(doc, value).ok_or(bad(Bad::Malformed))?;
                let script_public_key = self.script(e.script).map_err(bad)?;
                self.inputs[i].utxo_entry = UtxoEntry {
                    amount: e.amount,
                    script_public_key,
                };
            }
            Field::Sequence => {
                let v = optional_number(doc, value).ok_or(bad(Bad::Malformed))?;
                self.inputs[i].sequence = v.unwrap_or(u64::MAX);
            }
            Field::MinTime => {
                let v = optional_number(doc, value).ok_or(bad(Bad::Malformed))?;
                if let Some(t) = v {
                    self.min_time = Some(self.min_time.map_or(t, |m| m.max(t)));
                }
            }
            Field::SigOpCount => {
                let v = optional_number(doc, value).ok_or(bad(Bad::Malformed))?;
                self.inputs[i].sig_op_count = match v {
                    None => 0,
                    Some(n) => u8::try_from(n).map_err(|_| bad(Bad::Malformed))?,
                };
            }
            _ => {}
        }
        Ok(())
    }

    fn output(&mut self, k: usize, field: Field, value: Span) -> Result<(), ReadError> {
        let doc = self.doc;
        let scope = Scope::Output(k);
        let bad = |b: Bad| match b {
            Bad::Malformed => ReadError::Malformed { scope, field },
            Bad::Buffer => ReadError::BufferTooSmall,
        };
        match field {
            Field::Amount => {
                self.outputs[k].value = number(doc, value).ok_or(bad(Bad::Malformed))?;
            }
            Field::ScriptPublicKey => {
                let hex = string(doc, value).ok_or(bad(Bad::Malformed))?;
                self.outputs[k].script_public_key = self.script(hex).map_err(bad)?;
            }
            Field::Covenant => {
                self.outputs[k].covenant = covenant(doc, value).ok_or(bad(Bad::Malformed))?;
            }
            _ => {}
        }
        Ok(())
    }
}

impl Visitor for Reader<'_, '_> {
    fn transaction(&mut self, index: usize) -> Result<(), ParseError> {
        if self.current == Some(self.target) {
            if let Err(e) = self.close() {
                return self.fail(e);
            }
        }
        self.current = Some(index);
        Ok(())
    }

    fn object(&mut self, scope: Scope) -> Result<(), ParseError> {
        if self.current != Some(self.target) {
            return Ok(());
        }
        if let Err(e) = self.close() {
            return self.fail(e);
        }
        match scope {
            // Met once: the walk refuses a second `global` before it opens.
            Scope::Global => self.seen = 0,
            Scope::Input(i) => {
                if i != self.n_inputs {
                    return self.fail(ReadError::RepeatedSection);
                }
                let room = self.inputs.len();
                let Some(slot) = self.inputs.get_mut(i) else {
                    return self.fail(ReadError::TooManyInputs {
                        needed: i + 1,
                        room,
                    });
                };
                *slot = blank_input();
                self.n_inputs += 1;
                self.seen = 0;
            }
            Scope::Output(k) => {
                if k != self.n_outputs {
                    return self.fail(ReadError::RepeatedSection);
                }
                let room = self.outputs.len();
                let Some(slot) = self.outputs.get_mut(k) else {
                    return self.fail(ReadError::TooManyOutputs {
                        needed: k + 1,
                        room,
                    });
                };
                *slot = blank_output();
                self.n_outputs += 1;
                self.seen = 0;
            }
        }
        self.open = Some(scope);
        Ok(())
    }

    fn field(&mut self, scope: Scope, field: Field, value: Span) -> Result<(), ParseError> {
        if self.current != Some(self.target) {
            return Ok(());
        }
        // The walk refuses a field of upstream's written twice; a member kept
        // as unknown may repeat, and is not read.
        self.seen |= bit(field);
        let r = match scope {
            Scope::Global => self.global(field, value).map_err(|b| match b {
                Bad::Malformed => ReadError::Malformed { scope, field },
                Bad::Buffer => ReadError::BufferTooSmall,
            }),
            Scope::Input(i) => self.input(i, field, value),
            Scope::Output(k) => self.output(k, field, value),
        };
        match r {
            Ok(()) => Ok(()),
            Err(e) => self.fail(e),
        }
    }
}

// ── Values ──────────────────────────────────────────────────────────────────

/// The one token a scalar value consists of.
pub(crate) fn scalar(doc: &[u8], span: Span) -> Option<Token<'_>> {
    let src = doc.get(span.start..span.end)?;
    let mut lex = Lexer::new(src);
    let tok = lex.next_token()?.ok()?;
    if lex.next_token().is_some() {
        return None;
    }
    Some(tok)
}

/// An unsigned JSON integer: digits only, no leading zero, within `u64`.
pub(crate) fn unsigned(raw: &[u8]) -> Option<u64> {
    if raw.is_empty() || (raw.len() > 1 && raw[0] == b'0') {
        return None;
    }
    let mut v: u64 = 0;
    for &c in raw {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    Some(v)
}

pub(crate) fn number(doc: &[u8], span: Span) -> Option<u64> {
    match scalar(doc, span)? {
        Token::Number { raw } => unsigned(raw),
        _ => None,
    }
}

pub(crate) fn optional_number(doc: &[u8], span: Span) -> Option<Option<u64>> {
    match scalar(doc, span)? {
        Token::Null => Some(None),
        Token::Number { raw } => unsigned(raw).map(Some),
        _ => None,
    }
}

fn string(doc: &[u8], span: Span) -> Option<&[u8]> {
    match scalar(doc, span)? {
        Token::String { raw, .. } => Some(raw),
        _ => None,
    }
}

/// Room for a member's key, decoded: the longest read whole is an
/// uncompressed public key's hex, 130 characters (an extended public key's
/// text is about 111).
const MEMBER_ROOM: usize = 160;

/// Call `f` with each member of the object at `span`: its key, decoded as
/// upstream decodes it (`None` past [`MEMBER_ROOM`]), and its value's span.
/// A key serde_json would refuse, or `f` returning `None`, refuses the
/// object.
pub(crate) fn members(
    doc: &[u8],
    span: Span,
    mut f: impl FnMut(Option<&[u8]>, Span) -> Option<()>,
) -> Option<()> {
    let src = doc.get(span.start..span.end)?;
    let mut lex = Lexer::new(src);
    if !matches!(lex.next_token()?.ok()?, Token::ObjectStart) {
        return None;
    }
    loop {
        match lex.next_token()?.ok()? {
            Token::ObjectEnd => {
                return if lex.next_token().is_none() {
                    Some(())
                } else {
                    None
                };
            }
            Token::Comma => {}
            Token::String { raw, start, .. } => {
                let mut room = [0u8; MEMBER_ROOM];
                let key = decode_key(raw, span.start + start, &mut room).ok()?;
                if !matches!(lex.next_token()?.ok()?, Token::Colon) {
                    return None;
                }
                let (s, e) = lex.skip_value().ok()?;
                f(
                    key,
                    Span {
                        start: span.start + s,
                        end: span.start + e,
                    },
                )?;
            }
            _ => return None,
        }
    }
}

/// `{"transactionId": <hex>, "index": <u32>}`. Upstream: `TransactionOutpoint`.
pub(crate) fn outpoint(doc: &[u8], span: Span) -> Option<Outpoint> {
    let mut id = None;
    let mut index = None;
    members(doc, span, |key, v| {
        match key {
            Some(b"transactionId") if id.is_none() => id = Some(hash(string(doc, v)?)?),
            Some(b"index") if index.is_none() => {
                index = Some(u32::try_from(number(doc, v)?).ok()?);
            }
            Some(b"transactionId" | b"index") => return None,
            _ => {}
        }
        Some(())
    })?;
    Some(Outpoint {
        transaction_id: id?,
        index: index?,
    })
}

/// What [`entry`] reads of a `utxoEntry`.
pub(crate) struct Entry<'d> {
    /// `amount`.
    pub(crate) amount: u64,
    /// `scriptPublicKey`, as hex.
    pub(crate) script: &'d [u8],
    /// `covenantId`: the covenant the coin is bound to, `None` for `null`.
    pub(crate) covenant_id: Option<[u8; 32]>,
}

/// The amount, script hex and covenant id of a `utxoEntry` (upstream
/// `UtxoEntry`, read from JSON as `UtxoEntryHumanReadable`).
/// `blockDaaScore` and `isCoinbase` are required too (only `covenantId` has
/// a default). Each of the five is held to its type, `covenantId` to `null`
/// or a hash, and none may be written twice.
pub(crate) fn entry(doc: &[u8], span: Span) -> Option<Entry<'_>> {
    let mut amount = None;
    let mut script = None;
    let (mut daa_score, mut coinbase, mut covenant_id) = (false, false, None);
    members(doc, span, |key, v| {
        match key {
            Some(b"amount") if amount.is_none() => amount = Some(number(doc, v)?),
            Some(b"scriptPublicKey") if script.is_none() => script = Some(string(doc, v)?),
            Some(b"blockDaaScore") if !daa_score => {
                number(doc, v)?;
                daa_score = true;
            }
            Some(b"isCoinbase") if !coinbase => {
                matches!(scalar(doc, v)?, Token::True | Token::False).then_some(())?;
                coinbase = true;
            }
            Some(b"covenantId") if covenant_id.is_none() => {
                covenant_id = Some(match scalar(doc, v)? {
                    Token::Null => None,
                    Token::String { raw, .. } => Some(hash(raw)?),
                    _ => return None,
                });
            }
            Some(
                b"amount" | b"scriptPublicKey" | b"blockDaaScore" | b"isCoinbase" | b"covenantId",
            ) => return None,
            _ => {}
        }
        Some(())
    })?;
    (daa_score && coinbase).then_some(())?;
    Some(Entry {
        amount: amount?,
        script: script?,
        covenant_id: covenant_id.flatten(),
    })
}

/// `null`, or `{"authorizingInput": <u16>, "covenantId": <hex>}`. Upstream:
/// `CovenantBinding`.
pub(crate) fn covenant(doc: &[u8], span: Span) -> Option<Option<CovenantBinding>> {
    if matches!(scalar(doc, span), Some(Token::Null)) {
        return Some(None);
    }
    let mut input = None;
    let mut id = None;
    members(doc, span, |key, v| {
        match key {
            Some(b"authorizingInput") if input.is_none() => {
                input = Some(u16::try_from(number(doc, v)?).ok()?);
            }
            Some(b"covenantId") if id.is_none() => id = Some(hash(string(doc, v)?)?),
            Some(b"authorizingInput" | b"covenantId") => return None,
            _ => {}
        }
        Some(())
    })?;
    Some(Some(CovenantBinding {
        authorizing_input: input?,
        covenant_id: id?,
    }))
}

/// A 32-byte hash: 64 hex characters.
pub(crate) fn hash(hex: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    decode_into(hex, &mut out).ok()?;
    Some(out)
}

/// Whether a string's text, escapes decoded, is hex as upstream reads it:
/// an even number of hex digits in either case.
pub(crate) fn is_hex(hex: &[u8]) -> bool {
    let mut n = 0usize;
    ascii(hex).all(|c| {
        n += 1;
        nibble(c).is_some()
    }) && n.is_multiple_of(2)
}

/// How many characters a string's text stands for, its escapes decoded.
pub(crate) fn char_count(raw: &[u8]) -> usize {
    ascii(raw).count()
}

/// Decode a string's hex into the front of `buf`, returning the decoded bytes.
fn decode_hex<'a>(hex: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8], Bad> {
    let n = char_count(hex);
    if !n.is_multiple_of(2) {
        return Err(Bad::Malformed);
    }
    let out = buf.get_mut(..n / 2).ok_or(Bad::Buffer)?;
    decode_into(hex, out)?;
    Ok(out)
}

/// Decode exactly `out.len()` bytes from a string's hex of twice as many
/// characters.
fn decode_into(hex: &[u8], out: &mut [u8]) -> Result<(), Bad> {
    decode_chars(ascii(hex), out)
}

/// Whether a string's hex decodes to exactly `out.len()` bytes, written there.
pub(crate) fn hex_into(hex: &[u8], out: &mut [u8]) -> bool {
    decode_into(hex, out).is_ok()
}

/// Decode exactly `out.len()` bytes from exactly twice as many hex
/// characters.
fn decode_chars(mut chars: impl Iterator<Item = u8>, out: &mut [u8]) -> Result<(), Bad> {
    for o in out.iter_mut() {
        let hi = chars.next().and_then(nibble).ok_or(Bad::Malformed)?;
        let lo = chars.next().and_then(nibble).ok_or(Bad::Malformed)?;
        *o = (hi << 4) | lo;
    }
    match chars.next() {
        None => Ok(()),
        Some(_) => Err(Bad::Malformed),
    }
}
