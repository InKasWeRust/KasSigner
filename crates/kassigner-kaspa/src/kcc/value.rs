// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KCC-1's values (3.4): arguments and state read by their types, and an
//! `int` written.
//!
//! A value lowers to pushes (3.4.6): a scalar or an array of scalars is one
//! push, a record its fields in turn, an array of records one push per leaf
//! field holding that field of every element.
//!
//! Arguments are pushed by `PushMinimal`, state fields by `PushExplicit`
//! (3.4.2, 3.7.1), each refused in the other's form. A standalone argument's
//! `int` is a minimal ScriptNum and its `bool` `OP_0` or `OP_1`; elsewhere
//! an `int` is eight bytes and a `bool` `00` or `01`.
//!
//! A value is found by its location (3.4.7), a root and a path. Every read
//! checks the whole of what it reads, so a value never comes from a partial
//! or non-canonical encoding. Nothing allocates.

use super::abi::{AbiError, Field, Record, Type};
use super::push::{pushes, Push, PushError};

/// One step of a path (3.4.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment<'p> {
    /// A record's field, by its name.
    Field(&'p str),
    /// An array's element, from zero.
    Index(usize),
}

/// What a location holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    /// An `int`, or SilverScript's `temporal`.
    Int(i64),
    /// A `bool`.
    Bool(bool),
    /// A `byte`.
    Byte(u8),
    /// A `byte[N]`, a `byte[]`, a `pubkey`, a `sig` or a `datasig`.
    Bytes(&'a [u8]),
    /// A `string`.
    Text(&'a str),
    /// Any other array, by its number of elements.
    Array(usize),
    /// A record; each field is reached by its name.
    Record,
}

/// Why a value was not read, or not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueError {
    /// A type that can carry no value, or a bad record name.
    Type(AbiError),
    /// An opcode that is not a push, or a push that runs past the end.
    NotPush,
    /// A push not in its encoding's form.
    NotCanonicalPush,
    /// Fewer pushes than the types lower to.
    Missing,
    /// More pushes, or more bytes, than the types lower to.
    Trailing,
    /// An `int` out of range, not minimal, of the wrong width, or minus zero
    /// (3.4.3).
    BadInt,
    /// A `bool` other than its two encodings (3.4.4).
    BadBool,
    /// A payload of the wrong length (3.4.4, 3.4.5).
    BadLength,
    /// A `string` that is not UTF-8.
    BadText,
    /// An array of records whose fields hold different numbers of elements
    /// (3.4.6).
    UnequalGroups,
    /// A location that selects nothing.
    BadLocation,
    /// A state range past the program's end (3.7.2).
    OutOfBounds,
    /// The caller's buffer cannot hold it.
    BufferTooSmall,
}

impl From<PushError> for ValueError {
    fn from(e: PushError) -> Self {
        match e {
            PushError::BufferTooSmall => Self::BufferTooSmall,
            PushError::TooLong | PushError::Truncated | PushError::NotPush => Self::NotPush,
        }
    }
}

impl From<AbiError> for ValueError {
    fn from(e: AbiError) -> Self {
        Self::Type(e)
    }
}

/// How the pushes being read were written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Form {
    /// An invocation's arguments: `PushMinimal`.
    Argument,
    /// A covenant's state: `PushExplicit`.
    State,
}

/// Where a scalar's payload stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Context {
    /// Alone as an argument.
    Standalone,
    /// In a state field or an array.
    Payload,
}

/// The largest magnitude an `int` holds: `2^63 - 1`.
const INT_MAX_MAGNITUDE: u64 = i64::MAX as u64;

/// A minimal ScriptNum of up to eight bytes (3.4.3): little-endian
/// magnitude, sign in the last byte's top bit.
fn script_num(b: &[u8]) -> Result<i64, ValueError> {
    let Some((&last, rest)) = b.split_last() else {
        return Ok(0);
    };
    if b.len() > 8 {
        return Err(ValueError::BadInt);
    }
    // A sign-only last byte is minimal only to carry the previous byte's top
    // bit; otherwise it is redundant or minus zero.
    if last & 0x7f == 0 && rest.last().is_none_or(|p| p & 0x80 == 0) {
        return Err(ValueError::BadInt);
    }
    let mut magnitude = u64::from(last & 0x7f) << (8 * rest.len());
    for (i, &x) in rest.iter().enumerate() {
        magnitude |= u64::from(x) << (8 * i);
    }
    signed(magnitude, last & 0x80 != 0)
}

/// An eight-byte `int` payload (3.4.3), minus zero refused.
fn int8(b: &[u8]) -> Result<i64, ValueError> {
    let b: [u8; 8] = b.try_into().map_err(|_| ValueError::BadInt)?;
    let raw = u64::from_le_bytes(b);
    let negative = raw >> 63 == 1;
    let magnitude = raw & INT_MAX_MAGNITUDE;
    if negative && magnitude == 0 {
        return Err(ValueError::BadInt);
    }
    signed(magnitude, negative)
}

fn signed(magnitude: u64, negative: bool) -> Result<i64, ValueError> {
    let m = i64::try_from(magnitude).map_err(|_| ValueError::BadInt)?;
    Ok(if negative { -m } else { m })
}

/// `v` as a minimal ScriptNum into `out`, before its push (3.4.3): bytes
/// written, none for zero.
///
/// # Errors
///
/// [`ValueError::BadInt`] for `i64::MIN`, outside KCC-1's range.
pub fn int_argument(v: i64, out: &mut [u8; 8]) -> Result<usize, ValueError> {
    if v == i64::MIN {
        return Err(ValueError::BadInt);
    }
    let mut magnitude = v.unsigned_abs();
    let mut n = 0;
    while magnitude > 0 {
        out[n] = magnitude as u8;
        magnitude >>= 8;
        n += 1;
    }
    if n > 0 {
        if out[n - 1] & 0x80 != 0 {
            // The top bit is the sign's: one more byte for it.
            out[n] = 0;
            n += 1;
        }
        if v < 0 {
            out[n - 1] |= 0x80;
        }
    }
    Ok(n)
}

/// `v` as an eight-byte `int` payload (3.4.3).
///
/// # Errors
///
/// [`ValueError::BadInt`] for `i64::MIN`, outside KCC-1's range.
pub fn int_payload(v: i64) -> Result<[u8; 8], ValueError> {
    if v == i64::MIN {
        return Err(ValueError::BadInt);
    }
    let sign = if v < 0 { 1u64 << 63 } else { 0 };
    Ok((v.unsigned_abs() | sign).to_le_bytes())
}

/// A scalar's payload, read as `ty` in `context`.
fn scalar<'a>(ty: &Type<'_>, b: &'a [u8], context: Context) -> Result<Value<'a>, ValueError> {
    let exactly = |n: usize| {
        (b.len() == n)
            .then_some(Value::Bytes(b))
            .ok_or(ValueError::BadLength)
    };
    match (ty, context) {
        (Type::Int | Type::Temporal, Context::Standalone) => script_num(b).map(Value::Int),
        (Type::Int | Type::Temporal, Context::Payload) => int8(b).map(Value::Int),
        (Type::Bool, Context::Standalone) => match b {
            [] => Ok(Value::Bool(false)),
            [1] => Ok(Value::Bool(true)),
            _ => Err(ValueError::BadBool),
        },
        (Type::Bool, Context::Payload) => match b {
            [0] => Ok(Value::Bool(false)),
            [1] => Ok(Value::Bool(true)),
            _ => Err(ValueError::BadBool),
        },
        (Type::Byte, _) => match b {
            [x] => Ok(Value::Byte(*x)),
            _ => Err(ValueError::BadLength),
        },
        (Type::String, _) => core::str::from_utf8(b)
            .map(Value::Text)
            .map_err(|_| ValueError::BadText),
        (Type::Pubkey, _) => exactly(32),
        (Type::Sig, _) => exactly(65),
        (Type::Datasig, _) => exactly(64),
        _ => Err(ValueError::Type(AbiError::BadLayout)),
    }
}

/// An array's payload of fixed-width `item`s: every element checked, the
/// count against `fixed` if given, `want` read from it.
fn array<'a>(
    item: &Type<'_>,
    fixed: Option<usize>,
    b: &'a [u8],
    want: Option<&[Segment<'_>]>,
) -> Result<Option<Value<'a>>, ValueError> {
    let w = item.width().ok_or(ValueError::Type(AbiError::BadLayout))?;
    let count = match (fixed, w) {
        (Some(n), _) => {
            if Some(b.len()) != n.checked_mul(w) {
                return Err(ValueError::BadLength);
            }
            n
        }
        (None, 0) => return Err(ValueError::Type(AbiError::BadLayout)),
        (None, w) if b.len().is_multiple_of(w) => b.len() / w,
        (None, _) => return Err(ValueError::BadLength),
    };
    let mut found = None;
    for i in 0..count {
        let element = &b[i * w..(i + 1) * w];
        let sub = match want {
            Some([Segment::Index(j), rest @ ..]) if *j == i => Some(rest),
            _ => None,
        };
        if let Some(v) = payload(item, element, sub)? {
            found = Some(v);
        }
    }
    match want {
        None => Ok(None),
        Some([]) if *item == Type::Byte => Ok(Some(Value::Bytes(b))),
        Some([]) => Ok(Some(Value::Array(count))),
        Some(_) => found.map(Some).ok_or(ValueError::BadLocation),
    }
}

/// A fixed-width payload of `ty`, as a state field or array element holds it.
fn payload<'a>(
    ty: &Type<'_>,
    b: &'a [u8],
    want: Option<&[Segment<'_>]>,
) -> Result<Option<Value<'a>>, ValueError> {
    match ty {
        Type::Array(item, n) => array(item, Some(*n), b, want),
        Type::Dynamic(item) => array(item, None, b, want),
        _ => {
            let v = scalar(ty, b, Context::Payload)?;
            match want {
                None => Ok(None),
                Some([]) => Ok(Some(v)),
                Some(_) => Err(ValueError::BadLocation),
            }
        }
    }
}

/// Pushes read one at a time, each in its form's encoding.
pub(super) struct Reader<'a, I> {
    pushes: I,
    form: Form,
    _bytes: core::marker::PhantomData<&'a [u8]>,
}

impl<'a, I: Iterator<Item = Result<Push<'a>, PushError>>> Reader<'a, I> {
    pub(super) fn new(pushes: I, form: Form) -> Self {
        Self {
            pushes,
            form,
            _bytes: core::marker::PhantomData,
        }
    }

    fn take(&mut self) -> Result<&'a [u8], ValueError> {
        let p = self.pushes.next().ok_or(ValueError::Missing)??;
        let canonical = match self.form {
            Form::Argument => p.is_minimal(),
            Form::State => p.is_explicit(),
        };
        if !canonical {
            return Err(ValueError::NotCanonicalPush);
        }
        Ok(p.payload)
    }

    /// Nothing left: no push past the last the types lower to.
    pub(super) fn end(mut self) -> Result<(), ValueError> {
        match self.pushes.next() {
            None => Ok(()),
            Some(Err(e)) => Err(e.into()),
            Some(Ok(_)) => Err(ValueError::Trailing),
        }
    }

    /// One value of `ty`, every push it takes checked, `want` read from it.
    pub(super) fn value(
        &mut self,
        ty: &Type<'_>,
        want: Option<&[Segment<'_>]>,
    ) -> Result<Option<Value<'a>>, ValueError> {
        match ty {
            Type::Record(r) => self.record(r, want),
            Type::Array(Type::Record(r), n) => self.records(r, Some(*n), want),
            Type::Dynamic(Type::Record(r)) => self.records(r, None, want),
            Type::Array(item, n) => array(item, Some(*n), self.take()?, want),
            Type::Dynamic(item) => array(item, None, self.take()?, want),
            _ => {
                let context = match self.form {
                    Form::Argument => Context::Standalone,
                    Form::State => Context::Payload,
                };
                let v = scalar(ty, self.take()?, context)?;
                match want {
                    None => Ok(None),
                    Some([]) => Ok(Some(v)),
                    Some(_) => Err(ValueError::BadLocation),
                }
            }
        }
    }

    /// A record: its fields in order.
    fn record(
        &mut self,
        r: &Record<'_>,
        want: Option<&[Segment<'_>]>,
    ) -> Result<Option<Value<'a>>, ValueError> {
        let mut found = None;
        for f in r.fields {
            if let Some(v) = self.value(&f.ty, field_step(want, f))? {
                found = Some(v);
            }
        }
        on_the_way(want, found, Value::Record)
    }

    /// An array of records: one push per leaf field, all of one length, `fixed`
    /// if given.
    fn records(
        &mut self,
        r: &Record<'_>,
        fixed: Option<usize>,
        want: Option<&[Segment<'_>]>,
    ) -> Result<Option<Value<'a>>, ValueError> {
        let mut groups = Groups {
            fixed,
            count: None,
            index: None,
        };
        // The element `want` names, and where in it.
        let inner = match want {
            Some([Segment::Index(i), rest @ ..]) => {
                groups.index = Some(*i);
                Some(rest)
            }
            _ => None,
        };
        let found = self.groups(r, &mut groups, inner)?;
        let count = groups.count.or(fixed).unwrap_or(0);
        match (want, groups.index) {
            (None, _) => Ok(None),
            (Some([]), _) => Ok(Some(Value::Array(count))),
            (Some(_), Some(i)) if i < count => on_the_way(inner, found, Value::Record),
            _ => Err(ValueError::BadLocation),
        }
    }

    /// `r`'s leaf fields, nested records opened, one push each.
    fn groups(
        &mut self,
        r: &Record<'_>,
        groups: &mut Groups,
        want: Option<&[Segment<'_>]>,
    ) -> Result<Option<Value<'a>>, ValueError> {
        let mut found = None;
        for f in r.fields {
            let sub = field_step(want, f);
            let v = match &f.ty {
                Type::Record(inner) => {
                    let v = self.groups(inner, groups, sub)?;
                    on_the_way(sub, v, Value::Record)?
                }
                leaf => {
                    let w = leaf
                        .width()
                        .filter(|w| *w > 0)
                        .ok_or(ValueError::Type(AbiError::BadLayout))?;
                    let b = self.take()?;
                    if !b.len().is_multiple_of(w) {
                        return Err(ValueError::BadLength);
                    }
                    let n = b.len() / w;
                    if groups.fixed.is_some_and(|f| f != n) {
                        return Err(ValueError::BadLength);
                    }
                    match groups.count {
                        Some(c) if c != n => return Err(ValueError::UnequalGroups),
                        _ => groups.count = Some(n),
                    }
                    let mut v = None;
                    for i in 0..n {
                        let picked = if groups.index == Some(i) { sub } else { None };
                        if let Some(x) = payload(leaf, &b[i * w..(i + 1) * w], picked)? {
                            v = Some(x);
                        }
                    }
                    v
                }
            };
            if v.is_some() {
                found = v;
            }
        }
        Ok(found)
    }
}

/// What an array of records' groups have agreed on so far.
struct Groups {
    /// Its declared length, for `T[N]`.
    fixed: Option<usize>,
    /// The elements in each group read so far.
    count: Option<usize>,
    /// The element a location names.
    index: Option<usize>,
}

/// What remains of `want` past field `f`, when it goes through `f`.
fn field_step<'w, 'p>(want: Option<&'w [Segment<'p>]>, f: &Field<'_>) -> Option<&'w [Segment<'p>]> {
    match want {
        Some([Segment::Field(name), rest @ ..]) if *name == f.name => Some(rest),
        _ => None,
    }
}

/// A container's answer: itself when `want` ends at it, what was found in
/// it when `want` goes on, else no such location.
fn on_the_way<'a>(
    want: Option<&[Segment<'_>]>,
    found: Option<Value<'a>>,
    itself: Value<'a>,
) -> Result<Option<Value<'a>>, ValueError> {
    match want {
        None => Ok(None),
        Some([]) => Ok(Some(itself)),
        Some(_) => found.map(Some).ok_or(ValueError::BadLocation),
    }
}

/// `arguments` ([`super::envelope::Invocation::arguments`]) checked whole
/// against `params`: every argument canonical, nothing left over.
///
/// # Errors
///
/// [`ValueError`]'s, for the first thing wrong.
pub fn check_arguments(params: &[Type<'_>], arguments: &[u8]) -> Result<(), ValueError> {
    read_arguments(params, arguments, None).map(|_| ())
}

/// The value at `path` in argument `index` of `arguments`, after
/// [`check_arguments`]'s checks.
///
/// # Errors
///
/// [`ValueError`]'s; [`ValueError::BadLocation`] for a location that
/// selects nothing.
pub fn argument<'a>(
    params: &[Type<'_>],
    arguments: &'a [u8],
    index: usize,
    path: &[Segment<'_>],
) -> Result<Value<'a>, ValueError> {
    read_arguments(params, arguments, Some((index, path)))?.ok_or(ValueError::BadLocation)
}

fn read_arguments<'a>(
    params: &[Type<'_>],
    arguments: &'a [u8],
    want: Option<(usize, &[Segment<'_>])>,
) -> Result<Option<Value<'a>>, ValueError> {
    params.iter().try_for_each(Type::check_layout)?;
    let mut reader = Reader::new(pushes(arguments), Form::Argument);
    let mut found = None;
    for (i, ty) in params.iter().enumerate() {
        let sub = want.and_then(|(j, path)| (j == i).then_some(path));
        if let Some(v) = reader.value(ty, sub)? {
            found = Some(v);
        }
    }
    reader.end()?;
    Ok(found)
}
