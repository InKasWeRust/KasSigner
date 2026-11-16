// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KCC-1's value types and their names (3.4.1), and an entrypoint's dispatch
//! tag (3.5.1). An ABI is static data on a unit, borrowed all the way down;
//! nothing allocates.

use core::fmt;

/// Length of a dispatch tag.
pub const DISPATCH_TAG_LEN: usize = 4;

/// A KCC-1 value type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type<'a> {
    /// `int`.
    Int,
    /// `bool`.
    Bool,
    /// `byte`.
    Byte,
    /// `string`, UTF-8.
    String,
    /// `pubkey`, 32 bytes.
    Pubkey,
    /// `sig`, 65 bytes.
    Sig,
    /// `datasig`, 64 bytes.
    Datasig,
    /// SilverScript's `temporal`, milliseconds as an `int`. Not a KCC-1 name,
    /// but SilverScript writes it into entrypoint signatures
    /// (`silverscript-lang` 1.0.1, `write_dispatch_type_name`), so its tags
    /// use it.
    Temporal,
    /// `T[N]`. `byte[N]` is a fixed byte string.
    Array(&'a Type<'a>, usize),
    /// `T[]`. `byte[]` is a byte string of any length.
    Dynamic(&'a Type<'a>),
    /// A record.
    Record(&'a Record<'a>),
}

/// A record: its case-sensitive name and its fields, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    /// Its name, a type identifier.
    pub name: &'a str,
    /// Its fields, in declaration order, which is part of the ABI.
    pub fields: &'a [Field<'a>],
}

/// A record's field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    /// Its name. A dispatch tag never includes it.
    pub name: &'a str,
    /// Its type.
    pub ty: Type<'a>,
}

/// An entrypoint: its case-sensitive name and its argument types, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entrypoint<'a> {
    /// Its name.
    pub name: &'a str,
    /// Its argument types, in parameter order.
    pub params: &'a [Type<'a>],
}

/// Why an ABI was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiError {
    /// A record name that is not `[A-Za-z_][A-Za-z0-9_]*` (3.4.1).
    BadIdentifier,
    /// A program with no entrypoint (3.5).
    NoEntrypoint,
    /// Two entrypoints with one dispatch tag (3.5.1).
    DuplicateTag,
    /// A type that can carry no value (3.4.5, 3.4.6).
    BadLayout,
}

/// Whether `s` is a type identifier: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_identifier(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Every leaf of a record, nested records opened, has a positive fixed
/// width (3.4.6).
fn fixed_leaves(r: &Record<'_>) -> Result<(), AbiError> {
    r.fields.iter().try_for_each(|f| match &f.ty {
        Type::Record(inner) => fixed_leaves(inner),
        t if t.width().is_some_and(|w| w > 0) => t.layout(),
        _ => Err(AbiError::BadLayout),
    })
}

/// `n` in base ten, to `put` a digit at a time.
fn put_decimal(mut n: usize, put: &mut dyn FnMut(&str)) {
    let mut digits = [0u8; 20];
    let mut len = 0;
    loop {
        digits[len] = (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for &d in digits[..len].iter().rev() {
        let mut buf = [0u8; 4];
        put(char::from(b'0' + d).encode_utf8(&mut buf));
    }
}

impl Type<'_> {
    /// Every record name this type reaches is a type identifier (3.4.1).
    ///
    /// # Errors
    ///
    /// [`AbiError::BadIdentifier`] for the first one that is not.
    pub fn check(&self) -> Result<(), AbiError> {
        match self {
            Type::Array(item, _) | Type::Dynamic(item) => item.check(),
            Type::Record(r) => {
                if !is_identifier(r.name) {
                    return Err(AbiError::BadIdentifier);
                }
                r.fields.iter().try_for_each(|f| f.ty.check())
            }
            _ => Ok(()),
        }
    }

    /// `width(T)`, its fixed payload width (3.4.4, 3.4.5); `None` for `string`,
    /// `T[]` and a record.
    #[must_use]
    pub const fn width(&self) -> Option<usize> {
        match self {
            Type::Int | Type::Temporal => Some(8),
            Type::Bool | Type::Byte => Some(1),
            Type::Pubkey => Some(32),
            Type::Sig => Some(65),
            Type::Datasig => Some(64),
            Type::Array(item, n) => match item.width() {
                Some(w) => w.checked_mul(*n),
                None => None,
            },
            Type::String | Type::Dynamic(_) | Type::Record(_) => None,
        }
    }

    /// This type can carry a value (3.4.5, 3.4.6) and its record names are type
    /// identifiers: array elements of a fixed width, positive in `T[]`; arrays
    /// of records only of records whose leaves have positive fixed widths.
    ///
    /// # Errors
    ///
    /// [`AbiError::BadIdentifier`], [`AbiError::BadLayout`].
    pub fn check_layout(&self) -> Result<(), AbiError> {
        self.check()?;
        self.layout()
    }

    fn layout(&self) -> Result<(), AbiError> {
        match self {
            Type::Array(Type::Record(r), _) | Type::Dynamic(Type::Record(r)) => fixed_leaves(r),
            Type::Array(item, _) if item.width().is_some() => item.layout(),
            Type::Dynamic(item) if item.width().is_some_and(|w| w > 0) => item.layout(),
            Type::Array(..) | Type::Dynamic(_) => Err(AbiError::BadLayout),
            Type::Record(r) => r.fields.iter().try_for_each(|f| f.ty.layout()),
            _ => Ok(()),
        }
    }

    /// `TypeName(T)` (3.4.1): a record by its name.
    #[must_use]
    pub fn type_name(&self) -> Name<'_, '_> {
        Name {
            ty: self,
            dispatch: false,
        }
    }

    /// `DispatchTypeName(T)` (3.5.1): a record by its field types alone.
    #[must_use]
    pub fn dispatch_name(&self) -> Name<'_, '_> {
        Name {
            ty: self,
            dispatch: true,
        }
    }

    fn put_name(&self, dispatch: bool, put: &mut dyn FnMut(&str)) {
        match self {
            Type::Int => put("int"),
            Type::Bool => put("bool"),
            Type::Byte => put("byte"),
            Type::String => put("string"),
            Type::Pubkey => put("pubkey"),
            Type::Sig => put("sig"),
            Type::Datasig => put("datasig"),
            Type::Temporal => put("temporal"),
            Type::Array(item, n) => {
                item.put_name(dispatch, put);
                put("[");
                put_decimal(*n, put);
                put("]");
            }
            Type::Dynamic(item) => {
                item.put_name(dispatch, put);
                put("[]");
            }
            Type::Record(r) if !dispatch => put(r.name),
            Type::Record(r) => {
                put("{");
                for (i, f) in r.fields.iter().enumerate() {
                    if i > 0 {
                        put(",");
                    }
                    f.ty.put_name(true, put);
                }
                put("}");
            }
        }
    }
}

/// A type's name, as text: [`Type::type_name`] or [`Type::dispatch_name`].
#[derive(Clone, Copy, Debug)]
pub struct Name<'t, 'a> {
    ty: &'t Type<'a>,
    dispatch: bool,
}

/// Every piece `emit` puts written to `f`, the first error kept.
fn display(f: &mut fmt::Formatter<'_>, emit: impl FnOnce(&mut dyn FnMut(&str))) -> fmt::Result {
    let mut result = Ok(());
    emit(&mut |s| {
        if result.is_ok() {
            result = f.write_str(s);
        }
    });
    result
}

impl fmt::Display for Name<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display(f, |put| self.ty.put_name(self.dispatch, put))
    }
}

impl<'a> Entrypoint<'a> {
    /// `FunctionSignature` as text: `name(T_1,...,T_n)`, types by dispatch
    /// name, no whitespace (3.5.1).
    #[must_use]
    pub fn signature(&self) -> Signature<'_, 'a> {
        Signature(self)
    }

    fn put_signature(&self, put: &mut dyn FnMut(&str)) {
        put(self.name);
        put("(");
        for (i, t) in self.params.iter().enumerate() {
            if i > 0 {
                put(",");
            }
            t.put_name(true, put);
        }
        put(")");
    }

    /// The dispatch tag: `Hash(FunctionSignature)[0:4]` (3.5.1).
    ///
    /// # Errors
    ///
    /// [`AbiError::BadIdentifier`] for a record name that is not a type
    /// identifier.
    pub fn dispatch_tag(&self) -> Result<[u8; DISPATCH_TAG_LEN], AbiError> {
        self.params.iter().try_for_each(Type::check)?;
        let mut h = blake3::Hasher::new();
        self.put_signature(&mut |s| {
            h.update(s.as_bytes());
        });
        let mut tag = [0u8; DISPATCH_TAG_LEN];
        tag.copy_from_slice(&h.finalize().as_bytes()[..DISPATCH_TAG_LEN]);
        Ok(tag)
    }
}

/// An entrypoint's `FunctionSignature`, as text: [`Entrypoint::signature`].
#[derive(Clone, Copy, Debug)]
pub struct Signature<'e, 'a>(&'e Entrypoint<'a>);

impl fmt::Display for Signature<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display(f, |put| self.0.put_signature(put))
    }
}

/// A program's entrypoints: at least one (3.5), no two with one dispatch
/// tag (3.5.1).
///
/// # Errors
///
/// [`AbiError::NoEntrypoint`] for none, [`AbiError::DuplicateTag`] for two
/// alike, [`AbiError::BadIdentifier`] for a bad record name.
pub fn check_entrypoints(entries: &[Entrypoint<'_>]) -> Result<(), AbiError> {
    if entries.is_empty() {
        return Err(AbiError::NoEntrypoint);
    }
    for (i, a) in entries.iter().enumerate() {
        let tag = a.dispatch_tag()?;
        for b in &entries[i + 1..] {
            if b.dispatch_tag()? == tag {
                return Err(AbiError::DuplicateTag);
            }
        }
    }
    Ok(())
}
