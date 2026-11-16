// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A covenant's state (3.7): the bytes at the ABI's `state.start` and
//! `state.len` (`0` and `0` when stateless), between the template's prefix
//! and suffix. Its fields are pushed by `PushExplicit`, in declaration
//! order, lowered as [`super::value`] says.

use super::abi::Field;
use super::hash::{template_hash, HASH_LEN};
use super::push::pushes;
use super::value::{Form, Reader, Segment, Value, ValueError};

/// Where a program's state lies: its first byte and its length.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    /// `state.start`.
    pub start: usize,
    /// `state.len`.
    pub len: usize,
}

/// A program cut at its state: the template's prefix, the encoded state,
/// the template's suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parts<'a> {
    /// `template.prefix`.
    pub prefix: &'a [u8],
    /// `encoded_state`.
    pub state: &'a [u8],
    /// `template.suffix`.
    pub suffix: &'a [u8],
}

impl<'a> Parts<'a> {
    /// `program` cut at `span`, checked against its length (3.7.2).
    ///
    /// # Errors
    ///
    /// [`ValueError::OutOfBounds`] for a span past the program's end.
    pub fn of(program: &'a [u8], span: Span) -> Result<Self, ValueError> {
        let end = span
            .start
            .checked_add(span.len)
            .ok_or(ValueError::OutOfBounds)?;
        let (head, suffix) = program
            .split_at_checked(end)
            .ok_or(ValueError::OutOfBounds)?;
        let (prefix, state) = head.split_at(span.start);
        Ok(Self {
            prefix,
            state,
            suffix,
        })
    }

    /// The template's hash (3.7.3).
    #[must_use]
    pub fn template_hash(&self) -> [u8; HASH_LEN] {
        template_hash(self.prefix, self.suffix)
    }
}

/// `state` checked whole against the layout `fields`: one canonical push per
/// field it lowers to, nothing missing or after (3.7.1).
///
/// # Errors
///
/// [`ValueError`]'s, for the first thing wrong.
pub fn check_state(fields: &[Field<'_>], state: &[u8]) -> Result<(), ValueError> {
    read_state(fields, state, None).map(|_| ())
}

/// The value at `path` in `state` under `fields`, the path starting at a
/// field's name (3.4.7). The whole state is checked.
///
/// # Errors
///
/// [`ValueError`]'s; [`ValueError::BadLocation`] for a location that
/// selects nothing.
pub fn state_value<'a>(
    fields: &[Field<'_>],
    state: &'a [u8],
    path: &[Segment<'_>],
) -> Result<Value<'a>, ValueError> {
    read_state(fields, state, Some(path))?.ok_or(ValueError::BadLocation)
}

fn read_state<'a>(
    fields: &[Field<'_>],
    state: &'a [u8],
    want: Option<&[Segment<'_>]>,
) -> Result<Option<Value<'a>>, ValueError> {
    fields.iter().try_for_each(|f| f.ty.check_layout())?;
    let mut reader = Reader::new(pushes(state), Form::State);
    let mut found = None;
    for f in fields {
        let sub = match want {
            Some([Segment::Field(name), rest @ ..]) if *name == f.name => Some(rest),
            _ => None,
        };
        if let Some(v) = reader.value(&f.ty, sub)? {
            found = Some(v);
        }
    }
    reader.end()?;
    match want {
        Some([]) => Ok(Some(Value::Record)),
        _ => Ok(found),
    }
}
