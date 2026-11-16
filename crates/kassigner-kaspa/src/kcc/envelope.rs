// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KCC-1's P2SH covenant envelope (3.6): a program's lock, and a spend's
//! invocation. For the cards to come: nothing on a unit calls this yet.
//!
//! A covenant coin is plain pay-to-script-hash under version 0
//! ([`crate::script::pay_to_script_hash`]) of its program R. The spend's
//! signature script is push-only:
//!
//! ```text
//! PushArguments(arguments)
//! OP_DATA_4 dispatch_tag
//! PushMinimal(R)
//! ```
//!
//! Consensus checks R against the coin and runs it; the layout names the
//! entrypoint. Decoding the arguments takes the program's ABI (3.4).

use super::abi::DISPATCH_TAG_LEN;
use super::push::{minimal_len, push_minimal, pushes, Push, PushError};
use crate::script::{pay_to_script_hash, redeem_hash, redeem_matches, PAY_TO_SCRIPT_HASH_LEN};
use crate::tx::ScriptPublicKey;

/// `OP_DATA_4`, the dispatch tag's push.
const OP_DATA_4: u8 = 0x04;

/// Bytes the dispatch tag takes in a signature script, with its push.
pub const DISPATCH_TAG_PUSH_LEN: usize = 1 + DISPATCH_TAG_LEN;

/// An invocation, as a spend's signature script carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invocation<'a> {
    /// `PushArguments(arguments)`, as they arrived.
    pub arguments: &'a [u8],
    /// The entrypoint's dispatch tag.
    pub dispatch_tag: [u8; DISPATCH_TAG_LEN],
    /// The program, R.
    pub program: &'a [u8],
}

/// Why a signature script is not a KCC-1 invocation, or was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// A push that runs past the script's end.
    Truncated,
    /// An opcode that is not a push: a signature script is push-only.
    NotPushOnly,
    /// No dispatch tag: fewer than two pushes, or the one before the program
    /// is not `OP_DATA_4` and four bytes.
    NoDispatchTag,
    /// The program pushed in another form than `PushMinimal`.
    ProgramNotMinimal,
    /// A program that does not hash to the coin's script, or a coin that is not
    /// version 0 pay-to-script-hash.
    NotTheCoinsProgram,
    /// The caller's buffer cannot hold the script.
    BufferTooSmall,
    /// A program past `OP_PUSHDATA4`'s 32-bit length.
    TooLong,
}

impl From<PushError> for EnvelopeError {
    fn from(e: PushError) -> Self {
        match e {
            PushError::BufferTooSmall => Self::BufferTooSmall,
            PushError::TooLong => Self::TooLong,
            PushError::Truncated => Self::Truncated,
            PushError::NotPush => Self::NotPushOnly,
        }
    }
}

/// The script that locks `program`, under script version 0:
/// `OP_BLAKE2B OP_DATA_32 Blake2b(program) OP_EQUAL`.
#[must_use]
pub fn locking_script(program: &[u8]) -> [u8; PAY_TO_SCRIPT_HASH_LEN] {
    pay_to_script_hash(&redeem_hash(program))
}

/// The invocation `signature_script` carries.
///
/// # Errors
///
/// [`EnvelopeError::Truncated`], [`EnvelopeError::NotPushOnly`],
/// [`EnvelopeError::NoDispatchTag`], [`EnvelopeError::ProgramNotMinimal`].
pub fn read(signature_script: &[u8]) -> Result<Invocation<'_>, EnvelopeError> {
    // Only the last two pushes are kept; each is checked as it passes.
    let mut last: Option<Push<'_>> = None;
    let mut before: Option<Push<'_>> = None;
    for push in pushes(signature_script) {
        before = last;
        last = Some(push?);
    }
    let (Some(tag), Some(program)) = (before, last) else {
        return Err(EnvelopeError::NoDispatchTag);
    };
    let dispatch_tag: [u8; DISPATCH_TAG_LEN] = match (tag.opcode, tag.payload.try_into()) {
        (OP_DATA_4, Ok(t)) => t,
        _ => return Err(EnvelopeError::NoDispatchTag),
    };
    if !program.is_minimal() {
        return Err(EnvelopeError::ProgramNotMinimal);
    }
    Ok(Invocation {
        arguments: &signature_script[..tag.offset],
        dispatch_tag,
        program: program.payload,
    })
}

/// [`read`], the program checked to be the one `coin` commits to.
///
/// # Errors
///
/// [`read`]'s, and [`EnvelopeError::NotTheCoinsProgram`].
pub fn read_spend<'a>(
    coin: &ScriptPublicKey<'_>,
    signature_script: &'a [u8],
) -> Result<Invocation<'a>, EnvelopeError> {
    let invocation = read(signature_script)?;
    if !redeem_matches(coin, invocation.program) {
        return Err(EnvelopeError::NotTheCoinsProgram);
    }
    Ok(invocation)
}

/// Bytes [`write()`] takes for `arguments_len` bytes of argument pushes and
/// `program`.
#[must_use]
pub const fn signature_script_len(arguments_len: usize, program: &[u8]) -> usize {
    arguments_len + DISPATCH_TAG_PUSH_LEN + minimal_len(program)
}

/// The signature script of `invocation` into `out`. Bytes written.
///
/// # Errors
///
/// [`EnvelopeError::NotPushOnly`] or [`EnvelopeError::Truncated`] for
/// arguments that are not whole pushes, [`EnvelopeError::TooLong`],
/// [`EnvelopeError::BufferTooSmall`].
pub fn write(invocation: &Invocation<'_>, out: &mut [u8]) -> Result<usize, EnvelopeError> {
    for push in pushes(invocation.arguments) {
        push?;
    }
    let args = invocation.arguments.len();
    let at = args + DISPATCH_TAG_PUSH_LEN;
    let head = out.get_mut(..at).ok_or(EnvelopeError::BufferTooSmall)?;
    head[..args].copy_from_slice(invocation.arguments);
    head[args] = OP_DATA_4;
    head[args + 1..].copy_from_slice(&invocation.dispatch_tag);
    let tail = out.get_mut(at..).ok_or(EnvelopeError::BufferTooSmall)?;
    Ok(at + push_minimal(invocation.program, tail)?)
}
