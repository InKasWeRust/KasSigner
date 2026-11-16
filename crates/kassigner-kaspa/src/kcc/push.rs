// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KCC-1's two data pushes (3.4.2), written and read: `PushMinimal` for
//! arguments and the program, `PushExplicit` for state fields. They differ
//! only for a one-byte payload with a small-number opcode: `01` to `10` and
//! `81`.
//!
//! Up to 65,535 bytes `PushExplicit` is [`crate::script::unlock::push`]'s;
//! past it, `OP_PUSHDATA4` and a 32-bit length. Consensus's script and
//! element limits apply on top and are not checked here.

use crate::script::unlock::{self, UnlockError};
use crate::script::{DisasmError, Disassembler};

/// `OP_0`.
const OP_0: u8 = 0x00;
/// `OP_PUSHDATA4`.
const OP_PUSHDATA4: u8 = 0x4e;
/// `OP_1NEGATE`.
const OP_1NEGATE: u8 = 0x4f;
/// `OP_RESERVED`: below `OP_16`, but no push.
const OP_RESERVED: u8 = 0x50;
/// `OP_1`; `OP_16` is fifteen above it.
const OP_1: u8 = 0x51;
/// `OP_16`.
const OP_16: u8 = 0x60;
/// The largest `OP_DATA_n`.
const OP_DATA_MAX: u8 = 75;
/// `OP_PUSHDATA1`.
const OP_PUSHDATA1: u8 = 0x4c;
/// `OP_PUSHDATA2`.
const OP_PUSHDATA2: u8 = 0x4d;

/// What each small-number opcode pushes, `OP_1NEGATE` then `OP_1` to
/// `OP_16`; static, so a read push can borrow its payload.
static SMALL: [u8; 17] = [
    0x81, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10,
];

/// Why a push was not written or read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushError {
    /// The caller's buffer cannot hold it.
    BufferTooSmall,
    /// A payload past `OP_PUSHDATA4`'s 32-bit length.
    TooLong,
    /// A push that runs past the script's end.
    Truncated,
    /// An opcode that pushes no data where only pushes may be.
    NotPush,
}

/// The opcode a one-byte payload has of its own under `PushMinimal`.
const fn small_opcode(payload: &[u8]) -> Option<u8> {
    match payload {
        [b @ 0x01..=0x10] => Some(OP_1 - 1 + *b),
        [0x81] => Some(OP_1NEGATE),
        _ => None,
    }
}

/// Bytes `PushExplicit` takes for a payload of `len` bytes.
#[must_use]
pub const fn explicit_len(len: usize) -> usize {
    if len <= u16::MAX as usize {
        unlock::push_len(len)
    } else {
        5 + len
    }
}

/// Bytes `PushMinimal` takes for `payload`.
#[must_use]
pub const fn minimal_len(payload: &[u8]) -> usize {
    if small_opcode(payload).is_some() {
        1
    } else {
        explicit_len(payload.len())
    }
}

/// `PushExplicit(payload)` into `out`: bytes written.
///
/// # Errors
///
/// [`PushError::TooLong`] past a 32-bit length, [`PushError::BufferTooSmall`].
pub fn push_explicit(payload: &[u8], out: &mut [u8]) -> Result<usize, PushError> {
    if payload.len() <= u16::MAX as usize {
        return unlock::push(payload, out).map_err(|e| match e {
            UnlockError::BufferTooSmall => PushError::BufferTooSmall,
            _ => PushError::TooLong,
        });
    }
    let len = u32::try_from(payload.len()).map_err(|_| PushError::TooLong)?;
    let total = payload.len().checked_add(5).ok_or(PushError::TooLong)?;
    let out = out.get_mut(..total).ok_or(PushError::BufferTooSmall)?;
    out[0] = OP_PUSHDATA4;
    out[1..5].copy_from_slice(&len.to_le_bytes());
    out[5..].copy_from_slice(payload);
    Ok(total)
}

/// `PushMinimal(payload)` into `out`: bytes written.
///
/// # Errors
///
/// [`PushError::TooLong`] past a 32-bit length, [`PushError::BufferTooSmall`].
pub fn push_minimal(payload: &[u8], out: &mut [u8]) -> Result<usize, PushError> {
    match small_opcode(payload) {
        Some(op) => {
            *out.first_mut().ok_or(PushError::BufferTooSmall)? = op;
            Ok(1)
        }
        None => push_explicit(payload, out),
    }
}

/// One push of a script, as it was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Push<'a> {
    /// Where its opcode is in the script.
    pub offset: usize,
    /// Its opcode.
    pub opcode: u8,
    /// What it pushes: for a small-number opcode, the number's one byte.
    pub payload: &'a [u8],
}

impl Push<'_> {
    /// The opcode `PushExplicit` writes for this payload.
    const fn explicit_opcode(&self) -> u8 {
        let n = self.payload.len();
        if n == 0 {
            OP_0
        } else if n <= OP_DATA_MAX as usize {
            n as u8
        } else if n <= u8::MAX as usize {
            OP_PUSHDATA1
        } else if n <= u16::MAX as usize {
            OP_PUSHDATA2
        } else {
            OP_PUSHDATA4
        }
    }

    /// Whether it was written as `PushMinimal` writes its payload.
    #[must_use]
    pub const fn is_minimal(&self) -> bool {
        let want = match small_opcode(self.payload) {
            Some(op) => op,
            None => self.explicit_opcode(),
        };
        self.opcode == want
    }

    /// Whether it was written as `PushExplicit` writes its payload.
    #[must_use]
    pub const fn is_explicit(&self) -> bool {
        self.opcode == self.explicit_opcode()
    }
}

/// The pushes of `script`, in order, as written. A non-push opcode,
/// `OP_RESERVED` included, ends them with [`PushError::NotPush`]; a push past
/// the end with [`PushError::Truncated`].
pub fn pushes(script: &[u8]) -> impl Iterator<Item = Result<Push<'_>, PushError>> + '_ {
    let mut failed = false;
    Disassembler::new(script).map_while(move |step| {
        if failed {
            return None;
        }
        let read = match step {
            Err(DisasmError::Truncated { .. }) => Err(PushError::Truncated),
            Ok(s) => match s.opcode {
                OP_1NEGATE => Ok(&SMALL[..1]),
                OP_1..=OP_16 => {
                    let i = usize::from(s.opcode - OP_1) + 1;
                    Ok(&SMALL[i..=i])
                }
                OP_RESERVED => Err(PushError::NotPush),
                op if op <= OP_PUSHDATA4 => Ok(s.data),
                _ => Err(PushError::NotPush),
            }
            .map(|payload| Push {
                offset: s.offset,
                opcode: s.opcode,
                payload,
            }),
        };
        failed = read.is_err();
        Some(read)
    })
}
