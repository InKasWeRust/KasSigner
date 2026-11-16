// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Reading Kaspa script (table: `crypto/txscript/src/opcodes/mod.rs`).
//!
//! A signer never runs a script: it signs against a redeem script and shows
//! it. So this module has the opcode table and a disassembler, not the
//! engine; [`unlock`] writes the unlocking script, pushes only.
//!
//! The disassembler is why the wire format has no covenant type byte. Raw hex
//! on the signer would leave the only readable account of a transaction in
//! the application, the surface a signer exists to distrust. Reading a script
//! back is a fact anyone can check; naming a construction is a claim only its
//! author can make. An opcode the pin does not know shows as unknown, never
//! skipped or guessed.

pub mod opcodes;
pub mod recognize;
pub mod unlock;

pub use opcodes::{OPCODE_LENGTHS, OPCODE_NAMES};
pub use recognize::{
    address_payload, classify, kcc3_key, kcc3_redeem, kcc3_script_hash, multisig_shape,
    parse_multisig, pay_to_pubkey, pay_to_script_hash, redeem_hash, redeem_matches, schnorr_keys,
    Multisig, ScriptClass, KCC3_REDEEM_LEN, PAY_TO_PUBKEY_LEN, PAY_TO_SCRIPT_HASH_LEN,
};

/// One step of a disassembled script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step<'a> {
    /// Byte offset of the opcode within the script.
    pub offset: usize,
    /// The opcode byte.
    pub opcode: u8,
    /// Its name at the pinned revision.
    pub name: &'static str,
    /// Data pushed by this step, empty for everything that is not a push.
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisasmError {
    /// A push declares more bytes than the script holds, at `offset`.
    Truncated { offset: usize },
}

/// Walk a script one opcode at a time. A malformed push ends the walk with an
/// error: a guessed length would show what the network does not agree with.
pub struct Disassembler<'a> {
    script: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> Disassembler<'a> {
    pub fn new(script: &'a [u8]) -> Self {
        Self {
            script,
            pos: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for Disassembler<'a> {
    type Item = Result<Step<'a>, DisasmError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.pos >= self.script.len() {
            return None;
        }
        let offset = self.pos;
        let opcode = self.script[offset];
        let name = OPCODE_NAMES[opcode as usize];
        let declared = OPCODE_LENGTHS[opcode as usize];

        // Positive: the opcode plus a fixed number of data bytes.
        // Negative: a length field of that width follows the opcode.
        let (header, data_len) = if declared >= 0 {
            (1usize, (declared as usize).saturating_sub(1))
        } else {
            let width = (-declared) as usize;
            if offset + 1 + width > self.script.len() {
                self.done = true;
                return Some(Err(DisasmError::Truncated { offset }));
            }
            let mut n = 0usize;
            for i in 0..width {
                n |= (self.script[offset + 1 + i] as usize) << (8 * i);
            }
            (1 + width, n)
        };

        let start = offset + header;
        let end = match start.checked_add(data_len) {
            Some(e) if e <= self.script.len() => e,
            _ => {
                self.done = true;
                return Some(Err(DisasmError::Truncated { offset }));
            }
        };

        self.pos = end;
        Some(Ok(Step {
            offset,
            opcode,
            name,
            data: &self.script[start..end],
        }))
    }
}
