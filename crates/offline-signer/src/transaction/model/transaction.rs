// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

mod formatting;

use super::{
    constants::{
        SubnetworkId, DEFAULT_INPUT_CAPACITY, MAX_INPUTS, MAX_OUTPUTS, MAX_PAYLOAD_SIZE,
        MAX_REDEEM_SIZE, MAX_SCRIPT_SIZE, REDEEM_POOL_SIZE, SUBNETWORK_ID_NATIVE,
    },
    input::TransactionInput,
    output::TransactionOutput,
};
use crate::address::KaspaNetwork;
use alloc::{boxed::Box, vec::Vec};
/// Aggregate monetary totals for a transaction after checked arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionAmounts {
    pub input_total: u64,
    pub output_total: u64,
    pub fee: u64,
}
/// Monetary-shape failures that must reject a transaction before review/signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionAmountError {
    InputTotalOverflow,
    OutputTotalOverflow,
    OutputsExceedInputs,
}

/// Fallible-storage failures while constructing or expanding a transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionStorageError {
    AllocationFailed,
    TooManyInputs,
    RedeemScriptTooLarge,
    RedeemPoolFull,
    InternalStorageInvariant,
}
/// A complete Kaspa transaction with inputs, outputs, and metadata.
#[derive(Debug)]
pub struct Transaction {
    pub version: u16,
    pub inputs: Vec<TransactionInput>,
    pub num_inputs: usize,
    pub outputs: Box<[TransactionOutput; MAX_OUTPUTS]>,
    pub num_outputs: usize,
    /// Network bound by mandatory KSPT v4 metadata for address review.
    /// `Unknown` is valid only for a newly constructed, not-yet-serialized model.
    pub network: KaspaNetwork,
    pub locktime: u64,
    pub subnetwork_id: SubnetworkId,
    pub gas: u64,
    pub payload: Box<[u8; MAX_PAYLOAD_SIZE]>,
    pub payload_len: usize,
    /// Stealth address tweak: if non-zero, the signing key is
    /// account_privkey + stealth_tweak (scalar addition mod n).
    /// Set by KasSee when spending a stealth UTXO.
    pub stealth_tweak: [u8; 32],
    pub has_stealth_tweak: bool,
    /// Shared pool for redeem scripts > MAX_SCRIPT_SIZE bytes.
    /// Inputs with `redeem_in_pool == true` store their redeem data here
    /// at `redeem_script_offset..redeem_script_offset + redeem_script_len`.
    pub redeem_pool: Box<[u8; REDEEM_POOL_SIZE]>,
    /// Next free byte in redeem_pool.
    pub redeem_pool_used: usize,
}
fn try_boxed_array<T, F, const N: usize>(
    mut make: F,
) -> Result<Box<[T; N]>, TransactionStorageError>
where
    F: FnMut() -> T,
{
    let mut values = Vec::new();
    values
        .try_reserve_exact(N)
        .map_err(|_| TransactionStorageError::AllocationFailed)?;
    for _ in 0..N {
        values.push(make());
    }
    let boxed: Box<[T]> = values.into_boxed_slice();
    boxed
        .try_into()
        .map_err(|_| TransactionStorageError::InternalStorageInvariant)
}
impl Transaction {
    /// Create an empty transaction. The input vector starts with capacity for
    /// ordinary eight-input transactions and grows only up to `MAX_INPUTS`.
    /// All large fixed stores are allocated fallibly so firmware callers can
    /// reject memory pressure rather than panic.
    pub fn try_new() -> Result<Self, TransactionStorageError> {
        let mut inputs = Vec::new();
        inputs
            .try_reserve_exact(DEFAULT_INPUT_CAPACITY)
            .map_err(|_| TransactionStorageError::AllocationFailed)?;
        inputs.resize_with(DEFAULT_INPUT_CAPACITY, TransactionInput::empty);
        Ok(Self {
            version: 0,
            inputs,
            num_inputs: 0,
            outputs: try_boxed_array(TransactionOutput::empty)?,
            num_outputs: 0,
            network: KaspaNetwork::Unknown,
            locktime: 0,
            subnetwork_id: SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: try_boxed_array(|| 0u8)?,
            payload_len: 0,
            stealth_tweak: [0u8; 32],
            has_stealth_tweak: false,
            redeem_pool: try_boxed_array(|| 0u8)?,
            redeem_pool_used: 0,
        })
    }

    /// Reset the transaction while retaining allocated input capacity.
    pub fn clear(&mut self) {
        self.version = 0;
        self.num_inputs = 0;
        for input in &mut self.inputs {
            *input = TransactionInput::empty();
        }
        for output in self.outputs.iter_mut() {
            *output = TransactionOutput::empty();
        }
        self.num_outputs = 0;
        self.network = KaspaNetwork::Unknown;
        self.locktime = 0;
        self.subnetwork_id = SUBNETWORK_ID_NATIVE;
        self.gas = 0;
        self.payload.fill(0);
        self.payload_len = 0;
        self.stealth_tweak.fill(0);
        self.has_stealth_tweak = false;
        self.redeem_pool.fill(0);
        self.redeem_pool_used = 0;
    }

    /// Ensure storage exists for every declared input. This grows only the
    /// backing vector; `num_inputs` remains controlled by the parser/builder.
    pub fn ensure_input_slots(&mut self, count: usize) -> Result<(), TransactionStorageError> {
        if count > MAX_INPUTS {
            return Err(TransactionStorageError::TooManyInputs);
        }
        if count > self.inputs.len() {
            self.inputs
                .try_reserve(count - self.inputs.len())
                .map_err(|_| TransactionStorageError::AllocationFailed)?;
            self.inputs.resize_with(count, TransactionInput::empty);
        }
        Ok(())
    }

    /// Get the redeem script bytes for input `idx`.
    /// Returns the inline buffer if the script fits, or the pool slice
    /// if `redeem_in_pool` is set.
    pub fn redeem_bytes(&self, idx: usize) -> &[u8] {
        let inp = &self.inputs[idx];
        if inp.redeem_script_len == 0 {
            return &[];
        }
        if inp.redeem_in_pool {
            let off = inp.redeem_script_offset as usize;
            &self.redeem_pool[off..off + inp.redeem_script_len]
        } else {
            &inp.redeem_script[..inp.redeem_script_len]
        }
    }

    /// Store a redeem script for input `idx`. Scripts <= MAX_SCRIPT_SIZE
    /// go inline; larger ones go into the shared pool.
    /// Returns a specific storage error if the script cannot be retained safely.
    pub fn store_redeem(&mut self, idx: usize, data: &[u8]) -> Result<(), TransactionStorageError> {
        let len = data.len();
        if len == 0 {
            self.inputs[idx].redeem_script_len = 0;
            self.inputs[idx].redeem_in_pool = false;
            return Ok(());
        }
        if len <= MAX_SCRIPT_SIZE {
            self.inputs[idx].redeem_script[..len].copy_from_slice(data);
            self.inputs[idx].redeem_script_len = len;
            self.inputs[idx].redeem_in_pool = false;
        } else {
            if len > MAX_REDEEM_SIZE {
                return Err(TransactionStorageError::RedeemScriptTooLarge);
            }
            let off = self.redeem_pool_used;
            if off + len > REDEEM_POOL_SIZE {
                return Err(TransactionStorageError::RedeemPoolFull);
            }
            self.redeem_pool[off..off + len].copy_from_slice(data);
            self.inputs[idx].redeem_script_offset = off as u16;
            self.inputs[idx].redeem_script_len = len;
            self.inputs[idx].redeem_in_pool = true;
            self.redeem_pool_used = off + len;
        }
        Ok(())
    }

    /// Get the transaction inputs slice.
    pub fn inputs(&self) -> &[TransactionInput] {
        &self.inputs[..self.num_inputs]
    }

    /// Get the transaction outputs slice.
    pub fn outputs(&self) -> &[TransactionOutput] {
        &self.outputs[..self.num_outputs]
    }

    /// Returns true if the transaction subnetwork is native (not a registry tx).
    pub fn is_native(&self) -> bool {
        self.subnetwork_id == SUBNETWORK_ID_NATIVE
    }

    /// Calculate aggregate transaction amounts with checked arithmetic.
    ///
    /// A transaction is invalid if either aggregate exceeds `u64::MAX` or if
    /// outputs exceed inputs. Callers must propagate the error rather than
    /// displaying or signing a fabricated/saturated fee.
    pub fn checked_amounts(&self) -> Result<TransactionAmounts, TransactionAmountError> {
        let input_total = self.inputs().iter().try_fold(0u64, |total, input| {
            total
                .checked_add(input.utxo_entry.amount)
                .ok_or(TransactionAmountError::InputTotalOverflow)
        })?;
        let output_total = self.outputs().iter().try_fold(0u64, |total, output| {
            total
                .checked_add(output.value)
                .ok_or(TransactionAmountError::OutputTotalOverflow)
        })?;
        let fee = input_total
            .checked_sub(output_total)
            .ok_or(TransactionAmountError::OutputsExceedInputs)?;
        Ok(TransactionAmounts {
            input_total,
            output_total,
            fee,
        })
    }

    /// Calculate total sompi across inputs without overflow.
    pub fn total_input_value(&self) -> Result<u64, TransactionAmountError> {
        self.checked_amounts().map(|amounts| amounts.input_total)
    }

    /// Calculate total sompi across outputs without overflow.
    pub fn total_output_value(&self) -> Result<u64, TransactionAmountError> {
        self.checked_amounts().map(|amounts| amounts.output_total)
    }

    /// Implicit fee = inputs - outputs, rejecting an invalid monetary shape.
    pub fn fee(&self) -> Result<u64, TransactionAmountError> {
        self.checked_amounts().map(|amounts| amounts.fee)
    }
}
