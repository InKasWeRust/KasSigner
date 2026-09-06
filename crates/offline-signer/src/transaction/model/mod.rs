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

//! Kaspa transaction data model.
//!
//! Protocol limits, script analysis, signatures, inputs, outputs, transaction
//! behavior, and multisig configuration live in single-purpose modules.

mod constants;
mod input;
mod multisig;
mod multisig_change;
mod multisig_validation;
mod output;
mod parse_reset;
mod script;
mod sighash_type;
mod signatures;
mod transaction;

pub use constants::{
    Hash256, SubnetworkId, DEFAULT_INPUT_CAPACITY, MAX_INPUTS, MAX_MULTISIG_KEYS,
    MAX_MULTISIG_WALLETS, MAX_OUTPUTS, MAX_PAYLOAD_SIZE, MAX_REDEEM_SIZE, MAX_SCRIPT_SIZE,
    MAX_SIGS_PER_INPUT, OP_1, OP_2, OP_3, OP_4, OP_5, OP_BLAKE2B, OP_CHECKMULTISIG, OP_CHECKSIG,
    OP_DATA_32, OP_EQUAL, REDEEM_POOL_SIZE, SUBNETWORK_ID_NATIVE,
};
pub use input::{Ms45Hint, Outpoint, TransactionInput};
pub use multisig::{MultisigConfig, MultisigStore};
pub use multisig_change::{find_forged_change, trusted_multisig_output_chain};
pub use output::TransactionOutput;
pub use script::{
    detect_script_type, parse_multisig_script, MultisigInfo, ScriptPublicKey, ScriptType, UtxoEntry,
};
pub use sighash_type::SigHashType;
pub use signatures::{IncomingPartialSig, InputSig};
pub use transaction::{
    Transaction, TransactionAmountError, TransactionAmounts, TransactionStorageError,
};

#[cfg(test)]
mod unit_tests;
