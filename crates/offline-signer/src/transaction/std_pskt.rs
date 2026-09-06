// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Kaspa-standard PSKT/PSKB parsing and serialization.
//!
//! This file is the stable public façade. Protocol framing, restricted JSON
//! syntax, schema parsing, canonical serialization, scoped preservation, and
//! signature integration live in focused modules under `transaction/std_pskt/`.
//!
//! # Fidelity boundary
//!
//! Serialization is intentionally canonical, not a promise of byte-identical
//! JSON. Whitespace and known field order are normalized, signer-owned fields
//! are emitted from the fixed `Transaction` model, and partial signatures may
//! be augmented. Opaque and future fields are retained as scope-tagged ranges
//! into the caller-owned decoded JSON scratch buffer and re-emitted within a
//! fixed preservation budget. Parsing fails instead of silently dropping a
//! field when that budget or the u16 offset range is exceeded.
//!
//! Known metadata that is not represented directly by `Transaction`, such as
//! non-default UTXO metadata, output redeem scripts, modifiability flags, and
//! opaque maps, is also preserved through those scoped ranges. Malformed,
//! duplicate, mistyped, or ambiguous schema fields are rejected.

mod envelope;
mod error;
mod parser;
mod preservation;
mod serializer;
mod signatures;
mod syntax;

pub use envelope::{
    detect_tx_format, strip_pskt_magic, DetectedFormat, KSPT_MAGIC, PSKB_MAGIC, PSKT_MAGIC,
};
pub use error::PskError;
pub use parser::parse_pskt;
pub use serializer::{serialize_pskt, serialize_pskt_vec};
pub use signatures::{move_ksp_sigs_to_pskt, pskt_signature_status};
pub use syntax::{hex_decode_strict, hex_encode_lower, parse_u64_num, Tok, Tokenizer};

fn validate_monetary_shape(tx: &crate::transaction::model::Transaction) -> Result<(), PskError> {
    use crate::transaction::model::TransactionAmountError;

    tx.checked_amounts()
        .map(|_| ())
        .map_err(|error| match error {
            TransactionAmountError::InputTotalOverflow => PskError::InputAmountOverflow,
            TransactionAmountError::OutputTotalOverflow => PskError::OutputAmountOverflow,
            TransactionAmountError::OutputsExceedInputs => PskError::OutputsExceedInputs,
        })
}

#[cfg(test)]
mod unit_tests;
