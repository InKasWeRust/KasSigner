//! PSKT/PSKB serializer orchestration.
//!
//! Serialization is canonical rather than byte-identical: whitespace and
//! known field ordering are normalized, parsed signatures may be augmented,
//! and fields represented by the fixed transaction model are re-emitted from
//! that model. Scope-tagged opaque and unknown fields are spliced back from
//! the original decoded JSON while the caller retains the scratch buffer.
//!
//! The fixed preservation budget is explicit. Parsing fails with
//! `TooManyUnknownRegions` rather than silently discarding a value.

mod global;
mod inputs;
mod outputs;
mod preserved;
mod writer;

use crate::transaction::model::{Transaction, MAX_INPUTS};
use shared_signer::{PsktParsed, PsktUnknownScope, TxInputFormat};

use super::preservation::validate_preservation_metadata;
use super::{validate_monetary_shape, PskError, PSKB_MAGIC, PSKT_MAGIC};
use global::emit_global;
use inputs::emit_inputs_array;
use outputs::emit_outputs_array;
use preserved::emit_additional_fields;
use writer::HexWriter;

fn serialization_magic(format: TxInputFormat) -> Result<&'static [u8; 4], PskError> {
    match format {
        TxInputFormat::PsktPskb => Ok(PSKB_MAGIC),
        TxInputFormat::PsktSingle => Ok(PSKT_MAGIC),
        _ => Err(PskError::UnexpectedToken),
    }
}

fn validate_serialization_shape(
    tx: &Transaction,
    parsed: &PsktParsed,
    scratch: &[u8],
) -> Result<(), PskError> {
    if tx.num_inputs > MAX_INPUTS {
        return Err(PskError::TooManyInputs);
    }
    if tx.inputs.get(..tx.num_inputs).is_none() {
        return Err(PskError::CountMismatch);
    }
    if tx.outputs.get(..tx.num_outputs).is_none() {
        return Err(PskError::TooManyOutputs);
    }
    validate_monetary_shape(tx)?;
    validate_preservation_metadata(parsed, scratch, tx.num_inputs, tx.num_outputs)
}

fn emit_envelope(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
    bundle: bool,
) -> Result<(), PskError> {
    if bundle {
        writer.lit(b"[")?;
    }
    emit_pskt_object(writer, tx, parsed)?;
    if bundle {
        writer.lit(b"]")?;
    }
    Ok(())
}

/// Serialize a transaction as a PSKB bundle or a single PSKT envelope.
pub fn serialize_pskt(
    tx: &Transaction,
    parsed: &PsktParsed,
    scratch: &[u8],
    format: TxInputFormat,
    out: &mut [u8],
) -> Result<usize, PskError> {
    let magic = serialization_magic(format)?;
    let prefix = out.get_mut(..4).ok_or(PskError::OutputBufferTooSmall)?;
    validate_serialization_shape(tx, parsed, scratch)?;
    prefix.copy_from_slice(magic);

    let mut writer = HexWriter {
        out,
        pos: 4,
        scratch,
    };
    emit_envelope(
        &mut writer,
        tx,
        parsed,
        matches!(format, TxInputFormat::PsktPskb),
    )?;
    Ok(writer.pos)
}

fn emit_pskt_object(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
) -> Result<(), PskError> {
    writer.lit(b"{\"global\":")?;
    emit_global(writer, tx, parsed)?;
    writer.lit(b",\"inputs\":")?;
    emit_inputs_array(writer, tx, parsed)?;
    writer.lit(b",\"outputs\":")?;
    emit_outputs_array(writer, tx, parsed)?;
    emit_additional_fields(writer, parsed, PsktUnknownScope::top_level(), &[])?;
    writer.lit(b"}")?;
    Ok(())
}

/// Serialize into a heap buffer that grows until the canonical PSKT fits.
pub fn serialize_pskt_vec(
    tx: &Transaction,
    parsed: &PsktParsed,
    scratch: &[u8],
    format: TxInputFormat,
) -> Result<alloc::vec::Vec<u8>, PskError> {
    let capacity = 4_096usize.max(scratch.len().saturating_add(1_024));
    serialize_pskt_vec_with_capacity(tx, parsed, scratch, format, capacity)
}

fn serialize_pskt_vec_with_capacity(
    tx: &Transaction,
    parsed: &PsktParsed,
    scratch: &[u8],
    format: TxInputFormat,
    capacity: usize,
) -> Result<alloc::vec::Vec<u8>, PskError> {
    let mut output = alloc::vec::Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| PskError::OutputBufferTooSmall)?;
    output.resize(capacity, 0u8);
    serialize_pskt(tx, parsed, scratch, format, &mut output)
        .map(|length| {
            output.truncate(length);
            output
        })
        .or_else(|error| retry_pskt_vec(tx, parsed, scratch, format, capacity, error))
}

fn retry_pskt_vec(
    tx: &Transaction,
    parsed: &PsktParsed,
    scratch: &[u8],
    format: TxInputFormat,
    capacity: usize,
    error: PskError,
) -> Result<alloc::vec::Vec<u8>, PskError> {
    if error != PskError::OutputBufferTooSmall {
        return Err(error);
    }
    capacity
        .checked_mul(2)
        .ok_or(PskError::OutputBufferTooSmall)
        .and_then(|next| serialize_pskt_vec_with_capacity(tx, parsed, scratch, format, next))
}

#[cfg(test)]
mod unit_tests;
