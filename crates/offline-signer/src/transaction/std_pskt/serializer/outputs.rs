//! Serializer for PSKT outputs.

use crate::transaction::model::Transaction;
use shared_signer::{PsktParsed, PsktUnknownScope};

use super::super::PskError;
use super::preserved::{emit_additional_fields, emit_value_or_default};
use super::writer::{emit_script_public_key, HexWriter};

const OUTPUT_CAPTURED_FIELDS: &[&[u8]] = &[b"redeemScript", b"bip32Derivations", b"proprietaries"];

pub(super) fn emit_outputs_array(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
) -> Result<(), PskError> {
    writer.lit(b"[")?;
    for index in 0..tx.num_outputs {
        if index > 0 {
            writer.lit(b",")?;
        }
        emit_output(writer, tx, parsed, index)?;
    }
    writer.lit(b"]")?;
    Ok(())
}

fn output_scope(index: usize) -> Result<PsktUnknownScope, PskError> {
    u32::try_from(index)
        .map(PsktUnknownScope::output)
        .map_err(|_| PskError::TooManyOutputs)
}

fn emit_output_identity(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    index: usize,
) -> Result<(), PskError> {
    let output = &tx.outputs[index];
    writer.lit(b"{\"amount\":")?;
    writer.u64_string(output.value)?;
    writer.lit(b",\"scriptPublicKey\":")?;
    emit_script_public_key(writer, &output.script_public_key)
}

fn emit_output_preserved(
    writer: &mut HexWriter<'_>,
    parsed: &PsktParsed,
    scope: PsktUnknownScope,
) -> Result<(), PskError> {
    writer.lit(b",\"redeemScript\":")?;
    emit_value_or_default(writer, parsed, scope, b"redeemScript", b"null")?;
    writer.lit(b",\"bip32Derivations\":")?;
    emit_value_or_default(writer, parsed, scope, b"bip32Derivations", b"{}")?;
    writer.lit(b",\"proprietaries\":")?;
    emit_value_or_default(writer, parsed, scope, b"proprietaries", b"{}")
}

fn emit_output(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
    index: usize,
) -> Result<(), PskError> {
    let scope = output_scope(index)?;
    emit_output_identity(writer, tx, index)?;
    emit_covenant_binding(writer, tx, parsed, index)?;
    emit_output_preserved(writer, parsed, scope)?;
    emit_additional_fields(writer, parsed, scope, OUTPUT_CAPTURED_FIELDS)?;
    writer.lit(b"}")
}

fn emit_covenant_binding(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
    index: usize,
) -> Result<(), PskError> {
    validate_covenant_binding(tx, index)?;
    if !should_emit_covenant_binding(tx, parsed, index) {
        return Ok(());
    }
    writer.lit(b",\"covenantBinding\":")?;
    emit_covenant_value(writer, tx, index)
}

fn validate_covenant_binding(tx: &Transaction, index: usize) -> Result<(), PskError> {
    let output = &tx.outputs[index];
    (!output.has_covenant || (output.covenant_auth_input as usize) < tx.num_inputs)
        .then_some(())
        .ok_or(PskError::InvalidCovenantBinding)
}

fn should_emit_covenant_binding(tx: &Transaction, parsed: &PsktParsed, index: usize) -> bool {
    tx.outputs[index].has_covenant || parsed.output_has_covenant_binding_field(index)
}

fn emit_covenant_value(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    index: usize,
) -> Result<(), PskError> {
    if !tx.outputs[index].has_covenant {
        return writer.lit(b"null");
    }
    emit_present_covenant_value(writer, tx, index)
}

fn emit_present_covenant_value(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    index: usize,
) -> Result<(), PskError> {
    let output = &tx.outputs[index];
    writer
        .lit(b"{\"authorizingInput\":")
        .and_then(|()| writer.u64(output.covenant_auth_input as u64))
        .and_then(|()| writer.lit(b",\"covenantId\":"))
        .and_then(|()| writer.hex_string_field(&output.covenant_id))
        .and_then(|()| writer.lit(b"}"))
}
