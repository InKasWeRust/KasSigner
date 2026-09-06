//! Serializer for PSKT inputs.

use crate::transaction::model::{Transaction, TransactionInput};
use shared_signer::{PsktParsed, PsktUnknownScope};

use super::super::PskError;
use super::preserved::{emit_additional_fields, emit_value_or_default};
use super::writer::{emit_script_public_key, HexWriter};

const INPUT_CAPTURED_FIELDS: &[&[u8]] = &[
    b"minTime",
    b"bip32Derivations",
    b"finalScriptSig",
    b"proprietaries",
];
const UTXO_CAPTURED_FIELDS: &[&[u8]] = &[b"isCoinbase"];

pub(super) fn emit_inputs_array(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
) -> Result<(), PskError> {
    writer.lit(b"[")?;
    for index in 0..tx.num_inputs {
        if index > 0 {
            writer.lit(b",")?;
        }
        emit_input(writer, tx, parsed, index)?;
    }
    writer.lit(b"]")?;
    Ok(())
}

fn emit_input(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
    index: usize,
) -> Result<(), PskError> {
    let input = &tx.inputs[index];
    let scope = PsktUnknownScope::input(u32::try_from(index).map_err(|_| PskError::CountMismatch)?);

    writer.lit(b"{")?;
    emit_input_identity(writer, input, parsed, index)?;
    emit_input_signing(writer, input, parsed, scope)?;
    emit_input_scripts(writer, tx, input, parsed, scope, index)?;
    emit_input_preserved(writer, parsed, scope)?;
    writer.lit(b"}")?;
    Ok(())
}

fn emit_input_identity(
    writer: &mut HexWriter<'_>,
    input: &TransactionInput,
    parsed: &PsktParsed,
    index: usize,
) -> Result<(), PskError> {
    writer.lit(b"\"utxoEntry\":")?;
    emit_utxo_entry(writer, input, parsed, index)?;
    writer.lit(b",\"previousOutpoint\":")?;
    emit_outpoint(writer, input, parsed, index)?;
    writer.lit(b",\"sequence\":")?;
    writer.u64_string(input.sequence)?;
    Ok(())
}

fn emit_input_signing(
    writer: &mut HexWriter<'_>,
    input: &TransactionInput,
    parsed: &PsktParsed,
    scope: PsktUnknownScope,
) -> Result<(), PskError> {
    writer.lit(b",\"minTime\":")?;
    emit_value_or_default(writer, parsed, scope, b"minTime", b"null")?;
    writer.lit(b",\"partialSigs\":")?;
    emit_partial_sigs(writer, input)?;
    writer.lit(b",\"sighashType\":")?;
    writer.u64(input.sighash_type as u64)?;
    Ok(())
}

fn emit_input_scripts(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    input: &TransactionInput,
    parsed: &PsktParsed,
    scope: PsktUnknownScope,
    index: usize,
) -> Result<(), PskError> {
    writer.lit(b",\"redeemScript\":")?;
    emit_redeem_script(writer, tx, input, index)?;
    writer.lit(b",\"sigOpCount\":")?;
    writer.u64(input.sig_op_count as u64)?;
    writer.lit(b",\"bip32Derivations\":")?;
    emit_input_bip32_derivations(writer, input, parsed, scope)?;
    Ok(())
}

fn emit_redeem_script(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    input: &TransactionInput,
    index: usize,
) -> Result<(), PskError> {
    if input.redeem_script_len == 0 {
        return writer.lit(b"null");
    }
    writer.hex_string_field(tx.redeem_bytes(index))
}

fn emit_input_bip32_derivations(
    writer: &mut HexWriter<'_>,
    input: &TransactionInput,
    parsed: &PsktParsed,
    scope: PsktUnknownScope,
) -> Result<(), PskError> {
    let preserved = super::super::preservation::find_captured_value(
        parsed,
        writer.scratch,
        scope,
        b"bip32Derivations",
    )?
    .is_some();
    if preserved {
        return emit_value_or_default(writer, parsed, scope, b"bip32Derivations", b"{}");
    }
    emit_bip32_derivations_for_input(writer, input)
}

fn emit_input_preserved(
    writer: &mut HexWriter<'_>,
    parsed: &PsktParsed,
    scope: PsktUnknownScope,
) -> Result<(), PskError> {
    writer.lit(b",\"finalScriptSig\":")?;
    emit_value_or_default(writer, parsed, scope, b"finalScriptSig", b"null")?;
    writer.lit(b",\"proprietaries\":")?;
    emit_value_or_default(writer, parsed, scope, b"proprietaries", b"{}")?;
    emit_additional_fields(writer, parsed, scope, INPUT_CAPTURED_FIELDS)
}

fn input_utxo_scope(input_index: usize) -> Result<PsktUnknownScope, PskError> {
    u32::try_from(input_index)
        .map(PsktUnknownScope::input_utxo)
        .map_err(|_| PskError::CountMismatch)
}

fn emit_utxo_identity(
    writer: &mut HexWriter<'_>,
    input: &TransactionInput,
) -> Result<(), PskError> {
    writer.lit(b"{\"amount\":")?;
    writer.u64_string(input.utxo_entry.amount)?;
    writer.lit(b",\"scriptPublicKey\":")?;
    emit_script_public_key(writer, &input.utxo_entry.script_public_key)?;
    writer.lit(b",\"blockDaaScore\":")?;
    writer.u64_string(input.utxo_entry.block_daa_score)
}

fn emit_utxo_entry(
    writer: &mut HexWriter<'_>,
    input: &TransactionInput,
    parsed: &PsktParsed,
    input_index: usize,
) -> Result<(), PskError> {
    let scope = input_utxo_scope(input_index)?;
    emit_utxo_identity(writer, input)?;
    writer.lit(b",\"isCoinbase\":")?;
    emit_value_or_default(writer, parsed, scope, b"isCoinbase", b"false")?;
    emit_additional_fields(writer, parsed, scope, UTXO_CAPTURED_FIELDS)?;
    writer.lit(b"}")
}

fn emit_outpoint(
    writer: &mut HexWriter<'_>,
    input: &TransactionInput,
    parsed: &PsktParsed,
    input_index: usize,
) -> Result<(), PskError> {
    let scope = PsktUnknownScope::input_outpoint(
        u32::try_from(input_index).map_err(|_| PskError::CountMismatch)?,
    );
    writer.lit(b"{\"transactionId\":")?;
    writer.hex_string_field(&input.previous_outpoint.transaction_id)?;
    writer.lit(b",\"index\":")?;
    writer.u64(input.previous_outpoint.index as u64)?;
    emit_additional_fields(writer, parsed, scope, &[])?;
    writer.lit(b"}")?;
    Ok(())
}

fn emit_partial_sig_entry(
    writer: &mut HexWriter<'_>,
    signature: &crate::transaction::model::IncomingPartialSig,
) -> Result<(), PskError> {
    writer.hex_string_field(&signature.pubkey)?;
    writer.lit(b":{\"schnorr\":")?;
    writer.hex_string_field(&signature.signature)?;
    writer.lit(b"}")
}

fn emit_partial_sigs(writer: &mut HexWriter<'_>, input: &TransactionInput) -> Result<(), PskError> {
    if input.incoming_partial_sigs_count == 0 {
        writer.lit(b"{}")?;
        return Ok(());
    }
    writer.lit(b"{")?;
    for index in 0..input.incoming_partial_sigs_count as usize {
        if index > 0 {
            writer.lit(b",")?;
        }
        emit_partial_sig_entry(writer, &input.incoming_partial_sigs[index])?;
    }
    writer.lit(b"}")
}

fn emit_bip32_derivations_for_input(
    writer: &mut HexWriter<'_>,
    input: &TransactionInput,
) -> Result<(), PskError> {
    if input.incoming_partial_sigs_count == 0 {
        writer.lit(b"{}")?;
        return Ok(());
    }
    writer.lit(b"{")?;
    for index in 0..input.incoming_partial_sigs_count as usize {
        if index > 0 {
            writer.lit(b",")?;
        }
        writer.hex_string_field(&input.incoming_partial_sigs[index].pubkey)?;
        writer.lit(b":null")?;
    }
    writer.lit(b"}")?;
    Ok(())
}
