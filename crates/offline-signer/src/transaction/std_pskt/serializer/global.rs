//! Serializer for the PSKT global map.

use crate::transaction::model::Transaction;
use shared_signer::{PsktParsed, PsktUnknownScope};

use super::super::preservation::find_captured_value;
use super::super::PskError;
use super::preserved::{emit_additional_fields, emit_value_or_default};
use super::writer::HexWriter;

const KNOWN_CAPTURED_FIELDS: &[&[u8]] = &[
    b"fallbackLockTime",
    b"inputsModifiable",
    b"outputsModifiable",
    b"xpubs",
    b"id",
    b"proprietaries",
];

pub(super) fn emit_global(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
) -> Result<(), PskError> {
    let scope = PsktUnknownScope::global();
    emit_global_version(writer, tx)?;
    emit_global_locktime(writer, tx, parsed, scope)?;
    emit_global_modifiability(writer, parsed, scope)?;
    emit_global_counts(writer, tx)?;
    emit_global_preserved(writer, parsed, scope)?;
    emit_additional_fields(writer, parsed, scope, KNOWN_CAPTURED_FIELDS)?;
    writer.lit(b"}")
}

fn emit_global_version(writer: &mut HexWriter<'_>, tx: &Transaction) -> Result<(), PskError> {
    writer.lit(b"{\"version\":0,\"txVersion\":")?;
    writer.u64(tx.version as u64)
}

fn emit_global_locktime(
    writer: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
    scope: PsktUnknownScope,
) -> Result<(), PskError> {
    writer.lit(b",\"fallbackLockTime\":")?;
    if find_captured_value(parsed, writer.scratch, scope, b"fallbackLockTime")?.is_some() {
        writer.u64_string(tx.locktime)
    } else {
        writer.lit(b"null")
    }
}

fn emit_global_modifiability(
    writer: &mut HexWriter<'_>,
    parsed: &PsktParsed,
    scope: PsktUnknownScope,
) -> Result<(), PskError> {
    writer.lit(b",\"inputsModifiable\":")?;
    emit_value_or_default(writer, parsed, scope, b"inputsModifiable", b"true")?;
    writer.lit(b",\"outputsModifiable\":")?;
    emit_value_or_default(writer, parsed, scope, b"outputsModifiable", b"true")
}

fn emit_global_counts(writer: &mut HexWriter<'_>, tx: &Transaction) -> Result<(), PskError> {
    writer.lit(b",\"inputCount\":")?;
    writer.u64(tx.num_inputs as u64)?;
    writer.lit(b",\"outputCount\":")?;
    writer.u64(tx.num_outputs as u64)
}

fn emit_global_preserved(
    writer: &mut HexWriter<'_>,
    parsed: &PsktParsed,
    scope: PsktUnknownScope,
) -> Result<(), PskError> {
    writer.lit(b",\"xpubs\":")?;
    emit_value_or_default(writer, parsed, scope, b"xpubs", b"{}")?;
    writer.lit(b",\"id\":")?;
    emit_value_or_default(writer, parsed, scope, b"id", b"null")?;
    writer.lit(b",\"proprietaries\":")?;
    emit_value_or_default(writer, parsed, scope, b"proprietaries", b"{}")
}
