//! Serializer helpers for scope-aware captured fields.

use shared_signer::{PsktParsed, PsktUnknownScope};

use super::super::preservation::{captured_field_at, find_captured_value};
use super::super::PskError;
use super::writer::HexWriter;

pub(super) fn emit_value_or_default(
    writer: &mut HexWriter<'_>,
    parsed: &PsktParsed,
    scope: PsktUnknownScope,
    name: &[u8],
    default: &[u8],
) -> Result<(), PskError> {
    if let Some((start, end)) = find_captured_value(parsed, writer.scratch, scope, name)? {
        writer.scratch_range(start, end)
    } else {
        writer.lit(default)
    }
}

/// Append captured fields that are not already emitted at canonical positions.
pub(super) fn emit_additional_fields(
    writer: &mut HexWriter<'_>,
    parsed: &PsktParsed,
    scope: PsktUnknownScope,
    excluded: &[&[u8]],
) -> Result<(), PskError> {
    for index in 0..parsed.unknowns_count as usize {
        let Some((captured_scope, field)) = captured_field_at(parsed, writer.scratch, index)?
        else {
            continue;
        };
        if captured_scope != scope || excluded.contains(&field.key) {
            continue;
        }
        writer.lit(b",")?;
        writer.scratch_range(field.field_start, field.end)?;
    }
    Ok(())
}
