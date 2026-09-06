//! Scope-aware byte-range preservation for fields not represented directly
//! by the fixed transaction model.

use shared_signer::{PsktParsed, PsktUnknownScope, PsktUnknownScopeKind, MAX_PSKT_UNKNOWN_REGIONS};

use super::PskError;

#[derive(Debug, Clone, Copy)]
pub(super) struct CapturedField<'a> {
    pub(super) key: &'a [u8],
    pub(super) field_start: u16,
    pub(super) value_start: u16,
    pub(super) end: u16,
}

/// Record a field range together with its logical owner.
pub(super) fn capture_unknown(
    parsed: &mut PsktParsed,
    scope: PsktUnknownScope,
    start: usize,
    end: usize,
) -> Result<(), PskError> {
    let json_start = parsed.json_start as usize;
    let Some(json_end) = json_start.checked_add(parsed.json_len as usize) else {
        return Err(PskError::JsonTooLarge);
    };
    if start < json_start || start >= end || end > json_end || end > u16::MAX as usize {
        return Err(PskError::JsonTooLarge);
    }
    let index = parsed.unknowns_count as usize;
    if index >= MAX_PSKT_UNKNOWN_REGIONS {
        return Err(PskError::TooManyUnknownRegions);
    }
    parsed.unknowns[index] = (start as u16, end as u16);
    parsed.unknown_scopes[index] = scope;
    parsed.unknowns_count += 1;
    Ok(())
}

#[inline]
fn skip_ws_in_range(bytes: &[u8], start: usize, end: usize) -> usize {
    bytes
        .get(start..end)
        .and_then(|slice| slice.iter().position(|byte| !is_ws(*byte)))
        .and_then(|relative| start.checked_add(relative))
        .unwrap_or(end)
}

/// Parse one captured `"key" : value` range without assuming compact JSON.
///
/// Invalid externally constructed preservation metadata is rejected during
/// serialization rather than being silently omitted.
fn captured_bounds(
    parsed: &PsktParsed,
    scratch_len: usize,
    index: usize,
) -> Result<(usize, usize), PskError> {
    let (start, end) = parsed.unknowns[index];
    let position = start as usize;
    let end = end as usize;
    let json_start = parsed.json_start as usize;
    let json_end = json_start
        .checked_add(parsed.json_len as usize)
        .ok_or(PskError::UnexpectedToken)?;
    if position < json_start || position >= end {
        return Err(PskError::UnexpectedToken);
    }
    if end > json_end || json_end > scratch_len {
        return Err(PskError::UnexpectedToken);
    }
    Ok((position, end))
}

fn captured_key(
    scratch: &[u8],
    mut position: usize,
    end: usize,
) -> Result<(&[u8], usize, usize), PskError> {
    position = skip_ws_in_range(scratch, position, end);
    let field_start = position;
    if scratch.get(position) != Some(&b'"') {
        return Err(PskError::UnexpectedToken);
    }
    let key_start = position.checked_add(1).ok_or(PskError::UnexpectedToken)?;
    let quote_rel = scratch
        .get(key_start..end)
        .and_then(|bytes| bytes.iter().position(|byte| *byte == b'"'))
        .ok_or(PskError::UnexpectedToken)?;
    let quote = key_start
        .checked_add(quote_rel)
        .ok_or(PskError::UnexpectedToken)?;
    Ok((&scratch[key_start..quote], field_start, quote + 1))
}

fn captured_value_start(
    scratch: &[u8],
    mut position: usize,
    end: usize,
) -> Result<usize, PskError> {
    position = skip_ws_in_range(scratch, position, end);
    if scratch.get(position) != Some(&b':') {
        return Err(PskError::UnexpectedToken);
    }
    position = position.checked_add(1).ok_or(PskError::UnexpectedToken)?;
    position = skip_ws_in_range(scratch, position, end);
    if position >= end {
        return Err(PskError::UnexpectedToken);
    }
    Ok(position)
}

pub(super) fn captured_field_at<'a>(
    parsed: &PsktParsed,
    scratch: &'a [u8],
    index: usize,
) -> Result<Option<(PsktUnknownScope, CapturedField<'a>)>, PskError> {
    if index >= parsed.unknowns_count as usize {
        return Ok(None);
    }
    if index >= MAX_PSKT_UNKNOWN_REGIONS {
        return Err(PskError::TooManyUnknownRegions);
    }
    let (position, end_usize) = captured_bounds(parsed, scratch.len(), index)?;
    let (key, field_start, position) = captured_key(scratch, position, end_usize)?;
    let value_start = captured_value_start(scratch, position, end_usize)?;
    Ok(Some((
        parsed.unknown_scopes[index],
        CapturedField {
            key,
            field_start: field_start as u16,
            value_start: value_start as u16,
            end: parsed.unknowns[index].1,
        },
    )))
}

/// Locate a captured value by both scope and field name.
pub(super) fn find_captured_value(
    parsed: &PsktParsed,
    scratch: &[u8],
    scope: PsktUnknownScope,
    name: &[u8],
) -> Result<Option<(u16, u16)>, PskError> {
    for index in 0..parsed.unknowns_count as usize {
        let Some((captured_scope, field)) = captured_field_at(parsed, scratch, index)? else {
            continue;
        };
        if captured_scope == scope && field.key == name {
            return Ok(Some((field.value_start, field.end)));
        }
    }
    Ok(None)
}

/// Validate all externally supplied preservation state before serialization.
///
/// This prevents out-of-bounds counts, stale scratch ranges, duplicate scoped
/// field names, and scopes that cannot be emitted by the supplied transaction.
pub(super) fn validate_preservation_metadata(
    parsed: &PsktParsed,
    scratch: &[u8],
    num_inputs: usize,
    num_outputs: usize,
) -> Result<(), PskError> {
    let count = parsed.unknowns_count as usize;
    if count > MAX_PSKT_UNKNOWN_REGIONS {
        return Err(PskError::TooManyUnknownRegions);
    }

    for index in 0..count {
        let Some((scope, field)) = captured_field_at(parsed, scratch, index)? else {
            return Err(PskError::UnexpectedToken);
        };
        validate_scope(scope, num_inputs, num_outputs)?;

        for previous_index in 0..index {
            let Some((previous_scope, previous_field)) =
                captured_field_at(parsed, scratch, previous_index)?
            else {
                return Err(PskError::UnexpectedToken);
            };
            if previous_scope == scope && previous_field.key == field.key {
                return Err(PskError::DuplicateField);
            }
        }
    }
    Ok(())
}

fn validate_scope(
    scope: PsktUnknownScope,
    num_inputs: usize,
    num_outputs: usize,
) -> Result<(), PskError> {
    let index = scope.index as usize;
    let valid = match scope.kind {
        PsktUnknownScopeKind::TopLevel | PsktUnknownScopeKind::Global => index == 0,
        PsktUnknownScopeKind::Input
        | PsktUnknownScopeKind::InputUtxo
        | PsktUnknownScopeKind::InputOutpoint => index < num_inputs,
        PsktUnknownScopeKind::Output => index < num_outputs,
    };
    if valid {
        Ok(())
    } else {
        Err(PskError::UnexpectedToken)
    }
}

#[inline]
const fn is_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}
