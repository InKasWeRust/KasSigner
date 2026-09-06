//! Shared typed-token and schema parsing helpers.

use crate::transaction::model::{ScriptPublicKey, MAX_SCRIPT_SIZE};
use shared_signer::{PsktParsed, PsktUnknownScope};

use super::super::preservation::capture_unknown;

use super::super::{hex_decode_strict, parse_u64_num, PskError, Tok, Tokenizer};

const MAX_JSON_NESTING: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerState {
    ObjectKeyOrEnd,
    ObjectKey,
    ObjectColon,
    ObjectValue,
    ObjectCommaOrEnd,
    ArrayValueOrEnd,
    ArrayValue,
    ArrayCommaOrEnd,
}

pub(super) fn expect(tok: &mut Tokenizer<'_>, expected: Tok<'_>) -> Result<(), PskError> {
    let got = tok.next_token()?;
    if core::mem::discriminant(&got) != core::mem::discriminant(&expected) {
        return Err(PskError::UnexpectedToken);
    }
    Ok(())
}

pub(super) fn expect_string<'a>(tok: &mut Tokenizer<'a>) -> Result<&'a [u8], PskError> {
    match tok.next_token()? {
        Tok::Str(value) => Ok(value),
        _ => Err(PskError::UnexpectedToken),
    }
}

pub(super) fn expect_u64(tok: &mut Tokenizer<'_>) -> Result<u64, PskError> {
    match tok.next_token()? {
        Tok::Num(value) | Tok::Str(value) => parse_u64_num(value),
        _ => Err(PskError::UnexpectedToken),
    }
}

pub(super) fn expect_bool(tok: &mut Tokenizer<'_>) -> Result<bool, PskError> {
    match tok.next_token()? {
        Tok::True => Ok(true),
        Tok::False => Ok(false),
        _ => Err(PskError::UnexpectedToken),
    }
}

pub(super) fn reject_empty_object(tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
    if matches!(tok.peek()?, Tok::RBrace) {
        return Err(PskError::MissingField);
    }
    Ok(())
}

pub(super) fn consume_object_separator(tok: &mut Tokenizer<'_>) -> Result<bool, PskError> {
    match tok.next_token()? {
        Tok::Comma => Ok(true),
        Tok::RBrace => Ok(false),
        _ => Err(PskError::UnexpectedToken),
    }
}

fn consume_array_separator(tok: &mut Tokenizer<'_>) -> Result<bool, PskError> {
    match tok.next_token()? {
        Tok::Comma => Ok(true),
        Tok::RBracket => Ok(false),
        _ => Err(PskError::UnexpectedToken),
    }
}

/// Parse a bounded JSON array while delegating each element to a focused parser.
fn consume_empty_array(tok: &mut Tokenizer<'_>) -> Result<bool, PskError> {
    if matches!(tok.peek()?, Tok::RBracket) {
        tok.next_token()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(super) fn parse_bounded_array<'a>(
    tok: &mut Tokenizer<'a>,
    maximum: usize,
    too_many: PskError,
    mut parse_item: impl FnMut(&mut Tokenizer<'a>, usize) -> Result<(), PskError>,
) -> Result<usize, PskError> {
    expect(tok, Tok::LBracket)?;
    if consume_empty_array(tok)? {
        return Ok(0);
    }
    let mut count = 0usize;
    loop {
        if count >= maximum {
            return Err(too_many);
        }
        parse_item(tok, count)?;
        count += 1;
        if !consume_array_separator(tok)? {
            return Ok(count);
        }
    }
}

/// Skip exactly one syntactically valid JSON value.
pub(super) fn skip_value(tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
    match tok.next_token()? {
        Tok::Str(_) | Tok::Num(_) | Tok::True | Tok::False | Tok::Null => Ok(()),
        Tok::LBrace => skip_until_matching(tok, Tok::RBrace),
        Tok::LBracket => skip_until_matching(tok, Tok::RBracket),
        _ => Err(PskError::UnexpectedToken),
    }
}

/// Consume and validate a container after its opening token was read.
///
/// A fixed stack records both the exact closing delimiter and the grammar
/// state for each level. This rejects mismatched delimiters, missing colons,
/// duplicate separators, trailing commas, and excessive nesting without
/// recursion or allocation.
pub(super) fn skip_until_matching(tok: &mut Tokenizer<'_>, close: Tok<'_>) -> Result<(), PskError> {
    let initial = initial_container_state(close)?;
    let mut stack = [ContainerState::ObjectKeyOrEnd; MAX_JSON_NESTING];
    stack[0] = initial;
    let mut depth = 1usize;

    while depth > 0 {
        let token = next_container_token(tok)?;
        let state = stack[depth - 1];
        process_container_token(state, token, &mut stack, &mut depth)?;
    }
    Ok(())
}

fn initial_container_state(close: Tok<'_>) -> Result<ContainerState, PskError> {
    match close {
        Tok::RBrace => Ok(ContainerState::ObjectKeyOrEnd),
        Tok::RBracket => Ok(ContainerState::ArrayValueOrEnd),
        _ => Err(PskError::UnexpectedToken),
    }
}

fn next_container_token<'a>(tok: &mut Tokenizer<'a>) -> Result<Tok<'a>, PskError> {
    let token = tok.next_token()?;
    if matches!(token, Tok::Eof) {
        return Err(PskError::TruncatedEnvelope);
    }
    Ok(token)
}

fn process_container_token(
    state: ContainerState,
    token: Tok<'_>,
    stack: &mut [ContainerState; MAX_JSON_NESTING],
    depth: &mut usize,
) -> Result<(), PskError> {
    match state {
        ContainerState::ObjectKeyOrEnd => process_object_key_or_end(token, stack, depth),
        ContainerState::ObjectKey => process_object_key(token, stack, depth),
        ContainerState::ObjectColon => process_object_colon(token, stack, depth),
        ContainerState::ObjectValue => {
            process_nested_value(token, stack, depth, ContainerState::ObjectCommaOrEnd)
        }
        ContainerState::ObjectCommaOrEnd => process_object_separator(token, stack, depth),
        ContainerState::ArrayValueOrEnd => process_array_value_or_end(token, stack, depth),
        ContainerState::ArrayValue => {
            process_nested_value(token, stack, depth, ContainerState::ArrayCommaOrEnd)
        }
        ContainerState::ArrayCommaOrEnd => process_array_separator(token, stack, depth),
    }
}

fn process_object_key_or_end(
    token: Tok<'_>,
    stack: &mut [ContainerState; MAX_JSON_NESTING],
    depth: &mut usize,
) -> Result<(), PskError> {
    match token {
        Tok::RBrace => {
            close_container(depth);
            Ok(())
        }
        Tok::Str(_) => {
            set_current_state(stack, *depth, ContainerState::ObjectColon);
            Ok(())
        }
        _ => Err(PskError::UnexpectedToken),
    }
}

fn process_object_key(
    token: Tok<'_>,
    stack: &mut [ContainerState; MAX_JSON_NESTING],
    depth: &mut usize,
) -> Result<(), PskError> {
    match token {
        Tok::Str(_) => {
            set_current_state(stack, *depth, ContainerState::ObjectColon);
            Ok(())
        }
        _ => Err(PskError::UnexpectedToken),
    }
}

fn process_object_colon(
    token: Tok<'_>,
    stack: &mut [ContainerState; MAX_JSON_NESTING],
    depth: &mut usize,
) -> Result<(), PskError> {
    match token {
        Tok::Colon => {
            set_current_state(stack, *depth, ContainerState::ObjectValue);
            Ok(())
        }
        _ => Err(PskError::UnexpectedToken),
    }
}

fn process_object_separator(
    token: Tok<'_>,
    stack: &mut [ContainerState; MAX_JSON_NESTING],
    depth: &mut usize,
) -> Result<(), PskError> {
    match token {
        Tok::Comma => {
            set_current_state(stack, *depth, ContainerState::ObjectKey);
            Ok(())
        }
        Tok::RBrace => {
            close_container(depth);
            Ok(())
        }
        _ => Err(PskError::UnexpectedToken),
    }
}

fn process_array_value_or_end(
    token: Tok<'_>,
    stack: &mut [ContainerState; MAX_JSON_NESTING],
    depth: &mut usize,
) -> Result<(), PskError> {
    match token {
        Tok::RBracket => {
            close_container(depth);
            Ok(())
        }
        other => process_nested_value(other, stack, depth, ContainerState::ArrayCommaOrEnd),
    }
}

fn process_array_separator(
    token: Tok<'_>,
    stack: &mut [ContainerState; MAX_JSON_NESTING],
    depth: &mut usize,
) -> Result<(), PskError> {
    match token {
        Tok::Comma => {
            set_current_state(stack, *depth, ContainerState::ArrayValue);
            Ok(())
        }
        Tok::RBracket => {
            close_container(depth);
            Ok(())
        }
        _ => Err(PskError::UnexpectedToken),
    }
}

fn process_nested_value(
    token: Tok<'_>,
    stack: &mut [ContainerState; MAX_JSON_NESTING],
    depth: &mut usize,
    parent_next: ContainerState,
) -> Result<(), PskError> {
    match token {
        Tok::Str(_) | Tok::Num(_) | Tok::True | Tok::False | Tok::Null => {
            set_current_state(stack, *depth, parent_next);
            Ok(())
        }
        Tok::LBrace => push_container(stack, depth, parent_next, ContainerState::ObjectKeyOrEnd),
        Tok::LBracket => push_container(stack, depth, parent_next, ContainerState::ArrayValueOrEnd),
        _ => Err(PskError::UnexpectedToken),
    }
}

fn set_current_state(
    stack: &mut [ContainerState; MAX_JSON_NESTING],
    depth: usize,
    state: ContainerState,
) {
    stack[depth - 1] = state;
}

fn close_container(depth: &mut usize) {
    *depth -= 1;
}

fn push_container(
    stack: &mut [ContainerState; MAX_JSON_NESTING],
    depth: &mut usize,
    parent_next: ContainerState,
    child_initial: ContainerState,
) -> Result<(), PskError> {
    if *depth >= stack.len() {
        return Err(PskError::JsonNestingTooDeep);
    }
    stack[*depth - 1] = parent_next;
    stack[*depth] = child_initial;
    *depth += 1;
    Ok(())
}

#[inline]
pub(super) fn mark_seen_u8(seen: &mut u8, bit: u8) -> Result<(), PskError> {
    if *seen & bit != 0 {
        return Err(PskError::DuplicateField);
    }
    *seen |= bit;
    Ok(())
}

#[inline]
pub(super) fn mark_seen_u16(seen: &mut u16, bit: u16) -> Result<(), PskError> {
    if *seen & bit != 0 {
        return Err(PskError::DuplicateField);
    }
    *seen |= bit;
    Ok(())
}

pub(super) fn parse_hex_field(hex_str: &[u8], dst: &mut [u8]) -> Result<usize, PskError> {
    hex_decode_strict(hex_str, dst)
}

/// Validate lowercase even-length hex without allocating a decode buffer.
pub(super) fn validate_hex_string(hex_str: &[u8]) -> Result<(), PskError> {
    if hex_str.len() & 1 != 0 {
        return Err(PskError::OddHexLength);
    }
    for &byte in hex_str {
        if !matches!(byte, b'0'..=b'9' | b'a'..=b'f') {
            return Err(PskError::BadHexChar);
        }
    }
    Ok(())
}

pub(super) fn parse_script_public_key(
    hex_str: &[u8],
    out: &mut ScriptPublicKey,
) -> Result<(), PskError> {
    if hex_str.len() < 4 {
        return Err(PskError::ShortScriptPubkey);
    }
    let mut version_bytes = [0u8; 2];
    hex_decode_strict(&hex_str[..4], &mut version_bytes)?;
    out.version = u16::from_be_bytes(version_bytes);

    let script_hex = &hex_str[4..];
    if script_hex.len() / 2 > MAX_SCRIPT_SIZE {
        return Err(PskError::InvalidScriptLen);
    }
    out.script_len = hex_decode_strict(script_hex, &mut out.script)?;
    Ok(())
}

/// Capture a non-empty object as an unknown PSKT extension for the supplied scope.
pub(super) fn capture_nonempty_object(
    tok: &mut Tokenizer<'_>,
    parsed: &mut PsktParsed,
    field_start: usize,
    scope: PsktUnknownScope,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;
    if matches!(tok.peek()?, Tok::RBrace) {
        tok.next_token()?;
        return Ok(());
    }
    skip_until_matching(tok, Tok::RBrace)?;
    capture_unknown(parsed, scope, field_start, tok.position())
}
