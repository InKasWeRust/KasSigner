//! Top-level PSKT/PSKB parser orchestration.

mod derivation;
mod global;
mod helpers;
mod inputs;
mod outputs;

use crate::transaction::model::Transaction;
use shared_signer::{PsktParsed, PsktUnknownScope};

use super::preservation::capture_unknown;
use super::{
    hex_decode_strict, strip_pskt_magic, validate_monetary_shape, PskError, Tok, Tokenizer,
    PSKB_MAGIC, PSKT_MAGIC,
};
use global::parse_global;
use helpers::{expect, expect_string, skip_value};
use inputs::parse_inputs_array;
use outputs::parse_outputs_array;

pub(super) const MAX_TX_VERSION: u16 = 1;
pub(super) const PSKT_VERSION_OK: u64 = 0;
pub(super) const SIGHASH_ALL: u8 = 1;

#[derive(Debug, Default)]
pub(super) struct ParseContext {
    pub(super) declared_input_count: Option<usize>,
    pub(super) declared_output_count: Option<usize>,
}

fn bundle_format(wire: &[u8]) -> Result<bool, PskError> {
    if &wire[..4] == PSKB_MAGIC {
        return Ok(true);
    }
    if &wire[..4] == PSKT_MAGIC {
        return Ok(false);
    }
    Err(PskError::BadMagic)
}

fn parse_decoded_json(
    json: &[u8],
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
    is_bundle: bool,
) -> Result<(), PskError> {
    let mut tok = Tokenizer::new(json);
    if is_bundle {
        parse_bundle_array(&mut tok, tx, parsed)?;
    } else {
        parse_pskt_object(&mut tok, tx, parsed)?;
    }
    expect(&mut tok, Tok::Eof)
}

/// Decode a PSKB bundle or PSKT-single payload into the fixed transaction model.
pub fn parse_pskt(
    wire: &[u8],
    scratch: &mut [u8],
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    let body_hex = strip_pskt_magic(wire)?;
    let is_bundle = bundle_format(wire)?;
    let json_len = hex_decode_strict(body_hex, scratch)?;
    let json_len_u16 = u16::try_from(json_len).map_err(|_| PskError::JsonTooLarge)?;
    *parsed = PsktParsed::empty();
    parsed.json_start = 0;
    parsed.json_len = json_len_u16;
    tx.prepare_for_parse();
    parse_decoded_json(&scratch[..json_len], tx, parsed, is_bundle)
}

fn parse_bundle_array(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    expect(tok, Tok::LBracket)?;
    if matches!(tok.peek()?, Tok::RBracket) {
        return Err(PskError::MissingField);
    }

    parse_pskt_object(tok, tx, parsed)?;
    match tok.next_token()? {
        Tok::RBracket => Ok(()),
        Tok::Comma => Err(PskError::BundleMultiElement),
        _ => Err(PskError::UnexpectedToken),
    }
}

const HAS_GLOBAL: u8 = 0b001;
const HAS_INPUTS: u8 = 0b010;
const HAS_OUTPUTS: u8 = 0b100;
const REQUIRED_TOP_LEVEL_FIELDS: u8 = 0b111;

fn parse_top_level_field(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
    context: &mut ParseContext,
    seen: &mut u8,
) -> Result<(), PskError> {
    let key_start = tok.position();
    let key = expect_string(tok)?;
    expect(tok, Tok::Colon)?;
    let field = top_level_field_bit(key);
    reject_duplicate_top_level(*seen, field)?;
    parse_top_level_value(tok, tx, parsed, context, key_start, field)?;
    *seen |= field;
    Ok(())
}

fn top_level_field_bit(key: &[u8]) -> u8 {
    match key {
        b"global" => HAS_GLOBAL,
        b"inputs" => HAS_INPUTS,
        b"outputs" => HAS_OUTPUTS,
        _ => 0,
    }
}

fn reject_duplicate_top_level(seen: u8, field: u8) -> Result<(), PskError> {
    if field != 0 && seen & field != 0 {
        return Err(PskError::DuplicateField);
    }
    Ok(())
}

fn parse_top_level_value(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
    context: &mut ParseContext,
    key_start: usize,
    field: u8,
) -> Result<(), PskError> {
    match field {
        HAS_GLOBAL => parse_global(tok, tx, parsed, context),
        HAS_INPUTS => parse_inputs_array(tok, tx, parsed),
        HAS_OUTPUTS => parse_outputs_array(tok, tx, parsed),
        _ => preserve_unknown_top_level(tok, parsed, key_start),
    }
}

fn preserve_unknown_top_level(
    tok: &mut Tokenizer<'_>,
    parsed: &mut PsktParsed,
    key_start: usize,
) -> Result<(), PskError> {
    skip_value(tok)?;
    capture_unknown(
        parsed,
        PsktUnknownScope::top_level(),
        key_start,
        tok.position(),
    )
}

fn validate_top_level_object(
    tx: &Transaction,
    context: &ParseContext,
    seen: u8,
) -> Result<(), PskError> {
    if seen != REQUIRED_TOP_LEVEL_FIELDS {
        return Err(PskError::MissingField);
    }
    if context.declared_input_count != Some(tx.num_inputs)
        || context.declared_output_count != Some(tx.num_outputs)
    {
        return Err(PskError::CountMismatch);
    }
    if tx.outputs[..tx.num_outputs]
        .iter()
        .any(|output| output.has_covenant && output.covenant_auth_input as usize >= tx.num_inputs)
    {
        return Err(PskError::InvalidCovenantBinding);
    }
    validate_monetary_shape(tx)
}

fn parse_pskt_object(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;
    if matches!(tok.peek()?, Tok::RBrace) {
        return Err(PskError::MissingField);
    }

    let mut seen = 0u8;
    let mut context = ParseContext::default();
    loop {
        parse_top_level_field(tok, tx, parsed, &mut context, &mut seen)?;
        match tok.next_token()? {
            Tok::Comma => continue,
            Tok::RBrace => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }
    validate_top_level_object(tx, &context, seen)
}
