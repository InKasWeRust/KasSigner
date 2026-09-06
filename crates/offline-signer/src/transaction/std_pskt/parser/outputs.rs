//! Parser for PSKT output arrays and covenant bindings.

use crate::transaction::model::{Transaction, TransactionOutput, MAX_OUTPUTS};
use shared_signer::{PsktParsed, PsktUnknownScope};

use super::super::preservation::capture_unknown;
use super::super::{hex_decode_strict, PskError, Tok, Tokenizer};
use super::derivation::extract_ms45_hint;
use super::helpers::{
    capture_nonempty_object, consume_object_separator, expect, expect_string, expect_u64,
    mark_seen_u8, parse_bounded_array, parse_script_public_key, reject_empty_object,
    skip_until_matching, skip_value, validate_hex_string,
};

pub(super) fn parse_outputs_array(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    let count = parse_bounded_array(tok, MAX_OUTPUTS, PskError::TooManyOutputs, |tok, index| {
        tx.outputs[index] = TransactionOutput::empty();
        parse_output(tok, &mut tx.outputs[index], parsed, index)
    })?;
    tx.num_outputs = count;
    Ok(())
}

fn parse_output(
    tok: &mut Tokenizer<'_>,
    output: &mut TransactionOutput,
    parsed: &mut PsktParsed,
    index: usize,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;
    reject_empty_object(tok)?;

    let mut parser = OutputParser {
        output,
        parsed,
        index,
        seen: 0,
    };
    loop {
        parser.parse_member(tok)?;
        if !consume_object_separator(tok)? {
            break;
        }
    }
    parser.require_fields()
}

const AMOUNT: u8 = 0x01;
const SCRIPT_PUBLIC_KEY: u8 = 0x02;
const COVENANT_BINDING: u8 = 0x04;
const REDEEM_SCRIPT: u8 = 0x08;
const BIP32_DERIVATIONS: u8 = 0x10;
const PROPRIETARIES: u8 = 0x20;
const REQUIRED_OUTPUT_FIELDS: u8 = 0x03;

struct OutputParser<'a> {
    output: &'a mut TransactionOutput,
    parsed: &'a mut PsktParsed,
    index: usize,
    seen: u8,
}

impl OutputParser<'_> {
    fn parse_member(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        let key_start = tok.position();
        let key = expect_string(tok)?;
        expect(tok, Tok::Colon)?;
        self.parse_field(tok, key_start, key)
    }

    fn parse_field(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
        key: &[u8],
    ) -> Result<(), PskError> {
        match key {
            b"amount" => self.parse_amount(tok),
            b"scriptPublicKey" => self.parse_script_key(tok),
            b"covenantBinding" => self.parse_covenant_field(tok),
            b"redeemScript" => self.parse_redeem_script(tok, key_start),
            b"bip32Derivations" => self.parse_bip32_derivations(tok, key_start),
            b"proprietaries" => self.parse_preserved_object(tok, key_start, PROPRIETARIES),
            _ => self.preserve_unknown(tok, key_start),
        }
    }

    fn parse_amount(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u8(&mut self.seen, AMOUNT)?;
        self.output.value = expect_u64(tok)?;
        Ok(())
    }

    fn parse_script_key(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u8(&mut self.seen, SCRIPT_PUBLIC_KEY)?;
        let hex_str = expect_string(tok)?;
        parse_script_public_key(hex_str, &mut self.output.script_public_key)
    }

    fn parse_covenant_field(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u8(&mut self.seen, COVENANT_BINDING)?;
        self.parsed.mark_output_covenant_binding_field(self.index);
        parse_covenant_binding(tok, self.output)
    }

    fn parse_redeem_script(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
    ) -> Result<(), PskError> {
        mark_seen_u8(&mut self.seen, REDEEM_SCRIPT)?;
        match tok.next_token()? {
            Tok::Null => Ok(()),
            Tok::Str(hex_str) => {
                validate_hex_string(hex_str)?;
                self.capture(key_start, tok.position())
            }
            _ => Err(PskError::UnexpectedToken),
        }
    }

    fn parse_bip32_derivations(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
    ) -> Result<(), PskError> {
        mark_seen_u8(&mut self.seen, BIP32_DERIVATIONS)?;
        let value_start = tok.position();
        expect(tok, Tok::LBrace)?;
        if matches!(tok.peek()?, Tok::RBrace) {
            tok.next_token()?;
            return Ok(());
        }
        skip_until_matching(tok, Tok::RBrace)?;
        if !self.output.ms45_hint.present {
            if let Some(hint) = extract_ms45_hint(tok.source(), value_start, tok.position()) {
                self.output.ms45_hint = hint;
            }
        }
        self.capture(key_start, tok.position())
    }

    fn parse_preserved_object(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
        bit: u8,
    ) -> Result<(), PskError> {
        mark_seen_u8(&mut self.seen, bit)?;
        let scope = self.scope();
        capture_nonempty_object(tok, self.parsed, key_start, scope)
    }

    fn preserve_unknown(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
    ) -> Result<(), PskError> {
        skip_value(tok)?;
        self.capture(key_start, tok.position())
    }

    fn capture(&mut self, field_start: usize, field_end: usize) -> Result<(), PskError> {
        let scope = self.scope();
        capture_unknown(self.parsed, scope, field_start, field_end)
    }

    fn scope(&self) -> PsktUnknownScope {
        // `index` originates from `parse_bounded_array(..., MAX_OUTPUTS, ...)`,
        // and MAX_OUTPUTS is far below u32::MAX.
        PsktUnknownScope::output(self.index as u32)
    }

    fn require_fields(&self) -> Result<(), PskError> {
        if self.seen & REQUIRED_OUTPUT_FIELDS != REQUIRED_OUTPUT_FIELDS {
            return Err(PskError::MissingField);
        }
        Ok(())
    }
}

const COVENANT_AUTHORIZING_INPUT: u8 = 0x01;
const COVENANT_ID_FIELD: u8 = 0x02;
const REQUIRED_COVENANT_FIELDS: u8 = 0x03;

struct CovenantBindingParser<'a> {
    output: &'a mut TransactionOutput,
    seen: u8,
}

impl CovenantBindingParser<'_> {
    fn parse_object(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        if matches!(tok.peek()?, Tok::RBrace) {
            return Err(PskError::MissingField);
        }
        loop {
            self.parse_member(tok)?;
            if !consume_object_separator(tok)? {
                break;
            }
        }
        self.finish()
    }

    fn parse_member(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        let key = expect_string(tok)?;
        expect(tok, Tok::Colon)?;
        match key {
            b"authorizingInput" => self.parse_authorizing_input(tok),
            b"covenantId" => self.parse_covenant_id(tok),
            _ => Err(PskError::UnexpectedToken),
        }
    }

    fn parse_authorizing_input(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u8(&mut self.seen, COVENANT_AUTHORIZING_INPUT)?;
        let input_index = expect_u64(tok)?;
        self.output.covenant_auth_input =
            u16::try_from(input_index).map_err(|_| PskError::InvalidCovenantBinding)?;
        Ok(())
    }

    fn parse_covenant_id(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u8(&mut self.seen, COVENANT_ID_FIELD)?;
        let covenant_id = expect_string(tok)?;
        if covenant_id.len() != 64 {
            return Err(PskError::InvalidCovenantBinding);
        }
        hex_decode_strict(covenant_id, &mut self.output.covenant_id)
            .map(|_| ())
            .map_err(|_| PskError::InvalidCovenantBinding)
    }

    fn finish(&mut self) -> Result<(), PskError> {
        if self.seen & REQUIRED_COVENANT_FIELDS != REQUIRED_COVENANT_FIELDS {
            return Err(PskError::MissingField);
        }
        self.output.has_covenant = true;
        Ok(())
    }
}

fn parse_covenant_binding(
    tok: &mut Tokenizer<'_>,
    output: &mut TransactionOutput,
) -> Result<(), PskError> {
    match tok.next_token()? {
        Tok::Null => {
            output.has_covenant = false;
            Ok(())
        }
        Tok::LBrace => CovenantBindingParser { output, seen: 0 }.parse_object(tok),
        _ => Err(PskError::UnexpectedToken),
    }
}
