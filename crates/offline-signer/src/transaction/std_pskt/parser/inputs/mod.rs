//! Parser for PSKT input arrays and input-owned schema objects.

mod details;
mod metadata;

use details::{parse_outpoint, parse_utxo_entry};
use metadata::{parse_bip32_derivations, parse_partial_sigs};

use crate::transaction::model::{
    Transaction, TransactionInput, MAX_SCRIPT_SIZE, MAX_SIGS_PER_INPUT,
};
use shared_signer::{PsktParsed, PsktUnknownScope};

use super::super::preservation::capture_unknown;
use super::super::{PskError, Tok, Tokenizer};
use super::helpers::{
    capture_nonempty_object, consume_object_separator, expect, expect_string, expect_u64,
    mark_seen_u16, parse_hex_field, reject_empty_object, skip_value, validate_hex_string,
};
use super::SIGHASH_ALL;

const UTXO: u16 = 0x0001;
const OUTPOINT: u16 = 0x0002;
const SEQUENCE: u16 = 0x0004;
const MIN_TIME: u16 = 0x0008;
const PARTIAL_SIGS: u16 = 0x0010;
const SIGHASH: u16 = 0x0020;
const REDEEM_SCRIPT: u16 = 0x0040;
const SIG_OP_COUNT: u16 = 0x0080;
const BIP32_DERIVATIONS: u16 = 0x0100;
const FINAL_SCRIPT_SIG: u16 = 0x0200;
const PROPRIETARIES: u16 = 0x0400;
const REQUIRED: u16 = 0x0023;

pub(super) fn parse_inputs_array(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    if start_input_array(tok, tx)? {
        return Ok(());
    }
    let mut count = 0usize;
    loop {
        parse_input_at(tok, tx, parsed, count)?;
        count += 1;
        if input_array_finished(tok, tx, count)? {
            return Ok(());
        }
    }
}

fn start_input_array(tok: &mut Tokenizer<'_>, tx: &mut Transaction) -> Result<bool, PskError> {
    expect(tok, Tok::LBracket)
        .and_then(|()| input_array_is_empty(tok))
        .and_then(|empty| {
            if !empty {
                return Ok(false);
            }
            tok.next_token().map(|_| {
                tx.num_inputs = 0;
                true
            })
        })
}

fn parse_input_at(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
    count: usize,
) -> Result<(), PskError> {
    tx.ensure_input_slots(count + 1)
        .map_err(|_| PskError::TooManyInputs)?;
    tx.inputs[count] = TransactionInput::empty();
    parse_input(tok, &mut tx.inputs[count], parsed, count)
}

fn input_array_is_empty(tok: &mut Tokenizer<'_>) -> Result<bool, PskError> {
    tok.peek().map(|token| matches!(token, Tok::RBracket))
}

fn input_array_finished(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    count: usize,
) -> Result<bool, PskError> {
    tok.next_token().and_then(|token| {
        if token == Tok::Comma {
            return Ok(false);
        }
        finish_input_array(token, tx, count)
    })
}

fn finish_input_array(
    token: Tok<'_>,
    tx: &mut Transaction,
    count: usize,
) -> Result<bool, PskError> {
    if token != Tok::RBracket {
        return Err(PskError::UnexpectedToken);
    }
    tx.num_inputs = count;
    Ok(true)
}

fn parse_input(
    tok: &mut Tokenizer<'_>,
    input: &mut TransactionInput,
    parsed: &mut PsktParsed,
    index: usize,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;
    reject_empty_object(tok)?;

    let mut parser = InputParser {
        input,
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

struct InputParser<'a> {
    input: &'a mut TransactionInput,
    parsed: &'a mut PsktParsed,
    index: usize,
    seen: u16,
}

impl InputParser<'_> {
    fn parse_member(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        let key_start = tok.position();
        let key = expect_string(tok)?;
        expect(tok, Tok::Colon)?;
        self.parse_field(tok, key_start, key)
    }

    fn parse_primary_field(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
        key: &[u8],
    ) -> Option<Result<(), PskError>> {
        match key {
            b"utxoEntry" => Some(self.parse_utxo(tok)),
            b"previousOutpoint" => Some(self.parse_previous_outpoint(tok)),
            b"sequence" => Some(self.parse_sequence(tok)),
            b"minTime" => Some(self.parse_min_time(tok, key_start)),
            b"partialSigs" => Some(self.parse_partial_signatures(tok)),
            b"sighashType" => Some(self.parse_sighash(tok)),
            _ => None,
        }
    }

    fn parse_field(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
        key: &[u8],
    ) -> Result<(), PskError> {
        if let Some(result) = self.parse_primary_field(tok, key_start, key) {
            return result;
        }
        match key {
            b"redeemScript" => self.parse_redeem_script(tok),
            b"sigOpCount" => self.parse_sig_op_count(tok),
            b"bip32Derivations" => self.parse_bip32(tok, key_start),
            b"finalScriptSig" => self.parse_final_script_sig(tok, key_start),
            b"proprietaries" => self.parse_proprietaries(tok, key_start),
            _ => self.preserve_unknown(tok, key_start),
        }
    }

    fn parse_utxo(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, UTXO)?;
        parse_utxo_entry(tok, self.input, self.parsed, self.index)
    }

    fn parse_previous_outpoint(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, OUTPOINT)?;
        parse_outpoint(tok, self.input, self.parsed, self.index)
    }

    fn parse_sequence(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, SEQUENCE)?;
        self.input.sequence = expect_u64(tok)?;
        Ok(())
    }

    fn parse_min_time(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
    ) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, MIN_TIME)?;
        match tok.next_token()? {
            Tok::Null => Ok(()),
            Tok::Num(value) => {
                super::super::parse_u64_num(value)?;
                self.capture(key_start, tok.position())
            }
            _ => Err(PskError::UnexpectedToken),
        }
    }

    fn parse_partial_signatures(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, PARTIAL_SIGS)?;
        parse_partial_sigs(tok, self.input)
    }

    fn parse_sighash(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, SIGHASH)?;
        if expect_u64(tok)? != SIGHASH_ALL as u64 {
            return Err(PskError::InvalidSighashType);
        }
        self.input.sighash_type = SIGHASH_ALL;
        Ok(())
    }

    fn parse_redeem_script(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, REDEEM_SCRIPT)?;
        match tok.next_token()? {
            Tok::Null => {
                self.input.redeem_script_len = 0;
                Ok(())
            }
            Tok::Str(hex_str) => self.decode_redeem_script(hex_str),
            _ => Err(PskError::UnexpectedToken),
        }
    }

    fn decode_redeem_script(&mut self, hex_str: &[u8]) -> Result<(), PskError> {
        if hex_str.len() / 2 > MAX_SCRIPT_SIZE {
            return Err(PskError::InvalidScriptLen);
        }
        self.input.redeem_script_len = parse_hex_field(hex_str, &mut self.input.redeem_script)?;
        Ok(())
    }

    fn parse_sig_op_count(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, SIG_OP_COUNT)?;
        let count = expect_u64(tok)?;
        if count > MAX_SIGS_PER_INPUT as u64 {
            return Err(PskError::TooManyPartialSigs);
        }
        self.input.sig_op_count = count as u8;
        Ok(())
    }

    fn parse_bip32(&mut self, tok: &mut Tokenizer<'_>, key_start: usize) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, BIP32_DERIVATIONS)?;
        parse_bip32_derivations(tok, self.parsed, key_start, self.index, self.input)
    }

    fn parse_final_script_sig(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
    ) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, FINAL_SCRIPT_SIG)?;
        match tok.next_token()? {
            Tok::Null => Ok(()),
            Tok::Str(hex_str) => {
                validate_hex_string(hex_str)?;
                self.capture(key_start, tok.position())
            }
            _ => Err(PskError::UnexpectedToken),
        }
    }

    fn parse_proprietaries(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
    ) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, PROPRIETARIES)?;
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
        PsktUnknownScope::input(u32::try_from(self.index).unwrap_or(u32::MAX))
    }

    fn require_fields(&self) -> Result<(), PskError> {
        if self.seen & REQUIRED != REQUIRED {
            return Err(PskError::MissingField);
        }
        Ok(())
    }
}
