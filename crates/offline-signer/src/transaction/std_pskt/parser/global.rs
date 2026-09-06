//! Parser for the PSKT global map.

use crate::transaction::model::{Transaction, MAX_INPUTS, MAX_OUTPUTS};
use shared_signer::{PsktParsed, PsktUnknownScope};

use super::super::preservation::capture_unknown;
use super::super::{PskError, Tok, Tokenizer};
use super::helpers::{
    capture_nonempty_object, consume_object_separator, expect, expect_bool, expect_string,
    expect_u64, mark_seen_u16, reject_empty_object, skip_value,
};
use super::{ParseContext, MAX_TX_VERSION, PSKT_VERSION_OK};

const VERSION: u16 = 0x0001;
const TX_VERSION: u16 = 0x0002;
const FALLBACK_LOCK_TIME: u16 = 0x0004;
const INPUTS_MODIFIABLE: u16 = 0x0008;
const OUTPUTS_MODIFIABLE: u16 = 0x0010;
const INPUT_COUNT: u16 = 0x0020;
const OUTPUT_COUNT: u16 = 0x0040;
const XPUBS: u16 = 0x0080;
const ID: u16 = 0x0100;
const PROPRIETARIES: u16 = 0x0200;
const REQUIRED: u16 = 0x0063;

pub(super) fn parse_global(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
    context: &mut ParseContext,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;
    reject_empty_object(tok)?;

    let mut parser = GlobalParser {
        tx,
        parsed,
        context,
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

struct GlobalParser<'a> {
    tx: &'a mut Transaction,
    parsed: &'a mut PsktParsed,
    context: &'a mut ParseContext,
    seen: u16,
}

impl GlobalParser<'_> {
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
            b"version" => Some(self.parse_pskt_version(tok)),
            b"txVersion" => Some(self.parse_transaction_version(tok)),
            b"fallbackLockTime" => Some(self.parse_optional_lock_time(tok, key_start)),
            b"inputsModifiable" => Some(self.parse_modifiable(tok, INPUTS_MODIFIABLE, key_start)),
            b"outputsModifiable" => Some(self.parse_modifiable(tok, OUTPUTS_MODIFIABLE, key_start)),
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
            b"inputCount" => self.parse_input_count(tok),
            b"outputCount" => self.parse_output_count(tok),
            b"xpubs" => self.parse_preserved_object(tok, XPUBS, key_start),
            b"id" => self.parse_optional_id(tok, key_start),
            b"proprietaries" => self.parse_preserved_object(tok, PROPRIETARIES, key_start),
            _ => self.preserve_unknown(tok, key_start),
        }
    }

    fn parse_pskt_version(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, VERSION)?;
        if expect_u64(tok)? != PSKT_VERSION_OK {
            return Err(PskError::VersionNotSupported);
        }
        Ok(())
    }

    fn parse_transaction_version(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, TX_VERSION)?;
        let version = expect_u64(tok)?;
        if version > MAX_TX_VERSION as u64 {
            return Err(PskError::VersionNotSupported);
        }
        self.tx.version = version as u16;
        Ok(())
    }

    fn parse_optional_lock_time(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
    ) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, FALLBACK_LOCK_TIME)?;
        match tok.next_token()? {
            Tok::Null => Ok(()),
            Tok::Num(value) | Tok::Str(value) => {
                self.tx.locktime = super::super::parse_u64_num(value)?;
                self.capture(key_start, tok.position())
            }
            _ => Err(PskError::UnexpectedToken),
        }
    }

    fn parse_modifiable(
        &mut self,
        tok: &mut Tokenizer<'_>,
        bit: u16,
        key_start: usize,
    ) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, bit)?;
        if expect_bool(tok)? {
            return Ok(());
        }
        self.capture(key_start, tok.position())
    }

    fn parse_input_count(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, INPUT_COUNT)?;
        let count = expect_u64(tok)?;
        let count = usize::try_from(count).map_err(|_| PskError::TooManyInputs)?;
        if count > MAX_INPUTS {
            return Err(PskError::TooManyInputs);
        }
        self.context.declared_input_count = Some(count);
        Ok(())
    }

    fn parse_output_count(&mut self, tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, OUTPUT_COUNT)?;
        let count = expect_u64(tok)?;
        if count > MAX_OUTPUTS as u64 {
            return Err(PskError::TooManyOutputs);
        }
        self.context.declared_output_count = Some(count as usize);
        Ok(())
    }

    fn parse_preserved_object(
        &mut self,
        tok: &mut Tokenizer<'_>,
        bit: u16,
        key_start: usize,
    ) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, bit)?;
        capture_nonempty_object(tok, self.parsed, key_start, PsktUnknownScope::global())
    }

    fn parse_optional_id(
        &mut self,
        tok: &mut Tokenizer<'_>,
        key_start: usize,
    ) -> Result<(), PskError> {
        mark_seen_u16(&mut self.seen, ID)?;
        match tok.next_token()? {
            Tok::Null => Ok(()),
            Tok::Str(_) => self.capture(key_start, tok.position()),
            _ => Err(PskError::UnexpectedToken),
        }
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
        capture_unknown(
            self.parsed,
            PsktUnknownScope::global(),
            field_start,
            field_end,
        )
    }

    fn require_fields(&self) -> Result<(), PskError> {
        if self.seen & REQUIRED != REQUIRED {
            return Err(PskError::MissingField);
        }
        Ok(())
    }
}
