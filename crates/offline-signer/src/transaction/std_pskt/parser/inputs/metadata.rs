//! Input signatures, derivations, and schema bookkeeping.

use crate::transaction::model::{TransactionInput, MAX_SIGS_PER_INPUT};
use shared_signer::{PsktParsed, PsktUnknownScope};

use super::super::super::{
    hex_decode_strict, preservation::capture_unknown, PskError, Tok, Tokenizer,
};
use super::super::{
    derivation::extract_ms45_hint,
    helpers::{expect, expect_string, skip_until_matching},
};

fn parse_partial_sig_pubkey(
    tok: &mut Tokenizer<'_>,
    input: &TransactionInput,
    count: usize,
) -> Result<[u8; 33], PskError> {
    let pubkey_hex = expect_string(tok)?;
    if pubkey_hex.len() != 66 {
        return Err(PskError::InvalidPubkeyLen);
    }
    let mut pubkey = [0u8; 33];
    hex_decode_strict(pubkey_hex, &mut pubkey)?;
    if input.incoming_partial_sigs[..count]
        .iter()
        .any(|previous| previous.pubkey == pubkey)
    {
        return Err(PskError::DuplicateField);
    }
    Ok(pubkey)
}

fn expect_schnorr_kind(tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
    match expect_string(tok)? {
        b"ecdsa" => Err(PskError::InvalidSignatureType),
        b"schnorr" => Ok(()),
        _ => Err(PskError::UnexpectedToken),
    }
}

fn read_schnorr_bytes(tok: &mut Tokenizer<'_>) -> Result<[u8; 64], PskError> {
    let signature_hex = expect_string(tok)?;
    if signature_hex.len() != 128 {
        return Err(PskError::UnexpectedToken);
    }
    let mut signature = [0u8; 64];
    hex_decode_strict(signature_hex, &mut signature)?;
    Ok(signature)
}

fn object_continues(tok: &mut Tokenizer<'_>) -> Result<bool, PskError> {
    match tok.next_token()? {
        Tok::Comma => Ok(true),
        Tok::RBrace => Ok(false),
        _ => Err(PskError::UnexpectedToken),
    }
}

fn parse_schnorr_signature(tok: &mut Tokenizer<'_>) -> Result<[u8; 64], PskError> {
    expect(tok, Tok::Colon)?;
    expect(tok, Tok::LBrace)?;
    expect_schnorr_kind(tok)?;
    expect(tok, Tok::Colon)?;
    let signature = read_schnorr_bytes(tok)?;
    expect(tok, Tok::RBrace)?;
    Ok(signature)
}

fn consume_empty_partial_sigs(tok: &mut Tokenizer<'_>) -> Result<bool, PskError> {
    if matches!(tok.peek()?, Tok::RBrace) {
        tok.next_token()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn parse_partial_sig_slot(
    tok: &mut Tokenizer<'_>,
    input: &mut TransactionInput,
    count: usize,
) -> Result<(), PskError> {
    if count >= MAX_SIGS_PER_INPUT {
        return Err(PskError::TooManyPartialSigs);
    }
    let pubkey = parse_partial_sig_pubkey(tok, input, count)?;
    let signature = parse_schnorr_signature(tok)?;
    let slot = &mut input.incoming_partial_sigs[count];
    slot.pubkey = pubkey;
    slot.signature = signature;
    slot.present = true;
    Ok(())
}

pub(super) fn parse_partial_sigs(
    tok: &mut Tokenizer<'_>,
    input: &mut TransactionInput,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;
    if consume_empty_partial_sigs(tok)? {
        input.incoming_partial_sigs_count = 0;
        return Ok(());
    }
    let mut count = 0usize;
    loop {
        parse_partial_sig_slot(tok, input, count)?;
        count += 1;
        if !object_continues(tok)? {
            break;
        }
    }
    input.incoming_partial_sigs_count = count as u8;
    Ok(())
}

fn parse_bip32_derivation_entry(
    tok: &mut Tokenizer<'_>,
    input: &mut TransactionInput,
    pubkeys: &mut [[u8; 33]; MAX_SIGS_PER_INPUT],
    count: usize,
) -> Result<[u8; 33], PskError> {
    let pubkey = parse_derivation_pubkey(tok, pubkeys, count)?;
    expect(tok, Tok::Colon)?;
    let value_start = tok.position();
    parse_derivation_value(tok)?;
    install_first_ms45_hint(input, tok.source(), value_start, tok.position());
    Ok(pubkey)
}

fn parse_derivation_pubkey(
    tok: &mut Tokenizer<'_>,
    pubkeys: &[[u8; 33]; MAX_SIGS_PER_INPUT],
    count: usize,
) -> Result<[u8; 33], PskError> {
    if count >= MAX_SIGS_PER_INPUT {
        return Err(PskError::TooManyPartialSigs);
    }
    let pubkey_hex = expect_string(tok)?;
    if pubkey_hex.len() != 66 {
        return Err(PskError::InvalidPubkeyLen);
    }
    let mut pubkey = [0u8; 33];
    hex_decode_strict(pubkey_hex, &mut pubkey)?;
    if pubkeys[..count].contains(&pubkey) {
        return Err(PskError::DuplicateField);
    }
    Ok(pubkey)
}

fn install_first_ms45_hint(
    input: &mut TransactionInput,
    source: &[u8],
    value_start: usize,
    value_end: usize,
) {
    if input.ms45_hint.present {
        return;
    }
    if let Some(hint) = extract_ms45_hint(source, value_start, value_end) {
        input.ms45_hint = hint;
    }
}

fn parse_derivation_value(tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
    match tok.next_token()? {
        Tok::Null => Ok(()),
        Tok::LBrace => skip_until_matching(tok, Tok::RBrace),
        _ => Err(PskError::UnexpectedToken),
    }
}

pub(super) fn parse_bip32_derivations(
    tok: &mut Tokenizer<'_>,
    parsed: &mut PsktParsed,
    field_start: usize,
    input_index: usize,
    input: &mut TransactionInput,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;
    if matches!(tok.peek()?, Tok::RBrace) {
        tok.next_token()?;
        return Ok(());
    }
    let mut pubkeys = [[0u8; 33]; MAX_SIGS_PER_INPUT];
    let mut count = 0usize;
    loop {
        let pubkey = parse_bip32_derivation_entry(tok, input, &mut pubkeys, count)?;
        pubkeys[count] = pubkey;
        count += 1;
        if !object_continues(tok)? {
            break;
        }
    }
    capture_bip32_derivations(parsed, field_start, input_index, tok.position())
}

fn capture_bip32_derivations(
    parsed: &mut PsktParsed,
    field_start: usize,
    input_index: usize,
    field_end: usize,
) -> Result<(), PskError> {
    let scope =
        PsktUnknownScope::input(u32::try_from(input_index).map_err(|_| PskError::CountMismatch)?);
    capture_unknown(parsed, scope, field_start, field_end)
}
