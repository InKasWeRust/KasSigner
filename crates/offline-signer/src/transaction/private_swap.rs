//! Canonical Private Swap v2 script and transaction validation for the device.

use alloc::vec::Vec;

use crate::transaction::{
    model::{SigHashType, Transaction},
    sighash::calculate_sighash,
};

pub const PRIVATE_SWAP_MAX_FEE_SOMPI: u64 = 500_000_000;

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_VERIFY: u8 = 0x69;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_SUB: u8 = 0x94;
const OP_NUMEQUALVERIFY: u8 = 0x9d;
const OP_LESSTHANOREQUAL: u8 = 0xa1;
const OP_GREATERTHANOREQUAL: u8 = 0xa2;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb0;
const OP_TX_INPUT_COUNT: u8 = 0xb3;
const OP_TX_OUTPUT_COUNT: u8 = 0xb4;
const OP_TX_INPUT_AMOUNT: u8 = 0xbe;
const OP_TX_OUTPUT_AMOUNT: u8 = 0xc2;
const OP_TX_OUTPUT_SPK: u8 = 0xc3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateSwapScript {
    pub salt: [u8; 16],
    pub claimer_pubkey: [u8; 32],
    pub owner_pubkey: [u8; 32],
    pub destination_spk: Vec<u8>,
    pub refund_locktime_daa: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateSwapError {
    InvalidScript,
    WrongClaimer,
    InvalidTransaction,
    InvalidSighash,
    WrongDestination,
    FeeTooHigh,
}

struct PrivateSwapClaim {
    salt: [u8; 16],
    claimer_pubkey: [u8; 32],
    destination_spk: Vec<u8>,
}

pub fn parse_private_swap_script(script: &[u8]) -> Result<PrivateSwapScript, PrivateSwapError> {
    let mut pos = 0usize;
    let claim = parse_private_swap_claim(script, &mut pos)?;
    let (owner_pubkey, refund_locktime_daa) = parse_private_swap_refund(script, &mut pos)?;
    if owner_pubkey == claim.claimer_pubkey || pos != script.len() {
        return Err(PrivateSwapError::InvalidScript);
    }
    Ok(PrivateSwapScript {
        salt: claim.salt,
        claimer_pubkey: claim.claimer_pubkey,
        owner_pubkey,
        destination_spk: claim.destination_spk,
        refund_locktime_daa,
    })
}

fn parse_private_swap_claim(
    script: &[u8],
    pos: &mut usize,
) -> Result<PrivateSwapClaim, PrivateSwapError> {
    let salt = parse_claim_salt(script, pos)?;
    expect_sequence(script, pos, &[OP_DROP, OP_IF])?;
    let claimer_pubkey = parse_claim_pubkey(script, pos)?;
    let destination_spk = parse_claim_destination(script, pos)?;
    parse_claim_fee_policy(script, pos)?;
    Ok(PrivateSwapClaim {
        salt,
        claimer_pubkey,
        destination_spk,
    })
}

fn parse_claim_salt(script: &[u8], pos: &mut usize) -> Result<[u8; 16], PrivateSwapError> {
    let salt_slice = read_direct_push(script, pos, 16)?;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(salt_slice);
    if salt == [0u8; 16] {
        return Err(PrivateSwapError::InvalidScript);
    }
    Ok(salt)
}

fn parse_claim_pubkey(script: &[u8], pos: &mut usize) -> Result<[u8; 32], PrivateSwapError> {
    let claimer_slice = read_direct_push(script, pos, 32)?;
    let mut claimer_pubkey = [0u8; 32];
    claimer_pubkey.copy_from_slice(claimer_slice);
    expect_sequence(
        script,
        pos,
        &[
            OP_CHECKSIGVERIFY,
            OP_TX_INPUT_COUNT,
            OP_1,
            OP_NUMEQUALVERIFY,
            OP_TX_OUTPUT_COUNT,
            OP_1,
            OP_NUMEQUALVERIFY,
            OP_0,
            OP_TX_OUTPUT_SPK,
        ],
    )?;
    Ok(claimer_pubkey)
}

fn parse_claim_destination(script: &[u8], pos: &mut usize) -> Result<Vec<u8>, PrivateSwapError> {
    let destination_spk = read_bounded_direct_push(script, pos, 3, 75)?.to_vec();
    expect_sequence(
        script,
        pos,
        &[
            OP_EQUALVERIFY,
            OP_0,
            OP_TX_INPUT_AMOUNT,
            OP_DUP,
            OP_0,
            OP_TX_OUTPUT_AMOUNT,
            OP_GREATERTHANOREQUAL,
            OP_VERIFY,
            OP_0,
            OP_TX_OUTPUT_AMOUNT,
            OP_SUB,
        ],
    )?;
    Ok(destination_spk)
}

fn parse_claim_fee_policy(script: &[u8], pos: &mut usize) -> Result<(), PrivateSwapError> {
    if read_script_int(script, pos)? != PRIVATE_SWAP_MAX_FEE_SOMPI {
        return Err(PrivateSwapError::InvalidScript);
    }
    expect_sequence(script, pos, &[OP_LESSTHANOREQUAL, OP_VERIFY, OP_1, OP_ELSE])
}

fn parse_private_swap_refund(
    script: &[u8],
    pos: &mut usize,
) -> Result<([u8; 32], u64), PrivateSwapError> {
    let owner_slice = read_direct_push(script, pos, 32)?;
    let mut owner_pubkey = [0u8; 32];
    owner_pubkey.copy_from_slice(owner_slice);
    expect(script, pos, OP_CHECKSIGVERIFY)?;
    let refund_locktime_daa = read_script_int(script, pos)?;
    if refund_locktime_daa == 0 {
        return Err(PrivateSwapError::InvalidScript);
    }
    expect_sequence(script, pos, &[OP_CHECKLOCKTIMEVERIFY, OP_1, OP_ENDIF])?;
    Ok((owner_pubkey, refund_locktime_daa))
}

pub fn private_swap_claim_sighash(
    tx: &Transaction,
    expected_claimer_pubkey: &[u8; 32],
) -> Result<([u8; 32], PrivateSwapScript), PrivateSwapError> {
    let sighash_type = validate_claim_transaction_shape(tx)?;
    let policy = validate_claim_policy(tx, expected_claimer_pubkey)?;
    validate_claim_output(tx, &policy)?;
    Ok((calculate_sighash(tx, 0, sighash_type), policy))
}

fn validate_claim_transaction_shape(tx: &Transaction) -> Result<SigHashType, PrivateSwapError> {
    if tx.num_inputs != 1 || tx.num_outputs != 1 || tx.payload_len != 0 {
        return Err(PrivateSwapError::InvalidTransaction);
    }
    let input = &tx.inputs[0];
    if input.sig_count != 0 || input.incoming_partial_sigs_count != 0 {
        return Err(PrivateSwapError::InvalidTransaction);
    }
    let sighash_type =
        SigHashType::from_byte(input.sighash_type).ok_or(PrivateSwapError::InvalidSighash)?;
    if sighash_type != SigHashType::All {
        Err(PrivateSwapError::InvalidSighash)
    } else {
        Ok(sighash_type)
    }
}

fn validate_claim_policy(
    tx: &Transaction,
    expected_claimer_pubkey: &[u8; 32],
) -> Result<PrivateSwapScript, PrivateSwapError> {
    let redeem = tx.redeem_bytes(0);
    if redeem.is_empty() {
        return Err(PrivateSwapError::InvalidScript);
    }
    let policy = parse_private_swap_script(redeem)?;
    if &policy.claimer_pubkey != expected_claimer_pubkey {
        Err(PrivateSwapError::WrongClaimer)
    } else {
        Ok(policy)
    }
}

fn validate_claim_output(
    tx: &Transaction,
    policy: &PrivateSwapScript,
) -> Result<(), PrivateSwapError> {
    let input = &tx.inputs[0];
    let output = &tx.outputs[0];
    let capacity = 2usize
        .checked_add(output.script_public_key.script_len)
        .ok_or(PrivateSwapError::InvalidScript)?;
    let mut actual_spk = Vec::new();
    actual_spk
        .try_reserve_exact(capacity)
        .map_err(|_| PrivateSwapError::InvalidScript)?;
    actual_spk.extend_from_slice(&output.script_public_key.version.to_le_bytes());
    actual_spk.extend_from_slice(output.script_public_key.script_bytes());
    if actual_spk != policy.destination_spk {
        return Err(PrivateSwapError::WrongDestination);
    }
    let fee = input
        .utxo_entry
        .amount
        .checked_sub(output.value)
        .ok_or(PrivateSwapError::InvalidTransaction)?;
    if fee > PRIVATE_SWAP_MAX_FEE_SOMPI {
        Err(PrivateSwapError::FeeTooHigh)
    } else {
        Ok(())
    }
}

fn read_direct_push<'a>(
    script: &'a [u8],
    pos: &mut usize,
    exact: usize,
) -> Result<&'a [u8], PrivateSwapError> {
    let data = read_bounded_direct_push(script, pos, exact, exact)?;
    Ok(data)
}

fn read_bounded_direct_push<'a>(
    script: &'a [u8],
    pos: &mut usize,
    min: usize,
    max: usize,
) -> Result<&'a [u8], PrivateSwapError> {
    let len = usize::from(*script.get(*pos).ok_or(PrivateSwapError::InvalidScript)?);
    if len < min || len > max || len > 75 {
        return Err(PrivateSwapError::InvalidScript);
    }
    *pos = (*pos)
        .checked_add(1)
        .ok_or(PrivateSwapError::InvalidScript)?;
    let end = (*pos)
        .checked_add(len)
        .ok_or(PrivateSwapError::InvalidScript)?;
    let data = script
        .get(*pos..end)
        .ok_or(PrivateSwapError::InvalidScript)?;
    *pos = end;
    Ok(data)
}

fn read_script_int(script: &[u8], pos: &mut usize) -> Result<u64, PrivateSwapError> {
    let opcode = *script.get(*pos).ok_or(PrivateSwapError::InvalidScript)?;
    *pos = (*pos)
        .checked_add(1)
        .ok_or(PrivateSwapError::InvalidScript)?;
    if opcode == OP_0 {
        return Ok(0);
    }
    if (OP_1..=0x60).contains(&opcode) {
        return Ok(u64::from(opcode - 0x50));
    }
    read_script_int_bytes(script, pos, usize::from(opcode))
}

fn read_script_int_bytes(
    script: &[u8],
    pos: &mut usize,
    len: usize,
) -> Result<u64, PrivateSwapError> {
    if len == 0 || len > 9 || len > 75 {
        return Err(PrivateSwapError::InvalidScript);
    }
    let end = (*pos)
        .checked_add(len)
        .ok_or(PrivateSwapError::InvalidScript)?;
    let data = script
        .get(*pos..end)
        .ok_or(PrivateSwapError::InvalidScript)?;
    *pos = end;
    if !is_canonical_positive_script_int(data) {
        return Err(PrivateSwapError::InvalidScript);
    }
    let mut value = 0u64;
    for (index, byte) in data.iter().take(8).enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    if value <= 16 {
        return Err(PrivateSwapError::InvalidScript);
    }
    Ok(value)
}

fn is_canonical_positive_script_int(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let last = data[data.len() - 1];
    if last & 0x80 != 0 {
        return false;
    }
    data.len() == 1 || last != 0 || data[data.len() - 2] & 0x80 != 0
}

fn expect(script: &[u8], pos: &mut usize, expected: u8) -> Result<(), PrivateSwapError> {
    if script.get(*pos).copied() != Some(expected) {
        return Err(PrivateSwapError::InvalidScript);
    }
    *pos = (*pos)
        .checked_add(1)
        .ok_or(PrivateSwapError::InvalidScript)?;
    Ok(())
}

fn expect_sequence(
    script: &[u8],
    pos: &mut usize,
    expected: &[u8],
) -> Result<(), PrivateSwapError> {
    let end = (*pos)
        .checked_add(expected.len())
        .ok_or(PrivateSwapError::InvalidScript)?;
    if script.get(*pos..end) != Some(expected) {
        return Err(PrivateSwapError::InvalidScript);
    }
    *pos = end;
    Ok(())
}

#[cfg(test)]
mod unit_tests;
