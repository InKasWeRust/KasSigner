//! Plaintext codec and error mapping helpers for stego payloads.

use shared_signer::bytes::{zeroize_bytes, zeroize_u16};

use crate::services::backup::BackupError;

use super::{
    portable, PayloadError, StegoCarrier, StegoSecurity, MAX_HINT_SIZE, PLAINTEXT_SIZE,
    SECURITY_DEVICE, SECURITY_PORTABLE, WORD_BYTES, WORD_SLOTS,
};

pub(super) fn reset_outputs(indices: &mut [u16; WORD_SLOTS], hint: &mut [u8; MAX_HINT_SIZE]) {
    zeroize_u16(indices);
    zeroize_bytes(hint);
}

pub(super) fn validate_inputs(
    indices: &[u16; WORD_SLOTS],
    word_count: u8,
    hint: &[u8],
    descriptor: &[u8],
) -> Result<(), PayloadError> {
    if !crate::wallet::mnemonic::validate(indices, word_count)
        || hint.len() > MAX_HINT_SIZE
        || descriptor.is_empty()
        || descriptor.len() > 96
    {
        Err(PayloadError::InvalidInput)
    } else {
        Ok(())
    }
}

pub(super) fn encode_plaintext(
    format_version: u8,
    indices: &[u16; WORD_SLOTS],
    word_count: u8,
    hint: &[u8],
    output: &mut [u8; PLAINTEXT_SIZE],
) {
    output.fill(0);
    output[0] = format_version;
    output[1] = word_count;
    let words = if word_count == 12 { 12 } else { 24 };
    for (index, word) in indices[..words].iter().enumerate() {
        let offset = 2 + index * 2;
        output[offset..offset + 2].copy_from_slice(&word.to_le_bytes());
    }
    output[2 + WORD_BYTES] = hint.len() as u8;
    output[3 + WORD_BYTES..3 + WORD_BYTES + hint.len()].copy_from_slice(hint);
}

pub(super) fn finish_decode(
    expected: u8,
    plaintext: &mut [u8; PLAINTEXT_SIZE],
    indices: &mut [u16; WORD_SLOTS],
    hint: &mut [u8; MAX_HINT_SIZE],
) -> Result<(u8, usize), PayloadError> {
    let result = decode_plaintext(expected, plaintext, indices, hint);
    zeroize_bytes(plaintext);
    if result.is_err() {
        reset_outputs(indices, hint);
    }
    result
}

fn decode_plaintext(
    expected: u8,
    plaintext: &[u8; PLAINTEXT_SIZE],
    indices: &mut [u16; WORD_SLOTS],
    hint: &mut [u8; MAX_HINT_SIZE],
) -> Result<(u8, usize), PayloadError> {
    if plaintext[0] != expected {
        return Err(PayloadError::InvalidInput);
    }
    let word_count = plaintext[1];
    let words = match word_count {
        12 => 12usize,
        24 => 24usize,
        _ => return Err(PayloadError::InvalidInput),
    };

    for index in 0..WORD_SLOTS {
        let offset = 2 + index * 2;
        let word = u16::from_le_bytes([plaintext[offset], plaintext[offset + 1]]);
        if index < words {
            if word >= 2048 {
                return Err(PayloadError::InvalidInput);
            }
            indices[index] = word;
        } else if word != 0 {
            return Err(PayloadError::InvalidInput);
        }
    }
    if !crate::wallet::mnemonic::validate(indices, word_count) {
        return Err(PayloadError::InvalidInput);
    }

    let hint_len = usize::from(plaintext[2 + WORD_BYTES]);
    if hint_len > MAX_HINT_SIZE {
        return Err(PayloadError::InvalidInput);
    }
    let hint_start = 3 + WORD_BYTES;
    if plaintext[hint_start + hint_len..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(PayloadError::InvalidInput);
    }
    hint[..hint_len].copy_from_slice(&plaintext[hint_start..hint_start + hint_len]);
    Ok((word_count, hint_len))
}

pub(super) fn map_portable_error(error: portable::PortableError) -> PayloadError {
    match error {
        portable::PortableError::InvalidPassword => PayloadError::InvalidPassword,
        portable::PortableError::UnsupportedKdf => PayloadError::UnsupportedKdf,
        portable::PortableError::AuthenticationFailed => PayloadError::AuthenticationFailed,
        portable::PortableError::EncryptionFailed => PayloadError::EncryptionFailed,
    }
}

pub(super) fn map_backup_error(error: BackupError) -> PayloadError {
    match error {
        BackupError::EntropyUnavailable => PayloadError::EntropyUnavailable,
        BackupError::AuthenticationFailed | BackupError::InvalidCredential => {
            PayloadError::AuthenticationFailed
        }
        BackupError::DeviceKeyUnavailable => PayloadError::DeviceKeyUnavailable,
        _ => PayloadError::EncryptionFailed,
    }
}

pub(super) const fn carrier_code(carrier: StegoCarrier) -> u8 {
    match carrier {
        StegoCarrier::Descriptor => 1,
        StegoCarrier::Picture => 2,
    }
}

pub(super) fn carrier_from_code(code: u8) -> Result<StegoCarrier, PayloadError> {
    match code {
        1 => Ok(StegoCarrier::Descriptor),
        2 => Ok(StegoCarrier::Picture),
        _ => Err(PayloadError::InvalidInput),
    }
}

pub(super) fn security_from_code(code: u8) -> Result<StegoSecurity, PayloadError> {
    match code {
        SECURITY_DEVICE => Ok(StegoSecurity::DeviceBound),
        SECURITY_PORTABLE => Ok(StegoSecurity::Portable),
        _ => Err(PayloadError::InvalidInput),
    }
}
