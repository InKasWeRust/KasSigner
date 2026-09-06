use offline_signer::crypto::password_kdf;
use crate::services::credential_policy::{CredentialKind, SALT_SIZE};

use super::{
    bound, AlignedBytes, CredentialKdf, PersistError, RecordHeader, CURRENT_AAD_SIZE,
    CURRENT_CIPHERTEXT_START, CURRENT_FORMAT_VERSION, CURRENT_MAGIC, DEVICE_KDF_ID,
    LEGACY_AAD_SIZE, LEGACY_CIPHERTEXT_START, LEGACY_FORMAT_VERSION, LEGACY_MAGIC,
    PAYLOAD_SIZE, RECORD_SIZE, valid_key_slot,
};

pub(super) fn prepare_header(
    record: &mut AlignedBytes<RECORD_SIZE>,
    sequence: u32,
    key_slot: u8,
    credential_kind: CredentialKind,
    device_only: bool,
    salt: &[u8; SALT_SIZE],
) -> Result<(), PersistError> {
    if !valid_key_slot(key_slot) { return Err(PersistError::DeviceKeyMissing); }
    record.0.fill(0);
    record.0[..8].copy_from_slice(&CURRENT_MAGIC);
    record.0[8] = CURRENT_FORMAT_VERSION;
    record.0[9] = key_slot;
    record.0[10] = credential_kind as u8;
    record.0[11] = 1;
    record.0[12..16].copy_from_slice(&sequence.to_le_bytes());
    record.0[16..18].copy_from_slice(&(PAYLOAD_SIZE as u16).to_le_bytes());
    record.0[18] = DEVICE_KDF_ID;
    let metadata = password_kdf::encode_metadata(password_kdf::PasswordKdfParams::current())
        .map_err(|_| PersistError::Crypto)?;
    record.0[19..31].copy_from_slice(&metadata);
    crate::services::entropy::fill(&mut record.0[31..43]).map_err(|_| PersistError::Entropy)?;
    record.0[43..59].copy_from_slice(salt);
    record.0[59] = u8::from(device_only);
    Ok(())
}

pub(super) fn parse_header(record: &AlignedBytes<RECORD_SIZE>) -> Option<RecordHeader> {
    if record.0[..8] == CURRENT_MAGIC {
        return parse_current_header(record);
    }
    if record.0[..8] == LEGACY_MAGIC {
        return parse_legacy_header(record);
    }
    None
}

fn parse_current_header(record: &AlignedBytes<RECORD_SIZE>) -> Option<RecordHeader> {
    if record.0[8] != CURRENT_FORMAT_VERSION || record.0[18] != DEVICE_KDF_ID || record.0[59] > 1 {
        return None;
    }
    let parameters = password_kdf::parse_metadata(&record.0[19..31]).ok()?;
    parse_common_header(
        record,
        31,
        43,
        CredentialKdf::Argon2id(parameters),
        CURRENT_AAD_SIZE,
        CURRENT_CIPHERTEXT_START,
        record.0[59] == 1,
    )
}

fn parse_legacy_header(record: &AlignedBytes<RECORD_SIZE>) -> Option<RecordHeader> {
    if record.0[8] != LEGACY_FORMAT_VERSION || record.0[18] != DEVICE_KDF_ID || record.0[19] != 0 {
        return None;
    }
    parse_common_header(
        record,
        20,
        32,
        CredentialKdf::LegacyPbkdf2Sha256,
        LEGACY_AAD_SIZE,
        LEGACY_CIPHERTEXT_START,
        false,
    )
}

fn parse_common_header(
    record: &AlignedBytes<RECORD_SIZE>,
    nonce_start: usize,
    salt_start: usize,
    credential_kdf: CredentialKdf,
    aad_size: usize,
    ciphertext_start: usize,
    device_only: bool,
) -> Option<RecordHeader> {
    let payload_len = u16::from_le_bytes([record.0[16], record.0[17]]) as usize;
    if payload_len != PAYLOAD_SIZE || record.0[11] > 1 { return None; }
    let sequence = u32::from_le_bytes(record.0[12..16].try_into().ok()?);
    let key_slot = record.0[9];
    if !valid_key_slot(key_slot) { return None; }
    let credential_kind = CredentialKind::from_byte(record.0[10])?;
    let mut nonce = [0u8; bound::NONCE_SIZE];
    nonce.copy_from_slice(&record.0[nonce_start..nonce_start + bound::NONCE_SIZE]);
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&record.0[salt_start..salt_start + SALT_SIZE]);
    if nonce.iter().all(|byte| *byte == 0) || salt.iter().all(|byte| *byte == 0) { return None; }
    Some(RecordHeader {
        sequence,
        key_slot,
        credential_kind,
        device_only,
        salt,
        policy_required: record.0[11] == 1,
        credential_kdf,
        nonce,
        aad_size,
        ciphertext_start,
    })
}
