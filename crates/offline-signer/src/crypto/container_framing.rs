//! Pure framing parsers for externally supplied encrypted containers.
//!
//! Keeping these byte-level decisions in the host-testable offline signer lets
//! firmware, property tests and fuzzers execute one implementation. Crypto and
//! hardware key use remain in the firmware service layer.

use crate::crypto::credential::{CredentialKind, SALT_SIZE};

use super::{
    device_bound_storage::{KDF_ID_DEVICE_HMAC_SHA256, NONCE_SIZE, TAG_SIZE},
    password_kdf::{self, PasswordKdfParams, METADATA_SIZE},
};

pub const BACKUP_CURRENT_MAGIC: [u8; 8] = *b"KASDB005";
pub const BACKUP_LEGACY_MAGIC: [u8; 8] = *b"KASDB004";
pub const BACKUP_CURRENT_VERSION: u8 = 2;
pub const BACKUP_LEGACY_VERSION: u8 = 1;
pub const BACKUP_CURRENT_HEADER_SIZE: usize = 60;
pub const BACKUP_LEGACY_HEADER_SIZE: usize = 48;
pub const BACKUP_MAX_PLAINTEXT: usize = 120;

pub const TRANSPORT_CURRENT_MAGIC: [u8; 4] = *b"KAS\x04";
pub const TRANSPORT_LEGACY_MAGIC: [u8; 4] = *b"KAS\x03";
pub const TRANSPORT_NONCE_SIZE: usize = 12;
pub const TRANSPORT_TAG_SIZE: usize = 16;
pub const TRANSPORT_LEGACY_HEADER_SIZE: usize = 6;
pub const TRANSPORT_CURRENT_HEADER_SIZE: usize =
    4 + 2 + METADATA_SIZE + SALT_SIZE + TRANSPORT_NONCE_SIZE;
pub const TRANSPORT_CURRENT_CIPHERTEXT_START: usize = TRANSPORT_CURRENT_HEADER_SIZE;
pub const TRANSPORT_LEGACY_CIPHERTEXT_START: usize =
    TRANSPORT_LEGACY_HEADER_SIZE + TRANSPORT_NONCE_SIZE;
pub const TRANSPORT_CURRENT_MAX_DATA_LEN: usize =
    1024 - TRANSPORT_CURRENT_HEADER_SIZE - TRANSPORT_TAG_SIZE;
pub const TRANSPORT_LEGACY_MAX_DATA_LEN: usize =
    1024 - TRANSPORT_LEGACY_CIPHERTEXT_START - TRANSPORT_TAG_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramingError {
    InvalidFormat,
    UnsupportedFormat,
    WrongPurpose,
    InvalidLength,
    UnsupportedKdf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupPayloadKind {
    Seed,
    Xprv,
}

impl BackupPayloadKind {
    pub const fn code(self) -> u8 {
        match self {
            Self::Seed => 1,
            Self::Xprv => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupReaderKdf {
    Argon2id(PasswordKdfParams),
    LegacyPbkdf2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupEnvelopeHeader {
    pub kind: BackupPayloadKind,
    pub payload_len: usize,
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub header_size: usize,
    pub kdf: BackupReaderKdf,
}

pub fn parse_backup_header(input: &[u8]) -> Result<BackupEnvelopeHeader, FramingError> {
    let magic = input.get(..8).ok_or(FramingError::InvalidLength)?;
    if magic == BACKUP_CURRENT_MAGIC {
        parse_current_backup_header(input)
    } else if magic == BACKUP_LEGACY_MAGIC {
        parse_legacy_backup_header(input)
    } else {
        Err(FramingError::InvalidFormat)
    }
}

fn parse_current_backup_header(input: &[u8]) -> Result<BackupEnvelopeHeader, FramingError> {
    if input.len() < BACKUP_CURRENT_HEADER_SIZE + TAG_SIZE {
        return Err(FramingError::InvalidLength);
    }
    if input[8] != BACKUP_CURRENT_VERSION {
        return Err(FramingError::UnsupportedFormat);
    }
    let kind = parse_backup_kind(input[9])?;
    validate_backup_fixed_fields(input, 56..60)?;
    let payload_len = parse_backup_len(input, BACKUP_CURRENT_HEADER_SIZE)?;
    let kdf = password_kdf::parse_metadata(&input[16..16 + METADATA_SIZE])
        .map_err(|_| FramingError::UnsupportedKdf)?;
    let salt = copy_nonzero::<SALT_SIZE>(&input[28..44])?;
    let nonce = copy_nonzero::<NONCE_SIZE>(&input[44..56])?;
    Ok(BackupEnvelopeHeader {
        kind,
        payload_len,
        salt,
        nonce,
        header_size: BACKUP_CURRENT_HEADER_SIZE,
        kdf: BackupReaderKdf::Argon2id(kdf),
    })
}

fn parse_legacy_backup_header(input: &[u8]) -> Result<BackupEnvelopeHeader, FramingError> {
    let minimum = BACKUP_LEGACY_HEADER_SIZE
        .checked_add(1)
        .and_then(|value| value.checked_add(TAG_SIZE))
        .ok_or(FramingError::InvalidLength)?;
    if input.get(..minimum).is_none() {
        return Err(FramingError::InvalidLength);
    }
    if input[8] != BACKUP_LEGACY_VERSION {
        return Err(FramingError::UnsupportedFormat);
    }
    let kind = parse_backup_kind(input[9])?;
    validate_backup_fixed_fields(input, 44..48)?;
    let payload_len = parse_backup_len(input, BACKUP_LEGACY_HEADER_SIZE)?;
    let salt = copy_nonzero::<SALT_SIZE>(&input[16..32])?;
    let nonce = copy_nonzero::<NONCE_SIZE>(&input[32..44])?;
    Ok(BackupEnvelopeHeader {
        kind,
        payload_len,
        salt,
        nonce,
        header_size: BACKUP_LEGACY_HEADER_SIZE,
        kdf: BackupReaderKdf::LegacyPbkdf2,
    })
}

fn validate_backup_fixed_fields(
    input: &[u8],
    reserved: core::ops::Range<usize>,
) -> Result<(), FramingError> {
    let fixed_fields_valid = input[10] == KDF_ID_DEVICE_HMAC_SHA256
        && input[11] == CredentialKind::Password as u8
        && input[14] == 0
        && input[15] == 0;
    let reserved_clear = input
        .get(reserved)
        .is_some_and(|bytes| bytes.iter().all(|byte| *byte == 0));
    if fixed_fields_valid && reserved_clear {
        Ok(())
    } else {
        Err(FramingError::InvalidFormat)
    }
}

fn parse_backup_kind(code: u8) -> Result<BackupPayloadKind, FramingError> {
    match code {
        1 => Ok(BackupPayloadKind::Seed),
        2 => Ok(BackupPayloadKind::Xprv),
        _ => Err(FramingError::WrongPurpose),
    }
}

fn parse_backup_len(input: &[u8], header_size: usize) -> Result<usize, FramingError> {
    let payload_len = usize::from(u16::from_le_bytes([input[12], input[13]]));
    let total = header_size
        .checked_add(payload_len)
        .and_then(|value| value.checked_add(TAG_SIZE))
        .ok_or(FramingError::InvalidLength)?;
    if payload_len == 0 || payload_len > BACKUP_MAX_PLAINTEXT || input.len() != total {
        Err(FramingError::InvalidLength)
    } else {
        Ok(payload_len)
    }
}

fn copy_nonzero<const N: usize>(input: &[u8]) -> Result<[u8; N], FramingError> {
    let Some(slice) = input.get(..N).filter(|slice| slice.len() == input.len()) else {
        return Err(FramingError::InvalidLength);
    };
    let mut output = [0u8; N];
    output.copy_from_slice(slice);
    if output.iter().all(|byte| *byte == 0) {
        Err(FramingError::InvalidFormat)
    } else {
        Ok(output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportVersion {
    Current,
    Legacy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportEnvelopeHeader {
    pub version: TransportVersion,
    pub data_len: usize,
    pub header_len: usize,
    pub ciphertext_start: usize,
    pub tag_start: usize,
    pub parameters: Option<PasswordKdfParams>,
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; TRANSPORT_NONCE_SIZE],
}

pub fn parse_transport_header(
    input: &[u8],
    file_len: usize,
) -> Result<TransportEnvelopeHeader, FramingError> {
    let input = input.get(..file_len).ok_or(FramingError::InvalidLength)?;
    let magic = input.get(..4).ok_or(FramingError::InvalidLength)?;
    if magic == TRANSPORT_CURRENT_MAGIC {
        parse_current_transport_header(input)
    } else if magic == TRANSPORT_LEGACY_MAGIC {
        parse_legacy_transport_header(input)
    } else {
        Err(FramingError::InvalidFormat)
    }
}

fn parse_current_transport_header(input: &[u8]) -> Result<TransportEnvelopeHeader, FramingError> {
    let minimum = TRANSPORT_CURRENT_HEADER_SIZE
        .checked_add(1)
        .and_then(|value| value.checked_add(TRANSPORT_TAG_SIZE))
        .ok_or(FramingError::InvalidLength)?;
    if input.len() < minimum {
        return Err(FramingError::InvalidLength);
    }
    let data_len = usize::from(u16::from_le_bytes([input[4], input[5]]));
    let total = TRANSPORT_CURRENT_CIPHERTEXT_START
        .checked_add(data_len)
        .and_then(|value| value.checked_add(TRANSPORT_TAG_SIZE))
        .ok_or(FramingError::InvalidLength)?;
    if data_len == 0 || data_len > TRANSPORT_CURRENT_MAX_DATA_LEN || total != input.len() {
        return Err(FramingError::InvalidLength);
    }
    let parameters = password_kdf::parse_metadata(&input[6..6 + METADATA_SIZE])
        .map_err(|_| FramingError::UnsupportedKdf)?;
    let salt_start = 6 + METADATA_SIZE;
    let nonce_start = salt_start + SALT_SIZE;
    let salt = copy_nonzero::<SALT_SIZE>(&input[salt_start..nonce_start])?;
    let nonce =
        copy_nonzero::<TRANSPORT_NONCE_SIZE>(&input[nonce_start..TRANSPORT_CURRENT_HEADER_SIZE])?;
    Ok(TransportEnvelopeHeader {
        version: TransportVersion::Current,
        data_len,
        header_len: TRANSPORT_CURRENT_HEADER_SIZE,
        ciphertext_start: TRANSPORT_CURRENT_CIPHERTEXT_START,
        tag_start: TRANSPORT_CURRENT_CIPHERTEXT_START + data_len,
        parameters: Some(parameters),
        salt,
        nonce,
    })
}

fn parse_legacy_transport_header(input: &[u8]) -> Result<TransportEnvelopeHeader, FramingError> {
    let minimum = TRANSPORT_LEGACY_CIPHERTEXT_START
        .checked_add(1)
        .and_then(|value| value.checked_add(TRANSPORT_TAG_SIZE))
        .ok_or(FramingError::InvalidLength)?;
    if input.len() < minimum {
        return Err(FramingError::InvalidLength);
    }
    let data_len = usize::from(u16::from_le_bytes([input[4], input[5]]));
    let total = TRANSPORT_LEGACY_CIPHERTEXT_START
        .checked_add(data_len)
        .and_then(|value| value.checked_add(TRANSPORT_TAG_SIZE))
        .ok_or(FramingError::InvalidLength)?;
    if data_len == 0 || data_len > TRANSPORT_LEGACY_MAX_DATA_LEN || total != input.len() {
        return Err(FramingError::InvalidLength);
    }
    let mut nonce = [0u8; TRANSPORT_NONCE_SIZE];
    nonce.copy_from_slice(&input[TRANSPORT_LEGACY_HEADER_SIZE..TRANSPORT_LEGACY_CIPHERTEXT_START]);
    Ok(TransportEnvelopeHeader {
        version: TransportVersion::Legacy,
        data_len,
        header_len: TRANSPORT_LEGACY_HEADER_SIZE,
        ciphertext_start: TRANSPORT_LEGACY_CIPHERTEXT_START,
        tag_start: TRANSPORT_LEGACY_CIPHERTEXT_START + data_len,
        parameters: None,
        salt: [0u8; SALT_SIZE],
        nonce,
    })
}

#[cfg(test)]
#[path = "unit_tests/container_framing_tests.rs"]
mod unit_tests;
