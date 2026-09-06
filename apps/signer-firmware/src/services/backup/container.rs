//! Versioned device-bound SD wallet-secret container.
//!
//! New v5 writers use Argon2id v=19. The complete KDF metadata, salt, nonce,
//! purpose and payload length are authenticated as AES-GCM AAD. KASDB004 is a
//! restore-only legacy PBKDF2 reader; new writers never emit it and readers
//! never probe/fallback between KDFs.

use offline_signer::crypto::{
    container_framing::{self, BackupPayloadKind, BackupReaderKdf, FramingError},
    device_bound_storage::{KDF_ID_DEVICE_HMAC_SHA256, NONCE_SIZE, StoragePurpose, TAG_SIZE},
    legacy_pbkdf2,
    password_kdf::{self, PasswordKdfParams, PasswordKdfPurpose},
};
use shared_signer::bytes::zeroize_bytes;
use crate::services::credential_policy::{self, CredentialKind, SALT_SIZE};

use super::{BackupDevice, BackupError, randomness::BackupRandomness};

const CURRENT_MAGIC: [u8; 8] = container_framing::BACKUP_CURRENT_MAGIC;
#[cfg(test)]
const LEGACY_MAGIC: [u8; 8] = container_framing::BACKUP_LEGACY_MAGIC;
const CURRENT_VERSION: u8 = container_framing::BACKUP_CURRENT_VERSION;
#[cfg(test)]
const LEGACY_VERSION: u8 = container_framing::BACKUP_LEGACY_VERSION;
const LEGACY_PBKDF2_ROUNDS: u32 = 100_000;
pub(crate) const CURRENT_HEADER_SIZE: usize = container_framing::BACKUP_CURRENT_HEADER_SIZE;
#[cfg(test)]
pub(crate) const LEGACY_HEADER_SIZE: usize = container_framing::BACKUP_LEGACY_HEADER_SIZE;
pub(crate) const MAX_PLAINTEXT: usize = container_framing::BACKUP_MAX_PLAINTEXT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupKind { Seed, Xprv }

impl BackupKind {
    const fn code(self) -> u8 { match self { Self::Seed => 1, Self::Xprv => 2 } }
    const fn purpose(self) -> StoragePurpose {
        match self { Self::Seed => StoragePurpose::SdSeedBackup, Self::Xprv => StoragePurpose::SdXprvBackup }
    }
}

pub(crate) fn seal(
    kind: BackupKind,
    plaintext: &[u8],
    password: &[u8],
    device: &mut dyn BackupDevice,
    out: &mut [u8],
) -> Result<usize, BackupError> {
    validate_plaintext(plaintext, out)?;
    credential_policy::validate(CredentialKind::Password, password)
        .map_err(|_| BackupError::InvalidCredential)?;
    let randomness = BackupRandomness::collect()?;
    seal_with_material(kind, plaintext, password, device, randomness.salt(), randomness.nonce(), out)
}

fn seal_with_material(
    kind: BackupKind,
    plaintext: &[u8],
    password: &[u8],
    device: &mut dyn BackupDevice,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    out: &mut [u8],
) -> Result<usize, BackupError> {
    validate_plaintext(plaintext, out)?;
    if salt.iter().all(|b| *b == 0) || nonce.iter().all(|b| *b == 0) {
        out.fill(0); return Err(BackupError::EntropyUnavailable);
    }
    let total = CURRENT_HEADER_SIZE + plaintext.len() + TAG_SIZE;
    if out.len() < total { out.fill(0); return Err(BackupError::BufferTooSmall); }
    out.fill(0);
    write_current_header(kind, plaintext.len(), salt, nonce, &mut out[..CURRENT_HEADER_SIZE])?;
    let mut key = crate::services::memory::password_kdf::derive_key_32(PasswordKdfPurpose::DeviceBoundBackup, password, salt)
        .map_err(map_kdf_error)?;
    let (header, body_and_tag) = out[..total].split_at_mut(CURRENT_HEADER_SIZE);
    body_and_tag[..plaintext.len()].copy_from_slice(plaintext);
    let tag_result = device.seal_backup_key(
        kind.purpose(), &key, salt, nonce, header, &mut body_and_tag[..plaintext.len()],
    );
    zeroize_bytes(&mut key);
    let mut tag = match tag_result { Ok(tag) => tag, Err(error) => { out.fill(0); return Err(error); } };
    body_and_tag[plaintext.len()..plaintext.len()+TAG_SIZE].copy_from_slice(&tag);
    zeroize_bytes(&mut tag);
    Ok(total)
}

#[cfg(any(test, feature = "workflow-test-auto"))]
pub(crate) fn seal_for_test(
    kind: BackupKind, plaintext: &[u8], password: &[u8], device: &mut dyn BackupDevice,
    salt: &[u8; SALT_SIZE], nonce: &[u8; NONCE_SIZE], out: &mut [u8],
) -> Result<usize, BackupError> {
    seal_with_material(kind, plaintext, password, device, salt, nonce, out)
}

#[cfg(test)]
pub(crate) fn seal_legacy_for_test(
    kind: BackupKind, plaintext: &[u8], password: &[u8], device: &mut dyn BackupDevice,
    salt: &[u8; SALT_SIZE], nonce: &[u8; NONCE_SIZE], out: &mut [u8],
) -> Result<usize, BackupError> {
    validate_plaintext(plaintext, out)?;
    let total = LEGACY_HEADER_SIZE + plaintext.len() + TAG_SIZE;
    if out.len() < total { out.fill(0); return Err(BackupError::BufferTooSmall); }
    out.fill(0);
    out[..8].copy_from_slice(&LEGACY_MAGIC);
    out[8] = LEGACY_VERSION; out[9] = kind.code();
    out[10] = KDF_ID_DEVICE_HMAC_SHA256; out[11] = CredentialKind::Password as u8;
    out[12..14].copy_from_slice(&(plaintext.len() as u16).to_le_bytes());
    out[16..32].copy_from_slice(salt); out[32..44].copy_from_slice(nonce);
    let mut key = legacy_pbkdf2::derive_legacy_32(password, salt, LEGACY_PBKDF2_ROUNDS);
    let (header, body_and_tag) = out[..total].split_at_mut(LEGACY_HEADER_SIZE);
    body_and_tag[..plaintext.len()].copy_from_slice(plaintext);
    let tag_result = device.seal_backup_key(
        kind.purpose(), &key, salt, nonce, header, &mut body_and_tag[..plaintext.len()],
    );
    zeroize_bytes(&mut key);
    let mut tag = tag_result?;
    body_and_tag[plaintext.len()..plaintext.len() + TAG_SIZE].copy_from_slice(&tag);
    zeroize_bytes(&mut tag);
    Ok(total)
}

pub(crate) fn open(
    expected: BackupKind,
    input: &[u8],
    password: &[u8],
    device: &mut dyn BackupDevice,
    plaintext: &mut [u8; MAX_PLAINTEXT],
) -> Result<usize, BackupError> {
    plaintext.fill(0);
    credential_policy::validate(CredentialKind::Password, password)
        .map_err(|_| BackupError::InvalidCredential)?;
    let header = container_framing::parse_backup_header(input).map_err(map_framing_error)?;
    let kind = map_backup_kind(header.kind);
    if kind != expected { return Err(BackupError::WrongPurpose); }
    let payload_end = header.header_size
        .checked_add(header.payload_len)
        .ok_or(BackupError::InvalidLength)?;
    let total = payload_end.checked_add(TAG_SIZE).ok_or(BackupError::InvalidLength)?;
    if input.len() != total { return Err(BackupError::InvalidLength); }
    plaintext[..header.payload_len].copy_from_slice(&input[header.header_size..payload_end]);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&input[payload_end..total]);
    let mut key = derive_reader_key(password, &header)?;
    let result = device.open_backup_key(
        kind.purpose(), &key, &header.salt, &header.nonce,
        &input[..header.header_size], &mut plaintext[..header.payload_len], &tag,
    );
    zeroize_bytes(&mut key);
    zeroize_bytes(&mut tag);
    if let Err(error) = result { plaintext.fill(0); return Err(error); }
    Ok(header.payload_len)
}

pub fn kind(input: &[u8]) -> Result<BackupKind, BackupError> {
    let header = container_framing::parse_backup_header(input).map_err(map_framing_error)?;
    Ok(map_backup_kind(header.kind))
}

fn map_backup_kind(kind: BackupPayloadKind) -> BackupKind {
    match kind {
        BackupPayloadKind::Seed => BackupKind::Seed,
        BackupPayloadKind::Xprv => BackupKind::Xprv,
    }
}

fn write_current_header(
    kind: BackupKind,
    payload_len: usize,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    out: &mut [u8],
) -> Result<(), BackupError> {
    if out.len() < CURRENT_HEADER_SIZE { return Err(BackupError::BufferTooSmall); }
    out.fill(0);
    out[..8].copy_from_slice(&CURRENT_MAGIC);
    out[8] = CURRENT_VERSION;
    out[9] = kind.code();
    out[10] = KDF_ID_DEVICE_HMAC_SHA256;
    out[11] = CredentialKind::Password as u8;
    out[12..14].copy_from_slice(&(payload_len as u16).to_le_bytes());
    let metadata = password_kdf::encode_metadata(PasswordKdfParams::current()).map_err(map_kdf_error)?;
    out[16..28].copy_from_slice(&metadata);
    out[28..44].copy_from_slice(salt);
    out[44..56].copy_from_slice(nonce);
    Ok(())
}

fn derive_reader_key(
    password: &[u8],
    header: &container_framing::BackupEnvelopeHeader,
) -> Result<[u8; 32], BackupError> {
    match header.kdf {
        BackupReaderKdf::Argon2id(parameters) => {
            crate::services::memory::password_kdf::derive_key_32_with_params(
                PasswordKdfPurpose::DeviceBoundBackup, password, &header.salt, parameters,
            ).map_err(map_kdf_error)
        }
        BackupReaderKdf::LegacyPbkdf2 => Ok(legacy_pbkdf2::derive_legacy_32(
            password, &header.salt, LEGACY_PBKDF2_ROUNDS,
        )),
    }
}

fn map_framing_error(error: FramingError) -> BackupError {
    match error {
        FramingError::InvalidFormat => BackupError::InvalidFormat,
        FramingError::UnsupportedFormat | FramingError::UnsupportedKdf => BackupError::UnsupportedFormat,
        FramingError::WrongPurpose => BackupError::WrongPurpose,
        FramingError::InvalidLength => BackupError::InvalidLength,
    }
}

fn validate_plaintext(plaintext: &[u8], out: &mut [u8]) -> Result<(), BackupError> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
        out.fill(0);
        Err(BackupError::InvalidLength)
    } else {
        Ok(())
    }
}
fn map_kdf_error(_:password_kdf::PasswordKdfError)->BackupError{BackupError::UnsupportedFormat}
