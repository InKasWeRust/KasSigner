//! Versioned encrypted SD backend for persistent-wallet records.
//!
//! New `KSW4` slot envelopes authenticate Argon2id metadata, credential salt,
//! nonce and slot identity. The journal anchor selects the KDF/version before
//! any password derivation, so legacy PBKDF2 SD slots are read only when an
//! explicitly legacy anchor says so; there is no algorithm probing fallback.

use offline_signer::{
    crypto::password_kdf::{self, METADATA_SIZE},
    derivation::hmac::zeroize_buf,
};
use sha2::{Digest, Sha256};
use crate::services::credential_policy::{CredentialKind, SALT_SIZE};

use crate::hw::sdcard;

use super::{
    crypto::{DeviceCrypto, RECORD_SIZE},
    flash::AlignedBytes,
    kdf::CredentialKdf,
    PersistError,
};

const CURRENT_MAGIC: [u8; 4] = *b"KSW4";
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const CURRENT_HEADER_SIZE: usize = 4 + METADATA_SIZE + SALT_SIZE + NONCE_SIZE + TAG_SIZE;
const CURRENT_ENVELOPE_SIZE: usize = CURRENT_HEADER_SIZE + RECORD_SIZE;
const LEGACY_HEADER_SIZE: usize = NONCE_SIZE + TAG_SIZE;
const LEGACY_ENVELOPE_SIZE: usize = LEGACY_HEADER_SIZE + RECORD_SIZE;
const SLOT_FILES: [[u8; 11]; 2] = [*b"KSWALTA BIN", *b"KSWALTB BIN"];
const SLOT_AAD: [&[u8]; 2] = [
    b"KasSigner device-bound SD wallet slot A v4",
    b"KasSigner device-bound SD wallet slot B v4",
];

// The encrypted SD envelope is slightly larger than one 4 KiB wallet record.
// Keep it out of callers that already own a record-sized stack scratch buffer.
#[inline(never)]
pub(super) fn write_slot(
    crypto: &mut DeviceCrypto<'_>,
    kind: CredentialKind,
    credential_key: &[u8; 32],
    salt: &[u8; SALT_SIZE],
    slot: u8,
    record: &AlignedBytes<RECORD_SIZE>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) -> Result<(), PersistError> {
    let index = slot_index(slot)?;
    let mut envelope = AlignedBytes::<CURRENT_ENVELOPE_SIZE>::zeroed();
    seal_current(
        crypto,
        kind,
        credential_key,
        salt,
        index,
        record,
        &mut envelope,
    )?;
    let expected = Sha256::digest(&envelope.0);
    let write_result = sdcard::with_sd_card!(i2c, delay, |card| {
        let fat = sdcard::mount_fat32(card)?;
        sdcard::overwrite_file(card, &fat, &SLOT_FILES[index], &envelope.0)?;
        Ok(())
    });
    if write_result.is_err() {
        zeroize_buf(&mut envelope.0);
        return Err(PersistError::SdStorageWrite);
    }

    zeroize_buf(&mut envelope.0);
    read_raw_exact(index, &mut envelope.0, i2c, delay)?;
    let actual = Sha256::digest(&envelope.0);
    let verified = expected[..] == actual[..];
    zeroize_buf(&mut envelope.0);
    if verified {
        Ok(())
    } else {
        Err(PersistError::SdStorageWrite)
    }
}

#[inline(never)]
pub(super) fn read_slot(
    crypto: &mut DeviceCrypto<'_>,
    kind: CredentialKind,
    credential_kdf: CredentialKdf,
    credential_key: &[u8; 32],
    salt: &[u8; SALT_SIZE],
    slot: u8,
    out: &mut AlignedBytes<RECORD_SIZE>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) -> Result<(), PersistError> {
    let index = slot_index(slot)?;
    match credential_kdf {
        CredentialKdf::Argon2id(parameters) => {
            let mut envelope = AlignedBytes::<CURRENT_ENVELOPE_SIZE>::zeroed();
            read_raw_exact(index, &mut envelope.0, i2c, delay)?;
            let result = open_current(
                crypto,
                kind,
                parameters,
                credential_key,
                salt,
                index,
                &mut envelope,
                out,
            );
            zeroize_buf(&mut envelope.0);
            result
        }
        CredentialKdf::LegacyPbkdf2Sha256 => {
            let mut envelope = AlignedBytes::<LEGACY_ENVELOPE_SIZE>::zeroed();
            read_raw_exact(index, &mut envelope.0, i2c, delay)?;
            let result = open_legacy(
                crypto,
                kind,
                credential_key,
                salt,
                index,
                &mut envelope,
                out,
            );
            zeroize_buf(&mut envelope.0);
            result
        }
    }
}

pub(super) fn erase_files(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) -> Result<(), PersistError> {
    let result = sdcard::with_sd_card!(i2c, delay, |card| {
        let fat = sdcard::mount_fat32(card)?;
        let mut failed = false;
        for name in SLOT_FILES {
            match sdcard::delete_file(card, &fat, &name) {
                Ok(()) | Err("File not found") => {}
                Err(_) => failed = true,
            }
        }
        if failed {
            Err("SD wallet erase failed")
        } else {
            Ok(())
        }
    });
    result.map_err(|_| PersistError::SdStorageWrite)
}

fn read_raw_exact(
    index: usize,
    envelope: &mut [u8],
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) -> Result<(), PersistError> {
    let result = sdcard::with_sd_card!(i2c, delay, |card| {
        let fat = sdcard::mount_fat32(card)?;
        let (entry, _, _) = sdcard::find_file_in_root(card, &fat, &SLOT_FILES[index])?;
        if entry.file_size as usize != envelope.len() {
            return Err("SD persistence size mismatch");
        }
        let count = sdcard::read_file(card, &fat, &entry, envelope)?;
        if count != envelope.len() {
            return Err("SD persistence truncated");
        }
        Ok(())
    });
    result.map_err(|_| PersistError::SdStorageUnavailable)
}

fn seal_current(
    crypto: &mut DeviceCrypto<'_>,
    kind: CredentialKind,
    credential_key: &[u8; 32],
    salt: &[u8; SALT_SIZE],
    index: usize,
    record: &AlignedBytes<RECORD_SIZE>,
    envelope: &mut AlignedBytes<CURRENT_ENVELOPE_SIZE>,
) -> Result<(), PersistError> {
    envelope.0.fill(0);
    envelope.0[..4].copy_from_slice(&CURRENT_MAGIC);
    let metadata = password_kdf::encode_metadata(password_kdf::PasswordKdfParams::current())
        .map_err(|_| PersistError::Crypto)?;
    envelope.0[4..16].copy_from_slice(&metadata);
    envelope.0[16..32].copy_from_slice(salt);
    crate::services::entropy::fill(&mut envelope.0[32..44])
        .map_err(|_| PersistError::Entropy)?;
    envelope.0[CURRENT_HEADER_SIZE..].copy_from_slice(&record.0);

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&envelope.0[32..44]);
    let aad = aad_digest(index, &envelope.0[..44]);
    let mut tag = crypto.seal_sd(
        kind,
        credential_key,
        salt,
        &nonce,
        &aad,
        &mut envelope.0[CURRENT_HEADER_SIZE..],
    )?;
    envelope.0[44..60].copy_from_slice(&tag);
    zeroize_buf(&mut nonce);
    zeroize_buf(&mut tag);
    Ok(())
}

fn open_current(
    crypto: &mut DeviceCrypto<'_>,
    kind: CredentialKind,
    parameters: password_kdf::PasswordKdfParams,
    credential_key: &[u8; 32],
    expected_salt: &[u8; SALT_SIZE],
    index: usize,
    envelope: &mut AlignedBytes<CURRENT_ENVELOPE_SIZE>,
    out: &mut AlignedBytes<RECORD_SIZE>,
) -> Result<(), PersistError> {
    if envelope.0[..4] != CURRENT_MAGIC {
        return Err(PersistError::SdStorageCorrupt);
    }
    let parsed = password_kdf::parse_metadata(&envelope.0[4..16])
        .map_err(|_| PersistError::SdStorageCorrupt)?;
    if parsed != parameters || &envelope.0[16..32] != expected_salt {
        return Err(PersistError::SdStorageCorrupt);
    }

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&envelope.0[32..44]);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&envelope.0[44..60]);
    let aad = aad_digest(index, &envelope.0[..44]);
    let result = crypto.open_sd(
        kind,
        credential_key,
        expected_salt,
        &nonce,
        &aad,
        &mut envelope.0[CURRENT_HEADER_SIZE..],
        &tag,
    );
    zeroize_buf(&mut nonce);
    zeroize_buf(&mut tag);
    if result.is_err() {
        out.0.fill(0);
        return Err(PersistError::SdStorageCorrupt);
    }
    out.0.copy_from_slice(&envelope.0[CURRENT_HEADER_SIZE..]);
    Ok(())
}

fn open_legacy(
    crypto: &mut DeviceCrypto<'_>,
    kind: CredentialKind,
    credential_key: &[u8; 32],
    salt: &[u8; SALT_SIZE],
    index: usize,
    envelope: &mut AlignedBytes<LEGACY_ENVELOPE_SIZE>,
    out: &mut AlignedBytes<RECORD_SIZE>,
) -> Result<(), PersistError> {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&envelope.0[..NONCE_SIZE]);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&envelope.0[NONCE_SIZE..LEGACY_HEADER_SIZE]);
    let aad = match index {
        0 => b"KasSigner device-bound SD wallet slot A v3".as_slice(),
        _ => b"KasSigner device-bound SD wallet slot B v3".as_slice(),
    };
    let result = crypto.open_sd(
        kind,
        credential_key,
        salt,
        &nonce,
        aad,
        &mut envelope.0[LEGACY_HEADER_SIZE..],
        &tag,
    );
    zeroize_buf(&mut nonce);
    zeroize_buf(&mut tag);
    if result.is_err() {
        out.0.fill(0);
        return Err(PersistError::SdStorageCorrupt);
    }
    out.0.copy_from_slice(&envelope.0[LEGACY_HEADER_SIZE..]);
    Ok(())
}

fn aad_digest(index: usize, header: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_AAD[index]);
    hasher.update((header.len() as u32).to_le_bytes());
    hasher.update(header);
    hasher.finalize().into()
}

fn slot_index(slot: u8) -> Result<usize, PersistError> {
    if slot <= 1 {
        Ok(usize::from(slot))
    } else {
        Err(PersistError::SdStorageCorrupt)
    }
}
