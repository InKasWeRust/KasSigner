//! Versioned JPEG steganographic mnemonic payload.
//!
//! Portable v4 is self-contained cross-device recovery: JPEG + password. Its
//! Argon2id KDF ID/version/memory/time/parallelism, salt, nonce, security mode
//! and carrier are clear non-secret metadata authenticated by AES-GCM AAD.
//! Device-bound v2 instead derives a non-secret descriptor credential and mixes
//! it with the non-exportable device HMAC key; the original device is required.

use offline_signer::crypto::{
    device_bound_storage::{NONCE_SIZE, StoragePurpose, TAG_SIZE},
    password_kdf::{self, PasswordKdfParams, METADATA_SIZE, SALT_SIZE},
};
use sha2::{Digest, Sha256};
use shared_signer::bytes::zeroize_bytes;

use crate::services::{
    backup::BackupDevice,
    entropy,
};

use super::{portable, StegoCarrier, StegoSecurity};

mod helpers;
use helpers::{
    carrier_code, carrier_from_code, encode_plaintext, finish_decode, map_backup_error,
    map_portable_error, reset_outputs, security_from_code, validate_inputs,
};

const MAGIC: [u8; 4] = *b"KSJP";
const DEVICE_FORMAT_VERSION: u8 = 2;
const PORTABLE_FORMAT_VERSION: u8 = 4;
const SECURITY_DEVICE: u8 = 1;
const SECURITY_PORTABLE: u8 = 2;
const MAX_HINT_SIZE: usize = 64;
const WORD_SLOTS: usize = 24;
const WORD_BYTES: usize = WORD_SLOTS * 2;
const PLAINTEXT_SIZE: usize = 1 + 1 + WORD_BYTES + 1 + MAX_HINT_SIZE;
const HEADER_SIZE: usize = 48;
const CIPHERTEXT_OFFSET: usize = HEADER_SIZE;
const TAG_OFFSET: usize = CIPHERTEXT_OFFSET + PLAINTEXT_SIZE;
pub const PAYLOAD_SIZE: usize = TAG_OFFSET + TAG_SIZE;

const CREDENTIAL_DOMAIN: &[u8] = b"KasSigner/stego-descriptor-credential/v2";
const AAD_DOMAIN: &[u8] = b"KasSigner/stego-wallet/envelope-aad/v4";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    InvalidInput,
    InvalidLength,
    EntropyUnavailable,
    AuthenticationFailed,
    DeviceKeyUnavailable,
    EncryptionFailed,
    InvalidPassword,
    UnsupportedKdf,
}

impl PayloadError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidInput => "Invalid stego wallet data",
            Self::InvalidLength => "Invalid stego payload length",
            Self::EntropyUnavailable => "RNG health failed",
            Self::AuthenticationFailed => {
                "Wrong password/descriptor/device or damaged backup"
            }
            Self::DeviceKeyUnavailable => "Device backup key unavailable",
            Self::EncryptionFailed => "Stego encryption failed",
            Self::InvalidPassword => "Use 8+ chars with a letter and number",
            Self::UnsupportedKdf => "Unsupported backup KDF",
        }
    }
}

pub fn pack(
    security: StegoSecurity,
    carrier: StegoCarrier,
    indices: &[u16; WORD_SLOTS],
    word_count: u8,
    hint: &[u8],
    descriptor: &[u8],
    portable_password: &[u8],
    device: &mut dyn BackupDevice,
    output: &mut [u8],
) -> Result<usize, PayloadError> {
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    if entropy::fill(&mut salt).is_err() || entropy::fill(&mut nonce).is_err() {
        zeroize_bytes(&mut salt);
        zeroize_bytes(&mut nonce);
        output.fill(0);
        return Err(PayloadError::EntropyUnavailable);
    }

    let result = pack_with_material(
        security,
        carrier,
        indices,
        word_count,
        hint,
        descriptor,
        portable_password,
        device,
        &salt,
        &nonce,
        output,
    );
    zeroize_bytes(&mut salt);
    zeroize_bytes(&mut nonce);
    result
}

fn pack_with_material(
    security: StegoSecurity,
    carrier: StegoCarrier,
    indices: &[u16; WORD_SLOTS],
    word_count: u8,
    hint: &[u8],
    descriptor: &[u8],
    portable_password: &[u8],
    device: &mut dyn BackupDevice,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    output: &mut [u8],
) -> Result<usize, PayloadError> {
    output.fill(0);
    validate_inputs(indices, word_count, hint, descriptor)?;
    if output.len() < PAYLOAD_SIZE {
        return Err(PayloadError::InvalidLength);
    }
    if salt.iter().all(|byte| *byte == 0) || nonce.iter().all(|byte| *byte == 0) {
        return Err(PayloadError::EntropyUnavailable);
    }
    if security == StegoSecurity::Portable {
        portable::validate_password(portable_password).map_err(map_portable_error)?;
    }

    write_header(security, carrier, salt, nonce, &mut output[..HEADER_SIZE])?;
    let format = if security == StegoSecurity::Portable {
        PORTABLE_FORMAT_VERSION
    } else {
        DEVICE_FORMAT_VERSION
    };

    let mut plaintext = [0u8; PLAINTEXT_SIZE];
    encode_plaintext(format, indices, word_count, hint, &mut plaintext);
    output[CIPHERTEXT_OFFSET..TAG_OFFSET].copy_from_slice(&plaintext);
    let aad = build_aad(&output[..HEADER_SIZE], descriptor);

    let seal = match security {
        StegoSecurity::Portable => portable::seal(
            portable_password,
            salt,
            nonce,
            &aad,
            &mut output[CIPHERTEXT_OFFSET..TAG_OFFSET],
        )
        .map_err(map_portable_error),
        StegoSecurity::DeviceBound => {
            let mut key = descriptor_credential(descriptor);
            let result = device.seal_backup_key(
                StoragePurpose::StegoWallet,
                &key,
                salt,
                nonce,
                &aad,
                &mut output[CIPHERTEXT_OFFSET..TAG_OFFSET],
            );
            zeroize_bytes(&mut key);
            result.map_err(map_backup_error)
        }
    };

    zeroize_bytes(&mut plaintext);
    let mut tag = match seal {
        Ok(tag) => tag,
        Err(error) => {
            output.fill(0);
            return Err(error);
        }
    };
    output[TAG_OFFSET..PAYLOAD_SIZE].copy_from_slice(&tag);
    zeroize_bytes(&mut tag);
    Ok(PAYLOAD_SIZE)
}

pub fn unpack_device_bound(
    carrier: StegoCarrier,
    input: &[u8],
    descriptor: &[u8],
    device: &mut dyn BackupDevice,
    indices: &mut [u16; WORD_SLOTS],
    hint: &mut [u8; MAX_HINT_SIZE],
) -> Result<(u8, usize), PayloadError> {
    reset_outputs(indices, hint);
    let envelope = parse_envelope(
        input,
        descriptor,
        StegoSecurity::DeviceBound,
        carrier,
    )?;
    let mut plaintext = envelope.ciphertext;
    let mut key = descriptor_credential(descriptor);
    let result = device.open_backup_key(
        StoragePurpose::StegoWallet,
        &key,
        &envelope.salt,
        &envelope.nonce,
        &envelope.aad,
        &mut plaintext,
        &envelope.tag,
    );
    zeroize_bytes(&mut key);
    if result.is_err() {
        zeroize_bytes(&mut plaintext);
        return Err(PayloadError::AuthenticationFailed);
    }
    finish_decode(DEVICE_FORMAT_VERSION, &mut plaintext, indices, hint)
}

pub fn unpack_portable(
    carrier: StegoCarrier,
    input: &[u8],
    descriptor: &[u8],
    password: &[u8],
    indices: &mut [u16; WORD_SLOTS],
    hint: &mut [u8; MAX_HINT_SIZE],
) -> Result<(u8, usize), PayloadError> {
    reset_outputs(indices, hint);
    let envelope = parse_envelope(
        input,
        descriptor,
        StegoSecurity::Portable,
        carrier,
    )?;
    let parameters = password_kdf::parse_metadata(&envelope.metadata)
        .map_err(|_| PayloadError::UnsupportedKdf)?;
    let mut plaintext = envelope.ciphertext;
    portable::open(
        password,
        parameters,
        &envelope.salt,
        &envelope.nonce,
        &envelope.aad,
        &mut plaintext,
        &envelope.tag,
    )
    .map_err(map_portable_error)?;
    finish_decode(PORTABLE_FORMAT_VERSION, &mut plaintext, indices, hint)
}

struct Envelope {
    metadata: [u8; METADATA_SIZE],
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    ciphertext: [u8; PLAINTEXT_SIZE],
    tag: [u8; TAG_SIZE],
    aad: [u8; 80],
}

fn parse_envelope(
    input: &[u8],
    descriptor: &[u8],
    expected_security: StegoSecurity,
    expected_carrier: StegoCarrier,
) -> Result<Envelope, PayloadError> {
    validate_envelope_shape(input, descriptor)?;
    let security = validate_envelope_header(input, expected_security, expected_carrier)?;
    let metadata = parse_envelope_metadata(input, security)?;
    let (salt, nonce) = parse_envelope_material(input)?;

    let mut ciphertext = [0u8; PLAINTEXT_SIZE];
    ciphertext.copy_from_slice(&input[CIPHERTEXT_OFFSET..TAG_OFFSET]);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&input[TAG_OFFSET..PAYLOAD_SIZE]);
    let aad = build_aad(&input[..HEADER_SIZE], descriptor);
    Ok(Envelope {
        metadata,
        salt,
        nonce,
        ciphertext,
        tag,
        aad,
    })
}

fn validate_envelope_shape(input: &[u8], descriptor: &[u8]) -> Result<(), PayloadError> {
    if input.len() != PAYLOAD_SIZE || descriptor.is_empty() || descriptor.len() > 96 {
        Err(PayloadError::InvalidLength)
    } else {
        Ok(())
    }
}

fn validate_envelope_header(
    input: &[u8],
    expected_security: StegoSecurity,
    expected_carrier: StegoCarrier,
) -> Result<StegoSecurity, PayloadError> {
    if input[..4] != MAGIC {
        return Err(PayloadError::InvalidInput);
    }
    let carrier = carrier_from_code(input[5])?;
    let security = security_from_code(input[6])?;
    if input[7] != 0 || carrier != expected_carrier || security != expected_security {
        return Err(PayloadError::InvalidInput);
    }
    let expected_version = if security == StegoSecurity::Portable {
        PORTABLE_FORMAT_VERSION
    } else {
        DEVICE_FORMAT_VERSION
    };
    if input[4] != expected_version {
        return Err(PayloadError::InvalidInput);
    }
    Ok(security)
}

fn parse_envelope_metadata(
    input: &[u8],
    security: StegoSecurity,
) -> Result<[u8; METADATA_SIZE], PayloadError> {
    let mut metadata = [0u8; METADATA_SIZE];
    metadata.copy_from_slice(&input[8..20]);
    match security {
        StegoSecurity::Portable => {
            password_kdf::parse_metadata(&metadata)
                .map_err(|_| PayloadError::UnsupportedKdf)?;
        }
        StegoSecurity::DeviceBound if metadata.iter().any(|byte| *byte != 0) => {
            return Err(PayloadError::InvalidInput);
        }
        StegoSecurity::DeviceBound => {}
    }
    Ok(metadata)
}

fn parse_envelope_material(
    input: &[u8],
) -> Result<([u8; SALT_SIZE], [u8; NONCE_SIZE]), PayloadError> {
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&input[20..36]);
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&input[36..48]);
    if salt.iter().all(|byte| *byte == 0) || nonce.iter().all(|byte| *byte == 0) {
        Err(PayloadError::InvalidInput)
    } else {
        Ok((salt, nonce))
    }
}

fn write_header(
    security: StegoSecurity,
    carrier: StegoCarrier,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    output: &mut [u8],
) -> Result<(), PayloadError> {
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4] = if security == StegoSecurity::Portable {
        PORTABLE_FORMAT_VERSION
    } else {
        DEVICE_FORMAT_VERSION
    };
    output[5] = carrier_code(carrier);
    output[6] = if security == StegoSecurity::Portable {
        SECURITY_PORTABLE
    } else {
        SECURITY_DEVICE
    };
    if security == StegoSecurity::Portable {
        let metadata = password_kdf::encode_metadata(PasswordKdfParams::current())
            .map_err(|_| PayloadError::UnsupportedKdf)?;
        output[8..20].copy_from_slice(&metadata);
    }
    output[20..36].copy_from_slice(salt);
    output[36..48].copy_from_slice(nonce);
    Ok(())
}

fn build_aad(header: &[u8], descriptor: &[u8]) -> [u8; 80] {
    let mut digest = Sha256::new();
    digest.update(AAD_DOMAIN);
    digest.update((descriptor.len() as u16).to_le_bytes());
    digest.update(descriptor);
    let binding: [u8; 32] = digest.finalize().into();

    let mut aad = [0u8; 80];
    aad[..48].copy_from_slice(header);
    aad[48..].copy_from_slice(&binding);
    aad
}

fn descriptor_credential(descriptor: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(CREDENTIAL_DOMAIN);
    digest.update((descriptor.len() as u16).to_le_bytes());
    digest.update(descriptor);
    digest.finalize().into()
}

#[cfg(any(test, feature = "workflow-test-auto"))]
pub(crate) fn pack_for_test(
    security: StegoSecurity,
    carrier: StegoCarrier,
    indices: &[u16; WORD_SLOTS],
    word_count: u8,
    hint: &[u8],
    descriptor: &[u8],
    portable_password: &[u8],
    device: &mut dyn BackupDevice,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    output: &mut [u8],
) -> Result<usize, PayloadError> {
    pack_with_material(
        security,
        carrier,
        indices,
        word_count,
        hint,
        descriptor,
        portable_password,
        device,
        salt,
        nonce,
        output,
    )
}
