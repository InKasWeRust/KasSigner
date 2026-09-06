//! Versioned encrypted SD/transport envelope.
//!
//! KAS\x04 uses the reviewed KasSigner Argon2id v19 password KDF and authenticates
//! the KDF identifier/parameters, salt, nonce and payload length as AES-GCM AAD.
//! KAS\x03 is a restore-only PBKDF2 compatibility reader. There is no KDF probing
//! or fallback: the magic selects exactly one parser/KDF.

use super::super::super::{AppData, display};
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
};
use offline_signer::crypto::{
    container_framing::{self, TransportEnvelopeHeader, TransportVersion},
    legacy_pbkdf2,
    password_kdf::{self, PasswordKdfPurpose, METADATA_SIZE, SALT_SIZE},
};
use shared_signer::bytes::zeroize_bytes;

pub(super) const CURRENT_MAGIC: &[u8; 4] = &container_framing::TRANSPORT_CURRENT_MAGIC;
#[cfg(test)]
pub(super) const LEGACY_MAGIC: &[u8; 4] = &container_framing::TRANSPORT_LEGACY_MAGIC;
const NONCE_LEN: usize = container_framing::TRANSPORT_NONCE_SIZE;
const TAG_LEN: usize = container_framing::TRANSPORT_TAG_SIZE;
const CURRENT_HEADER_LEN: usize = container_framing::TRANSPORT_CURRENT_HEADER_SIZE;
#[cfg(test)]
const CURRENT_CIPHERTEXT_START: usize = container_framing::TRANSPORT_CURRENT_CIPHERTEXT_START;
#[cfg(test)]
const LEGACY_CIPHERTEXT_START: usize = container_framing::TRANSPORT_LEGACY_CIPHERTEXT_START;
const CURRENT_MAX_DATA_LEN: usize = container_framing::TRANSPORT_CURRENT_MAX_DATA_LEN;
const LEGACY_ITERATIONS: u32 = 100_000;
const LEGACY_SALT: &[u8] = b"KasSigner-KSPT-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DecryptError {
    InvalidEnvelope,
    Authentication,
}

pub(super) fn seal_envelope(
    data: &[u8],
    passphrase: &[u8],
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_LEN],
    output: &mut [u8],
) -> Result<usize, ()> {
    let required_len = CURRENT_HEADER_LEN.checked_add(data.len()).and_then(|n| n.checked_add(TAG_LEN)).ok_or(())?;
    if data.is_empty() || data.len() > CURRENT_MAX_DATA_LEN || output.len() < required_len || salt.iter().all(|b| *b == 0) || nonce.iter().all(|b| *b == 0) {
        return Err(());
    }
    output.fill(0);
    output[..4].copy_from_slice(CURRENT_MAGIC);
    output[4..6].copy_from_slice(&(data.len() as u16).to_le_bytes());
    let metadata = password_kdf::encode_metadata(password_kdf::PasswordKdfParams::current()).map_err(|_| ())?;
    output[6..6 + METADATA_SIZE].copy_from_slice(&metadata);
    let salt_start = 6 + METADATA_SIZE;
    let nonce_start = salt_start + SALT_SIZE;
    output[salt_start..nonce_start].copy_from_slice(salt);
    output[nonce_start..CURRENT_HEADER_LEN].copy_from_slice(nonce);
    let (header, body) = output.split_at_mut(CURRENT_HEADER_LEN);
    body[..data.len()].copy_from_slice(data);
    let mut key = crate::services::memory::password_kdf::derive_key_32(
        PasswordKdfPurpose::EncryptedTransport,
        passphrase,
        salt,
    )
    .map_err(|_| ())?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let tag = cipher
        .encrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            header,
            &mut body[..data.len()],
        )
        .map_err(|_| ())?;
    zeroize_bytes(&mut key);
    body[data.len()..data.len() + TAG_LEN].copy_from_slice(&tag);
    Ok(CURRENT_HEADER_LEN + data.len() + TAG_LEN)
}

pub(super) fn open_envelope(
    input: &[u8],
    file_len: usize,
    passphrase: &[u8],
    plaintext: &mut [u8],
) -> Result<usize, DecryptError> {
    let header = container_framing::parse_transport_header(input, file_len)
        .map_err(|_| DecryptError::InvalidEnvelope)?;
    if plaintext.len() < header.data_len {
        return Err(DecryptError::InvalidEnvelope);
    }
    match header.version {
        TransportVersion::Current => open_current(input, passphrase, plaintext, &header),
        TransportVersion::Legacy => open_legacy(input, passphrase, plaintext, &header),
    }
}

fn open_current(
    input: &[u8],
    passphrase: &[u8],
    plaintext: &mut [u8],
    header: &TransportEnvelopeHeader,
) -> Result<usize, DecryptError> {
    let parameters = header.parameters.ok_or(DecryptError::InvalidEnvelope)?;
    let mut salt = header.salt;
    let mut key = crate::services::memory::password_kdf::derive_key_32_with_params(
        PasswordKdfPurpose::EncryptedTransport, passphrase, &salt, parameters,
    ).map_err(|_| DecryptError::Authentication)?;
    plaintext[..header.data_len]
        .copy_from_slice(&input[header.ciphertext_start..header.tag_start]);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let result = cipher.decrypt_in_place_detached(
        GenericArray::from_slice(&header.nonce),
        &input[..header.header_len],
        &mut plaintext[..header.data_len],
        GenericArray::from_slice(&input[header.tag_start..header.tag_start + TAG_LEN]),
    );
    zeroize_bytes(&mut key);
    zeroize_bytes(&mut salt);
    if result.is_err() {
        plaintext[..header.data_len].fill(0);
        Err(DecryptError::Authentication)
    } else {
        Ok(header.data_len)
    }
}

fn open_legacy(
    input: &[u8],
    passphrase: &[u8],
    plaintext: &mut [u8],
    header: &TransportEnvelopeHeader,
) -> Result<usize, DecryptError> {
    let mut key = legacy_pbkdf2::derive_legacy_32(passphrase, LEGACY_SALT, LEGACY_ITERATIONS);
    plaintext[..header.data_len]
        .copy_from_slice(&input[header.ciphertext_start..header.tag_start]);
    let aad = [b'K', b'A', b'S', 0x03, input[4], input[5]];
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let result = cipher.decrypt_in_place_detached(
        GenericArray::from_slice(&header.nonce),
        &aad,
        &mut plaintext[..header.data_len],
        GenericArray::from_slice(&input[header.tag_start..header.tag_start + TAG_LEN]),
    );
    zeroize_bytes(&mut key);
    if result.is_err() {
        plaintext[..header.data_len].fill(0);
        Err(DecryptError::Authentication)
    } else {
        Ok(header.data_len)
    }
}

pub(super) fn decrypt_envelope(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    passphrase: &[u8],
    plaintext: &mut [u8],
) -> Result<usize, DecryptError> {
    boot_display.update_progress_bar(10);
    let result=open_envelope(&ad.qr.outgoing.buffer,ad.qr.outgoing.length,passphrase,plaintext);
    boot_display.update_progress_bar(80);
    let data_len=result?;
    ad.qr.outgoing.buffer[..data_len].copy_from_slice(&plaintext[..data_len]);
    ad.qr.outgoing.length=data_len; ad.qr.outgoing.frame=0; ad.qr.outgoing.frame_count=0; ad.qr.presentation.large=false;
    ad.signing.transaction.signatures_present=0; ad.signing.transaction.signatures_required=0;
    log!("[SD-KSPT] Decrypted {} bytes",data_len); Ok(data_len)
}


#[cfg(test)]
mod unit_tests;

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_seal_envelope(
    data: &[u8],
    passphrase: &[u8],
    output: &mut [u8],
) -> Result<usize, ()> {
    const SALT: [u8; SALT_SIZE] = [0x41; SALT_SIZE];
    const NONCE: [u8; NONCE_LEN] = [0x52; NONCE_LEN];
    seal_envelope(data, passphrase, &SALT, &NONCE, output)
}
