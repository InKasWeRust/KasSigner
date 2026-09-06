//! ESP32-S3 device-bound authenticated encryption for persisted wallet state.
//!
//! Current credentials are stretched by the shared Argon2id password-KDF policy, then mixed
//! through a read-protected eFuse HMAC_UP key. Only the HMAC result is exposed
//! to software; the raw 256-bit eFuse secret is never readable through this API.

use esp_hal::{
    efuse::{Efuse, RD_DIS},
    hmac::{Hmac, HmacPurpose, KeyId},
    peripherals::HMAC,
};
use offline_signer::{
    crypto::{
        device_bound_storage::{
            self as bound, DeviceBoundError, HardwareHmac, KdfParameters, StoragePurpose,
        },
    },
    derivation::hmac::zeroize_buf,
};
use crate::services::credential_policy::{CredentialKind, SALT_SIZE};

use super::{PersistError, codec::PAYLOAD_SIZE, flash::AlignedBytes, kdf::CredentialKdf};

#[cfg(all(feature = "m5stack", not(feature = "production")))]
mod dev_storage;
mod record;

pub(super) const RECORD_SIZE: usize = 4096;
pub(super) const POLICY_START: usize = 2048;
const CURRENT_AAD_SIZE: usize = 60;
const LEGACY_AAD_SIZE: usize = 48;
const TAG_SIZE: usize = bound::TAG_SIZE;
const CURRENT_CIPHERTEXT_START: usize = CURRENT_AAD_SIZE + TAG_SIZE;
const LEGACY_CIPHERTEXT_START: usize = LEGACY_AAD_SIZE + TAG_SIZE;
const CURRENT_MAGIC: [u8; 8] = *b"KSWLT004";
const LEGACY_MAGIC: [u8; 8] = *b"KSWLT003";
const CURRENT_FORMAT_VERSION: u8 = 4;
const LEGACY_FORMAT_VERSION: u8 = bound::FORMAT_VERSION;
const DEVICE_KDF_ID: u8 = bound::KDF_ID_DEVICE_HMAC_SHA256;
const POLICY_MAC_DOMAIN: &[u8] = b"KasSigner immutable advanced policy v1";
const DURESS_MAC_DOMAIN: &[u8] = b"KasSigner duress credential verifier v1";
const WALLET_ACTIVATION_MAC_DOMAIN: &[u8] = b"KasSigner wallet activation verifier v1";
const PERSISTENT_KEY_SLOTS: [u8; 3] = [3, 4, 5];
const HMAC_BUSY_RETRY_LIMIT: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RecordHeader {
    pub sequence: u32,
    pub key_slot: u8,
    pub credential_kind: CredentialKind,
    /// Authenticated header bit: true means no user PIN/password is required.
    pub device_only: bool,
    pub salt: [u8; SALT_SIZE],
    pub policy_required: bool,
    pub credential_kdf: CredentialKdf,
    nonce: [u8; bound::NONCE_SIZE],
    aad_size: usize,
    ciphertext_start: usize,
}

pub(super) struct DeviceCrypto<'d> {
    hmac: Hmac<'d>,
}

struct SlotHmac<'a, 'd> {
    crypto: &'a mut DeviceCrypto<'d>,
    key_slot: u8,
}

impl HardwareHmac for SlotHmac<'_, '_> {
    fn hmac_sha256(
        &mut self,
        message: &[u8],
        output: &mut [u8; 32],
    ) -> Result<(), DeviceBoundError> {
        self.crypto
            .hmac_sha256(self.key_slot, message, output)
            .map_err(|_| DeviceBoundError::HardwareHmacUnavailable)
    }
}

impl<'d> DeviceCrypto<'d> {
    pub fn new(peripheral: HMAC<'d>) -> Self {
        Self { hmac: Hmac::new(peripheral) }
    }

    pub fn available_key_slot(&mut self) -> Option<u8> {
        if let Some(slot) = PERSISTENT_KEY_SLOTS
            .into_iter()
            .find(|slot| self.configure(*slot).is_ok())
        {
            return Some(slot);
        }
        #[cfg(all(feature = "m5stack", not(feature = "production")))]
        {
            crate::log!("   [DEV] using software TEST device-storage identity");
            return Some(dev_storage::KEY_SLOT);
        }
        #[cfg(not(all(feature = "m5stack", not(feature = "production"))))]
        None
    }

    pub fn seal(
        &mut self,
        plaintext: &[u8; PAYLOAD_SIZE],
        sequence: u32,
        key_slot: u8,
        credential_kind: CredentialKind,
        device_only: bool,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        record: &mut AlignedBytes<RECORD_SIZE>,
    ) -> Result<(), PersistError> {
        record::prepare_header(record, sequence, key_slot, credential_kind, device_only, salt)?;
        let mut nonce = [0u8; bound::NONCE_SIZE];
        nonce.copy_from_slice(&record.0[31..43]);
        let mut aad = [0u8; CURRENT_AAD_SIZE];
        aad.copy_from_slice(&record.0[..CURRENT_AAD_SIZE]);
        let ciphertext = &mut record.0[CURRENT_CIPHERTEXT_START..CURRENT_CIPHERTEXT_START + PAYLOAD_SIZE];
        ciphertext.copy_from_slice(plaintext);
        let mut provider = SlotHmac { crypto: self, key_slot };
        let mut tag = bound::seal_in_place(
            &mut provider,
            KdfParameters::current(StoragePurpose::InternalWallet, credential_kind),
            credential_key,
            salt,
            &nonce,
            &aad,
            ciphertext,
        )
        .map_err(map_bound_error)?;
        record.0[CURRENT_AAD_SIZE..CURRENT_CIPHERTEXT_START].copy_from_slice(&tag);
        zeroize_buf(&mut nonce);
        zeroize_buf(&mut aad);
        zeroize_buf(&mut tag);
        Ok(())
    }

    pub fn open(
        &mut self,
        record: &AlignedBytes<RECORD_SIZE>,
        credential_key: &[u8; 32],
        plaintext: &mut [u8; PAYLOAD_SIZE],
    ) -> Result<RecordHeader, PersistError> {
        let header = parse_header(record).ok_or(PersistError::InvalidWallet)?;
        let body_end = header.ciphertext_start + PAYLOAD_SIZE;
        plaintext.copy_from_slice(&record.0[header.ciphertext_start..body_end]);
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&record.0[header.aad_size..header.ciphertext_start]);
        let result = {
            let mut provider = SlotHmac { crypto: self, key_slot: header.key_slot };
            bound::open_in_place(
                &mut provider,
                bound::OpenRequest {
                    parameters: KdfParameters::current(
                        StoragePurpose::InternalWallet,
                        header.credential_kind,
                    ),
                    stretched_credential: credential_key,
                    salt: &header.salt,
                    nonce: &header.nonce,
                    authenticated_header: &record.0[..header.aad_size],
                    tag: &tag,
                },
                plaintext,
            )
        };
        zeroize_buf(&mut tag);
        result.map_err(map_bound_error)?;
        Ok(header)
    }

    pub(super) fn seal_sd(
        &mut self,
        kind: CredentialKind,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        nonce: &[u8; bound::NONCE_SIZE],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<[u8; bound::TAG_SIZE], PersistError> {
        let key_slot = self.available_key_slot().ok_or(PersistError::DeviceKeyMissing)?;
        let mut provider = SlotHmac { crypto: self, key_slot };
        bound::seal_in_place(
            &mut provider,
            KdfParameters::current(StoragePurpose::SdWallet, kind),
            credential_key,
            salt,
            nonce,
            aad,
            ciphertext,
        )
        .map_err(map_bound_error)
    }

    pub(super) fn open_sd(
        &mut self,
        kind: CredentialKind,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        nonce: &[u8; bound::NONCE_SIZE],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; bound::TAG_SIZE],
    ) -> Result<(), PersistError> {
        let key_slot = self.available_key_slot().ok_or(PersistError::DeviceKeyMissing)?;
        let mut provider = SlotHmac { crypto: self, key_slot };
        bound::open_in_place(
            &mut provider,
            bound::OpenRequest {
                parameters: KdfParameters::current(StoragePurpose::SdWallet, kind),
                stretched_credential: credential_key,
                salt,
                nonce,
                authenticated_header: aad,
                tag,
            },
            ciphertext,
        )
        .map_err(map_bound_error)
    }

    pub(super) fn seal_backup(
        &mut self,
        purpose: StoragePurpose,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        nonce: &[u8; bound::NONCE_SIZE],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<[u8; bound::TAG_SIZE], PersistError> {
        if !matches!(purpose, StoragePurpose::SdSeedBackup | StoragePurpose::SdXprvBackup | StoragePurpose::StegoWallet) {
            return Err(PersistError::InvalidWallet);
        }
        let key_slot = self.available_key_slot().ok_or(PersistError::DeviceKeyMissing)?;
        let mut provider = SlotHmac { crypto: self, key_slot };
        bound::seal_in_place(
            &mut provider,
            KdfParameters::current(purpose, CredentialKind::Password),
            credential_key,
            salt,
            nonce,
            aad,
            ciphertext,
        )
        .map_err(map_bound_error)
    }

    pub(super) fn open_backup(
        &mut self,
        purpose: StoragePurpose,
        credential_key: &[u8; 32],
        salt: &[u8; SALT_SIZE],
        nonce: &[u8; bound::NONCE_SIZE],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; bound::TAG_SIZE],
    ) -> Result<(), PersistError> {
        if !matches!(purpose, StoragePurpose::SdSeedBackup | StoragePurpose::SdXprvBackup | StoragePurpose::StegoWallet) {
            return Err(PersistError::InvalidWallet);
        }
        let key_slot = self.available_key_slot().ok_or(PersistError::DeviceKeyMissing)?;
        let mut provider = SlotHmac { crypto: self, key_slot };
        bound::open_in_place(
            &mut provider,
            bound::OpenRequest {
                parameters: KdfParameters::current(purpose, CredentialKind::Password),
                stretched_credential: credential_key,
                salt,
                nonce,
                authenticated_header: aad,
                tag,
            },
            ciphertext,
        )
        .map_err(map_bound_error)
    }

    pub(super) fn policy_tag(
        &mut self,
        key_slot: u8,
        sequence: u32,
        encoded: &[u8],
    ) -> Result<[u8; 32], PersistError> {
        let sequence_bytes = sequence.to_le_bytes();
        #[cfg(all(feature = "m5stack", not(feature = "production")))]
        if key_slot == dev_storage::KEY_SLOT {
            return Ok(dev_storage::hmac(&[POLICY_MAC_DOMAIN, &sequence_bytes, encoded]));
        }
        self.configure(key_slot)?;
        self.update_all(POLICY_MAC_DOMAIN)?;
        self.update_all(&sequence_bytes)?;
        self.update_all(encoded)?;
        self.finalize_key()
    }

    pub(super) fn wallet_activation_verifier(
        &mut self,
        slot: u8,
        kind: CredentialKind,
        salt: &[u8; SALT_SIZE],
        stretched_key: &[u8; 32],
    ) -> Result<[u8; 32], PersistError> {
        let key_slot = self.available_key_slot().ok_or(PersistError::DeviceKeyMissing)?;
        let slot_byte = [slot];
        let kind_byte = [kind as u8];
        #[cfg(all(feature = "m5stack", not(feature = "production")))]
        if key_slot == dev_storage::KEY_SLOT {
            return Ok(dev_storage::hmac(&[
                WALLET_ACTIVATION_MAC_DOMAIN, &slot_byte, &kind_byte, salt, stretched_key,
            ]));
        }
        self.configure(key_slot)?;
        self.update_all(WALLET_ACTIVATION_MAC_DOMAIN)?;
        self.update_all(&slot_byte)?;
        self.update_all(&kind_byte)?;
        self.update_all(salt)?;
        self.update_all(stretched_key)?;
        self.finalize_key()
    }

    pub(super) fn duress_verifier(
        &mut self,
        key_slot: u8,
        kind: CredentialKind,
        salt: &[u8; SALT_SIZE],
        stretched_key: &[u8; 32],
    ) -> Result<[u8; 32], PersistError> {
        let kind_byte = [kind as u8];
        #[cfg(all(feature = "m5stack", not(feature = "production")))]
        if key_slot == dev_storage::KEY_SLOT {
            return Ok(dev_storage::hmac(&[DURESS_MAC_DOMAIN, &kind_byte, salt, stretched_key]));
        }
        self.configure(key_slot)?;
        self.update_all(DURESS_MAC_DOMAIN)?;
        self.update_all(&kind_byte)?;
        self.update_all(salt)?;
        self.update_all(stretched_key)?;
        self.finalize_key()
    }

    fn hmac_sha256(
        &mut self,
        key_slot: u8,
        message: &[u8],
        output: &mut [u8; 32],
    ) -> Result<(), PersistError> {
        #[cfg(all(feature = "m5stack", not(feature = "production")))]
        if key_slot == dev_storage::KEY_SLOT {
            *output = dev_storage::hmac(&[message]);
            return Ok(());
        }
        self.configure(key_slot)?;
        self.update_all(message)?;
        let result = self.finalize_into(output);
        if result.is_err() { zeroize_buf(output); }
        result
    }

    fn update_all(&mut self, mut remaining: &[u8]) -> Result<(), PersistError> {
        let mut retries = 0u32;
        while !remaining.is_empty() {
            match self.hmac.update(remaining) {
                Ok(next) => {
                    remaining = next;
                    retries = 0;
                }
                Err(_) => {
                    retries = retries.saturating_add(1);
                    if retries >= HMAC_BUSY_RETRY_LIMIT {
                        return Err(PersistError::DeviceKeyMissing);
                    }
                }
            }
        }
        Ok(())
    }

    fn finalize_key(&mut self) -> Result<[u8; 32], PersistError> {
        let mut key = [0u8; 32];
        self.finalize_into(&mut key)?;
        Ok(key)
    }

    fn finalize_into(&mut self, output: &mut [u8; 32]) -> Result<(), PersistError> {
        for _ in 0..HMAC_BUSY_RETRY_LIMIT {
            if self.hmac.finalize(output).is_ok() { return Ok(()); }
        }
        Err(PersistError::DeviceKeyMissing)
    }

    fn configure(&mut self, key_slot: u8) -> Result<(), PersistError> {
        let key_id = key_id(key_slot).ok_or(PersistError::DeviceKeyMissing)?;
        if !key_is_read_protected(key_slot) { return Err(PersistError::DeviceKeyMissing); }
        self.hmac.init();
        self.hmac
            .configure(HmacPurpose::ToUser, key_id)
            .map_err(|_| PersistError::DeviceKeyMissing)
    }
}

pub(super) fn parse_header(record: &AlignedBytes<RECORD_SIZE>) -> Option<RecordHeader> {
    record::parse_header(record)
}

fn map_bound_error(error: DeviceBoundError) -> PersistError {
    match error {
        DeviceBoundError::HardwareHmacUnavailable => PersistError::DeviceKeyMissing,
        DeviceBoundError::UnsupportedParameters => PersistError::InvalidWallet,
        DeviceBoundError::EntropyUnavailable => PersistError::Entropy,
        DeviceBoundError::EncryptionFailed => PersistError::Crypto,
        DeviceBoundError::AuthenticationFailed => PersistError::Authentication,
    }
}

pub(super) fn valid_key_slot(slot: u8) -> bool {
    if key_id(slot).is_some() { return true; }
    #[cfg(all(feature = "m5stack", not(feature = "production")))]
    {
        return slot == dev_storage::KEY_SLOT;
    }
    #[cfg(not(all(feature = "m5stack", not(feature = "production"))))]
    false
}

fn key_is_read_protected(slot: u8) -> bool {
    let disabled: u8 = Efuse::read_field_le(RD_DIS);
    disabled & (1u8 << slot) != 0
}

const fn key_id(slot: u8) -> Option<KeyId> {
    match slot {
        3 => Some(KeyId::Key3),
        4 => Some(KeyId::Key4),
        5 => Some(KeyId::Key5),
        _ => None,
    }
}
