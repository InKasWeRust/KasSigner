//! Power-loss-safe preference and encrypted-wallet journal selection.

use crate::services::credential_policy::{CredentialKind, SALT_SIZE};
use crate::wallet::seed_manager::{MAX_SLOTS, WALLET_NAME_MAX, SeedManager};

use super::{
    StorageMode,
    crypto::{RECORD_SIZE, RecordHeader, parse_header},
    security_policy::DuressPolicy,
    kdf::CredentialKdf,
    flash::{self, AlignedBytes, DeviceFlash, FlashError},
};

const CONFIG_SIZE: usize = 2048;
const LEGACY_CONFIG_SIZE: usize = 128;
const CONFIG_MAGIC: [u8; 8] = *b"KSPREF01";
const CONFIG_VERSION: u8 = 8;
const V7_COMPAT_VERSION: u8 = 7;
const V6_COMPAT_VERSION: u8 = 6;
const LEGACY_CONFIG_VERSION: u8 = 3;
const V471_V475_COMPAT_VERSION: u8 = 4;
const V5_COMPAT_VERSION: u8 = 5;
const DEVICE_FLAGS_OFFSET: usize = 39;
const DEVICE_PREFERENCES_OFFSET: usize = 88;
const DIM_TIMEOUT_OFFSET: usize = 89;
const V6_CONFIG_DIGEST_START: usize = 90;
const V6_CONFIG_DIGEST_END: usize = 122;
const LEGACY_CONFIG_DIGEST_START: usize = 88;
const LEGACY_CONFIG_DIGEST_END: usize = 120;
const WALLET_LABELS_OFFSET: usize = 96;
const WALLET_LABEL_RECORD_SIZE: usize = 1 + WALLET_NAME_MAX;
const WALLET_LABELS_END: usize = WALLET_LABELS_OFFSET + MAX_SLOTS * WALLET_LABEL_RECORD_SIZE;
const V7_CONFIG_DIGEST_START: usize = 448;
const V7_CONFIG_DIGEST_END: usize = 480;
const WALLET_ACTIVATION_OFFSET: usize = 448;
const WALLET_ACTIVATION_RECORD_SIZE: usize = 1 + SALT_SIZE + 32;
const WALLET_ACTIVATION_END: usize = WALLET_ACTIVATION_OFFSET + MAX_SLOTS * WALLET_ACTIVATION_RECORD_SIZE;
const CONFIG_DIGEST_START: usize = 1984;
const CONFIG_DIGEST_END: usize = 2016;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SdAnchor {
    pub credential_kind: CredentialKind,
    pub salt: [u8; SALT_SIZE],
    pub active_slot: u8,
    pub wallet_sequence: u32,
    pub duress: DuressPolicy,
    pub credential_kdf: CredentialKdf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConfigHeader {
    mode: Option<StorageMode>,
    sequence: u32,
    sd_anchor: Option<SdAnchor>,
    device_flags: DeviceFlags,
    device_preferences: DevicePreferences,
    wallet_labels: WalletLabels,
    wallet_activation: WalletActivationRecords,
}

/// Integrity-protected, non-secret labels keyed by physical wallet slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WalletLabels {
    lengths: [u8; MAX_SLOTS],
    names: [[u8; WALLET_NAME_MAX]; MAX_SLOTS],
}

impl WalletLabels {
    pub const fn empty() -> Self {
        Self { lengths: [0; MAX_SLOTS], names: [[0; WALLET_NAME_MAX]; MAX_SLOTS] }
    }

    pub fn from_manager(manager: &SeedManager) -> Self {
        let mut labels = Self::empty();
        for (index, slot) in manager.slots.iter().enumerate() {
            if slot.is_empty() || slot.transient { continue; }
            let len = usize::from(slot.name_len).min(WALLET_NAME_MAX);
            labels.lengths[index] = len as u8;
            labels.names[index][..len].copy_from_slice(&slot.name[..len]);
        }
        labels
    }

    pub fn apply(self, manager: &mut SeedManager) {
        for index in 0..MAX_SLOTS {
            let len = usize::from(self.lengths[index]).min(WALLET_NAME_MAX);
            let _ = manager.restore_slot_name(index, &self.names[index][..len]);
        }
    }
}

impl Default for WalletLabels {
    fn default() -> Self { Self::empty() }
}

/// Non-secret per-wallet activation KDF metadata. The protection kind itself is
/// authenticated inside the encrypted wallet slot header; these records cannot
/// downgrade a protected slot because a missing/tampered verifier fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WalletActivationRecord {
    pub salt: [u8; SALT_SIZE],
    pub verifier: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WalletActivationRecords {
    present: [bool; MAX_SLOTS],
    records: [WalletActivationRecord; MAX_SLOTS],
}

impl WalletActivationRecords {
    pub const fn empty() -> Self {
        Self {
            present: [false; MAX_SLOTS],
            records: [WalletActivationRecord { salt: [0; SALT_SIZE], verifier: [0; 32] }; MAX_SLOTS],
        }
    }
    pub fn get(&self, slot: usize) -> Option<WalletActivationRecord> {
        (slot < MAX_SLOTS && self.present[slot]).then_some(self.records[slot])
    }
    pub fn set(&mut self, slot: usize, record: WalletActivationRecord) -> bool {
        if slot >= MAX_SLOTS { return false; }
        self.present[slot] = true;
        self.records[slot] = record;
        true
    }
    pub fn clear(&mut self, slot: usize) {
        if slot >= MAX_SLOTS { return; }
        self.present[slot] = false;
        self.records[slot] = WalletActivationRecord { salt: [0; SALT_SIZE], verifier: [0; 32] };
    }
}

impl Default for WalletActivationRecords {
    fn default() -> Self { Self::empty() }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct DeviceFlags(u8);

impl DeviceFlags {
    // Bits 0-1 are reserved for compatibility with historical device-config
    // records. Current firmware does not interpret them as active features.
    const LEGACY_RESERVED_BIT_0: u8 = 1 << 0;
    const LEGACY_RESERVED_BIT_1: u8 = 1 << 1;
    const AUDIO_MUTED: u8 = 1 << 2;
    #[cfg(all(feature = "m5stack", not(feature = "production")))]
    const LEGACY_DEV_POP_IT_TAG_MASK: u8 = 0b1111_1000;
    const BASE_KNOWN_MASK: u8 =
        Self::LEGACY_RESERVED_BIT_0 | Self::LEGACY_RESERVED_BIT_1 | Self::AUDIO_MUTED;
    #[cfg(all(feature = "m5stack", not(feature = "production")))]
    const KNOWN_MASK: u8 = Self::BASE_KNOWN_MASK | Self::LEGACY_DEV_POP_IT_TAG_MASK;
    #[cfg(not(all(feature = "m5stack", not(feature = "production"))))]
    const KNOWN_MASK: u8 = Self::BASE_KNOWN_MASK;

    #[cfg(feature = "m5stack")]
    pub const fn audio_muted(self) -> bool {
        self.0 & Self::AUDIO_MUTED != 0
    }

    #[cfg(feature = "m5stack")]
    pub fn with_audio_muted(mut self, enabled: bool) -> Self {
        set_flag(&mut self.0, Self::AUDIO_MUTED, enabled);
        self
    }

}
mod preferences;
pub(super) use preferences::DevicePreferences;
mod config;
use config::write_config;
pub(in crate::services::persistent_wallet) use config::{
    read_device_flags, read_device_preferences, read_mode, read_sd_anchor,
    read_wallet_activation, read_wallet_labels, write_device_preferences,
    write_mode, write_sd_anchor, write_wallet_activation, write_wallet_labels,
};
#[cfg(feature = "m5stack")]
pub(in crate::services::persistent_wallet) use config::write_device_flags;

fn set_flag(value: &mut u8, mask: u8, enabled: bool) {
    if enabled { *value |= mask; } else { *value &= !mask; }
}

pub(super) fn read_wallet(
    device: &mut DeviceFlash<'_>,
    address: u32,
    record: &mut AlignedBytes<RECORD_SIZE>,
) -> Result<Option<RecordHeader>, FlashError> {
    device.read(address, record)?;
    Ok(parse_header(record))
}

#[inline(never)]
pub(super) fn newest_wallet_headers(
    device: &mut DeviceFlash<'_>,
) -> Result<(Option<RecordHeader>, Option<RecordHeader>), FlashError> {
    let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
    let a = read_wallet(device, flash::WALLET_A, &mut record)?;
    let b = read_wallet(device, flash::WALLET_B, &mut record)?;
    Ok((a, b))
}

pub(super) fn latest_wallet_header(
    device: &mut DeviceFlash<'_>,
) -> Result<Option<RecordHeader>, FlashError> {
    let (a, b) = newest_wallet_headers(device)?;
    Ok(newest_wallet(a, b).map(|(_, header)| header))
}

pub(super) fn next_wallet_target(
    device: &mut DeviceFlash<'_>,
) -> Result<(u32, u32), FlashError> {
    let (a, b) = newest_wallet_headers(device)?;
    let newest = newest_wallet(a, b);
    let sequence = newest.map_or(1, |(_, header)| header.sequence.wrapping_add(1));
    match newest {
        None => Ok((flash::WALLET_A, sequence)),
        Some((address, _)) if address == flash::WALLET_A => Ok((flash::WALLET_B, sequence)),
        Some(_) => Ok((flash::WALLET_A, sequence)),
    }
}

pub(super) fn wallet_order(device: &mut DeviceFlash<'_>) -> Result<[Option<u32>; 2], FlashError> {
    let (a, b) = newest_wallet_headers(device)?;
    Ok(match (a, b) {
        (None, None) => [None, None],
        (Some(_), None) => [Some(flash::WALLET_A), None],
        (None, Some(_)) => [Some(flash::WALLET_B), None],
        (Some(left), Some(right)) if is_newer(left.sequence, right.sequence) => {
            [Some(flash::WALLET_A), Some(flash::WALLET_B)]
        }
        (Some(_), Some(_)) => [Some(flash::WALLET_B), Some(flash::WALLET_A)],
    })
}

pub(super) fn erase_wallet(device: &mut DeviceFlash<'_>) -> Result<(), FlashError> {
    erase_wallet_sector_if_used(device, flash::WALLET_A)?;
    erase_wallet_sector_if_used(device, flash::WALLET_B)
}

/// Remove stale user-credential outer envelopes only after a newer device-only
/// device-only record has been committed. This preserves power-fail safety
/// during migration while ensuring the obsolete global-password ciphertext is not
/// retained as a second recoverable copy.
pub(super) fn erase_non_device_only_wallet_records(
    device: &mut DeviceFlash<'_>,
) -> Result<(), FlashError> {
    for address in [flash::WALLET_A, flash::WALLET_B] {
        let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
        let header = read_wallet(device, address, &mut record)?;
        let stale = header.is_some_and(|value| !value.device_only);
        offline_signer::derivation::hmac::zeroize_buf(&mut record.0);
        if stale { device.erase_sector(address)?; }
    }
    Ok(())
}

/// Erase all user-persistent state owned by the signer firmware. This intentionally
/// preserves the firmware image and one-time eFuse hardware material.
pub(super) fn erase_all_user_data(device: &mut DeviceFlash<'_>) -> Result<(), FlashError> {
    let device_flags = read_device_flags(device)?;
    let mut first_error = None;
    for address in [flash::CONFIG_A, flash::CONFIG_B, flash::WALLET_A, flash::WALLET_B] {
        if let Err(error) = erase_wallet_sector_if_used(device, address) {
            if first_error.is_none() { first_error = Some(error); }
        }
    }
    if let Some(error) = first_error { return Err(error); }
    if device_flags.0 != 0 {
        write_config(device, None, None, device_flags, DevicePreferences::default(), WalletLabels::default(), WalletActivationRecords::default())?;
    }
    Ok(())
}

#[inline(never)]
fn erase_wallet_sector_if_used(device: &mut DeviceFlash<'_>, address: u32) -> Result<(), FlashError> {
    let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
    device.read(address, &mut record)?;
    if record.0.iter().any(|byte| *byte != 0xFF) {
        device.erase_sector(address)?;
    }
    Ok(())
}

fn newest_wallet(a: Option<RecordHeader>, b: Option<RecordHeader>) -> Option<(u32, RecordHeader)> {
    match (a, b) {
        (Some(left), Some(right)) if is_newer(left.sequence, right.sequence) => Some((flash::WALLET_A, left)),
        (Some(_), Some(right)) => Some((flash::WALLET_B, right)),
        (Some(left), None) => Some((flash::WALLET_A, left)),
        (None, Some(right)) => Some((flash::WALLET_B, right)),
        (None, None) => None,
    }
}

const fn is_newer(left: u32, right: u32) -> bool {
    left != right && left.wrapping_sub(right) < 0x8000_0000
}
