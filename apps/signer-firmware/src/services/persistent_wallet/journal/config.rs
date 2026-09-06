//! Integrity-protected configuration journal codec and selection.

use sha2::{Digest, Sha256};
use crate::services::credential_policy::SALT_SIZE;
use crate::wallet::seed_manager::{MAX_SLOTS, WALLET_NAME_MAX};
use super::{
    AlignedBytes, CONFIG_DIGEST_END, CONFIG_DIGEST_START, CONFIG_MAGIC, CONFIG_SIZE, CONFIG_VERSION, ConfigHeader,
    CredentialKdf, CredentialKind, DEVICE_FLAGS_OFFSET, DEVICE_PREFERENCES_OFFSET, DIM_TIMEOUT_OFFSET, DeviceFlags, DevicePreferences,
    DeviceFlash, DuressPolicy, FlashError, LEGACY_CONFIG_DIGEST_END, LEGACY_CONFIG_DIGEST_START, LEGACY_CONFIG_SIZE,
    LEGACY_CONFIG_VERSION, SdAnchor, StorageMode, V471_V475_COMPAT_VERSION, V5_COMPAT_VERSION,
    V6_COMPAT_VERSION, V6_CONFIG_DIGEST_END, V6_CONFIG_DIGEST_START, V7_COMPAT_VERSION,
    V7_CONFIG_DIGEST_END, V7_CONFIG_DIGEST_START, WALLET_ACTIVATION_END, WALLET_ACTIVATION_OFFSET,
    WALLET_ACTIVATION_RECORD_SIZE, WALLET_LABELS_END, WALLET_LABELS_OFFSET, WALLET_LABEL_RECORD_SIZE,
    WalletActivationRecord, WalletActivationRecords, WalletLabels, flash, is_newer,
};

pub(in crate::services::persistent_wallet) fn read_mode(device: &mut DeviceFlash<'_>) -> Result<Option<StorageMode>, FlashError> {
    let a = read_config(device, flash::CONFIG_A)?;
    let b = read_config(device, flash::CONFIG_B)?;
    Ok(newest_config(a, b).and_then(|header| header.mode))
}

pub(in crate::services::persistent_wallet) fn read_sd_anchor(device: &mut DeviceFlash<'_>) -> Result<Option<SdAnchor>, FlashError> {
    let a = read_config(device, flash::CONFIG_A)?;
    let b = read_config(device, flash::CONFIG_B)?;
    Ok(newest_config(a, b).and_then(|header| {
        if header.mode == Some(StorageMode::SdCard) { header.sd_anchor } else { None }
    }))
}

pub(in crate::services::persistent_wallet) fn write_mode(device: &mut DeviceFlash<'_>, mode: StorageMode) -> Result<(), FlashError> {
    let current = current_config(device)?;
    write_config(
        device,
        Some(mode),
        None,
        current.map(|header| header.device_flags).unwrap_or_default(),
        current.map(|header| header.device_preferences).unwrap_or_default(),
        current.map(|header| header.wallet_labels).unwrap_or_default(),
        current.map(|header| header.wallet_activation).unwrap_or_default(),
    )
}

pub(in crate::services::persistent_wallet) fn read_device_flags(device: &mut DeviceFlash<'_>) -> Result<DeviceFlags, FlashError> {
    Ok(current_config(device)?.map(|header| header.device_flags).unwrap_or_default())
}

pub(in crate::services::persistent_wallet) fn read_device_preferences(
    device: &mut DeviceFlash<'_>,
) -> Result<DevicePreferences, FlashError> {
    Ok(current_config(device)?
        .map(|header| header.device_preferences)
        .unwrap_or_default())
}


pub(in crate::services::persistent_wallet) fn read_wallet_labels(device: &mut DeviceFlash<'_>) -> Result<WalletLabels, FlashError> {
    Ok(current_config(device)?.map(|header| header.wallet_labels).unwrap_or_default())
}

pub(in crate::services::persistent_wallet) fn read_wallet_activation(device: &mut DeviceFlash<'_>) -> Result<WalletActivationRecords, FlashError> {
    Ok(current_config(device)?.map(|header| header.wallet_activation).unwrap_or_default())
}

pub(in crate::services::persistent_wallet) fn write_wallet_activation(
    device: &mut DeviceFlash<'_>,
    records: WalletActivationRecords,
) -> Result<(), FlashError> {
    let current = current_config(device)?;
    write_config(
        device,
        current.and_then(|header| header.mode),
        current.and_then(|header| header.sd_anchor),
        current.map(|header| header.device_flags).unwrap_or_default(),
        current.map(|header| header.device_preferences).unwrap_or_default(),
        current.map(|header| header.wallet_labels).unwrap_or_default(),
        records,
    )
}

pub(in crate::services::persistent_wallet) fn write_wallet_labels(
    device: &mut DeviceFlash<'_>,
    labels: WalletLabels,
) -> Result<(), FlashError> {
    let current = current_config(device)?;
    let mode = current.and_then(|header| header.mode);
    let anchor = current.and_then(|header| header.sd_anchor);
    let flags = current.map(|header| header.device_flags).unwrap_or_default();
    let preferences = current.map(|header| header.device_preferences).unwrap_or_default();
    write_config(device, mode, anchor, flags, preferences, labels, current.map(|header| header.wallet_activation).unwrap_or_default())
}

#[cfg(feature = "m5stack")]
pub(in crate::services::persistent_wallet) fn write_device_flags(
    device: &mut DeviceFlash<'_>,
    flags: DeviceFlags,
) -> Result<(), FlashError> {
    let current = current_config(device)?;
    let mode = current.and_then(|header| header.mode);
    let anchor = current.and_then(|header| header.sd_anchor);
    let preferences = current.map(|header| header.device_preferences).unwrap_or_default();
    write_config(device, mode, anchor, flags, preferences, current.map(|header| header.wallet_labels).unwrap_or_default(), current.map(|header| header.wallet_activation).unwrap_or_default())
}

pub(in crate::services::persistent_wallet) fn write_device_preferences(
    device: &mut DeviceFlash<'_>,
    preferences: DevicePreferences,
) -> Result<(), FlashError> {
    let current = current_config(device)?;
    let mode = current.and_then(|header| header.mode);
    let anchor = current.and_then(|header| header.sd_anchor);
    let flags = current.map(|header| header.device_flags).unwrap_or_default();
    write_config(device, mode, anchor, flags, preferences, current.map(|header| header.wallet_labels).unwrap_or_default(), current.map(|header| header.wallet_activation).unwrap_or_default())
}

pub(in crate::services::persistent_wallet) fn write_sd_anchor(
    device: &mut DeviceFlash<'_>,
    anchor: SdAnchor,
) -> Result<(), FlashError> {
    let current = current_config(device)?;
    let flags = current.map(|header| header.device_flags).unwrap_or_default();
    let preferences = current.map(|header| header.device_preferences).unwrap_or_default();
    let labels = current.map(|header| header.wallet_labels).unwrap_or_default();
    write_config(device, Some(StorageMode::SdCard), Some(anchor), flags, preferences, labels, current.map(|header| header.wallet_activation).unwrap_or_default())
}

pub(super) fn write_config(
    device: &mut DeviceFlash<'_>,
    mode: Option<StorageMode>,
    sd_anchor: Option<SdAnchor>,
    device_flags: DeviceFlags,
    device_preferences: DevicePreferences,
    wallet_labels: WalletLabels,
    wallet_activation: WalletActivationRecords,
) -> Result<(), FlashError> {
    let a = read_config(device, flash::CONFIG_A)?;
    let b = read_config(device, flash::CONFIG_B)?;
    let sequence = newest_config(a, b).map_or(1, |header| header.sequence.wrapping_add(1));
    let target = match (a, b) {
        (None, _) => flash::CONFIG_A,
        (_, None) => flash::CONFIG_B,
        (Some(left), Some(right)) if is_newer(left.sequence, right.sequence) => flash::CONFIG_B,
        _ => flash::CONFIG_A,
    };
    let mut record = AlignedBytes::<CONFIG_SIZE>::zeroed();
    record.0[..8].copy_from_slice(&CONFIG_MAGIC);
    record.0[8] = CONFIG_VERSION;
    record.0[9] = mode.map_or(0, |value| value as u8);
    record.0[DEVICE_FLAGS_OFFSET] = device_flags.0;
    record.0[DEVICE_PREFERENCES_OFFSET] = device_preferences.flags;
    record.0[DIM_TIMEOUT_OFFSET] = device_preferences.dim_timeout_code;
    record.0[12..16].copy_from_slice(&sequence.to_le_bytes());
    if let Some(anchor) = sd_anchor { encode_sd_anchor(anchor, &mut record.0); }
    encode_wallet_labels(wallet_labels, &mut record.0);
    encode_wallet_activation(wallet_activation, &mut record.0);
    let digest = Sha256::digest(&record.0[..CONFIG_DIGEST_START]);
    record.0[CONFIG_DIGEST_START..CONFIG_DIGEST_END].copy_from_slice(&digest);
    device.replace_sector(target, &record)
}

pub(super) fn encode_wallet_labels(labels: WalletLabels, out: &mut [u8; CONFIG_SIZE]) {
    for index in 0..MAX_SLOTS {
        let base = WALLET_LABELS_OFFSET + index * WALLET_LABEL_RECORD_SIZE;
        let len = usize::from(labels.lengths[index]).min(WALLET_NAME_MAX);
        out[base] = len as u8;
        out[base + 1..base + 1 + len].copy_from_slice(&labels.names[index][..len]);
    }
}

pub(super) fn decode_wallet_labels(record: &[u8; CONFIG_SIZE], version: u8) -> Option<WalletLabels> {
    if !matches!(version, CONFIG_VERSION | V7_COMPAT_VERSION) { return Some(WalletLabels::empty()); }
    let mut labels = WalletLabels::empty();
    for index in 0..MAX_SLOTS {
        let base = WALLET_LABELS_OFFSET + index * WALLET_LABEL_RECORD_SIZE;
        let len = usize::from(record[base]);
        if len > WALLET_NAME_MAX { return None; }
        let name = &record[base + 1..base + 1 + WALLET_NAME_MAX];
        if name[len..].iter().any(|byte| *byte != 0) || core::str::from_utf8(&name[..len]).is_err() {
            return None;
        }
        labels.lengths[index] = len as u8;
        labels.names[index][..len].copy_from_slice(&name[..len]);
    }
    Some(labels)
}

pub(super) fn encode_wallet_activation(records: WalletActivationRecords, out: &mut [u8; CONFIG_SIZE]) {
    for index in 0..MAX_SLOTS {
        let base = WALLET_ACTIVATION_OFFSET + index * WALLET_ACTIVATION_RECORD_SIZE;
        if !records.present[index] { continue; }
        out[base] = 1;
        out[base + 1..base + 1 + SALT_SIZE].copy_from_slice(&records.records[index].salt);
        out[base + 1 + SALT_SIZE..base + WALLET_ACTIVATION_RECORD_SIZE]
            .copy_from_slice(&records.records[index].verifier);
    }
}

pub(super) fn decode_wallet_activation(record: &[u8; CONFIG_SIZE], version: u8) -> Option<WalletActivationRecords> {
    if version != CONFIG_VERSION { return Some(WalletActivationRecords::empty()); }
    let mut records = WalletActivationRecords::empty();
    for index in 0..MAX_SLOTS {
        let base = WALLET_ACTIVATION_OFFSET + index * WALLET_ACTIVATION_RECORD_SIZE;
        match record[base] {
            0 => {
                if record[base + 1..base + WALLET_ACTIVATION_RECORD_SIZE].iter().any(|byte| *byte != 0) { return None; }
            }
            1 => {
                let mut salt = [0u8; SALT_SIZE];
                salt.copy_from_slice(&record[base + 1..base + 1 + SALT_SIZE]);
                let mut verifier = [0u8; 32];
                verifier.copy_from_slice(&record[base + 1 + SALT_SIZE..base + WALLET_ACTIVATION_RECORD_SIZE]);
                records.present[index] = true;
                records.records[index] = WalletActivationRecord { salt, verifier };
            }
            _ => return None,
        }
    }
    Some(records)
}

pub(super) fn encode_sd_anchor(anchor: SdAnchor, out: &mut [u8; CONFIG_SIZE]) {
    out[10] = anchor.credential_kind as u8;
    out[11] = anchor.active_slot;
    out[16..20].copy_from_slice(&anchor.wallet_sequence.to_le_bytes());
    out[20..20 + SALT_SIZE].copy_from_slice(&anchor.salt);
    if anchor.duress.enabled {
        out[36] = 1;
        out[37] = anchor.duress.kind as u8;
        out[38] = anchor.duress.key_slot;
        out[40..40 + SALT_SIZE].copy_from_slice(&anchor.duress.salt);
        out[56..88].copy_from_slice(&anchor.duress.verifier);
    }
}


pub(super) fn read_config(device: &mut DeviceFlash<'_>, address: u32) -> Result<Option<ConfigHeader>, FlashError> {
    let mut record = AlignedBytes::<CONFIG_SIZE>::zeroed();
    device.read(address, &mut record)?;
    if record.0[..8] != CONFIG_MAGIC { return Ok(None); }
    if !matches!(
        record.0[8],
        CONFIG_VERSION | V7_COMPAT_VERSION | V6_COMPAT_VERSION | V5_COMPAT_VERSION | LEGACY_CONFIG_VERSION | V471_V475_COMPAT_VERSION
    ) {
        return Ok(None);
    }
    read_current_config(&record.0)
}

pub(super) fn contains_unknown_device_flags(device_flags: DeviceFlags) -> bool {
    has_unknown_bits(device_flags.0, DeviceFlags::KNOWN_MASK)
}

pub(super) fn has_unknown_bits(value: u8, known_mask: u8) -> bool {
    value & !known_mask != 0
}

pub(super) fn read_current_config(record: &[u8; CONFIG_SIZE]) -> Result<Option<ConfigHeader>, FlashError> {
    let version = record[8];
    let mode = if record[9] == 0 { None } else { StorageMode::from_byte(record[9]) };
    if record[9] != 0 && mode.is_none() { return Ok(None); }
    let device_flags = DeviceFlags(record[DEVICE_FLAGS_OFFSET]);
    if contains_unknown_device_flags(device_flags) { return Ok(None); }

    let Some((digest_start, digest_end, device_preferences)) = config_preferences(record, version) else {
        return Ok(None);
    };
    if !config_digest_valid(record, version, digest_start, digest_end) { return Ok(None); }
    let Some(wallet_labels) = decode_wallet_labels(record, version) else { return Ok(None); };
    let Some(wallet_activation) = decode_wallet_activation(record, version) else { return Ok(None); };
    let sequence = u32::from_le_bytes(record[12..16].try_into().map_err(|_| FlashError::Read)?);
    let legacy_kdf = matches!(version, LEGACY_CONFIG_VERSION | V471_V475_COMPAT_VERSION);
    let sd_anchor = if mode == Some(StorageMode::SdCard) {
        decode_sd_anchor(record, legacy_kdf)?
    } else {
        if !empty_config_body_valid(record, version, digest_start) { return Ok(None); }
        None
    };
    Ok(Some(ConfigHeader { mode, sequence, sd_anchor, device_flags, device_preferences, wallet_labels, wallet_activation }))
}

pub(super) fn config_preferences(
    record: &[u8; CONFIG_SIZE],
    version: u8,
) -> Option<(usize, usize, DevicePreferences)> {
    if matches!(version, CONFIG_VERSION | V7_COMPAT_VERSION | V6_COMPAT_VERSION) {
        let preferences = DevicePreferences {
            flags: record[DEVICE_PREFERENCES_OFFSET],
            dim_timeout_code: record[DIM_TIMEOUT_OFFSET],
        };
        if preferences.flags & !DevicePreferences::KNOWN_MASK != 0
            || preferences.dim_timeout_code > 4
            || !preferences.wallet_network_code_valid()
        {
            return None;
        }
        let digest = match version {
            CONFIG_VERSION => (CONFIG_DIGEST_START, CONFIG_DIGEST_END),
            V7_COMPAT_VERSION => (V7_CONFIG_DIGEST_START, V7_CONFIG_DIGEST_END),
            _ => (V6_CONFIG_DIGEST_START, V6_CONFIG_DIGEST_END),
        };
        return Some((digest.0, digest.1, preferences));
    }
    Some((
        LEGACY_CONFIG_DIGEST_START,
        LEGACY_CONFIG_DIGEST_END,
        DevicePreferences::default(),
    ))
}

pub(super) fn config_digest_valid(
    record: &[u8; CONFIG_SIZE],
    version: u8,
    digest_start: usize,
    digest_end: usize,
) -> bool {
    let digest = Sha256::digest(&record[..digest_start]);
    let tail_end = if version == CONFIG_VERSION { CONFIG_SIZE } else if version == V7_COMPAT_VERSION { 512 } else { LEGACY_CONFIG_SIZE };
    digest[..] == record[digest_start..digest_end]
        && record[digest_end..tail_end].iter().all(|byte| *byte == 0)
}

pub(super) fn empty_config_body_valid(
    record: &[u8; CONFIG_SIZE],
    version: u8,
    digest_start: usize,
) -> bool {
    if record[10] != 0 || record[11] != 0
        || record[16..DEVICE_FLAGS_OFFSET].iter().any(|byte| *byte != 0)
        || record[DEVICE_FLAGS_OFFSET + 1..DEVICE_PREFERENCES_OFFSET].iter().any(|byte| *byte != 0)
    {
        return false;
    }
    if version == CONFIG_VERSION {
        return record[90..WALLET_LABELS_OFFSET].iter().all(|byte| *byte == 0)
            && record[WALLET_LABELS_END..WALLET_ACTIVATION_OFFSET].iter().all(|byte| *byte == 0)
            && record[WALLET_ACTIVATION_END..CONFIG_DIGEST_START].iter().all(|byte| *byte == 0);
    }
    if version == V7_COMPAT_VERSION {
        return record[90..WALLET_LABELS_OFFSET].iter().all(|byte| *byte == 0)
            && record[WALLET_LABELS_END..V7_CONFIG_DIGEST_START].iter().all(|byte| *byte == 0);
    }
    record[DEVICE_PREFERENCES_OFFSET + usize::from(version == V6_COMPAT_VERSION) * 2..digest_start]
        .iter().all(|byte| *byte == 0)
}

pub(super) fn current_config(device: &mut DeviceFlash<'_>) -> Result<Option<ConfigHeader>, FlashError> {
    let a = read_config(device, flash::CONFIG_A)?;
    let b = read_config(device, flash::CONFIG_B)?;
    Ok(newest_config(a, b))
}

pub(super) fn decode_sd_anchor(record: &[u8; CONFIG_SIZE], legacy_kdf: bool) -> Result<Option<SdAnchor>, FlashError> {
    let Some(credential_kind) = CredentialKind::from_byte(record[10]) else { return Ok(None); };
    if record[11] > 1 || record[36] > 1 { return Ok(None); }
    let wallet_sequence = u32::from_le_bytes(record[16..20].try_into().map_err(|_| FlashError::Read)?);
    if wallet_sequence == 0 { return Ok(None); }
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&record[20..20 + SALT_SIZE]);
    let duress = if record[36] == 0 {
        if record[37] != 0 || record[38] != 0 || record[40..88].iter().any(|byte| *byte != 0) { return Ok(None); }
        DuressPolicy::disabled()
    } else {
        let Some(kind) = CredentialKind::from_byte(record[37]) else { return Ok(None); };
        let key_slot = record[38];
        if !(3..=5).contains(&key_slot) { return Ok(None); }
        let mut duress_salt = [0u8; SALT_SIZE];
        duress_salt.copy_from_slice(&record[40..40 + SALT_SIZE]);
        let mut verifier = [0u8; 32];
        verifier.copy_from_slice(&record[56..88]);
        DuressPolicy { enabled: true, kind, key_slot, salt: duress_salt, verifier }
    };
    Ok(Some(SdAnchor {
        credential_kind,
        salt,
        active_slot: record[11],
        wallet_sequence,
        duress,
        credential_kdf: if legacy_kdf { CredentialKdf::LegacyPbkdf2Sha256 } else { CredentialKdf::current() },
    }))
}

pub(super) fn newest_config(a: Option<ConfigHeader>, b: Option<ConfigHeader>) -> Option<ConfigHeader> {
    match (a, b) {
        (Some(left), Some(right)) if is_newer(left.sequence, right.sequence) => Some(left),
        (Some(_), Some(right)) => Some(right),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

