//! Canonical binary encoding for the complete in-RAM wallet slot set.

use crate::wallet::seed_manager::{MAX_SLOTS, SeedManager, WalletNetwork, WalletProtection, WalletSource};

pub(super) const SLOT_SIZE: usize = 122;
pub(super) const PAYLOAD_SIZE: usize = 4 + MAX_SLOTS * SLOT_SIZE;
const MAGIC: [u8; 3] = *b"PW1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CodecError {
    Header,
    ActiveSlot,
    Source,
    Network,
    Passphrase,
    Canonical,
}

pub(super) fn encode(manager: &SeedManager, out: &mut [u8; PAYLOAD_SIZE]) {
    out.fill(0);
    out[..3].copy_from_slice(&MAGIC);
    out[3] = manager.persistent_active();
    for (index, slot) in manager.slots.iter().enumerate() {
        if slot.transient { continue; }
        let base = 4 + index * SLOT_SIZE;
        out[base] = slot_header_byte(slot.source, slot.network, slot.protection);
        out[base + 1] = slot.passphrase_len;
        out[base + 2..base + 6].copy_from_slice(&slot.account_parent_fingerprint);
        out[base + 6..base + 10].copy_from_slice(&slot.fingerprint);
        for (word, destination) in slot.indices.iter().zip(out[base + 10..base + 58].chunks_exact_mut(2)) {
            destination.copy_from_slice(&word.to_le_bytes());
        }
        out[base + 58..base + 122].copy_from_slice(&slot.passphrase);
    }
}

pub(super) fn decode(input: &[u8; PAYLOAD_SIZE], manager: &mut SeedManager) -> Result<(), CodecError> {
    validate(input)?;
    let selected_network = manager.network();
    let mut restored = SeedManager::new();
    restored.set_network(selected_network);
    for index in 0..MAX_SLOTS {
        let base = 4 + index * SLOT_SIZE;
        let slot = &mut restored.slots[index];
        let (source, network, protection) = decode_slot_header(input[base])?;
        slot.source = source;
        slot.network = network;
        slot.protection = protection;
        slot.passphrase_len = input[base + 1];
        slot.account_parent_fingerprint.copy_from_slice(&input[base + 2..base + 6]);
        slot.fingerprint.copy_from_slice(&input[base + 6..base + 10]);
        for (source, word) in input[base + 10..base + 58].chunks_exact(2).zip(slot.indices.iter_mut()) {
            *word = u16::from_le_bytes([source[0], source[1]]);
        }
        slot.passphrase.copy_from_slice(&input[base + 58..base + 122]);
    }
    if input[3] != u8::MAX {
        let active = usize::from(input[3]);
        if restored.slot_visible(active) { let _ = restored.set_active(active); }
    }
    *manager = restored;
    Ok(())
}

fn validate(input: &[u8; PAYLOAD_SIZE]) -> Result<(), CodecError> {
    if input[..3] != MAGIC { return Err(CodecError::Header); }
    let active = input[3];
    if active != u8::MAX && usize::from(active) >= MAX_SLOTS { return Err(CodecError::ActiveSlot); }
    for index in 0..MAX_SLOTS {
        let base = 4 + index * SLOT_SIZE;
        let (source, _, _) = decode_slot_header(input[base])?;
        let passphrase_len = usize::from(input[base + 1]);
        if passphrase_len > 64 { return Err(CodecError::Passphrase); }
        validate_slot(source, passphrase_len, &input[base..base + SLOT_SIZE])?;
    }
    if active != u8::MAX {
        let source = decode_slot_header(input[4 + usize::from(active) * SLOT_SIZE])?.0;
        if source == WalletSource::Empty { return Err(CodecError::ActiveSlot); }
    }
    Ok(())
}

fn validate_slot(source: WalletSource, passphrase_len: usize, slot: &[u8]) -> Result<(), CodecError> {
    let indices = decode_indices(&slot[10..58]);
    let passphrase = &slot[58..122];
    match source {
        WalletSource::Empty => validate_empty_slot(passphrase_len, slot),
        WalletSource::Mnemonic12 | WalletSource::Mnemonic24 => {
            validate_mnemonic_slot(source, passphrase_len, slot, passphrase, &indices)
        }
        WalletSource::RawPrivateKey => {
            validate_raw_key_slot(passphrase_len, slot, passphrase, &indices)
        }
        WalletSource::AccountXprv => validate_account_xprv_slot(passphrase_len, passphrase, &indices),
    }
}

fn validate_empty_slot(passphrase_len: usize, slot: &[u8]) -> Result<(), CodecError> {
    if passphrase_len != 0 || slot[2..].iter().any(|byte| *byte != 0) {
        return Err(CodecError::Canonical);
    }
    Ok(())
}

fn validate_mnemonic_slot(
    source: WalletSource,
    passphrase_len: usize,
    slot: &[u8],
    passphrase: &[u8],
    indices: &[u16; 24],
) -> Result<(), CodecError> {
    let word_count = source.mnemonic_word_count().ok_or(CodecError::Source)?;
    let used_words = usize::from(word_count);
    if indices[..used_words].iter().any(|word| *word >= 2048)
        || indices[used_words..].iter().any(|word| *word != 0)
        || slot[2..6].iter().any(|byte| *byte != 0)
        || passphrase[passphrase_len..].iter().any(|byte| *byte != 0)
        || core::str::from_utf8(&passphrase[..passphrase_len]).is_err()
        || !crate::wallet::mnemonic::validate(indices, word_count)
    {
        return Err(CodecError::Canonical);
    }
    Ok(())
}

fn validate_raw_key_slot(
    passphrase_len: usize,
    slot: &[u8],
    passphrase: &[u8],
    indices: &[u16; 24],
) -> Result<(), CodecError> {
    if passphrase_len != 0
        || indices[16..].iter().any(|word| *word != 0)
        || slot[2..6].iter().any(|byte| *byte != 0)
        || passphrase.iter().any(|byte| *byte != 0)
        || !valid_private_key(indices)
    {
        return Err(CodecError::Canonical);
    }
    Ok(())
}

fn validate_account_xprv_slot(
    passphrase_len: usize,
    passphrase: &[u8],
    indices: &[u16; 24],
) -> Result<(), CodecError> {
    if passphrase_len != 33
        || indices[16..].iter().any(|word| *word != 0)
        || passphrase[32] != 3
        || passphrase[33..].iter().any(|byte| *byte != 0)
        || !valid_private_key(indices)
    {
        return Err(CodecError::Canonical);
    }
    Ok(())
}

fn decode_indices(bytes: &[u8]) -> [u16; 24] {
    let mut indices = [0u16; 24];
    for (source, word) in bytes.chunks_exact(2).zip(indices.iter_mut()) {
        *word = u16::from_le_bytes([source[0], source[1]]);
    }
    indices
}

fn valid_private_key(indices: &[u16; 24]) -> bool {
    let mut key = [0u8; 32];
    for (word, destination) in indices[..16].iter().zip(key.chunks_exact_mut(2)) {
        destination.copy_from_slice(&word.to_le_bytes());
    }
    let valid = offline_signer::derivation::bip32::compressed_pubkey_from_raw_key(&key).is_ok();
    shared_signer::bytes::zeroize_bytes(&mut key);
    valid
}

const SOURCE_MASK: u8 = 0x0f;
const SLOT_TAG_SHIFT: u8 = 4;
const NETWORK_COUNT: u8 = 3;

const fn source_byte(source: WalletSource) -> u8 {
    match source {
        WalletSource::Empty => 0,
        WalletSource::Mnemonic12 => 1,
        WalletSource::Mnemonic24 => 2,
        WalletSource::RawPrivateKey => 3,
        WalletSource::AccountXprv => 4,
    }
}

const fn source_from_byte(value: u8) -> Option<WalletSource> {
    match value {
        0 => Some(WalletSource::Empty),
        1 => Some(WalletSource::Mnemonic12),
        2 => Some(WalletSource::Mnemonic24),
        3 => Some(WalletSource::RawPrivateKey),
        4 => Some(WalletSource::AccountXprv),
        _ => None,
    }
}

const fn slot_header_byte(source: WalletSource, network: WalletNetwork, protection: WalletProtection) -> u8 {
    if matches!(source, WalletSource::Empty) {
        0
    } else {
        let tag = network.slot_tag() + NETWORK_COUNT * protection.slot_code();
        source_byte(source) | (tag << SLOT_TAG_SHIFT)
    }
}

fn decode_slot_header(value: u8) -> Result<(WalletSource, WalletNetwork, WalletProtection), CodecError> {
    let source = source_from_byte(value & SOURCE_MASK).ok_or(CodecError::Source)?;
    if source == WalletSource::Empty {
        if value != 0 { return Err(CodecError::Canonical); }
        return Ok((source, WalletNetwork::Mainnet, WalletProtection::DeviceOnly));
    }
    let tag = value >> SLOT_TAG_SHIFT;
    let network = WalletNetwork::from_slot_tag(tag % NETWORK_COUNT).ok_or(CodecError::Network)?;
    let protection = WalletProtection::from_slot_code(tag / NETWORK_COUNT).ok_or(CodecError::Canonical)?;
    Ok((source, network, protection))
}
