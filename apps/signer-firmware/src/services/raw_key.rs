//! Raw private-key decoding and wallet installation.

use crate::runtime::data::AppData;
use shared_signer::bytes::{decode_hex_nibble, zeroize_bytes};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawKeyImportError {
    InvalidLength,
    InvalidHex,
    InvalidKey,
    AlreadyExists,
    SlotsFull,
}

pub fn decode_private_key_hex(payload: &[u8]) -> Result<[u8; 32], RawKeyImportError> {
    if payload.len() != 64 {
        return Err(RawKeyImportError::InvalidLength);
    }
    let mut key = [0u8; 32];
    for index in 0..32 {
        let Some(high) = decode_hex_nibble(payload[index * 2]) else {
            zeroize_bytes(&mut key);
            return Err(RawKeyImportError::InvalidHex);
        };
        let Some(low) = decode_hex_nibble(payload[index * 2 + 1]) else {
            zeroize_bytes(&mut key);
            return Err(RawKeyImportError::InvalidHex);
        };
        key[index] = (high << 4) | low;
    }
    Ok(key)
}

pub fn install_raw_key(
    ad: &mut AppData,
    key: [u8; 32],
) -> Result<usize, RawKeyImportError> {
    install_raw_key_with_mode(ad, key, false)
}

pub fn install_raw_key_transient(
    ad: &mut AppData,
    key: [u8; 32],
) -> Result<usize, RawKeyImportError> {
    install_raw_key_with_mode(ad, key, true)
}

fn install_raw_key_with_mode(
    ad: &mut AppData,
    mut key: [u8; 32],
    transient: bool,
) -> Result<usize, RawKeyImportError> {
    let result = (|| {
        offline_signer::derivation::bip32::pubkey_from_raw_key(&key)
            .map_err(|_| RawKeyImportError::InvalidKey)?;
        if transient && ad.wallet.seeds.seed_mgr.find_matching_raw_key(&key).is_some() {
            return Err(RawKeyImportError::AlreadyExists);
        }
        let slot_index = if transient {
            ad.wallet.seeds.seed_mgr.store_raw_key_transient(&key)
        } else {
            ad.wallet.seeds.seed_mgr.store_raw_key(&key)
        }
        .ok_or(RawKeyImportError::SlotsFull)?;
        crate::services::wallet_session::activate_slot(ad, slot_index)
            .map_err(|_| RawKeyImportError::InvalidKey)?;
        Ok(slot_index)
    })();
    zeroize_bytes(&mut key);
    result
}

pub fn decode_and_install(
    ad: &mut AppData,
    payload: &[u8],
) -> Result<usize, RawKeyImportError> {
    install_raw_key(ad, decode_private_key_hex(payload)?)
}

pub fn decode_and_install_transient(
    ad: &mut AppData,
    payload: &[u8],
) -> Result<usize, RawKeyImportError> {
    install_raw_key_transient(ad, decode_private_key_hex(payload)?)
}
