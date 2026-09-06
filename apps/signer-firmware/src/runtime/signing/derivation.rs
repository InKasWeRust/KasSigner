// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Authoritative wallet-source, BIP39, BIP32, and address-key derivation.

use crate::runtime::data::AppData;
use crate::wallet::seed_manager::SeedSlot;

#[cfg(feature = "m5stack")]
mod address_cache;
#[cfg(all(feature = "m5stack", not(feature = "hardware-tests")))]
pub(crate) use address_cache::install_worker_address_cache;

#[cfg(any(feature = "m5stack", feature = "waveshare"))]
mod checkpoint;
#[cfg(feature = "waveshare")]
pub(crate) use checkpoint::{begin_active_kpub_derivation, finish_active_kpub_derivation, stage_active_kpub_account_derivation, KpubDerivationStart};
#[cfg(all(feature = "m5stack", not(feature = "hardware-tests")))]
pub(crate) use checkpoint::begin_mnemonic_seed;

pub use crate::services::wallet_keys::derive_active_seed_with_checkpoint;
#[cfg(feature = "workflow-test-auto")]
pub use crate::services::wallet_keys::derive_active_seed;
pub(crate) use crate::services::wallet_keys::{derive_slot_seed_with_checkpoint, zeroize_seed};
#[cfg(any(feature = "workflow-test-auto", feature = "hardware-tests"))]
pub(crate) use crate::services::wallet_keys::derive_slot_seed;

/// Parse and validate an imported account XPrv slot without mnemonic KDF work.
fn parse_account_slot_key(
    slot: &SeedSlot,
) -> Result<offline_signer::derivation::bip32::ExtendedPrivKey, &'static str> {
    let mut raw = [0u8; 65];
    if !slot.account_key_raw(&mut raw) {
        return Err("Invalid account key slot");
    }
    let account = offline_signer::derivation::bip32::ExtendedPrivKey::from_raw(&raw);
    shared_signer::bytes::zeroize_bytes(&mut raw);
    account.public_key_x_only().map_err(|_| "Invalid account key slot")?;
    Ok(account)
}

/// Test/workflow convenience only. Production mnemonic derivation is checkpoint-required.
#[cfg(any(feature = "workflow-test-auto", feature = "hardware-tests"))]
#[inline(never)]
pub(super) fn derive_slot_account_key(
    slot: &SeedSlot,
) -> Result<offline_signer::derivation::bip32::ExtendedPrivKey, &'static str> {
    if slot.is_account_key() {
        return parse_account_slot_key(slot);
    }
    if slot.is_mnemonic() {
        let mut seed = derive_slot_seed(slot)?;
        let result = offline_signer::derivation::bip32::derive_account_key(&seed.bytes)
            .map_err(|_| "Account key derivation failed");
        zeroize_seed(&mut seed.bytes);
        return result;
    }
    Err("Wallet source has no account key")
}

/// Signing-time account derivation with fixed BIP39 liveness checkpoints.
/// Imported account keys do not need checkpoints; mnemonic PBKDF2 does.
#[inline(never)]
pub(super) fn derive_slot_account_key_with_checkpoint(
    slot: &SeedSlot,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<offline_signer::derivation::bip32::ExtendedPrivKey, &'static str> {
    if slot.is_account_key() {
        return parse_account_slot_key(slot);
    }
    if slot.is_mnemonic() {
        let mut seed = derive_slot_seed_with_checkpoint(slot, checkpoint)?;
        checkpoint();
        let mut derivation = match offline_signer::derivation::bip32::AccountKeyDerivation::new(&seed.bytes) {
            Ok(derivation) => derivation,
            Err(_) => {
                zeroize_seed(&mut seed.bytes);
                return Err("Account key derivation failed");
            }
        };
        zeroize_seed(&mut seed.bytes);
        checkpoint();
        while !derivation.is_complete() {
            derivation.advance_one().map_err(|_| "Account key derivation failed")?;
            checkpoint();
        }
        return derivation.finish().map_err(|_| "Account key derivation failed");
    }
    Err("Wallet source has no account key")
}

#[inline(never)]
pub fn derive_active_account_key_with_checkpoint(
    ad: &AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<offline_signer::derivation::bip32::ExtendedPrivKey, &'static str> {
    let slot = ad
        .wallet
        .seeds
        .seed_mgr
        .active_slot()
        .ok_or("No active wallet")?;
    derive_slot_account_key_with_checkpoint(slot, checkpoint)
}

#[cfg(any(feature = "workflow-test-auto", feature = "hardware-tests"))]
#[inline(never)]
pub fn derive_active_account_key(
    ad: &AppData,
) -> Result<offline_signer::derivation::bip32::ExtendedPrivKey, &'static str> {
    let slot = ad.wallet.seeds.seed_mgr.active_slot().ok_or("No active wallet")?;
    derive_slot_account_key(slot)
}

/// Install the public-only receive fixture used by the connected GUI E2E image.
///
/// This intentionally lives beside the authoritative cache derivation code so
/// no workflow/controller bypasses address-cache ownership. It contains no
/// seed or private key and is excluded from production firmware.
#[cfg(feature = "workflow-test-auto")]
pub(crate) fn install_workflow_receive_fixture(ad: &mut AppData) {
    const GENERATOR_X: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    ];
    ad.wallet.addresses.current_addr_index = 0;
    ad.wallet.addresses.view_is_change = false;
    ad.wallet.addresses.partial_redraw = false;
    ad.wallet.addresses.pubkey_cache.fill(GENERATOR_X);
    ad.wallet.addresses.change_pubkey_cache.fill(GENERATOR_X);
    ad.wallet.addresses.pubkeys_cached = true;
}

/// Populate receive/change public-key caches for the active key source.
#[inline(never)]
pub fn populate_active_pubkeys_with_checkpoint(
    ad: &mut AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<(), &'static str> {
    let mut account_key_raw = [0u8; 65];
    let mut receive_cache = [[0u8; 32]; 20];
    let mut change_cache = [[0u8; 32]; 5];
    let result = {
        let slot = ad.wallet.seeds.seed_mgr.active_slot().ok_or("No active wallet")?;
        derive_slot_pubkeys_with_checkpoint(
            slot,
            &mut account_key_raw,
            &mut receive_cache,
            &mut change_cache,
            checkpoint,
        )
    };
    if let Err(message) = result {
        shared_signer::bytes::zeroize_bytes(&mut account_key_raw);
        return Err(message);
    }

    shared_signer::bytes::zeroize_bytes(&mut ad.wallet.keys.acct_key_raw);
    ad.wallet.keys.acct_key_raw.copy_from_slice(&account_key_raw);
    ad.wallet.addresses.pubkey_cache = receive_cache;
    ad.wallet.addresses.change_pubkey_cache = change_cache;
    ad.wallet.addresses.pubkeys_cached = true;
    shared_signer::bytes::zeroize_bytes(&mut account_key_raw);
    Ok(())
}

/// Derive all cached key material from one validated wallet slot.
#[inline(never)]
pub fn derive_slot_pubkeys_with_checkpoint(
    slot: &SeedSlot,
    account_key_raw: &mut [u8; 65],
    receive_cache: &mut [[u8; 32]; 20],
    change_cache: &mut [[u8; 32]; 5],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<(), &'static str> {
    shared_signer::bytes::zeroize_bytes(account_key_raw);
    receive_cache.fill([0u8; 32]);
    change_cache.fill([0u8; 32]);

    if slot.is_raw_key() {
        let mut raw_key = [0u8; 32];
        if !slot.raw_key_bytes(&mut raw_key) {
            return Err("Invalid raw key");
        }
        let result = offline_signer::derivation::bip32::pubkey_from_raw_key(&raw_key)
            .map_err(|_| "Invalid raw key");
        shared_signer::bytes::zeroize_bytes(&mut raw_key);
        receive_cache[0] = result?;
        return Ok(());
    }

    let account = derive_slot_account_key_with_checkpoint(slot, checkpoint)?;
    checkpoint();
    account_key_raw.copy_from_slice(&account.to_raw());

    for index in 0..20u32 {
        let address_key = offline_signer::derivation::bip32::derive_address_key(&account, index)
            .map_err(|_| "Address key derivation failed")?;
        receive_cache[index as usize] = address_key
            .public_key_x_only()
            .map_err(|_| "Public key derivation failed")?;
        checkpoint();
    }

    for index in 0..5u32 {
        let change_key = offline_signer::derivation::bip32::derive_change_key(&account, index)
            .map_err(|_| "Change key derivation failed")?;
        change_cache[index as usize] = change_key
            .public_key_x_only()
            .map_err(|_| "Change public key derivation failed")?;
        checkpoint();
    }
    Ok(())
}



/// Derive one active receive-chain private key with explicit liveness. Raw-key wallets support index 0.
#[inline(never)]
pub fn derive_active_private_key_with_checkpoint(
    ad: &AppData,
    address_index: u16,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<[u8; 32], &'static str> {
    let slot = ad.wallet.seeds.seed_mgr.active_slot().ok_or("No active wallet")?;
    checkpoint();
    if slot.is_raw_key() {
        if address_index != 0 { return Err("Raw key has no child addresses"); }
        let mut private_key = [0u8; 32];
        if !slot.raw_key_bytes(&mut private_key) { return Err("Invalid raw key"); }
        checkpoint();
        return Ok(private_key);
    }
    let account = derive_slot_account_key_with_checkpoint(slot, checkpoint)?;
    checkpoint();
    let key = offline_signer::derivation::bip32::derive_address_key(&account, u32::from(address_index))
        .map(|key| *key.private_key_bytes())
        .map_err(|_| "Key derivation failed")?;
    checkpoint();
    Ok(key)
}

/// Serialize the active account XPrv, whether it came from a mnemonic or import.
pub fn serialize_active_xprv_with_checkpoint(
    ad: &AppData,
    output: &mut [u8; offline_signer::derivation::xpub::XPRV_MAX_LEN],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<usize, &'static str> {
    let slot = ad
        .wallet
        .seeds
        .seed_mgr
        .active_slot()
        .ok_or("No active wallet")?;
    if slot.is_account_key() {
        let account = derive_slot_account_key_with_checkpoint(slot, checkpoint)?;
        return offline_signer::derivation::xpub::serialize_account_key_xprv(
            &account,
            slot.account_parent_fingerprint,
            output,
        )
        .map_err(|_| "xprv serialization failed");
    }
    let mut seed = derive_slot_seed_with_checkpoint(slot, checkpoint)?;
    checkpoint();
    let result = offline_signer::derivation::xpub::derive_and_serialize_xprv(
        &seed.bytes,
        output,
    )
    .map_err(|_| "xprv derivation failed");
    zeroize_seed(&mut seed.bytes);
    result
}

/// Derive a single receive-chain pubkey from the cached account key.
#[inline(never)]
pub fn derive_pubkey_from_acct(
    account_raw: &[u8; 65],
    address_index: u16,
    output: &mut [u8; 32],
) -> Result<(), &'static str> {
    derive_pubkey_from_account(account_raw, address_index, false, output)
}

/// Derive a single change-chain pubkey from the cached account key.
#[inline(never)]
pub fn derive_change_pubkey_from_acct(
    account_raw: &[u8; 65],
    address_index: u16,
    output: &mut [u8; 32],
) -> Result<(), &'static str> {
    derive_pubkey_from_account(account_raw, address_index, true, output)
}

fn derive_pubkey_from_account(
    account_raw: &[u8; 65],
    address_index: u16,
    change: bool,
    output: &mut [u8; 32],
) -> Result<(), &'static str> {
    *output = [0; 32];
    let account = offline_signer::derivation::bip32::ExtendedPrivKey::from_raw(account_raw);
    let key = if change {
        offline_signer::derivation::bip32::derive_change_key(&account, u32::from(address_index))
    } else {
        offline_signer::derivation::bip32::derive_address_key(&account, u32::from(address_index))
    }
    .map_err(|_| "Address key derivation failed")?;
    *output = key
        .public_key_x_only()
        .map_err(|_| "Address public key derivation failed")?;
    Ok(())
}
