//! Wallet-key derivation service boundary.
//!
//! Runtime orchestrates progress/presentation while this service owns the
//! secret-bearing derivation primitives and cross-core public-key worker.

use crate::{runtime::data::AppData, wallet::seed_manager::SeedSlot};

#[cfg(feature = "m5stack")]
pub(crate) mod worker;

/// Derive the active mnemonic seed while acknowledging caller-owned liveness.
/// Production hardware callers must provide this capability explicitly.
#[inline(never)]
pub fn derive_active_seed_with_checkpoint(
    ad: &AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<offline_signer::derivation::bip39::Seed, &'static str> {
    let slot = ad
        .wallet
        .seeds
        .seed_mgr
        .active_slot()
        .ok_or("No active wallet")?;
    derive_slot_seed_with_checkpoint(slot, checkpoint)
}

/// Test/workflow convenience only. Production code must use the checkpointed API.
#[cfg(any(feature = "workflow-test-auto", feature = "hardware-tests"))]
#[inline(never)]
pub fn derive_active_seed(
    ad: &AppData,
) -> Result<offline_signer::derivation::bip39::Seed, &'static str> {
    let slot = ad.wallet.seeds.seed_mgr.active_slot().ok_or("No active wallet")?;
    derive_slot_seed(slot)
}

/// Test/workflow convenience for deterministic fixtures. Production hardware
/// must use `derive_slot_seed_with_checkpoint`.
#[cfg(any(feature = "workflow-test-auto", feature = "hardware-tests"))]
#[inline(never)]
pub(crate) fn derive_slot_seed(
    slot: &SeedSlot,
) -> Result<offline_signer::derivation::bip39::Seed, &'static str> {
    let word_count = slot
        .mnemonic_word_count()
        .ok_or("Active wallet is not a mnemonic")?;
    derive_seed(&slot.indices, word_count, slot.passphrase_str())
}

/// Derive one mnemonic seed while periodically acknowledging caller-owned
/// liveness. The checkpoint never influences cryptographic input or output; it
/// only runs at the fixed PBKDF2 checkpoints provided by offline-signer.
#[inline(never)]
pub(crate) fn derive_slot_seed_with_checkpoint(
    slot: &SeedSlot,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<offline_signer::derivation::bip39::Seed, &'static str> {
    let word_count = slot
        .mnemonic_word_count()
        .ok_or("Active wallet is not a mnemonic")?;
    if !crate::wallet::mnemonic::validate(&slot.indices, word_count) {
        return Err("Invalid mnemonic");
    }
    let mut liveness = || checkpoint();
    match word_count {
        12 => {
            let mut indices = [0u16; 12];
            indices.copy_from_slice(&slot.indices[..12]);
            Ok(offline_signer::derivation::bip39::seed_from_mnemonic_12_with_checkpoint(
                &offline_signer::derivation::bip39::Mnemonic12 { indices },
                slot.passphrase_str(),
                &mut liveness,
            ))
        }
        24 => Ok(offline_signer::derivation::bip39::seed_from_mnemonic_24_with_checkpoint(
            &offline_signer::derivation::bip39::Mnemonic24 { indices: slot.indices },
            slot.passphrase_str(),
            &mut liveness,
        )),
        _ => Err("Wallet source is not a mnemonic"),
    }
}

/// Test/workflow convenience for deterministic fixtures.
#[cfg(any(feature = "workflow-test-auto", feature = "hardware-tests"))]
#[inline(never)]
pub(crate) fn derive_seed(
    mnemonic_indices: &[u16; 24],
    word_count: u8,
    passphrase: &str,
) -> Result<offline_signer::derivation::bip39::Seed, &'static str> {
    if !crate::wallet::mnemonic::validate(mnemonic_indices, word_count) {
        return Err("Invalid mnemonic");
    }
    match word_count {
        12 => {
            let mut indices = [0u16; 12];
            indices.copy_from_slice(&mnemonic_indices[..12]);
            Ok(offline_signer::derivation::bip39::seed_from_mnemonic_12(
                &offline_signer::derivation::bip39::Mnemonic12 { indices },
                passphrase,
            ))
        }
        24 => Ok(offline_signer::derivation::bip39::seed_from_mnemonic_24(
            &offline_signer::derivation::bip39::Mnemonic24 {
                indices: *mnemonic_indices,
            },
            passphrase,
        )),
        _ => Err("Wallet source is not a mnemonic"),
    }
}

/// Volatile-zero seed bytes so the compiler cannot optimize the clear away.
#[inline(always)]
pub(crate) fn zeroize_seed(buffer: &mut [u8]) {
    shared_signer::bytes::zeroize_bytes(buffer);
}
