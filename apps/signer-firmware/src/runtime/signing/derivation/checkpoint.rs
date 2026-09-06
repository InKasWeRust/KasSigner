//! Cooperative watch-account derivation for responsive embedded export flows.

use crate::wallet::seed_manager::SeedSlot;

#[cfg(feature = "waveshare")]
use crate::runtime::data::AppData;
#[cfg(feature = "waveshare")]
use super::zeroize_seed;

#[cfg(feature = "waveshare")]
pub(crate) struct KpubDerivationStart {
    pub(crate) pending_seed: Option<offline_signer::derivation::bip39::SeedDerivation>,
    pub(crate) pending_account: Option<offline_signer::derivation::bip32::AccountKeyDerivation>,
}

#[cfg(feature = "waveshare")]
impl KpubDerivationStart {
    fn seed(work: offline_signer::derivation::bip39::SeedDerivation) -> Self {
        Self { pending_seed: Some(work), pending_account: None }
    }

    fn account(work: offline_signer::derivation::bip32::AccountKeyDerivation) -> Self {
        Self { pending_seed: None, pending_account: Some(work) }
    }
}

/// Begin Connect KasSee without performing BIP32 child derivation or secp256k1
/// public-key serialization on this frame. Mnemonics stage resumable BIP39
/// PBKDF2; imported account keys stage an already-complete account work item.
#[cfg(feature = "waveshare")]
pub(crate) fn begin_active_kpub_derivation(
    ad: &AppData,
) -> Result<KpubDerivationStart, &'static str> {
    let slot = ad.wallet.seeds.seed_mgr.active_slot().ok_or("No active wallet")?;
    if slot.is_raw_key() { return Err("Raw key has no watch account"); }
    if slot.is_account_key() {
        let mut raw = [0u8; 65];
        if !slot.account_key_raw(&mut raw) { return Err("Invalid account key slot"); }
        let account = offline_signer::derivation::bip32::ExtendedPrivKey::from_raw(&raw);
        shared_signer::bytes::zeroize_bytes(&mut raw);
        return Ok(KpubDerivationStart::account(
            offline_signer::derivation::bip32::AccountKeyDerivation::from_account_key(account),
        ));
    }
    Ok(KpubDerivationStart::seed(begin_mnemonic_seed(slot)?))
}

/// Convert the completed PBKDF2 seed into a resumable BIP32 account derivation.
/// Only master-key HMAC work happens in this frame; the three hardened children
/// advance one per later outer-loop iteration.
#[inline(never)]
#[cfg(feature = "waveshare")]
pub(crate) fn stage_active_kpub_account_derivation(
    ad: &AppData,
    seed: &mut offline_signer::derivation::bip39::Seed,
) -> Result<offline_signer::derivation::bip32::AccountKeyDerivation, &'static str> {
    let slot = ad.wallet.seeds.seed_mgr.active_slot().ok_or("No active wallet")?;
    if !slot.is_mnemonic() { return Err("Wallet source changed during derivation"); }
    let result = offline_signer::derivation::bip32::AccountKeyDerivation::new(&seed.bytes)
        .map_err(|_| "Account key derivation failed");
    zeroize_seed(&mut seed.bytes);
    result
}

/// Serialize only after account derivation is complete. Keeping this as a
/// separate non-inlined call prevents the PBKDF2/BIP32 frames from remaining
/// live beneath the secp256k1 public-key conversion on constrained CoreS3 RAM.
#[inline(never)]
#[cfg(feature = "waveshare")]
pub(crate) fn finish_active_kpub_derivation(
    ad: &AppData,
    work: offline_signer::derivation::bip32::AccountKeyDerivation,
    output: &mut [u8; offline_signer::derivation::xpub::KPUB_MAX_LEN],
) -> Result<usize, &'static str> {
    let slot = ad.wallet.seeds.seed_mgr.active_slot().ok_or("No active wallet")?;
    let account = work.finish().map_err(|_| "Account derivation incomplete")?;
    offline_signer::derivation::xpub::serialize_account_kpub(
        &account, slot.account_parent_fingerprint, output,
    )
    .map_err(|_| "kpub serialization failed")
}

pub(crate) fn begin_mnemonic_seed(
    slot: &SeedSlot,
) -> Result<offline_signer::derivation::bip39::SeedDerivation, &'static str> {
    let count = slot.mnemonic_word_count().ok_or("Active wallet is not a mnemonic")?;
    if !crate::wallet::mnemonic::validate(&slot.indices, count) { return Err("Invalid mnemonic"); }
    match count {
        12 => {
            let mut words = [0u16; 12];
            words.copy_from_slice(&slot.indices[..12]);
            Ok(offline_signer::derivation::bip39::SeedDerivation::from_mnemonic_12(
                &offline_signer::derivation::bip39::Mnemonic12 { indices: words },
                slot.passphrase_str(),
            ))
        }
        24 => Ok(offline_signer::derivation::bip39::SeedDerivation::from_mnemonic_24(
            &offline_signer::derivation::bip39::Mnemonic24 { indices: slot.indices },
            slot.passphrase_str(),
        )),
        _ => Err("Wallet source is not a mnemonic"),
    }
}
