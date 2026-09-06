//! Authoritative installation of public receive/change cache worker results.

use crate::runtime::data::AppData;
use crate::services::wallet_keys::worker::KpubWorkerResult;

pub(crate) fn install_worker_address_cache(
    ad: &mut AppData,
    result: &mut KpubWorkerResult,
) -> Result<(), &'static str> {
    let mut account_raw = [0u8; 65];
    let mut receive_cache = [[0u8; 32]; 20];
    let mut change_cache = [[0u8; 32]; 5];
    if !result.take_address_cache(&mut account_raw, &mut receive_cache, &mut change_cache) {
        shared_signer::bytes::zeroize_bytes(&mut account_raw);
        return Err("address-cache worker result kind mismatch");
    }
    shared_signer::bytes::zeroize_bytes(&mut ad.wallet.keys.acct_key_raw);
    ad.wallet.keys.acct_key_raw.copy_from_slice(&account_raw);
    ad.wallet.addresses.pubkey_cache = receive_cache;
    ad.wallet.addresses.change_pubkey_cache = change_cache;
    ad.wallet.addresses.pubkeys_cached = true;
    shared_signer::bytes::zeroize_bytes(&mut account_raw);
    Ok(())
}
