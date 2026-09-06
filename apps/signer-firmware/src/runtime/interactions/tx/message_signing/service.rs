use crate::runtime::data::AppData;

pub(super) fn message_digest(ad: &AppData) -> [u8; 32] {
    let message = &ad.signing.message.payload[..ad.signing.message.payload_len];
    offline_signer::crypto::message::message_digest(message)
}

fn sign_with_entropy(ad: &AppData, signing_entropy: &[u8; 32], checkpoint: &mut dyn FnMut()) -> Result<[u8; 64], ()> {
    let slot = ad.wallet.seeds.seed_mgr.active_slot().ok_or(())?;
    let message = &ad.signing.message.payload[..ad.signing.message.payload_len];
    let mut private_key = [0u8; 32];
    let result = (|| {
        if slot.is_raw_key() {
            if !slot.raw_key_bytes(&mut private_key) {
                return Err(());
            }
        } else {
            let account = crate::runtime::signing::derive_active_account_key_with_checkpoint(ad, checkpoint).map_err(|_| ())?;
            private_key.copy_from_slice(account.private_key_bytes());
        }
        offline_signer::OfflineSigner::new()
            .sign_user_message_with_entropy(&private_key, message, signing_entropy)
            .map(|signature| signature.bytes)
            .map_err(|_| ())
    })();
    offline_signer::derivation::hmac::zeroize_buf(&mut private_key);
    result
}

pub(super) fn sign_reviewed_message(ad: &AppData, checkpoint: &mut dyn FnMut()) -> Result<[u8; 64], ()> {
    let mut signing_entropy = [0u8; 32];
    crate::crypto::entropy::fill(&mut signing_entropy).map_err(|_| ())?;
    let result = sign_with_entropy(ad, &signing_entropy, checkpoint);
    offline_signer::derivation::hmac::zeroize_buf(&mut signing_entropy);
    result
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_sign_reviewed_message(ad: &AppData) -> Result<[u8; 64], ()> {
    { let mut checkpoint = || {}; sign_with_entropy(ad, &[0x6c; 32], &mut checkpoint) }
}
