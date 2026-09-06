use crate::{runtime::data::AppData, services::persistent_wallet::PersistError};
use offline_signer::crypto::password_kdf::MAX_PASSWORD_SIZE;
use shared_signer::bytes::zeroize_bytes;

pub(super) struct SecretBuffer {
    bytes: [u8; MAX_PASSWORD_SIZE],
    len: usize,
}

impl SecretBuffer {
    pub(super) fn take_from_app(ad: &mut AppData) -> Result<Self, PersistError> {
        let len = ad.wallet.seeds.pp_input.len;
        let mut bytes = [0u8; MAX_PASSWORD_SIZE];
        let result = match (
            ad.wallet.seeds.pp_input.buf.get(..len),
            bytes.get_mut(..len),
        ) {
            (Some(source), Some(target)) => {
                target.copy_from_slice(source);
                Ok(Self { bytes, len })
            }
            _ => {
                zeroize_bytes(&mut bytes);
                Err(PersistError::InvalidWallet)
            }
        };
        // The task owns the only foreground credential copy from this point.
        ad.wallet.seeds.pp_input.reset();
        result
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }

    pub(super) fn clear(&mut self) {
        zeroize_bytes(&mut self.bytes);
        self.len = 0;
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) { self.clear(); }
}
