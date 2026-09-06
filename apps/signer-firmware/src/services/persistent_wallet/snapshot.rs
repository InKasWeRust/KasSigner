//! Snapshot encoding/restore shared by flash and SD persistence backends.

use offline_signer::derivation::hmac::zeroize_buf;

use crate::{
    runtime::data::AppData,
    services::wallet_session,
    wallet::seed_manager::{MAX_SLOTS, SeedManager},
};

use super::{
    PersistError, PersistentWallet,
    codec::{self, PAYLOAD_SIZE},
    crypto::{self, RECORD_SIZE},
    flash::AlignedBytes,
    journal, security_policy,
};

impl PersistentWallet<'_> {
    pub(super) fn restore_record_with_key(
        &mut self,
        record: &AlignedBytes<RECORD_SIZE>,
        credential_key: &[u8; 32],
        ad: &mut AppData,
    ) -> Result<(), PersistError> {
        // Network selection is device-persistent and not secret. Apply it
        // before decoding the encrypted wallet so a saved active slot from a
        // different namespace is never activated/derived during unlock.
        let selected_network = journal::read_device_preferences(&mut self.flash)?
            .wallet_network();
        ad.wallet.seeds.seed_mgr.set_network(selected_network);

        let mut payload = [0u8; PAYLOAD_SIZE];
        let opened = self.crypto.open(record, credential_key, &mut payload);
        if let Err(error) = opened {
            zeroize_buf(&mut payload);
            return Err(error);
        }
        let decoded = codec::decode(&payload, &mut ad.wallet.seeds.seed_mgr);
        zeroize_buf(&mut payload);
        decoded.map_err(|_| PersistError::InvalidWallet)?;
        journal::read_wallet_labels(&mut self.flash)?.apply(&mut ad.wallet.seeds.seed_mgr);
        self.activate_restored(ad)
    }

    fn activate_restored(&mut self, ad: &mut AppData) -> Result<(), PersistError> {
        // With multiple wallets, startup must ask the owner which wallet to
        // activate. Do not derive/populate the serialized last-active wallet
        // only to clear it a few instructions later.
        if wallet_session::visible_wallet_count(ad) > 1 {
            wallet_session::clear_active_wallet(ad);
            return Ok(());
        }
        let active = ad.wallet.seeds.seed_mgr.active;
        if active >= MAX_SLOTS as u8 { return Ok(()); }
        let slot = usize::from(active);
        let protection = ad.wallet.seeds.seed_mgr.slots[slot].protection;
        if matches!(
            protection,
            crate::wallet::seed_manager::WalletProtection::Pin
                | crate::wallet::seed_manager::WalletProtection::Password
        ) {
            ad.wallet.seeds.seed_mgr.clear_active();
            wallet_session::clear_active_wallet(ad);
            return Ok(());
        }
        wallet_session::activate_slot(ad, slot)
            .map_err(|_| PersistError::InvalidWallet)
    }

    #[inline(never)]
    pub(super) fn save_flash_snapshot(&mut self, manager: &SeedManager) -> Result<(), PersistError> {
        let (target, sequence) = journal::next_wallet_target(&mut self.flash)?;
        let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
        self.build_record_into(manager, sequence, &mut record)?;
        let result = self.flash.replace_sector(target, &record).map_err(PersistError::from);
        zeroize_buf(&mut record.0);
        result?;
        journal::write_wallet_labels(&mut self.flash, journal::WalletLabels::from_manager(manager))?;
        self.accept_revision(manager);
        Ok(())
    }

    #[inline(never)]
    pub(super) fn save_sd_snapshot(
        &mut self,
        manager: &SeedManager,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        delay: &mut esp_hal::delay::Delay,
    ) -> Result<(), PersistError> {
        if self.sd_active_slot > 1 { return Err(PersistError::SdStorageCorrupt); }
        let next_slot = 1u8 - self.sd_active_slot;
        let sequence = self.sd_wallet_sequence.wrapping_add(1);
        if sequence == 0 { return Err(PersistError::SdStorageCorrupt); }
        let mut record = AlignedBytes::<RECORD_SIZE>::zeroed();
        self.build_record_into(manager, sequence, &mut record)?;
        let kind = self.credential_kind.ok_or(PersistError::CredentialRequired)?;
        let mut key = *self.credential_key.as_ref().ok_or(PersistError::CredentialRequired)?;
        let result = super::sd_backend::write_slot(
            &mut self.crypto, kind, &key, &self.credential_salt, next_slot, &record, i2c, delay,
        );
        zeroize_buf(&mut key);
        zeroize_buf(&mut record.0);
        result?;
        journal::write_sd_anchor(&mut self.flash, journal::SdAnchor {
            credential_kind: kind,
            salt: self.credential_salt,
            active_slot: next_slot,
            wallet_sequence: sequence,
            duress: self.security_policy.duress,
            credential_kdf: self.credential_kdf,
        })?;
        self.sd_active_slot = next_slot;
        self.sd_wallet_sequence = sequence;
        journal::write_wallet_labels(&mut self.flash, journal::WalletLabels::from_manager(manager))?;
        self.accept_revision(manager);
        Ok(())
    }

    #[inline(never)]
    pub(super) fn build_record_into(
        &mut self,
        manager: &SeedManager,
        sequence: u32,
        record: &mut AlignedBytes<RECORD_SIZE>,
    ) -> Result<(), PersistError> {
        let key_slot = self.crypto.available_key_slot().ok_or(PersistError::DeviceKeyMissing)?;
        let kind = self.credential_kind.ok_or(PersistError::CredentialRequired)?;
        let credential_key = self.credential_key.as_ref().ok_or(PersistError::CredentialRequired)?;
        let mut payload = [0u8; PAYLOAD_SIZE];
        codec::encode(manager, &mut payload);
        record.0.fill(0);
        let result = (|| {
            self.crypto.seal(
                &payload, sequence, key_slot, kind, self.device_only, credential_key, &self.credential_salt, record,
            )?;
            let header = crypto::parse_header(record).ok_or(PersistError::InvalidWallet)?;
            security_policy::encode(&mut self.crypto, header, self.security_policy, record)
        })();
        zeroize_buf(&mut payload);
        result?;
        Ok(())
    }
}
