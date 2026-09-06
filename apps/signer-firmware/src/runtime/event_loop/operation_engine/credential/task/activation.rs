use crate::{
    runtime::data::{AppData, OperationKind},
    services::persistent_wallet::{CredentialKind, PersistentWallet},
};
use shared_signer::bytes::zeroize_bytes;
use crate::services::credential_policy::SALT_SIZE;

use super::{SecretBuffer, Step};

#[derive(Clone, Copy)]
pub(super) enum WalletActivationMode {
    Setup { slot: u8, salt: [u8; SALT_SIZE] },
    Verify { slot: u8, salt: [u8; SALT_SIZE], verifier: [u8; 32] },
}

pub(in crate::runtime::event_loop::operation_engine::credential) struct WalletActivationTask {
    pub(super) operation: OperationKind,
    pub(super) kind: CredentialKind,
    pub(super) secret: SecretBuffer,
    pub(super) mode: WalletActivationMode,
}

impl WalletActivationTask {
    #[inline(never)]
    pub(super) fn step(
        &mut self,
        ad: &mut AppData,
        persistence: &mut PersistentWallet<'_>,
        delay: &mut esp_hal::delay::Delay,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        liveness: &mut (impl FnMut() + ?Sized),
    ) -> Step {
        let (slot, salt) = match &self.mode {
            WalletActivationMode::Setup { slot, salt }
            | WalletActivationMode::Verify { slot, salt, .. } => (*slot, *salt),
        };
        crate::runtime::presentation::set_progress(ad, 8);
        crate::log!("   Wallet activation KDF foreground BEGIN");
        liveness();
        if matches!(self.mode, WalletActivationMode::Verify { .. }) {
            match persistence.duress_entered(self.kind, self.secret.as_slice(), liveness) {
                Ok(true) => {
                    let result = persistence.trigger_duress(ad, i2c, delay);
                    self.secret.clear();
                    ad.wallet.seeds.pp_input.reset();
                    return Step::Complete { kind: self.operation, result };
                }
                Ok(false) => {}
                Err(error) => {
                    self.secret.clear();
                    ad.wallet.seeds.pp_input.reset();
                    return Step::Complete { kind: self.operation, result: Err(error) };
                }
            }
        }
        let result = match persistence.derive_wallet_activation_key(
            self.secret.as_slice(), &salt, liveness,
        ) {
            Err(error) => Err(error),
            Ok(mut key) => {
                crate::runtime::presentation::set_progress(ad, 82);
                let result = match self.mode {
                    WalletActivationMode::Setup { .. } => {
                        match persistence.make_wallet_activation_verifier(
                            usize::from(slot), self.kind, &salt, &key,
                        ) {
                            Ok(verifier) => {
                                ad.wallet.seeds.pending_wallet_protection = match self.kind {
                                    CredentialKind::Pin => crate::wallet::seed_manager::WalletProtection::Pin,
                                    CredentialKind::Password => crate::wallet::seed_manager::WalletProtection::Password,
                                };
                                ad.wallet.seeds.pending_wallet_activation_salt = salt;
                                ad.wallet.seeds.pending_wallet_activation_verifier = verifier;
                                ad.wallet.seeds.mark_pending_wallet_activation_ready();
                                Ok(())
                            }
                            Err(error) => Err(error),
                        }
                    }
                    WalletActivationMode::Verify { verifier, .. } => persistence.verify_wallet_activation_key(
                        usize::from(slot), self.kind, &salt, &verifier, &key,
                    ),
                };
                zeroize_bytes(&mut key);
                result
            }
        };
        self.secret.clear();
        ad.wallet.seeds.pp_input.reset();
        crate::log!("   Wallet activation KDF foreground DONE ok={}", result.is_ok());
        Step::Complete { kind: self.operation, result }
    }
}
