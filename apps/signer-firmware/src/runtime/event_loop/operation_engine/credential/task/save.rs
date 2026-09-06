use crate::{
    hw::display::BootDisplay,
    runtime::data::{AppData, OperationKind},
    services::persistent_wallet::{CredentialKind, PersistentWallet},
};
use shared_signer::bytes::zeroize_bytes;
use crate::services::credential_policy::SALT_SIZE;

use super::{SecretBuffer, Step};

pub(in crate::runtime::event_loop::operation_engine::credential) struct SaveTask {
    pub(super) operation: OperationKind,
    pub(super) kind: CredentialKind,
    pub(super) secret: SecretBuffer,
    pub(super) salt: [u8; SALT_SIZE],
}

impl SaveTask {
    #[inline(never)]
    pub(super) fn step(
        &mut self,
        ad: &mut AppData,
        persistence: &mut PersistentWallet<'_>,
        display: &mut BootDisplay<'_>,
        liveness: &mut (impl FnMut() + ?Sized),
    ) -> Step {
        crate::runtime::presentation::set_progress(ad, 8);
        crate::log!("   Credential KDF foreground BEGIN save");
        liveness();
        let result = match persistence.derive_async_save_key(
            self.secret.as_slice(), &self.salt, liveness,
        ) {
            Err(error) => Err(error),
            Ok(mut key) => {
                crate::runtime::presentation::set_progress(ad, 82);
                let result = persistence.finish_async_save(
                    self.kind,
                    self.salt,
                    key,
                    &ad.wallet.seeds.seed_mgr,
                    &mut |pct| {
                        display.update_progress_bar(pct);
                        liveness();
                    },
                );
                zeroize_bytes(&mut key);
                result
            }
        };
        self.secret.clear();
        ad.wallet.seeds.pp_input.reset();
        crate::log!("   Credential KDF foreground DONE save ok={}", result.is_ok());
        Step::Complete { kind: self.operation, result }
    }
}
