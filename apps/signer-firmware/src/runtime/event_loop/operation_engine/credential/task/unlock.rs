use crate::{
    runtime::data::{AppData, OperationKind},
    services::persistent_wallet::{
        AsyncUnlockApply, AsyncUnlockSession, PersistError, PersistentWallet, UnlockKdfRequest,
    },
};
use shared_signer::bytes::zeroize_bytes;

use super::{SecretBuffer, Step};

pub(in crate::runtime::event_loop::operation_engine::credential) struct UnlockTask {
    pub(super) operation: OperationKind,
    pub(super) secret: SecretBuffer,
    pub(super) session: AsyncUnlockSession,
    pub(super) request: Option<UnlockKdfRequest>,
}

impl UnlockTask {
    #[inline(never)]
    pub(super) fn step(
        &mut self,
        ad: &mut AppData,
        persistence: &mut PersistentWallet<'_>,
        delay: &mut esp_hal::delay::Delay,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        liveness: &mut (impl FnMut() + ?Sized),
    ) -> Step {
        let Some(request) = self.request.take() else {
            return self.complete(ad, Err(PersistError::InvalidWallet));
        };
        crate::runtime::presentation::set_progress(ad, 8);
        crate::log!("   Credential KDF foreground BEGIN unlock");
        liveness();
        let mut key = match request.derive(self.secret.as_slice(), liveness) {
            Ok(key) => key,
            Err(error) => return self.complete(ad, Err(error)),
        };
        crate::runtime::presentation::set_progress(ad, 82);
        let applied = persistence.apply_async_unlock_key(&mut self.session, key, ad, i2c, delay);
        zeroize_bytes(&mut key);
        match applied {
            Err(error) => self.complete(ad, Err(error)),
            Ok(AsyncUnlockApply::Complete(result)) => self.complete(ad, result),
            Ok(AsyncUnlockApply::Continue) => match next_unlock_request(persistence, &mut self.session) {
                Ok(Some(request)) => {
                    self.request = Some(request);
                    crate::runtime::presentation::set_progress(ad, 8);
                    crate::log!("   Credential KDF foreground candidate DONE; next prepared");
                    Step::Continue
                }
                Ok(None) => {
                    let error = persistence.async_unlock_terminal_error(&self.session);
                    self.complete(ad, Err(error))
                }
                Err(error) => self.complete(ad, Err(error)),
            },
        }
    }

    fn complete(&mut self, ad: &mut AppData, result: Result<(), PersistError>) -> Step {
        self.secret.clear();
        self.request = None;
        ad.wallet.seeds.pp_input.reset();
        crate::log!("   Credential KDF foreground DONE unlock ok={}", result.is_ok());
        Step::Complete { kind: self.operation, result }
    }
}

pub(super) fn next_unlock_request(
    persistence: &mut PersistentWallet<'_>,
    session: &mut AsyncUnlockSession,
) -> Result<Option<UnlockKdfRequest>, PersistError> {
    persistence.next_async_unlock_kdf(session)
}
