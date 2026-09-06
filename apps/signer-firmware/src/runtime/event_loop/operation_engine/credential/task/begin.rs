use crate::{
    runtime::data::{AppData, OperationKind},
    services::persistent_wallet::{CredentialKind, PersistError, PersistentWallet},
};
use crate::services::credential_policy::SALT_SIZE;

use super::{
    credential_kind, next_unlock_request, SaveTask, SecretBuffer, Task, UnlockTask,
    WalletActivationMode, WalletActivationTask,
};

pub(super) fn begin(
    ad: &mut AppData,
    operation: OperationKind,
    persistence: &mut PersistentWallet<'_>,
) -> Result<Task, PersistError> {
    let (kind, unlock) = credential_kind(operation).ok_or(PersistError::CredentialRequired)?;
    let secret = SecretBuffer::take_from_app(ad)?;

    if !unlock {
        if let Some(slot) = setup_slot(ad)? {
            let salt = persistence.prepare_wallet_activation_salt(kind, secret.as_slice())?;
            crate::runtime::presentation::set_progress(ad, 4);
            return Ok(Task::WalletActivation(WalletActivationTask {
                operation,
                kind,
                secret,
                mode: WalletActivationMode::Setup { slot, salt },
            }));
        }
        return begin_save(ad, operation, kind, secret, persistence);
    }

    if let Some((slot, salt, verifier)) = wallet_verification_material(ad, kind, persistence)? {
        crate::runtime::presentation::set_progress(ad, 4);
        return Ok(Task::WalletActivation(WalletActivationTask {
            operation,
            kind,
            secret,
            mode: WalletActivationMode::Verify { slot, salt, verifier },
        }));
    }
    begin_unlock(ad, operation, kind, secret, persistence)
}

fn setup_slot(ad: &AppData) -> Result<Option<u8>, PersistError> {
    if ad.wallet.seeds.has_pending_add_wallet() {
        let slot = ad.wallet.seeds.pending_add_wallet_slot;
        return if slot == u8::MAX { Err(PersistError::InvalidWallet) } else { Ok(Some(slot)) };
    }
    Ok(ad.runtime
        .pending_wallet_protection_update()
        .and_then(|slot| u8::try_from(slot).ok()))
}

fn wallet_verification_material(
    ad: &AppData,
    kind: CredentialKind,
    persistence: &mut PersistentWallet<'_>,
) -> Result<Option<(u8, [u8; SALT_SIZE], [u8; 32])>, PersistError> {
    let Some(slot) = ad.runtime.pending_wallet_activation() else { return Ok(None); };
    let protection = ad.wallet.seeds.seed_mgr.slots
        .get(slot)
        .ok_or(PersistError::InvalidWallet)?
        .protection;
    let Some(expected_kind) = protection.credential_kind() else { return Ok(None); };
    if expected_kind != kind { return Err(PersistError::Authentication); }
    let (salt, verifier) = persistence.wallet_activation_material(slot)?;
    let slot = u8::try_from(slot).map_err(|_| PersistError::InvalidWallet)?;
    Ok(Some((slot, salt, verifier)))
}

fn begin_unlock(
    ad: &mut AppData,
    operation: OperationKind,
    kind: CredentialKind,
    secret: SecretBuffer,
    persistence: &mut PersistentWallet<'_>,
) -> Result<Task, PersistError> {
    let mut session = persistence.begin_async_unlock(kind, secret.as_slice())?;
    let request = next_unlock_request(persistence, &mut session)?
        .ok_or_else(|| persistence.async_unlock_terminal_error(&session))?;
    crate::runtime::presentation::set_progress(ad, 4);
    crate::log!("Persistent wallet unlock foreground KDF prepared");
    Ok(Task::Unlock(UnlockTask { operation, secret, session, request: Some(request) }))
}

fn begin_save(
    ad: &mut AppData,
    operation: OperationKind,
    kind: CredentialKind,
    secret: SecretBuffer,
    persistence: &mut PersistentWallet<'_>,
) -> Result<Task, PersistError> {
    let recovery_ack = ad.storage.persistence.recovery_words_acknowledged;
    let salt = persistence.prepare_async_save(kind, secret.as_slice(), recovery_ack)?;
    crate::runtime::presentation::set_progress(ad, 4);
    crate::log!("Persistent wallet save foreground KDF prepared");
    Ok(Task::Save(SaveTask { operation, kind, secret, salt }))
}
