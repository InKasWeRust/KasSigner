//! Event-loop liveness acknowledgement.
//!
//! Normal runtime acknowledgement is deliberately last, after a fully returned
//! application-loop iteration. The runner may also invoke this capability from
//! explicitly bounded cryptographic checkpoints after a visible progress frame;
//! hardware/controller stages never receive the capability and cannot mask hangs.

#[cfg(not(feature = "workflow-test-auto"))]
#[inline]
pub(crate) fn acknowledge(watchdog_feed: &mut (impl FnMut() + ?Sized)) {
    watchdog_feed();
}

#[cfg(feature = "m5stack")]
pub(crate) fn sync_watchdog_budget(ad: &crate::runtime::data::AppData) {
    use crate::runtime::{data::OperationKind, input::AppState};

    let credential_screen = matches!(
        ad.navigation.app.state,
        AppState::StoragePinEntry
            | AppState::StoragePinConfirm
            | AppState::StoragePasswordEntry
            | AppState::StoragePasswordConfirm
            | AppState::StorageUnlockPin
            | AppState::StorageUnlockPassword
    );
    let credential_operation = matches!(
        crate::runtime::presentation::operation_kind(ad),
        Some(
            OperationKind::SaveWalletPin
                | OperationKind::SaveWalletPassword
                | OperationKind::UnlockWalletPin
                | OperationKind::UnlockWalletPassword
        )
    );

    if credential_screen || credential_operation {
        crate::runtime::core_s3::enter_credential_watchdog_budget();
    } else {
        crate::runtime::core_s3::leave_credential_watchdog_budget();
    }
}

#[cfg(all(feature = "m5stack", not(feature = "workflow-test-auto")))]
#[inline]
pub(crate) fn acknowledge_runtime(
    ad: &crate::runtime::data::AppData,
    watchdog_feed: &mut impl FnMut(),
) {
    sync_watchdog_budget(ad);
    watchdog_feed();
}
