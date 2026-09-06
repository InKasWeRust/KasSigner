//! Authoritative long-running operation engine.
//!
//! Every expensive operation follows one lifecycle owned by PresentationState:
//! `Queued -> Presented -> Running/Progress -> terminal`. Drivers never start
//! themselves and never execute before the loading surface has been presented.

mod credential;

use crate::{
    hw::display::BootDisplay,
    runtime::data::{AppData, OperationExecution, OperationKind, OperationPhase},
    services::persistent_wallet::PersistentWallet,
};

pub(crate) struct OperationEngineState {
    credential: credential::CredentialDriver,
}

impl OperationEngineState {
    pub(crate) const fn new() -> Self {
        Self { credential: credential::CredentialDriver::new() }
    }
}

/// True while a foreground-exclusive operation owns the next runtime frame.
///
/// The driver state, rather than a hardware-specific mailbox, is authoritative.
/// This keeps the event-loop contract reusable for future memory-hard work.
#[inline]
pub(crate) fn owns_exclusive_frame(engine: &OperationEngineState) -> bool {
    engine.credential.owns_exclusive_frame()
}

#[inline(never)]
pub(crate) fn service(
    engine: &mut OperationEngineState,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    let Some(kind) = crate::runtime::presentation::operation_kind(ad) else {
        engine.credential.cancel(ad);
        return;
    };
    if crate::runtime::presentation::timed_out_operation(ad) == Some(kind) {
        timeout_operation(engine, ad, kind);
        return;
    }

    if crate::runtime::presentation::operation_phase(ad) == OperationPhase::Presented {
        if crate::runtime::presentation::take_ready_operation(ad) != Some(kind) { return; }
        crate::log!("   Operation {:?} BEGIN after loading surface", kind);
    }
    if !matches!(
        crate::runtime::presentation::operation_phase(ad),
        OperationPhase::Running | OperationPhase::Progress(_)
    ) {
        return;
    }

    match kind.execution() {
        OperationExecution::ForegroundExclusive => {
            engine.credential.service(ad, kind, persistence, display, delay, i2c, liveness);
        }
        OperationExecution::Stepped => {
            engine.credential.cancel(ad);
            service_stepped(ad, kind, persistence, display, delay, i2c, liveness);
        }
    }
}

fn service_stepped(
    ad: &mut AppData,
    kind: OperationKind,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    match kind {
        OperationKind::ConnectKasSee | OperationKind::DeriveMultisigKpub => {
            super::runner::service_kpub_operation(ad, display, liveness);
        }
        OperationKind::SignTransaction => {
            crate::runtime::signing::handle_signing_operation_step(
                ad, display, delay, i2c, persistence, liveness,
            );
        }
        OperationKind::SaveWalletPin
        | OperationKind::SaveWalletPassword
        | OperationKind::UnlockWalletPin
        | OperationKind::UnlockWalletPassword => {}
    }
}

fn timeout_operation(
    engine: &mut OperationEngineState,
    ad: &mut AppData,
    kind: OperationKind,
) {
    match kind.execution() {
        OperationExecution::ForegroundExclusive => engine.credential.cancel(ad),
        OperationExecution::Stepped => cancel_stepped(ad, kind),
    }
    let Some(error) = crate::runtime::presentation::timeout_error(kind) else { return; };
    crate::log!("   Operation {:?} timed out before hardware watchdog", kind);
    crate::runtime::presentation::fail_recoverable_spec(ad, error);
}

fn cancel_stepped(ad: &mut AppData, kind: OperationKind) {
    match kind {
        OperationKind::ConnectKasSee | OperationKind::DeriveMultisigKpub => {
            super::runner::cancel_kpub_operation(ad, kind);
        }
        OperationKind::SignTransaction => {
            crate::runtime::signing::cancel_active_signing_operation(ad);
        }
        OperationKind::SaveWalletPin
        | OperationKind::SaveWalletPassword
        | OperationKind::UnlockWalletPin
        | OperationKind::UnlockWalletPassword => {}
    }
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
pub(crate) fn workflow_inject_timeout(ad: &mut AppData, kind: OperationKind) {
    if kind.stepped() { cancel_stepped(ad, kind); }
    let Some(error) = crate::runtime::presentation::timeout_error(kind) else { return; };
    crate::runtime::presentation::fail_recoverable_spec(ad, error);
}

/// Cancel stepped work abandoned by an explicit Home transition. Credential
/// foreground-exclusive operations block input and cannot be abandoned by ordinary touch.
pub(crate) fn cancel_abandoned(ad: &mut AppData) {
    let Some(kind) = crate::runtime::presentation::operation_kind(ad) else { return; };
    if !kind.stepped() { return; }
    cancel_stepped(ad, kind);
    crate::runtime::presentation::clear_operation(ad);
    crate::log!("   UI abandoned stepped operation {:?} on Home", kind);
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) use credential::workflow_backoff_probe;
