//! Persistent-wallet driver for the unified operation engine.
//!
//! Memory-hard credential stretching is foreground-exclusive on CoreS3:
//! Loading is rendered first, the event-loop tail acknowledges liveness, then
//! the next exclusive frame runs one synchronous KDF on the normal application
//! core. The peer derivation worker is never forcibly stalled. This leaves one
//! reusable path for PIN, password, duress, wallet-candidate, and migration
//! derivations.

use crate::{
    hw::display::BootDisplay,
    runtime::data::{AppData, OperationKind},
    services::persistent_wallet::PersistentWallet,
};

mod result;
mod task;

#[cfg(feature = "workflow-test-auto")]
pub(crate) use result::workflow_backoff_probe;

use task::{Step, Task};

pub(super) struct CredentialDriver {
    task: Option<Task>,
}

impl CredentialDriver {
    pub(super) const fn new() -> Self {
        Self { task: None }
    }

    pub(super) fn owns_exclusive_frame(&self) -> bool {
        self.task.is_some()
    }

    pub(super) fn cancel(&mut self, ad: &mut AppData) {
        if let Some(task) = self.task.take() {
            task.cancel();
            ad.wallet.seeds.pp_input.reset();
        }
        crate::services::audio::resume_credential_cues();
    }

    pub(super) fn service(
        &mut self,
        ad: &mut AppData,
        kind: OperationKind,
        persistence: &mut PersistentWallet<'_>,
        display: &mut BootDisplay<'_>,
        delay: &mut esp_hal::delay::Delay,
        i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
        liveness: &mut (impl FnMut() + ?Sized),
    ) {
        if self.task.is_none() {
            // Flush the submit cue before entering the exclusive memory-hard
            // lane. Task publication itself is deliberately cheap; returning
            // here guarantees one real watchdog acknowledgement immediately
            // before the first foreground KDF begins on the next frame.
            crate::services::audio::suspend_credential_cues();
            match Task::begin(ad, kind, persistence) {
                Ok(task) => {
                    self.task = Some(task);
                    crate::log!("   Credential foreground-exclusive lane ARMED");
                    return;
                }
                Err(error) => {
                    ad.wallet.seeds.pp_input.reset();
                    crate::services::audio::resume_credential_cues();
                    result::finish(ad, kind, error, display, delay, persistence);
                    return;
                }
            }
        }
        let step = {
            let Some(task) = self.task.as_mut() else { return; };
            task.step(ad, persistence, display, delay, i2c, liveness)
        };
        match step {
            Step::Continue => {}
            Step::Complete { kind, result } => {
                self.task = None;
                crate::services::audio::resume_credential_cues();
                crate::log!("   Credential foreground-exclusive lane RELEASED");
                result::finish_result(ad, kind, result, display, delay, persistence);
            }
        }
    }
}
