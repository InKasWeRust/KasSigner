//! Local context and workflow diagnostics for ecosystem-standard PSKT imports.
//!
//! Standard PSKT does not carry KasSigner's compact-KSPT network trailer. The
//! selected wallet/network is therefore local signing context only; it is never
//! added to or required from the PSKT wire representation.

use crate::runtime::data::AppData;

pub(super) fn bind_selected_network(ad: &mut AppData) {
    ad.signing.transaction.active.network = ad.wallet.seeds.seed_mgr.network().kaspa_network();
}

#[cfg(feature = "workflow-test-auto")]
mod workflow {
    use core::sync::atomic::{AtomicU8, Ordering};

    static FAILURE_REASON: AtomicU8 = AtomicU8::new(0);

    pub(super) fn reset() {
        FAILURE_REASON.store(0, Ordering::Relaxed);
    }

    pub(super) fn mark(reason: u8) {
        FAILURE_REASON.store(reason, Ordering::Relaxed);
    }

    pub(crate) fn mark_review_state_failure() {
        if FAILURE_REASON.load(Ordering::Relaxed) == 0 {
            mark(5);
        }
    }

    pub(crate) fn replay_failure_reason() {
        let message = match FAILURE_REASON.load(Ordering::Relaxed) {
            1 => Some("working-memory allocation failed before PSKT parse"),
            2 => Some("standard PSKT parser rejected the ecosystem payload"),
            3 => Some("parsed PSKT failed transaction monetary/review validation"),
            4 => Some("parsed PSKT failed transaction output ownership verification"),
            5 => Some("PSKT parse completed but review state/counts were not reached"),
            _ => None,
        };
        if let Some(message) = message {
            crate::log!(
                "KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILURE REASON STANDARD-PSKT: {}",
                message,
            );
        }
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn reset() {
    workflow::reset();
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn mark(reason: u8) {
    workflow::mark(reason);
}
#[cfg(feature = "workflow-test-auto")]
pub(crate) use workflow::{
    mark_review_state_failure as workflow_mark_standard_pskt_review_state_failure,
    replay_failure_reason as workflow_replay_standard_pskt_failure_reason,
};
