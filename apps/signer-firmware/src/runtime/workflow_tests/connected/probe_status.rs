//! Generic connected-E2E subprobe accounting and liveness checkpoints.

use core::sync::atomic::{AtomicU16, Ordering};

pub(super) struct ProbeSummary {
    scope: &'static str,
    passed: usize,
    failed: usize,
}

impl ProbeSummary {
    pub(super) const fn new(scope: &'static str) -> Self {
        Self { scope, passed: 0, failed: 0 }
    }

    pub(super) fn begin(&self, name: &str) {
        // Refresh the host watchdog before each independently reportable
        // subprobe. Some real embedded cryptographic probes legitimately take
        // minutes on the ESP32-S3, but a hung probe still has one bounded
        // per-probe window rather than consuming a suite-global budget.
        log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE DEADLINE REFRESH");
        log!("KASSIGNER_WORKFLOW_TESTS: {} PROBE {} BEGIN", self.scope, name);
    }

    pub(super) fn record(&mut self, name: &str, result: bool) {
        if result {
            self.passed += 1;
            log!("KASSIGNER_WORKFLOW_TESTS: {} PROBE {} PASS", self.scope, name);
        } else {
            self.failed += 1;
            log!(
                "KASSIGNER_WORKFLOW_TESTS: {} PROBE {} FAILED; CONTINUING",
                self.scope,
                name,
            );
        }
    }

    pub(super) fn finish(self, attempted: usize) -> bool {
        log!(
            "KASSIGNER_WORKFLOW_TESTS: {} SUMMARY attempted={} passed={} failed={}",
            self.scope,
            attempted,
            self.passed,
            self.failed,
        );
        self.failed == 0 && self.passed == attempted
    }
}


pub(super) fn replay_mask(scope: &str, mask: &AtomicU16, labels: &[&str]) {
    let bits = mask.load(Ordering::Relaxed);
    log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED {} FAILURE SNAPSHOT mask=0x{:04x}", scope, bits);
    for (index, label) in labels.iter().enumerate() {
        if bits & (1u16 << index) != 0 {
            log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED {} PROBE {}", scope, label);
        }
    }
}
