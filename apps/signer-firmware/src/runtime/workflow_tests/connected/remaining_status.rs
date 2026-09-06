//! Small result accumulator for the connected remaining-surface probes.

pub(super) struct ProbeSummary {
    passed: usize,
    failed: usize,
}

impl ProbeSummary {
    pub(super) const fn new() -> Self {
        Self { passed: 0, failed: 0 }
    }

    pub(super) fn run<F>(&mut self, name: &str, probe: F)
    where
        F: FnOnce() -> bool,
    {
        log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE DEADLINE REFRESH");
        self.record(name, probe());
    }

    pub(super) fn record(&mut self, name: &str, result: bool) {
        if result {
            self.passed += 1;
            log!("KASSIGNER_WORKFLOW_TESTS: REMAINING PROBE {} PASS", name);
        } else {
            self.failed += 1;
            log!(
                "KASSIGNER_WORKFLOW_TESTS: REMAINING PROBE {} FAILED; CONTINUING",
                name,
            );
        }
    }

    pub(super) fn finish(self, attempted: usize) -> bool {
        log!(
            "KASSIGNER_WORKFLOW_TESTS: REMAINING PRODUCTION SURFACES SUMMARY attempted={} passed={} failed={}",
            attempted,
            self.passed,
            self.failed,
        );
        self.failed == 0 && self.passed == attempted
    }
}
