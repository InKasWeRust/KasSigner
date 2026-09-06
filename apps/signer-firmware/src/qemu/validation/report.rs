// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! UART test reporting with stable host-consumable markers.

pub(crate) struct Report {
    passed: u32,
    failed: u32,
    skipped: u32,
}

impl Report {
    pub(crate) const fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            skipped: 0,
        }
    }

    pub(crate) fn check(&mut self, name: &str, passed: bool) {
        if passed {
            self.passed += 1;
            crate::log!("[QEMU TEST] PASS: {}", name);
        } else {
            self.failed += 1;
            crate::log!("[QEMU TEST] FAIL: {}", name);
        }
    }

    pub(crate) fn counted(&mut self, name: &str, passed: u32, total: u32) {
        if total > 0 && passed == total {
            self.passed += total;
            crate::log!("[QEMU TEST] PASS: {} ({}/{})", name, passed, total);
        } else {
            self.passed += passed;
            self.failed += total.saturating_sub(passed).max(1);
            crate::log!("[QEMU TEST] FAIL: {} ({}/{})", name, passed, total);
        }
    }

    pub(crate) fn skipped(&mut self, name: &str, reason: &str) {
        self.skipped += 1;
        crate::log!("[QEMU TEST] SKIP: {} — {}", name, reason);
    }

    pub(crate) fn finish(self) -> bool {
        crate::log!(
            "QEMU test summary: {} passed, {} failed, {} skipped",
            self.passed,
            self.failed,
            self.skipped
        );
        if self.failed == 0 {
            crate::log!("KASSIGNER_QEMU_TESTS_PASS");
            true
        } else {
            crate::log!("KASSIGNER_QEMU_TESTS_FAIL");
            false
        }
    }
}
